using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.Text.Json;

namespace Observe;

public sealed class TrackedLaunches(string root):IDisposable
{
    readonly object gate=new();
    readonly Dictionary<string,TrackedRun> active=[];
    readonly Dictionary<string,HashSet<string>> ids=[];
    readonly LaunchProcessSampler sampler=new();
    ManagementEventWatcher? starts,stops;
    long sequence;DateTimeOffset lastSave;bool resumeExisting=true;
    public EvidenceArchive? Archive {get;set;}
    public event Action<EvidenceEvent>? Observed;
    public bool Recording {get{lock(gate)return active.Count>0;}}
    string FilePath(string id)=>Guid.TryParseExact(id,"D",out _)?Path.Combine(root,id+".json"):throw new ArgumentException("Invalid launch ID.");
    void Save(TrackedRun run){Directory.CreateDirectory(root);var path=FilePath(run.Id);File.WriteAllText(path+".tmp",JsonSerializer.Serialize(run,Evidence.Json));File.Move(path+".tmp",path,true);lastSave=DateTimeOffset.UtcNow;}
    public TrackedRun Get(string id)
    {
        TrackedRun run;lock(gate)
        {
            if(active.TryGetValue(id,out var current))run=Clone(current);
            else{var path=FilePath(id);run=JsonSerializer.Deserialize<TrackedRun>(File.ReadAllText(path),Evidence.Json)??throw new InvalidDataException("Recording could not be read.");if(run.Status=="recording"){run.Status="interrupted";run.Warnings.Add("Observe closed during this recording. Recorded history was retained; monitoring gaps cannot be recovered.");}}
        }
        if(Archive is not null)run.Events=run.Events.Concat(Archive.Read(run.Started,run.Ended??DateTimeOffset.UtcNow)).DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToList();
        return run;
    }
    static TrackedRun Clone(TrackedRun r)=>JsonSerializer.Deserialize<TrackedRun>(JsonSerializer.Serialize(r,Evidence.Json),Evidence.Json)!;
    public object[] List()
    {
        lock(gate)
        {
            if(!Directory.Exists(root))return [];
            return Directory.GetFiles(root,"*.json").OrderByDescending(File.GetLastWriteTimeUtc).Select(path=>
            {try{var id=Path.GetFileNameWithoutExtension(path);var r=active.GetValueOrDefault(id)??JsonSerializer.Deserialize<TrackedRun>(File.ReadAllText(path),Evidence.Json)!;return (object)new{r.Id,r.Name,r.Path,r.Started,r.Ended,status=r.Status=="recording"&&!active.ContainsKey(id)?"interrupted":r.Status,r.RootPid};}catch(JsonException){return null;}}).OfType<object>().ToArray();
        }
    }
    public static string ValidatePath(string path){path=Path.GetFullPath(path.Trim().Trim('"'));if(!File.Exists(path)||!path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||path.StartsWith(@"\\"))throw new ArgumentException("Choose an existing local .exe file.");return path;}
    void Activate(TrackedRun run){lock(gate){active[run.Id]=run;ids[run.Id]=[];Save(run);}StartWatchers(run);}
    public async Task<TrackedRun> Start(string path,string arguments,string[] warnings)
    {
        path=ValidatePath(path);if(arguments.Length>4000||arguments.Any(c=>c is '\r' or '\n' or '\0'))throw new ArgumentException("Arguments must be a single line up to 4,000 characters.");
        var run=new TrackedRun{Path=path,Name=Path.GetFileNameWithoutExtension(path),Arguments=arguments,Warnings=warnings.ToList()};
        await using(var input=File.OpenRead(path))run.Sha256=Convert.ToHexString(await SHA256.HashDataAsync(input)).ToLowerInvariant();
        run.Warnings.Add("Observation is not a sandbox or a malware verdict. A mod shares its host game's process. Work delegated to an unrelated launcher or service is not automatically attributed to this root.");
        // Establish identity while suspended; collectors see it before the application runs.
        using var child=ObservedProcess.Create(path,arguments);run.RootPid=child.Pid;run.Started=child.Started;Activate(run);
        try{Emit(new("tracked-root:"+run.Id,"Observe/TrackedLaunch",0,1,run.Started,new(){{"Image",path},{"ProcessId",child.Pid.ToString()},{"ProcessStartTime",run.Started.ToString("O")},{"ParentProcessId",Environment.ProcessId.ToString()},{"CommandLine",'"'+path+'"'+" "+arguments},{"Source","Observe launched this exact process"}}));child.Resume();return Get(run.Id);}
        catch{Finish(run.Id,"launch-failed");throw;}
    }
    public TrackedRun Attach(int pid,DateTimeOffset expected,string path,IEnumerable<EvidenceEvent>? history=null)
    {
        using var p=Process.GetProcessById(pid);var born=new DateTimeOffset(p.StartTime.ToUniversalTime());var image=p.MainModule?.FileName??"";
        if(Math.Abs((born-expected).TotalMilliseconds)>1||!image.Equals(path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("The selected process exited or changed. Refresh the app list.");
        lock(gate){var existing=active.Values.FirstOrDefault(r=>r.RootPid==pid&&r.Started==born);if(existing is not null)return Clone(existing);}
        var run=new TrackedRun{Path=image,Name=Path.GetFileNameWithoutExtension(image),RootPid=pid,Started=born,AttachedAt=DateTimeOffset.UtcNow,Warnings=["Attached to an already-running process. Earlier events are included only when retained. Actions before observation, brief children and work delegated to unrelated processes may be absent.",NetworkMonitor.Coverage,ScriptInvestigation.Limits]};
        if(history is not null)run.Events=history.Where(e=>e.Timestamp>=born).DistinctBy(e=>e.Id).ToList();
        Activate(run);Emit(new("tracked-attach:"+run.Id,"Observe/TrackedLaunch",0,1,born,new(){{"Image",image},{"ProcessId",pid.ToString()},{"ProcessStartTime",born.ToString("O")},{"Source","Attached process identity; creation time read from Windows"}}));return Get(run.Id);
    }
    public void ResumeWatched(AppCatalog apps)
    {
        var resume=resumeExisting;resumeExisting=false;
        // Watched executable paths are persistent; a fresh recording marks the observation gap after restart.
        foreach(var app in apps.All().Where(a=>a.Watch))foreach(var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(app.Path)))using(p)
            try{var born=new DateTimeOffset(p.StartTime.ToUniversalTime());if(!string.Equals(p.MainModule?.FileName,app.Path,StringComparison.OrdinalIgnoreCase))continue;var instance=p.Id+":"+born.ToString("O");if(resume)apps.Unclaim(app.Path,instance);if(apps.Claim(app.Path,instance))try{Attach(p.Id,born,app.Path);}catch{apps.Unclaim(app.Path,instance);throw;}}catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException){}
    }
    public void ObserveWatched(AppCatalog apps,EvidenceEvent[] batch)
    {
        foreach(var e in batch.Where(e=>e.EventId==1))
        {
            var path=e.Data.GetValueOrDefault("Image","");if(!Path.IsPathFullyQualified(path)||!int.TryParse(e.Data.GetValueOrDefault("ProcessId"),out var pid)||pid<=0)continue;
            var born=DateTimeOffset.TryParse(e.Data.GetValueOrDefault("ProcessStartTime"),out var time)?time:e.Timestamp;
            var instance=pid+":"+born.ToString("O");if(!apps.Claim(path,instance))continue;
            lock(gate)if(active.Values.Any(r=>r.RootPid==pid&&Math.Abs((r.Started-born).TotalMilliseconds)<250))continue;
            var run=new TrackedRun{Path=path,Name=Path.GetFileNameWithoutExtension(path),RootPid=pid,Started=born,AttachedAt=DateTimeOffset.UtcNow,Events=batch.Where(x=>x.Timestamp>=born).ToList(),Warnings=["Automatically tracked a watched executable from a recorded process start. Capture depends on the available sensors; work delegated to unrelated services is not attributed.",NetworkMonitor.Coverage,ScriptInvestigation.Limits]};
            Activate(run);
        }
    }
    void Emit(EvidenceEvent e){if(Observed is null)Record(e);else Observed.Invoke(e);}
    void StartWatchers(TrackedRun run)
    {
        if(starts is not null)return;
        try
        {
            starts=new(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));stops=new(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            void Receive(EventArrivedEventArgs args,int kind)
            {
                using var record=args.NewEvent;var at=DateTimeOffset.UtcNow;
                if(long.TryParse(record["TIME_CREATED"]?.ToString(),out var ticks))at=new(DateTime.FromFileTimeUtc(ticks));
                var n=Interlocked.Increment(ref sequence);var fields=new Dictionary<string,string>{{"ProcessId",record["ProcessID"]?.ToString()??""},{"Image",record["ProcessName"]?.ToString()??""},{"Source","Windows process trace"}};
                if(kind==1){fields["ParentProcessId"]=record["ParentProcessID"]?.ToString()??"";try{using var p=Process.GetProcessById(int.Parse(fields["ProcessId"]));var born=new DateTimeOffset(p.StartTime.ToUniversalTime());if(born<=at.AddMilliseconds(10)){fields["NotificationTime"]=at.ToString("O");fields["ProcessStartTime"]=born.ToString("O");at=born;fields["Image"]=p.MainModule?.FileName??fields["Image"];}}catch{} }
                Emit(new($"launch-trace:{Environment.ProcessId}:{n}:{at:O}","Observe/ProcessTrace",n,kind,at,fields));
            }
            starts.EventArrived+=(_,e)=>Receive(e,1);stops.EventArrived+=(_,e)=>Receive(e,5);starts.Start();stops.Start();
        }
        catch(Exception e){StopWatchers();run.Warnings.Add("Process trace unavailable: "+e.Message+". Ancestry snapshots remain sampled; short-lived children may be missed.");}
    }
    public void Record(EvidenceEvent e)
    {
        lock(gate)foreach(var run in active.Values)
            if(e.Timestamp>=run.Started.AddSeconds(-1)&&ids[run.Id].Add(e.Id))run.Events.Add(e);
    }
    public void Poll(){foreach(var e in sampler.Poll())Emit(e);}
    public void Checkpoint()
    {
        lock(gate)if(DateTimeOffset.UtcNow-lastSave>TimeSpan.FromSeconds(10))foreach(var run in active.Values.ToArray())
        {
            var linked=TrackedCorrelation.Read(run);var relevant=linked.Events.Select(e=>e.Id).ToHashSet();var cutoff=DateTimeOffset.UtcNow.AddSeconds(-15);
            // The journal retains every event, including rows omitted from the focused recording.
            run.Events.RemoveAll(e=>e.Timestamp<cutoff&&e.EventId is not (1 or 5)&&!relevant.Contains(e.Id));
            if(Archive is not null&&run.Events.Count>12000)
            {
                var keep=run.Events.Where(e=>e.EventId is not (1 or 5)).OrderByDescending(e=>e.Timestamp).Take(10000).Select(e=>e.Id).ToHashSet();
                run.Events.RemoveAll(e=>e.EventId is not (1 or 5)&&!keep.Contains(e.Id));
            }
            ids[run.Id]=run.Events.Select(e=>e.Id).ToHashSet();Save(run);
            if(run.AttachedAt is not null&&linked.Processes.All(p=>p.Ended is not null)&&linked.Processes.Max(p=>p.Ended)<DateTimeOffset.UtcNow.AddSeconds(-3))
            {run.Status="complete";run.Ended=DateTimeOffset.UtcNow;Save(run);active.Remove(run.Id);ids.Remove(run.Id);}
        }
        if(!Recording)StopWatchers();
    }
    public void Finish(string? id=null,string status="complete")
    {
        lock(gate)foreach(var run in active.Values.Where(r=>id is null||r.Id==id).ToArray()){run.Status=status;run.Ended=DateTimeOffset.UtcNow;Save(run);active.Remove(run.Id);ids.Remove(run.Id);}
        if(!Recording)StopWatchers();
    }
    void StopWatchers(){starts?.Dispose();stops?.Dispose();starts=null;stops=null;}
    public void Dispose(){Finish();StopWatchers();}
}
