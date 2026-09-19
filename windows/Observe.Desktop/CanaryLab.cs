using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace Observe;

public sealed class CanaryRun
{
    public string Id {get;set;}=Guid.NewGuid().ToString();
    public DateTimeOffset Started {get;set;}=DateTimeOffset.UtcNow;
    public DateTimeOffset Expires {get;set;}=DateTimeOffset.UtcNow.AddMinutes(20);
    public string CanaryPath {get;set;}="";
}
public sealed class CanaryReceipt
{
    public string SessionId {get;set;}="";
    public int Pid {get;set;}
    public string ProcessStartUtc {get;set;}="";
    public string StartedUtc {get;set;}="";
    public string CompletedUtc {get;set;}="";
    public int Bytes {get;set;}
    public string Mod {get;set;}="";
    public string ModPath {get;set;}="";
    public string ModSha256 {get;set;}="";
}

public sealed class CanaryLab
{
    public const int ReadEvent=10110,ReceiptEvent=10111;
    public const string Limits="This is a harmless canary exercise using a synthetic file outside the game. Windows ETW identifies a process read request; NTSTATUS completion, when present, records its outcome. A mod receipt is cooperative self-report, not independent per-mod call-stack attribution. Other mods and arbitrary file access are not covered by this canary sensor. No finding cannot establish safety. File contents are never captured.";
    public static string DefaultRoot=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ObserveDesktop","mod-canary");
    // AppData, including new LocalLow folders, may be redirected by an MSIX launcher.
    // Keep this tiny game handoff with the synthetic document in the user's Documents folder.
    public static string DefaultBridge=>Path.Combine(DefaultDocuments,"Observe Canary Lab",".control");
    public static string DefaultDocuments=>Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    public static string ModDirectory=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"AppData","LocalLow","Colossal Order","Cities Skylines II","Mods","Observe.CanaryMod");
    public static string ModPath=>Path.Combine(ModDirectory,"Observe.CanaryMod.dll");
    readonly string root,documents;
    public string Bridge {get;}
    readonly HashSet<string> imported=[];
    public event Action<EvidenceEvent>? Recorded;
    public CanaryLab(string storage,string? documents=null){root=Path.Combine(storage,"mod-canary");this.documents=documents??DefaultDocuments;Bridge=Path.GetFullPath(root).Equals(Path.GetFullPath(DefaultRoot),StringComparison.OrdinalIgnoreCase)?DefaultBridge:Path.Combine(root,"bridge");}
    public static string ValidateId(string id)=>Guid.TryParseExact(id,"D",out var guid)?guid.ToString():throw new ArgumentException("Invalid canary test ID.");
    public static void NoLinks(string path)
    {
        for(string? current=Path.GetFullPath(path);!string.IsNullOrEmpty(current);current=Path.GetDirectoryName(current))
            if((File.Exists(current)||Directory.Exists(current))&&(File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new IOException("Links are not allowed in the canary test path: "+current);
    }
    public string FilePath(string id,string suffix)=>Path.Combine(root,ValidateId(id)+suffix);
    public string BridgePath(string id,string suffix)=>Path.Combine(Bridge,ValidateId(id)+suffix);
    public static string Target(string documents,string id)=>Path.Combine(documents,"Observe Canary Lab",ValidateId(id),"canary.txt");
    public static T? Read<T>(string path)
    {
        if(!File.Exists(path))return default;NoLinks(path);if(new FileInfo(path).Length>1_000_000)throw new IOException("Canary record exceeds its size limit.");
        try{using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);return JsonSerializer.Deserialize<T>(input,Evidence.Json);}catch(JsonException){return default;}
    }
    public static void Write(string path,object value){NoLinks(path);NoLinks(path+".tmp");File.WriteAllText(path+".tmp",JsonSerializer.Serialize(value,Evidence.Json));File.Move(path+".tmp",path,true);}
    public CanaryRun[] Runs()=>Directory.Exists(root)?Directory.GetFiles(root,"*.run.json").Select(p=>Read<CanaryRun>(p)).OfType<CanaryRun>().OrderByDescending(r=>r.Started).ToArray():[];
    public CanaryRun Get(string id)=>Read<CanaryRun>(FilePath(id,".run.json"))??throw new ArgumentException("Canary test not found.");
    public bool Active=>Runs().Any(r=>r.Expires>DateTimeOffset.UtcNow&&!File.Exists(FilePath(r.Id,".stop")));
    public CanaryRun Arm(bool launchSensor=true)
    {
        if(Active)throw new InvalidOperationException("Stop the current test before arming another.");
        var run=new CanaryRun();run.CanaryPath=Target(documents,run.Id);NoLinks(root);NoLinks(run.CanaryPath);
        NoLinks(Bridge);Directory.CreateDirectory(root);Directory.CreateDirectory(Bridge);Directory.CreateDirectory(Path.GetDirectoryName(run.CanaryPath)!);
        using(var output=new StreamWriter(new FileStream(run.CanaryPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read)))output.Write("OBSERVE SYNTHETIC CANARY\r\nThis is fake test data. It contains no user information.\r\n");
        Write(FilePath(run.Id,".run.json"),run);
        NoLinks(Path.Combine(Bridge,"armed.txt"));File.WriteAllLines(Path.Combine(Bridge,"armed.txt"),["OBSERVE-CANARY-1",run.Id,run.Expires.ToString("O")]);
        if(launchSensor)try{Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden,Arguments="--canary-sensor "+run.Id})?.Dispose();}
        catch(Exception e){Stop();Write(FilePath(run.Id,".sensor.json"),new{state="error",message="Windows file-read sensor did not start: "+e.Message,at=DateTimeOffset.UtcNow});throw new InvalidOperationException("The canary was created, but Windows did not start the sensor. Approve the administrator prompt when arming another test.",e);}
        return run;
    }
    public void Stop()
    {
        if(!Directory.Exists(root))return;
        foreach(var run in Runs().Where(r=>r.Expires>DateTimeOffset.UtcNow)){var path=FilePath(run.Id,".stop");NoLinks(path);File.WriteAllText(path,"Stopped by Observe at "+DateTimeOffset.UtcNow.ToString("O"));if(Directory.Exists(Bridge)){var signal=BridgePath(run.Id,".stop");NoLinks(signal);File.WriteAllText(signal,"Stopped");}}
        var arm=Path.Combine(root,"armed.txt");NoLinks(arm);if(File.Exists(arm))File.Delete(arm);
        var sharedArm=Path.Combine(Bridge,"armed.txt");NoLinks(sharedArm);if(File.Exists(sharedArm))File.Delete(sharedArm);
    }
    public static string InstallMod()
    {
        if(Process.GetProcessesByName("Cities2").Any())throw new InvalidOperationException("Close Cities II before installing or updating the test mod.");
        NoLinks(ModPath);Directory.CreateDirectory(ModDirectory);
        using var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("Observe.CanaryMod.dll")??throw new InvalidOperationException("This build does not include the test mod. Use the packaged release.");
        using var memory=new MemoryStream();resource.CopyTo(memory);var bytes=memory.ToArray();
        if(File.Exists(ModPath)&&!File.ReadAllBytes(ModPath).SequenceEqual(bytes))throw new IOException("A different DLL exists at the test-mod path. Preserve or remove it before installing this version.");
        if(!File.Exists(ModPath))File.WriteAllBytes(ModPath,bytes);return ModPath;
    }
    public string RemoveMod()
    {
        Stop();if(Process.GetProcessesByName("Cities2").Any())throw new InvalidOperationException("Test stopped. Close Cities II before removing the loaded test mod.");
        NoLinks(ModPath);if(File.Exists(ModPath))
        {
            if(!Hash(ModPath).Equals(BundledHash(),StringComparison.OrdinalIgnoreCase))throw new IOException("The installed DLL differs from this release; it was kept.");
            File.Delete(ModPath);
        }
        foreach(var run in Runs())
        {
            _=Events(run.Id); // Preserve the receipt before cleaning the bridge.
            var target=Target(documents,run.Id);NoLinks(target);
            if(File.Exists(target))File.Delete(target);
            var directory=Path.GetDirectoryName(target)!;if(Directory.Exists(directory)&&!Directory.EnumerateFileSystemEntries(directory).Any())Directory.Delete(directory);
            foreach(var suffix in new[]{".ready",".stop",".receipt.json"}){var bridgeFile=BridgePath(run.Id,suffix);NoLinks(bridgeFile);if(File.Exists(bridgeFile))File.Delete(bridgeFile);}
        }
        return "Test mod and synthetic canary files removed. Saved evidence is retained.";
    }
    static string Hash(string path){using var input=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();}
    public static string BundledHash(){using var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("Observe.CanaryMod.dll");return input is null?"":Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();}
    public EvidenceEvent[] Events(string id)
    {
        var run=Get(id);var result=new List<EvidenceEvent>();var events=FilePath(id,".events.ndjson");
        if(File.Exists(events))
        {
            NoLinks(events);if(new FileInfo(events).Length>1_000_000)throw new IOException("Canary evidence exceeds its size limit.");
            using var input=new StreamReader(new FileStream(events,FileMode.Open,FileAccess.Read,FileShare.ReadWrite));
            while(input.ReadLine() is {} line)try
            {var e=JsonSerializer.Deserialize<EvidenceEvent>(line,Evidence.Json);if(e is not null&&e.EventId==ReadEvent&&e.Timestamp>=run.Started&&e.Timestamp<=run.Expires&&e.Data.GetValueOrDefault("CanarySession")==run.Id&&e.Data.GetValueOrDefault("TargetFilename")==run.CanaryPath)result.Add(e);}catch(JsonException){}
        }
        var receipt=Read<CanaryReceipt>(FilePath(id,".receipt.json"))??Read<CanaryReceipt>(BridgePath(id,".receipt.json"));
        if(receipt is not null&&ValidReceipt(run,receipt,out var at))
        {
            if(!File.Exists(FilePath(id,".receipt.json")))Write(FilePath(id,".receipt.json"),receipt);
            var matches=result.Where(e=>ReceiptMatches(e,receipt)).ToArray();
            var fields=new Dictionary<string,string>{{"CanarySession",id},{"ProcessId",receipt.Pid.ToString()},{"ProcessStartTime",receipt.ProcessStartUtc},{"Image",matches.FirstOrDefault()?.Data.GetValueOrDefault("Image","")??"Cities2.exe"},{"Mod",receipt.Mod},{"ModPath",receipt.ModPath},{"ModSha256",receipt.ModSha256},{"TargetFilename",run.CanaryPath},{"ReportedBytes",receipt.Bytes.ToString()},{"Source","Cooperative test-mod receipt (self-reported)"},{"Observation","The harmless test mod reports reading the synthetic canary outside the game."},{"MatchingWindowsEvents",string.Join(", ",matches.Select(e=>e.Id))},{"Attribution","Self-reported mod identity; Windows confirms only the process I/O. This is not managed call-stack attribution."},{"MatchesBundledMod",(receipt.ModSha256.Equals(BundledHash(),StringComparison.OrdinalIgnoreCase)&&receipt.ModSha256.Length==64).ToString()}};
            result.Add(new("canary-receipt:"+id,"Observe/CanaryModReceipt",0,ReceiptEvent,at,fields));
        }
        return result.DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToArray();
    }
    public static bool ValidReceipt(CanaryRun run,CanaryReceipt receipt,out DateTimeOffset at)
    {
        at=default;return receipt.SessionId==run.Id&&receipt.Pid>0&&receipt.Mod=="Observe.CanaryMod"&&receipt.Bytes is >0 and <=1024&&DateTimeOffset.TryParse(receipt.CompletedUtc,out at)&&DateTimeOffset.TryParse(receipt.StartedUtc,out var started)&&DateTimeOffset.TryParse(receipt.ProcessStartUtc,out var born)&&born<=started&&started>=run.Started&&at>=started&&at<=run.Expires&&(at-started)<TimeSpan.FromSeconds(30);
    }
    public static bool ReceiptMatches(EvidenceEvent e,CanaryReceipt r)=>e.EventId==ReadEvent&&e.Data.GetValueOrDefault("ProcessId")==r.Pid.ToString()&&DateTimeOffset.TryParse(e.Data.GetValueOrDefault("ProcessStartTime"),out var born)&&DateTimeOffset.TryParse(r.ProcessStartUtc,out var reportedBirth)&&Math.Abs((born-reportedBirth).TotalMilliseconds)<1&&DateTimeOffset.TryParse(r.StartedUtc,out var start)&&DateTimeOffset.TryParse(r.CompletedUtc,out var end)&&e.Timestamp>=start.AddMilliseconds(-250)&&e.Timestamp<=end.AddSeconds(1);
    public void Poll(){foreach(var run in Runs().Take(4))foreach(var e in Events(run.Id))if(imported.Add(e.Id))Recorded?.Invoke(e);}
    public Observation Observation(string id)
    {
        var run=Get(id);var observation=new Observation{Question="Did the harmless test mod perform the unexpected file access? Explain exactly what Windows observed, what the mod reported, and the attribution limits. This exercise does not assess other mods.",Start=run.Started,End=run.Expires<DateTimeOffset.UtcNow?run.Expires:DateTimeOffset.UtcNow,Events=Events(id).ToList(),Warnings=[Limits,"Only the synthetic canary is watched by this temporary file-read sensor. It does not assess arbitrary personal-file access or other mods.","Mod identity is cooperative self-report. A matching Windows event independently identifies the process, not a specific managed mod caller.","Expected behavior for a normal gameplay mod does not include reading this purpose-built document. Game saves, configuration and logs outside the install directory can be legitimate."]};
        var sensor=Read<JsonElement?>(FilePath(id,".sensor.json"));
        if(sensor is {} s){if(s.TryGetProperty("message",out var message))observation.Warnings.Add("File-read sensor: "+message.GetString());if(s.TryGetProperty("eventsLost",out var lost)&&lost.GetInt64()>0)observation.Warnings.Add("Windows trace reported "+lost.GetInt64()+" lost events. Capture is incomplete.");}
        else observation.Warnings.Add("No Windows sensor status was saved for this exercise.");
        return observation;
    }
    public object View()
    {
        var runs=Runs();var last=runs.FirstOrDefault();var events=last is null?[]:Events(last.Id);
        return new{installed=File.Exists(ModPath),modPath=ModPath,active=Active,latest=last,sensor=last is null?null:Read<JsonElement?>(FilePath(last.Id,".sensor.json")),events,findings=Evidence.Detect(events),runs=runs.Select(r=>new{r.Id,r.Started,r.Expires}),limits=Limits};
    }
}
