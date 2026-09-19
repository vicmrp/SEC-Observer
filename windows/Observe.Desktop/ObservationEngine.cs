using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace Observe;

public sealed class ObservationEngine : IAsyncDisposable
{
    readonly object gate=new();
    readonly ConcurrentQueue<EvidenceEvent> queue=new();
    readonly Collector collector=new();
    readonly ProcessMonitor processes=new();
    NetworkMonitor network=new();
    readonly SessionStore store;
    readonly PluginStore plugins;
    readonly CancellationTokenSource stop=new();
    readonly List<EvidenceEvent> live=[];
    readonly List<EvidenceEvent> networkHistory=[];
    public TrackedLaunches Launches {get;}
    public EvidenceArchive Archive {get;}
    public AppCatalog Apps {get;}
    public ProcessInspector Inspector {get;}
    public CanaryLab Canary {get;}
    public CitiesModBridge Mods {get;}
    public bool Gaming=>gaming;
    readonly HashSet<string> ids=[];
    readonly List<string> warnings=[NetworkMonitor.Coverage];
    readonly SemaphoreSlim sensorGate=new(1,1);
    Task? pump,warmup;
    Observation? capture,last;
    Observation? previewTarget;
    string approvedPreview="";
    object[] history=[];
    DateTimeOffset deadline,lastSave=DateTimeOffset.UtcNow;
    long captureBytes;
    int queued;
    bool gaming;
    public int RefreshInterval=>gaming?5000:1000;
    string[] readiness=[];
    string[] powerShellSessionWarnings=[];
    DateTimeOffset sessionsChecked;
    public string Notice {get;private set;}="Local monitoring is starting";
    public ObservationEngine(PluginStore plugins,string? storage=null){this.plugins=plugins;store=new SessionStore(storage);Archive=new(Path.Combine(plugins.Root,"evidence"));Apps=new(plugins.Root);Inspector=new(plugins.Root);Canary=new(plugins.Root);Mods=new(plugins,storage is not null);Canary.Recorded+=Enqueue;Launches=new(Path.Combine(plugins.Root,"tracked-launches")){Archive=Archive};Launches.Observed+=Enqueue;}
    public async Task Start()
    {
        Mods.Start();Archive.ImportLegacy(plugins.Root);var restored=Archive.Read(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow);Apps.Observe(restored);foreach(var e in restored.TakeLast(10000))ActivityRetention.Add(live,ids,e);
        gaming=plugins.Load().GamePerformance||SensorSetup.GameSensorsPaused;
        if(gaming){var transition=SensorSetup.GameBackup();Notice=transition is not null&&transition.Stage!="paused"&&transition.Stage!="resumed"?"Sensor transition incomplete · Observe collectors off · Restore monitoring to recover":"Game performance · Observe collectors stopped · Restore monitoring before recording";readiness=["Observe collectors are off. Pre-existing external monitoring may still run. Existing PowerShell hosts can retain their prior policy until restarted."];return;}
        readiness=(await Task.Run(Collector.Status)).ToArray();
        RefreshHistory();
        try{plugins.RemoveLegacyConnection();}catch(Exception e){Warn("Legacy connection cleanup: "+e.Message);}
        if(!SensorSetup.PolicyStatus().Contains("policy enabled"))Warn(SensorSetup.PolicyStatus());
        if(SensorSetup.Load()?.Stage!="configured")Warn("Observe has not configured Windows logging; existing Sysmon filters and event-type coverage are unknown.");
        SetPriority();
        collector.Recorded+=Enqueue;collector.Gap+=Warn;collector.Start(DateTimeOffset.UtcNow);Connect();
        processes.Recorded+=Enqueue;await Task.Run(processes.Poll);Drain();
        warmup=Task.Run(()=>
        {
            try
            {
                using var reader=new Collector();reader.Recorded+=Enqueue;reader.Gap+=Warn;
                using var limit=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);limit.CancelAfter(TimeSpan.FromSeconds(20));var now=DateTimeOffset.UtcNow;
                reader.ReadWindow(now.AddHours(-1),now,limit.Token,true,Collector.Channels.Skip(1),[4104,24577],200);
                reader.ReadWindow(now.AddHours(-1),now,limit.Token,true,Collector.Channels.Skip(1),[4103],150);
                reader.ReadWindow(now.AddHours(-1),now,limit.Token,true,[Collector.Channels[0]],[1,5],350);
            }
            catch(OperationCanceledException){if(!stop.IsCancellationRequested)Warn("Startup log read reached its time limit; live observation continues.");}
        });
        network.Gaming=gaming;await Task.Run(network.StartTrace);
        pump=Task.Run(Pump);
        Notice="Live monitoring · All evidence stays on this PC until you share it";
    }
    void Connect(){network.Recorded+=Enqueue;network.Gap+=Warn;}
    void Warn(string message){lock(gate){if(warnings.Count<100&&!warnings.Contains(message))warnings.Add(message);if(capture is not null&&!capture.Warnings.Contains(message))capture.Warnings.Add(message);}}
    void Enqueue(EvidenceEvent e){Launches.Record(e);if(Interlocked.Increment(ref queued)<=5000)queue.Enqueue(e);else{Interlocked.Decrement(ref queued);Warn("Event queue overflow; some activity was omitted.");}}
    void Drain()
    {
        lock(gate)
        {
            var batch=new List<EvidenceEvent>();
            while(queue.TryDequeue(out var e))
            {
                Interlocked.Decrement(ref queued);batch.Add(e);if(ids.Contains(e.Id))continue;ActivityRetention.Add(live,ids,e);
                if(e.IsNetwork){networkHistory.Add(e);if(networkHistory.Count>10000)networkHistory.RemoveRange(0,networkHistory.Count-10000);}
                if(capture is not null&&e.Timestamp>=capture.Start)
                {
                    var size=System.Text.Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(e,Evidence.Json));
                    if(capture.Events.Count<5000&&captureBytes+size<=16_000_000){capture.Events.Add(e);captureBytes+=size;}
                    else{if(!capture.Warnings.Contains("Capture limit reached; some activity was omitted."))capture.Warnings.Add("Capture limit reached; some activity was omitted.");deadline=DateTimeOffset.UtcNow;}
                }
            }
            if(batch.Count>0){Archive.Append(batch);Apps.Observe(batch);if(!gaming)Launches.ObserveWatched(Apps,batch.ToArray());}
        }
    }
    async Task Pump()
    {
        try
        {
            while(!stop.IsCancellationRequested)
            {
                await sensorGate.WaitAsync(stop.Token);try{network.Poll();processes.Poll();}finally{sensorGate.Release();}Drain();
                Observation? saving=null;
                lock(gate)
                {
                    if(capture is not null&&DateTimeOffset.UtcNow>=deadline){capture.End=DateTimeOffset.UtcNow;capture.Status="complete";last=capture;capture=null;saving=Copy(last);Notice="Timed capture saved to local history";}
                    else if(capture is not null&&(DateTimeOffset.UtcNow-lastSave).TotalSeconds>=(gaming?60:20)){saving=Copy(capture);lastSave=DateTimeOffset.UtcNow;}
                }
                if(saving is not null){await store.Save(saving);if(saving.Status=="complete")RefreshHistory();}
                Launches.Poll();try{if(plugins.Load().CitiesModObserver)Canary.Poll();}catch(Exception e){Warn("Canary evidence: "+e.Message);}Drain();Launches.ResumeWatched(Apps);Launches.Checkpoint();Apps.Save();
                await Task.Delay(gaming?5000:1000,stop.Token);
            }
        }
        catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        catch(Exception e){Warn("Live collector stopped: "+e.Message);Notice="Collection issue — check sensor status";}
    }
    static Observation Copy(Observation value)=>JsonSerializer.Deserialize<Observation>(JsonSerializer.Serialize(value,Evidence.Json),Evidence.Json)!;
    public EvidenceEvent[] Snapshot(){lock(gate)return live.ToArray();}
    public EvidenceEvent[] HistoryEvents(int minutes){Drain();return Archive.Read(minutes==0?DateTimeOffset.MinValue:DateTimeOffset.UtcNow.AddMinutes(-Math.Clamp(minutes,1,10080)),DateTimeOffset.UtcNow);}
    public NetworkSnapshot Network(int minutes,CountryMap? map=null)=>NetworkSnapshots.Create(HistoryEvents(minutes),minutes,map);
    public void Persist(IEnumerable<EvidenceEvent> events){Archive.Append(events);Apps.Observe(events);Apps.Save();}
    public void ExportLogs(string destination){Drain();lock(gate)LocalLogStorage.Export(plugins.Root,destination);}
    public void ClearLogs(){Drain();if(Launches.Recording||capture is not null||Canary.Active)throw new InvalidOperationException("Finish recordings and stop the canary test before deleting logs.");lock(gate){LocalLogStorage.Clear(plugins.Root);Archive.Clear();Apps.Clear();live.Clear();ids.Clear();networkHistory.Clear();history=[];last=null;}}
    public void RequireMonitoring(){if(gaming||SensorSetup.GameSensorsPaused)throw new InvalidOperationException("Restore monitoring and restart Observe before recording or reading new sensor data.");}
    void RefreshHistory(){var items=store.Load().Select(s=>(object)new{s.Id,s.Question,s.Start,s.End,s.Status,count=s.Events.Count}).ToArray();lock(gate)history=items;}
    public object State()
    {
        lock(gate)
        {
            var now=DateTimeOffset.UtcNow;using var process=Process.GetCurrentProcess();var cfg=plugins.Load();
            if(!gaming&&(now-sessionsChecked).TotalSeconds>10){powerShellSessionWarnings=SensorSetup.PowerShellSessionWarnings();sessionsChecked=now;}
            return new{version="0.12.0-beta-vibe-coded",machine=Environment.MachineName,administrator=SensorSetup.IsAdministrator,notice=Notice,gaming,tracking=Launches.Recording,recording=capture is not null,captureStart=capture?.Start,captureEnd=capture is null?(DateTimeOffset?)null:deadline,canaryAlert=live.LastOrDefault(e=>e.EventId==CanaryLab.ReadEvent),
                metrics=new{events=live.Count,network=live.Count(e=>e.IsNetwork),scripts=live.Count(e=>e.EventId==4104),signals=Evidence.Detect(live).Count,ramMb=process.WorkingSet64/1024/1024},
                pulse=Enumerable.Range(0,30).Select(i=>live.Count(e=>e.IsNetwork&&e.Timestamp>=now.AddSeconds((i-30)*2)&&e.Timestamp<now.AddSeconds((i-29)*2))).ToArray(),
                events=ActivityRetention.Rows(live),activity=new{scripts=ActivityRetention.Rows(live,"scripts"),process=ActivityRetention.Rows(live,"process"),network=ActivityRetention.Rows(live,"network")},network=NetworkView.Rows(live).ToArray(),
                sensors=new{tcp=gaming?"Off in game performance mode":network.TcpStatus,dns=gaming?"Off in game performance mode":network.DnsStatus,trace=gaming?"Off in game performance mode":network.TraceStatus,channels=readiness,policy=gaming?"Observe monitoring paused":SensorSetup.PolicyStatus(),powerShellSessionWarnings,powerShellEnabled=!gaming&&SensorSetup.PowerShellLoggingEnabled&&readiness.Any(c=>c.StartsWith(Collector.Channels[1]+": enabled"))},warnings=warnings.ToArray(),
                plugins=new{citiesModObserver=cfg.CitiesModObserver,unifi=cfg.Unifi,unifiUrl=cfg.UnifiUrl,unifiSite=cfg.UnifiSite,hasUnifiKey=cfg.UnifiKey.Length>0,certificatePin=cfg.CertificatePin,threatFox=cfg.ThreatFox,hasThreatFoxKey=cfg.ThreatFoxKey.Length>0},
                canAnalyze=capture is not null||last is not null,history};
        }
    }
    public async Task<object> Investigate(string question,string path,int minutes)
    {
        RequireIdle();var result=await Task.Run(()=>ScriptInvestigation.Read(question,path,minutes,stop.Token));await store.Save(result);
        lock(gate){last=result;previewTarget=null;approvedPreview="";Notice=$"Historical investigation ready · {result.Events.Count} related events";}RefreshHistory();return InvestigationView(result);
    }
    public static object InvestigationView(Observation s)=>new{s.Id,s.Question,s.Start,s.End,result=s.Investigation,scripts=ForensicQueries.Scripts(s),warnings=s.Warnings,report=s.Report??Analysis.LocalReport(s),events=s.Events.Take(1000).Select(e=>new{e.Id,e.Timestamp,e.Kind,e.Process,e.Detail,e.EventId}).ToArray()};
    public object OpenHistory(string id){var s=History(id);lock(gate){last=s;previewTarget=null;approvedPreview="";}return InvestigationView(s);}
    public async Task Begin(string question,int minutes)
    {
        RequireMonitoring();
        if(string.IsNullOrWhiteSpace(question)||question.Length>2000||minutes is <1 or >120)throw new ArgumentException("Enter a question and choose 1–120 minutes.");
        Observation saving;
        lock(gate)
        {
            if(capture is not null)throw new InvalidOperationException("A capture is already running.");
            capture=new(){Question=question,Warnings=warnings.ToList()};var managed=SensorSetup.Load();var coverage=managed is {Stage:"configured"}?SensorSetup.Coverage(managed.Profile):"External Sysmon configuration; event-type coverage is unknown.";capture.Profiles.Add(new(DateTimeOffset.UtcNow,gaming?"Performance":"Live",coverage+" "+NetworkMonitor.Coverage));deadline=DateTimeOffset.UtcNow.AddMinutes(minutes);captureBytes=0;lastSave=DateTimeOffset.UtcNow;saving=Copy(capture);network.ReplaySnapshot();Notice="Recording a timed capture";
        }
        await store.Save(saving);
    }
    public async Task Finish()
    {
        Drain();Observation saving;
        lock(gate){if(capture is null)return;capture.End=DateTimeOffset.UtcNow;capture.Status="complete";last=capture;capture=null;saving=Copy(last);Notice="Capture saved to local history";}
        await store.Save(saving);RefreshHistory();
    }
    public async Task Mode(bool value)
    {
        lock(gate)if(capture is not null)throw new InvalidOperationException("Stop capture before switching modes.");
        await sensorGate.WaitAsync();try{network.Dispose();gaming=value;network=new NetworkMonitor{Gaming=gaming};Connect();await Task.Run(network.StartTrace);}finally{sensorGate.Release();}
        SetPriority();Notice=gaming?"Performance mode · slower refresh, transfer tracing and AI paused":"Live mode · 1 second TCP refresh";
    }
    void SetPriority(){try{using var process=Process.GetCurrentProcess();process.PriorityClass=gaming?ProcessPriorityClass.BelowNormal:ProcessPriorityClass.Normal;}catch(Exception e){Warn("Could not adjust Observe process priority: "+e.Message);}}
    public void RequireIdle(){lock(gate)if(capture is not null)throw new InvalidOperationException("Stop capture before changing sensors or modes.");}
    public async Task RefreshReadiness(){var current=await Task.Run(Collector.Status);lock(gate)readiness=current.ToArray();collector.Start(DateTimeOffset.UtcNow);}
    public string Preview()
    {
        lock(gate){if(gaming)throw new InvalidOperationException("Return to live mode before using Astra.");previewTarget=capture??last??throw new InvalidOperationException("Investigate existing logs first.");approvedPreview=JsonSerializer.Serialize(Evidence.Payload(previewTarget),Evidence.Json);return approvedPreview;}
    }
    public async Task Analyze(string payload,string key)
    {
        if(string.IsNullOrWhiteSpace(key))throw new InvalidOperationException("Set an OpenAI API key in Settings.");
        Observation target;
        lock(gate){target=previewTarget??throw new InvalidOperationException("Preview evidence first.");if(payload!=approvedPreview||target!=(capture??last))throw new InvalidOperationException("Capture changed. Preview the evidence again.");if(gaming||target.AnalysisRequests>=10)throw new InvalidOperationException("AI is paused or this capture reached its ten-request limit.");target.AnalysisRequests++;previewTarget=null;approvedPreview="";}
        var report=await Analysis.Run(payload,key,null,stop.Token);Observation saving;lock(gate){target.Report=report;saving=Copy(target);}await store.Save(saving);
    }
    public Observation History(string id)=>store.Load().FirstOrDefault(s=>s.Id==id)??throw new ArgumentException("Capture not found.");
    public async ValueTask DisposeAsync()
    {
        Mods.Dispose();stop.Cancel();collector.Dispose();
        if(warmup is not null)try{await warmup;}catch(OperationCanceledException){}
        if(pump is not null)try{await pump;}catch(OperationCanceledException){}
        Canary.Stop();network.Dispose();Drain();await Finish();Launches.Dispose();Apps.Save();
        stop.Dispose();sensorGate.Dispose();
    }
}
