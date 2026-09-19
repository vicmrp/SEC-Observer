using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using Uvm.Bridge;

namespace Observe;

// Local game diagnostics, not an attestation authority or an arbitrary remote-control endpoint.
public sealed class CitiesModBridge : IDisposable
{
    readonly PluginStore plugins;
    readonly bool isolated;
    readonly CancellationTokenSource stop=new();
    readonly object gate=new();
    readonly SemaphoreSlim refreshGate=new(1,1);
    readonly BridgeFilters filters;
    JsonElement? snapshot;
    DateTimeOffset received;
    string notice="Enable Cities II mod observer and Connect to Observe in UVM.";
    public CitiesModBridge(PluginStore plugins,bool isolated=false){this.plugins=plugins;this.isolated=isolated;filters=new BridgeFilters(Path.Combine(plugins.Root,"uvm-filters.txt"));}
    public object FilterView()=>new{codeOnly=filters.CodeOnly,loadedOnly=filters.LoadedOnly};
    public void SetFilters(bool codeOnly,bool loadedOnly){filters.Set(codeOnly,loadedOnly);if(!isolated)_=Refresh();}
    public void Start(){if(!isolated)_ = Task.Run(Pump);}
    internal void TestSnapshot(JsonElement data){if(!isolated)throw new InvalidOperationException("Only isolated tests can provide fixtures.");lock(gate){snapshot=data.Clone();received=DateTimeOffset.UtcNow;notice="TEST FIXTURE · not a live game";}}
    async Task Pump()
    {
        while(!stop.IsCancellationRequested)
        {
            try{if(plugins.Load().CitiesModObserver)await Refresh();
            else Disconnect("Cities II mod observer is disabled.");}
            catch(Exception e){Disconnect("Could not read plugin settings: "+e.Message);}
            try{await Task.Delay(5000,stop.Token);}catch(OperationCanceledException){break;}
        }
    }
    void Disconnect(string message){lock(gate){received=default;notice=message;}}
    public async Task Refresh()
    {
        if(!await refreshGate.WaitAsync(0))return;
        try
        {
            if(!plugins.Load().CitiesModObserver){Disconnect("Cities II mod observer is disabled.");return;}
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);timeout.CancelAfter(2500);
            using var pipe=new NamedPipeClientStream(".",ObserveProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(750,timeout.Token);
            if(!ObserveProtocol.GetNamedPipeServerProcessId(pipe.SafePipeHandle,out var pid))throw new IOException("Cannot identify UVM's game process.");
            using var game=Process.GetProcessById((int)pid);
            if(!game.ProcessName.Equals("Cities2",StringComparison.OrdinalIgnoreCase))throw new IOException("The bridge endpoint is not Cities2.exe.");
            string nonce=Guid.NewGuid().ToString("N");
            await ObserveProtocol.Write(pipe,JsonSerializer.Serialize(new{schema=2,nonce,filters=filters.Wire}),timeout.Token);
            var raw=await ObserveProtocol.Read(pipe,ObserveProtocol.MaxBytes,timeout.Token);
            using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=32});
            Validate(doc.RootElement,nonce,game.Id,game.StartTime.ToUniversalTime(),DateTimeOffset.UtcNow);
            filters.Merge(S(doc.RootElement,"filters"));
            await ObserveProtocol.Write(pipe,"ACK "+nonce,timeout.Token);
            lock(gate){if(stop.IsCancellationRequested||!plugins.Load().CitiesModObserver)return;snapshot=doc.RootElement.Clone();received=DateTimeOffset.UtcNow;notice="Connected locally to Unified Verified Mods";}
        }
        catch(Exception e)when(e is not OutOfMemoryException){Disconnect("Not connected · start Cities II, enable UVM's Observe connection, and keep Observe open. "+(e is TimeoutException or OperationCanceledException?"":e.Message));}
        finally{refreshGate.Release();}
    }
    public static void Validate(JsonElement data,string nonce,int pid,DateTimeOffset born,DateTimeOffset now)
    {
        if(data.GetProperty("schema").GetInt32()!=2||S(data,"nonce")!=nonce||data.GetProperty("pid").GetInt32()!=pid||!Guid.TryParseExact(S(data,"session"),"N",out _))throw new InvalidDataException("Bridge identity/protocol mismatch. Update both UVM and Observe.");
        if(!DateTimeOffset.TryParse(S(data,"process_start"),out var start)||Math.Abs((start-born).TotalMilliseconds)>10)throw new InvalidDataException("Game process lifetime mismatch.");
        if(!DateTimeOffset.TryParse(S(data,"generated_at"),out var at)||(now-at).TotalSeconds is < -2 or > 20)throw new InvalidDataException("UVM inventory is stale.");
        var mods=data.GetProperty("mods");
        if(mods.ValueKind!=JsonValueKind.Array||mods.GetArrayLength()>1024)throw new InvalidDataException("Mod inventory exceeds limit.");
        var keys=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var row in mods.EnumerateArray())if(S(row,"key").Length is <1 or >2048||!keys.Add(S(row,"key")))throw new InvalidDataException("Invalid or duplicate mod identity.");
        if(data.GetProperty("receipts").GetArrayLength()>200)throw new InvalidDataException("Receipt limit exceeded.");
    }
    internal static string S(JsonElement obj,string name)=>obj.ValueKind==JsonValueKind.Object&&obj.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString()??"":"";
    internal static bool Loaded(JsonElement row)=>row.TryGetProperty("loaded",out var v)&&v.ValueKind==JsonValueKind.True;
    public object View(EvidenceEvent[] events,bool monitoring)
    {
        lock(gate)
        {
            bool connected=plugins.Load().CitiesModObserver&&received!=default&&(DateTimeOffset.UtcNow-received).TotalSeconds<12;
            var relevant=connected&&snapshot is {} data?Related(data,events):[];
            return new{connected,filters=FilterView(),notice=connected?notice:notice+" Inventory below, if any, is the last received snapshot.",receivedAt=received==default?(DateTimeOffset?)null:received,inventory=snapshot,monitoring,
                counts=new{network=relevant.Count(e=>e.IsNetwork),files=relevant.Count(e=>e.EventId is 2 or 11 or 23 or 26 or CanaryLab.ReadEvent),processes=relevant.Count(e=>e.EventId is 1 or ProcessMonitor.Appeared or ProcessMonitor.Existing)},
                coverage="UVM supplies cooperative inventory and last scan results. Compiled calls indicate capability, not execution. Windows events below belong to the shared game process or a recorded descendant; no individual mod is blamed. Missing evidence is not proof of no activity."};
        }
    }
    public object Details(string key,EvidenceEvent[] events,bool monitoring)
    {
        lock(gate)
        {
            var data=snapshot??throw new InvalidOperationException("Connect to UVM first.");
            var mod=data.GetProperty("mods").EnumerateArray().FirstOrDefault(m=>S(m,"key")==key);
            if(mod.ValueKind!=JsonValueKind.Object)throw new ArgumentException("Mod is no longer in this inventory.");
            bool connected=plugins.Load().CitiesModObserver&&received!=default&&(DateTimeOffset.UtcNow-received).TotalSeconds<12;
            var related=connected&&Loaded(mod)?Related(data,events):[];
            var modules=mod.TryGetProperty("modules",out var list)?list.EnumerateArray().ToArray():[];
            var receipts=data.GetProperty("receipts").EnumerateArray().Where(e=>modules.Any(m=>ReceiptMatches(m,e))).TakeLast(100).ToArray();
            return new{mod,connected,monitoring,scanAt=S(data,"scan_at"),pid=data.GetProperty("pid").GetInt32(),processStart=S(data,"process_start"),receipts,
                sharedGameActivity=related.TakeLast(200).Select(e=>new{e.Id,e.Timestamp,e.Kind,e.Process,e.Detail,category=e.IsNetwork?"network":e.EventId is 11 or 2 or 23 or 26 or CanaryLab.ReadEvent?"file":"process",e.Data}).ToArray(),
                coverage="Process/network/file evidence is shared game activity, not per-mod attribution. Cooperative receipts can be spoofed by code inside the game. Compiled references do not establish execution; reflection, native code, indirect calls and unreadable assemblies can be missed. AI alignment assessment is not implemented and nothing is uploaded automatically."};
        }
    }
    internal static bool ReceiptMatches(JsonElement module,JsonElement receipt)
    {
        var path=S(receipt,"assembly_path").Replace('/','\\');
        if(path.Length>0&&path.Equals(S(module,"path").Replace('/','\\'),StringComparison.OrdinalIgnoreCase))return true;
        // Unity byte-loaded assemblies have no Location. Match their cooperative
        // module identity instead; a name alone could alias another mod.
        var id=S(receipt,"assembly_mvid");
        return Guid.TryParse(id,out var mvid)&&mvid!=Guid.Empty&&Guid.TryParse(S(module,"assembly_mvid"),out var other)&&mvid==other&&
            S(receipt,"assembly_name").Length>0&&S(receipt,"assembly_name")==S(module,"assembly_name");
    }
    // Anchor both PID and creation time; never attach an unrelated process (such as SearchProtocolHost).
    public static EvidenceEvent[] Related(JsonElement data,EvidenceEvent[] events)
    {
        int pid=data.GetProperty("pid").GetInt32();var born=DateTimeOffset.Parse(S(data,"process_start"));var image=S(data,"image");
        var seed=new EvidenceEvent("uvm:process-identity","Observe/UVM",0,1,born,new(){{"Image",image},{"ProcessId",pid.ToString()},{"ProcessStartTime",born.ToString("O")},{"Source","UVM pipe endpoint checked against Windows process"}});
        var run=new TrackedRun{Path=image,RootPid=pid,Started=born,Ended=DateTimeOffset.UtcNow,Events=events.Prepend(seed).ToList()};
        return TrackedCorrelation.Read(run).Events.Where(e=>e.Id!=seed.Id).OrderBy(e=>e.Timestamp).ToArray();
    }
    public void Disable(){lock(gate){snapshot=null;received=default;notice="Cities II mod observer is disabled.";}}
    public void Dispose(){stop.Cancel();Disconnect("Observe closed.");}
}
