using System.Text.Json;
using Uvm.Bridge;

namespace Observe;

public static class CitiesModTests
{
    public static async Task<int> Run(string output)
    {
        var checks=new List<object>();int failed=0;
        void Check(string name,Action action){try{action();checks.Add(new{name,passed=true});}catch(Exception e){failed++;checks.Add(new{name,passed=false,error=e.ToString()});}}
        void Assert(bool condition,string reason){if(!condition)throw new Exception(reason);}
        Check("Unity-compatible SID matches desktop Windows identity",()=>Assert(ObserveProtocol.UserSid==System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,"Wrong Windows user SID"));
        Check("Fresh installer selects no plugins or logging dependencies",()=>{var s=new InstallSelection();var p=new PluginSettings();s.Apply(p);Assert(!p.CitiesModObserver&&!p.Observer&&!p.Unifi&&!p.ThreatFox&&s.Dependencies.Length==0&&!s.StartAtLogin,"Unexpected default integration");});
        Check("Cities integration does not require a driver or credentials",()=>{var s=new InstallSelection{Cities=true};s.Validate();var p=new PluginSettings();s.Apply(p);Assert(p.CitiesModObserver&&s.Dependencies.Length==0&&p.OpenAiKey=="","Unnecessary dependency");});
        Check("Logging selection requires explicit license acceptance",()=>{try{new InstallSelection{WindowsLogging=true}.Validate();}catch(InvalidOperationException){return;}throw new Exception("License acceptance bypassed");});
        Check("Filters converge both ways, survive restart and reject replay",()=>
        {
            var root=Path.Combine(Path.GetTempPath(),"Observe-filter-test-"+Guid.NewGuid().ToString("N"));
            try
            {
                var a=new BridgeFilters(Path.Combine(root,"a"));var b=new BridgeFilters(Path.Combine(root,"b"));
                a.Set(false,true);var old=a.Wire;b.Merge(old);Assert(!b.CodeOnly&&b.LoadedOnly,"Game edit lost");
                b.Set(true,false);a.Merge(b.Wire);Assert(a.CodeOnly&&!a.LoadedOnly,"Observe edit lost");
                Assert(!a.Merge(old),"Old snapshot clobbered edit");
                var restart=new BridgeFilters(Path.Combine(root,"a"));Assert(restart.Wire==a.Wire,"Restart lost filters");
                a.Set(false,false);b.Set(true,true);a.Merge(b.Wire);b.Merge(a.Wire);Assert(a.Wire==b.Wire,"Concurrent edits did not converge");
            }
            finally{if(Directory.Exists(root))Directory.Delete(root,true);}
        });
        Check("Malformed preferences cannot corrupt persisted filters",()=>{var f=new BridgeFilters("");var before=f.Wire;try{f.Merge("9999999999999999999|oops|1|0");}catch(InvalidDataException){Assert(f.Wire==before,"Preferences changed");return;}throw new Exception("Invalid preferences accepted");});
        Check("Paradox navigation accepts only inventory IDs and rejects URL injection",()=>
        {
            using var bridge=new CitiesModBridge(new PluginStore(Path.Combine(Path.GetTempPath(),"observe-link-fixture")),true);
            foreach(var id in new[]{"128566","https://example.com","12/../../bad","128566\n",""})
            {
                bridge.TestSnapshot(JsonSerializer.SerializeToElement(new{mods=new[]{new{key="fixture",mod_id=id}}}));
                if(id=="128566")Assert(bridge.ParadoxPage("fixture")=="https://mods.paradoxplaza.com/mods/128566/Windows","Wrong URL");
                else{try{bridge.ParadoxPage("fixture");}catch(ArgumentException){continue;}throw new Exception("Untrusted URL accepted");}
            }
        });
        var moduleId=Guid.NewGuid().ToString("D");
        var module=JsonSerializer.SerializeToElement(new{path=@"C:\Mods\UVM.dll",assembly_name="UVM, Version=0.4.0.0",assembly_mvid=moduleId});
        JsonElement Receipt(string id,string name="UVM, Version=0.4.0.0")=>JsonSerializer.SerializeToElement(new{assembly_path="",assembly_name=name,assembly_mvid=id});
        Check("Byte-loaded Unity receipt maps by module ID and full assembly name",()=>Assert(CitiesModBridge.ReceiptMatches(module,Receipt(moduleId)),"Byte-loaded receipt lost"));
        Check("An assembly name alone cannot claim another module's receipts",()=>Assert(!CitiesModBridge.ReceiptMatches(module,Receipt(Guid.NewGuid().ToString("D"))),"Unrelated receipt attached"));
        Check("A matching module ID with a different assembly name is rejected",()=>Assert(!CitiesModBridge.ReceiptMatches(module,Receipt(moduleId,"Other")),"Wrong assembly attached"));
        var now=DateTimeOffset.UtcNow;var born=now.AddMinutes(-2);var nonce=Guid.NewGuid().ToString("N");
        JsonElement Snapshot(int pid=42,string? challenge=null,DateTimeOffset? at=null,DateTimeOffset? start=null)=>JsonSerializer.SerializeToElement(new{schema=2,session=Guid.NewGuid().ToString("N"),nonce=challenge??nonce,pid,process_start=(start??born).ToString("O"),generated_at=(at??now).ToString("O"),image=@"C:\Game\Cities2.exe",mods=new[]{new{key="test",name="Fixture",loaded=true}},receipts=Array.Empty<object>()});
        void Reject(JsonElement value){try{CitiesModBridge.Validate(value,nonce,42,born,now);}catch(InvalidDataException){return;}throw new Exception("Invalid bridge snapshot accepted");}
        Check("Fresh inventory requires the pipe's PID, process lifetime, protocol and challenge",()=>CitiesModBridge.Validate(Snapshot(),nonce,42,born,now));
        Check("Reject stale snapshot",()=>Reject(Snapshot(at:now.AddSeconds(-30))));
        Check("Reject future snapshot",()=>Reject(Snapshot(at:now.AddMinutes(1))));
        Check("Reject replayed challenge",()=>Reject(Snapshot(challenge:Guid.NewGuid().ToString("N"))));
        Check("Reject reused PID",()=>Reject(Snapshot(start:born.AddMinutes(-1))));
        Check("Reject another process",()=>Reject(Snapshot(pid:43)));
        EvidenceEvent E(string id,int pid,string image,int eventId=3,DateTimeOffset? birth=null)=>new(id,"Observe/LiveNetwork",0,eventId,now,new(){{"ProcessId",pid.ToString()},{"Image",image},{"ProcessStartTime",(birth??born).ToString("O")},{"DestinationIp","192.0.2.1"}});
        var network=E("game",42,@"C:\Game\Cities2.exe");var search=E("search",84,@"C:\Windows\SearchProtocolHost.exe",CanaryLab.ReadEvent);var wrong=E("reused",42,@"C:\Game\Cities2.exe",birth:born.AddMinutes(-1));
        Check("Network event tied to game lifetime is retained",()=>Assert(CitiesModBridge.Related(Snapshot(),[network]).Single().Id=="game","Game event lost"));
        Check("SearchProtocolHost canary read is not blamed on a mod",()=>Assert(CitiesModBridge.Related(Snapshot(),[search]).Length==0,"Unrelated search activity attached"));
        Check("Events from reused PID are rejected",()=>Assert(CitiesModBridge.Related(Snapshot(),[wrong]).Length==0,"Wrong lifetime attached"));
        Check("No telemetry is not a positive safety verdict",()=>Assert(CitiesModBridge.Related(Snapshot(),[]).Length==0,"Invented evidence"));
        Check("A recorded descendant is game-tree evidence only",()=>
        {
            var child=E("child",99,@"C:\Windows\child.exe",1,now);child.Data["ParentProcessId"]="42";
            var childNetwork=E("child-net",99,@"C:\Windows\child.exe",3,now);
            Assert(CitiesModBridge.Related(Snapshot(),[child,childNetwork]).Length==2,"Descendant correlation lost");
        });
        using var framed=new MemoryStream();await ObserveProtocol.Write(framed,"UTF-8 ✓",CancellationToken.None);framed.Position=0;
        var text=await ObserveProtocol.Read(framed,100,CancellationToken.None);
        Check("Framing round-trips Unicode",()=>Assert(text=="UTF-8 ✓","Wire encoding changed"));
        foreach(var length in new[]{-1,0,ObserveProtocol.MaxBytes+1})
        {
            bool rejected=false;try{using var bad=new MemoryStream(BitConverter.GetBytes(length));await ObserveProtocol.Read(bad,ObserveProtocol.MaxBytes,CancellationToken.None);}catch(InvalidDataException){rejected=true;}
            Check("Reject hostile frame size "+length,()=>Assert(rejected,"Size accepted"));
        }
        bool torn=false;try{using var bad=new MemoryStream(new byte[]{5,0,0,0,1});await ObserveProtocol.Read(bad,100,CancellationToken.None);}catch(EndOfStreamException){torn=true;}
        Check("Torn frame fails without partial data",()=>Assert(torn,"Partial message accepted"));
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=checks.Count-failed,failed,checks},Evidence.Json));return failed==0?0:1;
    }
}
