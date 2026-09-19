using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace Observe;

public static class WorkspaceTests
{
    static void Check(bool condition,string message){if(!condition)throw new Exception(message);}
    public sealed class FoxApi(string status="ok",HttpStatusCode http=HttpStatusCode.OK):HttpMessageHandler
    {
        public int Calls;public string Body="";public bool SafeEndpoint;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++;Body=await request.Content!.ReadAsStringAsync(token);SafeEndpoint=request.RequestUri?.AbsoluteUri=="https://threatfox-api.abuse.ch/api/v1/"&&request.Headers.GetValues("Auth-Key").Single()=="fox-test-key";
            return new(http){Content=new StringContent(JsonSerializer.Serialize(new{query_status=status,data=new[]{new{id="42",ioc="8.8.8.8:443",malware_printable="Synthetic test",threat_type_desc="Synthetic indicator",confidence_level=80,first_seen="2026-09-18",last_seen="2026-09-19"}}}),Encoding.UTF8,"application/json")};
        }
    }
    public static TrackedRun Fixture()
    {
        var at=DateTimeOffset.UtcNow.AddMinutes(-3);var run=new TrackedRun{Path=@"C:\Games\game.exe",Name="Test game",RootPid=70,Started=at};
        void E(string id,int type,int seconds,params (string,string)[] fields)=>run.Events.Add(new(id,Collector.Channels[0],seconds,type,at.AddSeconds(seconds),fields.ToDictionary(x=>x.Item1,x=>x.Item2)));
        E("root",1,0,("Image",run.Path),("ProcessId","70"),("ProcessGuid","root-guid"));
        E("child",1,1,("Image",@"C:\Windows\powershell.exe"),("ProcessId","71"),("ParentProcessId","70"),("ParentProcessGuid","root-guid"),("ProcessGuid","child-guid"));
        E("root-network",3,2,("Image",run.Path),("ProcessId","70"),("ProcessGuid","root-guid"),("DestinationIp","8.8.8.8"),("DestinationPort","443"));
        E("root-end",5,3,("Image",run.Path),("ProcessId","70"),("ProcessGuid","root-guid"));
        E("file",11,4,("Image",@"C:\Windows\powershell.exe"),("ProcessId","71"),("ProcessGuid","child-guid"),("TargetFilename",@"C:\test.txt"));
        E("reuse",1,5,("Image",@"C:\Other\other.exe"),("ProcessId","70"),("ProcessGuid","other-guid"));
        E("wrong-network",3,6,("Image",@"C:\Other\other.exe"),("ProcessId","70"),("DestinationIp","1.1.1.1"));
        E("late-child",1,7,("Image",@"C:\Other\wrong.exe"),("ProcessId","90"),("ParentProcessGuid","root-guid"),("ProcessGuid","wrong-child"));
        E("child-end",5,8,("Image",@"C:\Windows\powershell.exe"),("ProcessId","71"),("ProcessGuid","child-guid"));
        E("after-exit",11,9,("Image",@"C:\Windows\powershell.exe"),("ProcessId","71"),("ProcessGuid","child-guid"),("TargetFilename",@"C:\wrong.txt"));
        return run;
    }
    public static async Task<int> Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"ObserveWorkspaceTests-"+Guid.NewGuid());Directory.CreateDirectory(root);var tests=new List<object>();var failed=0;
        async Task Test(string name,Func<Task> action){try{await action();tests.Add(new{name,passed=true});}catch(Exception e){failed++;tests.Add(new{name,passed=false,error=e.ToString()});}}
        Task Sync(Action action){action();return Task.CompletedTask;}
        var plugins=new PluginStore(Path.Combine(root,"settings"),Path.Combine(root,"config.toml"));
        try
        {
            await Test("New features require no credentials and ThreatFox is disabled by default",()=>Sync(()=>{var s=plugins.Load();Check(!s.ThreatFox&&s.ThreatFoxKey==""&&!s.GamePerformance,"Unexpected opt-in defaults");}));
            await Test("Tracked process trees include surviving children and bound PID reuse and exits",()=>Sync(()=>
            {
                var run=Fixture();var data=TrackedCorrelation.Read(run);var ids=data.Events.Select(e=>e.Id).ToHashSet();
                Check(data.Processes.Length==2&&ids.Contains("file")&&ids.Contains("root-network"),"Lost root or surviving child");
                Check(new[]{"reuse","wrong-network","late-child","after-exit"}.All(id=>!ids.Contains(id)),"False attribution across lifetime or PID reuse");Check(data.Findings.Any(f=>f.Title.Contains("child process")),"Missing shell child finding");
            }));
            await Test("Exact root launch distinguishes simultaneous identical executables",()=>Sync(()=>
            {
                var run=Fixture();run.Events.Add(new("other-root",Collector.Channels[0],22,1,run.Started,new(){{"Image",run.Path},{"ProcessId","999"},{"ProcessGuid","second-game"}}));
                run.Events.Add(new("other-file",Collector.Channels[0],23,11,run.Started.AddSeconds(1),new(){{"Image",run.Path},{"ProcessId","999"},{"ProcessGuid","second-game"},{"TargetFilename",@"C:\other.txt"}}));
                Check(!TrackedCorrelation.Read(run).Events.Any(e=>e.Id.StartsWith("other-")),"Selected an unrelated identical executable");
            }));
            await Test("Injection and process-access evidence is attributed to its source, not its target",()=>Sync(()=>
            {
                var run=Fixture();run.Events.Add(new("thread",Collector.Channels[0],40,8,run.Started.AddSeconds(2),new(){{"SourceProcessId","70"},{"SourceProcessGUID","root-guid"},{"SourceImage",run.Path},{"TargetImage",@"C:\Windows\explorer.exe"},{"TargetProcessId","501"}}));
                run.Events.Add(new("access",Collector.Channels[0],41,10,run.Started.AddSeconds(2),new(){{"SourceProcessId","71"},{"SourceProcessGUID","child-guid"},{"SourceImage",@"C:\Windows\powershell.exe"},{"TargetImage",@"C:\Windows\System32\lsass.exe"},{"TargetProcessId","502"},{"GrantedAccess","0x1010"}}));
                run.Events.Add(new("other-source",Collector.Channels[0],42,8,run.Started.AddSeconds(2),new(){{"SourceProcessId","999"},{"SourceProcessGUID","unrelated"},{"SourceImage",@"C:\other.exe"},{"TargetImage",run.Path},{"TargetProcessId","70"}}));
                var evidence=TrackedCorrelation.Read(run);Check(evidence.Events.Any(e=>e.Id=="thread")&&evidence.Events.Any(e=>e.Id=="access")&&!evidence.Events.Any(e=>e.Id=="other-source"),"Wrong source attribution");Check(evidence.Findings.Any(f=>f.Title.Contains("remote thread"))&&evidence.Findings.Any(f=>f.Title.Contains("security process")),"Missing sensitive operation findings");
            }));
            await Test("PID-only network evidence rejects a mismatched process birth time",()=>Sync(()=>
            {
                var run=Fixture();run.Events.Add(new("wrong-birth","Observe/LiveNetwork",10,NetworkMonitor.ConnectionEvent,run.Started.AddSeconds(2),new(){{"Image",run.Path},{"ProcessId","70"},{"ProcessStartTime",run.Started.AddMinutes(1).ToString("O")},{"RemoteIp","8.8.4.4"}}));Check(!TrackedCorrelation.Read(run).Events.Any(e=>e.Id=="wrong-birth"),"Mismatched process instance attached");
            }));
            await Test("Launch history survives restart and unfinished recordings disclose interruption",()=>Sync(()=>
            {
                var run=Fixture();var directory=Path.Combine(root,"launches");Directory.CreateDirectory(directory);File.WriteAllText(Path.Combine(directory,run.Id+".json"),JsonSerializer.Serialize(run,Evidence.Json));using var history=new TrackedLaunches(directory);Check(history.List().Length==1&&history.Get(run.Id).Status=="interrupted","History lost interruption");try{history.Get("../escape");throw new Exception("Path traversal accepted");}catch(ArgumentException){}
            }));
            await Test("Network snapshot aggregates apps and ETW bytes without claiming cache attribution",()=>Sync(()=>
            {
                var at=DateTimeOffset.UtcNow;EvidenceEvent E(string id,string direction,string bytes)=>new(id,"Observe/LiveNetwork",1,NetworkMonitor.TransferEvent,at.AddSeconds(-1),new(){{"Image",@"C:\Games\game.exe"},{"ProcessId","70"},{"RemoteIp","8.8.8.8"},{"RemotePort","443"},{"Protocol","TCP"},{"Direction",direction},{"Bytes",bytes}});
                var events=new[]{E("up","Send","400"),E("down","Receive","900"),new EvidenceEvent("cache","Observe/LiveNetwork",2,NetworkMonitor.CacheEvent,at,new(){{"QueryName","wrong.example"},{"QueryResults","8.8.8.8"}})};
                var snapshot=NetworkSnapshots.Create(events,60,icons:false,now:at);Check(snapshot.Flows.Length==1&&snapshot.Apps.Length==1&&snapshot.Apps[0].Upload==400&&snapshot.Apps[0].Download==900,"Wrong flow/byte totals");Check(snapshot.Flows[0].Domain==""&&snapshot.Traffic.Sum(b=>b.Download)==900,"Cache falsely attributed or chart bytes lost");
                var plain=NetworkSnapshots.Create(Fixture().Events,60,icons:false);Check(plain.Apps.All(a=>a.Download is null&&a.Upload is null),"Unknown bytes shown as measured zero");
            }));
            await Test("Country map uses longest prefix and never geolocates private destinations",()=>Sync(()=>
            {
                var map=new CountryMap("CIDR,country\n8.0.0.0/8,US\n8.8.8.0/24,DK\n192.168.0.0/16,DE\n");Check(map.Find("8.8.8.8")=="DK"&&map.Find("8.1.1.1")=="US"&&map.Find("192.168.1.1")==""&&map.Find("1.1.1.1")=="","Invented country or wrong prefix");
                try{_ = new CountryMap("8.8.8.0/33,US");throw new Exception("Invalid prefix accepted");}catch(ArgumentException){}
            }));
            await Test("Ownerless TCP rows never imply that the idle process made a call",()=>Sync(()=>
            {
                var record=new EvidenceEvent("ownerless","Observe/LiveNetwork",1,NetworkMonitor.ConnectionEvent,DateTimeOffset.UtcNow.AddSeconds(-1),new(){{"Image","Idle.exe"},{"ProcessId","0"},{"RemoteIp","8.8.8.8"},{"State","TimeWait"}});
                var snapshot=NetworkSnapshots.Create([record],60,icons:false);Check(snapshot.Flows[0].Process.StartsWith("Unattributed")&&snapshot.Apps[0].Pids.Length==0,"Idle process falsely attributed to a closed connection");
            }));
            await Test("ThreatFox rejects local destinations and validates hash/domain inputs",()=>Sync(()=>
            {
                foreach(var ip in new[]{"127.0.0.1","192.168.1.1","10.1.1.1","172.16.1.2","::1","::ffff:192.168.1.1","fe80::1","fc00::1","printer.local","https://example.com/path"}){try{ThreatFoxClient.Validate(ip);throw new Exception("Accepted "+ip);}catch(ArgumentException){}}
                Check(ThreatFoxClient.Validate("EXAMPLE.COM")=="example.com"&&ThreatFoxClient.Validate(new string('a',64)).Length==64,"Valid indicator rejected");
            }));
            await Test("ThreatFox needs opt-in, encrypts keys, caches lookups and uses exact searches",async()=>
            {
                var fox=new ThreatFoxClient(plugins);try{await fox.Search("8.8.8.8",handler:new FoxApi());throw new Exception("Lookup accepted before configuration");}catch(InvalidOperationException){}
                var s=plugins.Load();s.ThreatFox=true;s.ThreatFoxKey=PluginStore.Protect("fox-test-key");plugins.Save(s);var handler=new FoxApi();var result=await fox.Search("8.8.8.8",handler:handler);
                Check(result.Status=="match"&&result.Matches.Length==1&&handler.SafeEndpoint&&handler.Body.Contains("exact_match")&&!handler.Body.Contains("fox-test-key"),"Incorrect request or result");await fox.Search("8.8.8.8",handler:handler);Check(handler.Calls==1&&!File.ReadAllText(Path.Combine(plugins.Root,"plugins.json")).Contains("fox-test-key"),"Cache failed or key leaked");
            });
            await Test("ThreatFox no-result, HTTP failure, hash search and removal are explicit",async()=>
            {
                var fox=new ThreatFoxClient(plugins);var result=await fox.Search("1.1.1.1",handler:new FoxApi("no_result"));Check(result.Status=="no_match"&&result.Matches.Length==0&&result.Note.Contains("does not establish safety"),"No-result treated as safe");
                var hash=new FoxApi();await fox.Search(new string('a',64),handler:hash);Check(hash.Body.Contains("search_hash"),"Incorrect hash query");
                try{await fox.Search("9.9.9.9",handler:new FoxApi(http:HttpStatusCode.Unauthorized));throw new Exception("Authentication error swallowed");}catch(InvalidOperationException e){Check(e.Message.Contains("401")&&!e.Message.Contains("fox-test-key"),"Bad error explanation");}
                plugins.RemoveThreatFox();Check(!plugins.Load().ThreatFox&&plugins.Load().ThreatFoxKey=="","Key retained after removal");
            });
            await Test("Game pause plan only reverts owned changes and preserves exact resume settings",()=>Sync(()=>
            {
                var before=new RegistrySetting("policy","enabled",false,"DWord",null);var full=new SetupState{Stage="configured",SysmonChanged=true,WasInstalled=false,SysmonExe="owned.exe",Registry=[before]};
                RegistrySetting Current(string p,string n)=>new(p,n,true,"DWord","1");ChannelSetting? Channel(string name)=>new(name,true,64000000,EventLogMode.Circular);
                var plan=SensorSetup.PlanGamePause(full,null,Current,Channel);Check(plan.SysmonAction=="uninstall-owned"&&plan.Previous.Registry.Single()==before&&plan.Current.Registry.Single().Value=="1"&&plan.Current.Channels.Any(c=>c.Name==Collector.Channels[0]),"Wrong pause/resume plan");
                full.WasInstalled=true;full.OriginalConfig="<Sysmon/>";plan=SensorSetup.PlanGamePause(full,null,Current,Channel);Check(plan.SysmonAction=="restore-external"&&plan.OriginalConfig=="<Sysmon/>","External Sysmon would be removed");
                plan=SensorSetup.PlanGamePause(null,null,Current,Channel);Check(plan.SysmonAction=="none"&&plan.Previous.Registry.Count==0,"Unmanaged sensors were modified");
            }));
            await Test("Older PowerShell backup wins and incomplete setup refuses pause",()=>Sync(()=>
            {
                var full=new SetupState{Stage="configured",Registry=[new("policy","enabled",true,"DWord","1")]};var ps=new SetupState{Registry=[new("policy","enabled",false,"DWord",null)]};
                var plan=SensorSetup.PlanGamePause(full,ps,(p,n)=>new(p,n,true,"DWord","1"),_=>null);Check(!plan.Previous.Registry.Single().Existed,"Original policy restoration overwritten");full.Stage="incomplete";try{SensorSetup.PlanGamePause(full,ps,(p,n)=>new(p,n,true,"DWord","1"),_=>null);throw new Exception("Incomplete setup accepted");}catch(InvalidOperationException){}
            }));
            await Test("Restart in game mode starts no collectors and blocks new capture",async()=>
            {
                var cfg=plugins.Load();cfg.GamePerformance=true;plugins.Save(cfg);await using var engine=new ObservationEngine(plugins,Path.Combine(root,"sessions"));await engine.Start();await Task.Delay(1200);Check(engine.Gaming&&engine.Snapshot().Length==0,"Collectors started while paused");
                using var doc=JsonDocument.Parse(JsonSerializer.Serialize(engine.State(),Evidence.Json));Check(doc.RootElement.GetProperty("sensors").GetProperty("trace").GetString()!.StartsWith("Off"),"Trace not off");try{await engine.Begin("test",1);throw new Exception("Paused capture accepted");}catch(InvalidOperationException){}
                cfg.GamePerformance=false;plugins.Save(cfg);
            });
            await Test("Real harmless launch records root, child and loopback calls without running user games",async()=>
            {
                using var recorder=new TrackedLaunches(Path.Combine(root,"real-launches"));using var network=new NetworkMonitor();network.Recorded+=recorder.Record;
                var probe=await recorder.Start(Environment.ProcessPath!,"--tracking-probe",["Synthetic local loopback probe"]);
                var until=DateTimeOffset.UtcNow.AddSeconds(16);bool child=false,connection=false;
                while(DateTimeOffset.UtcNow<until){recorder.Poll();network.Poll();var evidence=TrackedCorrelation.Read(recorder.Get(probe.Id));child=evidence.Processes.Any(p=>p.ParentPid==probe.RootPid);connection=evidence.Events.Any(e=>e.IsNetwork&&e.Data.GetValueOrDefault("RemoteIp")=="127.0.0.1");if(child&&connection)break;await Task.Delay(500);}
                recorder.Finish();var saved=recorder.Get(probe.Id);Check(child&&connection&&saved.Sha256.Length==64&&saved.Status=="complete","Live launch failed to link its child or loopback connection");
                // Only the bounded test probe is waited for. User applications are never terminated.
                try{using var process=Process.GetProcessById(probe.RootPid);await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));}catch(ArgumentException){}
            });
        }
        finally{Directory.Delete(root,true);}
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests},Evidence.Json));return failed==0?0:1;
    }
    public static int Probe(string[] args)
    {
        if(args[0]=="--tracking-child")
        {
            using var client=new TcpClient();client.Connect(IPAddress.Loopback,int.Parse(args[1]));client.GetStream().Write(Encoding.UTF8.GetBytes("Observe harmless tracking probe"));Thread.Sleep(5000);return 0;
        }
        using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--tracking-child");info.ArgumentList.Add(port.ToString());
        using var child=Process.Start(info)!;var accept=listener.AcceptTcpClientAsync();if(!accept.Wait(TimeSpan.FromSeconds(10)))return 1;using var peer=accept.Result;Thread.Sleep(5000);child.WaitForExit(10000);return 0;
    }
}
