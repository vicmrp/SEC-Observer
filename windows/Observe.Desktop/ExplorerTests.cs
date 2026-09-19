using System.IO.Compression;
using System.Text.Json;

namespace Observe;

public static class ExplorerTests
{
    static void Check(bool value,string message){if(!value)throw new Exception(message);}
    public static async Task<int> Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"ObserveExplorerTests-"+Guid.NewGuid());Directory.CreateDirectory(root);var results=new List<object>();
        async Task Test(string name,Func<Task> work){try{await work();results.Add(new{name,passed=true});}catch(Exception error){results.Add(new{name,passed=false,error=error.ToString()});}}
        Task Sync(Action a){a();return Task.CompletedTask;}
        try
        {
            await Test("Delayed WMI start preserves root network and children; PID reuse is excluded",()=>Sync(()=>
            {
                var r=WorkspaceTests.Fixture();r.Events.Add(new("delayed-root","Observe/ProcessTrace",10,1,r.Started.AddSeconds(1.5),new(){{"ProcessId","70"},{"Image","game.exe"},{"ParentProcessId","999"}}));
                var linked=TrackedCorrelation.Read(r);Check(linked.Events.Any(e=>e.Id=="root-network")&&linked.Events.Any(e=>e.Id=="file")&&!linked.Events.Any(e=>e.Id=="wrong-network"),"Delayed trace broke attribution");
                r.Events.Add(new("trace-reuse","Observe/ProcessTrace",11,1,r.Started.AddSeconds(2.5),new(){{"ProcessId","70"},{"Image","game.exe"},{"ProcessStartTime",r.Started.AddSeconds(2.5).ToString("O")},{"ParentProcessId","999"}}));
                r.Events.Add(new("new-instance-network","Observe/LiveNetwork",12,10001,r.Started.AddSeconds(2.7),new(){{"Image",r.Path},{"ProcessId","70"},{"ProcessStartTime",r.Started.AddSeconds(2.5).ToString("O")},{"RemoteIp","8.8.8.8"}}));
                Check(!TrackedCorrelation.Read(r).Events.Any(e=>e.Id=="new-instance-network"),"Attributed reused PID with distinct creation time");
            }));
            await Test("Journal retains evidence beyond UI limits across restart and tolerates an interrupted tail",()=>Sync(()=>
            {
                var r=WorkspaceTests.Fixture();var archiveRoot=Path.Combine(root,"evidence");var archive=new EvidenceArchive(archiveRoot);archive.Append(r.Events);archive.Append(r.Events);
                var many=Enumerable.Range(0,2200).Select(i=>r.Events[2] with{Id="retained-"+i});archive.Append(many);
                File.AppendAllText(Directory.GetFiles(archiveRoot,"*.ndjson")[0],"{unfinished");
                var read=new EvidenceArchive(archiveRoot).Read(r.Started,DateTimeOffset.UtcNow);Check(read.Length==r.Events.Count+2200&&read.Any(e=>e.Id=="root-network"),"Journal lost or duplicated records");
                // A new writer creates a separate segment, so the torn tail cannot swallow new records.
                new EvidenceArchive(archiveRoot).Append([r.Events[0] with{Id="after-restart"}]);Check(new EvidenceArchive(archiveRoot).Read(r.Started,DateTimeOffset.UtcNow).Any(e=>e.Id=="after-restart"),"Recovery failed");
            }));
            await Test("Exports omit credentials and deletion only touches log allowlist",()=>Sync(()=>
            {
                File.WriteAllText(Path.Combine(root,"plugins.json"),"secret-test-only");Directory.CreateDirectory(Path.Combine(root,"observer-chats"));File.WriteAllText(Path.Combine(root,"observer-chats","test.json"),"{}");
                var zip=Path.Combine(root,"export.zip");LocalLogStorage.Export(root,zip);using(var input=ZipFile.OpenRead(zip)){Check(input.Entries.Any(e=>e.FullName.StartsWith("evidence"))&&input.Entries.All(e=>!e.FullName.Contains("plugins.json")),"Wrong export scope");}
                LocalLogStorage.Clear(root);Check(File.Exists(Path.Combine(root,"plugins.json"))&&File.Exists(zip)&&!Directory.GetFiles(Path.Combine(root,"evidence"),"*.ndjson").Any(),"Deletion escaped log scope");
            }));
            await Test("Known app watches and history survive restart without losing paths",()=>Sync(()=>
            {
                var c=new AppCatalog(root);c.Observe(WorkspaceTests.Fixture().Events);var app=c.All().Single(a=>a.Name=="game");c.Watch(app.Id,true);c.Save();var restored=new AppCatalog(root).All().Single(a=>a.Id==app.Id);Check(restored.Watch&&restored.Path==app.Path,"Watch preference lost");
            }));
            await Test("Same script text groups across hosts; partial fragments do not imply identical scripts",()=>Sync(()=>
            {
                var at=DateTimeOffset.UtcNow;EvidenceEvent Script(string id,string block,string pid,string text,string total="1")=>new(id,Collector.Channels[1],1,4104,at,new(){{"ScriptBlockId",block},{"ProcessId",pid},{"ScriptBlockText",text},{"MessageNumber","1"},{"MessageTotal",total},{"Path",@"C:\test.ps1"}});
                var o=new Observation{Events=[Script("a","block-a","1","Write-Output 'a'"),Script("b","block-b","2","Write-Output 'a'"),Script("c","block-c","1","Write-Output 'a'","2"),Script("d","block-d","1","Write-Output 'a'","2")]};
                var flows=ScriptWorkspace.Flows(o);Check(flows.Length==4&&flows.Where(f=>f.Complete).Select(f=>f.Fingerprint).Distinct().Count()==1&&flows.Where(f=>!f.Complete).Select(f=>f.Fingerprint).Distinct().Count()==2,"Unsafe script grouping");
                var detail=JsonSerializer.SerializeToElement(ScriptWorkspace.Details(o,flows[0].Id),Evidence.Json);Check(detail.GetProperty("evidence").GetProperty("events").GetArrayLength()==1,"Detail included unrelated script host activity");
            }));
            await Test("App chat uses saved local network identities without requiring Sysmon",()=>Sync(()=>
            {
                var at=DateTimeOffset.UtcNow.AddMinutes(-1);var data=new Dictionary<string,string>{{"Image",@"C:\Games\game.exe"},{"ProcessId","70"},{"ProcessStartTime",at.ToString("O")},{"RemoteIp","8.8.8.8"},{"RemotePort","443"}};
                var e=new EvidenceEvent("local-net","Observe/LiveNetwork",1,10001,at.AddSeconds(5),data);var r=ProgramEvidence.Correlate(new(){Start=at,End=at.AddMinutes(1),Events=[e]},@"C:\Games\game.exe");Check(r.Events.Any(e=>e.Id=="local-net"),"Local flow omitted from app chat");
            }));
            await Test("Small model includes network evidence even under a file-event flood",()=>Sync(()=>
            {
                var r=WorkspaceTests.Fixture();var o=new Observation{Events=Enumerable.Range(0,1500).Select(i=>r.Events[4] with{Id="file-"+i}).Append(r.Events[2]).Append(r.Events[0]).ToList()};
                var chat=new ObserverConversation{Messages=[new(){Text="Explain this app",Evidence=JsonSerializer.Serialize(Evidence.Payload(o),Evidence.Json)}]};
                var plan=ObserverModels.Prepare(chat,"gpt-5-nano");using var doc=JsonDocument.Parse(plan.Evidence);Check(doc.RootElement.GetProperty("events").EnumerateArray().Any(e=>e.GetProperty("id").GetString()=="root-network"),"Network starved from budget");Check(plan.TokenUpperBound<=plan.Model.InputBudget,"Exceeded token bound");
            }));
            await Test("Real process snapshot exposes this process and retains a historical snapshot",async()=>
            {
                var inspector=new ProcessInspector(root);var snapshot=await inspector.Capture();var self=snapshot.Processes.Single(p=>p.Pid==Environment.ProcessId);Check(self.Memory>0&&self.Threads>0&&self.Started is not null&&self.Image.Length>0,"Missing process identity/metrics");Check(new ProcessInspector(root).Saved() is {Saved:true},"Snapshot not durable");
                var detail=JsonSerializer.SerializeToElement(ProcessInspector.Details(self.Pid,self.Started!.Value.ToString("O")),Evidence.Json);Check(detail.GetProperty("modules").GetArrayLength()>0&&detail.GetProperty("threads").GetArrayLength()>0,"Missing modules/threads");
                try{ProcessInspector.Details(self.Pid,self.Started.Value.AddSeconds(-1).ToString("O"));throw new Exception("Reused identity accepted");}catch(InvalidOperationException){}
            });
            await Test("Reading a ps1 file is not classified as running it",()=>Sync(()=>
            {
                var at=DateTimeOffset.UtcNow;var scan=new Observation{Start=at.AddMinutes(-1),End=at.AddMinutes(1),Events=[new("read-only",Collector.Channels[0],1,1,at,new(){{"Image",@"C:\Windows\powershell.exe"},{"ProcessId","42"},{"ProcessGuid","read-guid"},{"CommandLine",@"powershell.exe -Command Get-Content C:\test.ps1"}})]};
                Check(ScriptInvestigation.Correlate(scan,@"C:\test.ps1").Investigation?.ExecutionStart is null,"Read-only command falsely proves execution");
            }));
            await Test("Watched short-lived starts create separate durable recordings for each lifetime",()=>Sync(()=>
            {
                var watchedRoot=Path.Combine(root,"watch");var catalog=new AppCatalog(watchedRoot);var fixture=WorkspaceTests.Fixture();catalog.Observe(fixture.Events);var app=catalog.All().Single(a=>a.Name=="game");catalog.Watch(app.Id,true);
                using var tracker=new TrackedLaunches(Path.Combine(watchedRoot,"tracked-launches"));tracker.ObserveWatched(catalog,fixture.Events.ToArray());Check(tracker.List().Length==1,"Missed recorded watched launch");tracker.ObserveWatched(catalog,fixture.Events.ToArray());Check(tracker.List().Length==1,"Duplicated same lifetime");tracker.Finish();
                var next=fixture.Events[0] with{Id="second-run",Timestamp=fixture.Started.AddMinutes(1)};tracker.ObserveWatched(catalog,[next]);Check(tracker.List().Length==2,"Did not track next start");
            }));
        }
        finally{try{Directory.Delete(root,true);}catch(IOException){}}
        var json=JsonSerializer.SerializeToElement(results,Evidence.Json);var failed=json.EnumerateArray().Count(r=>!r.GetProperty("passed").GetBoolean());await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=results.Count-failed,failed,tests=results},Evidence.Json));return failed==0?0:1;
    }
}
