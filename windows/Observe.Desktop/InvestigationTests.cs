using System.Text.Json;
using System.Xml.Linq;

namespace Observe;

public static class InvestigationTests
{
    static readonly DateTimeOffset At=DateTimeOffset.Parse("2026-09-17T12:00:00Z");
    const string Script=@"C:\scripts\observe-test.ps1";
    static EvidenceEvent Event(int id,int second,string guid="root",string pid="100",params (string,string)[] fields)
    {
        var data=new Dictionary<string,string>{{"ProcessGuid",guid},{"ProcessId",pid},{"Image",@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}};
        foreach(var (key,value) in fields)data[key]=value;
        return new($"fixture:{id}:{second}:{guid}",id is 4103 or 4104?Collector.Channels[1]:Collector.Channels[0],second,id,At.AddSeconds(second),data);
    }
    static EvidenceEvent Launch(int second=0,string guid="root",string pid="100")=>Event(1,second,guid,pid,("CommandLine",$"powershell.exe -File \"{Script}\""));
    static EvidenceEvent Block(int second=1)=>Event(4104,second,"root","100",("Path",Script),("ScriptBlockId","block1"),("ScriptBlockText","New-Item C:\\test\\a.txt; Remove-Item C:\\test\\a.txt"),("MessageNumber","1"),("MessageTotal","1"));
    static Observation Scan(params EvidenceEvent[] events)=>new(){Question="What did "+Script+" do?",Start=At,End=At.AddMinutes(5),Events=events.ToList()};
    static Observation Result(params EvidenceEvent[] events)=>ScriptInvestigation.Correlate(Scan(events),Script);
    public static Observation DashboardFixture()
    {
        var s=Result(Launch(),Block(),Event(11,2,fields:[("TargetFilename",@"C:\test\observe-test.txt")]),Event(12,3,fields:[("EventType","CreateKey"),("TargetObject",@"HKU\test\Software\ObserveTest")]),Event(13,4,fields:[("TargetObject",@"HKU\test\Software\ObserveTest\TestId"),("Details","DWORD (0x00000001)")]),Event(26,10,fields:[("TargetFilename",@"C:\test\observe-test.txt")]),Event(12,11,fields:[("EventType","DeleteKey"),("TargetObject",@"HKU\test\Software\ObserveTest")]));
        s.Demo=true;s.Warnings.Insert(0,"SYNTHETIC UI TEST FIXTURE. These events do not describe this PC.");return s;
    }
    static void Check(bool value,string why="Assertion failed"){if(!value)throw new Exception(why);}
    static void Reject(Action action){try{action();}catch(InvalidDataException){return;}throw new Exception("Unsupported assertion was accepted");}
    public static async Task<int> Run(string output)
    {
        var tests=new List<object>();var failed=0;
        void Test(string name,Action action){try{action();tests.Add(new{name,passed=true});}catch(Exception e){failed++;tests.Add(new{name,passed=false,error=e.ToString()});}}
        Test("Full path question extraction supports spaces and case-insensitive exact matching",()=>{
            Check(ScriptInvestigation.PathFromQuestion(@"I ran C:\some folder\observe-test.ps1 please explain")==@"C:\some folder\observe-test.ps1");
            Check(ScriptInvestigation.PathMatches(Script,Script.ToUpperInvariant()));Check(!ScriptInvestigation.PathMatches(Script+".bak",Script));Check(!ScriptInvestigation.PathMatches(@"C:\other\observe-test.ps1",Script));
        });
        Test("Retrospective matching works from process launch even without script-block logging",()=>{
            var s=Result(Launch(),Event(11,2,fields:[("TargetFilename",@"C:\test\a.txt")]));Check(s.Investigation!.Changes.Single().Operation=="create_or_overwrite");Check(s.Investigation.ProcessGuid=="root");
        });
        Test("Creation, deletion, registry set, rename and deletion produce ordered paths with references",()=>{
            var s=Result(Launch(),Block(),Event(11,2,fields:[("TargetFilename",@"C:\test\a.txt")]),Event(12,3,fields:[("EventType","CreateKey"),("TargetObject",@"HKU\user\Software\Test")]),Event(13,4,fields:[("TargetObject",@"HKU\user\Software\Test\Value"),("Details","DWORD (0x00000001)")]),Event(14,5,fields:[("TargetObject",@"HKU\user\Software\Test"),("NewName",@"HKU\user\Software\Renamed")]),Event(26,6,fields:[("TargetFilename",@"C:\test\a.txt")]),Event(12,7,fields:[("EventType","DeleteKey"),("TargetObject",@"HKU\user\Software\Renamed")]));
            Check(s.Investigation!.Changes.Select(c=>c.Operation).SequenceEqual(new[]{"create_or_overwrite","create_key","set_value","rename","delete","delete_key"}));
            Check(s.Investigation.Changes.All(c=>s.Events.Any(e=>e.Id==c.EvidenceId)));Check(s.Investigation.DirectoryContexts.SequenceEqual(new[]{@"C:\test"}));Check(s.Investigation.Changes.All(c=>c.Category!="directory"));
        });
        Test("Timestamp edits are not described as content edits",()=>{
            var s=Result(Launch(),Event(2,2,fields:[("TargetFilename",@"C:\test\a.txt"),("CreationUtcTime","2026-01-01")]));
            Check(s.Investigation!.Changes.Single().Operation=="change_creation_time");
        });
        Test("Unrelated process events are excluded and descendants are included",()=>{
            var s=Result(Launch(),Block(),Event(1,2,"child","200",("Image","cmd.exe"),("ParentProcessGuid","root")),Event(11,3,"child","200",("TargetFilename",@"C:\test\child.txt")),Event(11,4,"other","300",("TargetFilename",@"C:\test\unrelated.txt")));
            Check(s.Investigation!.Changes.Single().Path.EndsWith("child.txt"));
        });
        Test("PID reuse cannot attach a later process to an earlier script",()=>{
            var s=Result(Launch(),Block(),Event(5,4),Event(1,5,"new","100",("Image","other.exe")),Event(11,6,"new","100",("TargetFilename",@"C:\test\wrong.txt")),Event(4104,7,"new","100",("Path",@"C:\other.ps1")));
            Check(s.Investigation!.Changes.Count==0);Check(s.Events.All(e=>e.Timestamp<=At.AddSeconds(4)));
        });
        Test("Most recent matching launch is selected and earlier changes are excluded",()=>{
            var s=Result(Launch(),Event(11,2,fields:[("TargetFilename",@"C:\test\old.txt")]),Event(5,4),Launch(10,"second","101"),Event(11,12,"second","101",("TargetFilename",@"C:\test\new.txt")));
            Check(s.Investigation!.Changes.Single().Path.EndsWith("new.txt"));Check(s.Warnings.Any(x=>x.Contains("Multiple matching")));
        });
        Test("Interactive host correlation starts at the matched script block",()=>{
            var s=Result(Event(1,0,fields:[("CommandLine","powershell.exe")]),Event(11,1,fields:[("TargetFilename",@"C:\test\before.txt")]),Block(5),Event(11,6,fields:[("TargetFilename",@"C:\test\after.txt")]));
            Check(s.Investigation!.Changes.Single().Path.EndsWith("after.txt"));Check(s.Warnings.Any(x=>x.Contains("unrelated code")));
        });
        Test("Fragmented scripts retain the first fragment and intervening events",()=>{
            var first=Block(1);first.Data["MessageTotal"]="2";var last=Block(3);last.Data["MessageNumber"]="2";last.Data["MessageTotal"]="2";
            var s=Result(Launch(),first,Event(11,2,fields:[("TargetFilename",@"C:\test\between.txt")]),last);Check(s.Events.Count(e=>e.EventId==4104)==2);Check(s.Investigation!.Changes.Count==1);
        });
        Test("A final module record cannot discard script text and earlier file changes",()=>{
            var module=Event(4103,9,fields:[("Path",Script),("HostId","host"),("RunspaceId","runspace"),("PipelineId","1")]);
            var s=Result(Launch(),Block(),Event(11,2,fields:[("TargetFilename",@"C:\test\created.txt")]),module);
            Check(s.Events.Any(e=>e.EventId==4104));Check(s.Investigation!.Changes.Single().Path.EndsWith("created.txt"));Check(s.Investigation.ExecutionStart==At.AddSeconds(1));
        });
        Test("Repeated module pipelines select the newer invocation without reusing the prior compile time",()=>{
            var earlier=Event(4103,3,fields:[("Path",Script),("HostId","host"),("RunspaceId","runspace"),("PipelineId","1")]);
            var first=Event(4103,10,fields:[("Path",Script),("HostId","host"),("RunspaceId","runspace"),("PipelineId","2")]);
            var last=Event(4103,14,fields:[("Path",Script),("HostId","host"),("RunspaceId","runspace"),("PipelineId","2")]);
            var s=Result(Event(1,0,fields:[("CommandLine","powershell.exe")]),Block(),Event(11,2,fields:[("TargetFilename",@"C:\test\old.txt")]),earlier,first,Event(11,12,fields:[("TargetFilename",@"C:\test\new.txt")]),last);
            Check(s.Investigation!.ExecutionStart==At.AddSeconds(10));Check(s.Investigation.Changes.Single().Path.EndsWith("new.txt"));Check(s.Warnings.Any(w=>w.Contains("not a proven script start")));
        });
        Test("Missing process creation downgrades matching to explicit PID/time candidates",()=>{
            var s=Result(Block(),Event(26,2,fields:[("TargetFilename",@"C:\test\a.txt")]));
            Check(s.Investigation!.ProcessGuid=="");Check(s.Investigation.Changes.Single().Attribution=="PID/time candidate");
        });
        Test("No matching execution returns no invented changes and never consults source on disk",()=>{
            var s=ScriptInvestigation.Correlate(Scan(Launch(),Block()),@"C:\missing.ps1");Check(s.Events.Count==0);Check(s.Investigation!.Changes.Count==0);Check(s.Warnings.Any(x=>x.Contains("not used as evidence")));
        });
        Test("Automatic selection chooses the latest recorded PowerShell script",()=>{
            var s=ScriptInvestigation.Correlate(Scan(Launch(),Block()),"");Check(s.Investigation!.Script==Script);
        });
        Test("Only Sysmon change events can substantiate file operations",()=>{
            var e=Event(11,2,fields:[("TargetFilename",@"C:\test\a.txt")]) with{Channel="Other/provider"};Check(ScriptInvestigation.Change(e,"") is null);
        });
        Test("Forensic deletion metadata is enabled without file archiving; gaming omits broad deletes",()=>{
            Check(XDocument.Parse(SensorSetup.ProfileXml("Forensic")).Descendants("FileDeleteDetected").Single().Attribute("onmatch")!.Value=="exclude");
            Check(XDocument.Parse(SensorSetup.ProfileXml("Gaming")).Descendants("FileDeleteDetected").Single().Attribute("onmatch")!.Value=="include");
            Check(!XDocument.Parse(SensorSetup.ProfileXml("Forensic")).Descendants("FileDelete").Single().HasElements);
        });
        var change=Event(26,2,fields:[("TargetFilename",@"C:\test\a.txt")]);var observed=Result(Launch(),Block(),change);
        var payload=JsonSerializer.Serialize(Evidence.Payload(observed),Evidence.Json);
        string Report(string path=@"C:\test\a.txt",string? stamp="2026-09-17T12:00:02Z",string level="correlated",string id="fixture:26:2:root",string category="file",string operation="delete")=>JsonSerializer.Serialize(new{verdict="review",summary="Test",findings=Array.Empty<object>(),limitations=Array.Empty<string>(),nextSteps=Array.Empty<string>(),timeline=new[]{new{timestamp=stamp,category,operation,path,evidenceLevel=level,detail="Test",evidenceIds=new[]{id}}}},Evidence.Json);
        Test("AI timeline accepts a cited deletion with an exact recorded path and timestamp",()=>Check(Analysis.ValidateAndFormat(Report(),payload).Contains(@"C:\test\a.txt")));
        Test("AI timeline rejects invented paths, times, operations and directories",()=>{
            Reject(()=>Analysis.ValidateAndFormat(Report(path:@"C:\invented.txt"),payload));Reject(()=>Analysis.ValidateAndFormat(Report(stamp:"2026-09-17T13:00:00Z"),payload));
            Reject(()=>Analysis.ValidateAndFormat(Report(operation:"create_or_overwrite"),payload));Reject(()=>Analysis.ValidateAndFormat(Report(category:"directory"),payload));
        });
        Test("Script intent requires script evidence and no asserted execution time",()=>{
            Check(Analysis.ValidateAndFormat(Report(stamp:null,level:"script_intent",id:"fixture:4104:1:root"),payload).Contains("script_intent"));
            Reject(()=>Analysis.ValidateAndFormat(Report(level:"script_intent",id:"fixture:4104:1:root"),payload));Reject(()=>Analysis.ValidateAndFormat(Report(stamp:null,level:"script_intent"),payload));
        });
        Test("Historical investigation survives save and reopen with its timeline",()=>{
            var root=Path.Combine(Path.GetTempPath(),"ObserveHistoryTest-"+Guid.NewGuid());
            try{var store=new SessionStore(root);store.Save(observed).GetAwaiter().GetResult();var loaded=store.Load().Single();Check(loaded.Status=="investigation"&&loaded.Investigation!.Changes.Single().Path==@"C:\test\a.txt");}
            finally{if(Directory.Exists(root))Directory.Delete(root,true);}
        });
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests},Evidence.Json));return failed==0?0:1;
    }
}
