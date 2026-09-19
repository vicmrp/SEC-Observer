using System.Text.Json;

namespace Observe;

public static class CanaryTests
{
    public static int Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"Observe-Canary-Tests-"+Guid.NewGuid());Directory.CreateDirectory(root);
        var checks=new List<object>();int failed=0;
        void Check(string name,Action action){try{action();checks.Add(new{name,passed=true});}catch(Exception e){failed++;checks.Add(new{name,passed=false,error=e.ToString()});}}
        void Assert(bool condition,string detail){if(!condition)throw new Exception(detail);}
        try
        {
            Check("Cities II plugin is opt-in and survives a restart",()=>{var p=new PluginStore(Path.Combine(root,"plugin"));Assert(!p.Load().CitiesModObserver,"Plugin enabled by default");var settings=p.Load();settings.CitiesModObserver=true;p.Save(settings);Assert(new PluginStore(p.Root).Load().CitiesModObserver,"Plugin preference lost");});
            var lab=new CanaryLab(Path.Combine(root,"data"),Path.Combine(root,"documents"));var run=lab.Arm(false);
            Check("Arm creates only a synthetic bounded document and durable session",()=>{Assert(File.ReadAllText(run.CanaryPath).StartsWith("OBSERVE SYNTHETIC CANARY"),"Canary missing");Assert(new FileInfo(run.CanaryPath).Length<1024,"Canary too big");Assert(lab.Get(run.Id).Id==run.Id,"Run not persisted");});
            Check("Reject path traversal test IDs",()=>{try{lab.Get("../outside");throw new Exception("Traversal allowed");}catch(ArgumentException){}});
            Check("An active test cannot be silently replaced",()=>{try{lab.Arm(false);throw new Exception("Replaced active run");}catch(InvalidOperationException){}});
            var born=run.Started.AddMinutes(-1);var at=run.Started.AddSeconds(1);
            var receipt=new CanaryReceipt{SessionId=run.Id,Pid=42,ProcessStartUtc=born.ToString("O"),StartedUtc=at.ToString("O"),CompletedUtc=at.AddMilliseconds(20).ToString("O"),Bytes=80,Mod="Observe.CanaryMod",ModPath="C:\\Game\\Observe.CanaryMod.dll",ModSha256=CanaryLab.BundledHash()};
            CanaryLab.Write(lab.BridgePath(run.Id,".receipt.json"),receipt);
            Check("A cooperative receipt alone is never a Windows finding",()=>{var events=lab.Events(run.Id);Assert(events.Length==1&&events[0].EventId==CanaryLab.ReceiptEvent,"Receipt missing");Assert(Evidence.Detect(events).Count==0,"Self-report became independent alert");Assert(events[0].Data["MatchingWindowsEvents"]=="","Invented Windows match");});
            var e=new EvidenceEvent("canary-test:1","Observe/WindowsCanary",1,CanaryLab.ReadEvent,at,new(){{"CanarySession",run.Id},{"TargetFilename",run.CanaryPath},{"ProcessId","42"},{"ProcessStartTime",born.ToString("O")},{"Image","C:\\Game\\Cities2.exe"},{"Outcome","Read requested; completion not yet observed"}});
            File.WriteAllText(lab.FilePath(run.Id,".events.ndjson"),JsonSerializer.Serialize(e)+"\n{torn");
            Check("Independent Windows read survives a torn journal tail",()=>{var events=lab.Events(run.Id);Assert(events.Any(x=>x.Id==e.Id),"Read lost");Assert(Evidence.Detect(events).Count==1,"Read did not trigger review");Assert(events.Single(x=>x.EventId==CanaryLab.ReceiptEvent).Data["MatchingWindowsEvents"]==e.Id,"Receipt didn't correlate");});
            Check("PID reuse and wrong time do not correlate a receipt",()=>{Assert(!CanaryLab.ReceiptMatches(e with{Data=new(e.Data){{"Dummy","value"}} ,Timestamp=at.AddMinutes(1)},receipt),"Time mismatch accepted");var reused=e with{Data=new(e.Data)};reused.Data["ProcessStartTime"]=born.AddSeconds(4).ToString("O");Assert(!CanaryLab.ReceiptMatches(reused,receipt),"PID reuse accepted");});
            Check("Invalid and old mod receipts are rejected",()=>{receipt.SessionId=Guid.NewGuid().ToString();Assert(!CanaryLab.ValidReceipt(run,receipt,out _),"Wrong run accepted");receipt.SessionId=run.Id;receipt.CompletedUtc=run.Started.AddMinutes(-1).ToString("O");Assert(!CanaryLab.ValidReceipt(run,receipt,out _),"Old run accepted");receipt.CompletedUtc=at.AddMilliseconds(20).ToString("O");});
            Check("Evidence payload preserves canary findings and attribution limits",()=>{var payload=JsonSerializer.Serialize(Evidence.Payload(lab.Observation(run.Id)));Assert(payload.Contains("10110")&&payload.Contains("self-report")&&payload.Contains("synthetic"),"Missing model grounding");});
            Check("Restart retains independent evidence; polling is idempotent",()=>{var reopened=new CanaryLab(Path.Combine(root,"data"),Path.Combine(root,"documents"));int count=0;reopened.Recorded+=_=>count++;reopened.Poll();reopened.Poll();Assert(count==2,"Events lost or duplicated");Assert(reopened.View() is not null,"View unavailable");});
            Check("Stop disarms the game bridge without deleting evidence",()=>{lab.Stop();Assert(!lab.Active,"Still armed");Assert(!File.Exists(Path.Combine(lab.Bridge,"armed.txt")),"Arm retained");Assert(File.Exists(lab.BridgePath(run.Id,".stop")),"Game stop marker missing");Assert(lab.Events(run.Id).Length==2&&File.Exists(lab.FilePath(run.Id,".receipt.json")),"Evidence not retained locally");});
            Check("Log export includes canary evidence but no credentials",()=>{File.WriteAllText(Path.Combine(root,"data","plugins.json"),"fake-secret");var zip=Path.Combine(root,"export.zip");LocalLogStorage.Export(Path.Combine(root,"data"),zip);using var z=System.IO.Compression.ZipFile.OpenRead(zip);Assert(z.Entries.Any(x=>x.FullName.EndsWith(".events.ndjson")),"Canary omitted");Assert(z.Entries.All(x=>!x.FullName.Contains("plugins")),"Settings leaked");});
            Check("Packaged mod is available with a SHA-256 identity",()=>Assert(CanaryLab.BundledHash().Length==64,"Mod not bundled"));
        }
        finally
        {
            // This test-owned, absolute temporary root was created above; no game or real logs are touched.
            if(Path.GetFullPath(root).StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase)&&Path.GetFileName(root).StartsWith("Observe-Canary-Tests-"))Directory.Delete(root,true);
        }
        File.WriteAllText(output,JsonSerializer.Serialize(new{passed=checks.Count-failed,failed,checks},Evidence.Json));return failed==0?0:1;
    }
}
