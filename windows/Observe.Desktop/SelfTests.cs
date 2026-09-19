using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace Observe;

public static class SelfTests
{
    sealed class FakeHandler(Func<HttpRequestMessage,Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>respond(request);
    }
    public static async Task<int> Run(string output)
    {
        var results=new List<object>();var failed=0;
        async Task Test(string name,Func<Task> action){try{await action();results.Add(new{name,passed=true});}catch(Exception e){failed++;results.Add(new{name,passed=false,error=e.Message});}}
        static void Check(bool condition,string message="Assertion failed"){if(!condition)throw new Exception(message);}
        await Test("Parse namespaced Windows XML with full evidence identity",()=>{
            var e=EvidenceEvent.Parse("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>3</EventID><EventRecordID>42</EventRecordID><Channel>Test</Channel><TimeCreated SystemTime='2026-09-17T12:00:00Z'/></System><EventData><Data Name='Image'>browser.exe</Data><Data Name='DestinationIp'>203.0.113.10</Data><Data Name='DestinationPort'>443</Data></EventData></Event>");Check(e.RecordId==42&&e.EventId==3&&e.Data["DestinationIp"]=="203.0.113.10"&&e.Kind=="Connection");return Task.CompletedTask;
        });
        await Test("Malformed XML is rejected",()=>{try{EvidenceEvent.Parse("<Event/>");throw new Exception("Accepted malformed event");}catch(FormatException){}return Task.CompletedTask;});
        await Test("Synthetic demo is labelled and detects review signals",()=>{var s=Evidence.Demo();Check(s.Demo&&s.Events.Count==6&&Evidence.Detect(s.Events).Count==2);Check(s.Warnings.Any(w=>w.Contains("Synthetic")));return Task.CompletedTask;});
        await Test("DNS and connection telemetry are separate evidence types",()=>{var s=Evidence.Demo();Check(s.Events.Single(e=>e.EventId==22).Data["QueryName"]=="downloads.example.com");Check(s.Events.Single(e=>e.EventId==3).Data["DestinationIp"]=="203.0.113.10");return Task.CompletedTask;});
        await Test("Secret and identity redaction",()=>{var text=Evidence.Redact(@"C:\Users\alice\test.exe --password=hello token=abc sk-abcdefghijklmnop");Check(!text.Contains("alice")&&!text.Contains("hello")&&!text.Contains("abcdefghijklmnop"));return Task.CompletedTask;});
        await Test("Evidence payload is bounded and discloses omissions",()=>{var s=Evidence.Demo();for(var i=0;i<600;i++)s.Events.Add(new($"bulk:{i}","Test",i,1,DateTimeOffset.UtcNow,new(){{"CommandLine",new string('x',7000)}}));var json=JsonSerializer.Serialize(Evidence.Payload(s),Evidence.Json);using var p=JsonDocument.Parse(json);Check(p.RootElement.GetProperty("coverage").GetProperty("omitted").GetInt32()>0);Check(Encoding.UTF8.GetByteCount(json)<220_000);Check(p.RootElement.GetProperty("events").GetArrayLength()<=350);return Task.CompletedTask;});
        await Test("Forensic and Gaming XML retain network and process monitoring",()=>{
            foreach(var mode in new[]{"Forensic","Gaming"}){var xml=XDocument.Parse(SensorSetup.ProfileXml(mode));foreach(var name in new[]{"ProcessCreate","NetworkConnect","DnsQuery","ProcessTampering"})Check(xml.Descendants(name).Single().Attribute("onmatch")?.Value=="exclude");}return Task.CompletedTask;
        });
        await Test("Gaming disables broad file, registry and process-access detail",()=>{
            var xml=XDocument.Parse(SensorSetup.ProfileXml("Gaming"));Check(xml.Descendants("FileCreate").Single().Attribute("onmatch")?.Value=="include");Check(xml.Descendants("FileCreate").Single().Elements().Count()==1);Check(!xml.Descendants("ProcessAccess").Single().Elements().Any());Check(!xml.Descendants("CreateRemoteThread").Single().Elements().Any());return Task.CompletedTask;
        });
        await Test("Both profiles exclude clipboard content and file archives",()=>{foreach(var profile in new[]{"Gaming","Forensic"}){var xml=XDocument.Parse(SensorSetup.ProfileXml(profile));foreach(var name in new[]{"ClipboardChange","FileDelete","ImageLoad"}){var node=xml.Descendants(name).Single();Check(node.Attribute("onmatch")?.Value=="include"&&!node.Elements().Any());}}return Task.CompletedTask;});
        await Test("Inbound Sysmon connections show source IP as the remote peer",()=>
        {
            var e=new EvidenceEvent("inbound","Sysmon",1,3,DateTimeOffset.UtcNow,new(){{"Image","server.exe"},{"Initiated","false"},{"SourceIp","203.0.113.7"},{"SourcePort","50500"},{"DestinationIp","192.0.2.2"},{"DestinationPort","443"},{"Protocol","tcp"}});
            var row=NetworkView.Rows([e]).Single();Check(row.Remote=="203.0.113.7:50500"&&row.Local=="192.0.2.2:443"&&row.Activity=="Inbound connection");return Task.CompletedTask;
        });
        await Test("Cache attribution stays explicit and transfer bytes aggregate by direction",()=>
        {
            EvidenceEvent Transfer(string id,string direction)=>new(id,"Observe/LiveNetwork",1,NetworkMonitor.TransferEvent,DateTimeOffset.UtcNow,new(){{"Image","app.exe"},{"ProcessId","42"},{"RemoteIp","203.0.113.1"},{"RemotePort","443"},{"LocalIp","192.0.2.1"},{"LocalPort","51000"},{"DomainCandidate","example.com"},{"Source","Network ETW"},{"Direction",direction},{"Bytes","100"},{"Protocol","TCP"}});
            var rows=NetworkView.Rows([Transfer("a","Send"),Transfer("b","Send"),Transfer("c","Receive")]).ToArray();
            Check(rows.Length==2&&rows.All(r=>r.Domain.Contains("cache match"))&&rows.Single(r=>r.Activity=="Send").Bytes=="200"&&rows.Single(r=>r.Activity=="Receive").Bytes=="100");return Task.CompletedTask;
        });
        var payload=JsonSerializer.Serialize(Evidence.Payload(Evidence.Demo()),Evidence.Json);
        const string report="""{"verdict":"review","summary":"Check the evidence.","findings":[],"limitations":[],"nextSteps":[]}""";
        await Test("Valid report retains independent coverage caveat",()=>{Check(Analysis.ValidateAndFormat(report,payload).Contains("not proof"));return Task.CompletedTask;});
        await Test("Invented evidence references reject the AI report",()=>{var invalid="""{"verdict":"review","summary":"Test","findings":[{"severity":"high","title":"Claim","detail":"Test","evidenceIds":["invented"],"recommendation":"Inspect"}],"limitations":[],"nextSteps":[]}""";try{Analysis.ValidateAndFormat(invalid,payload);throw new Exception("Invalid citation accepted");}catch(InvalidDataException){}return Task.CompletedTask;});
        await Test("Empty evidence cannot get a clean assessment",()=>{var empty=JsonSerializer.Serialize(Evidence.Payload(new Observation()),Evidence.Json);Check(Analysis.ValidateAndFormat(report,empty).Contains("insufficient_evidence"));return Task.CompletedTask;});
        await Test("Direct Astra request has structured output, no tools and store false",async()=>{
            var handler=new FakeHandler(async request=>{Check(request.RequestUri!.AbsoluteUri=="https://api.openai.com/v1/responses");var body=await request.Content!.ReadAsStringAsync();using var doc=JsonDocument.Parse(body);Check(doc.RootElement.GetProperty("model").GetString()=="gpt-6-astra");Check(!doc.RootElement.GetProperty("store").GetBoolean());Check(!doc.RootElement.TryGetProperty("tools",out _));Check(doc.RootElement.GetProperty("text").GetProperty("format").GetProperty("strict").GetBoolean());return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{status="completed",output=new[]{new{content=new[]{new{type="output_text",text=report}}}}}))};});
            Check((await Analysis.Run(payload,"test-key",null,CancellationToken.None,handler)).Contains("ASTRA ASSESSMENT"));
        });
        await Test("Managed gateway uses the existing v1 contract",async()=>{var handler=new FakeHandler(async request=>{Check(request.RequestUri!.AbsolutePath=="/v1/analyze");Check(await request.Content!.ReadAsStringAsync()==payload);return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(report)};});Check((await Analysis.Run(payload,"test-token","https://example.com",CancellationToken.None,handler)).Contains("ASTRA"));});
        await Test("Unencrypted remote gateways are rejected",async()=>{try{await Analysis.Run(payload,"test-token","http://example.com",CancellationToken.None);throw new Exception("HTTP gateway accepted");}catch(InvalidOperationException e){Check(e.Message.Contains("HTTPS"));}});
        await Test("Provider HTTP failure does not expose its body or credentials",async()=>{var handler=new FakeHandler(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized){Content=new StringContent("secret-key")}));try{await Analysis.Run(payload,"secret-key",null,CancellationToken.None,handler);throw new Exception("Failure accepted");}catch(InvalidOperationException e){Check(e.Message.Contains("401")&&!e.Message.Contains("secret-key"));}});
        await Test("Interrupted local captures recover with an explicit gap",async()=>{var directory=Path.Combine(Path.GetTempPath(),"ObserveNativeTest-"+Guid.NewGuid());try{var store=new SessionStore(directory);await store.Save(new Observation{Question="Test"});var loaded=store.Load().Single();Check(loaded.Status=="interrupted"&&loaded.Warnings.Any(w=>w.Contains("incomplete")));}finally{Directory.Delete(directory,true);}});
        await Test("Session IDs cannot traverse paths",async()=>{var directory=Path.Combine(Path.GetTempPath(),"ObserveNativeTest-"+Guid.NewGuid());try{var store=new SessionStore(directory);try{await store.Save(new Observation{Id="../bad"});throw new Exception("Unsafe path accepted");}catch(FormatException){}}finally{Directory.Delete(directory,true);}});
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=results.Count-failed,failed,tests=results},Evidence.Json));return failed==0?0:1;
    }
}
