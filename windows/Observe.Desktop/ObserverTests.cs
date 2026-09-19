using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Observe;

public static class ObserverTests
{
    public const string Subject=@"C:\Users\ExampleUser\Documents\Games\Warcraft III\Frozen Throne.exe";
    static void Check(bool condition,string message){if(!condition)throw new Exception(message);}
    public static Observation Fixture()
    {
        var at=DateTimeOffset.Parse("2026-09-17T20:00:00Z");
        EvidenceEvent E(string id,int kind,int second,params (string,string)[] fields)=>new(id,Collector.Channels[0],second,kind,at.AddSeconds(second),fields.ToDictionary(x=>x.Item1,x=>x.Item2));
        var scan=new Observation{Start=at.AddMinutes(-1),End=at.AddMinutes(5),Question="What did "+Subject+" do?",Status="complete",Events=[
            E("older-start",1,0,("Image",Subject),("ProcessGuid","old"),("ProcessId","50")),
            E("old-file",11,1,("Image",Subject),("ProcessGuid","old"),("TargetFilename",@"C:\Game\old.log")),
            E("start",1,10,("Image",Subject),("ProcessGuid","root"),("ProcessId","50")),
            E("file",11,11,("Image",Subject),("ProcessGuid","root"),("TargetFilename",@"C:\Game\settings.ini")),
            E("registry",13,12,("Image",Subject),("ProcessGuid","root"),("TargetObject",@"HKCU\Software\Warcraft III\Video"),("Details","DWORD 1")),
            E("child-start",1,13,("Image",@"C:\Game\helper.exe"),("ProcessGuid","child"),("ParentProcessGuid","root"),("ProcessId","60")),
            E("connection",3,14,("Image",Subject),("ProcessGuid","root"),("DestinationIp","203.0.113.20"),("DestinationPort","443")),
            E("exit",5,15,("Image",Subject),("ProcessGuid","root")),
            E("child-file",26,16,("Image",@"C:\Game\helper.exe"),("ProcessGuid","child"),("TargetFilename",@"C:\Game\temporary.bin")),
            E("reuse-start",1,17,("Image",@"C:\Other\unrelated.exe"),("ProcessGuid","unrelated"),("ProcessId","50")),
            E("reuse-file",11,18,("Image",@"C:\Other\unrelated.exe"),("ProcessGuid","unrelated"),("ProcessId","50"),("TargetFilename",@"C:\Other\unrelated.txt")),
            E("invalid-child",1,19,("Image",@"C:\Game\invalid.exe"),("ParentProcessGuid","root"),("ProcessGuid","invalid"),("ProcessId","70")),
            E("child-exit",5,20,("Image",@"C:\Game\helper.exe"),("ProcessGuid","child")),
            E("after-child-exit",11,21,("Image",@"C:\Game\helper.exe"),("ProcessGuid","child"),("TargetFilename",@"C:\Game\impossible.bin"))
        ]};
        scan.Events.Add(new("live-connection","Observe/LiveNetwork",90,NetworkMonitor.ConnectionEvent,at.AddSeconds(14),new(){{"ProcessId","50"},{"RemoteIp","203.0.113.20"}}));
        scan.Events.Add(new("reused-live","Observe/LiveNetwork",91,NetworkMonitor.ConnectionEvent,at.AddSeconds(18),new(){{"ProcessId","50"},{"RemoteIp","203.0.113.55"}}));
        scan.Events.Add(new("dns-cache","Observe/LiveNetwork",92,NetworkMonitor.CacheEvent,at.AddSeconds(14),new(){{"QueryName","unrelated.example"}}));
        return scan;
    }
    public sealed class FakeApi(string answer="The program wrote or overwrote its settings file. [event:file]",HttpStatusCode status=HttpStatusCode.OK,bool complete=true,int delay=0):HttpMessageHandler
    {
        public string RequestBody="";
        public bool AuthCorrect;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            RequestBody=await request.Content!.ReadAsStringAsync(token);AuthCorrect=request.Headers.Authorization?.Scheme=="Bearer"&&request.Headers.Authorization.Parameter=="observer-test-key";
            if(delay>0)await Task.Delay(delay,token);
            var data="data: "+JsonSerializer.Serialize(new{type="response.output_text.delta",delta=answer})+"\n\n";
            if(complete)data+="data: "+JsonSerializer.Serialize(new{type="response.completed",response=new{status="completed"}})+"\n\n";
            return new(status){Content=new StringContent(data,Encoding.UTF8,"text/event-stream")};
        }
    }
    public sealed class ErrorApi(string body,HttpStatusCode status=HttpStatusCode.OK):HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            var response=new HttpResponseMessage(status){Content=new StringContent(body,Encoding.UTF8,status==HttpStatusCode.OK?"text/event-stream":"application/json")};response.Headers.Add("x-request-id","req-observer-test");return Task.FromResult(response);
        }
    }
    public static string Delta(string text)=>"data: "+JsonSerializer.Serialize(new{type="response.output_text.delta",delta=text})+"\n\n";
    public sealed class StreamingApi(string prefix,bool hang=false):HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StreamContent(new InterruptedStream(prefix,hang))});
    }
    sealed class InterruptedStream(string prefix,bool hang):Stream
    {
        readonly MemoryStream initial=new(Encoding.UTF8.GetBytes(prefix));
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {
            if(initial.Position<initial.Length)return await initial.ReadAsync(buffer,token);
            if(hang)await Task.Delay(Timeout.Infinite,token);
            throw new IOException("Simulated connection interrupted after text.");
        }
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken token)=>ReadAsync(buffer.AsMemory(offset,count),token).AsTask();
        public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
        public override void Flush(){}public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing){if(disposing)initial.Dispose();base.Dispose(disposing);}
    }
    public static async Task<int> Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"ObserveObserverTests-"+Guid.NewGuid());Directory.CreateDirectory(root);
        var tests=new List<object>();int failed=0;
        async Task Test(string name,Func<Task> test){try{await test();tests.Add(new{name,passed=true});}catch(Exception e){failed++;tests.Add(new{name,passed=false,error=e.ToString()});}}
        Task Sync(Action test){test();return Task.CompletedTask;}
        var plugins=new PluginStore(Path.Combine(root,"settings"),Path.Combine(root,"config.toml"));var store=new ObserverChatStore(Path.Combine(root,"chats"));var service=new ObserverChatService(plugins,store);
        var readCount=0;
        Observation Read(string q,string path,int minutes,EvidenceEvent[] live,CancellationToken token){readCount++;var s=Fixture();s.Question=q;return ProgramEvidence.Correlate(s,path);}
        ObserverConversation? chat=null;
        try
        {
            await Test("Recognizes executable paths with spaces and an unclosed quote",()=>Sync(()=>Check(ProgramEvidence.Subject("I just opened \""+Subject+" please tell me what it did")==Subject,"Wrong full path")));
            await Test("Latest launch includes children outliving parent and excludes PID reuse, cache and events after exits",()=>Sync(()=>
            {
                var r=ProgramEvidence.Correlate(Fixture(),Subject);var ids=r.Events.Select(e=>e.Id).ToHashSet();
                Check(new[]{"start","file","registry","connection","child-start","child-file","child-exit","live-connection"}.All(ids.Contains),"Missing program/child events");
                Check(new[]{"old-file","older-start","reuse-file","reused-live","invalid-child","after-child-exit","dns-cache"}.All(id=>!ids.Contains(id)),"False attribution");
                Check(r.Investigation!.Changes.Count==3&&r.Warnings.Any(w=>w.Contains("matching launches")),"Missing timeline or ambiguity warning");
            }));
            await Test("Unmatched executable yields no invented activity",()=>Sync(()=>Check(ProgramEvidence.Correlate(Fixture(),@"C:\never.exe").Events.Count==0,"Invented match")));
            await Test("Ambiguous executable filename requires a full path",()=>Sync(()=>{var s=Fixture();s.Events.Add(new("other",Collector.Channels[0],999,1,s.Start,new(){{"Image",@"C:\Other\Frozen Throne.exe"},{"ProcessGuid","other"}}));Check(ProgramEvidence.Correlate(s,"Frozen Throne.exe").Events.Count==0,"Ambiguous filename was attributed");}));
            await Test("Missing start can use matching GUID with an explicit limitation",()=>Sync(()=>{var s=Fixture();s.Events.RemoveAll(e=>e.EventId==1&&e.Data.GetValueOrDefault("Image")==Subject);var r=ProgramEvidence.Correlate(s,Subject);Check(r.Investigation!.ExecutionStart is null&&r.Events.Any(e=>e.Id=="file")&&r.Warnings.Any(w=>w.Contains("process-start record is missing")),"Missing partial-GUID evidence");}));
            await Test("Missing plugin key prevents requests",async()=>{try{await service.Send("","hello",60,false,[],default,handler:new FakeApi(),read:Read);throw new Exception("Accepted missing key");}catch(InvalidOperationException e){Check(e.Message.Contains("API key"),e.Message);}});
            plugins.Save(new(){Observer=true,OpenAiKey=PluginStore.Protect("observer-test-key")});
            await Test("Windows protects the key and legacy cleanup preserves the observer plugin",()=>Sync(()=>{Check(!File.ReadAllText(Path.Combine(root,"settings","plugins.json")).Contains("observer-test-key"),"Plaintext key stored");plugins.RemoveLegacyConnection();Check(plugins.Load().Observer&&PluginStore.Unprotect(plugins.Load().OpenAiKey)=="observer-test-key","Observer revoked by legacy cleanup");}));
            await Test("Streaming Responses request uses real evidence, bounded context, store false and fixed OpenAI endpoint",async()=>
            {
                var handler=new FakeApi();var chunks="";chat=await service.Send("","What did "+Subject+" do?",60,false,[],default,(_,part)=>chunks+=part,handler,Read);
                Check(chat.Messages.Last().Status=="complete"&&chunks.Contains("[event:file]"),"Stream or answer failed");
                using var body=JsonDocument.Parse(handler.RequestBody);Check(handler.AuthCorrect&&!body.RootElement.GetProperty("store").GetBoolean()&&body.RootElement.GetProperty("stream").GetBoolean()&&!body.RootElement.TryGetProperty("tools",out _),"Unsafe request configuration");
                Check(handler.RequestBody.Contains("file")&&!handler.RequestBody.Contains("observer-test-key")&&!handler.RequestBody.Contains(@"Users\\ExampleUser"),"Key/path leak or missing evidence");
                Check(store.Get(chat.Id).Messages.Count==2&&store.List().Length==1,"Chat not persisted");
            });
            await Test("Follow-up preserves the original snapshot and chat context",async()=>
            {
                Check(chat is not null,"Initial chat failed");var before=readCount;var handler=new FakeApi();chat=await service.Send(chat!.Id,"Which files changed?",60,false,[],default,handler:handler,read:Read);
                Check(readCount==before&&handler.RequestBody.Contains("Which files changed?")&&handler.RequestBody.Contains("What did"),"Lost context or silently changed snapshot");
            });
            await Test("Explicit refresh gathers fresh evidence",async()=>{var before=readCount;chat=await service.Send(chat!.Id,"Check again",60,true,[],default,handler:new FakeApi(),read:Read);Check(readCount==before+1,"Refresh didn't read evidence");});
            await Test("An empty script snapshot is refreshed automatically when new telemetry becomes available",async()=>
            {
                var reads=0;const string path=@"C:\scripts\fresh-run.ps1";
                Observation RetryRead(string q,string subject,int minutes,EvidenceEvent[] live,CancellationToken token)
                {
                    reads++;var scan=new Observation{Question=q,Start=DateTimeOffset.UtcNow.AddMinutes(-15),End=DateTimeOffset.UtcNow};
                    if(reads>1)scan.Events.Add(new("fresh-block",Collector.Channels[1],1,4104,DateTimeOffset.UtcNow.AddSeconds(-1),new(){{"Path",path},{"ProcessId","42"},{"ScriptBlockId","fresh"},{"ScriptBlockText","Write-Output test"}}));
                    return ScriptInvestigation.Correlate(scan,subject);
                }
                var first=await service.Send("","What did "+path+" do?",15,false,[],default,handler:new FakeApi("Observe could not link recorded activity to this run."),read:RetryRead);
                Check(ObserverChatService.NeedsFreshEvidence(first.Messages[0].Evidence),"Empty snapshot did not request a refresh");
                var second=await service.Send(first.Id,"I opened a fresh session. Check again.",15,false,[],default,handler:new FakeApi("Script text was recorded. [event:fresh-block]"),read:RetryRead);
                Check(reads==2&&second.Messages.Last().Status=="complete"&&!ObserverChatService.NeedsFreshEvidence(second.Messages[^2].Evidence)&&second.Messages[^2].Evidence.Contains("fresh-block"),"Retry reused stale empty evidence");
                store.Delete(first.Id);
            });
            await Test("Every model bounds Unicode, evidence and history below its input/output/context budgets",()=>Sync(()=>
            {
                var evidence=Fixture();evidence.Events.Clear();
                for(var i=0;i<350;i++)evidence.Events.Add(new("budget:"+i,Collector.Channels[0],i,11,DateTimeOffset.UtcNow,new(){{"Image",Subject},{"TargetFilename",@"C:\Game\file-"+i},{"Details",string.Concat(Enumerable.Repeat("界🙂",2000))}}));
                var heavy=new ObserverConversation();for(var i=0;i<30;i++)heavy.Messages.Add(new(){Role=i%2==0?"user":"assistant",Text=new string('x',7000)});
                heavy.Messages.Add(new(){Text="Explain changes",Evidence=JsonSerializer.Serialize(Evidence.Payload(evidence),Evidence.Json)});
                foreach(var model in ObserverModels.All)
                {
                    var plan=ObserverModels.Prepare(heavy,model.Id);using var payload=JsonDocument.Parse(plan.Evidence);
                    Check(plan.TokenUpperBound<=model.InputBudget&&plan.TokenUpperBound+model.OutputBudget+2048<model.ContextWindow&&model.OutputBudget<=model.MaxOutputTokens,"Invalid model budget: "+model.Id);
                    Check(plan.Input.Last().Content=="Explain changes"&&plan.OmittedEvents>0&&plan.OmittedMessages>0&&plan.IncludedEvents<=model.EventLimit,"Missing minimization or current question");
                }
            }));
            await Test("SSE failure preserves provider reason and request ID while redacting secrets",async()=>
            {
                var body="data: "+JsonSerializer.Serialize(new{type="response.failed",response=new{id="resp-test",error=new{code="insufficient_quota",message="Billing limit for observer-test-key and sk-proj-1234567890abcdef"}}})+"\n\n";
                var result=await service.Send(chat!.Id,"Explain",60,false,[],default,handler:new ErrorApi(body),read:Read);var message=result.Messages.Last();var json=JsonSerializer.Serialize(message.Error);
                Check(message.Status=="error"&&message.ErrorMessage!.Contains("billing")&&message.Error?.RequestId=="req-observer-test"&&message.Error.ResponseId=="resp-test"&&message.Error.Code=="insufficient_quota","Lost provider diagnostics");
                Check(!json.Contains("observer-test-key")&&!json.Contains("1234567890abcdef"),"Secret leaked into error log");
            });
            await Test("HTTP errors preserve code and parameter; output exhaustion explains the budget",async()=>
            {
                var body=JsonSerializer.Serialize(new{error=new{code="context_length_exceeded",type="invalid_request_error",param="input",message="Too many input tokens."}});
                var result=await service.Send(chat!.Id,"Explain",60,false,[],default,handler:new ErrorApi(body,HttpStatusCode.BadRequest),read:Read);
                Check(result.Messages.Last().Error?.Parameter=="input"&&result.Messages.Last().ErrorMessage!.Contains("request size"),"Missing context explanation");
                body="data: "+JsonSerializer.Serialize(new{type="response.incomplete",response=new{id="resp-incomplete",incomplete_details=new{reason="max_output_tokens"}}})+"\n\n";
                result=await service.Send(chat.Id,"Explain",60,false,[],default,handler:new ErrorApi(body),read:Read);
                Check(result.Messages.Last().ErrorMessage!.Contains("response token budget")&&result.Messages.Last().Error?.OutputBudget==ObserverModels.Get(plugins.Load().ObserverModel).OutputBudget,"Missing output budget explanation");
            });
            await Test("Network floods cannot evict all process/script records or hide them after filtering",()=>Sync(()=>
            {
                var events=new List<EvidenceEvent>();var ids=new HashSet<string>();var now=DateTimeOffset.UtcNow;
                ActivityRetention.Add(events,ids,new("script",Collector.Channels[1],1,4104,now,new(){{"Path",@"C:\script.ps1"}}));
                ActivityRetention.Add(events,ids,new("process",Collector.Channels[0],2,1,now,new(){{"Image",Subject}}));
                for(var i=0;i<3000;i++)ActivityRetention.Add(events,ids,new("network-"+i,"Observe/LiveNetwork",i,NetworkMonitor.ConnectionEvent,now.AddSeconds(i+1),new()));
                Check(events.Count<=2000&&ActivityRetention.Rows(events,"scripts").Length==1&&ActivityRetention.Rows(events,"process").Length==1,"Network crowded out typed records");
                for(var i=0;i<1000;i++)ActivityRetention.Add(events,ids,new("module-"+i,Collector.Channels[1],i,4103,now.AddSeconds(i+1),new()));
                Check(ids.Contains("script")&&ActivityRetention.Rows(events,"scripts").Length<=250,"Module logging crowded out script text");
            }));
            await Test("ISE invocation XML is visible without inventing script text",()=>Sync(()=>
            {
                const string xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>24577</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-09-17T21:12:43Z'/><Execution ProcessID='42'/><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System><EventData><Data Name='FileName'>C:\\scripts\\observe-test.ps1</Data></EventData></Event>";
                var record=EvidenceEvent.Parse(xml);using var data=JsonDocument.Parse(JsonSerializer.Serialize(ForensicQueries.Scripts(new(){Events=[record]}),Evidence.Json));var entry=data.RootElement[0];
                Check(record.Data["Path"]==@"C:\scripts\observe-test.ps1"&&!entry.GetProperty("hasText").GetBoolean()&&!entry.GetProperty("complete").GetBoolean()&&entry.GetProperty("recordType").GetString()=="ISE invocation","ISE omitted or presented as complete text");
                Check(ScriptInvestigation.Correlate(new(){Events=[record],Start=record.Timestamp.AddMinutes(-1),End=record.Timestamp.AddMinutes(1)},record.Data["Path"]).Events.Any(e=>e.Id==record.Id),"ISE record omitted from observer evidence");
                var module=xml.Replace("24577","4103").Replace("<Data Name='FileName'>C:\\scripts\\observe-test.ps1</Data>","<Data Name='ContextInfo'>Script Name =\r\nCommand Path = C:\\scripts\\observe-test.ps1\r\n</Data>");
                Check(EvidenceEvent.Parse(module).Data["Path"]==@"C:\scripts\observe-test.ps1","Empty module field consumed the next field label");
            }));
            await Test("Windows log timestamps stay invariant under Danish and non-Gregorian regional settings",()=>Sync(()=>
            {
                var previous=System.Globalization.CultureInfo.CurrentCulture;
                try
                {
                    foreach(var locale in new[]{"en-DK","da-DK","ar-SA","th-TH"})
                    {
                        System.Globalization.CultureInfo.CurrentCulture=new(locale);
                        Check(Collector.EventTime(new DateTimeOffset(2026,9,17,23,12,43,TimeSpan.FromHours(2)))=="2026-09-17T21:12:43.000Z","Locale changed Windows query timestamp: "+locale);
                    }
                }
                finally{System.Globalization.CultureInfo.CurrentCulture=previous;}
            }));
            await Test("Process snapshot supplies real running processes without Sysmon access",()=>Sync(()=>
            {
                var monitor=new ProcessMonitor();var events=new List<EvidenceEvent>();monitor.Recorded+=events.Add;monitor.Poll();
                Check(events.Any(e=>e.EventId==ProcessMonitor.Existing&&e.Data.GetValueOrDefault("ProcessId")==Environment.ProcessId.ToString())&&events.All(e=>e.EventId!=1),"Missing current process or snapshot mislabelled as Sysmon start");
            }));
            await Test("Provider authentication failure is saved without exposing the key",async()=>{var r=await service.Send(chat!.Id,"Check files",60,false,[],default,handler:new FakeApi(status:HttpStatusCode.Unauthorized),read:Read);Check(r.Messages.Last().Status=="error"&&r.Messages.Last().ErrorMessage!.Contains("rejected the API key")&&!r.Messages.Last().Text.Contains("observer-test-key"),"Wrong authentication handling");});
            await Test("Incomplete streams and unverified citations retain generated text and separate diagnostics on disk",async()=>
            {
                const string partial="The settings file changed. [event:file]";
                var r=await service.Send(chat!.Id,"Check files",60,false,[],default,handler:new FakeApi(partial,complete:false),read:Read);
                var saved=store.Get(r.Id).Messages.Last();Check(saved.Status=="error"&&saved.Text==partial&&saved.ErrorMessage?.Length>0&&saved.Error?.Code=="incomplete_stream","Lost incomplete text or diagnostics");
                const string unverified="The file changed. [event:file]\nAnother claim [event:fake]";
                r=await service.Send(chat.Id,"Check files",60,false,[],default,handler:new FakeApi(unverified),read:Read);saved=store.Get(r.Id).Messages.Last();
                Check(saved.Status=="error"&&saved.Text==unverified&&saved.Error?.Code=="unverified_citations"&&saved.Error.UnverifiedCitations.SequenceEqual(new[]{"fake"})&&saved.ErrorMessage!.StartsWith("Observe could not verify"),"Citation check discarded text or blamed the provider");
                var plan=ObserverModels.Prepare(r,plugins.Load().ObserverModel);Check(!plan.Input.Any(i=>i.Role=="assistant"&&i.Content==unverified),"Unverified answer became factual conversation context");
            });
            await Test("Short citation IDs validate, remain stable on follow-up, and exclude unrelated IDs",()=>Sync(()=>
            {
                var plan=ObserverModels.Prepare(store.Get(chat!.Id),plugins.Load().ObserverModel);using var snapshot=JsonDocument.Parse(plan.Evidence);
                var item=snapshot.RootElement.GetProperty("events").EnumerateArray().Single(e=>e.GetProperty("id").GetString()=="file");var citation=item.GetProperty("citationId").GetString()!;
                Check(citation.Length==18&&citation==ObserverModels.CitationId("file"),"Alias is not short/stable");
                Check(ObserverApi.UnknownCitations($"[event:{citation}] [event:file] [event:11] [event:missing]",plan.Evidence).SequenceEqual(new[]{"11","missing"}),"Invalid alias matching");
                var next=new ObserverConversation{Messages=[new(){Text="Follow up",Evidence=plan.Evidence}]};var again=ObserverModels.Prepare(next,ObserverModels.All[0].Id);
                Check(again.Evidence.Contains(citation),"Model change invalidated the citation");
            }));
            await Test("Stop after streamed output checkpoints and preserves partial text",async()=>
            {
                const string partial="A partial answer before Stop.";using var stop=new CancellationTokenSource();var checkpoint=false;
                var r=await service.Send(chat!.Id,"Explain more",60,false,[],stop.Token,(id,part)=>{if(part.Length>0){var saved=store.Get(id).Messages.Last();checkpoint=saved.Status=="pending"&&saved.Text==partial;stop.Cancel();}},new StreamingApi(Delta(partial),hang:true),Read);
                var answer=store.Get(r.Id).Messages.Last();Check(checkpoint&&answer.Text==partial&&answer.Error?.Code=="cancelled"&&answer.ErrorMessage!.Contains("stopped"),"Stop discarded partial text or did not checkpoint");
            });
            await Test("Network interruption and provider failure after a delta retain the answer",async()=>
            {
                const string partial="Recorded activity so far. [event:file]";
                foreach(var handler in new HttpMessageHandler[]{new StreamingApi(Delta(partial)),new ErrorApi(Delta(partial)+"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\",\"message\":\"Test failure\"}}}\n\n"),new ErrorApi(Delta(partial)+"data: {\"type\":\"response.incomplete\",\"response\":{\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n")})
                {
                    var r=await service.Send(chat!.Id,"Explain",60,false,[],default,handler:handler,read:Read);var answer=store.Get(r.Id).Messages.Last();
                    Check(answer.Status=="error"&&answer.Text==partial&&answer.ErrorMessage?.Length>0,"Partial answer replaced by an error");
                }
            });
            await Test("A completed response does not wait for transport EOF",async()=>
            {
                var body=Delta("Finished. [event:file]")+"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"id\":\"resp-complete\"}}\n\n";
                var r=await service.Send(chat!.Id,"Explain",60,false,[],default,handler:new StreamingApi(body),read:Read);
                Check(r.Messages.Last().Status=="complete"&&r.Messages.Last().Text=="Finished. [event:file]","Read past terminal event into a transport failure");
            });
            await Test("Stop cancels the request and preserves the chat",async()=>{using var stop=new CancellationTokenSource(100);var r=await service.Send(chat!.Id,"Explain more",60,false,[],stop.Token,handler:new FakeApi(delay:3000),read:Read);Check(r.Messages.Last().Status=="error"&&r.Messages.Last().ErrorMessage!.Contains("stopped"),"Cancellation lost chat");});
            await Test("Removing observer clears credentials, retains chats and blocks subsequent sends",async()=>{plugins.RemoveObserver();Check(!plugins.Load().Observer&&plugins.Load().OpenAiKey==""&&store.List().Length==1,"Removal did not isolate credentials and chats");try{await service.Send(chat!.Id,"hello",60,false,[],default,handler:new FakeApi(),read:Read);throw new Exception("Removed plugin sent a request");}catch(InvalidOperationException e){Check(e.Message.Contains("API key"),e.Message);}});
            await Test("Chat IDs cannot escape storage; deletion removes only the chosen chat",()=>Sync(()=>{try{store.Delete("../plugins");throw new Exception("Traversal accepted");}catch(ArgumentException){}store.Delete(chat!.Id);Check(store.List().Length==0,"Chat remains after deletion");}));
        }
        finally{Directory.Delete(root,true);}
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests},Evidence.Json));return failed==0?0:1;
    }
}
