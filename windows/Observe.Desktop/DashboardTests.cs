using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Observe;

public static class DashboardTests
{
    static void Check(bool value,string message){if(!value)throw new Exception(message);}
    static async Task Wait(DashboardForm form,string condition,int seconds=20)
    {
        var until=DateTime.UtcNow.AddSeconds(seconds);while(DateTime.UtcNow<until){if(await form.Script("Boolean("+condition+")")=="true")return;await Task.Delay(150);}throw new TimeoutException("Dashboard condition: "+condition);
    }
    static async Task<JsonElement> Request(DashboardForm form,string action,object? args=null)
    {
        await form.Script("window.testResponse=null;window.observeTest.request("+JsonSerializer.Serialize(action)+","+JsonSerializer.Serialize(args??new{})+").then(result=>window.testResponse={ok:true,result},error=>window.testResponse={ok:false,error:error.message});");
        await Wait(form,"window.testResponse!==null",60);using var doc=JsonDocument.Parse(await form.Script("window.testResponse"));Check(doc.RootElement.GetProperty("ok").GetBoolean(),doc.RootElement.ToString());return doc.RootElement.GetProperty("result").Clone();
    }
    public static int Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"ObserveDashboard-"+Guid.NewGuid());Directory.CreateDirectory(root);
        var artifacts=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!,"dashboard-previews");Directory.CreateDirectory(artifacts);
        var tests=new List<object>();var failed=0;var code=1;
        using var form=new DashboardForm(testMode:true,testRoot:root);
        form.Shown+=async(_,_)=>
        {
            async Task Test(string name,Func<Task> action){try{await action();tests.Add(new{name,passed=true});}catch(Exception error){failed++;tests.Add(new{name,passed=false,error=error.ToString()});}await File.WriteAllTextAsync(output+".progress.json",JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests},Evidence.Json));}
            try
            {
                await form.Loaded.Task.WaitAsync(TimeSpan.FromSeconds(30));await Wait(form,"window.observeState?.data?.metrics?.events>0");
                await Test("Overview loads styled assets without retired investigation controls",async()=>
                {
                    await Wait(form,"document.querySelector('h1')?.textContent.includes('Your PC')");
                    Check(await form.Script("document.documentElement.scrollWidth<=window.innerWidth&&!document.querySelector('[data-page=assessment]')&&!document.querySelector('[data-page=history]')&&!document.querySelector('[data-action=investigate]')")=="true","Old workflow or horizontal overflow");
                    Check(await form.Script("!document.querySelector('#recent-events')&&!document.querySelector('#pulse')&&document.querySelector('[data-page=launches]')&&document.querySelector('#mode-button').textContent.includes('Game performance')")=="true","Recent activity, pulse or old mode still present");
                    Check(await form.Script("getComputedStyle(document.querySelector('.observer-welcome')).backgroundImage!=='none'")=="true","Observer styles missing");await form.CapturePreview(Path.Combine(artifacts,"overview.png"));
                    try{await form.Command("investigate",JsonSerializer.SerializeToElement(new{}));throw new Exception("Retired command accepted");}catch(ArgumentException){}
                });
                await Test("UVM table, mod details, offline coverage and untrusted text render locally",async()=>
                {
                    await Request(form,"cities-mod-enable");
                    form.SetModTestSnapshot(JsonSerializer.SerializeToElement(new{schema=1,session="fixture",generated_at=DateTimeOffset.UtcNow.ToString("O"),scan_at=DateTimeOffset.UtcNow.ToString("O"),pid=42,process_start=DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"),image=@"C:\Fixture\Cities2.exe",receipts=Array.Empty<object>(),mods=new[]{new{key="fixture-mod",mod_id="128566",name="TEST <img src=x onerror=alert(1)> Mod",version="1.0",loaded=true,availability="Loaded in this game process",folder="fixture",path=@"C:\Fixture\Mods",description="LOCAL TEST FIXTURE",build=new{status="UNKNOWN",reason="No matching evidence",verified_by=Array.Empty<string>()},capabilities=new[]{new{category="network",api="System.Net.Http.HttpClient.SendAsync",caller="Fixture.Run",assembly="Fixture.dll"}},modules=new[]{new{name="Fixture",path=@"C:\Fixture\Mods\Fixture.dll",state="Loaded"}}}}}));
                    await form.Script("go('mods')");await Wait(form,"modsData?.inventory?.mods?.length===1&&document.querySelector('#mod-rows')?.textContent.includes('Fixture')===false&&document.querySelector('[data-mod-key]')!==null");
                    Check(await form.Script("document.querySelector('#mod-connection').textContent.includes('connected')&&!document.querySelector('#mod-rows img')&&document.querySelector('#mod-rows').textContent.includes('<img')") == "true","Markup executed or table missing");
                    await form.CapturePreview(Path.Combine(artifacts,"uvm-mod-table-fixture.png"));
                    await form.Script("document.querySelector('[data-mod-inform]').click()");
                    Check(await form.Script("document.querySelector('.mod-request textarea').value.includes('not a security audit')&&document.querySelector('[data-mod-inform]').getAttribute('aria-expanded')==='true'&&document.querySelectorAll('.mod-request img').length===0")=="true","Request missing or untrusted mod name became markup");
                    await form.Script("renderMods()");
                    Check(await form.Script("!!document.querySelector('.mod-request textarea')")=="true","Refresh collapsed the request");
                    await form.Script("document.querySelector('[data-mod-copy]').click()");
                    for(var tries=0;tries<40&&form.TestClipboard.Length==0;tries++)await Task.Delay(50);
                    Check(form.TestClipboard.Contains("uvm.json")&&!form.TestClipboard.Contains(@"C:\Fixture"),"Clipboard request missing or leaked a local path");
                    await form.Script("document.querySelector('[data-mod-goto]').click()");
                    for(var tries=0;tries<40&&form.TestOpenedModPage.Length==0;tries++)await Task.Delay(50);
                    Check(form.TestOpenedModPage=="https://mods.paradoxplaza.com/mods/128566/Windows","Wrong destination");
                    await form.Script("document.querySelector('.mod-request').scrollIntoView({block:'start'})");
                    await form.CapturePreview(Path.Combine(artifacts,"inform-modder-fixture.png"));
                    await form.Script("window.scrollTo(0,0)");
                    await form.Script("document.querySelector('[data-mod-inform]').click()");

                    await form.Script("document.querySelector('[data-mod-key]').click()");await Wait(form,"document.querySelector('#modal-body')?.textContent.includes('System.Net.Http.HttpClient.SendAsync')");
                    Check(await form.Script("document.querySelector('#modal-body').textContent.includes('not per-mod attribution')&&document.querySelector('#modal-body').textContent.includes('AI alignment assessment is not implemented')") == "true","Evidence boundary missing");
                    await form.CapturePreview(Path.Combine(artifacts,"uvm-mod-detail-fixture.png"));
                    await form.Script("document.querySelector('[data-action=close-modal]').click()");
                    await form.Script("window.modFixture=modsData.inventory.mods[0];modsData.inventory.mods=[{...modFixture,is_code:true},{...modFixture,key:'asset',mod_id:'',name:'Asset pack',is_code:false,loaded:false}];renderMods()");
                    Check(await form.Script("modCodeOnly&&document.querySelectorAll('[data-mod-key]').length===1")=="true","Default code filter included assets or excluded no-API code");
                    await form.Script("document.querySelector('#mod-code-only').click()");await Wait(form,"!modFilterSaving");
                    Check(await form.Script("document.querySelectorAll('[data-mod-key]').length===2")=="true","All-mod filter did not restore asset package");
                    Check(await form.Script("document.querySelectorAll('[data-mod-inform]').length===1")=="true","Local package got a fabricated Paradox link");
                    await form.Script("document.querySelector('#mod-loaded-only').click()");await Wait(form,"!modFilterSaving");
                    Check(await form.Script("document.querySelectorAll('[data-mod-key]').length===1")=="true","Loaded-only filter included an unloaded package");
                    await form.Script("modCodeOnly=true;modLoadedOnly=false;");
                    await Request(form,"cities-mod-disable");await form.Script("go('overview')");
                });
                await Test("Canary UI separates Windows evidence and mod self-report; no real mod or sensor is launched",async()=>
                {
                    Check(await form.Script("!window.observeState.data.plugins.citiesModObserver&&getComputedStyle(document.querySelector('#cities-mod-nav')).display==='none'")=="true","Cities plugin must default off with its workspace hidden");
                    await Request(form,"cities-mod-enable",new{});await Wait(form,"window.observeState.data.plugins.citiesModObserver");
                    var lab=new CanaryLab(Path.Combine(root,"settings"),Path.Combine(root,"synthetic-documents"));var run=lab.Arm(false);
                    var e=new EvidenceEvent("canary-ui-fixture","Observe/WindowsCanary",1,CanaryLab.ReadEvent,run.Started,new(){{"CanarySession",run.Id},{"TargetFilename",run.CanaryPath},{"ProcessId","42"},{"Image","C:\\Fixture\\Cities2.exe"},{"Outcome","Read requested; completion not yet observed"}});
                    File.WriteAllText(lab.FilePath(run.Id,".events.ndjson"),JsonSerializer.Serialize(e)+"\n");lab.Stop();
                    await form.Script("go('canary')");await Wait(form,"canaryData?.events.length===1&&document.querySelector('#canary-results').textContent.includes('Windows ETW')");
                    Check(await form.Script("document.querySelector('#content').textContent.includes('self-reported')&&document.querySelector('#content').textContent.includes('does not prove')")=="true","Attribution limits missing");
                    await form.CapturePreview(Path.Combine(artifacts,"mod-safety-test.png"));
                    var chat=await Request(form,"canary-chat",new{id=run.Id});Check(chat.GetProperty("trackedRunId").GetString()=="canary:"+run.Id,"Canary evidence not bound to chat");
                    await Request(form,"observer-delete",new{id=chat.GetProperty("id").GetString()});
                    lab.Arm(false);
                    await Request(form,"cities-mod-disable",new{});await Wait(form,"!window.observeState.data.plugins.citiesModObserver");
                    Check(!lab.Active,"Disabling plugin did not disarm test");
                    await form.Script("go('overview')");
                });
                await Test("Overview storage stays still and deletion requires explicit confirmation",async()=>
                {
                    await Wait(form,"!!storageData&&document.querySelector('#storage-info').textContent.includes('evidence')");await form.Script("window.storageBefore=document.querySelector('#storage-info').innerHTML");await Task.Delay(1200);Check(await form.Script("document.querySelector('#storage-info').innerHTML===window.storageBefore")=="true","Storage changed without refresh");
                    await form.Script("document.querySelector('[data-action=storage-delete]').click()");Check(await form.Script("!!document.querySelector('#storage-confirm')&&document.querySelector('#modal-body').textContent.includes('Windows event logs')")=="true","Missing deletion scope/confirmation");
                    await form.CapturePreview(Path.Combine(artifacts,"storage-delete-confirmation.png"));await form.Script("document.querySelector('[data-action=close-modal]').click();document.querySelector('.storage-card').scrollIntoView()");await form.CapturePreview(Path.Combine(artifacts,"storage.png"));await form.Script("window.scrollTo(0,0)");
                });
                using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
                using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,port);using var server=await listener.AcceptTcpClientAsync();
                await Test("Live activity and network work without an API key",async()=>
                {
                    await Wait(form,$"window.observeState.data.network.some(r=>r.remote.includes(':{port}')||r.local.includes(':{port}'))");
                    await form.Script("window.observeTest.go('activity')");await Wait(form,"document.querySelectorAll('[data-process-pid]').length>0",45);await form.CapturePreview(Path.Combine(artifacts,"activity.png"));
                    await form.Script("window.observeTest.go('network')");await Wait(form,$"document.querySelector('#network-rows').textContent.includes(':{port}')");await form.CapturePreview(Path.Combine(artifacts,"network.png"));
                });
                await Test("Network Flows and Activity stay frozen until manual refresh",async()=>
                {
                    await Wait(form,"networkSnapshot?.flows.length>0");
                    await form.Script("window.frozenRows=document.querySelector('#network-rows').innerHTML;window.frozenAt=networkSnapshot.capturedAt");await Task.Delay(2200);
                    Check(await form.Script("document.querySelector('#network-rows').innerHTML===window.frozenRows&&networkSnapshot.capturedAt===window.frozenAt")=="true","Network changed without refresh");
                    await form.Script("document.querySelector('[data-net-tab=activity]').click()");
                    Check(await form.Script("document.querySelector('#network-title').textContent==='App Activity'&&!!document.querySelector('.traffic-chart')&&document.querySelector('#network-rows').textContent.includes('Observe')")=="true","Missing per-app activity/chart");await form.CapturePreview(Path.Combine(artifacts,"network-activity.png"));
                    await form.Script("document.querySelector('[data-net-tab=flows]').click();document.querySelector('[data-action=network-refresh]').click()");await Wait(form,"!networkLoading&&networkSnapshot.capturedAt!==window.frozenAt");await form.CapturePreview(Path.Combine(artifacts,"network-flows.png"));
                });
                await Test("Tracked apps show a saved process tree, findings and evidence without launching user software",async()=>
                {
                    var run=WorkspaceTests.Fixture();run.Name="Synthetic game recording";run.Status="complete";run.Ended=DateTimeOffset.UtcNow;var directory=Path.Combine(root,"settings","tracked-launches");Directory.CreateDirectory(directory);File.WriteAllText(Path.Combine(directory,run.Id+".json"),JsonSerializer.Serialize(run,Evidence.Json));
                    await form.Script("window.observeTest.go('launches')");await Wait(form,"!!document.querySelector('[data-tracked-id]')");await form.Script("document.querySelector('[data-tracked-id]').click()");await Wait(form,"trackedView?.evidence.processes.length===2");
                    Check(await form.Script("document.querySelector('#launch-detail').textContent.includes('A child process')&&document.querySelector('#launch-detail').textContent.includes('8.8.8.8')&&!trackedView.evidence.events.some(e=>e.id==='wrong-network')")=="true","Missing tracking view or false PID attribution");await form.CapturePreview(Path.Combine(artifacts,"tracked-app.png"));
                    await form.Script("document.querySelector('[data-tracked-event]').click()");await Wait(form,"document.querySelector('#modal-body').textContent.includes('ProcessId')");await form.Script("document.querySelector('[data-action=close-modal]').click()");
                    await form.Script("document.querySelector('[data-action=tracked-chat]').click()");await Wait(form,"observerChat?.title.includes('Synthetic game')&&document.querySelector('#chat-input').value.includes('suspicious')");
                    Check(await form.Script("JSON.parse(observerChat.messages[0].evidence).events.some(e=>e.id==='root-network')")=="true","Tracked run evidence not handed to chat");
                    await Request(form,"observer-delete",new{id=JsonDocument.Parse(await form.Script("observerChat")).RootElement.GetProperty("id").GetString()});await form.Script("observerChat=null;observerDraft='';window.observeTest.go('overview')");
                    foreach(var action in new[]{"tracked-start","performance"})try{await form.Command(action,JsonSerializer.SerializeToElement(new{}));throw new Exception("Test mutation accepted");}catch(InvalidOperationException error){Check(error.Message.Contains("disabled in UI tests"),error.Message);}
                });
                await Test("ThreatFox is opt-in with encrypted credentials, manual lookup, and removal",async()=>
                {
                    await form.Script("window.observeTest.go('plugins')");await Wait(form,"document.querySelector('#threatfox-state')?.textContent==='Not configured'");
                    await form.Script("document.querySelector('[data-action=threatfox-config]').click();document.querySelector('#threatfox-key').value='fox-test-key';document.querySelector('[data-action=threatfox-save]').click()");await Wait(form,"window.observeState.data.plugins.threatFox&&document.querySelector('#modal').classList.contains('hidden')");
                    Check(await form.Script("!JSON.stringify(window.observeState).includes('fox-test-key')")=="true"&&!File.ReadAllText(Path.Combine(root,"settings","plugins.json")).Contains("fox-test-key"),"ThreatFox key exposed");
                    form.ThreatFoxHandler=new WorkspaceTests.FoxApi();await form.Script("document.querySelector('[data-action=threatfox-manual]').click();document.querySelector('#threatfox-indicator').value='8.8.8.8';document.querySelector('[data-action=threatfox-check]').click()");await Wait(form,"document.querySelector('#modal-title').textContent.includes('Indicator match')&&document.querySelector('#modal-body').textContent.includes('Synthetic test')");await form.CapturePreview(Path.Combine(artifacts,"threatfox-result.png"));
                    await form.Script("document.querySelector('[data-action=close-modal]').click();document.querySelector('[data-action=threatfox-remove]').click()");await Wait(form,"!window.observeState.data.plugins.threatFox&&!window.observeState.data.plugins.hasThreatFoxKey");
                    await form.CapturePreview(Path.Combine(artifacts,"plugins-threatfox.png"));await form.Script("window.observeTest.go('overview')");
                });
                await Test("Observer has left chat history and requires an API key",async()=>
                {
                    await form.Script("document.querySelector('[data-page=observer]').click()");await Wait(form,"!!document.querySelector('#chat-input')");
                    Check(await form.Script("document.querySelector('#chat-send').disabled&&document.querySelector('#chat-setup').textContent.includes('API key')&&document.querySelector('.chat-history').getBoundingClientRect().right<=document.querySelector('.chat-main').getBoundingClientRect().left")=="true","Missing key gate or left history");
                    Check(await form.Script("document.documentElement.scrollWidth<=window.innerWidth")=="true","Chat overflows horizontally");await form.CapturePreview(Path.Combine(artifacts,"observer-setup.png"));
                });
                await Test("Processes show resource metrics and remain still until Refresh",async()=>
                {
                    await form.Script("window.observeTest.go('activity')");
                    await Wait(form,"document.querySelectorAll('[data-process-pid]').length>0&&!processLoading",45);
                    await form.Script("window.oldProcesses=document.querySelector('#process-rows').innerHTML");await Task.Delay(1500);Check(await form.Script("window.oldProcesses===document.querySelector('#process-rows').innerHTML")=="true","Process rows changed without refresh");
                    await form.Script("document.querySelector('[data-action=process-tree]').click()");Check(await form.Script("!!document.querySelector('.branch')")=="true","Missing process tree");
                    await form.CapturePreview(Path.Combine(artifacts,"processes.png"));
                    await form.Script("document.querySelector('[data-process-pid=\""+Environment.ProcessId+"\"]').click()");await Wait(form,"processDetail?.details?.modules.length>0",30);await form.CapturePreview(Path.Combine(artifacts,"process-details.png"));
                    await form.Script("document.querySelector('[data-process-tab=modules]').click()");Check(await form.Script("document.querySelector('#modal-body').textContent.includes('baseAddress')")=="true","Module details missing");await form.Script("document.querySelector('[data-action=close-modal]').click();window.observeTest.go('observer')");
                });
                await Test("Plugin setup saves an encrypted key without exposing it in UI state",async()=>
                {
                    await form.Script("document.querySelector('[data-action=observer-config]').click()");await Wait(form,"!!document.querySelector('#observer-key')");
                    Check(await form.Script("document.querySelector('#observer-model').tagName==='SELECT'&&document.querySelector('#observer-model').options.length===5&&document.querySelector('#observer-model').value==='gpt-5.6-luna'")=="true","Model dropdown/default missing");
                    await form.Script("document.querySelector('#observer-model').value='gpt-5-nano';document.querySelector('#observer-model').dispatchEvent(new Event('change',{bubbles:true}))");
                    Check(await form.Script("document.querySelector('#observer-model-info').textContent.includes((24000).toLocaleString())")=="true","Model budget help missing");
                    await form.CapturePreview(Path.Combine(artifacts,"model-selection.png"));
                    await form.Script("document.querySelector('#observer-key').value='observer-test-key';document.querySelector('[data-action=observer-save]').click()");
                    await Wait(form,"window.observeState.hasApiKey&&document.querySelector('#modal').classList.contains('hidden')");
                    Check(!File.ReadAllText(Path.Combine(root,"settings","plugins.json")).Contains("observer-test-key"),"Plaintext key on disk");
                    Check(await form.Script("!JSON.stringify(window.observeState).includes('observer-test-key')")=="true","Key exposed in state");await form.CapturePreview(Path.Combine(artifacts,"observer.png"));
                });
                await Test("Warcraft example renders a cited answer and inspectable evidence safely",async()=>
                {
                    form.ObserverHandler=new ObserverTests.FakeApi("## Recorded activity\nThe program created or overwrote `C:\\Game\\settings.ini`. [event:file]\n\nThis synthetic test snapshot is incomplete. <script>window.injected=true</script>",delay:500);
                    form.ObserverReader=(q,path,minutes,live,token)=>{var scan=ObserverTests.Fixture();scan.Question=q;return ProgramEvidence.Correlate(scan,path);};
                    await form.Script("document.querySelector('[data-action=observer-example]').click()");await Wait(form,"!document.querySelector('#chat-send').disabled");
                    await form.Script("document.querySelector('#chat-send').click()");await Wait(form,"!observerSending&&observerChat?.messages.length===2",30);
                    Check(await form.Script("observerChat.subject.endsWith('Frozen Throne.exe')&&!!document.querySelector('[data-observer-event]')&&!!document.querySelector('.chat-evidence')&&!window.injected")=="true","Missing citations or unsafe HTML");
                    await Wait(form,"document.querySelectorAll('[data-chat-id]').length===1");await form.CapturePreview(Path.Combine(artifacts,"observer-conversation.png"));
                    await form.Script("document.querySelector('[data-observer-event]').click()");await Wait(form,"document.querySelector('#modal-body').textContent.includes('TargetFilename')");await form.Script("document.querySelector('[data-action=close-modal]').click()");
                });
                await Test("Follow-up, rename and reopen retain the conversation",async()=>
                {
                    form.ObserverHandler=new ObserverTests.FakeApi();
                    await form.Script("document.querySelector('#chat-input').value='Which files changed?';document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");await Wait(form,"!observerSending&&observerChat?.messages.length===4");
                    await form.Script("document.querySelector('[data-action=observer-rename]').click();document.querySelector('#chat-title').value='Warcraft activity';document.querySelector('[data-action=observer-rename-confirm]').click()");await Wait(form,"document.querySelector('[data-chat-id]').textContent.includes('Warcraft activity')");
                    await form.Script("document.querySelector('[data-action=observer-new]').click()");await Wait(form,"!!document.querySelector('.chat-welcome')");
                    await form.Script("document.querySelector('[data-chat-id]').click()");await Wait(form,"observerChat?.messages.length===4&&document.querySelectorAll('.chat-message').length===4");
                });
                await Test("Stop preserves streamed text and puts its notice below the answer",async()=>
                {
                    form.ObserverHandler=new ObserverTests.StreamingApi(ObserverTests.Delta("Partial answer before Stop."),hang:true);
                    await form.Script("document.querySelector('#chat-input').value='More detail';document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");await Wait(form,"observerSending&&!document.querySelector('#chat-stop').classList.contains('hidden')");
                    await Wait(form,"document.querySelector('#chat-stream')?.textContent.includes('Partial answer before Stop.')");
                    await form.Script("document.querySelector('#chat-stop').click()");await Wait(form,"!observerSending&&observerChat.messages.at(-1).errorMessage?.includes('stopped')");
                    Check(await form.Script("(()=>{const m=document.querySelectorAll('.from-observer');const last=m[m.length-1];return last.querySelector('.message-body').textContent==='Partial answer before Stop.'&&last.querySelector('.message-problem').getBoundingClientRect().top>=last.querySelector('.message-body').getBoundingClientRect().bottom})()")=="true","Stop replaced text or notice appeared above it");
                });
                await Test("Provider failures expose a redacted, copyable error log",async()=>
                {
                    var error=ObserverTests.Delta("Text received before the provider failed. [event:file]")+"data: "+JsonSerializer.Serialize(new{type="response.failed",response=new{id="resp-ui",error=new{code="server_error",message="Provider test failure for observer-test-key"}}})+"\n\n";
                    form.ObserverHandler=new ObserverTests.ErrorApi(error);
                    await form.Script("document.querySelector('#chat-input').value='Explain this error';document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");
                    await Wait(form,"!observerSending&&observerChat.messages.at(-1).error?.code==='server_error'");
                    Check(await form.Script("observerChat.messages.at(-1).text.startsWith('Text received before')&&Array.from(document.querySelectorAll('.from-observer')).at(-1).querySelector('.message-body').textContent.startsWith('Text received before')")=="true","Provider error replaced streamed text");
                    await form.Script("Array.from(document.querySelectorAll('[data-error-message]')).at(-1).click()");
                    await Wait(form,"document.querySelector('#observer-error-details')?.textContent.includes('req-observer-test')");
                    Check(await form.Script("document.querySelector('#observer-error-details').textContent.includes('outputBudget')&&!document.querySelector('#observer-error-details').textContent.includes('observer-test-key')")=="true","Unsafe or incomplete error log");
                    await form.CapturePreview(Path.Combine(artifacts,"observer-error-log.png"));
                    form.TestClipboard="";await form.Script("document.querySelector('[data-action=observer-copy-error]').click()");await Wait(form,"document.querySelector('#toast').textContent==='Error log copied.'");Check(form.TestClipboard.Contains("req-observer-test"),"Copy error log did not copy diagnostics");
                    await form.Script("document.querySelector('[data-action=close-modal]').click()");
                });
                await Test("Citation warnings preserve copyable text, scope valid links and survive chat reopening",async()=>
                {
                    var citation=ObserverModels.CitationId("file");
                    var answer="## Recorded activity\nThe program wrote or overwrote its settings file. [event:"+citation+"]\n\nThis reference cannot be verified. [event:not-supplied]";
                    form.ObserverHandler=new ObserverTests.FakeApi(answer);
                    await form.Script("document.querySelector('#chat-input').value='Explain the recorded changes';document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");
                    await Wait(form,"!observerSending&&observerChat.messages.at(-1).error?.code==='unverified_citations'");
                    await form.Script("document.querySelector('[data-action=observer-new]').click()");await Wait(form,"!!document.querySelector('.chat-welcome')");
                    await form.Script("document.querySelector('[data-chat-id]').click()");await Wait(form,"observerChat?.messages.at(-1).error?.code==='unverified_citations'");
                    Check(await form.Script("(()=>{const m=Array.from(document.querySelectorAll('.from-observer')).at(-1);return m.querySelector('.message-body').textContent.includes('settings file')&&m.querySelectorAll('[data-observer-event]').length===1&&m.querySelector('.unverified-citation').textContent.includes('not-supplied')&&m.querySelector('.message-problem').textContent.startsWith('Observe could not verify')&&m.querySelector('.message-problem').getBoundingClientRect().top>=m.querySelector('.message-body').getBoundingClientRect().bottom})()")=="true","Citation warning lost text, linked an unknown event, or appeared above the answer");
                    await form.CapturePreview(Path.Combine(artifacts,"observer-retained-answer.png"));
                    await form.Script("Array.from(document.querySelectorAll('.from-observer')).at(-1).querySelector('[data-observer-event]').click()");await Wait(form,"document.querySelector('#modal-body').textContent.includes('TargetFilename')");await form.Script("document.querySelector('[data-action=close-modal]').click()");
                    form.TestClipboard="";await form.Script("Array.from(document.querySelectorAll('[data-copy-message]')).at(-1).click()");await Wait(form,"document.querySelector('#toast').textContent==='Copied.'");Check(form.TestClipboard==answer,"Copy replaced the generated text with a diagnostic");
                    Check(await form.Script("observerBody({status:'error',text:'Legacy saved error'})===''&&observerProblem({status:'error',text:'Legacy saved error'})==='Legacy saved error'")=="true","Older chat errors no longer display");
                });
                await Test("An empty evidence snapshot displays a clear logging-gap notice",async()=>
                {
                    form.ObserverHandler=new ObserverTests.FakeApi("Observe could not link recorded activity to this run.");
                    form.ObserverReader=(q,path,minutes,live,token)=>ScriptInvestigation.Correlate(new(){Question=q,Start=DateTimeOffset.UtcNow.AddMinutes(-15),End=DateTimeOffset.UtcNow},path);
                    await form.Script("document.querySelector('#chat-input').value='What did C:\\\\scripts\\\\not-recorded.ps1 do?';document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");
                    await Wait(form,"!observerSending&&observerChat.messages.at(-1).status==='complete'&&!!document.querySelector('.chat-evidence-gap')");
                    Check(await form.Script("document.querySelector('.chat-evidence-gap').textContent.includes('does not mean')&&document.querySelector('.chat-evidence-gap').textContent.includes('automatically checks')")=="true","Missing gap/retry explanation");
                    await form.CapturePreview(Path.Combine(artifacts,"observer-logging-gap.png"));
                });
                await Test("Plugin removal clears its key, keeps history and blocks sending",async()=>
                {
                    await form.Script("window.observeTest.go('plugins')");await Wait(form,"!!document.querySelector('#observer-plugin-state')&&!!document.querySelector('#unifi-state')");await form.CapturePreview(Path.Combine(artifacts,"plugins.png"));
                    await Request(form,"observer-remove");await Wait(form,"!window.observeState.hasApiKey&&!window.observeState.observer.enabled");
                    await form.Script("window.observeTest.go('observer')");await Wait(form,"document.querySelector('#chat-send').disabled&&document.querySelectorAll('[data-chat-id]').length===1");
                    Check(new PluginStore(Path.Combine(root,"settings"),Path.Combine(root,"config.toml")).Load().OpenAiKey=="","Key not cleared");
                });
                await Test("Chat deletion removes the selected conversation",async()=>
                {
                    await form.Script("document.querySelector('[data-action=observer-delete]').click();document.querySelector('[data-action=observer-delete-confirm]').click()");await Wait(form,"observerChat===null&&document.querySelectorAll('[data-chat-id]').length===0");
                });
                await Test("Minimum window size fits the chat composer",async()=>
                {
                    form.Size=new(1060,720);await Task.Delay(300);Check(await form.Script("document.documentElement.scrollWidth<=window.innerWidth&&document.querySelector('#chat-form').getBoundingClientRect().bottom<=window.innerHeight")=="true","Composer offscreen or horizontal overflow");await form.CapturePreview(Path.Combine(artifacts,"observer-compact.png"));form.Size=new(1440,950);
                });
                await Test("Sensor controls remain available and UI tests cannot mutate logging",async()=>
                {
                    await form.Script("window.observeTest.go('settings')");Check(await form.Script("Boolean(document.querySelector('[data-action=enable-powershell]'))===!window.observeState.data.sensors.powerShellEnabled")=="true","Wrong logging state");await form.CapturePreview(Path.Combine(artifacts,"settings.png"));
                    try{await form.Command("enable-powershell",JsonSerializer.SerializeToElement(new{}));throw new Exception("Test changed logging");}catch(InvalidOperationException e){Check(e.Message.Contains("disabled in UI tests"),e.Message);}
                    await form.Script("window.observeTest.go('scripts')");await Wait(form,"scriptData?.flows&&!scriptLoading",45);
                });
                await Test("A fresh PowerShell script appears in Flows and grouped Activity on refresh",async()=>
                {
                    if(!SensorSetup.PowerShellLoggingEnabled)return; // This gate never changes machine logging.
                    var script=Path.Combine(root,"observe-ui-script.ps1");await File.WriteAllTextAsync(script,"Write-Output 'Observe UI logging probe'");
                    var info=new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe")){UseShellExecute=false,CreateNoWindow=true};
                    info.ArgumentList.Add("-NoProfile");info.ArgumentList.Add("-NonInteractive");info.ArgumentList.Add("-File");info.ArgumentList.Add(script);
                    using var child=System.Diagnostics.Process.Start(info)!;await child.WaitForExitAsync();Check(child.ExitCode==0,"PowerShell probe failed");
                    // Event-log delivery is asynchronous; the view intentionally no longer auto-refreshes.
                    await Task.Delay(2000);
                    await form.Script("window.observeTest.go('scripts')");
                    await Wait(form,"scriptData?.flows.some(s=>s.text.length>0&&s.path==="+JsonSerializer.Serialize(script)+")",45);
                    await Wait(form,"window.observeState.data.activity.scripts.some(e=>scriptData.flows.some(s=>s.path==="+JsonSerializer.Serialize(script)+"&&s.evidenceIds.includes(e.id)))",20);
                    await form.CapturePreview(Path.Combine(artifacts,"powershell-scripts.png"));
                    await form.Script("document.querySelector('[data-script-tab=activity]').click()");
                    Check(await form.Script("document.querySelectorAll('[data-script-flow]').length>0")=="true","PowerShell filter empty after capture");
                    // Exercise the actual Observer evidence reader, not the synthetic chat fixture.
                    await form.Script("window.observeTest.go('observer')");await Wait(form,"!window.observeState.busy");
                    await Request(form,"observer-save",new{key="observer-test-key",model=ObserverModels.Default});
                    var provider=new ObserverTests.FakeApi("The supplied evidence contains this script's recorded text.");form.ObserverHandler=provider;form.ObserverReader=null;
                    await form.Script("document.querySelector('#chat-input').value="+JsonSerializer.Serialize("What did "+script+" do?")+";document.querySelector('#chat-input').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#chat-send').click()");
                    await Wait(form,"!observerSending&&observerChat?.messages.at(-1).status==='complete'",60);
                    Check(await form.Script("JSON.parse(observerChat.messages[0].evidence).events.some(e=>e.eventId===4104&&e.data.Path.endsWith('observe-ui-script.ps1'))")=="true","Real script text did not reach Observer evidence");
                    Check(provider.RequestBody.Contains("Observe UI logging probe"),"Actual recorded script text was not sent to the test provider");
                    await form.CapturePreview(Path.Combine(artifacts,"observer-real-script.png"));
                });
                await Test("PowerShell flow and grouped activity open the same detail and seed a scoped summary",async()=>
                {
                    await form.Script("window.observeTest.go('scripts')");await Wait(form,"!scriptLoading&&scriptData?.flows.some(f=>f.text.length>0)");
                    await form.Script("window.chosenScript=scriptData.flows.find(f=>f.text.length>0);openScriptFlow(window.chosenScript.id)");await Wait(form,"!!document.querySelector('.script-source')&&!!document.querySelector('[data-action=script-summary]')");await form.CapturePreview(Path.Combine(artifacts,"script-detail.png"));
                    await form.Script("document.querySelector('[data-action=script-summary]').click()");await Wait(form,"page==='observer'&&observerChat?.title.endsWith('summary')");Check(await form.Script("observerDraft.includes('Wazuh')&&JSON.parse(observerChat.messages[0].evidence).events.every(e=>window.chosenScript.evidenceIds.includes(e.id))")=="true","Unrelated host activity in summary");
                    await form.Script("window.observeTest.go('scripts')");await Wait(form,"!scriptLoading");await form.Script("document.querySelector('[data-script-tab=activity]').click()");await form.CapturePreview(Path.Combine(artifacts,"script-activity.png"));
                });
                foreach(var mode in new[]{"install","uninstall"})await Test(mode+" screen keeps plugins optional and prevents test installation changes",async()=>
                {
                    using var setup=new DashboardForm(mode,true,root);setup.Show();try{await setup.Loaded.Task.WaitAsync(TimeSpan.FromSeconds(30));await Wait(setup,"document.querySelector('#setup-submit')!==null");
                    if(mode=="install")Check(await setup.Script("document.querySelectorAll('.setup-content input[type=checkbox]').length===7&&[...document.querySelectorAll('.setup-content input[type=checkbox]')].every(x=>!x.checked)")=="true","Plugin preselected");else Check(await setup.Script("document.querySelector('input[name=sysmon]:checked').value==='keep'")=="true","Sysmon removal preselected");
                    await setup.CapturePreview(Path.Combine(artifacts,mode+".png"));
                    try{await setup.Command(mode,JsonSerializer.SerializeToElement(new{}));throw new Exception("Test changed installation");}catch(InvalidOperationException e){Check(e.Message.Contains("disabled in UI tests"),e.Message);}
                    }finally{var closed=new TaskCompletionSource();setup.FormClosed+=(_,_)=>closed.SetResult();setup.Close();await closed.Task;}
                });
                code=failed==0?0:1;
            }
            catch(Exception error){failed++;tests.Add(new{name="Dashboard initialization",passed=false,error=error.ToString()});}
            finally{await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests,previews=artifacts},Evidence.Json));File.Delete(output+".progress.json");form.Close();}
        };
        Application.Run(form);try{Directory.Delete(root,true);}catch(IOException){}catch(UnauthorizedAccessException){}return code;
    }
}
