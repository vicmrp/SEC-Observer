using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.IO.Pipes;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text.Json;

namespace Observe;

public static class FeatureTests
{
    sealed class Handler(Func<HttpRequestMessage,HttpResponseMessage> respond):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(respond(request));}
    static void Check(bool value,string message="Assertion failed"){if(!value)throw new Exception(message);}
    static JsonElement Json(object value)=>JsonSerializer.SerializeToElement(value,Evidence.Json);
    static async Task Reject(Func<Task> action){try{await action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}catch(InvalidDataException){return;}throw new Exception("Operation should have been rejected");}
    public static async Task<int> Run(string output)
    {
        var root=Path.Combine(Path.GetTempPath(),"ObserveFeatures-"+Guid.NewGuid());Directory.CreateDirectory(root);
        var tests=new List<object>();var failed=0;
        async Task Test(string name,Func<Task> action){try{await action();tests.Add(new{name,passed=true});}catch(Exception e){failed++;tests.Add(new{name,passed=false,error=e.ToString()});}}
        try
        {
            var plugins=new PluginStore(Path.Combine(root,"settings"),Path.Combine(root,"config.toml"));
            const string original="model = \"test\"\n\n[mcp_servers.existing]\ncommand = \"keep.exe\"\n";
            await Test("Retired connection is revoked and only the managed entry is removed",()=>
            {
                var settings=plugins.Load();settings.ChatGpt=true;plugins.Save(settings);
                File.WriteAllText(plugins.ConfigPath,original+"\n# BEGIN OBSERVE MANAGED MCP\n[mcp_servers.observe]\ncommand = 'Observe.exe'\n# END OBSERVE MANAGED MCP\n");
                plugins.RemoveLegacyConnection();Check(!plugins.Load().ChatGpt);Check(File.ReadAllText(plugins.ConfigPath).TrimEnd()==original.TrimEnd());
                plugins.RemoveLegacyConnection();Check(File.ReadAllText(plugins.ConfigPath).TrimEnd()==original.TrimEnd());return Task.CompletedTask;
            });
            await Test("Legacy cleanup preserves unowned entries and rejects malformed managed blocks",async()=>
            {
                var unowned="[mcp_servers.observe]\ncommand='user.exe'";Check(PluginStore.RemoveManagedMcpConfig(unowned)==unowned);
                await Reject(()=>Task.FromResult(PluginStore.RemoveManagedMcpConfig("# BEGIN OBSERVE MANAGED MCP\nincomplete")));
            });
            EvidenceEvent Part(int number,int total=2)=>new("ps:"+number,"PowerShell",number,4104,DateTimeOffset.UtcNow,new(){{"ScriptBlockId","block-a"},{"ProcessId","123"},{"MessageNumber",number.ToString()},{"MessageTotal",total.ToString()},{"Path",@"C:\scripts\x.ps1"},{"ScriptBlockText","Write-Output "+number}});
            await Test("PowerShell fragments are ordered, deduplicated and incomplete sequences disclosed",()=>
            {
                var complete=Json(ForensicQueries.Scripts(new(){Events=[Part(2),Part(1),Part(1)]}))[0];Check(complete.GetProperty("complete").GetBoolean()&&complete.GetProperty("fragments").GetInt32()==2);Check(complete.GetProperty("preview").GetString()!.StartsWith("Write-Output 1"));
                var gap=Json(ForensicQueries.Scripts(new(){Events=[Part(1),Part(3)]}))[0];Check(!gap.GetProperty("complete").GetBoolean());return Task.CompletedTask;
            });
            await Test("Script detail lookup uses recorded evidence and never reads the named file",()=>
            {
                var secret=Path.Combine(root,"secret.ps1");File.WriteAllText(secret,"not logged; do not read");var observation=new Observation{Events=[Part(1),Part(2)]};Check(Json(ForensicQueries.Details(observation,"x.ps1")).GetProperty("found").GetBoolean());Check(!Json(ForensicQueries.Details(observation,secret)).GetProperty("found").GetBoolean());return Task.CompletedTask;
            });
            await Test("PowerShell process ID comes from event System Execution metadata",()=>
            {
                var e=EvidenceEvent.Parse("<Event><System><EventID>4104</EventID><Execution ProcessID='4321'/><TimeCreated SystemTime='2026-09-17T12:00:00Z'/></System><EventData><Data Name='ScriptBlockText'>Write-Output test</Data></EventData></Event>");Check(e.Data["ProcessId"]=="4321");return Task.CompletedTask;
            });
            await Test("UniFi credentials round trip through Windows protection and are cleared on removal",()=>
            {
                var cipher=PluginStore.Protect("test-unifi-secret");Check(!cipher.Contains("test-unifi-secret")&&PluginStore.Unprotect(cipher)=="test-unifi-secret");plugins.Save(new(){Unifi=true,UnifiKey=cipher});plugins.RemoveUnifi();Check(!plugins.Load().Unifi&&plugins.Load().UnifiKey=="");return Task.CompletedTask;
            });
            await Test("UniFi rejects insecure URLs and invalid certificate pins",async()=>
            {
                foreach(var url in new[]{"http://example.test/integration","https://user:pass@example.test/integration","https://example.test/not-the-api","https://example.test/integration?key=x"})await Reject(()=>Task.FromResult(UnifiClient.ValidateUrl(url)));
                await Reject(()=>Task.FromResult(UnifiClient.ValidatePin("invalid")));Check(UnifiClient.ValidatePin(new string('a',64))==new string('A',64));
            });
            await Test("UniFi connector issues fixed GET routes with the protected API key and bounded pagination",async()=>
            {
                plugins.Save(new(){Unifi=true,UnifiUrl="https://example.test/proxy/network/integration",UnifiSite="11111111-1111-1111-1111-111111111111",UnifiKey=PluginStore.Protect("test-secret")});var calls=0;
                var handler=new Handler(request=>{calls++;Check(request.Method==HttpMethod.Get&&request.Headers.GetValues("X-API-Key").Single()=="test-secret");Check(request.RequestUri!.AbsolutePath.EndsWith("/v1/sites/11111111-1111-1111-1111-111111111111/clients"));Check(request.RequestUri.Query.Contains("offset="+(calls-1)*200));return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{data=calls==1?Enumerable.Range(0,200).Select(i=>new{ipAddress="192.0.2."+i}).ToArray():[] }))};});
                var result=await new UnifiClient(plugins,handler).Get("clients");Check(calls==2&&result.GetProperty("data").GetArrayLength()==200&&!result.GetProperty("truncated").GetBoolean());
            });
            await Test("UniFi errors do not expose response bodies or credentials",async()=>
            {
                var handler=new Handler(_=>new(HttpStatusCode.Unauthorized){Content=new StringContent("secret-response")});try{await new UnifiClient(plugins,handler).Get("sites");throw new Exception("Expected failure");}catch(InvalidOperationException e){Check(e.Message.Contains("401")&&!e.Message.Contains("secret"));}
            });
            await Test("Installer removal deletes only its recorded payload and retains unrelated evidence",()=>
            {
                var source=Path.Combine(root,"release");var target=Path.Combine(root,"installed");Directory.CreateDirectory(source);var exe=Path.Combine(source,"Observe-Setup.exe");File.WriteAllText(exe,"test payload");File.WriteAllText(Path.Combine(source,"LICENSE"),"MIT");Installation.CopyPayload(exe,target);Check(File.ReadAllText(Path.Combine(target,"Observe.exe"))=="test payload");File.WriteAllText(Path.Combine(target,"my-evidence.json"),"retain");Check(!Installation.RemovePayload(target));Check(!File.Exists(Path.Combine(target,"Observe.exe"))&&File.ReadAllText(Path.Combine(target,"my-evidence.json"))=="retain");return Task.CompletedTask;
            });
            await Test("Traversal in uninstall receipt is rejected before any payload deletion",async()=>
            {
                var target=Path.Combine(root,"tampered");Directory.CreateDirectory(target);File.WriteAllText(Path.Combine(target,"Observe.exe"),"retain");File.WriteAllText(Path.Combine(target,"install.json"),JsonSerializer.Serialize(new InstallReceipt{Files=["Observe.exe","..\\outside"]},Evidence.Json));await Reject(()=>Task.FromResult(Installation.RemovePayload(target)));Check(File.Exists(Path.Combine(target,"Observe.exe")));
            });
            await Test("Retired MCP executable mode exits without serving tools or opening a GUI",async()=>
            {
                var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true};info.ArgumentList.Add("--mcp");using var process=Process.Start(info)!;
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));try{await process.WaitForExitAsync(timeout.Token);Check(process.ExitCode==1&&(await process.StandardOutput.ReadToEndAsync()).Length==0);}finally{if(!process.HasExited)process.Kill();}
            });
        }
        finally{Directory.Delete(root,true);}
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=tests.Count-failed,failed,tests},Evidence.Json));return failed==0?0:1;
    }
}
