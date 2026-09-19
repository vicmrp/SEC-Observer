using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Observe;

public sealed class DashboardForm : Form
{
    readonly WebView2 web=new(){Dock=DockStyle.Fill,DefaultBackgroundColor=Color.FromArgb(246,247,249)};
    readonly PluginStore plugins;
    readonly ObservationEngine engine;
    readonly ObserverChatStore chats;
    readonly ObserverChatService observer;
    readonly ThreatFoxClient threatFox;
    CountryMap countries=new();
    Observation? scriptSnapshot;
    internal HttpMessageHandler? ThreatFoxHandler;
    internal string TestClipboard="";
    internal string TestOpenedModPage="";
    CancellationTokenSource? chatCancellation;
    Task<ObserverConversation>? chatTask;
    internal HttpMessageHandler? ObserverHandler;
    internal Func<string,string,int,EvidenceEvent[],CancellationToken,Observation>? ObserverReader;
    readonly System.Windows.Forms.Timer timer=new(){Interval=1000};
    readonly NotifyIcon canaryNotification=new(){Icon=SystemIcons.Warning,Text="Observe · canary test"};
    readonly HashSet<string> notifiedCanaries=[];
    readonly DateTimeOffset openedAt=DateTimeOffset.UtcNow;
    readonly string mode;
    readonly bool testMode;
    bool ready,closing,busy;
    readonly SemaphoreSlim commands=new(1,1);
    public TaskCompletionSource<bool> Loaded {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public DashboardForm(string mode="app",bool testMode=false,string? testRoot=null)
    {
        this.mode=mode;this.testMode=testMode;
        plugins=testRoot is null?new():new(Path.Combine(testRoot,"settings"),Path.Combine(testRoot,"config.toml"));engine=new(plugins,testRoot is null?null:Path.Combine(testRoot,"sessions"));
        chats=new(Path.Combine(plugins.Root,"observer-chats"));observer=new(plugins,chats);
        threatFox=new(plugins);try{var map=Path.Combine(plugins.Root,"countries.csv");if(File.Exists(map))countries=new(File.ReadAllText(map));}catch(Exception e){Debug.WriteLine(e.Message);}
        Text=mode=="install"?"Install Observe":mode=="uninstall"?"Uninstall Observe":"Observe · 0.12.1-beta-vibe-coded";AutoScaleMode=AutoScaleMode.Dpi;AutoScaleDimensions=new(96,96);Size=new(1440,950);MinimumSize=new(1060,720);StartPosition=FormStartPosition.CenterScreen;
        Controls.Add(web);Shown+=async(_,_)=>await Initialize();timer.Tick+=(_,_)=>Push();FormClosing+=OnClosing;
        canaryNotification.BalloonTipClicked+=async(_,_)=>{Show();WindowState=FormWindowState.Normal;Activate();if(ready)await Script("go('canary')");};
    }
    async Task Initialize()
    {
        try
        {
            var userData=Path.Combine(plugins.Root,testMode?"WebView-Test":"WebView");
            var environment=await CoreWebView2Environment.CreateAsync(null,userData);await web.EnsureCoreWebView2Async(environment);
            var core=web.CoreWebView2;core.Settings.AreDevToolsEnabled=testMode;core.Settings.AreDefaultContextMenusEnabled=false;core.Settings.AreHostObjectsAllowed=false;core.Settings.IsStatusBarEnabled=false;core.Settings.IsPasswordAutosaveEnabled=false;core.Settings.IsGeneralAutofillEnabled=false;
            core.NavigationStarting+=(_,e)=>{if(!e.Uri.StartsWith("https://observe.local/",StringComparison.Ordinal))e.Cancel=true;};core.NewWindowRequested+=(_,e)=>e.Handled=true;
            core.PermissionRequested+=(_,e)=>e.State=CoreWebView2PermissionState.Deny;
            core.AddWebResourceRequestedFilter("https://observe.local/*",CoreWebView2WebResourceContext.All);
            core.WebResourceRequested+=(_,e)=>
            {
                var path=new Uri(e.Request.Uri).AbsolutePath;var file=path switch{"/" or "/index.html"=>"index.html","/app.js"=>"app.js","/observer.js"=>"observer.js","/workspace.js"=>"workspace.js","/style.css"=>"style.css","/observer.css"=>"observer.css","/workspace.css"=>"workspace.css","/explorer.js"=>"explorer.js","/explorer.css"=>"explorer.css","/canary.js"=>"canary.js","/canary.css"=>"canary.css","/mods.js"=>"mods.js","/mods.css"=>"mods.css",_=>""};
                var assembly=Assembly.GetExecutingAssembly();var resource=assembly.GetManifestResourceNames().SingleOrDefault(n=>n.EndsWith(".Dashboard."+file)&&file.Length>0);
                if(resource is null){e.Response=core.Environment.CreateWebResourceResponse(new MemoryStream(),404,"Not Found","");return;}
                var stream=assembly.GetManifestResourceStream(resource)!;var mime=file.EndsWith(".js")?"text/javascript":file.EndsWith(".css")?"text/css":"text/html";
                e.Response=core.Environment.CreateWebResourceResponse(stream,200,"OK","Content-Type: "+mime+"; charset=utf-8\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'\r\n");
            };
            core.WebMessageReceived+=Message;
            core.NavigationCompleted+=(_,e)=>{if(e.IsSuccess){ready=true;Push();timer.Start();Loaded.TrySetResult(true);}else Loaded.TrySetException(new Exception("Dashboard navigation failed: "+e.WebErrorStatus));};
            if(mode=="app"){await engine.Start();timer.Interval=engine.RefreshInterval;}core.Navigate("https://observe.local/index.html");
        }
        catch(Exception e){Loaded.TrySetException(e);MessageBox.Show("Observe could not open its interface: "+e.Message+"\nMicrosoft Edge WebView2 Runtime is required. Install it from Microsoft's WebView2 download page.","Observe",MessageBoxButtons.OK,MessageBoxIcon.Error);Close();}
    }
    void Push()
    {
        if(!ready||closing)return;
        if(!testMode&&mode=="app"&&plugins.Load().CitiesModObserver)
        {
            var alert=engine.Snapshot().LastOrDefault(e=>e.EventId==CanaryLab.ReadEvent&&e.Timestamp>=openedAt);
            if(alert is not null&&notifiedCanaries.Add(alert.Data.GetValueOrDefault("CanarySession",alert.Id)+":"+alert.Data.GetValueOrDefault("ProcessId")+":"+alert.Data.GetValueOrDefault("ProcessStartTime"))){canaryNotification.Visible=true;canaryNotification.ShowBalloonTip(10000,"Observe · canary exercise",alert.Process+" requested a read of the synthetic document outside the game. Open Mod safety test for the evidence.",ToolTipIcon.Warning);}
        }
        try{var cfg=plugins.Load();web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new{type="state",mode,hasApiKey=cfg.Observer&&cfg.OpenAiKey.Length>0,observer=new{enabled=cfg.Observer,hasKey=cfg.OpenAiKey.Length>0,model=cfg.ObserverModel,models=ObserverModels.All},busy,installed=File.Exists(Path.Combine(Installation.InstallRoot,"install.json")),installPath=Installation.InstallRoot,data=mode=="app"?engine.State():null},Evidence.Json));}
        catch(Exception e){Debug.WriteLine(e.Message);}
    }
    async void Message(object? sender,CoreWebView2WebMessageReceivedEventArgs e)
    {
        if(e.Source!="https://observe.local/index.html"||e.WebMessageAsJson.Length>64_000)return;
        string id="";var ownsBusy=false;
        try
        {
            using var doc=JsonDocument.Parse(e.WebMessageAsJson);var r=doc.RootElement;id=r.GetProperty("id").GetString()!;
            var action=r.GetProperty("action").GetString()!;var args=r.TryGetProperty("args",out var a)?a:JsonSerializer.SerializeToElement(new{});
            if(action is not ("observer-cancel" or "observer-list" or "observer-open")){await commands.WaitAsync();busy=true;ownsBusy=true;Push();}
            var result=await Command(action,args);if(!closing)web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new{type="response",id,result},Evidence.Json));
        }
        catch(Exception error){if(ready&&!closing)web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new{type="response",id,error=error.Message}));}
        finally{if(ownsBusy){busy=false;commands.Release();}Push();}
    }
    internal async Task<object> Command(string action,JsonElement args)
    {
        string Text(string name)=>args.TryGetProperty(name,out var x)?x.GetString()??"":"";
        bool Flag(string name)=>args.TryGetProperty(name,out var x)&&x.GetBoolean();
        int Number(string name,int fallback)=>args.TryGetProperty(name,out var x)?x.GetInt32():fallback;
        if(mode!="app"&&action is not ("install" or "uninstall" or "launch" or "close"))throw new InvalidOperationException("Action unavailable in setup.");
        if(action is "configure" or "restore" or "enable-powershell" or "tracked-start")engine.RequireMonitoring();
        switch(action)
        {
            case "storage-usage":return LocalLogStorage.Usage(plugins.Root);
            case "storage-export":
                if(testMode)throw new InvalidOperationException("File dialogs are disabled in UI tests.");
                using(var export=new SaveFileDialog{Filter="Evidence archive (*.zip)|*.zip",FileName="Observe-evidence-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".zip",OverwritePrompt=true}){if(export.ShowDialog(this)!=DialogResult.OK)return new{cancelled=true};var temp=export.FileName+".tmp";if(File.Exists(temp))throw new IOException("A temporary export exists at this destination. Choose another filename.");try{await Task.Run(()=>engine.ExportLogs(temp));File.Move(temp,export.FileName,true);}finally{if(File.Exists(temp))File.Delete(temp);}return new{path=export.FileName};}
            case "storage-delete":
                if(Text("confirmation")!="DELETE")throw new ArgumentException("Type DELETE to confirm deletion of Observe's saved evidence, recordings and chats.");
                if(testMode)throw new InvalidOperationException("Log deletion is disabled in UI tests.");engine.ClearLogs();scriptSnapshot=null;return LocalLogStorage.Usage(plugins.Root);
            case "process-snapshot":
                if(engine.Gaming)return new{snapshot=engine.Inspector.Saved(),network=Array.Empty<object>()};
                var processSnapshot=await Task.Run(()=>engine.Inspector.Capture());
                engine.Persist(processSnapshot.Processes.Select(p=>new EvidenceEvent("process-metrics:"+p.Pid+":"+processSnapshot.At.ToString("O"),"Observe/ProcessMetrics",0,10104,processSnapshot.At,new(){{"Image",p.Image},{"ProcessId",p.Pid.ToString()},{"ParentProcessId",p.ParentPid.ToString()},{"ProcessStartTime",p.Started?.ToString("O")??""},{"CommandLine",p.CommandLine},{"Company",p.Company},{"MemoryBytes",p.Memory?.ToString()??""},{"PrivateBytes",p.PrivateBytes?.ToString()??""},{"CpuPercent",p.Cpu?.ToString(System.Globalization.CultureInfo.InvariantCulture)??""},{"IoReadBytesPerSecond",p.IoRead?.ToString()??""},{"IoWriteBytesPerSecond",p.IoWrite?.ToString()??""},{"Threads",p.Threads?.ToString()??""},{"Handles",p.Handles?.ToString()??""}})));
                return new{snapshot=processSnapshot,network=ProcessConnections(processSnapshot)};
            case "process-details":return await Task.Run(()=>ProcessInspector.Details(Number("pid",0),Text("started")));
            case "apps-list":
                var catalogSnapshot=engine.Gaming?engine.Inspector.Saved():await Task.Run(()=>engine.Inspector.Capture());
                if(catalogSnapshot is not null&&!catalogSnapshot.Saved)engine.Apps.Observe(catalogSnapshot.Processes.Where(p=>p.Image.Length>0).Select(p=>new EvidenceEvent("catalog:"+p.Pid+":"+catalogSnapshot.At.ToString("O"),"Observe/Catalog",0,ProcessMonitor.Existing,catalogSnapshot.At,new(){{"Image",p.Image},{"ProcessId",p.Pid.ToString()},{"ProcessStartTime",p.Started?.ToString("O")??""}})));
                engine.Apps.Save();return new{apps=engine.Apps.All(),running=engine.Gaming?Array.Empty<ProcessRow>():catalogSnapshot?.Processes??[],paused=engine.Gaming};
            case "app-watch":engine.Apps.Watch(Text("id"),Flag("enabled"));return new{ok=true};
            case "tracked-attach":
                engine.RequireMonitoring();if(testMode)throw new InvalidOperationException("Attaching real processes is disabled in UI tests.");
                return engine.Launches.Attach(Number("pid",0),DateTimeOffset.Parse(Text("started")),Text("path"),engine.HistoryEvents(10080));
            case "network-snapshot":return engine.Network(Number("minutes",60),countries);
            case "country-import":
                if(testMode)throw new InvalidOperationException("File dialogs are disabled in UI tests.");
                using(var picker=new OpenFileDialog{Filter="IP country map (*.csv)|*.csv",Title="Import local CIDR,country CSV"})
                {if(picker.ShowDialog(this)!=DialogResult.OK)return new{cancelled=true};if(new FileInfo(picker.FileName).Length>4_000_000)throw new ArgumentException("Country map must be under 4 MB.");var csv=File.ReadAllText(picker.FileName);countries=new(csv);Directory.CreateDirectory(plugins.Root);File.WriteAllText(Path.Combine(plugins.Root,"countries.csv"),csv);}return new{loaded=true};
            case "tracked-list":return engine.Launches.List();
            case "cities-mod-filters": if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable Cities II mod observer first.");engine.Mods.SetFilters(Flag("codeOnly"),Flag("loadedOnly"));return engine.Mods.FilterView();
            case "cities-mod-inventory":if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable Cities II mod observer first.");return engine.Mods.View(engine.Snapshot(),!engine.Gaming);
            case "cities-mod-open-page":
                if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable Cities II mod observer first.");
                var modPage=engine.Mods.ParadoxPage(Text("key"));
                if(testMode)TestOpenedModPage=modPage;else Process.Start(new ProcessStartInfo(modPage){UseShellExecute=true});
                return new{opened=true};
            case "cities-mod-details":if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable Cities II mod observer first.");return engine.Mods.Details(Text("key"),engine.Snapshot(),!engine.Gaming);
            case "canary-status":return engine.Canary.View();
            case "cities-mod-enable":var citiesSettings=plugins.Load();citiesSettings.CitiesModObserver=true;plugins.Save(citiesSettings);break;
            case "cities-mod-disable":engine.Mods.Disable();engine.Canary.Stop();var citiesOff=plugins.Load();citiesOff.CitiesModObserver=false;plugins.Save(citiesOff);break;
            case "canary-install":if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable the Cities II mod observer plugin first.");if(testMode)throw new InvalidOperationException("Mod installation is disabled in UI tests.");return new{path=CanaryLab.InstallMod()};
            case "canary-arm":if(!plugins.Load().CitiesModObserver)throw new InvalidOperationException("Enable the Cities II mod observer plugin first.");if(testMode)throw new InvalidOperationException("Canary arming is disabled in UI tests.");engine.RequireMonitoring();return engine.Canary.Arm();
            case "canary-stop":engine.Canary.Stop();return engine.Canary.View();
            case "canary-remove":if(testMode)throw new InvalidOperationException("Mod removal is disabled in UI tests.");return new{message=engine.Canary.RemoveMod()};
            case "canary-chat":
                var canary=engine.Canary.Observation(Text("id"));engine.Persist(canary.Events);
                var canaryChat=new ObserverConversation{Title="Harmless mod · canary exercise",Subject=(canary.Events.LastOrDefault(e=>e.EventId==CanaryLab.ReceiptEvent)??canary.Events.LastOrDefault(e=>e.EventId==CanaryLab.ReadEvent))?.Data.GetValueOrDefault("Image","")??"",TrackedRunId="canary:"+Text("id"),Messages=[new(){Text=canary.Question,Evidence=JsonSerializer.Serialize(Evidence.Payload(canary),Evidence.Json)}]};chats.Save(canaryChat);return canaryChat;
            case "tracked-pick":
                if(testMode)throw new InvalidOperationException("File dialogs are disabled in UI tests.");
                using(var picker=new OpenFileDialog{Filter="Windows application (*.exe)|*.exe",Title="Choose an app to launch and observe"})return new{path=picker.ShowDialog(this)==DialogResult.OK?picker.FileName:""};
            case "tracked-start":
                if(testMode)throw new InvalidOperationException("App launching is disabled in UI tests.");
                var current=JsonSerializer.SerializeToElement(engine.State(),Evidence.Json);var gaps=current.GetProperty("sensors").GetProperty("channels").EnumerateArray().Select(v=>v.GetString()!).Where(v=>!v.Contains("verified")).Append(NetworkMonitor.Coverage).Append(ScriptInvestigation.Limits).Append("Parent/process snapshots are sampled each second during a tracked run; brief children can be missed and sampled exit times are approximate.").Append(SensorSetup.Load() is {Stage:"configured"} sensor?SensorSetup.Coverage(sensor.Profile):"External Sysmon filters are unknown. File and registry evidence may not be captured.").ToArray();
                return await engine.Launches.Start(Text("path"),Text("arguments"),gaps);
            case "tracked-finish":engine.Launches.Finish(Text("id").Length>0?Text("id"):null);return new{message="Recording saved. The app and its child processes keep running."};
            case "tracked-open":
                var run=engine.Launches.Get(Text("id"));var evidence=TrackedCorrelation.Read(run);
                return new{run=new{run.Id,run.Name,run.Path,run.Arguments,run.Sha256,run.RootPid,run.Started,run.Ended,run.Status,run.Warnings},evidence,network=NetworkSnapshots.Create(evidence.Events,1440,countries,now:run.Ended??DateTimeOffset.UtcNow)};
            case "tracked-chat":
                var tracked=engine.Launches.Get(Text("id"));var linked=TrackedCorrelation.Read(tracked);
                var snapshot=new Observation{Question="Explain this recorded launch and any suspicious behavior.",Start=tracked.Started,End=tracked.Ended??DateTimeOffset.UtcNow,Events=linked.Events.ToList(),Warnings=tracked.Warnings,Investigation=new(){Script=tracked.Path,Match="Explicit tracked launch",ExecutionStart=tracked.Started,ProcessId=tracked.RootPid.ToString(),ScannedEvents=tracked.Events.Count}};
                var conversation=new ObserverConversation{Title=tracked.Name+" · recorded launch",Subject=tracked.Path,TrackedRunId=tracked.Id,Messages=[new(){Text="Recorded launch of "+tracked.Path+" at "+tracked.Started.ToLocalTime().ToString("O")+". Use this saved run's evidence.",Evidence=JsonSerializer.Serialize(Evidence.Payload(snapshot),Evidence.Json)}]};chats.Save(conversation);return conversation;
            case "threatfox-save":
                var fox=plugins.Load();var auth=Text("key").Trim();if(auth.Length>1024||auth.Any(char.IsControl))throw new ArgumentException("Enter a valid ThreatFox Auth-Key.");if(auth.Length>0)fox.ThreatFoxKey=PluginStore.Protect(auth);if(fox.ThreatFoxKey.Length==0)throw new ArgumentException("ThreatFox requires an Auth-Key.");fox.ThreatFox=true;plugins.Save(fox);threatFox.Clear();break;
            case "threatfox-remove":plugins.RemoveThreatFox();threatFox.Clear();break;
            case "threatfox-search":
                if(engine.Gaming)throw new InvalidOperationException("Restore monitoring before using lookups.");
                if(testMode&&ThreatFoxHandler is null)throw new InvalidOperationException("External lookups are disabled in UI tests.");return await threatFox.Search(Text("indicator"),handler:ThreatFoxHandler);
            case "observer-list":return chats.List();
            case "observer-copy":var copied=Text("text");if(copied.Length is >0 and <=80_000){if(testMode)TestClipboard=copied;else Clipboard.SetText(copied);}break;
            case "observer-open":return BindTrackedChat(Text("id"));
            case "observer-delete":chats.Delete(Text("id"));break;
            case "observer-rename":
                var renamed=chats.Get(Text("id"));var title=Text("title").Trim();if(title.Length is <1 or >100)throw new ArgumentException("Use a chat title between 1 and 100 characters.");renamed.Title=title;chats.Save(renamed);return renamed;
            case "observer-save":
                var settings=plugins.Load();var model=Text("model").Trim();var key=Text("key").Trim();
                ObserverModels.Get(model);
                if(key.Length>1024||key.Any(char.IsControl))throw new ArgumentException("Enter a valid API key.");
                if(key.Length>0)settings.OpenAiKey=PluginStore.Protect(key);
                if(settings.OpenAiKey.Length==0)throw new ArgumentException("An OpenAI API key is required for this plugin.");
                settings.Observer=true;settings.ObserverModel=model;plugins.Save(settings);break;
            case "observer-remove":plugins.RemoveObserver();break;
            case "observer-cancel":chatCancellation?.Cancel();break;
            case "observer-send":
                if(testMode&&ObserverHandler is null)throw new InvalidOperationException("Paid API requests are disabled in UI tests.");
                if(((JsonElement)JsonSerializer.SerializeToElement(engine.State())).GetProperty("gaming").GetBoolean())throw new InvalidOperationException("Return to live mode to use chatGPT observer.");
                chatCancellation?.Dispose();chatCancellation=new();
                if(Text("id").Length>0)BindTrackedChat(Text("id"));
                chatTask=observer.Send(Text("id"),Text("question"),Number("minutes",60),Flag("refresh"),engine.HistoryEvents(Number("minutes",60)==0?0:10080),chatCancellation.Token,(chatId,delta)=>
                {if(ready&&!closing)web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new{type="observer-delta",chatId,delta}));},ObserverHandler,ObserverReader??ReadProgram,TrackedObservation);
                return await chatTask;
            case "enable-powershell":if(testMode)throw new InvalidOperationException("Logging changes are disabled in UI tests.");await SensorSetup.EnablePowerShellWithElevation();await engine.RefreshReadiness();return new{message="PowerShell logging is enabled. Open a new PowerShell session before the next run. Earlier script text cannot be recovered; PowerShell 7 requires its event provider to be registered."};
            case "performance":
                if(testMode)throw new InvalidOperationException("Sensor changes and restarts are disabled in UI tests.");
                await engine.Finish();engine.Launches.Finish();
                engine.Canary.Stop();
                try{await SensorSetup.SwitchGameSensors(Flag("enabled"));}
                catch
                {
                    if(SensorSetup.GameSensorsPaused){var failed=plugins.Load();failed.GamePerformance=true;plugins.Save(failed);Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true});BeginInvoke(Close);}
                    throw;
                }
                var performance=plugins.Load();performance.GamePerformance=Flag("enabled");plugins.Save(performance);
                Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true});BeginInvoke(Close);return new{restarting=true};
            case "scripts":
                var observation=await ReadScripts(Number("minutes",60));return new{scripts=ForensicQueries.Scripts(observation),warnings=observation.Warnings,refreshedAt=DateTimeOffset.UtcNow};
            case "script":return ForensicQueries.Details(await ReadScripts(Number("minutes",60)),Text("script"));
            case "script-snapshot":scriptSnapshot=await ReadScripts(Number("minutes",60));return ScriptWorkspace.Snapshot(scriptSnapshot);
            case "script-detail":return ScriptWorkspace.Details(scriptSnapshot??throw new InvalidOperationException("Refresh PowerShell first."),Text("id"));
            case "script-chat":
                var ss=scriptSnapshot??throw new InvalidOperationException("Refresh PowerShell first.");var sf=ScriptWorkspace.Flows(ss).FirstOrDefault(f=>f.Id==Text("id"))??throw new ArgumentException("Select a script record.");var so=ScriptWorkspace.Selected(ss,sf);
                var sc=new ObserverConversation{Title=(Path.GetFileName(sf.Path) is {Length:>0} sn?sn:"PowerShell script")+" · summary",Subject=sf.Path,Messages=[new(){Text=so.Question,Evidence=JsonSerializer.Serialize(Evidence.Payload(so),Evidence.Json)}]};chats.Save(sc);return sc;
            case "event":return engine.Snapshot().FirstOrDefault(x=>x.Id==Text("id"))??throw new ArgumentException("Event is no longer in the live buffer.");
            case "unifi-save":
                var cfg=plugins.Load();cfg.UnifiUrl=UnifiClient.ValidateUrl(Text("url")).AbsoluteUri.TrimEnd('/');cfg.CertificatePin=UnifiClient.ValidatePin(Text("pin"));
                var site=Text("site");if(site.Length>0&&!Guid.TryParse(site,out _))throw new ArgumentException("Choose a valid site UUID from Test connection.");cfg.UnifiSite=site;
                if(Text("key").Length>0)cfg.UnifiKey=PluginStore.Protect(Text("key"));if(cfg.UnifiKey.Length==0)throw new ArgumentException("Enter a UniFi integration API key.");cfg.Unifi=true;plugins.Save(cfg);break;
            case "unifi-remove":plugins.RemoveUnifi();break;
            case "unifi-test":return await new UnifiClient(plugins).Get("sites");
            case "unifi-clients":return await new UnifiClient(plugins).Get("clients");
            case "configure":
                if(!SensorSetup.IsAdministrator)throw new InvalidOperationException("Restart as administrator to configure Windows sensors.");
                engine.RequireIdle();using(var dialog=new SetupDialog())if(dialog.ShowDialog(this)==DialogResult.OK)await SensorSetup.Configure(dialog.Executable,dialog.RestoreXml,dialog.ReplaceExisting,dialog.AcceptLicense);await engine.RefreshReadiness();break;
            case "restore":if(MessageBox.Show(this,"Restore the sensor configuration and PowerShell policies saved by Observe?", "Restore sensors",MessageBoxButtons.YesNo)==DialogResult.Yes)await SensorSetup.Restore();break;
            case "elevate":await engine.Finish();Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"});BeginInvoke(Close);break;
            case "sysmon-license":Process.Start(new ProcessStartInfo("https://learn.microsoft.com/en-us/sysinternals/license-terms"){UseShellExecute=true});break;
            case "install":if(testMode)throw new InvalidOperationException("Installation is disabled in UI tests.");await Installation.Install(new InstallSelection{Cities=Flag("cities"),WindowsLogging=Flag("logging"),Unifi=Flag("unifi"),Observer=Flag("observer"),ThreatFox=Flag("threatfox"),AcceptSysmonLicense=Flag("license"),StartAtLogin=Flag("startup")});return new{installed=true};
            case "uninstall":if(testMode)throw new InvalidOperationException("Uninstallation is disabled in UI tests.");Installation.StartUninstall(Flag("disableSysmon"));BeginInvoke(Close);break;
            case "setup":Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Arguments="--install"});break;
            case "uninstall-dialog":await engine.Finish();Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Arguments="--uninstall"});BeginInvoke(Close);break;
            case "launch":Process.Start(new ProcessStartInfo(Path.Combine(Installation.InstallRoot,"Observe.exe")){UseShellExecute=true});BeginInvoke(Close);break;
            case "close":BeginInvoke(Close);break;
            default:throw new ArgumentException("Unknown application command.");
        }
        return new{ok=true};
    }
    ObserverConversation BindTrackedChat(string id)
    {
        var chat=chats.Get(id);
        if(chat.TrackedRunId.Length==0&&chat.Messages.FirstOrDefault()?.Text.StartsWith("Recorded launch of ")==true)
        {
            try
            {
                using var payload=JsonDocument.Parse(chat.Messages.First(m=>m.Evidence.Length>0).Evidence);
                var start=payload.RootElement.GetProperty("investigation").GetProperty("executionStart").GetDateTimeOffset();
                var runs=JsonSerializer.SerializeToElement(engine.Launches.List(),Evidence.Json);
                foreach(var run in runs.EnumerateArray())if(run.GetProperty("path").GetString()?.Equals(chat.Subject,StringComparison.OrdinalIgnoreCase)==true&&Math.Abs((run.GetProperty("started").GetDateTimeOffset()-start).TotalMilliseconds)<250){chat.TrackedRunId=run.GetProperty("id").GetString()!;chats.Save(chat);break;}
            }
            catch(Exception error)when(error is JsonException or InvalidOperationException or KeyNotFoundException){Debug.WriteLine(error.Message);}
        }
        return chat;
    }
    async Task<Observation> ReadScripts(int minutes)
    {
        var saved=engine.HistoryEvents(minutes);
        var result=engine.Gaming?new Observation{Start=minutes==0?DateTimeOffset.MinValue:DateTimeOffset.UtcNow.AddMinutes(-minutes),End=DateTimeOffset.UtcNow,Events=saved.Where(ActivityRetention.IsScript).ToList(),Warnings=["Monitoring is paused. Showing saved records only."]}:await Task.Run(()=>ForensicQueries.Read(minutes==0?10080:minutes,saved));
        if(minutes==0)result.Events=result.Events.Concat(saved.Where(ActivityRetention.IsScript)).DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToList();
        engine.Persist(result.Events);return result;
    }
    object[] ProcessConnections(ProcessSnapshot snapshot)
    {
        var events=engine.HistoryEvents(60).Where(e=>e.IsNetwork).ToLookup(e=>e.Data.GetValueOrDefault("ProcessId",""));return snapshot.Processes.Where(p=>p.Started is not null).Select(p=>
        {
            var linked=events[p.Pid.ToString()].Where(e=>e.Timestamp>=p.Started&&Path.GetFileName(e.Data.GetValueOrDefault("Image","")).Equals(Path.GetFileName(p.Image),StringComparison.OrdinalIgnoreCase)&&(!DateTimeOffset.TryParse(e.Data.GetValueOrDefault("ProcessStartTime"),out var born)||Math.Abs((born-p.Started!.Value).TotalMilliseconds)<250)).ToArray();
            return (object)new{pid=p.Pid,flows=NetworkSnapshots.Create(linked,60).Flows.Length,events=linked.Length};
        }).ToArray();
    }
    Observation ReadProgram(string question,string subject,int minutes,EvidenceEvent[] saved,CancellationToken token)
    {
        var result=ProgramEvidence.Read(question,subject,minutes,saved,token);engine.Persist(result.Events);return result;
    }
    Observation TrackedObservation(string id)
    {
        if(id.StartsWith("canary:",StringComparison.Ordinal)){var snapshot=engine.Canary.Observation(id[7..]);engine.Persist(snapshot.Events);return snapshot;}
        var run=engine.Launches.Get(id);var linked=TrackedCorrelation.Read(run);
        return new(){Question="Explain this exact tracked process lifetime and descendants.",Start=run.Started,End=run.Ended??DateTimeOffset.UtcNow,Events=linked.Events.ToList(),Warnings=run.Warnings.Append("This snapshot was refreshed from the saved recording for this answer. Other instances of the same executable are separate processes; they are not attributed to this recording.").ToList(),Investigation=new(){Script=run.Path,Match="Exact tracked process lifetime",ExecutionStart=run.Started,ProcessId=run.RootPid.ToString(),ScannedEvents=run.Events.Count}};
    }
    async void OnClosing(object? sender,FormClosingEventArgs e)
    {
        if(closing)return;e.Cancel=true;closing=true;timer.Stop();chatCancellation?.Cancel();try{if(chatTask is not null)await chatTask;await engine.DisposeAsync();}catch(Exception error){Debug.WriteLine(error);}finally{chatCancellation?.Dispose();BeginInvoke(Close);}
    }
    internal Task<string> Script(string script)=>web.CoreWebView2.ExecuteScriptAsync(script);
    internal void SetModTestSnapshot(JsonElement snapshot){if(!testMode)throw new InvalidOperationException("Not a test window.");engine.Mods.TestSnapshot(snapshot);}
    internal async Task CapturePreview(string path){await using var stream=File.Create(path);await web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,stream);}
    protected override void Dispose(bool disposing){if(disposing){canaryNotification.Dispose();timer.Dispose();web.Dispose();}base.Dispose(disposing);}
}
