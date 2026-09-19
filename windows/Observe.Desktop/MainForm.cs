using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace Observe;

public sealed partial class MainForm : Form
{
    static readonly Color Background=Color.FromArgb(24,28,28),Card=Color.FromArgb(36,43,41),Accent=Color.FromArgb(181,237,143),Ink=Color.FromArgb(236,242,235),Muted=Color.FromArgb(154,172,159);
    readonly Panel content=new(){Dock=DockStyle.Fill,Padding=new Padding(28)};
    readonly Dictionary<string,Control> pages=[];
    readonly TextBox question=Input("I just installed Markdown PDF. Did it do anything suspicious?",true);
    readonly ComboBox window=Choice(["From now · 15 minutes","From now · 60 minutes","Last 5 minutes","Last 15 minutes","Last hour"]);
    readonly CheckBox automatic=new ReadableCheckBox(){Text="Astra review every minute (sends evidence; max 10 requests)",AutoSize=true,ForeColor=Muted};
    readonly TextBox apiKey=Input(""),gateway=Input(""),serviceToken=Input("");
    readonly ComboBox provider=Choice(["My OpenAI API key","Managed service"]);
    readonly Label status=Label("Checking this device…",10,Muted),metrics=Label("No capture yet",12,Ink),sensorStatus=Label("",10,Muted),modeStatus=Label("",10,Muted),load=Label("",10,Muted);
    readonly Button observe=Button("◎  Observe",true),stop=Button("Stop capture"),game=Button("Enable performance mode"),setup=Button("Configure sensors"),restore=Button("Restore previous sensor settings"),review=Button("Preview & analyze"),elevate=Button("Restart as administrator");
    readonly DataGridView events=Grid(),networks=Grid(),history=Grid();
    readonly TextBox report=Input("Start an observation or load the synthetic demo.",true);
    readonly SessionStore store;
    readonly Collector collector=new();
    NetworkMonitor network=new();
    readonly Observation live=new(){Question="Live local activity",Status="live"};
    readonly HashSet<string> liveIds=[];
    readonly List<Label> liveLabels=[];
    readonly Label aiNotice=Label("! Set an API key in Settings to enable Astra features.",10,Color.FromArgb(238,196,116));
    readonly Label reviewNotice=Label("",10,Color.FromArgb(238,196,116));
    readonly Label networkStatus=Label("Starting live network monitor…",10,Muted);
    readonly ToolTip tips=new(){ShowAlways=true};
    string lastRenderedId="";
    readonly ConcurrentQueue<EvidenceEvent> incoming=new();
    readonly ConcurrentQueue<string> gaps=new();
    readonly HashSet<string> seen=[];
    readonly System.Windows.Forms.Timer timer=new(){Interval=1000};
    Observation? session;
    bool busy,ticking,gaming,collecting,closing,analyzing,limitReached,resourcesDisposed;
    int pendingCount,lastRendered=-1,lastAnalyzed=-1;
    long capturedBytes;
    DateTimeOffset deadline,lastSave=DateTimeOffset.MinValue,lastAnalysis=DateTimeOffset.MinValue;
    TimeSpan cpuPrevious=TimeSpan.Zero; DateTimeOffset cpuAt=DateTimeOffset.UtcNow;
    CancellationTokenSource analysisCancellation=new();

    public MainForm(string? storageDirectory=null)
    {
        store=new SessionStore(storageDirectory);
        Text="Observe 0.3 — Live Windows forensics"; MinimumSize=new Size(1100,760); Size=new Size(1440,960); StartPosition=FormStartPosition.CenterScreen;
        AutoScaleDimensions=new SizeF(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        BackColor=Background; ForeColor=Ink; Font=new Font("Segoe UI",10);
        var navigation=new FlowLayoutPanel { Dock=DockStyle.Left,Width=205,BackColor=Color.FromArgb(17,38,32),Padding=new Padding(18,24,16,20),FlowDirection=FlowDirection.TopDown,WrapContents=false };
        navigation.Controls.Add(Label("observe.",22,Accent,165,55)); navigation.Controls.Add(Label("LOCAL WINDOWS WORKSPACE",8,Muted,165,45));
        foreach(var title in new[]{"Overview","Activity","Domains & IPs","Assessment","History","Settings"}) { var button=Button(title); button.Width=165; button.Height=43; button.Margin=new Padding(0,5,0,5); button.Click+=(_,_)=>ShowPage(title); navigation.Controls.Add(button); }
        navigation.Controls.Add(Label("Native .NET · 0.3\nMIT open source\n\nLocal monitoring works\nwithout an API key.",9,Muted,165,160));
        Controls.Add(content); Controls.Add(navigation);
        pages["Overview"]=Overview(); pages["Activity"]=TablePage("Activity timeline","Double-click an event to inspect the original evidence. Showing the latest 500 events.",events);
        pages["Domains & IPs"]=TablePage("Domains & IPs","Live connections and DNS. Cached names are IP matches, not confirmed visits. Run as administrator for TCP/UDP send and receive. Full URLs and HTTPS content are not captured.",networks);
        pages["Assessment"]=ReportPage(); pages["History"]=HistoryPage(); pages["Settings"]=SettingsPage();
        foreach(var page in pages.Values) { page.Dock=DockStyle.Fill; page.Visible=false; content.Controls.Add(page); }
        ShowPage("Overview"); report.ReadOnly=true; report.Font=new Font("Consolas",10); report.ScrollBars=ScrollBars.Both; report.WordWrap=true;
        apiKey.UseSystemPasswordChar=true; serviceToken.UseSystemPasswordChar=true;
        observe.Click+=async(_,_)=>await Work(StartObservation); stop.Click+=async(_,_)=>await Work(Finish);
        setup.Click+=async(_,_)=>await Work(Configure); restore.Click+=async(_,_)=>await Work(RestoreSensors);
        game.Click+=async(_,_)=>await Work(ChangeMode); elevate.Click+=(_,_)=>Elevate();
        review.Click+=async(_,_)=>await Work(()=>Review(true));
        automatic.CheckedChanged+=(_,_)=> { if(automatic.Checked && MessageBox.Show(this,$"Minimized commands, scripts, domains and IPs will be sent to {(provider.SelectedIndex==0 ? "OpenAI" : "your configured service and OpenAI")} every minute during capture. Redaction is best effort. API costs may apply. Allow for this capture?","Live AI analysis",MessageBoxButtons.YesNo,MessageBoxIcon.Information)!=DialogResult.Yes) automatic.Checked=false; };
        collector.Recorded+=Enqueue;
        collector.Gap+=g=>gaps.Enqueue(g);
        ConnectNetwork();
        foreach(var field in new[]{apiKey,gateway,serviceToken})field.TextChanged+=(_,_)=>ControlsEnabled();
        provider.SelectedIndexChanged+=(_,_)=>ControlsEnabled();
        events.CellDoubleClick+=(_,e)=> { if(e.RowIndex>=0 && events.Rows[e.RowIndex].Tag is EvidenceEvent record) TextDialog("Original event evidence",JsonSerializer.Serialize(record,Evidence.Json),false); };
        history.CellDoubleClick+=async(_,e)=> { if(e.RowIndex>=0 && history.Rows[e.RowIndex].Tag is Observation s) await Work(()=>LoadObservation(s)); };
        timer.Tick+=async(_,_)=>await Tick(); timer.Start();
        Shown+=async(_,_)=> { await Work(RefreshSensors); collector.Start(DateTimeOffset.UtcNow); await Task.Run(network.StartTrace); RefreshHistory(); RenderEvidence(); };
        FormClosing+=OnClosing;
        ControlsEnabled();RenderEvidence();
    }
    void Enqueue(EvidenceEvent e)
    {
        if(Interlocked.Increment(ref pendingCount)<=5000)incoming.Enqueue(e);
        else{Interlocked.Decrement(ref pendingCount);if(gaps.IsEmpty)gaps.Enqueue("The event queue overflowed. Some activity was omitted.");}
    }
    void ConnectNetwork(){network.Recorded+=Enqueue;network.Gap+=g=>gaps.Enqueue(g);}
    static Label Label(string text,int size,Color color,int width=0,int height=0) => new(){Text=text,Font=new Font("Segoe UI",size),ForeColor=color,AutoSize=width==0,Width=width,Height=height,Margin=new Padding(0,4,0,10)};
    static TextBox Input(string text,bool multiline=false) => new(){Text=text,Multiline=multiline,BackColor=Color.FromArgb(27,33,30),ForeColor=Ink,BorderStyle=BorderStyle.FixedSingle,Font=new Font("Segoe UI",11),Dock=DockStyle.Fill,Margin=new Padding(0,4,0,12)};
    static ComboBox Choice(string[] choices) { var c=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,BackColor=Card,ForeColor=Ink,Width=260,Margin=new Padding(0,4,12,12)}; c.Items.AddRange(choices); c.SelectedIndex=0; return c; }
    static Button Button(string text,bool primary=false) => new ReadableButton(){Text=text,AutoSize=true,MinimumSize=new Size(130,38),Padding=new Padding(12,6,12,6),FlatStyle=FlatStyle.Flat,BackColor=primary ? Accent : Card,ForeColor=primary ? Color.FromArgb(22,46,30) : Ink,Margin=new Padding(0,4,12,8)};
    static DataGridView Grid() => new(){Dock=DockStyle.Fill,BackgroundColor=Background,BorderStyle=BorderStyle.None,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,RowHeadersVisible=false,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,SelectionMode=DataGridViewSelectionMode.FullRowSelect,MultiSelect=false,EnableHeadersVisualStyles=false,ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.AutoSize,ColumnHeadersDefaultCellStyle=new(){BackColor=Card,ForeColor=Accent,Padding=new Padding(7)},DefaultCellStyle=new(){BackColor=Background,ForeColor=Ink,SelectionBackColor=Color.FromArgb(58,81,59),SelectionForeColor=Ink,Padding=new Padding(5),Font=new Font("Segoe UI",9)},RowTemplate={Height=35}};
    static TableLayoutPanel Stack(params (Control control,int height)[] children)
    {
        var p=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=children.Length,BackColor=Background};
        for(var i=0;i<children.Length;i++){p.RowStyles.Add(new RowStyle(children[i].height<0 ? SizeType.Percent : SizeType.Absolute,children[i].height<0 ? 100 : children[i].height)); children[i].control.Dock=DockStyle.Fill;p.Controls.Add(children[i].control,0,i);} return p;
    }
    static FlowLayoutPanel Row(params Control[] controls) { var p=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,AutoScroll=false};p.Controls.AddRange(controls);return p; }
    Control Overview()
    {
        var demo=Button("Explore demo"); demo.Click+=async(_,_)=>await Work(()=>LoadObservation(Evidence.Demo()));
        var refresh=Button("Refresh readiness"); refresh.Click+=async(_,_)=>await Work(RefreshSensors);
        var top=Row(Label("Know what happened.",27,Ink),elevate);
        var card=new Panel{Dock=DockStyle.Fill,BackColor=Card,Padding=new Padding(20)};
        var query=Stack((Label("What would you like to investigate?",15,Ink),44),(question,72),(Row(window,observe,stop),62),(Row(automatic),38),(aiNotice,38));query.BackColor=Card; card.Controls.Add(query);
        var telemetry=Label("Activity and Domains & IPs update automatically. Observe saves a timed capture. Browser secure DNS (DoH), VPNs and brief connections can limit visibility.",10,Muted); telemetry.MaximumSize=new Size(1000,0);
        var layout=Stack((top,70),(status,52),(card,300),(metrics,45),(networkStatus,80),(Row(setup,game,demo),62),(modeStatus,100),(sensorStatus,112),(Row(refresh,load),55),(telemetry,70));
        layout.Dock=DockStyle.Top;layout.Height=1050;var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};scroll.Controls.Add(layout);return scroll;
    }
    Control TablePage(string title,string subtitle,Control table)
    {
        var hint=Label(subtitle,10,Muted);hint.MaximumSize=new Size(1100,0);
        var caption=Label("Live · waiting for first refresh",10,Accent);liveLabels.Add(caption);
        var goLive=Button("Return to live");goLive.Click+=(_,_)=>{if(collecting)return;session=null;lastRendered=-1;RenderEvidence();ControlsEnabled();};
        return Stack((Label(title,25,Ink),65),(hint,64),(Row(goLive,caption),62),(table,-1));
    }
    Control ReportPage()
    {
        var export=Button("Export evidence");export.Click+=async(_,_)=>await Work(Export);
        return Stack((Label("Evidence before conclusions.",25,Ink),65),(Row(review,export),60),(reviewNotice,48),(Label("Reports are advisory. A quiet log does not establish that an application is safe.",10,Muted),45),(report,-1));
    }
    Control HistoryPage()
    {
        var refresh=Button("Refresh history");refresh.Click+=(_,_)=>RefreshHistory();
        var folder=Button("Open local evidence folder");folder.Click+=(_,_)=>Process.Start(new ProcessStartInfo(store.DirectoryPath){UseShellExecute=true});
        return Stack((Label("Observation history",25,Ink),60),(Label("Double-click to open. Raw logs are local and can contain sensitive data. No automatic upload.",10,Muted),45),(Row(refresh,folder),55),(history,-1));
    }
    Control SettingsPage()
    {
        var panel=new TableLayoutPanel{Dock=DockStyle.Top,ColumnCount=1,AutoSize=true};
        void Add(Control c,int height){c.Dock=DockStyle.Top;c.Height=height;panel.RowStyles.Add(new RowStyle(SizeType.Absolute,height+10));panel.Controls.Add(c,0,panel.RowCount++);}
        Add(Label("Your analysis, your choice.",25,Ink),50);Add(Label("Credentials are held only in memory for this run. Stop capture before editing them.",10,Muted),35);
        Add(provider,34);Add(Label("OpenAI API key · GPT-6 Astra",10,Muted),25);Add(apiKey,32);
        Add(Label("Managed-service URL · HTTPS required outside localhost",10,Muted),25);Add(gateway,32);Add(Label("Managed-service access token",10,Muted),25);Add(serviceToken,32);
        Add(Label("Sensor controls",17,Ink),42);Add(restore,42);
        var doc=Button("Microsoft Sysmon documentation");doc.Click+=(_,_)=>Process.Start(new ProcessStartInfo("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"){UseShellExecute=true});Add(doc,42);
        var privacy=Label("Live activity stays in a bounded memory buffer. Observe saves a timed capture to local history. Local monitoring needs no API key. Windows sensors log independently after setup. Performance mode slows refresh and pauses transfer tracing and AI; an Observe-managed Sysmon profile also reduces logging. Antivirus and firewall settings are unchanged.",10,Muted);privacy.MaximumSize=new Size(840,0);Add(privacy,140);
        var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};scroll.Controls.Add(panel);return scroll;
    }
    void ShowPage(string name) { foreach(var (key,page) in pages) page.Visible=key==name; if(pages.TryGetValue(name,out var chosen)) chosen.BringToFront(); if(name is "Activity" or "Domains & IPs"){lastRendered=-1;RenderEvidence();} }
    void ControlsEnabled()
    {
        observe.Enabled=!busy&&!collecting;stop.Enabled=!busy&&collecting;setup.Enabled=!busy&&!collecting;restore.Enabled=!busy&&!collecting;game.Enabled=!busy&&!collecting;
        var ready=HasCredentials;
        review.Enabled=ready&&!busy&&!gaming&&session is not null;automatic.Enabled=ready&&!collecting&&!gaming&&!busy;
        if(!ready)automatic.Checked=false;
        var notice=!ready ? provider.SelectedIndex==0?"! Set an API key in Settings to enable Astra features.":"! Set a service URL and access token in Settings to enable Astra features." : gaming?"! Astra review is paused in performance mode.":"Astra ready · Local monitoring also works without AI.";
        aiNotice.Text=notice;reviewNotice.Text=notice+(ready&&session is null?" Save an observation to analyze it.":"");
        tips.SetToolTip(review,notice);tips.SetToolTip(automatic,notice);
        foreach(Control c in new Control[]{apiKey,gateway,serviceToken,provider,window}) c.Enabled=!collecting&&!busy;
        elevate.Visible=!SensorSetup.IsAdministrator;
    }
    bool HasCredentials=>provider.SelectedIndex==0?!string.IsNullOrWhiteSpace(apiKey.Text):!string.IsNullOrWhiteSpace(serviceToken.Text)&&Uri.TryCreate(gateway.Text,UriKind.Absolute,out var uri)&&(uri.Scheme=="https"||uri.Scheme=="http"&&uri.IsLoopback);
    async Task Work(Func<Task> action)
    {
        if(busy)return; busy=true;ControlsEnabled();
        try{await action();}catch(Exception e){status.Text=e.Message;if(!closing)MessageBox.Show(this,e.Message,"Observe",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
        finally{busy=false;ControlsEnabled();}
    }
    void Warn(string message){if(session is not null&&!session.Warnings.Contains(message))session.Warnings.Add(message);}
    void Drain()
    {
        var changed=false;
        while(gaps.TryDequeue(out var gap)){Warn(gap);if(!live.Warnings.Contains(gap)&&live.Warnings.Count<100)live.Warnings.Add(gap);changed=true;}
        while(incoming.TryDequeue(out var item))
        {
            Interlocked.Decrement(ref pendingCount);
            if(item.Timestamp>=live.Start&&liveIds.Add(item.Id))
            {
                live.Events.Add(item);if(live.Events.Count>2000){liveIds.Remove(live.Events[0].Id);live.Events.RemoveAt(0);}if(session is null)changed=true;
            }
            if(session is null||item.Timestamp<session.Start||session.End is { } end&&item.Timestamp>end||seen.Contains(item.Id))continue;
            var bytes=System.Text.Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(item,Evidence.Json));
            if(session.Events.Count>=5000||capturedBytes+bytes>16_000_000){limitReached=true;Warn("Local capture limit reached (5,000 events / 16 MB). Some activity was omitted.");continue;}
            seen.Add(item.Id);session.Events.Add(item);capturedBytes+=bytes;changed=true;
        }
        if(changed)RenderEvidence();
    }
    async Task Tick()
    {
        if(ticking||closing)return;ticking=true;
        try
        {
            await Task.Run(network.Poll);
            if(closing)return;
            Drain();using var p=Process.GetCurrentProcess();var now=DateTimeOffset.UtcNow;var elapsed=(now-cpuAt).TotalMilliseconds;
            networkStatus.Text=network.TcpStatus+"\n"+network.DnsStatus+"\n"+network.TraceStatus;
            foreach(var caption in liveLabels)caption.Text=(session is null?"LIVE · ":collecting?"RECORDING · ":"SAVED CAPTURE · ")+(session is null||collecting?$"Updated {network.LastPoll?.ToLocalTime():HH:mm:ss} · {timer.Interval/1000}s refresh":"Return to live to see new activity");
            var cpu=elapsed>0 ? Math.Max(0,(p.TotalProcessorTime-cpuPrevious).TotalMilliseconds/elapsed/Environment.ProcessorCount*100) : 0;
            load.Text=$"Observe CPU {cpu:F1}% · RAM {p.WorkingSet64/1024/1024} MB";cpuPrevious=p.TotalProcessorTime;cpuAt=now;
            if(collecting&&!busy)
            {
                if(now>=deadline||session!.Events.Count>=5000||limitReached)await Work(Finish);
                else if((now-lastSave).TotalSeconds>=(gaming?60:20)){await store.Save(session!);lastSave=now;}
                if(collecting&&!gaming&&automatic.Checked&&!busy&&session!.Events.Count>0&&session.Events.Count!=lastAnalyzed&&session.AnalysisRequests<10&&(now-lastAnalysis).TotalSeconds>=60)await Work(()=>Review(false));
            }
        }
        catch(Exception e){status.Text=$"Observation issue: {e.Message}";Warn(e.Message);}
        finally{ticking=false;}
    }
    async Task RefreshSensors()
    {
        var checks=await Task.Run(Collector.Status);sensorStatus.Text=string.Join(Environment.NewLine,checks.Select(s=>s.Replace("Microsoft-Windows-", "")));
        var saved=SensorSetup.Load();if(saved?.Stage=="configured")gaming=saved.Profile=="Gaming";ApplyModeToUi();
        if(saved?.Stage!="configured")modeStatus.Text="Sysmon uses an external configuration; its filters may omit ordinary activity. Independent TCP and DNS monitoring is active. Configure sensors for fuller forensic logging.\n"+SensorSetup.PolicyStatus();
        status.Text=$"Live local monitoring · {(SensorSetup.IsAdministrator ? "Administrator access" : "Standard user; some forensic logs require administrator access")} · No API key required";
        if(saved?.Stage is "incomplete" or "applying-sysmon" or "applying-policies" or "prepared")status.Text="Sensor setup is incomplete. Use Restore previous sensor settings before trying setup again.";
    }
    void ApplyModeToUi()
    {
        timer.Interval=gaming?5000:1000;game.Text=gaming?"Return to forensic mode":"Enable performance mode";modeStatus.Text=SensorSetup.Coverage(gaming?"Gaming":"Forensic");
        network.Gaming=gaming;
        if(gaming)automatic.Checked=false;
        try{Process.GetCurrentProcess().PriorityClass=gaming?ProcessPriorityClass.BelowNormal:ProcessPriorityClass.Normal;}catch(System.ComponentModel.Win32Exception){}
        ControlsEnabled();
    }
    void Elevate()
    {
        if(collecting){MessageBox.Show(this,"Stop the observation before restarting.");return;}
        try{Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"});Close();}
        catch(System.ComponentModel.Win32Exception e) when(e.NativeErrorCode==1223){status.Text="Administrator request cancelled. No sensor settings changed.";}
    }
    async Task Configure()
    {
        if(!SensorSetup.IsAdministrator){Elevate();return;}
        using var dialog=new SetupDialog();if(dialog.ShowDialog(this)!=DialogResult.OK)return;
        status.Text="Applying sensor configuration. Backup is saved before changes.";
        await SensorSetup.Configure(dialog.Executable,dialog.RestoreXml,dialog.ReplaceExisting,dialog.AcceptLicense);
        await RefreshSensors();MessageBox.Show(this,"Sensors configured. New PowerShell sessions will use the policy. Click Observe before the activity you want to investigate.","Ready",MessageBoxButtons.OK,MessageBoxIcon.Information);
    }
    async Task RestoreSensors()
    {
        if(!SensorSetup.IsAdministrator){Elevate();return;}
        if(MessageBox.Show(this,"Restore the saved PowerShell policies and event-channel settings? Existing Sysmon uses your supplied original XML. Sysmon installed by Observe will be uninstalled. This can reduce logging back to its previous level.","Restore sensor configuration",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        await SensorSetup.Restore();await RefreshSensors();
    }
    async Task ChangeMode()
    {
        var next=gaming?"Forensic":"Gaming";
        if(SensorSetup.Load()?.Stage=="configured")
        {
            if(!SensorSetup.IsAdministrator){Elevate();return;}
            if(MessageBox.Show(this,SensorSetup.Coverage(next)+"\n\nChange the managed Sysmon profile too?","Change collection profile",MessageBoxButtons.YesNo,MessageBoxIcon.Information)!=DialogResult.Yes)return;
            await SensorSetup.SetProfile(next);
        }
        await ApplyLocalMode(!gaming);
        status.Text=gaming?"Performance mode · 5s TCP refresh, 15s DNS cache refresh, transfer tracing and AI paused.":"Live mode · 1s TCP refresh, 3s DNS cache refresh.";
    }
    async Task ApplyLocalMode(bool enabled)
    {
        gaming=enabled;network.Dispose();network=new NetworkMonitor{Gaming=gaming};ConnectNetwork();await Task.Run(network.StartTrace);ApplyModeToUi();
        if(SensorSetup.Load()?.Stage!="configured")modeStatus.Text=gaming?"Performance mode for this app session: slower refresh, transfer tracing and AI paused. Your external Sysmon configuration is unchanged.":"Independent live monitoring active. Sysmon coverage depends on its external configuration.";
    }
    async Task StartObservation()
    {
        if(string.IsNullOrWhiteSpace(question.Text))throw new InvalidOperationException("Enter what you want to investigate.");
        if(automatic.Checked&&string.IsNullOrWhiteSpace(provider.SelectedIndex==0?apiKey.Text:serviceToken.Text))throw new InvalidOperationException("Set your analysis credentials before enabling automatic review.");
        ResetCapture();
        var lookback=window.SelectedIndex switch{2=>5,3=>15,4=>60,_=>0};var now=DateTimeOffset.UtcNow;
        session=new Observation{Question=question.Text,Start=now.AddMinutes(-lookback),End=lookback>0?now:null,Status=lookback>0?"loading":"observing"};
        var managed=SensorSetup.Load()?.Stage=="configured";
        session.Profiles.Add(new(now,managed ? gaming?"Gaming":"Forensic" : "External / unknown",managed?SensorSetup.Coverage(gaming?"Gaming":"Forensic"):"Observe has not configured the existing sensors. Event-type coverage is unknown."));
        Warn("Telemetry includes unrelated background activity. A DNS query or connection is not proof of a website visit. Full URLs, page content, and encrypted payloads are not recorded.");
        Warn("Logs can be missing, filtered, cleared, delayed or overwritten. Performance mode intentionally reduces coverage. PowerShell script fragments are not reassembled.");
        Warn(NetworkMonitor.Coverage);
        Warn(network.TraceStatus);
        if(managed)Warn(SensorSetup.Coverage(gaming?"Gaming":"Forensic"));
        if(SensorSetup.Load()?.Stage!="configured")Warn("Observe has not configured these sensors; event-type and policy coverage is unknown.");
        if(!SensorSetup.PolicyStatus().Contains("policy enabled"))Warn(SensorSetup.PolicyStatus());
        foreach(var warning in live.Warnings)Warn(warning);lastAnalysis=now;deadline=now.AddMinutes(window.SelectedIndex==1?60:15);
        await store.Save(session);
        if(lookback>0){await Task.Run(()=>collector.ReadWindow(session.Start,now,CancellationToken.None));Drain();session.Status="complete";Warn("Retrospective capture includes only events still retained by Windows. Live connection sampling cannot recover past traffic.");await store.Save(session);collector.Start(DateTimeOffset.UtcNow);}
        else{collecting=true;collector.Start(now);network.ReplaySnapshot();}
        status.Text=lookback>0?"Retrospective capture complete.":"Observing. Run your installer, script, or game, then stop capture.";RenderEvidence();
    }
    void ResetCapture(){Drain();collector.Dispose();seen.Clear();capturedBytes=0;limitReached=false;lastRendered=-1;lastRenderedId="";lastAnalyzed=-1;lastSave=DateTimeOffset.UtcNow;}
    async Task Finish()
    {
        if(!collecting||session is null)return;await Task.Run(network.Poll);session.End=DateTimeOffset.UtcNow;collecting=false;collector.Dispose();
        await Task.Run(()=>collector.ReadWindow(session.Start,session.End.Value,CancellationToken.None));Drain();session.Status="complete";await store.Save(session);RenderEvidence();RefreshHistory();collector.Start(DateTimeOffset.UtcNow);status.Text="Capture saved locally. Select Return to live for current traffic.";
        if(automatic.Checked&&!gaming&&session.Events.Count>0&&session.Events.Count!=lastAnalyzed&&session.AnalysisRequests<10)await Review(false);
    }
    async Task LoadObservation(Observation s)
    {
        if(collecting)throw new InvalidOperationException("Stop the active observation first.");ResetCapture();session=s;foreach(var e in s.Events)seen.Add(e.Id);collector.Start(DateTimeOffset.UtcNow);RenderEvidence();ShowPage("Assessment");if(s.Demo)await store.Save(s);
    }
    void RenderEvidence()
    {
        var current=session??live;var count=current.Events.Count;
        metrics.Text=$"{(current.Demo ? "SYNTHETIC DEMO · " : session is null?"LIVE · ":"")}{count:N0} events   /   {current.Events.Count(e=>e.EventId==1):N0} process starts   /   {current.Events.Count(e=>e.IsNetwork):N0} network events   /   {Evidence.Detect(current.Events).Count} signals";
        report.Text=current.Report??Analysis.LocalReport(current);
        var tail=current.Events.LastOrDefault()?.Id??"";
        if(count==lastRendered&&tail==lastRenderedId)return;lastRendered=count;lastRenderedId=tail;
        if(events.Columns.Count==0)
        {
            foreach(var (key,label) in new[]{("time","Time"),("kind","Event"),("process","Process"),("detail","Evidence")})events.Columns.Add(key,label);
            events.Columns["detail"]!.FillWeight=220;
            foreach(var (key,label) in new[]{("source","Source"),("process","Process"),("domain","Domain / cache candidate"),("remote","Remote IP / DNS answer"),("local","Local endpoint"),("protocol","Protocol"),("activity","Activity / state"),("bytes","Bytes (ETW)"),("count","Updates"),("time","Last observed")})networks.Columns.Add(key,label);
            foreach(DataGridViewColumn column in networks.Columns)column.MinimumWidth=65;
            networks.Columns["domain"]!.MinimumWidth=150;networks.Columns["remote"]!.MinimumWidth=155;networks.Columns["local"]!.MinimumWidth=135;networks.Columns["source"]!.MinimumWidth=120;networks.Columns["process"]!.MinimumWidth=125;networks.Columns["activity"]!.MinimumWidth=120;
        }
        events.SuspendLayout();networks.SuspendLayout();
        try
        {
            events.Rows.Clear();
            foreach(var e in current.Events.OrderByDescending(e=>e.Timestamp).Take(500)){var index=events.Rows.Add(e.Timestamp.ToLocalTime().ToString("HH:mm:ss"),e.Kind,e.Process,e.Detail);events.Rows[index].Tag=e;}
            networks.Rows.Clear();
            foreach(var r in NetworkView.Rows(current.Events))networks.Rows.Add(r.Source,r.Process,r.Domain,r.Remote,r.Local,r.Protocol,r.Activity,r.Bytes,r.Count,r.Time);
        }
        finally{events.ResumeLayout();networks.ResumeLayout();}
    }
    async Task Review(bool manual)
    {
        if(session is null)return;if(gaming)throw new InvalidOperationException("AI review is paused in performance mode. Return to Forensic mode first.");
        if(session.AnalysisRequests>=10)throw new InvalidOperationException("This observation reached its ten-request limit.");
        Drain();var target=session;var count=target.Events.Count;var payload=JsonSerializer.Serialize(Evidence.Payload(target),Evidence.Json);
        if(manual&&!TextDialog("Evidence preview — "+(provider.SelectedIndex==0?"OpenAI":gateway.Text+" → OpenAI"),payload,true))return;
        var key=provider.SelectedIndex==0?apiKey.Text:serviceToken.Text;var url=provider.SelectedIndex==0?null:gateway.Text;
        if(string.IsNullOrWhiteSpace(key))throw new InvalidOperationException("Enter your key or managed-service token in Settings.");
        if(provider.SelectedIndex==1&&string.IsNullOrWhiteSpace(url))throw new InvalidOperationException("Enter your managed-service URL.");
        lastAnalysis=DateTimeOffset.UtcNow;target.AnalysisRequests++;await store.Save(target);status.Text="Astra is reviewing the fixed evidence snapshot…";
        analyzing=true;
        try{target.Report=await Analysis.Run(payload,key,url,analysisCancellation.Token);lastAnalyzed=count;if(target.Events.Count!=count)target.Report+="\r\n\r\nNew events arrived after this assessment. Review another snapshot for an updated report.";report.Text=target.Report;status.Text="Assessment complete. Review findings and coverage gaps.";}
        finally{analyzing=false;await store.Save(target);}
    }
    bool TextDialog(string title,string text,bool consent)
    {
        using var dialog=new Form{Text=title,Size=new Size(900,650),MinimumSize=new Size(600,450),StartPosition=FormStartPosition.CenterParent,BackColor=Background,ForeColor=Ink};
        var box=Input(text,true);box.ReadOnly=true;box.ScrollBars=ScrollBars.Both;box.Font=new Font("Consolas",9);
        var close=Button(consent?"Cancel":"Close");close.DialogResult=DialogResult.Cancel;
        var agree=new CheckBox{Text="Send this snapshot to the provider. Redaction may miss secrets; API charges can apply.",AutoSize=true,ForeColor=Ink};
        var send=Button("Send to Astra",true);send.Enabled=false;send.DialogResult=DialogResult.OK;agree.CheckedChanged+=(_,_)=>send.Enabled=agree.Checked;
        var bottom=Row(close);if(consent)bottom.Controls.Add(send);
        dialog.Controls.Add(Stack((box,-1),(consent?agree:new Label(),consent?40:0),(bottom,55)));return dialog.ShowDialog(this)==DialogResult.OK;
    }
    async Task Export()
    {
        if(session is null)return;using var dialog=new SaveFileDialog{Filter="JSON evidence|*.json",FileName=$"observe-{session.Id}.json"};if(dialog.ShowDialog(this)!=DialogResult.OK)return;
        // Payload export is minimized and explicitly reports omitted events.
        await File.WriteAllTextAsync(dialog.FileName,JsonSerializer.Serialize(Evidence.Payload(session),Evidence.Json));status.Text="Minimized evidence exported. Full local capture remains in the history folder.";
    }
    void RefreshHistory()
    {
        history.Rows.Clear();history.Columns.Clear();history.Columns.Add("date","Started");history.Columns.Add("question","Question");history.Columns.Add("status","Status");history.Columns.Add("events","Events");
        foreach(var s in store.Load()){var index=history.Rows.Add(s.Start.ToLocalTime().ToString("g"),s.Question,s.Demo?"Synthetic demo":s.Status,s.Events.Count);history.Rows[index].Tag=s;}
    }
    async void OnClosing(object? sender,FormClosingEventArgs e)
    {
        if(closing)return;e.Cancel=true;
        if(busy&&!analyzing){status.Text="Wait for the current operation to finish before closing.";return;}
        if(collecting&&MessageBox.Show(this,"Stop this observation and close? Windows sensor logging continues independently.","Close Observe",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
        closing=true;timer.Stop();analysisCancellation.Cancel();collector.Dispose();network.Dispose();Drain();
        if(session is not null){if(collecting){session.End=DateTimeOffset.UtcNow;session.Status="interrupted";Warn("App closed during observation. Final log drain was not completed.");}try{await store.Save(session);}catch{}}
        BeginInvoke(new Action(Close));
    }
    protected override void Dispose(bool disposing)
    {
        if(disposing&&!resourcesDisposed){resourcesDisposed=true;closing=true;timer.Dispose();collector.Dispose();network.Dispose();tips.Dispose();analysisCancellation.Cancel();analysisCancellation.Dispose();}
        base.Dispose(disposing);
    }
}

