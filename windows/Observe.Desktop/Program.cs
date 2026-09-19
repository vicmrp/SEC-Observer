using System.Text.Json;

namespace Observe;

internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if(args.Contains("--install-logging-dependencies"))
        {
            try{InstallDependencies.InstallLogging(args.Contains("--accept-sysmon-license")).GetAwaiter().GetResult();return 0;}
            catch(Exception e){MessageBox.Show(e.Message,"Observe logging setup",MessageBoxButtons.OK,MessageBoxIcon.Warning);return 1;}
        }
        if(args.Length>1&&args[0]=="--canary-sensor")return CanarySensor.Run(args[1]).GetAwaiter().GetResult();
        if(args.Length>0&&args[0].StartsWith("--canary-"))
        {
            try
            {
                var lab=new CanaryLab(Path.GetDirectoryName(CanaryLab.DefaultRoot)!);object result;
                switch(args[0])
                {
                    case "--canary-arm":result=lab.Arm();break;
                    case "--canary-install":result=new{path=CanaryLab.InstallMod()};break;
                    case "--canary-stop":lab.Stop();result=lab.View();break;
                    case "--canary-status":result=lab.View();break;
                    case "--canary-test":return CanaryTests.Run(args.Length>1?args[1]:"canary-test-results.json");
                    default:throw new ArgumentException("Unknown canary action.");
                }
                if(args.Length>1)File.WriteAllText(args[1],JsonSerializer.Serialize(result,Evidence.Json));return 0;
            }
            catch(Exception error){if(args.Length>1)File.WriteAllText(args[1],JsonSerializer.Serialize(new{error=error.Message},Evidence.Json));return 1;}
        }
        if(args.Contains("--cities-mod-status")){using var bridge=new CitiesModBridge(new PluginStore());bridge.Refresh().GetAwaiter().GetResult();File.WriteAllText(args[1],JsonSerializer.Serialize(bridge.View([],!SensorSetup.GameSensorsPaused),Evidence.Json));return 0;}
        if(args.Contains("--cities-mod-test"))return CitiesModTests.Run(args[1]).GetAwaiter().GetResult();
        if(args.Contains("--explorer-test"))return ExplorerTests.Run(args.Length>1?args[1]:"explorer-test.json").GetAwaiter().GetResult();
        if(args.Length>0&&args[0] is "--tracking-probe" or "--tracking-child")return WorkspaceTests.Probe(args);
        if(args.Contains("--workspace-test"))return WorkspaceTests.Run(args.Length>1?args[1]:"observe-workspace-test.json").GetAwaiter().GetResult();
        if(args.Contains("--mcp"))return 1; // Retired in 0.5; do not start a GUI for old MCP clients.
        if(args.Contains("--pause-observe-sensors")||args.Contains("--resume-observe-sensors"))
        {
            try{(args.Contains("--pause-observe-sensors")?SensorSetup.PauseGameSensors():SensorSetup.ResumeGameSensors()).GetAwaiter().GetResult();return 0;}
            catch(Exception e){MessageBox.Show(e.Message,"Observe sensor transition",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        }
        if(args.Contains("--remove-legacy-connection")){new PluginStore().RemoveLegacyConnection();return 0;}
        if(args.Contains("--enable-powershell-logging"))
        {
            try{SensorSetup.EnablePowerShellLogging();return 0;}catch(Exception e){MessageBox.Show(e.Message,"PowerShell logging",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        }
        if(args.Contains("--remove-sysmon"))
        {
            try{SensorSetup.DisableSysmon().GetAwaiter().GetResult();return 0;}catch(Exception e){MessageBox.Show(e.Message,"Sysmon removal failed",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        }
        if(args.Contains("--uninstall-worker")){ApplicationConfiguration.Initialize();return Installation.UninstallWorker(int.Parse(args[1]),args.Contains("--disable-sysmon")).GetAwaiter().GetResult();}
        if(args.Contains("--diagnostics"))
        {
            var result=JsonSerializer.Serialize(new{administrator=SensorSetup.IsAdministrator,sysmonInstalled=SensorSetup.InstalledSysmon() is not null,policy=SensorSetup.PolicyStatus(),channels=Collector.Status()},Evidence.Json);
            if(args.Length>1)File.WriteAllText(args[1],result);else Console.WriteLine(result);return 0;
        }
        if(args.Contains("--self-test")) return SelfTests.Run(args.Length>1?args[1]:"observe-self-test.json").GetAwaiter().GetResult();
        if(args.Contains("--feature-test")) return FeatureTests.Run(args.Length>1?args[1]:"observe-feature-test.json").GetAwaiter().GetResult();
        if(args.Contains("--investigation-test")) return InvestigationTests.Run(args.Length>1?args[1]:"observe-investigation-test.json").GetAwaiter().GetResult();
        if(args.Contains("--observer-test")) return ObserverTests.Run(args.Length>1?args[1]:"observe-observer-test.json").GetAwaiter().GetResult();
        if(args.Contains("--live-test")) return LiveTests.Run(args.Length>1?args[1]:"observe-live-test.json").GetAwaiter().GetResult();
        ApplicationConfiguration.Initialize();
        if(args.Contains("--dashboard-test"))return DashboardTests.Run(args.Length>1?args[1]:"observe-dashboard-test.json");
        if(args.Contains("--ui-live-test"))
        {
            var directory=Path.Combine(Path.GetTempPath(),"ObserveUiLive-"+Guid.NewGuid());
            using var form=new MainForm(directory);var code=1;
            form.Shown+=async(_,_)=>
            {
                var output=args.Length>1?args[1]:"observe-ui-live-test.json";
                try{await File.WriteAllTextAsync(output,JsonSerializer.Serialize(await form.TestLiveUi(),Evidence.Json));code=0;}
                catch(Exception e){await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=false,error=e.ToString()},Evidence.Json));}
                finally{form.Dispose();Application.ExitThread();}
            };
            Application.Run(form);Directory.Delete(directory,true);return code;
        }
        if(args.Contains("--ui-smoke"))
        {
            try
            {
                using var form=new MainForm();form.PerformLayout();
                int Count(Control parent)=>parent.Controls.Count+parent.Controls.Cast<Control>().Sum(Count);
                File.WriteAllText(args.Length>1?args[1]:"observe-ui-smoke.json",JsonSerializer.Serialize(new{constructed=true,controls=Count(form),width=form.Width,height=form.Height},Evidence.Json));return 0;
            }
            catch(Exception e){File.WriteAllText(args.Length>1?args[1]:"observe-ui-smoke.json",e.ToString());return 1;}
        }
        Application.ThreadException+=(_,e)=>MessageBox.Show(e.Exception.Message,"Observe error",MessageBoxButtons.OK,MessageBoxIcon.Error);
        var mode=args.Contains("--uninstall")?"uninstall":args.Contains("--install")||Path.GetFileNameWithoutExtension(Environment.ProcessPath!).EndsWith("-Setup",StringComparison.OrdinalIgnoreCase)?"install":"app";
        if(args.Contains("--classic"))Application.Run(new MainForm());else {using var dashboard=new DashboardForm(mode);if(args.Contains("--background")){dashboard.WindowState=FormWindowState.Minimized;dashboard.ShowInTaskbar=true;}Application.Run(dashboard);}return 0;
    }
}
