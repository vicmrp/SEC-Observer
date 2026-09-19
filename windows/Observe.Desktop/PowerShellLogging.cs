using Microsoft.Win32;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json;

namespace Observe;

public static partial class SensorSetup
{
    static string PowerShellBackupPath=>Path.Combine(DirectoryPath,"powershell-logging.json");
    public static bool PowerShellLoggingEnabled
    {
        get{using var machine=Registry.LocalMachine.OpenSubKey(PolicyRoots[0]+@"\ScriptBlockLogging");using var user=Registry.CurrentUser.OpenSubKey(PolicyRoots[0]+@"\ScriptBlockLogging");return Convert.ToInt32(machine?.GetValue("EnableScriptBlockLogging")??user?.GetValue("EnableScriptBlockLogging")??0)==1;}
    }
    internal static string SessionWarning(string name,int pid,DateTimeOffset started,DateTimeOffset setupAt)=>
        $"{name} (PID {pid}) started at {started.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}, before Observe's logging setup at {setupAt.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}. It may still use the earlier logging policy. Save your work, close that PowerShell/ISE window and open a new one before the next run. A policy-enabled badge does not verify logging inside an existing session.";
    public static string[] PowerShellSessionWarnings()
    {
        if(!PowerShellLoggingEnabled)return ["PowerShell Script Block Logging is disabled. Enable it in Settings and open a new PowerShell session before the next run."];
        DateTimeOffset? setupAt=null;
        try
        {
            if(File.Exists(PowerShellBackupPath))
            {
                var backup=JsonSerializer.Deserialize<SetupState>(File.ReadAllText(PowerShellBackupPath),Evidence.Json);
                if(backup is not null&&backup.Stage!="restored")setupAt=backup.UpdatedAt;
            }
            var full=Load();if(full?.Stage=="configured"&&(setupAt is null||full.UpdatedAt<setupAt))setupAt=full.UpdatedAt;
        }
        catch(Exception e)when(e is IOException or UnauthorizedAccessException or JsonException){}
        if(setupAt is null)return [];
        var warnings=new List<string>();
        foreach(var name in new[]{"powershell","powershell_ise","pwsh"})foreach(var process in Process.GetProcessesByName(name))using(process)
        {
            try{var started=new DateTimeOffset(process.StartTime);if(started<setupAt)warnings.Add(SessionWarning(name,process.Id,started,setupAt.Value));}
            catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException){}
        }
        return warnings.Take(8).ToArray();
    }
    public static void EnablePowerShellLogging()
    {
        if(GameSensorsPaused)throw new InvalidOperationException("Restore monitoring from game performance mode before enabling PowerShell logging.");
        using var gate=Lock();
        var full=Load();
        // A full sensor backup already owns restoration when it preceded this action.
        if(full is null||full.Stage=="restored")
        {
            SetupState? old=File.Exists(PowerShellBackupPath)?JsonSerializer.Deserialize<SetupState>(File.ReadAllText(PowerShellBackupPath),Evidence.Json):null;
            if(old is null||old.Stage=="restored")
            {
                var backup=new SetupState{Stage="prepared",Profile="PowerShell only"};
                foreach(var root in PolicyRoots){backup.Registry.Add(Snapshot(root+@"\ScriptBlockLogging","EnableScriptBlockLogging"));backup.Registry.Add(Snapshot(root+@"\ModuleLogging","EnableModuleLogging"));backup.Registry.Add(Snapshot(root+@"\ModuleLogging\ModuleNames","*"));}
                foreach(var channel in Collector.Channels.Skip(1)){try{using var c=new EventLogConfiguration(channel);backup.Channels.Add(new(channel,c.IsEnabled,c.MaximumSizeInBytes,c.LogMode));}catch(EventLogNotFoundException){}}
                File.WriteAllText(PowerShellBackupPath,JsonSerializer.Serialize(backup,Evidence.Json));
            }
        }
        else if(full.Stage!="configured")throw new InvalidOperationException("Restore the incomplete sensor setup before enabling logging.");
        foreach(var root in PolicyRoots)
        {
            using var block=Registry.LocalMachine.CreateSubKey(root+@"\ScriptBlockLogging");block.SetValue("EnableScriptBlockLogging",1,RegistryValueKind.DWord);
            using var module=Registry.LocalMachine.CreateSubKey(root+@"\ModuleLogging");module.SetValue("EnableModuleLogging",1,RegistryValueKind.DWord);
            using var names=Registry.LocalMachine.CreateSubKey(root+@"\ModuleLogging\ModuleNames");names.SetValue("*","*",RegistryValueKind.String);
        }
        foreach(var channel in Collector.Channels.Skip(1))
        {
            try{using var c=new EventLogConfiguration(channel);c.IsEnabled=true;c.MaximumSizeInBytes=Math.Max(c.MaximumSizeInBytes,64L*1024*1024);c.LogMode=EventLogMode.Circular;c.SaveChanges();}
            catch(EventLogNotFoundException)when(channel==Collector.Channels[2]){} // PowerShell 7/provider is optional.
        }
        if(!PowerShellLoggingEnabled)throw new InvalidOperationException("Windows did not confirm the logging policy. Check organizational policy.");
    }
    static void RestorePowerShellBackup()
    {
        if(!File.Exists(PowerShellBackupPath))return;
        var backup=JsonSerializer.Deserialize<SetupState>(File.ReadAllText(PowerShellBackupPath),Evidence.Json)!;
        if(backup.Stage=="restored")return;RestorePolicies(backup);backup.Stage="restored";File.WriteAllText(PowerShellBackupPath,JsonSerializer.Serialize(backup,Evidence.Json));
    }
    public static async Task EnablePowerShellWithElevation()
    {
        if(IsAdministrator){await Task.Run(EnablePowerShellLogging);return;}
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};info.ArgumentList.Add("--enable-powershell-logging");
        using var helper=Process.Start(info)??throw new InvalidOperationException("Windows did not start the logging helper.");await helper.WaitForExitAsync();
        if(helper.ExitCode!=0)throw new InvalidOperationException("PowerShell logging was not enabled. Administrator approval is required; existing restore data is retained.");
    }
}
