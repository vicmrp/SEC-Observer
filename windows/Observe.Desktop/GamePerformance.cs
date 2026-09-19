using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json;

namespace Observe;

public sealed class GameSensorBackup
{
    public string Stage {get;set;}="prepared";
    public string SysmonAction {get;set;}="none";
    public string Executable {get;set;}="";
    public string Profile {get;set;}="Forensic";
    public string? OriginalConfig {get;set;}
    public SetupState Current {get;set;}=new();
    public SetupState Previous {get;set;}=new();
}
public static partial class SensorSetup
{
    static string GamePath=>Path.Combine(DirectoryPath,"game-performance.json");
    public static GameSensorBackup? GameBackup()=>File.Exists(GamePath)?JsonSerializer.Deserialize<GameSensorBackup>(File.ReadAllText(GamePath),Evidence.Json):null;
    public static bool GameSensorsPaused=>GameBackup() is {Stage:not "resumed"};
    public static bool HasManagedSensors=>Load() is {Stage:"configured"}||File.Exists(PowerShellBackupPath)&&JsonSerializer.Deserialize<SetupState>(File.ReadAllText(PowerShellBackupPath),Evidence.Json) is {Stage:not "restored"};
    internal static GameSensorBackup PlanGamePause(SetupState? full,SetupState? powershell,Func<string,string,RegistrySetting> registry,Func<string,ChannelSetting?> channel)
    {
        var plan=new GameSensorBackup();
        if(full is not null&&full.Stage is not ("configured" or "restored"))throw new InvalidOperationException("Finish restoring the incomplete sensor setup before using game performance mode.");
        if(full is {Stage:"configured"})
        {
            if(full.SysmonChanged){plan.SysmonAction=full.WasInstalled?"restore-external":"uninstall-owned";plan.Executable=full.SysmonExe;plan.Profile=full.Profile;plan.OriginalConfig=full.OriginalConfig;}
            plan.Previous.Registry.AddRange(full.Registry);plan.Previous.Channels.AddRange(full.Channels);
        }
        if(powershell is {Stage:not "restored"})
        {
            foreach(var p in powershell.Registry){plan.Previous.Registry.RemoveAll(x=>x.Path==p.Path&&x.Name==p.Name);plan.Previous.Registry.Add(p);}
            foreach(var c in powershell.Channels){plan.Previous.Channels.RemoveAll(x=>x.Name==c.Name);plan.Previous.Channels.Add(c);}
        }
        foreach(var p in plan.Previous.Registry)plan.Current.Registry.Add(registry(p.Path,p.Name));
        foreach(var c in plan.Previous.Channels)if(channel(c.Name) is {} current)plan.Current.Channels.Add(current);
        if(plan.SysmonAction!="none"&&!plan.Current.Channels.Any(c=>c.Name==Collector.Channels[0])&&channel(Collector.Channels[0]) is {} sysmon)plan.Current.Channels.Add(sysmon);
        return plan;
    }
    static void SaveGame(GameSensorBackup plan){File.WriteAllText(GamePath+".tmp",JsonSerializer.Serialize(plan,Evidence.Json));File.Move(GamePath+".tmp",GamePath,true);}
    static void ApplyGamePolicies(SetupState state)
    {
        // Preserve retained records and tolerate a channel unregistered by owned Sysmon removal.
        RestorePolicies(new(){Registry=state.Registry});
        foreach(var c in state.Channels)try{using var cfg=new EventLogConfiguration(c.Name);cfg.IsEnabled=c.Enabled;cfg.MaximumSizeInBytes=c.MaximumSize;cfg.LogMode=c.Mode;cfg.SaveChanges();}catch(EventLogNotFoundException){}
    }
    public static async Task PauseGameSensors()
    {
        using var gate=Lock();var existing=GameBackup();if(existing is {Stage:"paused"})return;
        if(existing is {Stage:not "resumed"})throw new InvalidOperationException("A prior sensor transition was interrupted. Restore monitoring first.");
        var ps=File.Exists(PowerShellBackupPath)?JsonSerializer.Deserialize<SetupState>(File.ReadAllText(PowerShellBackupPath),Evidence.Json):null;
        ChannelSetting? Channel(string name){try{using var c=new EventLogConfiguration(name);return new(name,c.IsEnabled,c.MaximumSizeInBytes,c.LogMode);}catch(EventLogNotFoundException){return null;}}
        var plan=PlanGamePause(Load(),ps,Snapshot,Channel);SaveGame(plan);
        try
        {
            plan.Stage="pausing";SaveGame(plan);
            if(plan.SysmonAction!="none")
            {
                await VerifyMicrosoftSysmon(plan.Executable);
                if(plan.SysmonAction=="uninstall-owned"){if(InstalledSysmon() is not null)await Run(plan.Executable,["-u"]);if(InstalledSysmon() is not null)throw new InvalidOperationException("Owned Sysmon removal could not be verified.");}
                else{if(string.IsNullOrWhiteSpace(plan.OriginalConfig))throw new InvalidDataException("The original external Sysmon configuration is missing.");var path=Path.Combine(DirectoryPath,"Game-Original.xml");File.WriteAllText(path,plan.OriginalConfig);await Run(plan.Executable,["-c",path]);}
            }
            ApplyGamePolicies(plan.Previous);plan.Stage="paused";SaveGame(plan);
        }
        catch{plan.Stage="pause-incomplete";SaveGame(plan);throw;}
    }
    public static async Task ResumeGameSensors()
    {
        using var gate=Lock();var plan=GameBackup();if(plan is null||plan.Stage=="resumed")return;
        plan.Stage="resuming";SaveGame(plan);
        try
        {
            if(plan.SysmonAction!="none")
            {
                await VerifyMicrosoftSysmon(plan.Executable);var xml=Path.Combine(DirectoryPath,"Game-Resume.xml");File.WriteAllText(xml,ProfileXml(plan.Profile));
                await Run(plan.Executable,InstalledSysmon() is null?["-accepteula","-i",xml]:["-c",xml]);
            }
            ApplyGamePolicies(plan.Current);plan.Stage="resumed";SaveGame(plan);
        }
        catch{plan.Stage="resume-incomplete";SaveGame(plan);throw;}
    }
    public static async Task SwitchGameSensors(bool pause)
    {
        if(pause&&!HasManagedSensors&&!GameSensorsPaused)return;
        if(!pause&&!GameSensorsPaused)return;
        if(IsAdministrator){if(pause)await PauseGameSensors();else await ResumeGameSensors();return;}
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};info.ArgumentList.Add(pause?"--pause-observe-sensors":"--resume-observe-sensors");
        using var helper=Process.Start(info)??throw new InvalidOperationException("Windows did not start the sensor helper.");await helper.WaitForExitAsync();
        if(helper.ExitCode!=0)throw new InvalidOperationException("The sensor change did not finish. Monitoring is not confirmed restored. Use Restore monitoring to retry; the backup is retained.");
    }
}
