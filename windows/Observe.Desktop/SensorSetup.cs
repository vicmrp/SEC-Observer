using Microsoft.Win32;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using System.Xml.Linq;

namespace Observe;

public record RegistrySetting(string Path,string Name,bool Existed,string Kind,string? Value);
public record ChannelSetting(string Name,bool Enabled,long MaximumSize,EventLogMode Mode);
public sealed class SetupState
{
    public string Stage { get; set; } = "prepared";
    public string Profile { get; set; } = "Forensic";
    public string SysmonExe { get; set; } = "";
    public bool WasInstalled { get; set; }
    public bool SysmonChanged { get; set; }
    public string? OriginalConfig { get; set; }
    public List<RegistrySetting> Registry { get; set; } = [];
    public List<ChannelSetting> Channels { get; set; } = [];
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public static partial class SensorSetup
{
    public static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ObserveDesktop");
    public static string StatePath => Path.Combine(DirectoryPath,"setup.json");
    public static bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    static readonly string[] PolicyRoots = [@"SOFTWARE\Policies\Microsoft\Windows\PowerShell",@"SOFTWARE\Policies\Microsoft\PowerShellCore"];
    public static string Coverage(string profile) => profile == "Gaming"
        ? "Performance: process starts, DNS, network connections, process tampering, startup writes and PowerShell scripts remain. General file/registry writes, process exits, remote-thread, process-access and WMI detail are omitted. Automatic AI paused; display refresh every 5 seconds."
        : "Forensic: process starts/exits, DNS, network connections, file creation/overwrite and deletion metadata, registry changes, remote threads, selected LSASS access, WMI and script logs. Clipboard, file-content archives and general DLL-load logging are disabled in both Observe profiles.";
    public static string ProfileXml(string profile)
    {
        if(profile is not ("Forensic" or "Gaming")) throw new ArgumentException("Unknown profile.");
        var a=Assembly.GetExecutingAssembly(); var name=a.GetManifestResourceNames().Single(n=>n.EndsWith($".Profiles.{profile}.xml"));
        using var stream=a.GetManifestResourceStream(name)!; using var reader=new StreamReader(stream); return reader.ReadToEnd();
    }
    public static SetupState? Load()
    {
        if(!File.Exists(StatePath)) return null;
        return JsonSerializer.Deserialize<SetupState>(File.ReadAllText(StatePath),Evidence.Json) ?? throw new InvalidDataException("Invalid sensor setup state. Restore your backup before reconfiguring.");
    }
    static void Save(SetupState s) { s.UpdatedAt=DateTimeOffset.UtcNow; File.WriteAllText(StatePath+".tmp",JsonSerializer.Serialize(s,Evidence.Json)); File.Move(StatePath+".tmp",StatePath,true); }
    public static string? InstalledSysmon()
    {
        using var services=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        foreach(var name in new[]{"Sysmon","Sysmon64","Sysmon64a"})
        {
            using var key=services?.OpenSubKey(name);
            if(key?.GetValue("ImagePath") is string value)
            {
                var expanded=Environment.ExpandEnvironmentVariables(value).Trim();
                if(expanded.StartsWith('"')) return expanded.Split('"')[1];
                var end=expanded.IndexOf(".exe",StringComparison.OrdinalIgnoreCase); if(end>=0) return expanded[..(end+4)];
            }
        }
        return null;
    }
    public static string SuggestedExecutable()
    {
        var doc=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Documents","Sysmon","Sysmon64.exe");
        return File.Exists(doc) ? doc : InstalledSysmon() ?? "";
    }
    public static string CanonicalExecutableName(string path)
    {
        using var reader=new BinaryReader(File.OpenRead(path));
        if(reader.ReadUInt16()!=0x5a4d || reader.BaseStream.Length<64)throw new InvalidDataException("Not a Windows executable.");
        reader.BaseStream.Position=60;var offset=reader.ReadInt32();
        if(offset<0||offset>reader.BaseStream.Length-6)throw new InvalidDataException("Invalid executable header.");
        reader.BaseStream.Position=offset;if(reader.ReadUInt32()!=0x00004550)throw new InvalidDataException("Invalid PE signature.");
        return reader.ReadUInt16() switch{0x8664=>"Sysmon64.exe",0x14c=>"Sysmon.exe",0xaa64=>"Sysmon64a.exe",_=>throw new InvalidDataException("Unsupported Sysmon architecture.")};
    }
    static void DemandAdmin() { if(!IsAdministrator) throw new InvalidOperationException("Windows administrator approval is required. Use Restart as administrator."); }
    static FileStream Lock()
    {
        DemandAdmin(); Directory.CreateDirectory(DirectoryPath);
        // ProgramData state must not be writable by an unelevated user.
        var security=new System.Security.AccessControl.DirectorySecurity(); security.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{WellKnownSidType.BuiltinAdministratorsSid,WellKnownSidType.LocalSystemSid}) security.AddAccessRule(new(new SecurityIdentifier(sid,null),System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));
        security.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),System.Security.AccessControl.FileSystemRights.ReadAndExecute,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(security);
        return new FileStream(Path.Combine(DirectoryPath,"setup.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    }
    public static async Task<string> Run(string exe,IEnumerable<string> args,Dictionary<string,string>? environment=null)
    {
        var info=new ProcessStartInfo(exe) { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
        foreach(var arg in args) info.ArgumentList.Add(arg);
        if(environment is not null) foreach(var (k,v) in environment) info.Environment[k]=v;
        using var process=Process.Start(info) ?? throw new InvalidOperationException("Could not start the configuration tool.");
        var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch(OperationCanceledException) { try{process.Kill(true);}catch{} throw new TimeoutException("The configuration tool timed out. Inspect sensor status before continuing."); }
        var text=await output+await error;
        if(process.ExitCode!=0) throw new InvalidOperationException($"Configuration tool returned {process.ExitCode}: {text}");
        return text;
    }
    static Task VerifyMicrosoftSysmon(string path)
    {
        var ps=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe");
        const string command="$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:OBSERVE_VERIFY_FILE; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'The executable must have a valid Microsoft signature.'}; $v=[Diagnostics.FileVersionInfo]::GetVersionInfo($env:OBSERVE_VERIFY_FILE); if($v.ProductName -ne 'Sysinternals Sysmon'){throw 'This is not a Sysmon executable.'}";
        return Run(ps,["-NoProfile","-NonInteractive","-Command",command],new(){{"OBSERVE_VERIFY_FILE",path}});
    }
    static RegistrySetting Snapshot(string path,string name)
    {
        using var key=Registry.LocalMachine.OpenSubKey(path); var value=key?.GetValue(name); var kind=value is null ? RegistryValueKind.DWord : key!.GetValueKind(name);
        if(value is not null && kind is not (RegistryValueKind.DWord or RegistryValueKind.String)) throw new InvalidOperationException($"Unexpected policy type at {path}/{name}; refusing to overwrite it.");
        return new(path,name,value is not null,kind.ToString(),value?.ToString());
    }
    static void RestorePolicies(SetupState state)
    {
        foreach(var p in state.Registry)
        {
            using var key=Registry.LocalMachine.CreateSubKey(p.Path);
            if(!p.Existed) key.DeleteValue(p.Name,false);
            else if(p.Kind=="DWord") key.SetValue(p.Name,int.Parse(p.Value!),RegistryValueKind.DWord);
            else key.SetValue(p.Name,p.Value!,RegistryValueKind.String);
        }
        foreach(var c in state.Channels)
        {
            using var config=new EventLogConfiguration(c.Name); config.IsEnabled=c.Enabled; config.MaximumSizeInBytes=c.MaximumSize; config.LogMode=c.Mode; config.SaveChanges();
        }
    }
    public static async Task Configure(string executable,string? restoreXml,bool replaceExisting,bool acceptedLicense)
    {
        if(GameSensorsPaused)throw new InvalidOperationException("Restore monitoring from game performance mode before changing sensor setup.");
        using var gate=Lock();
        var previous=Load(); if(previous is not null && previous.Stage!="restored") throw new InvalidOperationException("Observe already has a sensor configuration or an incomplete setup. Restore it before running setup again.");
        var installed=InstalledSysmon();
        if(installed is not null && (!replaceExisting || string.IsNullOrWhiteSpace(restoreXml))) throw new InvalidOperationException("Existing Sysmon needs your explicit replacement choice and its original XML configuration for restoration.");
        if(installed is null && !acceptedLicense) throw new InvalidOperationException("Review and accept the Microsoft Sysmon license before installation.");
        string? original=null;
        if(installed is not null)
        {
            original=File.ReadAllText(restoreXml!); if(original.Length>2_000_000 || XDocument.Parse(original).Root?.Name.LocalName!="Sysmon") throw new InvalidDataException("Choose a valid Sysmon configuration XML.");
        }
        // For existing services, use that service's actual binary; do not mix service versions/architectures.
        var source=installed ?? executable;
        var destination=Path.Combine(DirectoryPath,CanonicalExecutableName(source));
        if(!Path.GetFullPath(source).Equals(destination,StringComparison.OrdinalIgnoreCase)) File.Copy(source,destination,true);
        await VerifyMicrosoftSysmon(destination);
        // Clear tool diagnostics are backed up, but restoration uses the supplied real XML, not the text dump.
        if(installed is not null) File.WriteAllText(Path.Combine(DirectoryPath,"original-sysmon-diagnostic.txt"),await Run(destination,["-c"]));
        var state=new SetupState { SysmonExe=destination,WasInstalled=installed is not null,OriginalConfig=original };
        foreach(var root in PolicyRoots)
        {
            state.Registry.Add(Snapshot(root+@"\ScriptBlockLogging","EnableScriptBlockLogging"));
            state.Registry.Add(Snapshot(root+@"\ModuleLogging","EnableModuleLogging"));
            state.Registry.Add(Snapshot(root+@"\ModuleLogging\ModuleNames","*"));
        }
        foreach(var channel in Collector.Channels)
        {
            try { using var config=new EventLogConfiguration(channel); state.Channels.Add(new(channel,config.IsEnabled,config.MaximumSizeInBytes,config.LogMode)); }
            catch(EventLogNotFoundException) { /* PowerShell 7 and newly installed Sysmon may not be registered yet. */ }
        }
        Save(state); // Persist restoration data before any monitoring changes.
        try
        {
            var xml=Path.Combine(DirectoryPath,"Forensic.xml"); File.WriteAllText(xml,ProfileXml("Forensic"));
            state.SysmonChanged=true; state.Stage="applying-sysmon"; Save(state);
            await Run(destination,installed is null ? ["-accepteula","-i",xml] : ["-c",xml]);
            state.Stage="applying-policies"; Save(state);
            foreach(var p in state.Registry)
            {
                using var key=Registry.LocalMachine.CreateSubKey(p.Path);
                if(p.Name=="*") key.SetValue(p.Name,"*",RegistryValueKind.String); else key.SetValue(p.Name,1,RegistryValueKind.DWord);
            }
            foreach(var channel in Collector.Channels)
            {
                try { using var config=new EventLogConfiguration(channel); config.IsEnabled=true; config.LogMode=EventLogMode.Circular; config.MaximumSizeInBytes=Math.Max(config.MaximumSizeInBytes,64L*1024*1024); config.SaveChanges(); }
                catch(EventLogNotFoundException) when(channel==Collector.Channels[2]) { }
            }
            state.Stage="configured"; Save(state);
        }
        catch
        {
            state.Stage="incomplete"; Save(state);
            throw new InvalidOperationException("Setup did not finish. Restoration data has been retained. Use Restore previous sensor settings, then inspect sensor status before retrying.");
        }
    }
    public static async Task SetProfile(string profile)
    {
        if(GameSensorsPaused)throw new InvalidOperationException("Restore monitoring before changing sensor profiles.");
        using var gate=Lock(); var state=Load() ?? throw new InvalidOperationException("Configure sensors with Observe before changing their profile.");
        if(state.Stage!="configured") throw new InvalidOperationException("Restore the incomplete sensor setup first.");
        var xml=Path.Combine(DirectoryPath,profile+".xml"); File.WriteAllText(xml,ProfileXml(profile));
        await VerifyMicrosoftSysmon(state.SysmonExe); await Run(state.SysmonExe,["-c",xml]);
        state.Profile=profile; Save(state);
    }
    public static async Task Restore()
    {
        if(GameSensorsPaused)throw new InvalidOperationException("Restore monitoring from game performance mode first, then restore the previous sensor settings.");
        using var gate=Lock(); var state=Load();
        if(state is null||state.Stage=="restored"){RestorePowerShellBackup();return;}
        if(state.SysmonChanged)
        {
            await VerifyMicrosoftSysmon(state.SysmonExe);
            if(state.WasInstalled)
            {
                if(string.IsNullOrWhiteSpace(state.OriginalConfig)) throw new InvalidDataException("Original Sysmon XML is missing. Refusing to guess a restore configuration.");
                var original=Path.Combine(DirectoryPath,"Original.xml"); File.WriteAllText(original,state.OriginalConfig); await Run(state.SysmonExe,["-c",original]);
            }
            else if(InstalledSysmon() is not null) await Run(state.SysmonExe,["-u"]);
        }
        RestorePolicies(state); state.Stage="restored"; Save(state);RestorePowerShellBackup();
    }
    public static string PolicyStatus()
    {
        using var key=Registry.LocalMachine.OpenSubKey(PolicyRoots[0]+@"\ScriptBlockLogging");
        return Convert.ToInt32(key?.GetValue("EnableScriptBlockLogging") ?? 0)==1 ? "Script Block Logging machine policy enabled" : "Script Block Logging machine policy is not enabled";
    }
    public static async Task DisableSysmon()
    {
        DemandAdmin();var executable=InstalledSysmon();if(executable is null)return;
        await VerifyMicrosoftSysmon(executable);
        await Run(executable,["-u"]);
        if(InstalledSysmon() is not null)throw new InvalidOperationException("Sysmon still appears installed. Its removal was not confirmed.");
        // Preserve restoration data and PowerShell policy backups for the user.
    }
}
