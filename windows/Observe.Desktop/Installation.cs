using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json;

namespace Observe;

public sealed class InstallReceipt
{
    public string Product {get;set;}="Observe";
    public string Version {get;set;}="0.12.0-beta-vibe-coded";
    public List<string> Files {get;set;}=[];
}
public static class Installation
{
    public static string InstallRoot=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs","Observe");
    const string UninstallKey=@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Observe";
    public static string ShortcutPath=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"Observe.lnk");
    public static string CheckedPath(string root,string relative)
    {
        root=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);var path=Path.GetFullPath(Path.Combine(root,relative));
        if(Path.IsPathRooted(relative)||!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Install path escapes Observe's directory.");
        for(var dir=Path.GetDirectoryName(path);dir is not null&&dir.StartsWith(root,StringComparison.OrdinalIgnoreCase);dir=Path.GetDirectoryName(dir))
            if(Directory.Exists(dir)&&(File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)throw new IOException("Refusing to change an installation through a directory link.");
        return path;
    }
    public static InstallReceipt CopyPayload(string sourceExecutable,string targetRoot)
    {
        Directory.CreateDirectory(targetRoot);var executable=CheckedPath(targetRoot,"Observe.exe");
        if(Path.GetFullPath(sourceExecutable).Equals(executable,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("This copy is already installed. Run the downloaded setup to update it.");
        var receipt=new InstallReceipt();var sourceRoot=Path.GetDirectoryName(sourceExecutable)!;
        // Copy only release payload, never unrelated user files or evidence.
        var paths=new List<(string Source,string Relative)>{(sourceExecutable,"Observe.exe")};
        foreach(var name in new[]{"README.md","LICENSE","UVM-Integration.md"})if(File.Exists(Path.Combine(sourceRoot,name)))paths.Add((Path.Combine(sourceRoot,name),name));
        if(Directory.Exists(Path.Combine(sourceRoot,"licenses")))foreach(var file in Directory.EnumerateFiles(Path.Combine(sourceRoot,"licenses"),"*",SearchOption.AllDirectories))paths.Add((file,Path.GetRelativePath(sourceRoot,file)));
        var previous=File.Exists(Path.Combine(targetRoot,"install.json"))?JsonSerializer.Deserialize<InstallReceipt>(File.ReadAllText(Path.Combine(targetRoot,"install.json")),Evidence.Json):null;
        foreach(var (source,relative) in paths)
        {
            var target=CheckedPath(targetRoot,relative);Directory.CreateDirectory(Path.GetDirectoryName(target)!);File.Copy(source,target+".new",true);File.Move(target+".new",target,true);receipt.Files.Add(relative);
        }
        if(previous is {Product:"Observe"})receipt.Files.AddRange(previous.Files.Where(f=>!receipt.Files.Contains(f)));
        File.WriteAllText(CheckedPath(targetRoot,"install.json"),JsonSerializer.Serialize(receipt,Evidence.Json));return receipt;
    }
    public static async Task Install(InstallSelection selection)
    {
        selection.Validate();
        var plugins=new PluginStore();
        plugins.RemoveLegacyConnection();
        CopyPayload(Environment.ProcessPath!,InstallRoot);
        var executable=Path.Combine(InstallRoot,"Observe.exe");
        using(var key=Registry.CurrentUser.CreateSubKey(UninstallKey))
        {
            key.SetValue("DisplayName","Observe");key.SetValue("DisplayVersion","0.12.0-beta-vibe-coded");key.SetValue("Publisher","Observe open source");key.SetValue("InstallLocation",InstallRoot);key.SetValue("DisplayIcon",executable);
            key.SetValue("UninstallString",'"'+executable+"\" --uninstall");key.SetValue("NoModify",1);key.SetValue("NoRepair",1);
        }
        var shellType=Type.GetTypeFromProgID("WScript.Shell")??throw new InvalidOperationException("Windows shortcut support is unavailable.");
        dynamic shell=Activator.CreateInstance(shellType)!;dynamic shortcut=shell.CreateShortcut(ShortcutPath);shortcut.TargetPath=executable;shortcut.WorkingDirectory=InstallRoot;shortcut.Description="Observe — local Windows forensics";shortcut.Save();
        System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        await InstallDependencies.Ensure(selection);
        var settings=plugins.Load();selection.Apply(settings);plugins.Save(settings);
        if(selection.StartAtLogin)
        {
            using var startup=Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            startup.SetValue("Observe",'"'+executable+"\" --background");
        }
    }
    public static bool RemovePayload(string root)
    {
        var marker=CheckedPath(root,"install.json");var receipt=JsonSerializer.Deserialize<InstallReceipt>(File.ReadAllText(marker),Evidence.Json);
        if(receipt?.Product!="Observe")throw new InvalidDataException("This directory is not an Observe installation.");
        var targets=receipt.Files.Select(f=>CheckedPath(root,f)).ToArray(); // Validate every path before deleting any.
        foreach(var path in targets)if(File.Exists(path))File.Delete(path);
        File.Delete(marker);
        foreach(var directory in targets.Select(Path.GetDirectoryName).Where(d=>d is not null&&d!=root).Distinct().OrderByDescending(d=>d!.Length))if(Directory.Exists(directory)&&!Directory.EnumerateFileSystemEntries(directory!).Any())Directory.Delete(directory!);
        if(!Directory.EnumerateFileSystemEntries(root).Any()){Directory.Delete(root);return true;}return false;
    }
    public static void StartUninstall(bool disableSysmon)
    {
        if(!File.Exists(Path.Combine(InstallRoot,"install.json")))throw new InvalidOperationException("This is a portable copy. No installed Observe package was found.");
        var directory=Path.Combine(Path.GetTempPath(),"Observe-Uninstall-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        var helper=Path.Combine(directory,"Observe.exe");File.Copy(Environment.ProcessPath!,helper);
        var info=new ProcessStartInfo(helper){UseShellExecute=true,WindowStyle=ProcessWindowStyle.Hidden};
        info.ArgumentList.Add("--uninstall-worker");info.ArgumentList.Add(Environment.ProcessId.ToString());if(disableSysmon)info.ArgumentList.Add("--disable-sysmon");Process.Start(info);
    }
    public static async Task<int> UninstallWorker(int parent,bool disableSysmon)
    {
        try
        {
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try{using var p=Process.GetProcessById(parent);await p.WaitForExitAsync(timeout.Token);}catch(ArgumentException){}
            // Check executable locks before touching sensors or connections.
            using(var check=new FileStream(Path.Combine(InstallRoot,"Observe.exe"),FileMode.Open,FileAccess.Read,FileShare.None)){}
            if(disableSysmon)
            {
                if(SensorSetup.IsAdministrator)await SensorSetup.DisableSysmon();
                else
                {
                    // Elevate only the machine-level sensor operation. Keep per-user files and HKCU in the original account.
                    var sensorInfo=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};sensorInfo.ArgumentList.Add("--remove-sysmon");
                    using var sensor=Process.Start(sensorInfo)??throw new InvalidOperationException("Could not start Sysmon removal.");await sensor.WaitForExitAsync();if(sensor.ExitCode!=0)throw new InvalidOperationException("Sysmon removal failed. Observe has been retained.");
                }
            }
            // Remove only Observe's managed MCP entry; preserve every other server and plugin.
            var plugins=new PluginStore();plugins.RemoveLegacyConnection();plugins.RemoveUnifi();plugins.RemoveObserver();plugins.RemoveThreatFox();
            RemovePayload(InstallRoot);Registry.CurrentUser.DeleteSubKeyTree(UninstallKey,false);
            using(var startup=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run",true))startup?.DeleteValue("Observe",false);
            if(File.Exists(ShortcutPath))File.Delete(ShortcutPath);
            File.WriteAllText(Path.Combine(plugins.Root,"last-uninstall.json"),JsonSerializer.Serialize(new{success=true,sysmonDisabled=disableSysmon,evidenceRetained=true,at=DateTimeOffset.UtcNow}));
            MessageBox.Show("Observe was uninstalled. Saved evidence and sensor backups were retained."+(disableSysmon?" Sysmon's service and driver were removed.":" Sysmon and PowerShell logging were left unchanged."),"Observe",MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;
        }
        catch(Exception e){MessageBox.Show("Uninstall did not finish: "+e.Message+"\nClose other Observe windows and retry. Existing evidence is retained.","Observe",MessageBoxButtons.OK,MessageBoxIcon.Warning);return 1;}
    }
}
