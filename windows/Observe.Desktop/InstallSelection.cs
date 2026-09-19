using System.Diagnostics;
using System.IO.Compression;

namespace Observe;

public sealed class InstallSelection
{
    public bool Cities {get;set;}
    public bool WindowsLogging {get;set;}
    public bool Unifi {get;set;}
    public bool Observer {get;set;}
    public bool ThreatFox {get;set;}
    public bool AcceptSysmonLicense {get;set;}
    public bool StartAtLogin {get;set;}
    public string[] Dependencies=>WindowsLogging?["Microsoft Sysmon", "Windows PowerShell logging"]:[];
    public void Validate(){if(WindowsLogging&&!AcceptSysmonLicense)throw new InvalidOperationException("Review and accept the Microsoft Sysmon license before installing Windows logging.");}
    public void Apply(PluginSettings settings)
    {
        // Updates retain configured plugins and credentials. Fresh installs start empty.
        settings.CitiesModObserver|=Cities;settings.Unifi|=Unifi;
        settings.Observer|=Observer;settings.ThreatFox|=ThreatFox;
    }
}

public static class InstallDependencies
{
    public static async Task Ensure(InstallSelection selection)
    {
        selection.Validate();if(!selection.WindowsLogging)return;
        // Only this operation elevates, after the user explicitly selects logging.
        var info=new ProcessStartInfo(Path.Combine(Installation.InstallRoot,"Observe.exe")){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
        info.ArgumentList.Add("--install-logging-dependencies");info.ArgumentList.Add("--accept-sysmon-license");
        using var child=Process.Start(info)??throw new InvalidOperationException("Windows logging setup did not start.");
        await child.WaitForExitAsync();
        if(child.ExitCode!=0)throw new InvalidOperationException("Observe was copied, but logging setup did not finish. Existing plugins and evidence were retained. Retry setup or use Settings > Configure sensors.");
    }
    public static async Task InstallLogging(bool acceptedLicense)
    {
        if(!acceptedLicense||!SensorSetup.IsAdministrator)throw new InvalidOperationException("Logging setup requires license acceptance and Windows administrator approval.");
        if(SensorSetup.InstalledSysmon() is not null)
        {
            // Reuse the existing service; never replace someone else's Sysmon rules.
            SensorSetup.EnablePowerShellLogging();return;
        }
        using var http=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(90)};
        using var response=await http.GetAsync("https://download.sysinternals.com/files/Sysmon.zip",HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        using var bytes=new MemoryStream();using var input=await response.Content.ReadAsStreamAsync();
        var buffer=new byte[65536];int n;
        while((n=await input.ReadAsync(buffer))>0){if(bytes.Length+n>32*1024*1024)throw new IOException("Sysmon download exceeds limit.");await bytes.WriteAsync(buffer.AsMemory(0,n));}
        bytes.Position=0;using var zip=new ZipArchive(bytes,ZipArchiveMode.Read);
        var entry=zip.GetEntry("Sysmon64.exe")??throw new InvalidDataException("Official download did not contain Sysmon64.exe.");
        if(entry.Length>32*1024*1024)throw new InvalidDataException("Sysmon executable exceeds limit.");
        // FileShare.None prevents replacement while Configure validates and copies it.
        var staging=Path.Combine(Path.GetTempPath(),"Observe-Sysmon-"+Guid.NewGuid().ToString("N")+".exe");
        try
        {
            using(var file=new FileStream(staging,FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var source=entry.Open())await source.CopyToAsync(file);
            // Configure checks the Microsoft Authenticode signature and product name
            // before executing, and saves restoration data before changing sensors.
            await SensorSetup.Configure(staging,null,false,true);
        }
        finally{if(File.Exists(staging))File.Delete(staging);}
    }
}
