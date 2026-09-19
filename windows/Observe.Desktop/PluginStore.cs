using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Observe;

public sealed class PluginSettings
{
    public bool ChatGpt { get; set; }
    public bool Unifi { get; set; }
    public bool Observer { get; set; }
    public bool GamePerformance { get; set; }
    public bool ThreatFox { get; set; }
    public bool CitiesModObserver { get; set; }
    public string ThreatFoxKey { get; set; }="";
    public string OpenAiKey { get; set; }="";
    public string ObserverModel { get; set; }=ObserverModels.Default;
    public string UnifiUrl { get; set; }="";
    public string UnifiSite { get; set; }="";
    public string UnifiKey { get; set; }="";
    public string CertificatePin { get; set; }="";
}

public sealed class PluginStore
{
    public string Root { get; }
    public string ConfigPath { get; }
    string PathName=>Path.Combine(Root,"plugins.json");
    public PluginStore(string? root=null,string? config=null)
    {
        Root=root??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ObserveDesktop");
        ConfigPath=config??Path.Combine(Environment.GetEnvironmentVariable("CODEX_HOME")??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),".codex"),"config.toml");
    }
    public PluginSettings Load()=>File.Exists(PathName)?JsonSerializer.Deserialize<PluginSettings>(File.ReadAllText(PathName),Evidence.Json)??new():new();
    public void Save(PluginSettings settings)
    {
        Directory.CreateDirectory(Root);File.WriteAllText(PathName+".tmp",JsonSerializer.Serialize(settings,Evidence.Json));File.Move(PathName+".tmp",PathName,true);
    }
    public static string Protect(string value)=>Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value),null,DataProtectionScope.CurrentUser));
    public static string Unprotect(string value)=>string.IsNullOrEmpty(value)?"":Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value),null,DataProtectionScope.CurrentUser));
    const string Begin="# BEGIN OBSERVE MANAGED MCP",End="# END OBSERVE MANAGED MCP";
    public static string RemoveManagedMcpConfig(string text)
    {
        var pattern=@"(?ms)^# BEGIN OBSERVE MANAGED MCP\r?\n.*?^# END OBSERVE MANAGED MCP(?:\r?\n)?";
        var count=Regex.Matches(text,pattern).Count;
        if(count>1||text.Contains(Begin)&&count!=1)throw new InvalidDataException("Observe's MCP configuration block is ambiguous. No configuration was changed.");
        var clean=Regex.Replace(text,pattern,"");
        return clean;
    }
    public void RemoveLegacyConnection()
    {
        var settings=Load();if(settings.ChatGpt){settings.ChatGpt=false;Save(settings);} // Revoke old running 0.4 servers before removing configuration.
        if(!File.Exists(ConfigPath))return;
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        using var gate=new FileStream(ConfigPath+".observe-lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        var before=File.Exists(ConfigPath)?File.ReadAllText(ConfigPath):"";
        var after=RemoveManagedMcpConfig(before);
        if(after!=before)
        {
            if(File.Exists(ConfigPath))File.Copy(ConfigPath,ConfigPath+".observe-backup",true);
            File.WriteAllText(ConfigPath+".observe-tmp",after);File.Move(ConfigPath+".observe-tmp",ConfigPath,true);
        }
    }
    public void RemoveUnifi(){var s=Load();s.Unifi=false;s.UnifiKey="";s.UnifiUrl="";s.UnifiSite="";s.CertificatePin="";Save(s);}
    public void RemoveObserver(){var s=Load();s.Observer=false;s.OpenAiKey="";Save(s);}
    public void RemoveThreatFox(){var s=Load();s.ThreatFox=false;s.ThreatFoxKey="";Save(s);}
}
