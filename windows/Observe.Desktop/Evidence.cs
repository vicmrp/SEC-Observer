using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Observe;

public record EvidenceEvent(string Id, string Channel, long RecordId, int EventId, DateTimeOffset Timestamp, Dictionary<string,string> Data)
{
    public string Process => Path.GetFileName(Data.GetValueOrDefault("Image", Data.GetValueOrDefault("SourceImage",EventId is 4103 or 4104 or 24577 ? "PowerShell" : "Unknown")));
    public bool IsNetwork => EventId is 3 or 22 or NetworkMonitor.ConnectionEvent or NetworkMonitor.CacheEvent or NetworkMonitor.TransferEvent or NetworkMonitor.DnsEvent;
    public string Detail => Data.ContainsKey("Observation") ? Data["Observation"] : Data.TryGetValue("RemoteIp",out var remote) ? $"{Data.GetValueOrDefault("Direction")} {Data.GetValueOrDefault("Protocol")} {Data.GetValueOrDefault("LocalIp")}:{Data.GetValueOrDefault("LocalPort")} ↔ {remote}:{Data.GetValueOrDefault("RemotePort")} · {Data.GetValueOrDefault("State",Data.GetValueOrDefault("Bytes","")+" bytes")}" : Data.GetValueOrDefault("QueryName", Data.GetValueOrDefault("DestinationIp", Data.GetValueOrDefault("TargetFilename", Data.GetValueOrDefault("TargetObject", Data.GetValueOrDefault("CommandLine", Data.GetValueOrDefault("ScriptBlockText", ""))))));
    public string Kind => EventId switch { CanaryLab.ReadEvent => "Canary file read (Windows)", CanaryLab.ReceiptEvent => "Test mod receipt (self-reported)", 10104 => "Process resource snapshot", 1 => "Process started", 3 => "Connection", 5 => "Process ended", 11 => "File created / overwritten", 2 => "File timestamp changed", 23 or 26 => "File deleted", 12 or 13 or 14 => "Registry change", 22 or NetworkMonitor.DnsEvent => "DNS query", NetworkMonitor.ConnectionEvent => Data.GetValueOrDefault("Change","TCP connection"), NetworkMonitor.CacheEvent => "DNS cache observed", NetworkMonitor.TransferEvent => "Network "+Data.GetValueOrDefault("Direction"), 25 => "Process tampering", 24577 => "PowerShell ISE script started", ProcessMonitor.Existing => "Process already running (sampled)", ProcessMonitor.Appeared => "Process appeared (sampled)", ProcessMonitor.Disappeared => "Process no longer present (sampled)", 4104 => "PowerShell script", 4103 => "PowerShell module", _ => $"Event {EventId}" };
    public static EvidenceEvent Parse(string xml)
    {
        var root = XDocument.Parse(xml).Root ?? throw new FormatException("Missing event."); var ns = root.Name.Namespace;
        var system = root.Element(ns+"System") ?? throw new FormatException("Missing system metadata.");
        var channel = system.Element(ns+"Channel")?.Value ?? "Unknown";
        var record = long.Parse(system.Element(ns+"EventRecordID")?.Value ?? "0");
        var time = DateTimeOffset.Parse(system.Element(ns+"TimeCreated")?.Attribute("SystemTime")?.Value ?? throw new FormatException("Missing time."));
        var data = new Dictionary<string,string>();
        foreach (var field in root.Element(ns+"EventData")?.Elements(ns+"Data") ?? []) if (field.Attribute("Name") is { } name) data[name.Value] = field.Value;
        var eventId=int.Parse(system.Element(ns+"EventID")!.Value);
        if(eventId==24577&&data.TryGetValue("FileName",out var file)){data["Path"]=file;data["Observation"]="PowerShell ISE started script: "+file+" (script text and completion not recorded by this event)";}
        if(eventId==4103&&data.TryGetValue("ContextInfo",out var context))
        {
            foreach(var (label,key) in new[]{("Host ID","HostId"),("Runspace ID","RunspaceId"),("Pipeline ID","PipelineId")})
            {
                var field=Regex.Match(context,@"(?im)^[ \t]*"+label+@"[ \t]*=[ \t]*([^\r\n]+)[ \t]*\r?$");if(field.Success)data[key]=field.Groups[1].Value.Trim();
            }
            var script=Regex.Match(context,@"(?im)^[ \t]*(?:Script Name|Command Path)[ \t]*=[ \t]*([^\r\n]+\.ps1)[ \t]*\r?$");if(script.Success)data["Path"]=script.Groups[1].Value.Trim();
        }
        if(!data.ContainsKey("ProcessId")&&system.Element(ns+"Execution")?.Attribute("ProcessID") is { } pid)data["ProcessId"]=pid.Value;
        return new($"{channel}:{record}:{time:O}", channel, record, int.Parse(system.Element(ns+"EventID")!.Value), time, data);
    }
}

public record Finding(string Severity, string Title, string Detail, string[] EvidenceIds, string Recommendation);
public record ProfileChange(DateTimeOffset At, string Profile, string Coverage);
public sealed class Observation
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Question { get; set; } = "";
    public DateTimeOffset Start { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? End { get; set; }
    public string Status { get; set; } = "observing";
    public bool Demo { get; set; }
    public List<EvidenceEvent> Events { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
    public List<ProfileChange> Profiles { get; set; } = [];
    public string? Report { get; set; }
    public int AnalysisRequests { get; set; }
    public InvestigationResult? Investigation { get; set; }
}

public static partial class Evidence
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true, PropertyNameCaseInsensitive = true };
    public static List<Finding> Detect(IEnumerable<EvidenceEvent> events)
    {
        var findings = new List<Finding>();
        foreach (var e in events)
        {
            var text = e.Data.GetValueOrDefault("CommandLine",e.Data.GetValueOrDefault("ScriptBlockText",""));
            void Add(string severity, string title, string detail) => findings.Add(new(severity,title,detail,[e.Id],"Check the original event, parent process, and whether the behavior was expected."));
            if(e.EventId==CanaryLab.ReadEvent)Add("review","Canary exercise: file access outside the game",e.Process+" · "+e.Data.GetValueOrDefault("Outcome","Read requested")+" · "+e.Data.GetValueOrDefault("TargetFilename")+". This is synthetic test data. Windows identifies the process, not the specific mod caller.");
            if (Regex.IsMatch(text,@"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{12,}")) Add("medium","Encoded PowerShell command","Encoding can obscure intent; legitimate installers also use it.");
            if (Regex.IsMatch(text,@"(?i)\b(?:DownloadString|Invoke-WebRequest|iwr|curl)\b") && Regex.IsMatch(text,@"(?i)\b(?:Invoke-Expression|iex)\b")) Add("high","Download and script evaluation","Review the source and parent process. This pattern is not itself proof of a successful compromise.");
            if (e.EventId is 11 or 13 && Regex.IsMatch(e.Detail,@"(?i)\\(?:CurrentVersion\\Run(?:Once)?(?:\\|$)|Start Menu\\Programs\\Startup\\)")) Add("medium","Startup persistence changed","An application wrote to a startup location. This may be legitimate.");
            if (e.EventId == 25) Add("high","Sysmon process-tampering event","Inspect the affected process and its ancestry.");
            if(e.EventId==8)Add("review","A remote thread was created",$"{e.Data.GetValueOrDefault("SourceImage","A process")} created a thread in {e.Data.GetValueOrDefault("TargetImage","another process")}. Overlays, debuggers and anti-cheat tools can also do this legitimately.");
            if(e.EventId==10&&Path.GetFileName(e.Data.GetValueOrDefault("TargetImage","")).Equals("lsass.exe",StringComparison.OrdinalIgnoreCase))Add("review","Access to the Windows security process",$"Recorded access to lsass.exe with access mask {e.Data.GetValueOrDefault("GrantedAccess","unknown")}. Inspect the source and reason; this alone does not prove credential theft.");
        }
        return findings;
    }
    public static string Redact(string text)
    {
        text = Regex.Replace(text,@"(?i)C:\\Users\\[^\\\s""']+",@"C:\Users\[user]");
        text = Regex.Replace(text,@"\bsk-[A-Za-z0-9_-]{10,}","[redacted key]");
        text = Regex.Replace(text,@"(?i)(Bearer\s+)[a-z0-9._~+/=-]+","$1[redacted]");
        return Regex.Replace(text,@"(?i)((?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)(?:""[^""\r\n]*""|'[^'\r\n]*'|[^\s&;]+)","$1[redacted]");
    }
    public static object Payload(Observation observation)
    {
        var flagged = Detect(observation.Events).SelectMany(f => f.EvidenceIds).ToHashSet();
        var selected = new List<EvidenceEvent>(); var bytes = 0; var shortened = 0;
        foreach (var e in Balanced(observation.Events,flagged))
        {
            var fields = new Dictionary<string,string>(); var eventShortened = 0;
            foreach (var (key,value) in e.Data)
            {
                var redacted = key is "User" or "UserName" or "Computer" ? "[redacted identity]" : Redact(value);
                if (redacted.Length > 6000) { redacted = redacted[..6000]+" [TRUNCATED]"; eventShortened++; }
                fields[key] = redacted;
            }
            var clean = e with { Data = fields }; var size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(clean,Json));
            if (selected.Count >= 350 || bytes + size > 150_000) continue;
            bytes += size; shortened += eventShortened; selected.Add(clean);
        }
        return new { question = Redact(observation.Question), focus = observation.Investigation is null?"":Redact(observation.Investigation.Script), investigation=observation.Investigation is null?null:new{script=Redact(observation.Investigation.Script),observation.Investigation.Match,observation.Investigation.ExecutionStart,observation.Investigation.ProcessGuid,observation.Investigation.ProcessId,observation.Investigation.ScannedEvents,directoryContextMeaning="Parent directories of file paths; not proven directory operations"}, start = observation.Start, end = observation.End ?? DateTimeOffset.UtcNow, demo = observation.Demo,
            coverage = new { captured = observation.Events.Count, included = selected.Count, omitted = observation.Events.Count-selected.Count, categories=observation.Events.GroupBy(Category).Select(g=>new{category=g.Key,recorded=g.Count(),included=selected.Count(e=>Category(e)==g.Key)}), shortenedFields = shortened, warnings = observation.Warnings.Select(Redact).ToArray(), sensors = observation.Profiles },
            events = selected.OrderBy(e=>e.Timestamp), rules = Detect(selected).Take(20), privacy = "Best-effort redaction. Commands, scripts, domains, and IPs can still be sensitive." };
    }
    internal static string Category(EvidenceEvent e)=>e.IsNetwork?"network":ActivityRetention.IsProcess(e)?"process":ActivityRetention.IsScript(e)?"powershell":e.EventId is 2 or 11 or 23 or 26?"file":e.EventId is 12 or 13 or 14?"registry":"other";
    internal static IEnumerable<EvidenceEvent> Balanced(IEnumerable<EvidenceEvent> events,HashSet<string>? flagged=null)
    {
        // Interleave categories so a noisy file writer cannot erase all network evidence from a model request.
        var groups=events.GroupBy(Category).Select(g=>new Queue<EvidenceEvent>(g.OrderByDescending(e=>flagged?.Contains(e.Id)==true).ThenByDescending(e=>e.Timestamp))).ToArray();
        while(groups.Any(g=>g.Count>0))foreach(var group in groups)if(group.Count>0)yield return group.Dequeue();
    }
    public static Observation Demo()
    {
        var s = new Observation { Question = "What happened during this synthetic installation?", Demo = true, Start = DateTimeOffset.UtcNow.AddMinutes(-1), End = DateTimeOffset.UtcNow, Status = "complete", Warnings = ["Synthetic demonstration. Not evidence about a real application."] };
        (int Id, Dictionary<string,string> Data)[] data = [
            (1,new(){{"Image",@"C:\Users\demo\Downloads\example-setup.exe"},{"ProcessGuid","{demo-root}"},{"ParentImage",@"C:\Windows\explorer.exe"}}),
            (22,new(){{"Image","example-setup.exe"},{"QueryName","downloads.example.com"},{"QueryResults","203.0.113.10"}}),
            (3,new(){{"Image","example-setup.exe"},{"DestinationIp","203.0.113.10"},{"DestinationPort","443"},{"Protocol","tcp"},{"DestinationHostname","downloads.example.com"}}),
            (1,new(){{"Image","powershell.exe"},{"CommandLine","powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAxAA=="},{"ProcessGuid","{demo-child}"},{"ParentProcessGuid","{demo-root}"}}),
            (4104,new(){{"ScriptBlockText","Write-Output 1"},{"MessageNumber","1"},{"MessageTotal","1"}}),
            (13,new(){{"Image","example-setup.exe"},{"TargetObject",@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Example"}})];
        for(var i=0;i<data.Length;i++) s.Events.Add(new($"demo:{i}",data[i].Id==4104 ? Collector.Channels[1] : Collector.Channels[0],i,data[i].Id,s.Start.AddSeconds(i*3),data[i].Data));
        return s;
    }
}
