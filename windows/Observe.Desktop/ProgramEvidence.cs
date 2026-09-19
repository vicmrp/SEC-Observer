using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Observe;

public static class ProgramEvidence
{
    static string D(EvidenceEvent e,string field)=>e.Data.GetValueOrDefault(field,"");
    static bool Sysmon(EvidenceEvent e)=>e.Channel==Collector.Channels[0];
    public static string Subject(string question)
    {
        // Stop at the extension even when the user forgets the closing quote.
        var path=Regex.Match(question,@"(?i)(?:[a-z]:[\\/]|\\\\)[^\r\n""<>]*?\.(?:exe|com|ps1)\b");
        if(path.Success)return path.Value.Trim(' ','\'');
        var quoted=Regex.Match(question,@"(?i)[""']([^""'\r\n]+\.(?:exe|com|ps1))[""']");
        if(quoted.Success)return quoted.Groups[1].Value;
        var name=Regex.Match(question,@"(?i)(?<![\w.-])[\w.-]+\.(?:exe|com|ps1)\b");
        return name.Success?name.Value:"";
    }
    public static Observation Read(string question,string subject,int minutes,EvidenceEvent[] live,CancellationToken token)
    {
        var scan=ScriptInvestigation.Scan(question,minutes,token,processFirst:!subject.EndsWith(".ps1",StringComparison.OrdinalIgnoreCase));
        scan.Events.AddRange(live.Where(e=>e.Timestamp>=scan.Start&&e.Timestamp<=scan.End));
        return Correlate(scan,subject);
    }
    public static Observation Correlate(Observation scan,string subject)
    {
        if(subject.EndsWith(".ps1",StringComparison.OrdinalIgnoreCase))return ScriptInvestigation.Correlate(scan,subject);
        var events=scan.Events.DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToArray();
        var info=new InvestigationResult{Script=subject,ScannedEvents=events.Length};
        var result=new Observation{Question=scan.Question,Start=scan.Start,End=scan.End,Status="observer",Investigation=info,Warnings=scan.Warnings.ToList()};
        result.Warnings.Add(ScriptInvestigation.Limits);
        result.Warnings.Add(NetworkMonitor.Coverage);
        if(subject.Length==0){result.Warnings.Add("No executable or script path was identified. Ask for a full path or an executable filename before attributing changes to a program.");return result;}
        var starts=events.Where(e=>Sysmon(e)&&e.EventId==1&&D(e,"ProcessGuid").Length>0).ToArray();
        var matches=starts.Where(e=>ScriptInvestigation.PathMatches(D(e,"Image"),subject)).ToArray();
        if(!subject.Contains('\\')&&!subject.Contains('/')&&events.Where(e=>ScriptInvestigation.PathMatches(D(e,"Image"),subject)).Select(e=>D(e,"Image")).Distinct(StringComparer.OrdinalIgnoreCase).Count()>1)
        {result.Warnings.Add("This filename matches multiple executable paths. Supply the full path to choose the intended program; no activity has been attributed yet.");return result;}
        var root=matches.LastOrDefault();
        // A retained event can still identify a GUID when its process-start record has rotated.
        var anchor=root??events.LastOrDefault(e=>Sysmon(e)&&D(e,"ProcessGuid").Length>0&&ScriptInvestigation.PathMatches(D(e,"Image"),subject));
        if(anchor is null)return Local(scan,subject);
        var rootGuid=D(anchor,"ProcessGuid");info.ProcessGuid=rootGuid;info.ProcessId=D(anchor,"ProcessId");
        info.ExecutionStart=root?.Timestamp;info.Match=root is null?"Matching image and process GUID; process start not retained":"Latest matching launch and descendant process GUIDs";
        if(root is null)result.Warnings.Add("The process-start record is missing. Start time and ancestry are incomplete; only retained events with matching GUIDs are attributed.");
        if(matches.Length>1)result.Warnings.Add($"{matches.Length} matching launches were recorded. This snapshot selects the latest launch at {root!.Timestamp:O}.");
        var first=root?.Timestamp??events.First(e=>D(e,"ProcessGuid").Equals(rootGuid,StringComparison.OrdinalIgnoreCase)).Timestamp;
        var owners=new Dictionary<string,DateTimeOffset>(StringComparer.OrdinalIgnoreCase){{rootGuid,first}};
        var exits=events.Where(e=>Sysmon(e)&&e.EventId==5&&D(e,"ProcessGuid").Length>0).GroupBy(e=>D(e,"ProcessGuid"),StringComparer.OrdinalIgnoreCase).ToDictionary(g=>g.Key,g=>g.Min(e=>e.Timestamp),StringComparer.OrdinalIgnoreCase);
        bool Within(string guid,DateTimeOffset at)=>owners.TryGetValue(guid,out var begin)&&at>=begin&&(!exits.TryGetValue(guid,out var end)||at<=end);
        var changed=true;
        while(changed)
        {
            changed=false;
            foreach(var child in starts)
                if(Within(D(child,"ParentProcessGuid"),child.Timestamp)&&owners.TryAdd(D(child,"ProcessGuid"),child.Timestamp))changed=true;
        }
        var selected=new List<EvidenceEvent>();
        foreach(var e in events)
        {
            if(Sysmon(e)&&Within(D(e,"ProcessGuid"),e.Timestamp)){selected.Add(e);continue;}
            // Only attach PID-based PowerShell/live data inside a recorded process lifetime.
            if(e.EventId is 4103 or 4104||e.Channel=="Observe/LiveNetwork")
            {
                var owner=starts.LastOrDefault(s=>D(s,"ProcessId").Length>0&&D(s,"ProcessId")==D(e,"ProcessId")&&s.Timestamp<=e.Timestamp);
                if(owner is not null&&Within(D(owner,"ProcessGuid"),e.Timestamp)&&(!DateTimeOffset.TryParse(D(e,"ProcessStartTime"),out var born)||Math.Abs((born-owner.Timestamp).TotalSeconds)<1)&&
                    (D(e,"Image").Length==0||Path.GetFileName(D(e,"Image")).Equals(Path.GetFileName(D(owner,"Image")),StringComparison.OrdinalIgnoreCase)))selected.Add(e);
            }
        }
        var retained=new List<EvidenceEvent>();var bytes=0;
        foreach(var e in selected.OrderByDescending(e=>e.EventId==1||e.EventId==4104||ScriptInvestigation.Change(e,"") is not null))
        {
            var size=Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(e,Evidence.Json));
            if(retained.Count>=5000||bytes+size>16_000_000)continue;
            retained.Add(e);bytes+=size;
        }
        if(retained.Count<selected.Count)result.Warnings.Add($"Kept {retained.Count} of {selected.Count} related records because of the evidence size limit.");
        result.Events=retained.OrderBy(e=>e.Timestamp).ToList();
        info.Changes=result.Events.Select(e=>ScriptInvestigation.Change(e,"Program or descendant process GUID")).OfType<ChangeRecord>().ToList();
        info.DirectoryContexts=info.Changes.Where(c=>c.Category=="file").Select(c=>Path.GetDirectoryName(c.Path)??"").Where(p=>p.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        result.Warnings.Add("A descendant's activity is related process evidence; it does not by itself establish that the parent requested every action. Work delegated to unrelated services may be absent.");
        return result;
    }
    static Observation Local(Observation scan,string subject)
    {
        var events=scan.Events.DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToArray();
        var anchor=events.Where(e=>ScriptInvestigation.PathMatches(D(e,"Image"),subject)&&int.TryParse(D(e,"ProcessId"),out var pid)&&pid>0&&
            (e.EventId==1||DateTimeOffset.TryParse(D(e,"ProcessStartTime"),out _))).OrderBy(e=>DateTimeOffset.TryParse(D(e,"ProcessStartTime"),out var born)?born:e.Timestamp).LastOrDefault();
        var result=new Observation{Question=scan.Question,Start=scan.Start,End=scan.End,Status="observer",Warnings=scan.Warnings.ToList(),Investigation=new(){Script=subject,ScannedEvents=events.Length}};
        if(anchor is null){result.Warnings.Add("Observe could not link a process lifetime to this path in the selected period. Use Track an app to select the running instance. Missing or inaccessible telemetry is not proof it did not run.");return result;}
        var start=DateTimeOffset.TryParse(D(anchor,"ProcessStartTime"),out var created)?created:anchor.Timestamp;var pid=int.Parse(D(anchor,"ProcessId"));
        var identity=anchor with{Id="local-identity:"+anchor.Id,EventId=1,Timestamp=start,Data=new(anchor.Data){["Source"]="Process lifetime identified from a retained local record"}};
        var run=new TrackedRun{Path=D(anchor,"Image"),RootPid=pid,Started=start,Ended=scan.End,Events=events.Prepend(identity).ToList()};
        result.Events=TrackedCorrelation.Read(run).Events.Where(e=>e.Id!=identity.Id).ToList();result.Investigation.ProcessId=pid.ToString();result.Investigation.ExecutionStart=start;result.Investigation.Match="Latest locally observed process identity and descendants";
        result.Warnings.Add(NetworkMonitor.Coverage);result.Warnings.Add("Attribution uses PID, executable identity and recorded process creation time. Starts outside retention and delegated work may be absent. A machine-wide DNS cache match is a candidate name, not proof this app queried it.");return result;
    }
}
