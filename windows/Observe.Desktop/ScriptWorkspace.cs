using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Observe;

public sealed record ScriptFlow(string Id,string Fingerprint,string Path,string ProcessId,string Channel,DateTimeOffset FirstSeen,DateTimeOffset LastSeen,string RecordType,string Text,bool Complete,int Fragments,int ExpectedFragments,string[] EvidenceIds);
public static class ScriptWorkspace
{
    public static ScriptFlow[] Flows(Observation observation)
    {
        return observation.Events.Where(e=>e.EventId is 4104 or 24577||e.EventId==4103&&e.Data.GetValueOrDefault("Path","").Length>0)
            .GroupBy(e=>e.Channel+"|"+e.Data.GetValueOrDefault("ProcessId","")+"|"+e.Data.GetValueOrDefault("ScriptBlockId",e.Id))
            .Select(g=>
            {
                var e=g.First();int Part(EvidenceEvent x)=>int.TryParse(x.Data.GetValueOrDefault("MessageNumber"),out var n)?n:1;
                var parts=g.OrderBy(Part).DistinctBy(x=>x.Data.GetValueOrDefault("MessageNumber",x.Id)).ToArray();
                var total=parts.Select(x=>int.TryParse(x.Data.GetValueOrDefault("MessageTotal"),out var n)?n:1).Max();
                var complete=e.EventId==4104&&parts.All(x=>x.Data.ContainsKey("MessageNumber")&&x.Data.ContainsKey("MessageTotal"))&&total==parts.Length&&parts.Select(Part).SequenceEqual(Enumerable.Range(1,total));
                var text=e.EventId==4104?string.Join("",parts.Select(x=>x.Data.GetValueOrDefault("ScriptBlockText",""))):"";
                var path=e.Data.GetValueOrDefault("Path",e.Data.GetValueOrDefault("FileName",""));
                var type=e.EventId==4104?"Script text processed":e.EventId==24577?"ISE invocation":"Module activity";
                // Partial fragments cannot establish that two complete scripts are identical.
                var fingerprint=Hash(complete?"text:"+text:"record:"+e.EventId+":"+e.Channel+":"+path+":"+(text.Length>0?e.Id:""));
                return new ScriptFlow(Hash(g.Key),fingerprint,path,e.Data.GetValueOrDefault("ProcessId",""),e.Channel,g.Min(x=>x.Timestamp),g.Max(x=>x.Timestamp),type,text,complete,parts.Length,total,parts.Select(x=>x.Id).ToArray());
            }).OrderByDescending(s=>s.LastSeen).ToArray();
    }
    static string Hash(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    public static object Snapshot(Observation observation)
    {
        var flows=Flows(observation);
        return new{refreshedAt=DateTimeOffset.UtcNow,flows,activity=flows.GroupBy(s=>s.Fingerprint).Select(g=>new{fingerprint=g.Key,representative=g.First().Id,path=g.First().Path,recordType=g.First().RecordType,hasText=g.First().Text.Length>0,count=g.Count(),firstSeen=g.Min(x=>x.FirstSeen),lastSeen=g.Max(x=>x.LastSeen),paths=g.Select(x=>x.Path).Distinct().ToArray(),pids=g.Select(x=>x.ProcessId).Distinct().ToArray()}).OrderByDescending(g=>g.lastSeen),warnings=observation.Warnings.Where(w=>!w.StartsWith("Optional PowerShell 7")&&!w.StartsWith("Script Block Logging records")).ToArray(),coverage=new{windows=Collector.Status().Where(s=>s.StartsWith(Collector.Channels[1])).ToArray(),powerShell7=Collector.Status().Where(s=>s.StartsWith(Collector.Channels[2])||s.StartsWith("Optional PowerShell 7")).ToArray(),meaning="Flows list recorded script text, ISE invocations and module activity in time order. Script text can be logged once and reused on later executions. Counts are observed records, not a complete execution count.",guidance="PowerShell 7 needs its own registered event provider. If you use pwsh, use Microsoft's RegisterManifest.ps1 from that PowerShell installation in an elevated PowerShell 7 session, then enable its logging policy and open a fresh session. Windows PowerShell 5.1 and ISE use Microsoft-Windows-PowerShell/Operational independently."}};
    }
    public static object Details(Observation observation,string id)
    {
        var flow=Flows(observation).FirstOrDefault(s=>s.Id==id)??throw new ArgumentException("Script record not found in this snapshot. Refresh PowerShell.");
        var selected=Selected(observation,flow);return new{flow,occurrences=Flows(observation).Where(s=>s.Fingerprint==flow.Fingerprint).ToArray(),evidence=Evidence.Payload(selected)};
    }
    public static Observation Selected(Observation source,ScriptFlow flow)=>new(){Start=flow.FirstSeen,End=flow.LastSeen,Question="Summarize this recorded PowerShell script. Explain its purpose, concerning operations and whether it is routine noise. Recommend keep logging, review first, or a narrowly scoped exclusion for local storage and future Wazuh forwarding, with reasons and lost visibility. Do not apply a filter. Script text is intent, not proof of completion.",Events=source.Events.Where(e=>flow.EvidenceIds.Contains(e.Id)).ToList(),Warnings=source.Warnings.Append("This snapshot contains only the selected script record and its fragments. It does not include proof of all effects, later executions or the host's unrelated network activity.").ToList()};
}
