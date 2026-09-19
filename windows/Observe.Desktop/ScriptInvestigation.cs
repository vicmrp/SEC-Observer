using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Text.RegularExpressions;

namespace Observe;

public sealed record ChangeRecord(DateTimeOffset Timestamp,string Category,string Operation,string Path,string Detail,string Attribution,string EvidenceId);
public sealed class InvestigationResult
{
    public string Script {get;set;}="";
    public string Match {get;set;}="No matching execution found";
    public int ScannedEvents {get;set;}
    public DateTimeOffset? ExecutionStart {get;set;}
    public string ProcessGuid {get;set;}="";
    public string ProcessId {get;set;}="";
    public List<ChangeRecord> Changes {get;set;}=[];
    public string[] DirectoryContexts {get;set;}=[];
}

public static class ScriptInvestigation
{
    public const string Limits="Sysmon Event 11 records creation or overwrite, not every content edit. Directory creation/deletion is not comprehensively logged. Event 26 deletion requires an enabled rule before the action. Script text describes intent, not proof of execution. Missing records do not prove an action did not happen.";
    static string D(EvidenceEvent e,string key)=>e.Data.GetValueOrDefault(key,"");
    static bool Sysmon(EvidenceEvent e)=>e.Channel==Collector.Channels[0];
    static bool Script(EvidenceEvent e)=>(e.EventId is 4104 or 24577||e.EventId==4103&&D(e,"Path").Length>0)&&e.Channel!=Collector.Channels[0];
    static string Normalize(string s)=>s.Trim().Trim('"','\'').Replace('/','\\');
    public static bool PathMatches(string observed,string requested)=>requested.Length>0&&(Normalize(requested).Contains('\\')?Normalize(observed).Equals(Normalize(requested),StringComparison.OrdinalIgnoreCase):Path.GetFileName(Normalize(observed)).Equals(Normalize(requested),StringComparison.OrdinalIgnoreCase));
    public static string PathFromQuestion(string question)
    {
        var full=Regex.Match(question,@"(?i)(?:[a-z]:[\\/]|\\\\)[^\r\n""<>]*?\.ps1\b");
        if(full.Success)return full.Value.Trim(' ', '\'');
        var name=Regex.Match(question,@"(?i)(?<![\w.-])[\w.-]+\.ps1\b");return name.Success?name.Value:"";
    }
    static string[] CommandScripts(EvidenceEvent e)
    {
        if(!Sysmon(e)||e.EventId!=1||!new[]{"powershell.exe","pwsh.exe","powershell_ise.exe"}.Contains(e.Process.ToLowerInvariant()))return [];
        var command=D(e,"CommandLine");
        // A path in a read command is not a script launch. Only recognize direct invocation forms.
        var expression=Regex.Match(command,@"(?i)\s-(?:c|command)\s+(.+)$");
        if(expression.Success&&!Regex.IsMatch(expression.Groups[1].Value.Trim().TrimStart('"'),@"^\s*(?:&|\.)\s+"))return [];
        var matches=Regex.Matches(command,@"(?i)[""']([^""'\r\n]+\.ps1)[""']|(?<![\w.])((?:[a-z]:[\\/]|\.\.?[\\/]|\\\\)?[^\s""';]+\.ps1)(?=[\s""';]|$)");
        return matches.Select(m=>m.Groups[1].Success?m.Groups[1].Value:m.Groups[2].Value).Select(p=>Path.IsPathFullyQualified(p)?Normalize(p):D(e,"CurrentDirectory").Length>0?Normalize(Path.Combine(D(e,"CurrentDirectory"),p)):Normalize(p)).ToArray();
    }
    public static Observation Read(string question,string script,int minutes,CancellationToken token)
    {
        if(string.IsNullOrWhiteSpace(question)||question.Length>2000||script.Length>500||minutes is <0 or >10080)throw new ArgumentException("Enter a question, optional script path, and a period up to seven days (or all retained logs).");
        return Correlate(Scan(question,minutes,token),string.IsNullOrWhiteSpace(script)?PathFromQuestion(question):script);
    }
    internal static Observation Scan(string question,int minutes,CancellationToken token,bool processFirst=false)
    {
        if(minutes is <0 or >10080)throw new ArgumentException("Choose a period up to seven days or all retained logs.");
        var end=DateTimeOffset.UtcNow;var scan=new Observation{Question=question,Start=minutes==0?DateTimeOffset.UnixEpoch:end.AddMinutes(-minutes),End=end,Status="investigation"};
        var totalBytes=0;using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(45));
        foreach(var channel in processFirst?Collector.Channels:Collector.Channels.Skip(1).Append(Collector.Channels[0]))
        {
            try
            {
                // Event-log queries, not the 2,000-row live network buffer. No user input is inserted in XPath.
                var ids=channel==Collector.Channels[0]?"(EventID=1 or EventID=2 or EventID=3 or EventID=5 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=15 or EventID=16 or EventID=22 or EventID=23 or EventID=26 or EventID=29 or EventID=255)":"(EventID=4103 or EventID=4104 or EventID=24577)";
                var query=new EventLogQuery(channel,PathType.LogName,$"*[System[{ids} and TimeCreated[@SystemTime >= '{Collector.EventTime(scan.Start)}' and @SystemTime <= '{Collector.EventTime(end)}']]]"){ReverseDirection=true};
                using var reader=new EventLogReader(query);var count=0;
                while(true)
                {
                    deadline.Token.ThrowIfCancellationRequested();using var record=reader.ReadEvent(TimeSpan.FromSeconds(1));if(record is null)break;
                    var xml=record.ToXml();if(totalBytes+Encoding.UTF8.GetByteCount(xml)>48_000_000){scan.Warnings.Add("Historical scan reached its 48 MB limit; unscanned evidence is missing.");break;}
                    totalBytes+=Encoding.UTF8.GetByteCount(xml);scan.Events.Add(EvidenceEvent.Parse(xml));
                    if(++count==25000){scan.Warnings.Add(channel+": scanned the newest 25,000 matching events; older evidence may be missing. Narrow the time window.");break;}
                }
            }
            catch(OperationCanceledException)when(!token.IsCancellationRequested){scan.Warnings.Add("Historical scan reached its 45-second time limit; results are partial. Narrow the time window.");break;}
            catch(OperationCanceledException){throw;}
            catch(EventLogNotFoundException)when(channel==Collector.Channels[2]){scan.Warnings.Add("Optional PowerShell 7 log channel is unavailable. Windows PowerShell and ISE use Microsoft-Windows-PowerShell/Operational; this does not explain missing records from those hosts.");}
            catch(Exception e){scan.Warnings.Add(channel+": "+e.Message);}
        }
        if(!SensorSetup.PowerShellLoggingEnabled)scan.Warnings.Add("PowerShell Script Block Logging is currently disabled. Enabling it cannot recover earlier script text.");
        if(!processFirst)
        {
            scan.Warnings.InsertRange(0,SensorSetup.PowerShellSessionWarnings());
            if(!scan.Events.Any(e=>e.EventId is 4103 or 4104 or 24577))scan.Warnings.Add("No PowerShell script/module/invocation records were available in this search period. Other scanned events do not establish which script an existing interactive host ran. This is a logging or attribution gap, not evidence that the script did not run.");
        }
        scan.Warnings.Add("The selected period is a search boundary, not a guarantee the entire period is retained. Log rotation, disabled sensors and filter changes can remove evidence.");
        return scan;
    }
    public static Observation Correlate(Observation scan,string requested)
    {
        var events=scan.Events.DistinctBy(e=>e.Id).OrderBy(e=>e.Timestamp).ToArray();
        var starts=events.Where(e=>Sysmon(e)&&e.EventId==1&&D(e,"ProcessGuid").Length>0).ToArray();
        var blocks=events.Where(e=>Script(e)&&D(e,"Path").Length>0).ToArray();
        if(string.IsNullOrWhiteSpace(requested))
        {
            var latestBlock=blocks.LastOrDefault();var latestCommand=starts.LastOrDefault(e=>CommandScripts(e).Length>0);
            requested=latestBlock is not null&&(latestCommand is null||latestBlock.Timestamp>=latestCommand.Timestamp)?D(latestBlock,"Path"):latestCommand is null?"":CommandScripts(latestCommand).Last();
        }
        requested=Normalize(requested);
        var matchingBlocks=blocks.Where(e=>PathMatches(D(e,"Path"),requested)).ToArray();
        var matchingStarts=starts.Where(e=>CommandScripts(e).Any(p=>PathMatches(p,requested))).ToArray();
        // Module records are often emitted at the END of a command/pipeline. Do not
        // let the last cleanup/output command move the run boundary past its script text.
        var anchor=matchingBlocks.LastOrDefault(e=>e.EventId is 4104 or 24577);
        var module=matchingBlocks.LastOrDefault(e=>e.EventId==4103);
        if(module is not null&&(anchor is null||module.Timestamp>anchor.Timestamp))
        {
            var pid=D(module,"ProcessId");
            bool SamePipeline(EvidenceEvent e)=>D(e,"ProcessId")==pid&&D(e,"HostId")==D(module,"HostId")&&D(e,"RunspaceId")==D(module,"RunspaceId")&&D(e,"PipelineId")==D(module,"PipelineId");
            if(D(module,"HostId").Length>0&&D(module,"RunspaceId").Length>0&&D(module,"PipelineId").Length>0)
            {
                var first=matchingBlocks.First(e=>e.EventId==4103&&SamePipeline(e));
                var prior=events.LastOrDefault(e=>e.EventId==4103&&D(e,"ProcessId")==pid&&e.Timestamp<first.Timestamp&&!SamePipeline(e));
                var host=starts.LastOrDefault(e=>D(e,"ProcessId")==pid&&e.Timestamp<=first.Timestamp);
                var boundary=scan.Start;if(prior is not null&&prior.Timestamp>=boundary)boundary=prior.Timestamp.AddTicks(1);if(host is not null&&host.Timestamp>boundary)boundary=host.Timestamp;
                var direct=matchingBlocks.Where(e=>e.EventId is 4104 or 24577&&D(e,"ProcessId")==pid&&e.Timestamp>=boundary&&e.Timestamp<=module.Timestamp).ToArray();
                anchor=direct.LastOrDefault(e=>e.EventId==24577)??direct.FirstOrDefault(e=>e.EventId==4104)??first;
            }
            else if(anchor is null||D(anchor,"ProcessId")!=pid)anchor=module;
        }
        if(anchor is not null&&D(anchor,"ScriptBlockId").Length>0)anchor=matchingBlocks.First(e=>e.Channel==anchor.Channel&&D(e,"ScriptBlockId")==D(anchor,"ScriptBlockId")&&D(e,"ProcessId")==D(anchor,"ProcessId"));
        var root=matchingStarts.LastOrDefault();
        if(anchor is not null&&(root is null||anchor.Timestamp>=root.Timestamp))
        {
            var host=starts.LastOrDefault(e=>D(e,"ProcessId")==D(anchor,"ProcessId")&&e.Timestamp<=anchor.Timestamp);
            if(host is not null&&!events.Any(e=>Sysmon(e)&&e.EventId==5&&D(e,"ProcessGuid")==D(host,"ProcessGuid")&&e.Timestamp<anchor.Timestamp&&e.Timestamp>=host.Timestamp))root=host;
            else root=null;
        }
        else anchor=null;
        var info=new InvestigationResult{Script=requested,ScannedEvents=events.Length};
        var result=new Observation{Question=scan.Question,Start=scan.Start,End=scan.End,Status="investigation",Warnings=scan.Warnings.ToList(),Investigation=info};
        result.Warnings.Add(Limits);
        if(root is null&&anchor is null){info.Match="Unable to link recorded activity to this script";result.Warnings.Add("No logged script path or PowerShell process command line matched. The script may have run inside an existing PowerShell/ISE host without a new process launch or script record. The current file on disk was not used as evidence of execution. Save work and open a fresh PowerShell session if logging was recently enabled; try a wider period for older records.");return result;}
        var start=anchor?.Timestamp??root!.Timestamp;info.ExecutionStart=start;info.ProcessGuid=root is null?"":D(root,"ProcessGuid");info.ProcessId=D(root??anchor!,"ProcessId");
        var end=scan.End??DateTimeOffset.UtcNow;
        var exit=root is null?null:events.FirstOrDefault(e=>Sysmon(e)&&e.EventId==5&&D(e,"ProcessGuid")==info.ProcessGuid&&e.Timestamp>=start);
        var reuse=starts.FirstOrDefault(e=>D(e,"ProcessId")==info.ProcessId&&e.Timestamp>start&&(root is null||D(e,"ProcessGuid")!=info.ProcessGuid));
        if(exit is not null&&exit.Timestamp<end)end=exit.Timestamp;
        if(reuse is not null&&reuse.Timestamp<end)end=reuse.Timestamp.AddTicks(-1);
        var guids=new HashSet<string>(StringComparer.OrdinalIgnoreCase);if(info.ProcessGuid.Length>0)guids.Add(info.ProcessGuid);
        // GUID lineage avoids attributing a reused PID to a prior script run.
        var parents=new Dictionary<string,EvidenceEvent>(StringComparer.OrdinalIgnoreCase);if(root is not null)parents[info.ProcessGuid]=root;
        var changed=true;while(changed){changed=false;foreach(var p in starts){var parent=D(p,"ParentProcessGuid");if(p.Timestamp<start||p.Timestamp>(scan.End??end)||!parents.TryGetValue(parent,out var parentStart)||p.Timestamp<parentStart.Timestamp)continue;var parentExit=events.FirstOrDefault(e=>Sysmon(e)&&e.EventId==5&&D(e,"ProcessGuid")==parent&&e.Timestamp>=parentStart.Timestamp);if(parentExit is not null&&p.Timestamp>parentExit.Timestamp)continue;if(guids.Add(D(p,"ProcessGuid"))){parents[D(p,"ProcessGuid")]=p;changed=true;}}}
        var selected=new List<EvidenceEvent>();
        foreach(var e in events)
        {
            if(root is not null&&e.Id==root.Id){selected.Add(e);continue;}
            if(e.Timestamp<start||e.Timestamp>(scan.End??end))continue;
            var guid=D(e,"ProcessGuid");
            if(Sysmon(e)&&guid.Length>0&&guids.Contains(guid))
            {
                if(guid.Equals(info.ProcessGuid,StringComparison.OrdinalIgnoreCase)&&e.Timestamp>end)continue;
                selected.Add(e);continue;
            }
            if(e.EventId is 4103 or 4104)
            {
                var owner=starts.LastOrDefault(p=>D(p,"ProcessId")==D(e,"ProcessId")&&p.Timestamp<=e.Timestamp);
                if(owner is not null&&guids.Contains(D(owner,"ProcessGuid"))&&!events.Any(x=>Sysmon(x)&&x.EventId==5&&D(x,"ProcessGuid")==D(owner,"ProcessGuid")&&x.Timestamp>=owner.Timestamp&&x.Timestamp<e.Timestamp)){selected.Add(e);continue;}
            }
            if(root is null&&e.Timestamp<=end&&info.ProcessId.Length>0&&D(e,"ProcessId")==info.ProcessId)selected.Add(e);
        }
        if(anchor is not null&&!selected.Any(e=>e.Id==anchor.Id))selected.Add(anchor);
        info.Match=root is not null?"Process GUID and descendant correlation":"Script record matched; PID/time correlation only";
        if(anchor?.EventId==4103)result.Warnings.Add("The matching module pipeline identifies script activity, but its first record can be emitted after execution began. The boundary is the earliest available matching module record, not a proven script start time; earlier actions may be missing.");
        result.Warnings.Add(root is not null?"Events are attributed to the script's host process or descendants, not proof that this specific script caused every action. Shared or interactive PowerShell hosts can run unrelated code.":"Process creation/GUID evidence is missing. Same-PID activity is only a candidate; process lifetime cannot be fully verified.");
        if(matchingStarts.Length>1)result.Warnings.Add("Multiple matching process launches exist in this period. This report selects the most recent matching execution.");
        if(!requested.Contains('\\')&&matchingBlocks.Select(e=>D(e,"Path")).Distinct(StringComparer.OrdinalIgnoreCase).Count()>1)result.Warnings.Add("The filename matches multiple paths. Enter a full script path to disambiguate.");
        var ordered=selected.OrderBy(e=>e.Timestamp).ToArray();
        var retained=new List<EvidenceEvent>();var bytes=0;
        foreach(var e in ordered.OrderByDescending(e=>e.Id==root?.Id||Script(e)||Change(e,"") is not null))
        {
            var size=Encoding.UTF8.GetByteCount(System.Text.Json.JsonSerializer.Serialize(e,Evidence.Json));
            if(retained.Count>=5000||bytes+size>16_000_000)continue;
            retained.Add(e);bytes+=size;
        }
        retained=retained.OrderBy(e=>e.Timestamp).ToList();
        if(retained.Count<ordered.Length)result.Warnings.Add($"Investigation kept {retained.Count} of {ordered.Length} related events, prioritizing script text and changes; the timeline is incomplete.");
        result.Events=retained;
        info.Changes=retained.Select(e=>Change(e,root is null?"PID/time candidate":"Related process GUID")).Where(x=>x is not null).Cast<ChangeRecord>().ToList();
        info.DirectoryContexts=info.Changes.Where(c=>c.Category=="file").Select(c=>Path.GetDirectoryName(c.Path)??"").Where(p=>p.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray();
        return result;
    }
    public static ChangeRecord? Change(EvidenceEvent e,string attribution)
    {
        if(!Sysmon(e))return null;
        var path=D(e,e.EventId is 12 or 13 or 14?"TargetObject":"TargetFilename");if(path.Length==0)return null;
        var operation=e.EventId switch{11=>"create_or_overwrite",23 or 26=>"delete",2=>"change_creation_time",12=>D(e,"EventType") switch{"CreateKey"=>"create_key","DeleteKey"=>"delete_key","CreateValue"=>"create_value","DeleteValue"=>"delete_value",_=>"registry_object_change"},13=>"set_value",14=>"rename",_=>""};
        return operation.Length==0?null:new(e.Timestamp,e.EventId is 12 or 13 or 14?"registry":"file",operation,path,e.EventId==14?D(e,"NewName"):e.EventId==2?D(e,"PreviousCreationUtcTime")+" → "+D(e,"CreationUtcTime"):D(e,"Details"),attribution,e.Id);
    }
    public static string FormatLocal(Observation s)
    {
        var i=s.Investigation!;var text=new StringBuilder("HISTORICAL SCRIPT INVESTIGATION — LOCAL EVIDENCE\n\n");text.AppendLine("Script: "+(i.Script.Length>0?i.Script:"No matching script"));text.AppendLine(i.Match);text.AppendLine($"Scanned {i.ScannedEvents:N0} events; retained {s.Events.Count:N0} related events.");
        foreach(var c in i.Changes)text.AppendLine($"\n{c.Timestamp:O} | {c.Category} | {c.Operation.Replace('_',' ')}\n{c.Path}\n{c.Detail}\n{c.Attribution} · {c.EvidenceId}");
        if(i.Changes.Count==0)text.AppendLine("\nNo file or registry changes were established by the available related Sysmon events.");
        text.AppendLine("\nDIRECTORY CONTEXT (parent paths only; creation/deletion unproven)");foreach(var path in i.DirectoryContexts)text.AppendLine(path);
        text.AppendLine("\nCOVERAGE\n"+string.Join("\n",s.Warnings));return text.ToString();
    }
}
