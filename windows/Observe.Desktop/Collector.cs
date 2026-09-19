using System.Diagnostics.Eventing.Reader;

namespace Observe;

public sealed class Collector : IDisposable
{
    public static readonly string[] Channels = ["Microsoft-Windows-Sysmon/Operational","Microsoft-Windows-PowerShell/Operational","PowerShellCore/Operational"];
    readonly List<EventLogWatcher> watchers = [];
    public event Action<EvidenceEvent>? Recorded;
    public event Action<string>? Gap;
    internal static string EventTime(DateTimeOffset at)=>at.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ",System.Globalization.CultureInfo.InvariantCulture);
    internal static string ChannelProblem(string channel,Exception error)=>channel==Channels[2]&&error is EventLogNotFoundException?"Optional PowerShell 7 log channel is unavailable. Windows PowerShell and ISE use a separate channel; their logging is unaffected by this missing provider.":$"{channel}: {error.Message}";
    public static List<string> Status()
    {
        var status = new List<string>();
        foreach (var channel in Channels)
        {
            try
            {
                using var c=new EventLogConfiguration(channel);
                if(!c.IsEnabled){status.Add($"{channel}: disabled");continue;}
                using var reader=new EventLogReader(new EventLogQuery(channel,PathType.LogName,"*"){ReverseDirection=true});
                using var item=reader.ReadEvent(TimeSpan.FromSeconds(1));
                status.Add($"{channel}: enabled; {(item is null ? "readable, no events" : "event read verified")}");
            }
            catch(Exception e) { status.Add(ChannelProblem(channel,e)); }
        }
        return status;
    }
    public void Start(DateTimeOffset start)
    {
        Dispose();
        foreach(var channel in Channels)
        {
            try
            {
                var filter = channel == Channels[0] ? "" : " and (EventID=4103 or EventID=4104 or EventID=24577)";
                var query = new EventLogQuery(channel,PathType.LogName,$"*[System[TimeCreated[@SystemTime >= '{EventTime(start)}']{filter}]]");
                var watcher = new EventLogWatcher(query,null,true);
                watcher.EventRecordWritten += (_,args) =>
                {
                    if(args.EventException is not null) { Gap?.Invoke($"{channel}: {args.EventException.Message}"); return; }
                    using var record = args.EventRecord;
                    if(record is null) return;
                    try { Recorded?.Invoke(EvidenceEvent.Parse(record.ToXml())); }
                    catch(Exception e) { Gap?.Invoke($"Could not parse an event: {e.Message}"); }
                };
                watchers.Add(watcher); watcher.Enabled = true;
            }
            catch(Exception e) { Gap?.Invoke(ChannelProblem(channel,e)); }
        }
    }
    public void ReadWindow(DateTimeOffset start, DateTimeOffset end, CancellationToken cancellationToken,bool newestFirst=false,IEnumerable<string>? channels=null,int[]? eventIds=null,int maxRecords=5000)
    {
        foreach(var channel in channels??Channels)
        {
            try
            {
                var filter = eventIds is not null?" and ("+string.Join(" or ",eventIds.Select(id=>"EventID="+id))+")":channel == Channels[0] ? "" : " and (EventID=4103 or EventID=4104 or EventID=24577)";
                var query = new EventLogQuery(channel,PathType.LogName,$"*[System[TimeCreated[@SystemTime >= '{EventTime(start)}' and @SystemTime <= '{EventTime(end)}']{filter}]]") { ReverseDirection = newestFirst };
                using var reader = new EventLogReader(query);
                var count = 0;
                while(true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var record = reader.ReadEvent(TimeSpan.FromSeconds(2)); if(record is null) break;
                    Recorded?.Invoke(EvidenceEvent.Parse(record.ToXml()));
                    if(++count >= maxRecords) { Gap?.Invoke($"{channel}: reached the {maxRecords:N0}-event read limit; additional events may be omitted."); break; }
                }
            }
            catch(OperationCanceledException) { throw; }
            catch(Exception e) { Gap?.Invoke(ChannelProblem(channel,e)); }
        }
    }
    public void Dispose() { foreach(var watcher in watchers) { watcher.Enabled=false; watcher.Dispose(); } watchers.Clear(); }
}
