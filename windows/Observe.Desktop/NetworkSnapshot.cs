using System.Net;
using System.Drawing.Imaging;

namespace Observe;

public sealed record FlowRow(string Id,string Process,string Image,string Pid,string RemoteIp,string Port,string Local,string Domain,string Protocol,string State,string Source,string Direction,DateTimeOffset First,DateTimeOffset Last,long? Download,long? Upload,int Observations,string Country,string Scope,string Icon);
public sealed record AppTraffic(string Name,string Image,string[] Pids,int Flows,int Destinations,long? Download,long? Upload,DateTimeOffset Last,string Icon);
public sealed record TrafficBucket(DateTimeOffset At,long Download,long Upload);
public sealed record NetworkSnapshot(DateTimeOffset CapturedAt,DateTimeOffset Start,FlowRow[] Flows,AppTraffic[] Apps,TrafficBucket[] Traffic,string[] Warnings);
public static class NetworkSnapshots
{
    public static NetworkSnapshot Create(IEnumerable<EvidenceEvent> source,int minutes,CountryMap? map=null,bool icons=true,DateTimeOffset? now=null)
    {
        if(minutes is <1 or >1440)throw new ArgumentException("Choose a period between 1 minute and 24 hours.");
        var end=now??DateTimeOffset.UtcNow;var start=end.AddMinutes(-minutes);
        var events=source.Where(e=>e.IsNetwork&&e.EventId!=NetworkMonitor.CacheEvent&&e.Timestamp>=start&&e.Timestamp<=end).OrderBy(e=>e.Timestamp).ToArray();
        var normalized=events.Select(e=>
        {
            var d=e.Data;var inbound=d.GetValueOrDefault("Initiated")=="false";
            var image=d.GetValueOrDefault("Image",e.Process);var pid=d.GetValueOrDefault("ProcessId","");
            if(!int.TryParse(pid,out var owner)||owner<=0)image="Unattributed (owner unavailable)";
            var remote=d.GetValueOrDefault("RemoteIp",d.GetValueOrDefault(inbound?"SourceIp":"DestinationIp",""));var port=d.GetValueOrDefault("RemotePort",d.GetValueOrDefault(inbound?"SourcePort":"DestinationPort",""));
            var local=d.GetValueOrDefault("LocalIp",d.GetValueOrDefault(inbound?"DestinationIp":"SourceIp",""));
            var domain=d.GetValueOrDefault("QueryName",d.GetValueOrDefault("DomainCandidate",d.GetValueOrDefault("DestinationHostname","")));
            var protocol=d.GetValueOrDefault("Protocol",e.EventId is 22 or NetworkMonitor.DnsEvent?"DNS":"TCP").ToUpperInvariant();
            var direction=d.GetValueOrDefault("Direction",inbound?"Inbound":"Outbound");
            // DNS queries remain separate from connections; never infer a connection from cached answers.
            var key=string.Join('|',image.ToLowerInvariant(),pid,d.GetValueOrDefault("ProcessStartTime",d.GetValueOrDefault("ProcessGuid","")),remote,port,local,protocol,protocol=="DNS"?domain:"");
            return new{e,d,image,pid,remote,port,local,domain,protocol,direction,key};
        });
        var flows=normalized.GroupBy(x=>x.key).Select(g=>
        {
            var x=g.Last();var transfers=g.Where(y=>y.e.EventId==NetworkMonitor.TransferEvent).ToArray();
            long Bytes(string direction)=>transfers.Where(y=>y.direction==direction).Sum(y=>long.TryParse(y.d.GetValueOrDefault("Bytes"),out var n)?Math.Max(0,n):0);
            var parsed=IPAddress.TryParse(x.remote,out var address);var scope=parsed&&!ThreatFoxClient.PublicAddress(address!)?"Local / reserved":parsed?"Public":"DNS";
            return new FlowRow(x.e.Id,System.IO.Path.GetFileName(x.image),x.image,x.pid,x.remote,x.port,x.local,x.domain+(x.d.ContainsKey("DomainCandidate")&&x.domain.Length>0?" (cache candidate)":""),x.protocol,x.d.GetValueOrDefault("State",x.direction),string.Join(", ",g.Select(y=>y.d.GetValueOrDefault("Source",y.e.Channel)).Distinct()),x.direction,g.First().e.Timestamp,x.e.Timestamp,transfers.Length>0?Bytes("Receive"):null,transfers.Length>0?Bytes("Send"):null,g.Count(),map?.Find(x.remote)??"",scope,"");
        }).OrderByDescending(f=>f.Last).Take(1000).ToArray();
        var apps=flows.GroupBy(f=>f.Image,StringComparer.OrdinalIgnoreCase).Select(g=>new AppTraffic(g.First().Process,g.Key,g.Select(f=>f.Pid).Where(pid=>int.TryParse(pid,out var n)&&n>0).Distinct().ToArray(),g.Count(),g.Select(f=>f.RemoteIp.Length>0?f.RemoteIp:f.Domain).Distinct().Count(),g.Any(f=>f.Download.HasValue)?g.Sum(f=>f.Download??0):null,g.Any(f=>f.Upload.HasValue)?g.Sum(f=>f.Upload??0):null,g.Max(f=>f.Last),icons?AppIcons.Get(g.Key):"")).OrderByDescending(a=>(a.Download??0)+(a.Upload??0)).ThenByDescending(a=>a.Flows).ToArray();
        var buckets=Enumerable.Range(0,36).Select(i=>{var begin=start.AddTicks((end-start).Ticks*i/36);var stop=start.AddTicks((end-start).Ticks*(i+1)/36);var subset=events.Where(e=>e.EventId==NetworkMonitor.TransferEvent&&e.Timestamp>=begin&&e.Timestamp<stop);long Sum(string direction)=>subset.Where(e=>e.Data.GetValueOrDefault("Direction")==direction).Sum(e=>long.TryParse(e.Data.GetValueOrDefault("Bytes"),out var n)?Math.Max(0,n):0);return new TrafficBucket(begin,Sum("Receive"),Sum("Send"));}).ToArray();
        return new(end,start,flows,apps,buckets,["A frozen view of the current bounded memory buffer; click Refresh to update. Up to 1,000 grouped flows are shown. Separate telemetry sources may describe the same connection.","Transfer bytes are observed ETW bytes only, not router totals. — means unavailable. Connections, DNS and cache candidates do not prove a website visit.",map?.Loaded==true?"Country labels come from your imported local map and may be outdated. Location does not establish risk.":"Country locations are unknown until a local CIDR,country CSV map is imported. No geolocation service is contacted."]);
    }
}
public static class AppIcons
{
    static readonly Dictionary<string,string> cache=new(StringComparer.OrdinalIgnoreCase);
    public static string Get(string path)
    {
        if(cache.TryGetValue(path,out var saved))return saved;var result="";
        try{if(System.IO.Path.IsPathFullyQualified(path)&&!path.StartsWith(@"\\")&&File.Exists(path)){using var icon=Icon.ExtractAssociatedIcon(path);using var bitmap=icon?.ToBitmap();if(bitmap is not null){using var stream=new MemoryStream();bitmap.Save(stream,ImageFormat.Png);result="data:image/png;base64,"+Convert.ToBase64String(stream.ToArray());}}}catch(Exception e)when(e is ArgumentException or IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException){}
        if(cache.Count>=128)cache.Clear();cache[path]=result;return result;
    }
}
public sealed class CountryMap
{
    readonly List<(byte[] Network,int Bits,string Country)> ranges=[];
    public bool Loaded=>ranges.Count>0;
    public CountryMap(string? csv=null)
    {
        if(csv is null)return;if(csv.Length>4_000_000)throw new ArgumentException("Country map must be under 4 MB.");
        foreach(var line in csv.Split('\n',StringSplitOptions.RemoveEmptyEntries))
        {
            var value=line.Trim();if(value.StartsWith('#')||value.StartsWith("cidr,",StringComparison.OrdinalIgnoreCase))continue;
            var fields=value.Split(',');if(fields.Length!=2)throw new ArgumentException("Use two CSV columns: CIDR,country (ISO two-letter code).");
            var prefix=fields[0].Trim().Split('/');if(prefix.Length!=2||!IPAddress.TryParse(prefix[0],out var ip)||!int.TryParse(prefix[1],out var bits)||bits<0||bits>ip.GetAddressBytes().Length*8)throw new ArgumentException("Invalid network prefix in country map.");
            var country=fields[1].Trim().ToUpperInvariant();if(country.Length!=2||country.Any(c=>c is <'A' or >'Z'))throw new ArgumentException("Use ISO two-letter country codes.");
            _=new System.Globalization.RegionInfo(country);ranges.Add((ip.GetAddressBytes(),bits,country));if(ranges.Count>50000)throw new ArgumentException("Country map supports up to 50,000 prefixes.");
        }
        ranges.Sort((a,b)=>b.Bits.CompareTo(a.Bits));
    }
    public string Find(string value)
    {
        if(!IPAddress.TryParse(value,out var ip)||!ThreatFoxClient.PublicAddress(ip))return "";var bytes=ip.GetAddressBytes();
        foreach(var (network,bits,country) in ranges){if(network.Length!=bytes.Length)continue;var full=bits/8;var remaining=bits%8;if(!bytes.AsSpan(0,full).SequenceEqual(network.AsSpan(0,full)))continue;if(remaining>0&&(bytes[full]>>(8-remaining))!=(network[full]>>(8-remaining)))continue;return country;}return "";
    }
}
