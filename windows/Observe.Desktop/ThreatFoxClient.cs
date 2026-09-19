using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Observe;

public record ThreatMatch(string Id,string Ioc,string Malware,string Threat,int Confidence,string FirstSeen,string LastSeen,string Reference);
public record ThreatResult(string Indicator,string Status,DateTimeOffset CheckedAt,ThreatMatch[] Matches,string Note);
public sealed class ThreatFoxClient(PluginStore store)
{
    readonly Dictionary<string,ThreatResult> cache=new(StringComparer.OrdinalIgnoreCase);
    public static string Validate(string indicator)
    {
        indicator=indicator.Trim();
        if(indicator.Length is <1 or >253||indicator.Any(char.IsControl))throw new ArgumentException("Enter a public IP address, domain, or SHA-256 hash.");
        if(System.Text.RegularExpressions.Regex.IsMatch(indicator,"^[a-fA-F0-9]{64}$"))return indicator.ToLowerInvariant();
        if(IPAddress.TryParse(indicator,out var ip))
        {
            if(!PublicAddress(ip))throw new ArgumentException("Private, local and reserved addresses are not sent to ThreatFox.");return ip.ToString();
        }
        if(!indicator.Contains('.')||indicator.EndsWith(".local",StringComparison.OrdinalIgnoreCase)||indicator.EndsWith(".lan",StringComparison.OrdinalIgnoreCase)||indicator.EndsWith(".internal",StringComparison.OrdinalIgnoreCase)||Uri.CheckHostName(indicator)!=UriHostNameType.Dns)throw new ArgumentException("Use a public IP, domain or SHA-256 hash; URLs and local names are not sent.");
        return new System.Globalization.IdnMapping().GetAscii(indicator).ToLowerInvariant();
    }
    public static bool PublicAddress(IPAddress ip)
    {
        if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();if(IPAddress.IsLoopback(ip))return false;var b=ip.GetAddressBytes();
        if(b.Length==16)return !ip.IsIPv6LinkLocal&&!ip.IsIPv6SiteLocal&&!ip.IsIPv6Multicast&&!ip.Equals(IPAddress.IPv6Any)&&(b[0]&0xfe)!=0xfc&&!(b[0]==0x20&&b[1]==1&&b[2]==0x0d&&b[3]==0xb8);
        return !(b[0] is 0 or 10 or 127||b[0]>=224||b[0]==169&&b[1]==254||b[0]==172&&b[1]>=16&&b[1]<=31||b[0]==192&&(b[1]==168||b[1]==0)||b[0]==100&&b[1]>=64&&b[1]<=127||b[0]==198&&(b[1] is 18 or 19||b[1]==51&&b[2]==100)||b[0]==203&&b[1]==0&&b[2]==113);
    }
    public async Task<ThreatResult> Search(string indicator,CancellationToken token=default,HttpMessageHandler? handler=null)
    {
        indicator=Validate(indicator);var settings=store.Load();
        if(!settings.ThreatFox||settings.ThreatFoxKey.Length==0)throw new InvalidOperationException("Configure the optional ThreatFox plugin first.");
        if(cache.TryGetValue(indicator,out var old)&&DateTimeOffset.UtcNow-old.CheckedAt<TimeSpan.FromMinutes(30))return old;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(20));
        using var client=new HttpClient(handler??new HttpClientHandler{AllowAutoRedirect=false});
        using var request=new HttpRequestMessage(HttpMethod.Post,"https://threatfox-api.abuse.ch/api/v1/");
        request.Headers.Add("Auth-Key",PluginStore.Unprotect(settings.ThreatFoxKey));
        var hash=System.Text.RegularExpressions.Regex.IsMatch(indicator,"^[a-f0-9]{64}$");
        request.Content=new StringContent(JsonSerializer.Serialize(hash?(object)new{query="search_hash",hash=indicator}:new{query="search_ioc",search_term=indicator,exact_match=true}),Encoding.UTF8,"application/json");
        using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
        if(!response.IsSuccessStatusCode)throw new InvalidOperationException($"ThreatFox returned HTTP {(int)response.StatusCode}. Check the Auth-Key, access and rate limits.");
        using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);using var buffer=new MemoryStream();var bytes=new byte[8192];int read;
        while((read=await stream.ReadAsync(bytes,deadline.Token))>0){if(buffer.Length+read>2_000_000)throw new InvalidDataException("ThreatFox response exceeded the limit.");buffer.Write(bytes,0,read);}
        using var doc=JsonDocument.Parse(buffer.ToArray());var root=doc.RootElement;var status=root.GetProperty("query_status").GetString()??"unknown";
        if(status is not ("ok" or "no_result"))throw new InvalidOperationException("ThreatFox could not complete the lookup ("+status[..Math.Min(status.Length,80)]+").");
        string S(JsonElement item,string name)=>item.TryGetProperty(name,out var value)?(value.ToString() is var s?s[..Math.Min(1000,s.Length)]:""):"";
        var matches=status=="ok"&&root.TryGetProperty("data",out var items)&&items.ValueKind==JsonValueKind.Array?items.EnumerateArray().Take(100).Select(e=>new ThreatMatch(S(e,"id"),S(e,"ioc"),S(e,"malware_printable"),S(e,"threat_type_desc"),int.TryParse(S(e,"confidence_level"),out var n)?n:0,S(e,"first_seen"),S(e,"last_seen"),S(e,"reference"))).ToArray():[];
        var result=new ThreatResult(indicator,matches.Length>0?"match":"no_match",DateTimeOffset.UtcNow,matches,"A match is an indicator to investigate, not a malware verdict. No match does not establish safety. ThreatFox's API omits expired indicators older than six months.");
        if(cache.Count>=200)cache.Clear();cache[indicator]=result;return result;
    }
    public void Clear()=>cache.Clear();
}
