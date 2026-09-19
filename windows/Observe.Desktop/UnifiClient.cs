using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;

namespace Observe;

public sealed class UnifiClient
{
    readonly PluginStore store;
    readonly HttpMessageHandler? testHandler;
    public UnifiClient(PluginStore store,HttpMessageHandler? testHandler=null){this.store=store;this.testHandler=testHandler;}
    public static Uri ValidateUrl(string text)
    {
        if(!Uri.TryCreate(text.TrimEnd('/')+"/",UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.UserInfo.Length>0||uri.Query.Length>0||uri.Fragment.Length>0)throw new ArgumentException("Use an HTTPS integration base URL, without embedded credentials, query or fragment.");
        if(!uri.AbsolutePath.EndsWith("/integration/",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("The URL must end in /proxy/network/integration (UniFi OS) or /integration (standalone Network).");
        return uri;
    }
    public static string ValidatePin(string pin)
    {
        pin=pin.Replace(":","").Replace(" ","").ToUpperInvariant();
        if(pin.Length>0&&(pin.Length!=64||pin.Any(c=>!Uri.IsHexDigit(c))))throw new ArgumentException("The optional certificate pin must be a SHA-256 fingerprint (64 hex characters).");return pin;
    }
    public async Task<JsonElement> Get(string resource,CancellationToken cancellationToken=default)
    {
        using var totalTimeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);totalTimeout.CancelAfter(TimeSpan.FromSeconds(30));cancellationToken=totalTimeout.Token;
        var settings=store.Load();if(!settings.Unifi)throw new InvalidOperationException("Add the UniFi plugin first.");
        var baseUri=ValidateUrl(settings.UnifiUrl);var pin=ValidatePin(settings.CertificatePin);
        // Fixed GET routes only. Model input cannot supply a URL or a write operation.
        var route=resource switch{"sites"=>"v1/sites","clients"=>"v1/sites/"+Guid.Parse(settings.UnifiSite)+"/clients","devices"=>"v1/sites/"+Guid.Parse(settings.UnifiSite)+"/devices",_=>throw new ArgumentException("Unsupported UniFi resource.")};
        using var handler=testHandler??new HttpClientHandler{AllowAutoRedirect=false,ServerCertificateCustomValidationCallback=(_,cert,_,errors)=>pin.Length==0?errors==SslPolicyErrors.None:cert is not null&&CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData),Convert.FromHexString(pin))};
        using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(15)};
        var key=PluginStore.Unprotect(settings.UnifiKey);if(string.IsNullOrWhiteSpace(key))throw new InvalidOperationException("Set a UniFi integration API key.");
        var rows=new List<JsonElement>();var truncated=false;
        for(var offset=0;offset<1000;offset+=200)
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,new Uri(baseUri,route+$"?limit=200&offset={offset}"));request.Headers.Add("X-API-Key",key);request.Headers.Accept.ParseAdd("application/json");
            using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancellationToken);
            if(!response.IsSuccessStatusCode)throw new InvalidOperationException($"UniFi returned HTTP {(int)response.StatusCode}. Check the integration URL, API key, permissions and Network version.");
            await using var stream=await response.Content.ReadAsStreamAsync(cancellationToken);using var buffer=new MemoryStream();var bytes=new byte[8192];int n;
            while((n=await stream.ReadAsync(bytes,cancellationToken))>0){if(buffer.Length+n>2_000_000)throw new InvalidDataException("UniFi response exceeded 2 MB.");buffer.Write(bytes,0,n);}
            using var doc=JsonDocument.Parse(buffer.ToArray());var root=doc.RootElement;
            if(!root.TryGetProperty("data",out var data)||data.ValueKind!=JsonValueKind.Array)throw new InvalidDataException("Unexpected UniFi response; expected a data array.");
            if(data.GetArrayLength()>200)throw new InvalidDataException("UniFi exceeded the requested 200-row page limit.");
            rows.AddRange(data.EnumerateArray().Select(x=>x.Clone()));
            if(data.GetArrayLength()<200)break;
            if(offset==800)truncated=true;
        }
        return JsonSerializer.SerializeToElement(new{source="UniFi Network Integration API",resource,observedAt=DateTimeOffset.UtcNow,data=rows,truncated,coverage="Current client/device inventory, not historical traffic flows. IP matches are correlation candidates; DHCP assignments may change."},Evidence.Json);
    }
}
