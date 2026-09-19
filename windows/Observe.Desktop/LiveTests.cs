using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Observe;

public sealed partial class MainForm
{
    /// <summary>Runs on the real WinForms message loop, using real local sockets and the production timer.</summary>
    internal async Task<object> TestLiveUi()
    {
        static void Check(bool condition,string message){if(!condition)throw new InvalidOperationException(message);}
        async Task WaitFor(Func<bool> predicate,string error)
        {
            var until=DateTimeOffset.UtcNow.AddSeconds(20);
            while(!predicate()&&DateTimeOffset.UtcNow<until)await Task.Delay(100);
            Check(predicate(),error);
        }
        await WaitFor(()=>!busy,"Readiness never completed");
        Check(!HasCredentials&&!review.Enabled&&!automatic.Enabled,"AI must be disabled without credentials");
        Check(observe.Enabled,"Observe must work without a key");
        using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        var port=((IPEndPoint)listener.LocalEndpoint).Port;
        using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,port);using var server=await listener.AcceptTcpClientAsync();
        await client.GetStream().WriteAsync(new byte[]{1,2,3});var received=new byte[3];await server.GetStream().ReadExactlyAsync(received);
        await WaitFor(()=>live.Events.Any(e=>e.EventId==NetworkMonitor.ConnectionEvent&&e.Data.GetValueOrDefault("RemotePort")==port.ToString()),"Real loopback connection never reached the live buffer");
        ShowPage("Activity");
        // Busy hosts can produce >500 unrelated events between a TCP sample and rendering.
        // The classic timeline promises only its latest 500 rows; the network view below
        // must still display the real connection independently of that timeline limit.
        Check(events.Rows.Count>0&&events.Rows.Count<=500,"Activity did not render its bounded timeline.");
        if(live.Events.OrderByDescending(e=>e.Timestamp).Take(500).Any(e=>e.Data.GetValueOrDefault("RemotePort")==port.ToString()))
            Check(events.Rows.Cast<DataGridViewRow>().Any(r=>r.Tag is EvidenceEvent e&&e.Data.GetValueOrDefault("RemotePort")==port.ToString()),"A visible-window loopback event was not rendered.");
        ShowPage("Domains & IPs");
        Check(networks.Rows.Cast<DataGridViewRow>().Any(r=>r.Cells["remote"].Value?.ToString()==$"127.0.0.1:{port}"),"Loopback missing from visible network rows");
        var liveRows=events.Rows.Count;var networkRows=networks.Rows.Count;
        // Exercise the same command as Observe with no credentials and no elevation.
        await Work(StartObservation);
        Check(collecting&&session is not null,"Observe failed without a key");
        await WaitFor(()=>session!.Events.Any(e=>e.Data.GetValueOrDefault("RemotePort")==port.ToString()),"Connection baseline missing from saved observation");
        await Work(Finish);
        Check(!collecting&&session!.Events.Count>0&&File.Exists(Path.Combine(store.DirectoryPath,session.Id+".json")),"Capture was not saved");
        apiKey.Text="test-key-for-enablement-only";
        Check(HasCredentials&&review.Enabled&&automatic.Enabled,"Setting a key did not enable AI controls");
        apiKey.Clear();Check(!review.Enabled&&!automatic.Enabled,"Removing a key did not disable AI controls");
        provider.SelectedIndex=1;serviceToken.Text="test-token-for-enablement-only";
        Check(!HasCredentials&&!review.Enabled,"Managed AI enabled without a service URL");
        gateway.Text="https://example.com";Check(HasCredentials&&review.Enabled,"Managed credentials did not enable AI");
        gateway.Clear();serviceToken.Clear();provider.SelectedIndex=0;
        Check(!HasCredentials&&!review.Enabled&&!automatic.Enabled,"AI did not return to disabled state");
        session=null;lastRendered=-1;RenderEvidence();ControlsEnabled();
        await Work(()=>ApplyLocalMode(true));Check(gaming&&timer.Interval==5000&&!review.Enabled,"Performance mode failed without admin");
        await Work(()=>ApplyLocalMode(false));Check(!gaming&&timer.Interval==1000,"Performance mode did not restore live refresh");
        ShowPage("Overview");
        return new{passed=true,administrator=SensorSetup.IsAdministrator,liveActivityRows=liveRows,liveNetworkRows=networkRows,noKeyCapture=true,realLoopbackVisible=true,credentialGating=true,performanceMode=true,apiCalls=0};
    }
}

public static class LiveTests
{
    public static async Task<int> Run(string output)
    {
        var results=new List<object>();var failed=0;
        async Task Test(string name,Func<Task> action){try{await action();results.Add(new{name,passed=true});}catch(Exception e){failed++;results.Add(new{name,passed=false,error=e.ToString()});}}
        static void Check(bool condition,string message){if(!condition)throw new InvalidOperationException(message);}
        foreach(var ip in new[]{IPAddress.Loopback,IPAddress.IPv6Loopback})await Test($"Real {ip.AddressFamily} TCP endpoints and PID",async()=>
        {
            using var listener=new TcpListener(ip,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
            using var client=new TcpClient(ip.AddressFamily);await client.ConnectAsync(ip,port);using var server=await listener.AcceptTcpClientAsync();
            var rows=NetworkMonitor.ReadTcpConnections();
            Check(rows.Any(r=>r.Pid==Environment.ProcessId&&r.RemoteIp==ip.ToString()&&r.RemotePort==port),"Outgoing side was not detected");
            Check(rows.Any(r=>r.Pid==Environment.ProcessId&&r.LocalIp==ip.ToString()&&r.LocalPort==port&&r.RemotePort!=0),"Incoming side was not detected");
        });
        await Test("Live DNS resolution appears in the Windows cache",async()=>
        {
            var addresses=await Dns.GetHostAddressesAsync("example.com");var cache=NetworkMonitor.ReadDnsCache();
            Check(cache.Any(c=>c.Name.TrimEnd('.').Equals("example.com",StringComparison.OrdinalIgnoreCase)&&addresses.Any(a=>a.ToString()==c.Address)),"Resolved example.com address missing from DNS cache");
        });
        await Test("Real outbound HTTPS connection reaches telemetry and view rows",async()=>
        {
            using var monitor=new NetworkMonitor();var evidence=new List<EvidenceEvent>();monitor.Recorded+=e=>evidence.Add(e);
            monitor.StartTrace();monitor.Poll();
            using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(15)};
            using var response=await client.GetAsync("https://example.com",HttpCompletionOption.ResponseHeadersRead);response.EnsureSuccessStatusCode();
            monitor.ReplaySnapshot();monitor.Poll();
            Check(evidence.Any(e=>e.EventId==NetworkMonitor.ConnectionEvent&&e.Data.GetValueOrDefault("ProcessId")==Environment.ProcessId.ToString()&&e.Data.GetValueOrDefault("RemotePort")=="443"),"HTTPS process/remote endpoint not observed");
            Check(NetworkView.Rows(evidence).Any(r=>r.Domain.Contains("example.com")),"Domain not represented in network view");
            Check(evidence.Any(e=>e.EventId==NetworkMonitor.CacheEvent),"DNS evidence missing");
        });
        await Test("Connection closes are retained and sampling does not duplicate unchanged rows",async()=>
        {
            using var monitor=new NetworkMonitor();var evidence=new List<EvidenceEvent>();monitor.Recorded+=e=>evidence.Add(e);
            using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
            using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,port);using var server=await listener.AcceptTcpClientAsync();
            monitor.Poll();var before=evidence.Count(e=>e.Data.GetValueOrDefault("RemotePort")==port.ToString());monitor.Poll();
            Check(evidence.Count(e=>e.Data.GetValueOrDefault("RemotePort")==port.ToString())==before,"Unchanged TCP connection duplicated");
            client.Client.LingerState=new LingerOption(true,0);client.Close();server.Close();await Task.Delay(150);monitor.Poll();
            Check(evidence.Any(e=>e.Data.GetValueOrDefault("RemotePort")==port.ToString()&&e.Data.GetValueOrDefault("Change")=="No longer in TCP table"),"Closed endpoint not reported");
        });
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed=results.Count-failed,failed,administrator=SensorSetup.IsAdministrator,tests=results},Evidence.Json));return failed==0?0:1;
    }
}
