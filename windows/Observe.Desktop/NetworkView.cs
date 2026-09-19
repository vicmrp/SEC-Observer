namespace Observe;

public record NetworkRow(string Source,string Process,string Domain,string Remote,string Local,string Protocol,string Activity,string Bytes,string Count,string Time);

public static class NetworkView
{
    public static IEnumerable<NetworkRow> Rows(IEnumerable<EvidenceEvent> events)
    {
        return events.Where(e=>e.IsNetwork).Select(e=>
        {
            var d=e.Data;var inbound=d.GetValueOrDefault("Initiated")=="false";
            string Endpoint(string ip,string port)=>string.IsNullOrEmpty(port)?ip:$"{(ip.Contains(':')?"["+ip+"]":ip)}:{port}";
            var remote=Endpoint(d.GetValueOrDefault("RemoteIp",d.GetValueOrDefault(inbound?"SourceIp":"DestinationIp",d.GetValueOrDefault("QueryResults",""))),d.GetValueOrDefault("RemotePort",d.GetValueOrDefault(inbound?"SourcePort":"DestinationPort","")));
            var local=Endpoint(d.GetValueOrDefault("LocalIp",d.GetValueOrDefault(inbound?"DestinationIp":"SourceIp","")),d.GetValueOrDefault("LocalPort",d.GetValueOrDefault(inbound?"DestinationPort":"SourcePort","")));
            var domain=d.GetValueOrDefault("QueryName",d.GetValueOrDefault("DomainCandidate",d.GetValueOrDefault("DestinationHostname","")));
            if(!string.IsNullOrEmpty(d.GetValueOrDefault("DomainCandidate")))domain+=" (cache match)";
            var source=d.GetValueOrDefault("Source",e.EventId==22?"Sysmon DNS":"Sysmon connection");
            var activity=d.GetValueOrDefault("Direction",e.EventId==22?"DNS query":d.ContainsKey("Initiated")?inbound?"Inbound connection":"Outbound connection":"Connection");
            return new{Event=e,Source=source,e.Process,Pid=d.GetValueOrDefault("ProcessId",d.GetValueOrDefault("ProcessGuid","")),Domain=domain,Remote=remote,Local=local,Protocol=d.GetValueOrDefault("Protocol",e.EventId is 22 or NetworkMonitor.CacheEvent or NetworkMonitor.DnsEvent?"DNS":""),Activity=activity};
        }).GroupBy(x=>new{x.Source,x.Process,x.Pid,x.Domain,x.Remote,x.Local,x.Protocol,x.Activity})
        .OrderByDescending(g=>g.Max(x=>x.Event.Timestamp)).Take(500)
        .Select(g=>
        {
            var latest=g.MaxBy(x=>x.Event.Timestamp)!.Event;var k=g.Key;
            var size=g.Sum(x=>long.TryParse(x.Event.Data.GetValueOrDefault("Bytes"),out var b)?b:0);
            return new NetworkRow(k.Source,k.Process,k.Domain,k.Remote,k.Local,k.Protocol,latest.Data.GetValueOrDefault("State",k.Activity),size>0?size.ToString("N0"):"—",g.Count().ToString(),latest.Timestamp.ToLocalTime().ToString("HH:mm:ss"));
        });
    }
}

public sealed class ReadableButton : Button
{
    protected override void OnPaint(PaintEventArgs e)
    {
        if(Enabled){base.OnPaint(e);return;}
        e.Graphics.Clear(Color.FromArgb(42,47,45));
        using var pen=new Pen(Color.FromArgb(74,83,77));e.Graphics.DrawRectangle(pen,0,0,Width-1,Height-1);
        TextRenderer.DrawText(e.Graphics,Text,Font,ClientRectangle,Color.FromArgb(133,146,137),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.WordBreak);
    }
}
public sealed class ReadableCheckBox : CheckBox
{
    protected override void OnPaint(PaintEventArgs e)
    {
        if(Enabled){base.OnPaint(e);return;}
        e.Graphics.Clear(BackColor);using var pen=new Pen(Color.FromArgb(117,131,122));e.Graphics.DrawRectangle(pen,1,Math.Max(1,(Height-13)/2),13,13);
        TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle(22,0,Width-22,Height),Color.FromArgb(133,146,137),TextFormatFlags.Left|TextFormatFlags.VerticalCenter);
    }
}
