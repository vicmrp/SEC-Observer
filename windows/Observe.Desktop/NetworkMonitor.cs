using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Observe;

public record TcpConnection(int Pid, string LocalIp, int LocalPort, string RemoteIp, int RemotePort, TcpState State)
{
    public string Key => $"{Pid}|{LocalIp}|{LocalPort}|{RemoteIp}|{RemotePort}";
}
public record DnsCacheRecord(string Name, string Address);

/// <summary>Read-only local telemetry. IP Helper works without Sysmon or elevation.
/// ETW adds DNS queries and send/receive aggregates when Windows grants access.</summary>
public sealed class NetworkMonitor : IDisposable
{
    public const int ConnectionEvent=10001, CacheEvent=10002, TransferEvent=10003, DnsEvent=10004;
    public const string Coverage="TCP tables are sampled; brief connections can be missed. DNS cache timestamps are first observed, not query times. Cached IP/name matches are candidates, not proof of a site visit. Full URLs and encrypted content are not captured. ETW send/receive events require administrator access and are paused in performance mode.";
    readonly object gate=new();
    readonly object sampling=new();
    readonly Dictionary<string,Transfer> transfers=[];
    Dictionary<string,TcpConnection> previous=[];
    readonly Dictionary<string,Dictionary<string,string>> connectionOwners=[];
    HashSet<DnsCacheRecord> cached=[];
    Dictionary<string,string> domains=[];
    readonly Dictionary<int,(string Name,DateTimeOffset At)> names=[];
    TraceEventSession? trace;
    Task? traceTask;
    bool disposed;
    long sequence;
    DateTimeOffset lastDns=DateTimeOffset.MinValue;
    public bool Gaming { get; set; }
    public string TcpStatus { get; private set; }="Starting TCP monitor…";
    public string DnsStatus { get; private set; }="Starting DNS cache monitor…";
    public string TraceStatus { get; private set; }="ETW not started";
    public DateTimeOffset? LastPoll { get; private set; }
    public event Action<EvidenceEvent>? Recorded;
    public event Action<string>? Gap;
    sealed record Transfer(int Pid,string Protocol,string Direction,string LocalIp,int LocalPort,string RemoteIp,int RemotePort)
    {
        public long Bytes; public int Packets; public DateTimeOffset At;
        public Dictionary<string,string> Identity=[];
    }

    public void StartTrace()
    {
        if(disposed||trace is not null)return;
        if(!SensorSetup.IsAdministrator){TraceStatus="TCP sampling + DNS cache active · Run as administrator for ETW send/receive and DNS queries";return;}
        try
        {
            trace=new TraceEventSession($"Observe-{Environment.ProcessId}-{Guid.NewGuid():N}"){StopOnDispose=true};
            // Kernel must be enabled before Source or any other provider starts the session.
            if(!Gaming)trace.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            trace.EnableProvider(DnsProvider,TraceEventLevel.Verbose,ulong.MaxValue,new TraceEventProviderOptions{EventIDsToEnable=[3008]});
            var source=trace.Source;
            source.Dynamic.All+=e=>
            {
                if(disposed||e.ProviderGuid!=DnsProvider)return;
                if((int)e.ID!=3008)return;
                var query=Field(e,"QueryName");if(query.Length==0)return;
                var pid=e.ProcessID;
                var identity=EndpointData(pid,"",0,"",0);identity["QueryName"]=query;identity["QueryResults"]=Field(e,"QueryResults");identity["QueryStatus"]=Field(e,"QueryStatus");identity["Source"]="Windows DNS ETW";identity["Direction"]="DNS query";
                identity.Remove("DomainCandidate");identity.Remove("DomainAttribution");
                Recorded?.Invoke(Create(DnsEvent,identity,new DateTimeOffset(e.TimeStamp.ToUniversalTime())));
            };
            source.Kernel.TcpIpSend+=e=>OnTransfer(e,"TCP","Send");
            source.Kernel.TcpIpRecv+=e=>OnTransfer(e,"TCP","Receive");
            source.Kernel.TcpIpSendIPV6+=e=>OnTransfer(e,"TCP","Send");
            source.Kernel.TcpIpRecvIPV6+=e=>OnTransfer(e,"TCP","Receive");
            source.Kernel.UdpIpSend+=e=>OnTransfer(e,"UDP","Send");
            source.Kernel.UdpIpRecv+=e=>OnTransfer(e,"UDP","Receive");
            source.Kernel.UdpIpSendIPV6+=e=>OnTransfer(e,"UDP","Send");
            source.Kernel.UdpIpRecvIPV6+=e=>OnTransfer(e,"UDP","Receive");
            TraceStatus=Gaming?"DNS queries live · Send/receive ETW paused for performance":"Live DNS queries + TCP/UDP send/receive (ETW)";
            traceTask=Task.Run(()=>
            {
                try{source.Process();if(!disposed){TraceStatus="ETW stopped unexpectedly · TCP sampling continues";Gap?.Invoke(TraceStatus);}}
                catch(Exception e){if(!disposed){TraceStatus="ETW unavailable: "+e.Message;Gap?.Invoke(TraceStatus);}}
            });
        }
        catch(Exception e){trace?.Dispose();trace=null;TraceStatus="ETW unavailable · TCP sampling continues: "+e.Message;Gap?.Invoke(TraceStatus);}
    }
    static readonly Guid DnsProvider=new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    static string Field(TraceEvent e,string field)
    {
        var index=Array.FindIndex(e.PayloadNames,n=>n.Equals(field,StringComparison.OrdinalIgnoreCase));
        return index<0?"":e.PayloadValue(index)?.ToString()??"";
    }
    void OnTransfer(TraceEvent e,string protocol,string direction)
    {
        if(disposed||Gaming)return;
        var sent=direction=="Send";var source=Field(e,"saddr");var destination=Field(e,"daddr");
        if(!int.TryParse(Field(e,"sport"),out var sourcePort)||!int.TryParse(Field(e,"dport"),out var destinationPort))return;
        if(!long.TryParse(Field(e,"size"),out var bytes))return;
        var t=new Transfer(e.ProcessID,protocol,direction,sent?source:destination,sent?sourcePort:destinationPort,sent?destination:source,sent?destinationPort:sourcePort);
        var key=$"{t.Pid}|{protocol}|{direction}|{t.LocalIp}|{t.LocalPort}|{t.RemoteIp}|{t.RemotePort}";
        lock(gate)
        {
            if(!transfers.TryGetValue(key,out var old))
            {
                if(transfers.Count>=5000){if(!transferOverflow){transferOverflow=true;Gap?.Invoke("ETW aggregation limit reached; some network transfers were omitted.");}return;}
                old=t;old.Identity=EndpointData(t.Pid,t.LocalIp,t.LocalPort,t.RemoteIp,t.RemotePort);transfers[key]=old;
            }
            old.Bytes+=bytes;old.Packets++;old.At=new DateTimeOffset(e.TimeStamp.ToUniversalTime());
        }
    }
    bool transferOverflow;
    volatile bool replay;
    public void ReplaySnapshot()=>replay=true;
    public void Poll()
    {
        lock(sampling)PollCore();
    }
    void PollCore()
    {
        if(disposed)return;
        var now=DateTimeOffset.UtcNow;
        var refreshAll=replay;replay=false;
        var priorDomains=domains;
        if(refreshAll||(now-lastDns).TotalSeconds>=(Gaming?15:3))
        {
            lastDns=now;
            try
            {
                var current=ReadDnsCache().ToHashSet();
                // Cache entries have no originating process or trustworthy query timestamp.
                foreach(var entry in refreshAll?current:current.Except(cached))Recorded?.Invoke(Create(CacheEvent,new(){{"Image","Unknown (DNS cache)"},{"QueryName",entry.Name},{"QueryResults",entry.Address},{"Source","DNS cache (first observed)"},{"Direction","Cached answer"},{"Attribution","Machine cache; originating process and query time unknown"}},now));
                cached=current;domains=current.GroupBy(d=>d.Address).ToDictionary(g=>g.Key,g=>string.Join(", ",g.Select(d=>d.Name).Distinct().Take(4)));
                DnsStatus=$"DNS cache · {current.Count:N0} address/name records";
            }
            catch(Exception e){DnsStatus="DNS cache unavailable: "+e.Message;Gap?.Invoke(DnsStatus);}
        }
        try
        {
            var current=ReadTcpConnections().Where(c=>c.State!=TcpState.Listen&&c.RemotePort!=0).ToDictionary(c=>c.Key);
            foreach(var c in current.Values)
                if(refreshAll||!previous.TryGetValue(c.Key,out var old)||old.State!=c.State||priorDomains.GetValueOrDefault(c.RemoteIp,"")!=domains.GetValueOrDefault(c.RemoteIp,""))EmitConnection(c,previous.ContainsKey(c.Key)&&!refreshAll?"Connection updated":"Connection observed",now);
            foreach(var c in previous.Values.Where(c=>!current.ContainsKey(c.Key)))EmitConnection(c,"No longer in TCP table",now);
            previous=current;TcpStatus=$"TCP IPv4/IPv6 · {current.Count:N0} connections · {(Gaming?5:1)}s refresh";LastPoll=now;
        }
        catch(Exception e){TcpStatus="TCP monitor unavailable: "+e.Message;Gap?.Invoke(TcpStatus);}
        List<Transfer> batch;
        lock(gate){batch=transfers.Values.ToList();transfers.Clear();transferOverflow=false;}
        foreach(var t in batch)
        {
            var data=t.Identity;
            data["Protocol"]=t.Protocol;data["Direction"]=t.Direction;data["Bytes"]=t.Bytes.ToString();data["Packets"]=t.Packets.ToString();data["Source"]="Network ETW";
            Recorded?.Invoke(Create(TransferEvent,data,t.At));
        }
        try{if(trace?.EventsLost>0)Gap?.Invoke("ETW reports lost events; network totals are incomplete.");}
        catch(Exception e){Gap?.Invoke("Could not check ETW loss counters: "+e.Message);}
    }
    void EmitConnection(TcpConnection c,string change,DateTimeOffset at)
    {
        var closed=change=="No longer in TCP table";
        var data=closed&&connectionOwners.TryGetValue(c.Key,out var owner)?new Dictionary<string,string>(owner):EndpointData(c.Pid,c.LocalIp,c.LocalPort,c.RemoteIp,c.RemotePort);
        if(closed)connectionOwners.Remove(c.Key);else connectionOwners[c.Key]=new(data);
        data["Protocol"]="TCP";data["State"]=change=="No longer in TCP table"?"Closed / no longer observed":c.State.ToString();data["Change"]=change;
        data["Direction"]="Connection";data["Source"]="TCP table sample";
        Recorded?.Invoke(Create(ConnectionEvent,data,at));
    }
    Dictionary<string,string> EndpointData(int pid,string localIp,int localPort,string remoteIp,int remotePort)
    {
        var data=new Dictionary<string,string>(){
        {"Image",ProcessName(pid)},{"ProcessId",pid.ToString()},{"LocalIp",localIp},{"LocalPort",localPort.ToString()},
        {"RemoteIp",remoteIp},{"RemotePort",remotePort.ToString()},{"DomainCandidate",domains.GetValueOrDefault(remoteIp,"")},
        {"DomainAttribution","IP matched to current machine DNS cache; names may be shared and are not process-attributed"}
        };
        if(pid>0)try{using var p=Process.GetProcessById(pid);data["ProcessStartTime"]=p.StartTime.ToUniversalTime().ToString("O");data["Image"]=p.MainModule?.FileName??data["Image"];}catch(Exception e)when(e is Win32Exception or InvalidOperationException or ArgumentException or NotSupportedException){}
        return data;
    }
    string ProcessName(int pid)
    {
        if(pid<=0)return "Unattributed (TCP owner unavailable)";
        lock(names)
        {
            if(names.TryGetValue(pid,out var old)&&(DateTimeOffset.UtcNow-old.At).TotalSeconds<10)return old.Name;
            var name=$"PID {pid}";try{using var p=Process.GetProcessById(pid);name=p.ProcessName+".exe";}catch(ArgumentException){}catch(Win32Exception){}
            if(names.Count>4096)names.Clear();names[pid]=(name,DateTimeOffset.UtcNow);return name;
        }
    }
    EvidenceEvent Create(int kind,Dictionary<string,string> data,DateTimeOffset at)
    {
        if(DateTimeOffset.TryParse(data.GetValueOrDefault("ProcessStartTime"),out var born)&&born>at.AddMilliseconds(10))
        {data["Image"]="Unattributed (PID reused before identity lookup)";data["ProcessId"]="0";data.Remove("ProcessStartTime");data["Attribution"]="The current PID belongs to a process created after this event. It is not the event's owner.";}
        var n=Interlocked.Increment(ref sequence);return new($"network:{Environment.ProcessId}:{n}:{at:O}","Observe/LiveNetwork",n,kind,at,data);
    }
    public static List<DnsCacheRecord> ReadDnsCache()
    {
        using var query=new ManagementObjectSearcher(new ManagementScope(@"root\StandardCimv2"),new ObjectQuery("SELECT Entry, Data, Type FROM MSFT_DNSClientCache"),new System.Management.EnumerationOptions{Timeout=TimeSpan.FromSeconds(2)});
        using var result=query.Get();var list=new List<DnsCacheRecord>();
        foreach(ManagementObject row in result)
        {
            using(row)
            {
                var name=row["Entry"]?.ToString();var address=row["Data"]?.ToString();
                if(!string.IsNullOrWhiteSpace(name)&&IPAddress.TryParse(address,out var ip))list.Add(new(name,ip.ToString()));
            }
        }
        return list;
    }
    [DllImport("iphlpapi.dll",SetLastError=true)] static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
    public static List<TcpConnection> ReadTcpConnections()
    {
        var result=new List<TcpConnection>();
        foreach(var family in new[]{2,23})
        {
            var size=0;var code=GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,5,0);
            if(code!=0&&code!=122)throw new Win32Exception((int)code);
            for(var attempt=0;attempt<4;attempt++)
            {
                var capacity=size;var buffer=Marshal.AllocHGlobal(capacity);
                try
                {
                    code=GetExtendedTcpTable(buffer,ref size,false,family,5,0);
                    if(code==122)continue;
                    if(code!=0)throw new Win32Exception((int)code);
                    var count=Marshal.ReadInt32(buffer);var rowSize=family==2?24:56;
                    if(count<0||4L+count*(long)rowSize>capacity)throw new InvalidDataException("Invalid TCP table size.");
                    for(var i=0;i<count;i++)
                    {
                        var row=IntPtr.Add(buffer,4+i*rowSize);
                        int Port(int offset)=>(Marshal.ReadByte(row,offset)<<8)|Marshal.ReadByte(row,offset+1);
                        string Ip(int offset,int length,long scope=0){var bytes=new byte[length];Marshal.Copy(IntPtr.Add(row,offset),bytes,0,length);return length==16?new IPAddress(bytes,scope).ToString():new IPAddress(bytes).ToString();}
                        result.Add(family==2
                            ?new(Marshal.ReadInt32(row,20),Ip(4,4),Port(8),Ip(12,4),Port(16),(TcpState)Marshal.ReadInt32(row,0))
                            :new(Marshal.ReadInt32(row,52),Ip(0,16,(uint)Marshal.ReadInt32(row,16)),Port(20),Ip(24,16,(uint)Marshal.ReadInt32(row,40)),Port(44),(TcpState)Marshal.ReadInt32(row,48)));
                    }
                    break;
                }
                finally{Marshal.FreeHGlobal(buffer);}
            }
            if(code==122)throw new IOException("TCP table kept changing; retry on the next refresh.");
        }
        return result;
    }
    public void Dispose()
    {
        lock(sampling){disposed=true;trace?.Dispose();trace=null;}
        // StopOnDispose closes only this uniquely named trace, never another tool's session.
    }
}
