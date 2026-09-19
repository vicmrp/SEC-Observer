using System.Diagnostics;

namespace Observe;

public sealed class ProcessMonitor
{
    public const int Existing=10101,Appeared=10102,Disappeared=10103;
    Dictionary<int,(string Image,string Started)> previous=[];
    bool initialized;
    long sequence;
    DateTimeOffset last;
    public event Action<EvidenceEvent>? Recorded;
    public void Poll()
    {
        var now=DateTimeOffset.UtcNow;if((now-last).TotalSeconds<3)return;last=now;
        var current=new Dictionary<int,(string Image,string Started)>();
        foreach(var process in Process.GetProcesses())using(process)
        {
            try
            {
                var pid=process.Id;var image=process.ProcessName;var started="";
                try{started=process.StartTime.ToUniversalTime().ToString("O");}catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException){}
                if(previous.TryGetValue(pid,out var prior)&&prior.Started==started)image=prior.Image;
                else try{image=process.MainModule?.FileName??image;}catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException){}
                current[pid]=(image,started);
                if(!previous.TryGetValue(pid,out prior)||prior.Started!=started)
                {
                    if(initialized&&previous.ContainsKey(pid))Emit(Disappeared,pid,prior,now);
                    Emit(initialized?Appeared:Existing,pid,(image,started),now);
                }
            }
            catch(Exception e)when(e is System.ComponentModel.Win32Exception or InvalidOperationException){}
        }
        foreach(var (pid,process) in previous)if(!current.ContainsKey(pid))Emit(Disappeared,pid,process,now);
        previous=current;initialized=true;
    }
    void Emit(int kind,int pid,(string Image,string Started) process,DateTimeOffset at)
    {
        var n=Interlocked.Increment(ref sequence);
        Recorded?.Invoke(new($"process-sample:{Environment.ProcessId}:{n}:{at:O}","Observe/Processes",n,kind,at,new()
        {
            {"Image",process.Image},{"ProcessId",pid.ToString()},{"ProcessStartTime",process.Started},{"Source","Windows process snapshot (sampled every 3 seconds)"},
            {"Observation",kind==Existing?"Already running when Observe started sampling":kind==Appeared?"Appeared between process samples":"No longer present in the process snapshot"},
            {"Attribution","Sample observation time is not an exact start/exit time. Short-lived processes can be missed. This record does not establish file or registry activity."}
        }));
    }
}
public static class ActivityRetention
{
    public static bool IsScript(EvidenceEvent e)=>e.EventId is 4103 or 4104 or 24577;
    public static bool IsProcess(EvidenceEvent e)=>e.EventId is 1 or 5 or 10104 or ProcessMonitor.Existing or ProcessMonitor.Appeared or ProcessMonitor.Disappeared;
    static string Category(EvidenceEvent e)=>e.EventId==4103?"modules":IsScript(e)?"scripts":IsProcess(e)?"process":e.IsNetwork?"network":"other";
    public static void Add(List<EvidenceEvent> events,HashSet<string> ids,EvidenceEvent e)
    {
        if(!ids.Add(e.Id))return;events.Add(e);var category=Category(e);var max=category switch{"network"=>1200,"scripts"=>200,"modules"=>150,"process"=>350,_=>100};
        var group=events.Where(x=>Category(x)==category).OrderBy(x=>x.Timestamp).ToArray();
        foreach(var old in group.Take(Math.Max(0,group.Length-max))){events.Remove(old);ids.Remove(old.Id);}
    }
    public static object[] Rows(IEnumerable<EvidenceEvent> events,string category="")=>events.Where(e=>category switch{"scripts"=>IsScript(e),"process"=>IsProcess(e),"network"=>e.IsNetwork,_=>true}).OrderByDescending(e=>e.Timestamp).Take(250).Select(e=>(object)new{e.Id,e.Timestamp,e.Kind,e.Process,e.Detail,e.EventId,e.Channel}).ToArray();
}
