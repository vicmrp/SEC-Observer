using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Observe;

public sealed class TrackedRun
{
    public string Id {get;set;}=Guid.NewGuid().ToString();
    public string Name {get;set;}="";
    public string Path {get;set;}="";
    public string Arguments {get;set;}="";
    public string Sha256 {get;set;}="";
    public int RootPid {get;set;}
    public DateTimeOffset Started {get;set;}=DateTimeOffset.UtcNow;
    public DateTimeOffset? Ended {get;set;}
    public string Status {get;set;}="recording";
    public DateTimeOffset? AttachedAt {get;set;}
    public List<EvidenceEvent> Events {get;set;}=[];
    public List<string> Warnings {get;set;}=[];
}
public sealed class TrackedProcess
{
    public int Pid {get;set;} public int ParentPid {get;set;}
    public string Image {get;set;}="";public DateTimeOffset Started {get;set;}public DateTimeOffset? Ended {get;set;}
    public HashSet<string> Guids {get;set;}=[];
}
public sealed record TrackedEvidence(TrackedProcess[] Processes,EvidenceEvent[] Events,Finding[] Findings);
public static class TrackedCorrelation
{
    public static TrackedEvidence Read(TrackedRun run)
    {
        var root=new TrackedProcess{Pid=run.RootPid,Image=run.Path,Started=run.Started};var nodes=new List<TrackedProcess>{root};
        var active=new Dictionary<int,TrackedProcess>{{root.Pid,root}};var byGuid=new Dictionary<string,TrackedProcess>(StringComparer.OrdinalIgnoreCase);var matched=new List<EvidenceEvent>();
        bool Alive(TrackedProcess p,DateTimeOffset at)=>at>=p.Started.AddMilliseconds(-250)&&(p.Ended is null||at<=p.Ended);
        bool SameImage(string a,string b)=>System.IO.Path.GetFileName(a).Equals(System.IO.Path.GetFileName(b),StringComparison.OrdinalIgnoreCase);
        foreach(var e in run.Events.OrderBy(e=>e.Timestamp).ThenBy(e=>e.EventId==1?0:1))
        {
            if(e.Timestamp<run.Started.AddMilliseconds(-250)||run.Ended is {} end&&e.Timestamp>end)continue;
            var d=e.Data;var sourceOperation=e.EventId is 8 or 10;
            if(!int.TryParse(d.GetValueOrDefault(sourceOperation?"SourceProcessId":"ProcessId"),out var pid))continue;
            var guid=sourceOperation?d.GetValueOrDefault("SourceProcessGUID",d.GetValueOrDefault("SourceProcessGuid","")):d.GetValueOrDefault("ProcessGuid","");
            var image=d.GetValueOrDefault(sourceOperation?"SourceImage":"Image","");TrackedProcess? node=null;
            if(e.EventId==1)
            {
                var isTrace=e.Channel=="Observe/ProcessTrace";
                var eventBirth=DateTimeOffset.TryParse(d.GetValueOrDefault("ProcessStartTime"),out var traceBirth)?traceBirth:e.Timestamp;
                // WMI TIME_CREATED is delivery time, not process creation time. Old recordings lack the birth field.
                if(active.TryGetValue(pid,out var known)&&SameImage(known.Image,image)&&
                    (Math.Abs((known.Started-eventBirth).TotalMilliseconds)<=250||isTrace&&!d.ContainsKey("ProcessStartTime")&&e.Timestamp>=known.Started&&e.Timestamp<=known.Started.AddSeconds(10)))node=known;
                else
                {
                    active.Remove(pid); // An unrelated launch must bound a previously tracked PID.
                    var parentGuid=d.GetValueOrDefault("ParentProcessGuid","");int.TryParse(d.GetValueOrDefault("ParentProcessId"),out var parentPid);
                    var parent=parentGuid.Length>0?byGuid.GetValueOrDefault(parentGuid):active.GetValueOrDefault(parentPid);
                    if(parent is not null&&Alive(parent,eventBirth)){node=new(){Pid=pid,ParentPid=parent.Pid,Image=image,Started=eventBirth};nodes.Add(node);active[pid]=node;}
                }
                if(node is not null&&guid.Length>0){node.Guids.Add(guid);byGuid[guid]=node;}
            }
            else node=guid.Length>0?byGuid.GetValueOrDefault(guid):active.GetValueOrDefault(pid);
            if(node is null||!Alive(node,e.Timestamp))continue;
            // Sampled IP traffic carries the queried process start time when available, preventing PID-reuse attribution.
            if(d.TryGetValue("ProcessStartTime",out var birth)&&DateTimeOffset.TryParse(birth,out var started)&&Math.Abs((started-node.Started).TotalSeconds)>1)continue;
            if(guid.Length==0&&image.Length>0&&!SameImage(image,node.Image))continue;
            matched.Add(e);
            if(e.EventId==5){node.Ended=e.Timestamp;active.Remove(pid);}
        }
        var findings=Evidence.Detect(matched);
        foreach(var e in matched.Where(e=>e.EventId==1&&new[]{"powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe"}.Contains(e.Process,StringComparer.OrdinalIgnoreCase)))
            findings.Add(new("review","A child process can run commands or scripts",e.Process+" was launched in the tracked tree. Installers may do this legitimately; inspect its command line and subsequent changes.",[e.Id],"Review the recorded command and whether the game or mod needs it."));
        return new(nodes.ToArray(),matched.ToArray(),findings.ToArray());
    }
}
// Parent IDs and creation times also work without administrative event-log access.
// This fallback is sampled: brief children and precise exit times can be missed.
public sealed class LaunchProcessSampler
{
    Dictionary<int,(DateTimeOffset Started,string Image,int Parent)> previous=[];long sequence;
    public void Reset()=>previous=[];
    public IEnumerable<EvidenceEvent> Poll()
    {
        var result=new List<EvidenceEvent>();var current=new Dictionary<int,(DateTimeOffset Started,string Image,int Parent)>();var at=DateTimeOffset.UtcNow;
        var snapshot=CreateToolhelp32Snapshot(2,0);if(snapshot==new IntPtr(-1))return result;
        try
        {
            var entry=new ProcessEntry{Size=(uint)Marshal.SizeOf<ProcessEntry>()};
            if(Process32FirstW(snapshot,ref entry))do
            {
                var pid=(int)entry.Pid;try
                {
                    using var p=Process.GetProcessById(pid);var born=new DateTimeOffset(p.StartTime.ToUniversalTime());var image=entry.Name;
                    if(previous.TryGetValue(pid,out var old)&&old.Started==born)image=old.Image;
                    else try{image=p.MainModule?.FileName??image;}catch(Win32Exception){}
                    var value=(born,image,(int)entry.ParentPid);current[pid]=value;
                    if(!previous.TryGetValue(pid,out old)||old.Started!=born)Emit(1,pid,value,born);
                }
                catch(Exception e)when(e is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException){}
            }while(Process32NextW(snapshot,ref entry));
        }
        finally{CloseHandle(snapshot);}
        foreach(var (pid,value) in previous)if(!current.TryGetValue(pid,out var now)||now.Started!=value.Started)Emit(5,pid,value,at);
        previous=current;return result;
        void Emit(int id,int pid,(DateTimeOffset Started,string Image,int Parent) value,DateTimeOffset time)
        {
            var n=++sequence;result.Add(new($"launch-sample:{Environment.ProcessId}:{n}","Observe/LaunchSamples",n,id,time,new(){{"ProcessId",pid.ToString()},{"ParentProcessId",value.Parent.ToString()},{"Image",value.Image},{"ProcessStartTime",value.Started.ToString("O")},{"Source","Process ancestry snapshot (sampled)"},{"Observation",id==1?"Process creation time and parent from a live sample; brief children may be missed":"Process disappeared between samples; exit time is approximate"}}));
        }
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct ProcessEntry{public uint Size,Usage,Pid;public UIntPtr Heap;public uint Module,Threads,ParentPid;public int Priority;public uint Flags;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string Name;}
    [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32FirstW(IntPtr snapshot,ref ProcessEntry entry);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32NextW(IntPtr snapshot,ref ProcessEntry entry);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
}

// Launch as the desktop user even when Observe was elevated to read Sysmon.
public sealed class ObservedProcess:IDisposable
{
    IntPtr process,thread;bool resumed;
    public int Pid{get;private set;}public DateTimeOffset Started{get;private set;}
    public static ObservedProcess Create(string path,string arguments)
    {
        var si=new StartupInfo{Size=Marshal.SizeOf<StartupInfo>()};ProcessInfo pi;var command=new StringBuilder('"'+path+'"'+(arguments.Length>0?" "+arguments:""));
        if(SensorSetup.IsAdministrator)
        {
            var shell=GetShellWindow();GetWindowThreadProcessId(shell,out var pid);if(pid==0)throw new InvalidOperationException("No ordinary Windows desktop session is available for launching this app.");
            using var shellProcess=Process.GetProcessById((int)pid);
            if(!OpenProcessToken(shellProcess.Handle,0x0002|0x0008|0x0001,out var token))throw new Win32Exception();
            using(token)
            {
                if(!DuplicateTokenEx(token,0x02000000,IntPtr.Zero,2,1,out var primary))throw new Win32Exception();
                using(primary)if(!CreateProcessWithTokenW(primary,0,path,command,4,IntPtr.Zero,System.IO.Path.GetDirectoryName(path)!,ref si,out pi))throw new Win32Exception();
            }
        }
        else if(!CreateProcessW(path,command,IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,System.IO.Path.GetDirectoryName(path)!,ref si,out pi))throw new Win32Exception();
        var result=new ObservedProcess{process=pi.Process,thread=pi.Thread,Pid=(int)pi.ProcessId};
        if(GetProcessTimes(pi.Process,out var created,out _,out _,out _))result.Started=new DateTimeOffset(DateTime.FromFileTimeUtc(created));else result.Started=DateTimeOffset.UtcNow;
        return result;
    }
    public void Resume(){if(ResumeThread(thread)==uint.MaxValue)throw new Win32Exception();resumed=true;}
    public void Dispose(){if(process!=IntPtr.Zero){if(!resumed)TerminateProcess(process,1);CloseHandle(process);process=IntPtr.Zero;}if(thread!=IntPtr.Zero){CloseHandle(thread);thread=IntPtr.Zero;}}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct StartupInfo{public int Size;public string? Reserved,Desktop,Title;public int X,Y,XSize,YSize,XCount,YCount,Fill,Flags;public short Show,Reserved2;public IntPtr ReservedPtr,Input,Output,Error;}
    [StructLayout(LayoutKind.Sequential)]struct ProcessInfo{public IntPtr Process,Thread;public uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcessW(string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfo si,out ProcessInfo pi);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token,uint logon,string app,StringBuilder command,uint flags,IntPtr environment,string directory,ref StartupInfo si,out ProcessInfo pi);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle token);
    [DllImport("user32.dll")]static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")]static extern bool GetProcessTimes(IntPtr process,out long created,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll")]static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
}
