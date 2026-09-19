using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Observe;

public sealed class AppEntry
{
    public string Id {get;set;}="";
    public string Path {get;set;}="";
    public string Name {get;set;}="";
    public DateTimeOffset FirstSeen {get;set;}
    public DateTimeOffset LastSeen {get;set;}
    public bool Watch {get;set;}
    public HashSet<string> TrackedInstances {get;set;}=[];
}
public sealed class AppCatalog
{
    readonly object gate=new();readonly string path;Dictionary<string,AppEntry> apps=[];bool dirty;
    public AppCatalog(string root){path=System.IO.Path.Combine(root,"known-apps.json");if(File.Exists(path))try{apps=(JsonSerializer.Deserialize<AppEntry[]>(File.ReadAllText(path),Evidence.Json)??[]).ToDictionary(a=>a.Id);}catch(JsonException){} }
    public static string Identity(string path)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path.ToUpperInvariant())))[..24];
    public void Observe(IEnumerable<EvidenceEvent> events)
    {
        lock(gate)foreach(var e in events)
        {
            var image=e.Data.GetValueOrDefault("Image","");if(!System.IO.Path.IsPathFullyQualified(image)||!image.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))continue;
            var id=Identity(image);if(!apps.TryGetValue(id,out var app))apps[id]=app=new(){Id=id,Path=image,Name=System.IO.Path.GetFileNameWithoutExtension(image),FirstSeen=e.Timestamp,LastSeen=e.Timestamp};
            if(e.Timestamp<app.FirstSeen)app.FirstSeen=e.Timestamp;if(e.Timestamp>app.LastSeen)app.LastSeen=e.Timestamp;dirty=true;
        }
    }
    public AppEntry[] All(){lock(gate)return apps.Values.OrderByDescending(a=>a.LastSeen).Select(a=>JsonSerializer.Deserialize<AppEntry>(JsonSerializer.Serialize(a,Evidence.Json),Evidence.Json)!).ToArray();}
    public void Watch(string id,bool enabled){lock(gate){if(!apps.TryGetValue(id,out var app))throw new ArgumentException("Select a known app.");app.Watch=enabled;if(enabled)app.TrackedInstances.Clear();dirty=true;Save();}}
    public bool Claim(string path,string instance){lock(gate){var id=Identity(path);if(!apps.TryGetValue(id,out var app)||!app.Watch||!app.TrackedInstances.Add(instance))return false;dirty=true;Save();return true;}}
    public void Unclaim(string path,string instance){lock(gate){if(apps.TryGetValue(Identity(path),out var app)){app.TrackedInstances.Remove(instance);dirty=true;Save();}}}
    public void Save(){lock(gate){if(!dirty)return;Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);File.WriteAllText(path+".tmp",JsonSerializer.Serialize(apps.Values,Evidence.Json));File.Move(path+".tmp",path,true);dirty=false;}}
    public void Clear(){lock(gate){apps.Clear();dirty=true;Save();}}
}

public sealed record ProcessRow(int Pid,int ParentPid,string Name,string Image,string Description,string Company,string CommandLine,DateTimeOffset? Started,string Group,string Status,double? Cpu,long? Memory,long? PrivateBytes,long? IoRead,long? IoWrite,int? Threads,int? Handles,int? Session,string Priority,string Icon);
public sealed record ProcessSnapshot(DateTimeOffset At,ProcessRow[] Processes,double Cpu,long MemoryTotal,long MemoryUsed,bool Saved,string[] Warnings);
public sealed class ProcessInspector
{
    readonly string saved;
    public ProcessInspector(string root)=>saved=Path.Combine(root,"process-snapshot.json");
    public ProcessSnapshot? Saved(){try{return File.Exists(saved)?(JsonSerializer.Deserialize<ProcessSnapshot>(File.ReadAllText(saved),Evidence.Json)??throw new JsonException()) with {Saved=true}:null;}catch(JsonException){return null;}}
    public async Task<ProcessSnapshot> Capture(CancellationToken token=default)
    {
        var metadata=new Dictionary<int,(int Parent,string Command,string Path)>();var warnings=new List<string>();
        try{using var search=new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,CommandLine,ExecutablePath FROM Win32_Process");using var found=search.Get();foreach(ManagementObject p in found)using(p)metadata[Convert.ToInt32(p["ProcessId"])]=(Convert.ToInt32(p["ParentProcessId"]),p["CommandLine"]?.ToString()??"",p["ExecutablePath"]?.ToString()??"");}catch(Exception e){warnings.Add("Some process metadata is unavailable: "+e.Message);}
        var first=new Dictionary<int,(long Cpu,long Read,long Write,DateTime Born,long At)>();
        foreach(var p in Process.GetProcesses())using(p)try{Io(p,out var io);first[p.Id]=(p.TotalProcessorTime.Ticks,(long)io.Read,(long)io.Write,p.StartTime.ToUniversalTime(),Stopwatch.GetTimestamp());}catch(Exception e)when(e is Win32Exception or InvalidOperationException or NotSupportedException){}
        await Task.Delay(250,token);var rows=new List<ProcessRow>();
        foreach(var p in Process.GetProcesses())using(p)
        {
            try
            {
                var pid=p.Id;var name=p.ProcessName;var m=metadata.GetValueOrDefault(pid);var image=m.Path??"";DateTimeOffset? born=null;double? cpu=null;double sampleSeconds=1;long? read=null,write=null,working=null,priv=null;int? threads=null,handles=null,session=null;var priority="Unavailable";var status="Running";var group="Background processes";
                try{born=new(p.StartTime.ToUniversalTime());if(first.TryGetValue(pid,out var before)&&before.Born==born.Value.UtcDateTime){sampleSeconds=Math.Max(.001,Stopwatch.GetElapsedTime(before.At).TotalSeconds);cpu=pid==0?0:Math.Clamp((p.TotalProcessorTime.Ticks-before.Cpu)/(sampleSeconds*TimeSpan.TicksPerSecond*Environment.ProcessorCount)*100,0,100);if(Io(p,out var io)){read=Math.Max(0,(long)io.Read-before.Read);write=Math.Max(0,(long)io.Write-before.Write);}}}catch(Win32Exception){}
                try{working=p.WorkingSet64;priv=p.PrivateMemorySize64;threads=p.Threads.Count;handles=p.HandleCount;session=p.SessionId;priority=p.PriorityClass.ToString();if(p.MainWindowHandle!=IntPtr.Zero)group="Apps";if(!p.Responding)status="Not responding";if(session==0||pid<=4)group="Windows processes";}catch(Win32Exception){status="Limited access";}
                if(image.Length==0)try{image=p.MainModule?.FileName??"";}catch(Exception e)when(e is Win32Exception or NotSupportedException){}
                var description="";var company="";try{if(File.Exists(image)){var v=FileVersionInfo.GetVersionInfo(image);description=v.FileDescription??"";company=v.CompanyName??"";}}catch(Exception e)when(e is IOException or Win32Exception){}
                rows.Add(new(pid,m.Parent,name,image,description,company,m.Command??"",born,group,status,cpu,working,priv,read is null?null:(long)(read/sampleSeconds),write is null?null:(long)(write/sampleSeconds),threads,handles,session,priority,AppIcons.Get(image)));
            }
            catch(Exception e)when(e is Win32Exception or InvalidOperationException or NotSupportedException){}
        }
        var memory=new MemoryStatus{Length=(uint)Marshal.SizeOf<MemoryStatus>()};GlobalMemoryStatusEx(ref memory);
        warnings.Add("CPU and process I/O rates are sampled on Refresh. I/O includes file, device and other process I/O; it is not a disk-only measurement. Inaccessible values are shown as unavailable.");
        var snapshot=new ProcessSnapshot(DateTimeOffset.UtcNow,rows.OrderBy(p=>p.Group).ThenBy(p=>p.Name).ToArray(),rows.Sum(p=>p.Cpu??0),(long)memory.TotalPhys,(long)(memory.TotalPhys-memory.AvailPhys),false,warnings.ToArray());
        Directory.CreateDirectory(Path.GetDirectoryName(saved)!);File.WriteAllText(saved+".tmp",JsonSerializer.Serialize(snapshot,Evidence.Json));File.Move(saved+".tmp",saved,true);return snapshot;
    }
    public static object Details(int pid,string expectedStart)
    {
        using var p=Process.GetProcessById(pid);var born=p.StartTime.ToUniversalTime();if(!DateTimeOffset.TryParse(expectedStart,out var expected)||Math.Abs((born-expected.UtcDateTime).TotalMilliseconds)>1)throw new InvalidOperationException("This process exited or its PID was reused. Refresh Processes.");
        var warnings=new List<string>();var modules=new List<object>();var threads=new List<object>();var services=new List<object>();string owner="Unavailable",path="",architecture="Unknown";
        try{path=p.MainModule?.FileName??"";foreach(ProcessModule m in p.Modules)modules.Add(new{name=m.ModuleName,path=m.FileName,baseAddress="0x"+m.BaseAddress.ToInt64().ToString("X"),bytes=m.ModuleMemorySize,description=m.FileVersionInfo.FileDescription,company=m.FileVersionInfo.CompanyName,version=m.FileVersionInfo.FileVersion});}catch(Exception e)when(e is Win32Exception or InvalidOperationException or NotSupportedException){warnings.Add("Modules: "+e.Message);}
        try{foreach(ProcessThread t in p.Threads)using(t){try{threads.Add(new{id=t.Id,state=t.ThreadState.ToString(),wait=t.ThreadState==System.Diagnostics.ThreadState.Wait?t.WaitReason.ToString():"",cpuSeconds=t.TotalProcessorTime.TotalSeconds,priority=t.CurrentPriority,started=t.StartTime});}catch(Win32Exception){threads.Add(new{id=t.Id,state="Limited access"});}}}catch(Exception e)when(e is Win32Exception or InvalidOperationException){warnings.Add("Threads: "+e.Message);}
        try{using var mo=new ManagementObject("Win32_Process.Handle='"+pid+"'");var args=new string[2];if(Convert.ToUInt32(mo.InvokeMethod("GetOwner",args))==0)owner=args[1]+"\\"+args[0];using var search=new ManagementObjectSearcher("SELECT Name,DisplayName,State,StartMode FROM Win32_Service WHERE ProcessId="+pid);using var found=search.Get();foreach(ManagementObject s in found)using(s)services.Add(new{name=s["Name"],displayName=s["DisplayName"],state=s["State"],startMode=s["StartMode"]});}catch(Exception e){warnings.Add("Owner/services: "+e.Message);}
        try{if(IsWow64Process2(p.Handle,out var machine,out var native))architecture=(machine==0?native:machine) switch{0x8664=>"x64",0x14c=>"x86",0xaa64=>"ARM64",_=>"Unknown"};}catch(Win32Exception){}
        string hash="",signature="Unavailable";if(File.Exists(path)){try{using var file=File.OpenRead(path);hash=Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();signature=FileSignature.Verify(path);}catch(Exception e){warnings.Add("File identity: "+e.Message);}}
        return new{pid,started=born,owner,architecture,path,sha256=hash,signature,modules,threads,services,warnings,handleNote="Handle count is shown in Processes. Protected kernel handles and full security-token inspection require facilities not available to this user-mode view."};
    }
    static bool Io(Process p,out IoCounters io)=>GetProcessIoCounters(p.Handle,out io);
    [StructLayout(LayoutKind.Sequential)]struct IoCounters{public ulong ReadOperations,WriteOperations,OtherOperations,Read,Write,Other;}
    [StructLayout(LayoutKind.Sequential)]struct MemoryStatus{public uint Length,Load;public ulong TotalPhys,AvailPhys,TotalPage,AvailPage,TotalVirtual,AvailVirtual,AvailExtended;}
    [DllImport("kernel32.dll")]static extern bool GetProcessIoCounters(IntPtr process,out IoCounters counters);
    [DllImport("kernel32.dll")]static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
    [DllImport("kernel32.dll")]static extern bool IsWow64Process2(IntPtr process,out ushort machine,out ushort native);
}

internal static class FileSignature
{
    // Offline, cache-only Authenticode trust verification: opening a process detail does not contact a certificate server.
    public static string Verify(string path)
    {
        var file=new TrustFile{Size=(uint)Marshal.SizeOf<TrustFile>(),Path=path};var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());Marshal.StructureToPtr(file,pointer,false);
        try{var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),Ui=2,UnionChoice=1,File=pointer,Flags=0x1000};var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");var result=WinVerifyTrust(new IntPtr(-1),ref action,ref data);return result==0?"Valid Authenticode signature (offline Windows trust check)":$"Signature not verified (Windows status 0x{result:X8}; unsigned, untrusted or unavailable offline)";}
        finally{Marshal.DestroyStructure<TrustFile>(pointer);Marshal.FreeHGlobal(pointer);}
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct TrustFile{public uint Size;[MarshalAs(UnmanagedType.LPWStr)]public string Path;public IntPtr Handle,Subject;}
    [StructLayout(LayoutKind.Sequential)]struct TrustData{public uint Size;public IntPtr Policy,Sip;public uint Ui,Revocation,UnionChoice;public IntPtr File;public uint Action;public IntPtr State,Url;public uint Flags,Context;public IntPtr Signature;}
    [DllImport("wintrust.dll",ExactSpelling=true)]static extern uint WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
}
