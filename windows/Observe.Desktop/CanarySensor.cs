using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Observe;

// Short, opt-in Windows trace. Only the one synthetic canary path is retained.
// This does not install a driver or change Sysmon/audit policy.
public static class CanarySensor
{
    public static async Task<int> Run(string id)
    {
        id=CanaryLab.ValidateId(id);var root=CanaryLab.DefaultRoot;
        var lab=new CanaryLab(Path.GetDirectoryName(root)!);var run=lab.Get(id);
        var status=lab.FilePath(id,".sensor.json");
        var sessionName="Observe-Canary-"+id;
        void State(string state,string message,long lost=0)=>CanaryLab.Write(status,new{state,message,at=DateTimeOffset.UtcNow,eventsLost=lost,sessionName});
        try
        {
            if(!SensorSetup.IsAdministrator)throw new InvalidOperationException("Administrator access is required for the Windows file-read sensor.");
            if(run.CanaryPath!=CanaryLab.Target(CanaryLab.DefaultDocuments,id)||run.Started>DateTimeOffset.UtcNow||run.Expires<=DateTimeOffset.UtcNow||run.Expires>DateTimeOffset.UtcNow.AddMinutes(21))throw new InvalidDataException("Canary test is expired or invalid.");
            CanaryLab.NoLinks(run.CanaryPath);CanaryLab.NoLinks(root);
            var eventPath=lab.FilePath(id,".events.ndjson");CanaryLab.NoLinks(eventPath);
            using var output=new StreamWriter(new FileStream(eventPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read),new UTF8Encoding(false)){AutoFlush=true};
            using var trace=new TraceEventSession(sessionName){StopOnDispose=true,BufferSizeMB=32};
            trace.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIO|KernelTraceEventParser.Keywords.FileIOInit|KernelTraceEventParser.Keywords.DiskFileIO|KernelTraceEventParser.Keywords.Process|KernelTraceEventParser.Keywords.Thread);
            var source=trace.Source;var objects=new HashSet<ulong>();var pending=new Dictionary<ulong,EvidenceEvent>();long sequence=0;int reads=0;
            var native=NativePath(run.CanaryPath);
            bool Same(string path)=>path.Equals(run.CanaryPath,StringComparison.OrdinalIgnoreCase)||path.Equals(native,StringComparison.OrdinalIgnoreCase)||path.Equals(@"\??\"+run.CanaryPath,StringComparison.OrdinalIgnoreCase);
            source.Kernel.FileIOCreate+=e=>{if(Same(e.FileName))objects.Add(e.FileObject);};
            source.Kernel.FileIOClose+=e=>objects.Remove(e.FileObject);
            void Emit(EvidenceEvent e)=>output.WriteLine(JsonSerializer.Serialize(e,new JsonSerializerOptions(Evidence.Json){WriteIndented=false}));
            source.Kernel.FileIORead+=e=>
            {
                if(reads>=100||(!Same(e.FileName)&&!objects.Contains(e.FileObject)))return;
                var at=new DateTimeOffset(e.TimeStamp.ToUniversalTime());if(at<run.Started||at>run.Expires)return;
                var data=new Dictionary<string,string>{{"CanarySession",id},{"TargetFilename",run.CanaryPath},{"ProcessId",e.ProcessID.ToString()},{"ThreadId",e.ThreadID.ToString()},{"RequestedBytes",e.IoSize.ToString()},{"Source","Windows kernel FileIO/Read ETW"},{"Outcome","Read requested; completion not yet observed"},{"Observation","A process requested a read of the synthetic canary outside the game."},{"Attribution","Windows process identity only; this event does not identify the managed mod caller."}};
                try{using var p=Process.GetProcessById(e.ProcessID);var born=new DateTimeOffset(p.StartTime.ToUniversalTime());if(born<=at.AddMilliseconds(10)){data["ProcessStartTime"]=born.ToString("O");data["Image"]=p.MainModule?.FileName??p.ProcessName;}}catch{data["IdentityGap"]="Process identity could not be resolved before exit.";}
                var n=++sequence;var record=new EvidenceEvent("canary-read:"+id+":"+n,"Observe/WindowsCanary",n,CanaryLab.ReadEvent,at,data);
                reads++;Emit(record);pending[e.IrpPtr]=record;
            };
            source.Kernel.FileIOOperationEnd+=e=>
            {
                if(!pending.Remove(e.IrpPtr,out var request))return;
                var at=new DateTimeOffset(e.TimeStamp.ToUniversalTime());if(at<request.Timestamp||at>request.Timestamp.AddSeconds(30))return;
                var data=new Dictionary<string,string>(request.Data){{"NtStatus","0x"+unchecked((uint)e.NtStatus).ToString("X8")},{"CompletionTime",at.ToString("O")},{"ReadRequestEvent",request.Id}};
                data["Outcome"]=e.NtStatus==0?"Windows reported successful completion":"Windows reported a non-success completion";
                data["Observation"]=e.NtStatus==0?"Windows completed the synthetic canary file read successfully.":"Windows completed the canary read with a non-success status.";
                Emit(request with{Id=request.Id+":completion",Data=data});
            };
            State("listening","Windows file-read sensor ready. Start Cities II with the harmless test mod enabled.");
            var reader=Task.Run(()=>source.Process());
            var ready=lab.FilePath(id,".ready");CanaryLab.NoLinks(ready);File.WriteAllText(ready,DateTimeOffset.UtcNow.ToString("O"));
            var sharedReady=lab.BridgePath(id,".ready");CanaryLab.NoLinks(sharedReady);Directory.CreateDirectory(lab.Bridge);File.WriteAllText(sharedReady,DateTimeOffset.UtcNow.ToString("O"));
            while(DateTimeOffset.UtcNow<run.Expires&&!File.Exists(lab.FilePath(id,".stop"))&&!reader.IsCompleted)
            {await Task.Delay(1000);State("listening",reads>0?"Canary read observed. Review its process identity and completion status.":"Windows file-read sensor ready; waiting for a canary read.",trace.EventsLost);}
            var lost=trace.EventsLost;trace.Dispose();await reader.WaitAsync(TimeSpan.FromSeconds(10));
            State("stopped",reads>0?"Test sensor stopped. Saved file-read evidence is available.":"Test sensor stopped without observing a canary read. This does not prove that the mod ran or that software is safe.",lost);return 0;
        }
        catch(Exception error){State("error",error.Message);return 1;}
        finally{foreach(var ready in new[]{lab.FilePath(id,".ready"),lab.BridgePath(id,".ready")}){CanaryLab.NoLinks(ready);if(File.Exists(ready))File.Delete(ready);}}
    }
    static string NativePath(string path)
    {
        var drive=Path.GetPathRoot(path)!.TrimEnd('\\');var buffer=new StringBuilder(1024);
        return QueryDosDevice(drive,buffer,buffer.Capacity)>0?buffer.ToString().Split('\0')[0]+path[drive.Length..]:path;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern uint QueryDosDevice(string device,StringBuilder target,int size);
}
