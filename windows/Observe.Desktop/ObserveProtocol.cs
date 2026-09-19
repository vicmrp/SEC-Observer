using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Uvm.Bridge
{
    // Length-prefixed UTF-8, no executable commands and no caller-supplied file paths.
    public static class ObserveProtocol
    {
        public const int MaxBytes=8*1024*1024;
        // Unity's Mono throws NotImplementedException for WindowsIdentity.User.
        // Read the Windows token directly so Unity and desktop .NET use the same identity.
        public static readonly string UserSid=ReadUserSid();
        public static string PipeName => "UVM.Observe.v2."+UserSid;
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int length,out int needed);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSidToStringSid(IntPtr sid,out IntPtr text);
        static string ReadUserSid()
        {
            if(!OpenProcessToken(GetCurrentProcess(),8,out var token))throw new System.ComponentModel.Win32Exception();
            IntPtr buffer=IntPtr.Zero,text=IntPtr.Zero;
            try
            {
                GetTokenInformation(token,1,IntPtr.Zero,0,out var length);
                if(length<1||length>65536)throw new InvalidDataException("Invalid user token length.");
                buffer=Marshal.AllocHGlobal(length);
                if(!GetTokenInformation(token,1,buffer,length,out _)||!ConvertSidToStringSid(Marshal.ReadIntPtr(buffer),out text))throw new System.ComponentModel.Win32Exception();
                return Marshal.PtrToStringUni(text)??throw new InvalidDataException("Missing Windows user SID.");
            }
            finally{if(text!=IntPtr.Zero)LocalFree(text);if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);CloseHandle(token);}
        }
        [DllImport("kernel32.dll",SetLastError=true)]
        public static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint pid);
        [DllImport("kernel32.dll",SetLastError=true)]
        public static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint pid);
        public static async Task Write(Stream stream,string text,CancellationToken token)
        {
            var bytes=Encoding.UTF8.GetBytes(text);
            if(bytes.Length>MaxBytes)throw new InvalidDataException("Bridge message exceeds limit.");
            var prefix=BitConverter.GetBytes(bytes.Length);
            await stream.WriteAsync(prefix,0,4,token).ConfigureAwait(false);
            await stream.WriteAsync(bytes,0,bytes.Length,token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
        }
        public static async Task<string> Read(Stream stream,int limit,CancellationToken token)
        {
            var prefix=new byte[4];await Exact(stream,prefix,token).ConfigureAwait(false);
            int length=BitConverter.ToInt32(prefix,0);
            if(length<1||length>Math.Min(limit,MaxBytes))throw new InvalidDataException("Invalid bridge message length.");
            var bytes=new byte[length];await Exact(stream,bytes,token).ConfigureAwait(false);
            return new UTF8Encoding(false,true).GetString(bytes);
        }
        static async Task Exact(Stream stream,byte[] bytes,CancellationToken token)
        {
            int offset=0;
            while(offset<bytes.Length){int n=await stream.ReadAsync(bytes,offset,bytes.Length-offset,token).ConfigureAwait(false);if(n==0)throw new EndOfStreamException();offset+=n;}
        }
    }
}

