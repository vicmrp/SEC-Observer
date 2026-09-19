using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Uvm.Bridge;

namespace Observe;

internal static class UvmPipeConnection
{
    // CurrentUserOnly compares TokenOwner, which becomes Administrators when
    // Observe is elevated. UVM deliberately owns its pipe with TokenUser.
    // Check that exact user ourselves, before sending preferences or reading data.
    // https://github.com/dotnet/runtime/issues/123903
    internal static NamedPipeClientStream Create(string name) => new(".", name,
        PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);

    internal static void VerifyOwner(NamedPipeClientStream pipe)
    {
        var error = GetSecurityInfo(pipe.SafePipeHandle, 6 /* SE_KERNEL_OBJECT */,
            1 /* OWNER_SECURITY_INFORMATION */, out var owner, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, out var descriptor);
        try
        {
            if (error != 0) throw new Win32Exception((int)error, "Cannot verify UVM pipe ownership.");
            if (owner == IntPtr.Zero) throw new UnauthorizedAccessException("UVM pipe has no Windows owner.");
            RequireUserOwner(new SecurityIdentifier(owner).Value, ObserveProtocol.UserSid);
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }

    internal static void RequireUserOwner(string owner, string user)
    {
        if (string.IsNullOrEmpty(user) || !string.Equals(owner, user, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("UVM's pipe belongs to a different Windows user. Run Observe and Cities II under the same account.");
    }

    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(SafePipeHandle handle, int objectType, uint information,
        out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
}
