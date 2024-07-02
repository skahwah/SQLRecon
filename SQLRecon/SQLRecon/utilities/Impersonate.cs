using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace SQLRecon.Utilities
{
    // Reference: https://t.ly/eVP0J
    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]

    internal class Impersonate : IDisposable
    {
        private readonly SafeTokenHandle _handle;
        private readonly WindowsImpersonationContext _context;

        const int Logon32LogonNewCredentials = 9;

        internal Impersonate(string domain, string username, string password)
        {
            bool ok = LogonUser(username, domain, password,
                           Logon32LogonNewCredentials, 0, out this._handle);
            if (!ok)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new ApplicationException(
                    Print.Error($"Could not impersonate the elevated user. LogonUser returned error code {errorCode}."));
            }

            this._context = WindowsIdentity.Impersonate(this._handle.DangerousGetHandle());
        }

        public void Dispose()
        {
            this._context.Dispose();
            this._handle.Dispose();
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, 
            int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        private sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeTokenHandle()
                : base(true) { }

            [DllImport("kernel32.dll")]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [SuppressUnmanagedCodeSecurity]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }
    }
}