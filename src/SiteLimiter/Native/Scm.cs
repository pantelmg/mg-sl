using System.Runtime.InteropServices;

namespace SiteLimiter.Native;

/// <summary>Small Service Control Manager helper: query state/PID, start a service.</summary>
internal static class Scm
{
    public const uint Stopped = 1, StartPending = 2, StopPending = 3, Running = 4;

    public readonly record struct Info(bool Exists, uint State, int Pid);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode,
                    dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }

    private const uint SC_MANAGER_CONNECT = 1, SERVICE_QUERY_STATUS = 4, SERVICE_START = 0x10;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060, ERROR_SERVICE_ALREADY_RUNNING = 1056;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr svc, int level, ref SERVICE_STATUS_PROCESS status, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartServiceW(IntPtr svc, int argc, IntPtr argv);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr h);

    public static Info Query(string name)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return new Info(true, 0, 0); // unknown: assume it exists, do nothing
        try
        {
            var svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
                return new Info(Marshal.GetLastWin32Error() != ERROR_SERVICE_DOES_NOT_EXIST, 0, 0);
            try
            {
                var st = new SERVICE_STATUS_PROCESS();
                return QueryServiceStatusEx(svc, 0, ref st, Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _)
                    ? new Info(true, st.dwCurrentState, (int)st.dwProcessId)
                    : new Info(true, 0, 0);
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Starts the service; true if it is now starting or already running.</summary>
    public static bool Start(string name)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return false;
        try
        {
            var svc = OpenServiceW(scm, name, SERVICE_START);
            if (svc == IntPtr.Zero) return false;
            try { return StartServiceW(svc, 0, IntPtr.Zero) || Marshal.GetLastWin32Error() == ERROR_SERVICE_ALREADY_RUNNING; }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
