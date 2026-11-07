using System.Diagnostics;
using System.Runtime.InteropServices;
using SiteLimiter.Native;

namespace SiteLimiter.Service;

/// <summary>
/// Keeps one tracker/tray agent running in every active user session. This is also the
/// autostart mechanism: the service starts at boot and launches the agent at each logon.
/// </summary>
internal sealed class AgentLauncher
{
    private readonly Dictionary<int, DateTime> _lastLaunch = new();
    private readonly string _exe = Environment.ProcessPath!;

    public IReadOnlyList<int> ActiveSessions { get; private set; } = [];

    public void Tick()
    {
        List<int> sessions;
        try { sessions = Wtsapi32.ActiveSessions(); }
        catch (Exception ex) { Log.Error("WTSEnumerateSessions failed", ex); return; }
        ActiveSessions = sessions;
        if (sessions.Count == 0) return;

        var running = new HashSet<int>();
        var name = Path.GetFileNameWithoutExtension(_exe);
        foreach (var p in Process.GetProcessesByName(name))
        {
            try
            {
                if (p.SessionId == 0) continue;
                // A suspended (frozen) agent can't track or close tabs: kill it and start a fresh one now.
                if (ProcessGuard.IsSuspended(p))
                {
                    Log.Warn($"Agent in session {p.SessionId} (pid {p.Id}) was suspended; restarting it");
                    p.Kill();
                    p.WaitForExit(2000);
                    _lastLaunch.Remove(p.SessionId);
                    continue;
                }
                running.Add(p.SessionId);
            }
            catch { /* exited */ }
            finally { p.Dispose(); }
        }

        foreach (var s in sessions)
        {
            if (running.Contains(s)) continue;
            if (_lastLaunch.TryGetValue(s, out var last) && DateTime.UtcNow - last < TimeSpan.FromSeconds(5)) continue;
            _lastLaunch[s] = DateTime.UtcNow;
            Launch(s);
        }
    }

    private void Launch(int sessionId)
    {
        IntPtr userToken = IntPtr.Zero, primary = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!Wtsapi32.WTSQueryUserToken(sessionId, out userToken)) return; // nobody logged on yet
            if (!Advapi32.DuplicateTokenEx(userToken, Advapi32.MAXIMUM_ALLOWED, IntPtr.Zero,
                    Advapi32.SecurityImpersonation, Advapi32.TokenPrimary, out primary))
                throw new InvalidOperationException($"DuplicateTokenEx: {Marshal.GetLastWin32Error()}");
            if (!Userenv.CreateEnvironmentBlock(out env, primary, false)) env = IntPtr.Zero;

            var si = new Advapi32.STARTUPINFO { cb = Marshal.SizeOf<Advapi32.STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            var cmd = $"\"{_exe}\" --agent\0".ToCharArray();
            if (!Advapi32.CreateProcessAsUserW(primary, null, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    Advapi32.CREATE_UNICODE_ENVIRONMENT | Advapi32.CREATE_NEW_PROCESS_GROUP, env,
                    Path.GetDirectoryName(_exe), ref si, out var pi))
                throw new InvalidOperationException($"CreateProcessAsUser: {Marshal.GetLastWin32Error()}");

            Kernel32.CloseHandle(pi.hThread);
            Kernel32.CloseHandle(pi.hProcess);
            Log.Info($"Started agent in session {sessionId} (pid {pi.dwProcessId})");
        }
        catch (Exception ex) { Log.Error($"Agent launch in session {sessionId} failed", ex); }
        finally
        {
            if (env != IntPtr.Zero) Userenv.DestroyEnvironmentBlock(env);
            if (primary != IntPtr.Zero) Kernel32.CloseHandle(primary);
            if (userToken != IntPtr.Zero) Kernel32.CloseHandle(userToken);
        }
    }
}
