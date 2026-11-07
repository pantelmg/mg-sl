using System.Diagnostics;
using SiteLimiter.Native;

namespace SiteLimiter.Service;

/// <summary>
/// Detects a frozen ("suspended", e.g. via Resource Monitor) process and brings services back.
/// A suspended process never crashes, so Windows' own restart-on-failure never kicks in.
/// </summary>
internal static class ProcessGuard
{
    /// <summary>
    /// True when every thread of the process is suspended, checked twice 250 ms apart.
    /// (The .NET runtime briefly suspends individual threads during garbage collection, but never all of them.)
    /// </summary>
    public static bool IsSuspended(Process p)
    {
        return Check() && Sleep() && Check();

        bool Check()
        {
            try
            {
                p.Refresh();
                var threads = p.Threads;
                if (threads.Count == 0) return false;
                foreach (ProcessThread t in threads)
                {
                    if (t.ThreadState != System.Diagnostics.ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended)
                        return false;
                }
                return true;
            }
            catch { return false; } // exited or no access
        }

        static bool Sleep() { Thread.Sleep(250); return true; }
    }
}

/// <summary>Keeps another service running: starts it if stopped, kills and restarts it if suspended.</summary>
internal sealed class Watchdog
{
    private readonly string _service;
    private readonly Func<bool> _standDown; // true during an authorized uninstall
    private DateTime _lastStart = DateTime.MinValue;

    public Watchdog(string service, Func<bool> standDown)
    {
        _service = service;
        _standDown = standDown;
    }

    public void Tick()
    {
        if (_standDown()) return;
        var info = Scm.Query(_service);
        if (!info.Exists || info.State == 0) return;

        if (info.State == Scm.Stopped)
        {
            if (DateTime.UtcNow - _lastStart < TimeSpan.FromSeconds(2)) return;
            _lastStart = DateTime.UtcNow;
            if (Scm.Start(_service)) Log.Warn($"{_service} was stopped; started it again");
            return;
        }

        if (info.State != Scm.Running || info.Pid <= 0) return;
        Process p;
        try { p = Process.GetProcessById(info.Pid); } catch { return; }
        using (p)
        {
            if (!ProcessGuard.IsSuspended(p)) return;
            Log.Warn($"{_service} (pid {info.Pid}) was suspended; restarting it");
            try { p.Kill(); p.WaitForExit(3000); } catch (Exception ex) { Log.Warn($"Kill failed: {ex.Message}"); }
        }

        // Start right away instead of waiting for Windows' delayed restart-on-failure.
        var sw = Stopwatch.StartNew();
        while (Scm.Query(_service).State != Scm.Stopped && sw.Elapsed < TimeSpan.FromSeconds(5)) Thread.Sleep(100);
        _lastStart = DateTime.UtcNow;
        Scm.Start(_service);
    }
}
