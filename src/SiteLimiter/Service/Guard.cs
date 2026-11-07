using System.Text.Json;
using SiteLimiter.Core;

namespace SiteLimiter.Service;

/// <summary>
/// "SiteLimiterGuard" service (SiteLimiter.exe --guard). It and the main service watch each other
/// every second: a stopped one is started, a suspended one is killed and restarted immediately.
/// It also re-applies autostart / Safe Mode registration. It stands down during an authorized uninstall.
/// </summary>
internal sealed class Guard : IServiceBody
{
    private readonly CancellationTokenSource _cts = new();
    private Thread? _loop;

    public void Start()
    {
        Directory.CreateDirectory(Api.DataDir);
        Log.Init(Path.Combine(Api.DataDir, "logs"), "guard.log");
        Log.Info("Guard service starting");
        _loop = new Thread(Loop) { IsBackground = true, Name = "guard" };
        _loop.Start();
    }

    public void Stop()
    {
        Log.Info("Guard service stopping");
        _cts.Cancel();
        _loop?.Join(TimeSpan.FromSeconds(5));
    }

    private void Loop()
    {
        var watch = new Watchdog(Hardening.ServiceName, UninstallPrepared);
        var tick = 0;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                watch.Tick();
                if (tick % 30 == 0 && !UninstallPrepared()) Hardening.EnsureAutostart();
            }
            catch (Exception ex) { Log.Error("Guard tick", ex); }
            tick++;
            _cts.Token.WaitHandle.WaitOne(1000);
        }
    }

    /// <summary>Reads the main service's state file: is an authorized uninstall in progress?</summary>
    public static bool UninstallPrepared()
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Api.DataDir, "state.json")));
            return doc.RootElement.TryGetProperty("uninstallPreparedUntilUtc", out var v)
                   && v.ValueKind == JsonValueKind.String
                   && v.GetDateTime().ToUniversalTime() > DateTime.UtcNow.AddMinutes(-1);
        }
        catch { return false; } // missing/locked/being rewritten: keep guarding
    }
}
