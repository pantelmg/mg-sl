using System.Diagnostics;
using System.Runtime.InteropServices;
using SiteLimiter.Core;
using SiteLimiter.Native;
using static SiteLimiter.Native.User32;

namespace SiteLimiter.Agent;

/// <summary>
/// Per-user agent: tray icon, foreground-tab usage tracking, closing tabs of blocked sites,
/// and "time almost up" notifications. Started (and restarted) by the service in each session.
/// </summary>
internal static class AgentApp
{
    private const uint WM_TRAY = WM_APP + 1, WM_BALLOON = WM_APP + 2;
    private const int CmdDashboard = 1;
    private const uint WM_SETTINGCHANGE = 0x001A, WM_DISPLAYCHANGE = 0x007E;
    private static readonly TimeSpan ReportEvery = TimeSpan.FromSeconds(5);

    private static IntPtr _hwnd;
    private static WndProc? _wndProc;          // kept alive for native code
    private static uint _taskbarCreated;
    private static Shell32.NOTIFYICONDATA _icon;

    private static readonly object Gate = new();
    private static ReportResponse? _last;
    private static readonly Queue<(string title, string text)> Balloons = new();
    private static readonly Dictionary<string, int> WarnedLevel = new(); // ruleId -> 0/1/2
    private static string _warnDay = "";
    private static bool _setupNagged;

    public static int Run()
    {
        using var mutex = new Mutex(true, @"Local\SiteLimiter.Agent", out var first);
        if (!first) return 0;

        Log.Init(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SiteLimiter"), "agent.log");
        Log.Info("Agent started");

        CreateWindowAndIcon();

        var tracker = new Thread(TrackLoop) { IsBackground = true, Name = "tracker" };
        tracker.SetApartmentState(ApartmentState.MTA); // UI Automation client calls
        tracker.Start();

        while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
        Shell32.Shell_NotifyIconW(Shell32.NIM_DELETE, ref _icon);
        return 0;
    }

    // ------------------------------------------------------------------ tray window

    private static void CreateWindowAndIcon()
    {
        _wndProc = WindowProc;
        var hInstance = Kernel32.GetModuleHandleW(null);
        var wc = new WNDCLASSEX
        {
            cbSize = Marshal.SizeOf<WNDCLASSEX>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = hInstance,
            lpszClassName = "SiteLimiterAgentWindow",
        };
        RegisterClassExW(ref wc);
        _hwnd = CreateWindowExW(0, wc.lpszClassName, "SiteLimiter", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);
        _taskbarCreated = RegisterWindowMessageW("TaskbarCreated");

        _icon = new Shell32.NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<Shell32.NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = 1,
            uFlags = Shell32.NIF_MESSAGE | Shell32.NIF_ICON | Shell32.NIF_TIP,
            uCallbackMessage = WM_TRAY,
            hIcon = TrayIcon.Load(),
            szTip = "MG SiteLimiter",
            szInfo = "", szInfoTitle = "",
        };
        Shell32.Shell_NotifyIconW(Shell32.NIM_ADD, ref _icon);
    }

    private static IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == _taskbarCreated && _taskbarCreated != 0)
        {
            ReloadIcon(add: true); // Explorer restarted (maybe with a new theme or DPI)
            return IntPtr.Zero;
        }
        switch (msg)
        {
            case WM_TRAY:
                var mouse = (uint)(lParam.ToInt64() & 0xFFFF);
                if (mouse == WM_LBUTTONUP) OpenDashboard();
                else if (mouse == WM_RBUTTONUP) ShowMenu();
                return IntPtr.Zero;
            case WM_BALLOON:
                ShowPendingBalloons();
                return IntPtr.Zero;
            case WM_SETTINGCHANGE:
            case WM_DISPLAYCHANGE:
                // Light/dark theme switch or display scaling change: pick the matching icon.
                ReloadIcon(add: false);
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            case WM_DESTROY:
                PostQuitMessage(0);
                return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    private static void ReloadIcon(bool add)
    {
        var fresh = TrayIcon.Load();
        if (fresh == IntPtr.Zero) return;
        var old = _icon.hIcon;
        _icon.hIcon = fresh;
        var data = _icon;
        data.uFlags = Shell32.NIF_MESSAGE | Shell32.NIF_ICON | Shell32.NIF_TIP;
        Shell32.Shell_NotifyIconW(add ? Shell32.NIM_ADD : Shell32.NIM_MODIFY, ref data);
        if (old != IntPtr.Zero) TrayIcon.DestroyIcon(old);
    }

    private static void ShowMenu()
    {
        var menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, CmdDashboard, "Open dashboard");
        AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, null);

        ReportResponse? last;
        lock (Gate) last = _last;
        if (last is null) AppendMenuW(menu, MF_STRING | MF_GRAYED, UIntPtr.Zero, "Service not reachable");
        else
        {
            if (!last.Enforcing) AppendMenuW(menu, MF_STRING | MF_GRAYED, UIntPtr.Zero, "Limits are off");
            foreach (var r in last.Rules.Take(12))
                AppendMenuW(menu, MF_STRING | MF_GRAYED, UIntPtr.Zero, $"{r.Name}: {Describe(r)}");
            if (last.Rules.Count == 0) AppendMenuW(menu, MF_STRING | MF_GRAYED, UIntPtr.Zero, "No limits set");
        }

        GetCursorPos(out var pt);
        SetForegroundWindow(_hwnd);
        var cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.X, pt.Y, 0, _hwnd, IntPtr.Zero);
        PostMessageW(_hwnd, WM_NULL, IntPtr.Zero, IntPtr.Zero);
        DestroyMenu(menu);
        if (cmd == CmdDashboard) OpenDashboard();
    }

    private static string Describe(RuleStatus r)
    {
        if (r.LimitSeconds == 0) return "Always blocked";
        if (r.Blocked) return "Limit reached";
        var left = Math.Max(0, r.LimitSeconds - r.UsedSeconds);
        return $"{left / 60} min left of {r.LimitSeconds / 60}";
    }

    private static void OpenDashboard()
    {
        try
        {
            var token = File.ReadAllText(Api.TokenPath).Trim();
            Process.Start(new ProcessStartInfo($"{Api.BaseUrl}#t={token}") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Log.Error("Open dashboard failed", ex);
            Notify("MG SiteLimiter", "The service is not running.");
        }
    }

    private static void Notify(string title, string text)
    {
        lock (Gate) Balloons.Enqueue((title, text));
        PostMessageW(_hwnd, WM_BALLOON, IntPtr.Zero, IntPtr.Zero);
    }

    private static void ShowPendingBalloons()
    {
        while (true)
        {
            (string title, string text) b;
            lock (Gate)
            {
                if (Balloons.Count == 0) return;
                b = Balloons.Dequeue();
            }
            var data = _icon;
            data.uFlags = Shell32.NIF_INFO;
            data.szInfoTitle = Trunc(b.title, 63);
            data.szInfo = Trunc(b.text, 255);
            data.dwInfoFlags = Shell32.NIIF_WARNING;
            Shell32.Shell_NotifyIconW(Shell32.NIM_MODIFY, ref data);
        }
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n];

    // ------------------------------------------------------------------ tracking

    private static void TrackLoop()
    {
        var reader = new UrlReader();
        using var client = new ServiceClient();
        var pending = new Dictionary<string, double>();
        var processNames = new Dictionary<uint, string>();
        var sinceReport = Stopwatch.StartNew();
        var tick = Stopwatch.StartNew();
        var lastClose = Stopwatch.StartNew();
        var sessionId = Process.GetCurrentProcess().SessionId;
        var lastContact = Stopwatch.StartNew();

        while (true)
        {
            Thread.Sleep(1000);
            var elapsed = Math.Min(tick.Elapsed.TotalSeconds, 3); // cap after sleep/hibernate
            tick.Restart();

            ReportResponse? state;
            lock (Gate) state = _last;
            var browsers = state?.BrowserProcesses ?? Settings.DefaultBrowsers();
            var idleSeconds = state?.IdleTimeoutSeconds ?? 0; // 0 = never stop counting

            string? host = null;
            IntPtr fg = IntPtr.Zero;
            try
            {
                fg = GetForegroundWindow();
                if (fg != IntPtr.Zero)
                {
                    GetWindowThreadProcessId(fg, out var pid);
                    if (processNames.Count > 256) processNames.Clear();
                    if (!processNames.TryGetValue(pid, out var proc))
                    {
                        try { using var p = Process.GetProcessById((int)pid); proc = p.ProcessName.ToLowerInvariant(); }
                        catch { proc = ""; }
                        processNames[pid] = proc;
                    }
                    host = reader.GetHost(fg, proc, browsers.Contains(proc)); // also catches renamed/unlisted browsers
                }
            }
            catch (Exception ex) { Log.Error("Tracking tick", ex); }

            if (host is not null)
            {
                if (!SessionLocked() && (idleSeconds == 0 || IdleTime() < TimeSpan.FromSeconds(idleSeconds)))
                    pending[host] = pending.GetValueOrDefault(host) + elapsed;

                // Enforce on the visible tab right away (DNS alone can't kill open connections/caches).
                if (state is { Enforcing: true } && lastClose.Elapsed > TimeSpan.FromSeconds(1.5) &&
                    Domains.IsInSet(host, state.BlockedDomains.ToHashSet()) && GetForegroundWindow() == fg)
                {
                    CloseActiveTab();
                    lastClose.Restart();
                    Notify("Blocked by MG SiteLimiter", $"{host} is over its daily limit. It resets at {state.NextResetUtc.ToLocalTime():HH:mm}.");
                }
            }

            if (sinceReport.Elapsed >= ReportEvery)
            {
                sinceReport.Restart();
                var send = new ReportRequest { SessionId = sessionId };
                foreach (var (h, s) in pending)
                {
                    var whole = (int)s;
                    if (whole > 0) send.Seconds[h] = whole;
                }
                try
                {
                    var resp = client.ReportAsync(send).GetAwaiter().GetResult();
                    if (resp is not null)
                    {
                        foreach (var (h, s) in send.Seconds) pending[h] -= s; // keep fractional remainder
                        foreach (var k in pending.Where(kv => kv.Value < 0.01).Select(kv => kv.Key).ToList()) pending.Remove(k);
                        lock (Gate) _last = resp;
                        lastContact.Restart();
                        UpdateTooltip(resp);
                        Warn(resp);
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    lock (Gate) _last = null; // service restarting; keep pending and retry
                    if (pending.Count > 50) pending.Clear();
                }
                catch (Exception ex) { Log.Error("Report failed", ex); }

                // Started by hand (dev/--console run) and the service is gone: quit and remove the tray icon.
                // When installed, the service restarts quickly and relaunches us anyway, so stay put.
                if (lastContact.Elapsed > TimeSpan.FromSeconds(30) && !ServiceInstalled())
                {
                    Log.Info("Service not installed and not reachable; agent exiting");
                    PostMessageW(_hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                    return;
                }
            }
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")]
    private static extern bool CloseDesktop(IntPtr desktop);

    /// <summary>
    /// True while the workstation is locked (the input desktop is the secure Winlogon desktop,
    /// which a normal user can't open). Time never counts on a locked PC, even with "Don't stop".
    /// </summary>
    private static bool SessionLocked()
    {
        var h = OpenInputDesktop(0, false, 0x0100 /* DESKTOP_SWITCHDESKTOP */);
        if (h == IntPtr.Zero) return true;
        CloseDesktop(h);
        return false;
    }

    private static bool ServiceInstalled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + Service.Hardening.ServiceName);
            return key is not null;
        }
        catch { return true; } // can't tell: assume installed and keep running
    }

    private static void CloseActiveTab()
    {
        // Release any modifiers the user is holding so the shortcut is exactly Ctrl+W.
        foreach (var vk in new byte[] { 0x10, 0x12, 0x5B }) // Shift, Alt, Win
            if ((GetAsyncKeyState(vk) & 0x8000) != 0) keybd_event(vk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        keybd_event(VK_CONTROL, 0, 0, UIntPtr.Zero);
        keybd_event(VK_W, 0, 0, UIntPtr.Zero);
        keybd_event(VK_W, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    private static void UpdateTooltip(ReportResponse r)
    {
        var tip = !r.Enforcing ? "MG SiteLimiter — Limits are off"
            : r.Rules.Count == 0 ? "MG SiteLimiter — No limits set"
            : "MG SiteLimiter\n" + string.Join("\n", r.Rules.Take(3).Select(x => $"{x.Name}: {Describe(x)}"));
        var data = _icon;
        data.uFlags = Shell32.NIF_TIP;
        data.szTip = Trunc(tip, 127);
        Shell32.Shell_NotifyIconW(Shell32.NIM_MODIFY, ref data);
    }

    private static void Warn(ReportResponse r)
    {
        if (r.SetupNeeded && !_setupNagged)
        {
            _setupNagged = true;
            Notify("Set up MG SiteLimiter", "Click the MG gauge icon in the tray to add limits and choose a lock.");
        }
        if (!r.Enforcing) return;

        var day = r.NextResetUtc.ToString("O");
        if (day != _warnDay) { _warnDay = day; WarnedLevel.Clear(); }

        foreach (var rule in r.Rules.Where(x => x.LimitSeconds > 0))
        {
            var left = rule.LimitSeconds - rule.UsedSeconds;
            var level = left <= 0 ? 3 : left <= 60 ? 2 : left <= 300 ? 1 : 0;
            var prev = WarnedLevel.GetValueOrDefault(rule.Id);
            if (level <= prev) continue;
            WarnedLevel[rule.Id] = level;
            if (level == 1 && prev == 0 && rule.UsedSeconds > 0)
                Notify("5 minutes left", $"{rule.Name}: About 5 minutes left today.");
            else if (level == 2)
                Notify("1 minute left", $"{rule.Name}: 1 minute left today.");
            else if (level == 3)
                Notify("Limit reached", $"{rule.Name} is blocked until {r.NextResetUtc.ToLocalTime():HH:mm}.");
        }
    }
}
