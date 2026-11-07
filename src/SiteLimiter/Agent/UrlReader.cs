using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SiteLimiter.Core;
using SiteLimiter.Native;

namespace SiteLimiter.Agent;

/// <summary>
/// Reads the active tab's host from a browser's address bar via UI Automation.
/// Browsers are recognised by their window type and address-bar signature, not only by
/// process name, so a renamed chrome.exe or an unlisted Chromium/Firefox-based browser is
/// still timed. Electron apps (VS Code, Discord, …) share Chromium's window class but have no
/// omnibox, so they are never mistaken for browsers.
/// </summary>
internal sealed class UrlReader
{
    private static readonly HashSet<string> GeckoProcesses = ["firefox", "librewolf", "waterfox", "floorp", "zen", "mullvadbrowser"];
    private static readonly TimeSpan NegativeCacheFor = TimeSpan.FromSeconds(20);

    private readonly IUIAutomation _uia = (IUIAutomation)new CUIAutomation();
    private IntPtr _cachedHwnd;
    private IUIAutomationElement? _cachedBar;
    private string? _lastHost;
    private readonly Dictionary<IntPtr, long> _notBrowser = new(); // hwnd -> Stopwatch timestamp

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int max);

    public static string WindowClass(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        return GetClassNameW(hwnd, sb, sb.Capacity) > 0 ? sb.ToString() : "";
    }

    /// <summary>Must be called from an MTA thread. <paramref name="listed"/> = process is in the tracked-browsers setting.</summary>
    public string? GetHost(IntPtr hwnd, string process, bool listed)
    {
        var cls = WindowClass(hwnd);
        var gecko = cls == "MozillaWindowClass" || GeckoProcesses.Contains(process);
        var chromium = cls.StartsWith("Chrome_WidgetWin", StringComparison.Ordinal);
        if (!gecko && !chromium && !listed) return null; // not a browser window: no UIA work at all

        if (_notBrowser.TryGetValue(hwnd, out var since))
        {
            if (Stopwatch.GetElapsedTime(since) < NegativeCacheFor) return null;
            _notBrowser.Remove(hwnd);
        }
        if (_notBrowser.Count > 200) _notBrowser.Clear();

        try
        {
            if (hwnd != _cachedHwnd || _cachedBar is null)
            {
                Release();
                _cachedBar = FindAddressBar(hwnd, gecko, chromium, listed);
                _lastHost = null;
                if (_cachedBar is null)
                {
                    _notBrowser[hwnd] = Stopwatch.GetTimestamp();
                    return null;
                }
                _cachedHwnd = hwnd;
            }

            // While the user is typing in the bar, keep the page they are actually on.
            if (_cachedBar.GetCurrentPropertyValue(Uia.HasKeyboardFocusProperty, out var focus) == 0 && focus is true)
                return _lastHost;

            if (_cachedBar.GetCurrentPropertyValue(Uia.ValueValueProperty, out var value) != 0)
            {
                Release();
                return null;
            }
            var host = Domains.HostFromAddressBar(value as string);
            _lastHost = host;
            return host;
        }
        catch (COMException)
        {
            Release(); // window closed or browser UI rebuilt; re-find next tick
            return null;
        }
        catch (InvalidCastException)
        {
            Release();
            return null;
        }
    }

    private IUIAutomationElement? FindAddressBar(IntPtr hwnd, bool gecko, bool chromium, bool listed)
    {
        if (_uia.ElementFromHandle(hwnd, out var root) != 0 || root is null) return null;
        try
        {
            // Firefox family: the URL bar has a fixed automation id (Thunderbird etc. don't have it).
            if (gecko) return Find(root, Uia.AutomationIdProperty, "urlbar-input");

            // Chromium family: the omnibox is a views class named OmniboxViewViews.
            if (chromium && Find(root, Uia.ClassNameProperty, "OmniboxViewViews") is { } omnibox) return omnibox;

            // Listed browsers with a custom UI (Opera, Vivaldi, …): first Edit in tree order is the address bar.
            return listed ? Find(root, Uia.ControlTypeProperty, Uia.EditControlType) : null;
        }
        finally { Marshal.ReleaseComObject(root); }
    }

    private IUIAutomationElement? Find(IUIAutomationElement root, int property, object value)
    {
        var cond = IntPtr.Zero;
        try
        {
            if (_uia.CreatePropertyCondition(property, value, out cond) != 0) return null;
            return root.FindFirst(Uia.TreeScope_Descendants, cond, out var found) == 0 ? found : null;
        }
        finally { if (cond != IntPtr.Zero) Marshal.Release(cond); }
    }

    private void Release()
    {
        if (_cachedBar is not null)
        {
            try { Marshal.ReleaseComObject(_cachedBar); } catch { }
        }
        _cachedBar = null;
        _cachedHwnd = IntPtr.Zero;
    }
}
