using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SiteLimiter.Service;

/// <summary>
/// Calls back as soon as anything under the given HKLM keys changes. Used to undo DNS edits
/// made in Windows Settings / Control Panel within about a second, instead of waiting for the poll.
/// </summary>
internal sealed class RegistryWatcher : IDisposable
{
    private const uint REG_NOTIFY_CHANGE_NAME = 1, REG_NOTIFY_CHANGE_LAST_SET = 4, REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000;

    [DllImport("advapi32.dll")]
    private static extern int RegNotifyChangeKeyValue(SafeRegistryHandle key, bool watchSubtree, uint filter,
        SafeWaitHandle evt, bool asynchronous);

    private readonly Action _changed;
    private readonly string[] _paths;
    private readonly CancellationTokenSource _cts = new();
    private Thread? _thread;

    public RegistryWatcher(Action changed, params string[] paths)
    {
        _changed = changed;
        _paths = paths;
    }

    public void Start()
    {
        _thread = new Thread(Run) { IsBackground = true, Name = "registry-watch" };
        _thread.Start();
    }

    private void Run()
    {
        var keys = new List<RegistryKey>();
        var events = new List<AutoResetEvent>();
        try
        {
            foreach (var path in _paths)
            {
                var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (key is null) continue;
                keys.Add(key);
                events.Add(new AutoResetEvent(false));
            }
            if (keys.Count == 0) return;
            for (var i = 0; i < keys.Count; i++) Arm(keys[i], events[i]);

            var handles = events.Cast<WaitHandle>().Append(_cts.Token.WaitHandle).ToArray();
            while (true)
            {
                var index = WaitHandle.WaitAny(handles);
                if (index == handles.Length - 1) return; // disposed
                Arm(keys[index], events[index]);         // notifications are one-shot: re-arm first
                Thread.Sleep(300);                       // netsh / Settings write several values in a row
                if (_cts.IsCancellationRequested) return;
                try { _changed(); }
                catch (Exception ex) { Log.Error("Registry change handler", ex); }
            }
        }
        catch (Exception ex) { Log.Error("Registry watcher stopped", ex); }
        finally
        {
            foreach (var k in keys) k.Dispose();
            foreach (var e in events) e.Dispose();
        }
    }

    private static void Arm(RegistryKey key, AutoResetEvent evt)
    {
        var rc = RegNotifyChangeKeyValue(key.Handle, true,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, evt.SafeWaitHandle, true);
        if (rc != 0) Log.Warn($"RegNotifyChangeKeyValue failed: {rc}");
    }

    public void Dispose()
    {
        _cts.Cancel();
        _thread?.Join(TimeSpan.FromSeconds(2));
    }
}
