using System.Runtime.InteropServices;
using SiteLimiter.Native;
using static SiteLimiter.Native.Advapi32;

namespace SiteLimiter.Service;

internal interface IServiceBody
{
    void Start();
    void Stop();
}

/// <summary>Minimal Win32 service plumbing (no Microsoft.Extensions.Hosting dependency).</summary>
internal static class ServiceHost
{
    private static ServiceMainProc? _main;      // kept alive for the native dispatcher
    private static HandlerEx? _handler;
    private static IntPtr _statusHandle;
    private static SERVICE_STATUS _status;
    private static readonly ManualResetEventSlim StopRequested = new();
    private static IServiceBody? _body;
    private static Func<IServiceBody>? _factory;
    private static string _name = Hardening.ServiceName;

    /// <summary>Returns false when not launched by the Service Control Manager.</summary>
    public static bool TryRun(string name, Func<IServiceBody> factory)
    {
        _name = name;
        _factory = factory;
        _main = ServiceMain;
        var table = new[]
        {
            new SERVICE_TABLE_ENTRY { lpServiceName = name, lpServiceProc = Marshal.GetFunctionPointerForDelegate(_main) },
            new SERVICE_TABLE_ENTRY { lpServiceName = null, lpServiceProc = IntPtr.Zero },
        };
        if (StartServiceCtrlDispatcherW(table)) return true;
        return Marshal.GetLastWin32Error() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;
    }

    private static void ServiceMain(uint argc, IntPtr argv)
    {
        _handler = Handler;
        _statusHandle = RegisterServiceCtrlHandlerExW(_name, _handler, IntPtr.Zero);
        _status = new SERVICE_STATUS { dwServiceType = SERVICE_WIN32_OWN_PROCESS };
        Report(SERVICE_START_PENDING, 30_000);

        try
        {
            _body = _factory!();
            _body.Start();
        }
        catch (Exception ex)
        {
            Log.Error("Service failed to start", ex);
            _status.dwWin32ExitCode = 1064; // ERROR_EXCEPTION_IN_SERVICE -> triggers recovery restart
            Report(SERVICE_STOPPED, 0);
            return;
        }

        Report(SERVICE_RUNNING, 0);
        StopRequested.Wait();

        Report(SERVICE_STOP_PENDING, 30_000);
        try { _body.Stop(); } catch (Exception ex) { Log.Error("Stop failed", ex); }
        Report(SERVICE_STOPPED, 0);
    }

    private static uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                Report(SERVICE_STOP_PENDING, 30_000);
                StopRequested.Set();
                return 0;
            case SERVICE_CONTROL_INTERROGATE:
                return 0;
            default:
                return 120; // ERROR_CALL_NOT_IMPLEMENTED
        }
    }

    private static void Report(uint state, uint waitHint)
    {
        _status.dwCurrentState = state;
        _status.dwWaitHint = waitHint;
        _status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
        _status.dwCheckPoint = state is SERVICE_RUNNING or SERVICE_STOPPED ? 0 : _status.dwCheckPoint + 1;
        SetServiceStatus(_statusHandle, ref _status);
    }

    /// <summary>Foreground debug mode: SiteLimiter.exe --console (run as admin/SYSTEM).</summary>
    public static void RunConsole()
    {
        Kernel32.AllocConsole();
        Log.Echo = true;
        var engine = new Engine(consoleMode: true);
        engine.Start();
        Console.WriteLine($"Running. Dashboard: {Core.Api.BaseUrl}#t={engine.Token}");
        Console.WriteLine("Start the tracker in a normal (non-admin) terminal: SiteLimiter.exe --agent");
        Console.WriteLine("Press Enter to stop (restores DNS).");
        Console.ReadLine();
        engine.Stop();
    }
}
