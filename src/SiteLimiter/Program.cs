using System.Runtime.Versioning;
using SiteLimiter.Agent;
using SiteLimiter.Native;
using SiteLimiter.Service;

[assembly: SupportedOSPlatform("windows")]

namespace SiteLimiter;

internal static class Program
{
    // One executable, several roles:
    //   (no args, started by SCM)  -> "SiteLimiter" service (DNS filter, limits, API)
    //   --guard                    -> "SiteLimiterGuard" service (watchdog; it and the main service watch each other)
    //   --agent                    -> per-user tray + usage tracker (launched by the service)
    //   --console                  -> service in a console window for debugging
    //   "MGSL Installer.exe"   / --install    -> installs this exe as the service
    //   "MGSL Uninstaller.exe" / --uninstall  -> removes it (after "Prepare uninstall")
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Contains("--agent", StringComparer.OrdinalIgnoreCase))
            return AgentApp.Run();

        if (args.Contains("--console", StringComparer.OrdinalIgnoreCase))
        {
            ServiceHost.RunConsole();
            return 0;
        }

        if (args.Contains(Hardening.GuardArg, StringComparer.OrdinalIgnoreCase))
            return ServiceHost.TryRun(Hardening.GuardName, () => new Guard()) ? 0 : 1;

        var name = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "").ToLowerInvariant();
        if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase) || args.Contains("--reset-dns", StringComparer.OrdinalIgnoreCase)
            || name.Contains("uninstall"))
            return Setup.Setup.Uninstall(args);
        if (args.Contains("--install", StringComparer.OrdinalIgnoreCase) || name.Contains("install"))
            return Setup.Setup.Install(args);

        if (ServiceHost.TryRun(Hardening.ServiceName, () => new Engine())) return 0;

        User32.MessageBoxW(IntPtr.Zero,
            "MG SiteLimiter runs as a Windows service.\n\nInstall it by running MGSL Installer.exe.",
            "MG SiteLimiter", User32.MB_ICONINFORMATION);
        return 1;
    }
}
