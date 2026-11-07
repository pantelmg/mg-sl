using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using SiteLimiter.Core;
using SiteLimiter.Native;
using static SiteLimiter.Native.User32;

namespace SiteLimiter.Setup;

/// <summary>
/// "MGSL Installer.exe" and "MGSL Uninstaller.exe" are this same executable under another name.
/// The installer copies itself into Program Files as the service; the uninstaller removes it.
/// </summary>
internal static class Setup
{
    public const string AppName = "MG SiteLimiter";
    public const string InstallerName = "MGSL Installer.exe";
    public const string UninstallerName = "MGSL Uninstaller.exe";
    private const string ServiceName = Service.Hardening.ServiceName;
    private const string GuardName = Service.Hardening.GuardName;
    private const string SafeBootNetwork = @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MGSiteLimiter";
    private const string Warning = "WARNING: This is a strict limiter! Be careful.";

    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SiteLimiter");
    private static string ServiceExe => Path.Combine(InstallDir, "SiteLimiter.exe");
    private static string UninstallerExe => Path.Combine(InstallDir, UninstallerName);

    // ------------------------------------------------------------------ install

    public static int Install(string[] args)
    {
        if (!EnsureElevated(args)) return 1;

        var mainExists = ServiceExists(ServiceName);
        var guardExists = ServiceExists(GuardName);
        if (mainExists || guardExists)
        {
            if (mainExists && guardExists && File.Exists(ServiceExe) && File.Exists(UninstallerExe))
            {
                Box($"{AppName} is already installed.\n\nTo update: Open the dashboard, unlock, choose Prepare uninstall, " +
                    $"run {UninstallerName} and choose No (keeps your data), then run this installer again.", MB_ICONINFORMATION);
                return 1;
            }
            return Repair(createMain: !mainExists, createGuard: !guardExists);
        }

        if (Ask($"Install {AppName}?\n\n{Warning}\n\nOnce you choose a password or a waiting period, limits can't be " +
                "loosened, turned off or uninstalled without it.", MB_YESNO | MB_ICONWARNING) != IDYES)
            return 1;

        try
        {
            Directory.CreateDirectory(InstallDir);
            var self = Environment.ProcessPath!;
            File.Copy(self, ServiceExe, overwrite: true);
            File.Delete(UninstallerExe);
            // Hard link: a second name for the same file, so it takes no extra disk space.
            if (!CreateHardLinkW(UninstallerExe, ServiceExe, IntPtr.Zero)) File.Copy(ServiceExe, UninstallerExe, true);

            CreateMainService();
            CreateGuardService();
            RegisterInApps();
            StartService(ServiceName);
            StartService(GuardName);
        }
        catch (Exception ex)
        {
            Box($"Installation failed:\n\n{ex.Message}", MB_ICONERROR);
            return 1;
        }

        Box($"{AppName} is installed and running.\n\nThe MG gauge icon appears in the system tray within a few seconds. " +
            "Click it to add limits and choose a password or a waiting period. Until then nothing is locked.", MB_ICONINFORMATION);
        return 0;
    }

    private static void CreateMainService()
    {
        CreateService(ServiceName, AppName, $"\"{ServiceExe}\"");
        Sc($"description {ServiceName} \"Daily time limits for websites, enforced through a local DNS filter.\"");
        SetRecovery(ServiceName);
    }

    private static void CreateGuardService()
    {
        CreateService(GuardName, AppName + " Guard", $"\"{ServiceExe}\" {Service.Hardening.GuardArg}");
        Sc($"description {GuardName} \"Keeps MG SiteLimiter running: Restarts it if it is stopped or frozen.\"");
        SetRecovery(GuardName);
    }

    private static void SetRecovery(string name)
    {
        Sc($"failure {name} reset= 86400 actions= restart/1000/restart/1000/restart/1000");
        Sc($"failureflag {name} 1");
    }

    // ------------------------------------------------------------------ repair

    /// <summary>
    /// The services are registered but program files (or one service) are missing, e.g. removed by an
    /// antivirus. Puts the exe back and restarts both services. Limits, statistics and protection in
    /// ProgramData are untouched; repair only ever restores protection, it never removes any.
    /// </summary>
    private static int Repair(bool createMain, bool createGuard)
    {
        if (Ask($"{AppName} is installed, but some of its files are missing (often removed by an antivirus).\n\n" +
                "Repair it? Your limits, statistics and lock settings are kept.\n\n" +
                $"Tip: Add {InstallDir} to your antivirus allow list so it doesn't happen again.",
                MB_YESNO | MB_ICONWARNING) != IDYES)
            return 1;

        try
        {
            // The folder is owned by SYSTEM and read-only for Administrators: take it over for the repair.
            EnablePrivilege("SeTakeOwnershipPrivilege");
            EnablePrivilege("SeRestorePrivilege");
            Directory.CreateDirectory(InstallDir);
            SetInstallDirAccess(adminsFull: true);

            var self = Environment.ProcessPath!;
            if (!File.Exists(ServiceExe))
            {
                File.Copy(self, ServiceExe, overwrite: true);
                File.Delete(UninstallerExe); // relink so both names are the same (new) file
            }
            if (!File.Exists(UninstallerExe) && !CreateHardLinkW(UninstallerExe, ServiceExe, IntPtr.Zero))
                File.Copy(ServiceExe, UninstallerExe, true);

            if (createMain) CreateMainService();
            if (createGuard) CreateGuardService();
            RegisterInApps();

            // Lock the folder again (the services also do this when they start).
            if (!Service.Guard.UninstallPrepared()) SetInstallDirAccess(adminsFull: false);

            StartService(ServiceName);
            StartService(GuardName);
        }
        catch (Exception ex)
        {
            Box($"Repair failed:\n\n{ex.Message}", MB_ICONERROR);
            return 1;
        }

        Box($"{AppName} has been repaired and is running again. Your limits and lock are as before.", MB_ICONINFORMATION);
        return 0;
    }

    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier UsersSid = new(WellKnownSidType.BuiltinUsersSid, null);

    /// <summary>Open (Administrators own it, full control) or lock (SYSTEM owns it, Administrators read-only).</summary>
    private static void SetInstallDirAccess(bool adminsFull)
    {
        var info = new DirectoryInfo(InstallDir);
        var owner = new DirectorySecurity();
        owner.SetOwner(adminsFull ? AdminsSid : SystemSid);
        if (adminsFull) info.SetAccessControl(owner);   // take ownership first, so we may rewrite the DACL

        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var dacl = new DirectorySecurity();
        dacl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        dacl.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        dacl.AddAccessRule(new FileSystemAccessRule(AdminsSid, adminsFull ? FileSystemRights.FullControl : FileSystemRights.ReadAndExecute,
            inherit, PropagationFlags.None, AccessControlType.Allow));
        dacl.AddAccessRule(new FileSystemAccessRule(UsersSid, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(dacl);                    // propagates to the files inside

        if (!adminsFull) info.SetAccessControl(owner);  // hand ownership back to SYSTEM last
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, int length, IntPtr previous, IntPtr returnLength);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    /// <summary>Administrators hold these privileges but they start disabled; ownership changes need them on.</summary>
    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x20 /* ADJUST_PRIVILEGES */ | 0x8 /* QUERY */, out var token))
            throw new Win32Exception();
        try
        {
            if (!LookupPrivilegeValueW(null, name, out var luid)) throw new Win32Exception();
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 2 /* SE_PRIVILEGE_ENABLED */ };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not enable {name}");
        }
        finally { Kernel32.CloseHandle(token); }
    }

    // ------------------------------------------------------------------ uninstall

    public static int Uninstall(string[] args)
    {
        if (!EnsureElevated(args)) return 1;

        // Emergency DNS reset only (no uninstall).
        if (args.Contains("--reset-dns", StringComparer.OrdinalIgnoreCase))
        {
            ResetAllDns();
            Box("Every network adapter is set back to automatic DNS.", MB_ICONINFORMATION);
            return 0;
        }

        // A running exe can't delete its own folder: continue from a copy in %TEMP%.
        var self = Environment.ProcessPath!;
        if (string.Equals(Path.GetDirectoryName(self), InstallDir, StringComparison.OrdinalIgnoreCase))
        {
            var temp = Path.Combine(Path.GetTempPath(), UninstallerName);
            File.Copy(self, temp, overwrite: true);
            Process.Start(new ProcessStartInfo(temp, string.Join(' ', args.Append("--uninstall").Distinct())) { UseShellExecute = false });
            return 0;
        }

        var exists = ServiceExists(ServiceName);
        var guardExists = ServiceExists(GuardName);
        if ((exists && !CanStopService(ServiceName)) || (guardExists && !CanStopService(GuardName)))
        {
            if (Ask($"{AppName} is locked and can't be uninstalled yet.\n\nOpen the dashboard, unlock, then choose " +
                    $"Prepare uninstall (last card). After that, run {UninstallerName} again within 1 hour.\n\n" +
                    "Open the dashboard now?", MB_YESNO | MB_ICONWARNING) == IDYES)
                OpenDashboard();
            return 1;
        }

        var choice = Ask($"Uninstall {AppName}?\n\nYes: Uninstall and delete everything, including your limits and statistics.\n" +
                         "No: Uninstall but keep your limits and statistics (for a reinstall).\nCancel: Do nothing.",
                         MB_YESNOCANCEL | MB_ICONQUESTION);
        if (choice != IDYES && choice != IDNO) return 1; // Cancel or closed
        var removeData = choice == IDYES;

        try
        {
            // Guard first, otherwise it would restart the main service.
            if (guardExists) StopAndDeleteService(GuardName);
            if (exists) StopAndDeleteService(ServiceName);
            foreach (var name in new[] { ServiceName, GuardName })
                Registry.LocalMachine.DeleteSubKeyTree(SafeBootNetwork + name, throwOnMissingSubKey: false);
            foreach (var p in Process.GetProcessesByName("SiteLimiter"))
            {
                try { p.Kill(); p.WaitForExit(3000); } catch { } finally { p.Dispose(); }
            }
            DeleteDir(InstallDir);
            if (removeData) DeleteDir(Api.DataDir);
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
        }
        catch (Exception ex)
        {
            Box($"Uninstall did not finish:\n\n{ex.Message}", MB_ICONERROR);
            return 1;
        }

        MoveFileExW(self, null, MOVEFILE_DELAY_UNTIL_REBOOT); // tidy up this temporary copy later
        Box($"{AppName} has been removed." + (removeData ? "" : $"\n\nYour limits and statistics were kept in {Api.DataDir}."),
            MB_ICONINFORMATION);
        return 0;
    }

    // ------------------------------------------------------------------ helpers

    private static bool EnsureElevated(string[] args)
    {
        using var id = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)) return true;
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, string.Join(' ', args)) { UseShellExecute = true, Verb = "runas" });
        }
        catch (Win32Exception) { /* user declined the UAC prompt */ }
        return false;
    }

    private static void CreateService(string name, string display, string binPath)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var svc = CreateServiceW(scm, name, display, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binPath, null, IntPtr.Zero, null, null, null);
            if (svc == IntPtr.Zero) throw new Win32Exception();
            CloseServiceHandle(svc);
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StartService(string name)
    {
        WithService(name, SERVICE_START, svc =>
        {
            if (!StartServiceW(svc, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != 1056 /* already running */)
                throw new Win32Exception();
        });
    }

    private static bool ServiceExists(string name)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return false;
        try
        {
            var svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero) return Marshal.GetLastWin32Error() != ERROR_SERVICE_DOES_NOT_EXIST;
            CloseServiceHandle(svc);
            return true;
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>False while the service is hardened (before "Prepare uninstall").</summary>
    private static bool CanStopService(string name)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return false;
        try
        {
            var svc = OpenServiceW(scm, name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero) return false;
            CloseServiceHandle(svc);
            return true;
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StopAndDeleteService(string name)
    {
        WithService(name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS, svc =>
        {
            var status = new Advapi32.SERVICE_STATUS();
            if (!ControlService(svc, SERVICE_CONTROL_STOP, ref status) && Marshal.GetLastWin32Error() != ERROR_SERVICE_NOT_ACTIVE)
                throw new Win32Exception();
            var sw = Stopwatch.StartNew();
            while (QueryServiceStatus(svc, ref status) && status.dwCurrentState != Advapi32.SERVICE_STOPPED && sw.Elapsed < TimeSpan.FromSeconds(60))
                Thread.Sleep(300);
            if (!DeleteService(svc) && Marshal.GetLastWin32Error() != 1072 /* already marked for deletion */)
                throw new Win32Exception();
        });
    }

    private static void WithService(string name, uint access, Action<IntPtr> action)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var svc = OpenServiceW(scm, name, access);
            if (svc == IntPtr.Zero) throw new Win32Exception();
            try { action(svc); } finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Entry in Settings → Apps so it can be found and uninstalled like any program.</summary>
    private static void RegisterInApps()
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey);
        key.SetValue("DisplayName", AppName);
        key.SetValue("DisplayVersion", typeof(Setup).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
        key.SetValue("Publisher", "pantelmg");
        key.SetValue("URLInfoAbout", "https://github.com/pantelmg");
        key.SetValue("DisplayIcon", $"\"{ServiceExe}\",0");
        key.SetValue("InstallLocation", InstallDir);
        key.SetValue("UninstallString", $"\"{UninstallerExe}\"");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        key.SetValue("EstimatedSize", (int)(new FileInfo(ServiceExe).Length / 1024), RegistryValueKind.DWord);
    }

    private static void ResetAllDns()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
            try
            {
                var idx = ni.GetIPProperties().GetIPv4Properties()?.Index;
                if (idx is null) continue;
                Netsh($"interface ipv4 set dnsservers name={idx} source=dhcp");
                Netsh($"interface ipv6 set dnsservers name={idx} source=dhcp");
            }
            catch { /* adapter without IP config */ }
        }
        Dnsapi.DnsFlushResolverCache();
    }

    private static void OpenDashboard()
    {
        // The tray agent runs in the user's (non-elevated) session; open the dashboard through it if possible.
        try
        {
            var token = File.ReadAllText(Api.TokenPath).Trim();
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Api.BaseUrl}#t={token}\"") { UseShellExecute = false });
        }
        catch { Box("Click the MG gauge icon in the system tray to open the dashboard.", MB_ICONINFORMATION); }
    }

    private static void DeleteDir(string dir)
    {
        for (var i = 0; i < 20 && Directory.Exists(dir); i++)
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception) when (i < 19) { Thread.Sleep(300); }
        }
    }

    private static void Sc(string args) => Run("sc.exe", args);
    private static void Netsh(string args) => Run("netsh.exe", args);

    private static void Run(string exe, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false })!;
        p.WaitForExit(15000);
    }

    private static void Box(string text, uint icon) => MessageBoxW(IntPtr.Zero, text, AppName, icon | MB_SETFOREGROUND | MB_TOPMOST);
    private static int Ask(string text, uint flags) => MessageBoxW(IntPtr.Zero, text, AppName, flags | MB_SETFOREGROUND | MB_TOPMOST);

    // ------------------------------------------------------------------ interop

    private const uint MB_YESNO = 4, MB_YESNOCANCEL = 3, MB_ICONERROR = 0x10, MB_ICONQUESTION = 0x20,
                       MB_ICONWARNING = 0x30, MB_SETFOREGROUND = 0x10000, MB_TOPMOST = 0x40000;
    private const int IDYES = 6, IDNO = 7, IDCANCEL = 2;
    private const uint SC_MANAGER_CONNECT = 1, SC_MANAGER_ALL_ACCESS = 0xF003F, SERVICE_ALL_ACCESS = 0xF01FF,
                       SERVICE_QUERY_STATUS = 4, SERVICE_START = 0x10, SERVICE_STOP = 0x20, DELETE = 0x10000,
                       SERVICE_WIN32_OWN_PROCESS = 0x10, SERVICE_AUTO_START = 2, SERVICE_ERROR_NORMAL = 1,
                       SERVICE_CONTROL_STOP = 1, MOVEFILE_DELAY_UNTIL_REBOOT = 4;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060, ERROR_SERVICE_NOT_ACTIVE = 1062;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start,
        uint error, string path, string? group, IntPtr tag, string? deps, string? account, string? password);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartServiceW(IntPtr svc, int argc, IntPtr argv);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr svc, uint control, ref Advapi32.SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr svc, ref Advapi32.SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr svc);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(string newFile, string existing, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string existing, string? newName, uint flags);
}
