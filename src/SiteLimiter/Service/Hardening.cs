using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace SiteLimiter.Service;

/// <summary>
/// Anti-tamper for both services (SiteLimiter + SiteLimiterGuard). While hardened, Administrators
/// cannot stop, reconfigure, disable autostart, delete, or replace them by normal means
/// (services.msc, sc.exe, regedit, Explorer), and both also start in Safe Mode with Networking.
/// Relaxed only after an authorized "prepare uninstall".
/// </summary>
internal static class Hardening
{
    public const string ServiceName = "SiteLimiter";
    public const string GuardName = "SiteLimiterGuard";
    public const string GuardArg = "--guard";

    /// <summary>Both services and the command-line arguments in their ImagePath.</summary>
    public static readonly (string Name, string Args)[] Services = [(ServiceName, ""), (GuardName, " " + GuardArg)];

    private const string ServicesRoot = @"SYSTEM\CurrentControlSet\Services\";
    private const string SafeBootNetwork = @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\";
    private const int StartAutomatic = 2;

    private const string Hardened =
        "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
    private const string Relaxed =
        "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    public static void Harden()
    {
        EnsureAutostart();
        foreach (var (name, _) in Services)
        {
            if (!Exists(name)) continue;
            SetSddl(name, Hardened);
            SetRegistryAcl(ServicesRoot + name, adminsFull: false);
            SetRegistryAcl(SafeBootNetwork + name, adminsFull: false);
        }
        SetInstallDirAcl(adminsFull: false);
    }

    public static void Relax()
    {
        foreach (var (name, _) in Services)
        {
            if (!Exists(name)) continue;
            SetSddl(name, Relaxed);
            SetRegistryAcl(ServicesRoot + name, adminsFull: true);
            SetRegistryAcl(SafeBootNetwork + name, adminsFull: true);
        }
        SetInstallDirAcl(adminsFull: true);
    }

    /// <summary>
    /// Puts autostart, the exe path and Safe Mode registration back if they were changed
    /// (e.g. from Safe Mode or offline). Runs every 30 s in both services.
    /// </summary>
    public static void EnsureAutostart()
    {
        foreach (var (name, args) in Services)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(ServicesRoot + name, writable: true);
                if (key is null) continue; // not installed (dev/console run)
                if (key.GetValue("Start") is not int start || start != StartAutomatic)
                {
                    Log.Warn($"{name} startup type was changed (Start={key.GetValue("Start")}); reset to Automatic");
                    key.SetValue("Start", StartAutomatic, RegistryValueKind.DWord);
                }
                var expected = $"\"{Environment.ProcessPath}\"{args}";
                if (key.GetValue("ImagePath") is string image && !string.Equals(image, expected, StringComparison.OrdinalIgnoreCase))
                {
                    Log.Warn($"{name} ImagePath was changed to {image}; reset");
                    key.SetValue("ImagePath", expected, RegistryValueKind.ExpandString);
                }

                // Safe Mode with Networking starts only services listed under SafeBoot\Network.
                using var safe = Registry.LocalMachine.CreateSubKey(SafeBootNetwork + name, writable: true);
                if (safe.GetValue("") as string != "Service")
                {
                    safe.SetValue("", "Service");
                    SetRegistryAcl(SafeBootNetwork + name, adminsFull: false);
                    Log.Info($"{name} registered for Safe Mode with Networking");
                }
            }
            catch (Exception ex) { Log.Warn($"Autostart check ({name}): {ex.Message}"); }
        }
    }

    private static bool Exists(string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(ServicesRoot + name);
        return key is not null;
    }

    private static void SetSddl(string service, string sddl)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", $"sdset {service} {sddl}")
            {
                CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true,
            })!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            if (p.ExitCode != 0) Log.Warn($"sc sdset {service} -> {p.ExitCode}: {output.Trim()}");
        }
        catch (Exception ex) { Log.Error("sc sdset failed", ex); }
    }

    // Owner is set separately so a refused ownership change never undoes the DACL.
    // (An owner can always rewrite the DACL, so SYSTEM must own these while hardened.)
    private static void TrySetOwner(Action apply)
    {
        try { apply(); } catch (Exception ex) { Log.Warn($"Set owner: {ex.Message}"); }
    }

    /// <summary>SYSTEM owns the key; Administrators read-only while hardened.</summary>
    private static void SetRegistryAcl(string path, bool adminsFull)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);
            if (key is null) return;
            var sec = new RegistrySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit;
            sec.AddAccessRule(new RegistryAccessRule(System, RegistryRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new RegistryAccessRule(Admins, adminsFull ? RegistryRights.FullControl : RegistryRights.ReadKey,
                inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new RegistryAccessRule(Users, RegistryRights.ReadKey, inherit, PropagationFlags.None, AccessControlType.Allow));
            key.SetAccessControl(sec);
            if (!adminsFull) TrySetOwner(() => { var o = new RegistrySecurity(); o.SetOwner(System); key.SetAccessControl(o); });
        }
        catch (Exception ex) { Log.Warn($"Registry ACL {path}: {ex.Message}"); }
    }

    /// <summary>Program Files\SiteLimiter: Administrators can run but not modify or delete while hardened.</summary>
    private static void SetInstallDirAcl(bool adminsFull)
    {
        var dir = Path.GetDirectoryName(Environment.ProcessPath);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (dir is null || !dir.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)) return; // dev build: leave alone
        try
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(Admins, adminsFull ? FileSystemRights.FullControl : FileSystemRights.ReadAndExecute,
                inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            var info = new DirectoryInfo(dir);
            info.SetAccessControl(sec);
            if (!adminsFull) TrySetOwner(() => { var o = new DirectorySecurity(); o.SetOwner(System); info.SetAccessControl(o); });
        }
        catch (Exception ex) { Log.Warn($"Install folder ACL: {ex.Message}"); }
    }
}
