using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SiteLimiter.Core;

namespace SiteLimiter.Service;

/// <summary>Config/state persistence in %ProgramData%\SiteLimiter, ACL'd to SYSTEM (+ read for admins).</summary>
internal sealed class Storage
{
    private readonly string _configPath = Path.Combine(Api.DataDir, "config.json");
    private readonly string _statePath = Path.Combine(Api.DataDir, "state.json");

    /// <param name="adminsFullControl">True only during an authorized uninstall, so the folder can be deleted.</param>
    public void PrepareDirectory(bool adminsFullControl = false)
    {
        Directory.CreateDirectory(Api.DataDir);
        try
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(admins,
                adminsFullControl ? FileSystemRights.FullControl : FileSystemRights.ReadAndExecute,
                inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.SetOwner(system);
            new DirectoryInfo(Api.DataDir).SetAccessControl(sec);
        }
        catch (Exception ex) { Log.Warn($"Could not set data folder ACL: {ex.Message}"); }
    }

    /// <summary>Token that the dashboard and agent must send. Readable by local users, not by web pages.</summary>
    public string LoadOrCreateToken()
    {
        string token;
        try { token = File.ReadAllText(Api.TokenPath).Trim(); }
        catch { token = ""; }
        if (token.Length < 32)
        {
            token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
            File.WriteAllText(Api.TokenPath, token);
        }
        try
        {
            var fi = new FileInfo(Api.TokenPath);
            var sec = fi.GetAccessControl();
            sec.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Read, AccessControlType.Allow));
            fi.SetAccessControl(sec);
        }
        catch (Exception ex) { Log.Warn($"Could not grant users read on token: {ex.Message}"); }
        return token;
    }

    public AppConfig LoadConfig() => Load<AppConfig>(_configPath) ?? new AppConfig();
    public ServiceState LoadState() => Load<ServiceState>(_statePath) ?? new ServiceState();
    public void SaveConfig(AppConfig c) => Save(_configPath, c);
    public void SaveState(ServiceState s) => Save(_statePath, s);

    private static T? Load<T>(string path) where T : class
    {
        foreach (var p in new[] { path, path + ".bak" })
        {
            try
            {
                if (File.Exists(p)) return JsonSerializer.Deserialize<T>(File.ReadAllText(p), Api.JsonFile);
            }
            catch (Exception ex) { Log.Error($"Failed to read {p}", ex); }
        }
        return null;
    }

    private static void Save<T>(string path, T value)
    {
        try
        {
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(value, Api.JsonFile));
            if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
            else File.Move(tmp, path);
        }
        catch (Exception ex) { Log.Error($"Failed to write {path}", ex); }
    }
}
