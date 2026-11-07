using Microsoft.Win32;
using SiteLimiter.Core;

namespace SiteLimiter.Service;

/// <summary>
/// Machine policies that stop browsers from bypassing system DNS (DNS-over-HTTPS, Brave Tor windows).
/// Original values are backed up and restored on uninstall.
/// </summary>
internal static class BrowserPolicies
{
    private sealed record Entry(string Key, string Name, string? Str, int? Dword);

    private static readonly Entry[] Entries =
    [
        new(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off", null),
        new(@"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off", null),
        new(@"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off", null),
        new(@"SOFTWARE\Policies\BraveSoftware\Brave", "TorDisabled", null, 1),
        new(@"SOFTWARE\Policies\Vivaldi", "DnsOverHttpsMode", "off", null),
        new(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", null, 0),
        new(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", null, 1),
    ];

    /// <summary>Hostnames of public DoH/DoT resolvers, answered as blocked while enforcing.</summary>
    public static readonly string[] DohHosts =
    [
        "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "one.one.one.one",
        "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
        "doh.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com", "dns.nextdns.io",
        "doh.cleanbrowsing.org", "dns.adguard-dns.com", "dns.adguard.com", "dns-unfiltered.adguard.com",
        "doh.dns.sb", "dns.mullvad.net", "dns.controld.com", "freedns.controld.com", "doh.libredns.gr",
        "dns.alidns.com", "doh.pub", "doh.360.cn", "dns.twnic.tw", "doh.ffmuc.net", "dns.digitale-gesellschaft.ch",
    ];

    /// <summary>Firefox checks this name; NXDOMAIN tells it not to auto-enable DoH.</summary>
    public const string FirefoxCanary = "use-application-dns.net";

    public static void Apply(ServiceState state)
    {
        foreach (var e in Entries)
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(e.Key, writable: true);
                var id = $@"{e.Key}\{e.Name}";
                if (!state.PolicyBackups.ContainsKey(id))
                {
                    var existing = key.GetValue(e.Name);
                    state.PolicyBackups[id] = new PolicyBackup
                    {
                        Existed = existing is not null,
                        StringValue = existing as string,
                        DwordValue = existing is int i ? i : null,
                    };
                }
                if (e.Str is not null) key.SetValue(e.Name, e.Str, RegistryValueKind.String);
                else key.SetValue(e.Name, e.Dword!.Value, RegistryValueKind.DWord);
            }
            catch (Exception ex) { Log.Warn($"Policy {e.Key}\\{e.Name}: {ex.Message}"); }
        }
    }

    public static void Restore(ServiceState state)
    {
        foreach (var e in Entries)
        {
            var id = $@"{e.Key}\{e.Name}";
            if (!state.PolicyBackups.TryGetValue(id, out var b)) continue;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(e.Key, writable: true);
                if (key is null) continue;
                if (!b.Existed) key.DeleteValue(e.Name, throwOnMissingValue: false);
                else if (b.StringValue is not null) key.SetValue(e.Name, b.StringValue, RegistryValueKind.String);
                else if (b.DwordValue is not null) key.SetValue(e.Name, b.DwordValue.Value, RegistryValueKind.DWord);
                state.PolicyBackups.Remove(id);
            }
            catch (Exception ex) { Log.Warn($"Restore policy {id}: {ex.Message}"); }
        }
    }
}
