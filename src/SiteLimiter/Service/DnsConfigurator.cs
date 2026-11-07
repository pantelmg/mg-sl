using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using SiteLimiter.Core;
using SiteLimiter.Native;

namespace SiteLimiter.Service;

/// <summary>
/// Points every active network adapter's DNS at the local proxy and remembers the
/// original configuration (static list or DHCP) so it can be restored exactly.
/// </summary>
internal sealed class DnsConfigurator
{
    private const string V4Root = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
    private const string V6Root = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";
    private const string Local4 = "127.0.0.1", Local6 = "::1";

    private readonly ServiceState _state;
    private readonly Func<Settings> _settings;

    public DnsConfigurator(ServiceState state, Func<Settings> settings)
    {
        _state = state;
        _settings = settings;
    }

    /// <summary>Applies the override to adapters that drifted (new adapter, user edit, DHCP renew). Returns true if anything changed.</summary>
    public bool Reconcile()
    {
        var changed = false;
        foreach (var ni in Interfaces())
        {
            var guid = ni.Id;
            var props = ni.GetIPProperties();
            var orig = _state.OriginalDns.TryGetValue(guid, out var o) ? o : new OriginalDns();
            orig.Name = ni.Name;

            if (ni.Supports(NetworkInterfaceComponent.IPv4) && props.GetIPv4Properties() is { } p4)
            {
                orig.Index = p4.Index;
                var current = ReadNameServer(V4Root, guid);
                if (!SameList(current, Local4))
                {
                    // Keep the first original (what DHCP/the user had before install) as the restore target.
                    if (orig.V4 is null) orig.V4 = current;
                    else Log.Warn($"IPv4 DNS on \"{ni.Name}\" was changed to \"{current}\"; reverting");
                    _state.OriginalDns[guid] = orig;
                    if (Netsh($"interface ipv4 set dnsservers name={p4.Index} source=static address={Local4} register=none validate=no"))
                    {
                        Log.Info($"DNS override applied to \"{ni.Name}\" (IPv4, was \"{current}\")");
                        changed = true;
                    }
                }
            }

            if (ni.Supports(NetworkInterfaceComponent.IPv6) && props.GetIPv6Properties() is { } p6)
            {
                if (orig.Index == 0) orig.Index = p6.Index;
                var current = ReadNameServer(V6Root, guid);
                if (!SameList(current, Local6))
                {
                    if (orig.V6 is null) orig.V6 = current;
                    else Log.Warn($"IPv6 DNS on \"{ni.Name}\" was changed to \"{current}\"; reverting");
                    _state.OriginalDns[guid] = orig;
                    if (Netsh($"interface ipv6 set dnsservers name={p6.Index} source=static address={Local6} register=none validate=no"))
                    {
                        Log.Info($"DNS override applied to \"{ni.Name}\" (IPv6, was \"{current}\")");
                        changed = true;
                    }
                }
            }
        }
        if (changed) Dnsapi.DnsFlushResolverCache();
        return changed;
    }

    /// <summary>Puts every adapter we touched back to its original DNS setting.</summary>
    public void RestoreAll()
    {
        foreach (var (guid, o) in _state.OriginalDns.ToList())
        {
            var idx = CurrentIndex(guid) ?? o.Index;
            if (o.V4 is not null) Restore("ipv4", idx, o.V4);
            if (o.V6 is not null) Restore("ipv6", idx, o.V6);
            Log.Info($"DNS restored on \"{o.Name}\"");
            _state.OriginalDns.Remove(guid);
        }
        Dnsapi.DnsFlushResolverCache();
    }

    /// <summary>Real resolvers to forward to: user override, then original static, then DHCP-provided, then public fallback.</summary>
    public IReadOnlyList<IPAddress> Upstreams()
    {
        var list = new List<IPAddress>();
        void Add(string? csv)
        {
            foreach (var part in Split(csv))
                if (IPAddress.TryParse(part, out var ip) && Usable(ip) && !list.Contains(ip)) list.Add(ip);
        }

        foreach (var u in _settings().UpstreamDns) Add(u);
        foreach (var o in _state.OriginalDns.Values) { Add(o.V4); Add(o.V6); }
        foreach (var ni in Interfaces())
        {
            Add(ReadValue(V4Root, ni.Id, "DhcpNameServer"));
            Add(ReadValue(V6Root, ni.Id, "DhcpNameServer"));
        }
        // IPv4 first: more reliably reachable than IPv6 upstreams
        list = list.OrderBy(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6).ToList();
        if (list.Count == 0) list.AddRange([IPAddress.Parse("1.1.1.1"), IPAddress.Parse("9.9.9.9")]);
        return list;
    }

    private static IEnumerable<NetworkInterface> Interfaces() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(ni =>
            ni.OperationalStatus == OperationalStatus.Up &&
            ni.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel));

    private static int? CurrentIndex(string guid)
    {
        var ni = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == guid);
        try { return ni?.GetIPProperties().GetIPv4Properties()?.Index; } catch { return null; }
    }

    private static void Restore(string family, int idx, string original)
    {
        var servers = Split(original).ToList();
        if (servers.Count == 0)
        {
            Netsh($"interface {family} set dnsservers name={idx} source=dhcp");
            return;
        }
        Netsh($"interface {family} set dnsservers name={idx} source=static address={servers[0]} register=primary validate=no");
        for (var i = 1; i < servers.Count; i++)
            Netsh($"interface {family} add dnsservers name={idx} address={servers[i]} index={i + 1} validate=no");
    }

    private static bool Usable(IPAddress ip) =>
        !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any) &&
        !(ip.IsIPv6SiteLocal && ip.ToString().StartsWith("fec0:", StringComparison.OrdinalIgnoreCase));

    private static string ReadNameServer(string root, string guid) => ReadValue(root, guid, "NameServer") ?? "";

    private static string? ReadValue(string root, string guid, string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(root + guid);
        return key?.GetValue(name) as string;
    }

    private static IEnumerable<string> Split(string? csv) =>
        (csv ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool SameList(string current, string expected)
    {
        var parts = Split(current).ToList();
        return parts.Count == 1 && parts[0] == expected;
    }

    private static bool Netsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh.exe", args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(15000)) { p.Kill(); return false; }
            if (p.ExitCode != 0) Log.Warn($"netsh {args} -> {p.ExitCode}: {output.Trim()}");
            return p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            Log.Error($"netsh {args} failed", ex);
            return false;
        }
    }
}
