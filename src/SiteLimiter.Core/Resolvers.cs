namespace SiteLimiter.Core;

/// <summary>Cloudflare 1.1.1.1 for Families. Ordered from least to most strict (the order matters for unlock checks).</summary>
public enum CloudflareFilter { Inactive = 0, Malware = 1, MalwareAndAdult = 2 }

public static class Resolvers
{
    /// <summary>Resolver addresses for a filter level (IPv4 first). Empty = use the network's own DNS.</summary>
    public static IReadOnlyList<string> Cloudflare(CloudflareFilter filter) => filter switch
    {
        CloudflareFilter.Malware => ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"],
        CloudflareFilter.MalwareAndAdult => ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"],
        _ => [],
    };

    /// <summary>Null if the change keeps or raises filtering, else why it needs an unlock.</summary>
    public static string? FindLoosening(CloudflareFilter current, CloudflareFilter next) =>
        next < current ? "Making DNS filtering less strict needs an unlock." : null;
}
