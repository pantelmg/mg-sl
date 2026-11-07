using System.Globalization;

namespace SiteLimiter.Core;

public static class Domains
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// Turns user input ("https://www.YouTube.com/watch?v=1", "*.reddit.com") into a bare
    /// registrable-style domain ("youtube.com", "reddit.com"). Returns null when invalid.
    /// </summary>
    public static string? Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        var s = input.Trim().ToLowerInvariant();

        var scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];
        var pathStart = s.IndexOfAny(['/', '?', '#']);
        if (pathStart >= 0) s = s[..pathStart];
        var at = s.LastIndexOf('@');
        if (at >= 0) s = s[(at + 1)..];
        var port = s.IndexOf(':');
        if (port >= 0) s = s[..port];

        s = s.Trim('.');
        if (s.StartsWith("*.", StringComparison.Ordinal)) s = s[2..];
        if (s.StartsWith("www.", StringComparison.Ordinal) && s.IndexOf('.', 4) > 0) s = s[4..];

        if (s.Any(c => c > 127))
        {
            try { s = Idn.GetAscii(s); } catch (ArgumentException) { return null; }
        }

        return IsValidHostName(s) && s.Contains('.') ? s : null;
    }

    public static bool IsValidHostName(string s)
    {
        if (s.Length is 0 or > 253) return false;
        foreach (var label in s.Split('.'))
        {
            if (label.Length is 0 or > 63) return false;
            if (label[0] == '-' || label[^1] == '-') return false;
            foreach (var c in label)
                if (!(c is >= 'a' and <= 'z' || c is >= '0' and <= '9' || c is '-' or '_')) return false;
        }
        return true;
    }

    /// <summary>Extracts a lowercase host from whatever a browser address bar shows.</summary>
    public static string? HostFromAddressBar(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        if (v.Contains(' ')) return null; // a search being typed, not a URL
        if (!v.Contains("://", StringComparison.Ordinal))
        {
            // chrome://, about:, edge:// etc. without "//" are internal pages
            if (v.StartsWith("about:", StringComparison.OrdinalIgnoreCase)) return null;
            v = "http://" + v;
        }
        if (!Uri.TryCreate(v, UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme is not ("http" or "https")) return null;
        var host = uri.IdnHost.ToLowerInvariant().TrimEnd('.');
        return host.Contains('.') || host == "localhost" ? host : null;
    }

    /// <summary>True when host equals domain or is a subdomain of it.</summary>
    public static bool Matches(string host, string domain) =>
        host.Length == domain.Length
            ? string.Equals(host, domain, StringComparison.Ordinal)
            : host.Length > domain.Length && host[host.Length - domain.Length - 1] == '.'
              && host.EndsWith(domain, StringComparison.Ordinal);

    /// <summary>Checks the host and every parent domain against a set of blocked domains.</summary>
    public static bool IsInSet(string host, IReadOnlySet<string> set)
    {
        if (set.Count == 0) return false;
        var h = host.ToLowerInvariant().TrimEnd('.');
        while (true)
        {
            if (set.Contains(h)) return true;
            var dot = h.IndexOf('.');
            if (dot < 0) return false;
            h = h[(dot + 1)..];
        }
    }
}
