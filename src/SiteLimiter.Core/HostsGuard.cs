namespace SiteLimiter.Core;

/// <summary>
/// The Windows hosts file is consulted before DNS, so an entry like "142.250.1.1 youtube.com"
/// would bypass the DNS filter. These entries are commented out. Entries that *block* a site
/// (0.0.0.0, 127.x, ::, ::1) are left alone.
/// </summary>
public static class HostsGuard
{
    public const string Marker = "# [MG SiteLimiter disabled] ";

    /// <returns>The new file content and the hostnames whose lines were disabled (empty = unchanged).</returns>
    public static (string Content, List<string> Disabled) Clean(string content, Func<string, bool> isLimited)
    {
        var disabled = new List<string>();
        var lines = content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var body = line.TrimEnd('\r');
            var hash = body.IndexOf('#');
            var active = (hash >= 0 ? body[..hash] : body).Trim();
            if (active.Length == 0) continue;

            var tokens = active.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2 || IsBlockingAddress(tokens[0])) continue;

            var hit = tokens.Skip(1).Select(h => h.ToLowerInvariant().TrimEnd('.')).FirstOrDefault(isLimited);
            if (hit is null) continue;
            disabled.Add(hit);
            lines[i] = Marker + line;
        }
        return (disabled.Count == 0 ? content : string.Join('\n', lines), disabled);
    }

    public static bool IsBlockingAddress(string ip) =>
        ip is "0.0.0.0" or "::" or "::0" or "::1" || ip.StartsWith("127.", StringComparison.Ordinal);
}
