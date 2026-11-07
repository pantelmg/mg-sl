namespace SiteLimiter.Core;

/// <summary>Decides whether a requested change makes the limits weaker (needs an unlock).</summary>
public static class Policy
{
    /// <summary>Returns null if the change only tightens restrictions, else the reason it loosens them.</summary>
    public static string? FindLoosening(AppConfig current, List<Rule> newRules, Settings newSettings)
    {
        foreach (var old in current.Rules.Where(r => r.Enabled))
        {
            var updated = newRules.FirstOrDefault(r => r.Id == old.Id);
            if (updated is null) return $"Removing \"{old.Name}\" needs an unlock.";
            if (!updated.Enabled) return $"Disabling \"{old.Name}\" needs an unlock.";
            if (updated.DailyLimitMinutes > old.DailyLimitMinutes)
                return $"Raising the limit of \"{old.Name}\" needs an unlock.";
            var missing = old.Domains.FirstOrDefault(d => !updated.Domains.Contains(d));
            if (missing is not null) return $"Removing {missing} from \"{old.Name}\" needs an unlock.";
        }

        var o = current.Settings;
        if (newSettings.ResetHour != o.ResetHour) return "Changing the reset hour needs an unlock.";
        if (Settings.EffectiveIdle(newSettings.IdleTimeoutSeconds) < Settings.EffectiveIdle(o.IdleTimeoutSeconds))
            return "Counting less idle time needs an unlock.";
        if (o.FailClosed && !newSettings.FailClosed) return "Turning off fail-closed needs an unlock.";
        if (Settings.EffectiveWindow(newSettings.UnlockWindowMinutes) > Settings.EffectiveWindow(o.UnlockWindowMinutes))
            return "Lengthening the unlock window needs an unlock.";
        var droppedBrowser = o.BrowserProcesses.FirstOrDefault(b =>
            !newSettings.BrowserProcesses.Contains(b, StringComparer.OrdinalIgnoreCase));
        if (droppedBrowser is not null) return $"Removing the browser \"{droppedBrowser}\" needs an unlock.";
        return null;
    }

    /// <summary>Protection changes allowed while locked: only ones that make unlocking harder.</summary>
    public static string? FindProtectionLoosening(Protection current, ProtectionMode mode, int delayHours, bool newPassword)
    {
        if (current.Mode == ProtectionMode.None) return null;
        if (newPassword) return "Changing the password needs an unlock.";
        if (mode == current.Mode)
            return delayHours < current.DelayHours && current.AllowsDelay ? "Shortening the delay needs an unlock." : null;
        if (current.Mode == ProtectionMode.PasswordOrDelay && mode is ProtectionMode.Password)
            return null;
        if (current.Mode == ProtectionMode.PasswordOrDelay && mode is ProtectionMode.Delay)
            return delayHours < current.DelayHours ? "Shortening the delay needs an unlock." : null;
        return "Switching the lock type needs an unlock.";
    }

    /// <summary>The "usage day" a moment belongs to, given a local reset hour.</summary>
    public static string DayKey(DateTime localNow, int resetHour) =>
        DateOnly.FromDateTime(localNow.AddHours(-resetHour)).ToString("yyyy-MM-dd");

    /// <summary>Days of history kept for the statistics charts.</summary>
    public const int HistoryDays = 400;

    /// <summary>
    /// Moves the finished day's usage into history, starts the new day, and prunes old history.
    /// Returns false when the day hasn't changed.
    /// </summary>
    public static bool RollDay(ServiceState state, string newDay)
    {
        if (newDay == state.UsageDay) return false;
        if (state.UsageDay.Length > 0 && state.UsageSeconds.Count > 0)
        {
            var bucket = state.History.TryGetValue(state.UsageDay, out var existing) ? existing : new Dictionary<string, int>();
            foreach (var (rule, secs) in state.UsageSeconds)
                bucket[rule] = bucket.GetValueOrDefault(rule) + secs;
            state.History[state.UsageDay] = bucket;
        }
        state.UsageDay = newDay;
        state.UsageSeconds = state.History.Remove(newDay, out var resumed) ? resumed : new Dictionary<string, int>();

        var cutoff = DateOnly.ParseExact(newDay, "yyyy-MM-dd").AddDays(-HistoryDays).ToString("yyyy-MM-dd");
        foreach (var old in state.History.Keys.Where(k => string.CompareOrdinal(k, cutoff) < 0).ToList())
            state.History.Remove(old);
        return true;
    }

    /// <summary>Usage for the last <paramref name="count"/> days ending today (oldest first), today taken live.</summary>
    public static List<(string day, Dictionary<string, int> usage)> RecentDays(ServiceState state, int count)
    {
        var today = DateOnly.ParseExact(state.UsageDay, "yyyy-MM-dd");
        var list = new List<(string, Dictionary<string, int>)>(count);
        for (var i = count - 1; i >= 0; i--)
        {
            var key = today.AddDays(-i).ToString("yyyy-MM-dd");
            var usage = i == 0 ? state.UsageSeconds
                : state.History.TryGetValue(key, out var h) ? h : new Dictionary<string, int>();
            list.Add((key, new Dictionary<string, int>(usage)));
        }
        return list;
    }

    /// <summary>Next local moment when usage resets.</summary>
    public static DateTime NextReset(DateTime localNow, int resetHour)
    {
        var candidate = localNow.Date.AddHours(resetHour);
        return candidate > localNow ? candidate : candidate.AddDays(1);
    }

    public static (List<Rule>? rules, string? error) ValidateRules(IEnumerable<Rule> input)
    {
        var result = new List<Rule>();
        var ids = new HashSet<string>();
        foreach (var r in input)
        {
            var name = (r.Name ?? "").Trim();
            var domains = new List<string>();
            foreach (var d in r.Domains ?? new())
            {
                var n = Domains.Normalize(d);
                if (n is null) return (null, $"\"{d}\" is not a valid domain.");
                if (!domains.Contains(n)) domains.Add(n);
            }
            if (domains.Count == 0) return (null, $"\"{(name.Length > 0 ? name : "Rule")}\" has no domains.");
            if (r.DailyLimitMinutes is < 0 or > 1440) return (null, "Daily limits must be 0–1440 minutes.");
            var id = string.IsNullOrWhiteSpace(r.Id) || !ids.Add(r.Id) ? Rule.NewId() : r.Id;
            ids.Add(id);
            result.Add(new Rule
            {
                Id = id,
                Name = name.Length > 0 ? name[..Math.Min(name.Length, 60)] : domains[0],
                Domains = domains,
                DailyLimitMinutes = r.DailyLimitMinutes,
                Enabled = r.Enabled,
            });
        }
        return (result, null);
    }

    public static string? ValidateSettings(Settings s)
    {
        if (s.ResetHour is < 0 or > 23) return "Reset hour must be 0–23.";
        if (s.IdleTimeoutSeconds != 0 && s.IdleTimeoutSeconds is < 30 or > 7200)
            return "Idle timeout must be \"Don't stop\" or 30–7200 seconds.";
        if (s.UnlockWindowMinutes != 0 && s.UnlockWindowMinutes is < 1 or > 1440)
            return "Unlock length must be \"Until locked again\" or 1–1440 minutes.";
        s.BrowserProcesses = s.BrowserProcesses
            .Select(b => b.Trim().ToLowerInvariant().Replace(".exe", ""))
            .Where(b => b.Length > 0).Distinct().ToList();
        var dns = new List<string>();
        foreach (var u in s.UpstreamDns.Select(x => x.Trim()).Where(x => x.Length > 0))
        {
            if (!System.Net.IPAddress.TryParse(u, out var ip) || System.Net.IPAddress.IsLoopback(ip))
                return $"\"{u}\" is not a usable upstream DNS IP.";
            dns.Add(ip.ToString());
        }
        s.UpstreamDns = dns;
        return null;
    }
}
