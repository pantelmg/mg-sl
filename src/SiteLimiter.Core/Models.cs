namespace SiteLimiter.Core;

/// <summary>A site (one domain) or a pack (several domains) sharing one daily budget.</summary>
public sealed class Rule
{
    public string Id { get; set; } = NewId();
    public string Name { get; set; } = "";
    public List<string> Domains { get; set; } = new();
    /// <summary>Minutes per day. 0 = always blocked.</summary>
    public int DailyLimitMinutes { get; set; }
    public bool Enabled { get; set; } = true;

    public static string NewId() => Guid.NewGuid().ToString("N")[..12];

    public Rule Clone() => new()
    {
        Id = Id, Name = Name, Domains = new List<string>(Domains),
        DailyLimitMinutes = DailyLimitMinutes, Enabled = Enabled,
    };
}

public sealed class Settings
{
    /// <summary>Local hour (0-23) at which daily usage resets.</summary>
    public int ResetHour { get; set; }
    /// <summary>Stop counting after this many seconds without keyboard/mouse input. 0 = never stop.</summary>
    public int IdleTimeoutSeconds { get; set; }
    /// <summary>Block every limited site while a logged-on user has no running tracker.</summary>
    public bool FailClosed { get; set; } = true;
    /// <summary>How long an unlock (password or matured delay) stays valid. 0 = until locked again.</summary>
    public int UnlockWindowMinutes { get; set; }

    /// <summary>Idle cut-off as a comparable length (0 = never stop = longest).</summary>
    public static long EffectiveIdle(int seconds) => seconds == 0 ? long.MaxValue : seconds;
    /// <summary>Unlock window as a comparable length (0 = until locked = longest).</summary>
    public static long EffectiveWindow(int minutes) => minutes == 0 ? long.MaxValue : minutes;
    public List<string> BrowserProcesses { get; set; } = DefaultBrowsers();
    /// <summary>Optional upstream resolvers. Empty = use the adapters' original DNS servers.</summary>
    public List<string> UpstreamDns { get; set; } = new();

    public static List<string> DefaultBrowsers() => new()
    {
        "chrome", "msedge", "firefox", "brave", "opera", "opera_gx", "vivaldi", "chromium",
        "thorium", "librewolf", "waterfox", "floorp", "zen", "arc", "yandex", "iexplore",
    };

    public Settings Clone() => new()
    {
        ResetHour = ResetHour, IdleTimeoutSeconds = IdleTimeoutSeconds, FailClosed = FailClosed,
        UnlockWindowMinutes = UnlockWindowMinutes,
        BrowserProcesses = new List<string>(BrowserProcesses), UpstreamDns = new List<string>(UpstreamDns),
    };
}

public enum ProtectionMode { None, Password, Delay, PasswordOrDelay }

public sealed class Protection
{
    public ProtectionMode Mode { get; set; } = ProtectionMode.None;
    public string? PasswordHash { get; set; }
    public int DelayHours { get; set; } = 24;

    public bool AllowsPassword => Mode is ProtectionMode.Password or ProtectionMode.PasswordOrDelay;
    public bool AllowsDelay => Mode is ProtectionMode.Delay or ProtectionMode.PasswordOrDelay;
}

public sealed class AppConfig
{
    public List<Rule> Rules { get; set; } = new();
    public Settings Settings { get; set; } = new();
    public Protection Protection { get; set; } = new();
    /// <summary>Cloudflare 1.1.1.1 for Families filtering for every lookup that isn't blocked by a limit.</summary>
    public CloudflareFilter Cloudflare { get; set; } = CloudflareFilter.Inactive;
}

public sealed class LockState
{
    public DateTime? UnlockRequestedUtc { get; set; }
    public DateTime? UnlockedUntilUtc { get; set; }
}

public sealed class OriginalDns
{
    public int Index { get; set; }
    public string Name { get; set; } = "";
    /// <summary>Static IPv4 NameServer value before override ("" = DHCP). Null = never touched.</summary>
    public string? V4 { get; set; }
    public string? V6 { get; set; }
}

public sealed class PolicyBackup
{
    public bool Existed { get; set; }
    public string? StringValue { get; set; }
    public int? DwordValue { get; set; }
}

public sealed class ServiceState
{
    public string UsageDay { get; set; } = "";
    public Dictionary<string, int> UsageSeconds { get; set; } = new();
    /// <summary>Finished usage days: day key (yyyy-MM-dd) -> rule id -> seconds.</summary>
    public Dictionary<string, Dictionary<string, int>> History { get; set; } = new();
    public LockState Lock { get; set; } = new();
    public DateTime? UninstallPreparedUntilUtc { get; set; }
    /// <summary>Global switch: all limits off until turned back on (turning off needs an unlock).</summary>
    public bool LimitsOff { get; set; }
    public Dictionary<string, OriginalDns> OriginalDns { get; set; } = new();
    public Dictionary<string, PolicyBackup> PolicyBackups { get; set; } = new();
    public double NtpOffsetSeconds { get; set; }
}
