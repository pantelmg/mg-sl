using System.Net;
using System.Diagnostics;
using SiteLimiter.Core;
using SiteLimiter.Native;

namespace SiteLimiter.Service;

/// <summary>Owns config + state and drives every enforcement component. All mutations happen under _gate.</summary>
internal sealed class Engine : IServiceBody
{
    private static readonly TimeSpan AgentGrace = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan UninstallWindow = TimeSpan.FromHours(1);
    private const int MaxSecondsPerReport = 15;

    private readonly object _gate = new();
    private readonly Storage _storage = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Dictionary<int, long> _agentLastReport = new();     // session -> Stopwatch ts
    private readonly Dictionary<int, long> _sessionFirstSeen = new();
    private readonly HashSet<string> _alwaysBlocked = new(BrowserPolicies.DohHosts);
    private readonly List<string> _warnings = new();

    private AppConfig _config = new();
    private ServiceState _state = new();
    private TrustedClock _clock = new(0);
    private DnsProxy? _proxy;
    private DnsConfigurator? _dns;
    private ApiServer? _api;
    private readonly AgentLauncher _launcher = new();
    private volatile IReadOnlySet<string> _blocked = new HashSet<string>();
    private bool _enforcingApplied;
    private bool _dirty;
    private bool _stopping;
    private RegistryWatcher? _regWatch;
    private static readonly Dictionary<CloudflareFilter, IPAddress[]> CloudflareIps =
        Enum.GetValues<CloudflareFilter>().ToDictionary(f => f, f => Resolvers.Cloudflare(f).Select(IPAddress.Parse).ToArray());
    private Task? _loop;

    public string Token { get; private set; } = "";

    /// <summary>Debug run from an admin console: no service ACL/SDDL hardening, no agent launching.</summary>
    private readonly bool _console;
    public Engine(bool consoleMode = false) => _console = consoleMode;

    // ------------------------------------------------------------------ lifecycle

    public void Start()
    {
        if (_console) Directory.CreateDirectory(Api.DataDir);
        else _storage.PrepareDirectory();
        Log.Init(Path.Combine(Api.DataDir, "logs"), "service.log");
        Log.Info($"SiteLimiter service starting ({Environment.ProcessPath})");

        _config = _storage.LoadConfig();
        _state = _storage.LoadState();
        _clock = new TrustedClock(_state.NtpOffsetSeconds);
        Token = _storage.LoadOrCreateToken();

        _dns = new DnsConfigurator(_state, () => _config.Settings);
        _proxy = new DnsProxy(Classify, Upstreams);
        _proxy.Start();
        if (!_proxy.IsListening)
            _warnings.Add("The DNS filter could not start because port 53 is in use by another program. Sites are not being blocked.");

        lock (_gate)
        {
            RollDay();
            Recompute();
        }

        // Undo DNS edits made in Windows Settings / Control Panel / netsh within about a second.
        _regWatch = new RegistryWatcher(OnNetworkConfigChanged,
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces");
        _regWatch.Start();

        _api = new ApiServer(this);
        _api.Start();
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        if (!_console) new Thread(GuardWatchLoop) { IsBackground = true, Name = "watch-guard" }.Start();
    }

    public void Stop()
    {
        Log.Info("SiteLimiter service stopping");
        _cts.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(5)); } catch { /* cancelled */ }
        _api?.Dispose();
        lock (_gate) _stopping = true;
        _regWatch?.Dispose();
        lock (_gate)
        {
            // Never leave the machine pointing at a DNS server that is about to disappear.
            try { _dns?.RestoreAll(); } catch (Exception ex) { Log.Error("DNS restore failed", ex); }
            _state.NtpOffsetSeconds = _clock.OffsetSeconds;
            _storage.SaveState(_state);
            _storage.SaveConfig(_config);
        }
        _proxy?.Dispose();
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        var tick = 0;
        _ = SyncClockAsync(ct);
        // Slow machine changes (netsh, sc, registry) run here, after the service reported RUNNING.
        try { lock (_gate) ApplyEnforcementMode(force: true); }
        catch (Exception ex) { Log.Error("Initial enforcement setup failed", ex); }
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!_console) _launcher.Tick();
                lock (_gate)
                {
                    var now = _clock.UtcNow;
                    if (LockLogic.Expire(_config.Protection, _state.Lock, now)) _dirty = true;
                    if (_state.UninstallPreparedUntilUtc is { } u && now >= u)
                    {
                        _state.UninstallPreparedUntilUtc = null;
                        _dirty = true;
                        Log.Info("Uninstall window expired; protection re-armed");
                    }
                    RollDay();
                    ApplyEnforcementMode(force: false);
                    if (!_console && !UninstallPrepared && tick % 6 == 0) Hardening.EnsureAutostart();
                    // Backup for the registry watcher. Runs even with limits off: the Cloudflare filter still applies.
                    if (!UninstallPrepared && _proxy!.IsListening && _dns!.Reconcile()) _dirty = true;
                    if (Enforcing) GuardHostsFile();
                    Recompute();
                    if (_dirty || tick % 6 == 0) Save();
                }
                if (tick % 360 == 0 && tick > 0) _ = SyncClockAsync(ct);
            }
            catch (Exception ex) { Log.Error("Engine loop error", ex); }

            tick++;
            try { await Task.Delay(TimeSpan.FromSeconds(5), ct); } catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Every second: keep the guard service alive (start if stopped, restart if suspended).</summary>
    private void GuardWatchLoop()
    {
        var watch = new Watchdog(Hardening.GuardName, () => UninstallPrepared);
        while (!_cts.IsCancellationRequested)
        {
            try { watch.Tick(); }
            catch (Exception ex) { Log.Error("Guard watch", ex); }
            _cts.Token.WaitHandle.WaitOne(1000);
        }
    }

    private async Task SyncClockAsync(CancellationToken ct)
    {
        try
        {
            if (await _clock.SyncAsync(ct))
                lock (_gate) { _state.NtpOffsetSeconds = _clock.OffsetSeconds; _dirty = true; }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Warn($"Time sync failed: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ enforcement

    private bool UninstallPrepared => _state.UninstallPreparedUntilUtc is not null;
    private bool Enforcing => !UninstallPrepared && !_state.LimitsOff;

    /// <summary>Hardens / relaxes the machine when enforcement turns on or off.</summary>
    private void ApplyEnforcementMode(bool force)
    {
        var want = !UninstallPrepared;
        if (!force && want == _enforcingApplied) return;
        _enforcingApplied = want;
        if (want)
        {
            if (!_console)
            {
                Hardening.Harden();
                _storage.PrepareDirectory(adminsFullControl: false);
            }
            BrowserPolicies.Apply(_state);
            if (_proxy!.IsListening) _dns!.Reconcile();
        }
        else
        {
            _dns!.RestoreAll();
            BrowserPolicies.Restore(_state);
            if (!_console)
            {
                Hardening.Relax();
                _storage.PrepareDirectory(adminsFullControl: true);
            }
        }
        _dirty = true;
    }

    private DnsProxy.Verdict Classify(string name)
    {
        if (!Enforcing) return DnsProxy.Verdict.Forward;
        if (name == BrowserPolicies.FirefoxCanary) return DnsProxy.Verdict.NxDomain;
        if (Domains.IsInSet(name, _alwaysBlocked) || Domains.IsInSet(name, _blocked)) return DnsProxy.Verdict.Block;
        return DnsProxy.Verdict.Forward;
    }

    private void RollDay()
    {
        var day = Policy.DayKey(_clock.LocalNow, _config.Settings.ResetHour);
        if (!Policy.RollDay(_state, day)) return;
        Log.Info($"New usage day {day}");
        _dirty = true;
    }

    private bool FailClosedActive()
    {
        if (!_config.Settings.FailClosed || _config.Protection.Mode == ProtectionMode.None) return false;
        var now = Stopwatch.GetTimestamp();
        var active = _launcher.ActiveSessions;
        foreach (var gone in _sessionFirstSeen.Keys.Except(active).ToList())
        {
            _sessionFirstSeen.Remove(gone);
            _agentLastReport.Remove(gone);
        }
        foreach (var s in active)
        {
            if (!_sessionFirstSeen.ContainsKey(s)) _sessionFirstSeen[s] = now;
            var last = _agentLastReport.TryGetValue(s, out var t) ? t : _sessionFirstSeen[s];
            if (Stopwatch.GetElapsedTime(last) > AgentGrace) return true;
        }
        return false;
    }

    private void Recompute()
    {
        var set = new HashSet<string>();
        if (Enforcing)
        {
            var failClosed = FailClosedActive();
            foreach (var r in _config.Rules.Where(r => r.Enabled))
                if (failClosed || Used(r) >= r.DailyLimitMinutes * 60)
                    set.UnionWith(r.Domains);
        }
        var added = set.Except(_blocked).ToList();
        _blocked = set;
        if (added.Count > 0)
        {
            Log.Info($"Now blocking: {string.Join(", ", added)}");
            Dnsapi.DnsFlushResolverCache();
        }
    }

    private static readonly string HostsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Comments out hosts-file entries that would redirect a limited domain around the DNS filter.</summary>
    private void GuardHostsFile()
    {
        try
        {
            var fi = new FileInfo(HostsPath);
            if (!fi.Exists) return;
            var domains = _config.Rules.Where(r => r.Enabled).SelectMany(r => r.Domains).ToList();
            if (domains.Count == 0) return;

            // Latin-1 maps every byte to one char and back, so any encoding round-trips byte-for-byte.
            var text = System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(HostsPath));
            var (clean, disabled) = HostsGuard.Clean(text, h => domains.Any(d => Domains.Matches(h, d)));
            if (disabled.Count == 0) return;

            var readOnly = fi.IsReadOnly;
            if (readOnly) fi.IsReadOnly = false;
            File.WriteAllBytes(HostsPath, System.Text.Encoding.Latin1.GetBytes(clean));
            if (readOnly) fi.IsReadOnly = true;
            Dnsapi.DnsFlushResolverCache();
            Log.Warn($"Hosts file redirected limited sites; disabled entries for: {string.Join(", ", disabled)}");
        }
        catch (Exception ex) { Log.Warn($"Hosts file check: {ex.Message}"); }
    }

    private int Used(Rule r) => _state.UsageSeconds.TryGetValue(r.Id, out var s) ? s : 0;

    private void Save()
    {
        _storage.SaveState(_state);
        _dirty = false;
    }

    // ------------------------------------------------------------------ API (called by ApiServer)

    public ReportResponse Report(ReportRequest req)
    {
        lock (_gate)
        {
            RollDay();
            _agentLastReport[req.SessionId] = Stopwatch.GetTimestamp();
            foreach (var (rawHost, secs) in req.Seconds)
            {
                var host = rawHost.ToLowerInvariant();
                var add = Math.Clamp(secs, 0, MaxSecondsPerReport);
                if (add == 0) continue;
                foreach (var r in _config.Rules.Where(r => r.Enabled && r.Domains.Any(d => Domains.Matches(host, d))))
                {
                    _state.UsageSeconds[r.Id] = Used(r) + add;
                    _dirty = true;
                }
            }
            Recompute();
            return new ReportResponse
            {
                Enforcing = Enforcing,
                SetupNeeded = _config.Protection.Mode == ProtectionMode.None,
                BlockedDomains = _blocked.ToList(),
                Rules = _config.Rules.Where(r => r.Enabled).Select(r => new RuleStatus
                {
                    Id = r.Id, Name = r.Name, LimitSeconds = r.DailyLimitMinutes * 60,
                    UsedSeconds = Used(r), Blocked = r.Domains.Any(_blocked.Contains),
                }).ToList(),
                IdleTimeoutSeconds = _config.Settings.IdleTimeoutSeconds,
                BrowserProcesses = _config.Settings.BrowserProcesses,
                NextResetUtc = TimeZoneInfo.ConvertTimeToUtc(Policy.NextReset(_clock.LocalNow, _config.Settings.ResetHour), TimeZoneInfo.Local),
            };
        }
    }

    /// <summary>Per-rule usage history for the statistics charts (98 days = 14 full weeks).</summary>
    public object GetStats()
    {
        lock (_gate)
        {
            RollDay();
            var known = _state.History.Keys.Append(_state.UsageDay).Where(k => k.Length > 0).ToList();
            return new
            {
                today = _state.UsageDay,
                firstDay = known.Count > 0 ? known.Min(StringComparer.Ordinal) : _state.UsageDay,
                rules = _config.Rules.Select(r => new { r.Id, r.Name, r.Domains, r.DailyLimitMinutes, r.Enabled }),
                days = Policy.RecentDays(_state, 98).Select(d => new { d.day, d.usage }),
            };
        }
    }

    /// <summary>Where non-blocked lookups go: Cloudflare's filtering resolvers, or the network's own DNS.</summary>
    private IReadOnlyList<IPAddress> Upstreams()
    {
        var filter = _config.Cloudflare;
        return filter == CloudflareFilter.Inactive ? _dns!.Upstreams() : CloudflareIps[filter];
    }

    private void OnNetworkConfigChanged()
    {
        lock (_gate)
        {
            if (_stopping || UninstallPrepared || _proxy is not { IsListening: true }) return;
            if (_dns!.Reconcile()) _dirty = true;
        }
    }

    /// <summary>Stricter is always allowed; less strict needs an unlock.</summary>
    public (int, string?) SetCloudflare(CloudflareFilter filter)
    {
        if (!Enum.IsDefined(filter)) return (400, "Unknown filter.");
        lock (_gate)
        {
            if (filter == _config.Cloudflare) return (200, null);
            var loosening = Resolvers.FindLoosening(_config.Cloudflare, filter);
            if (loosening is not null && !UninstallPrepared &&
                !LockLogic.IsUnlocked(_config.Protection, _state.Lock, _clock.UtcNow))
                return (403, loosening);
            _config.Cloudflare = filter;
            _storage.SaveConfig(_config);
            Dnsapi.DnsFlushResolverCache();
            Log.Info($"Cloudflare filter set to {filter}");
            return (200, null);
        }
    }

    public object GetState()
    {
        lock (_gate)
        {
            var now = _clock.UtcNow;
            var p = _config.Protection;
            var l = _state.Lock;
            var readyAt = LockLogic.ReadyAt(p, l);
            var warnings = new List<string>(_warnings);
            if (Enforcing && FailClosedActive())
                warnings.Add("The usage tracker is not running in a logged-on session, so all limited sites are blocked (fail-closed).");
            return new
            {
                now,
                unlocked = LockLogic.IsUnlocked(p, l, now),
                timeTrusted = _clock.IsTrusted,
                protection = new { mode = p.Mode, delayHours = p.DelayHours, hasPassword = p.PasswordHash is not null },
                @lock = new
                {
                    unlockedUntil = p.Mode == ProtectionMode.None || LockLogic.IsIndefinite(l) ? null : l.UnlockedUntilUtc,
                    indefinite = p.Mode != ProtectionMode.None && LockLogic.IsIndefinite(l),
                    requestedAt = l.UnlockRequestedUtc,
                    readyAt,
                    readyExpiresAt = readyAt + LockLogic.ReadyGrace,
                    ready = LockLogic.IsDelayReady(p, l, now),
                },
                enforcement = new
                {
                    enabled = Enforcing,
                    limitsOff = _state.LimitsOff,
                    uninstallPreparedUntil = _state.UninstallPreparedUntilUtc,
                },
                nextReset = TimeZoneInfo.ConvertTimeToUtc(Policy.NextReset(_clock.LocalNow, _config.Settings.ResetHour), TimeZoneInfo.Local),
                rules = _config.Rules.Select(r => new
                {
                    r.Id, r.Name, r.Domains, r.DailyLimitMinutes, r.Enabled,
                    usedSeconds = Used(r),
                    blocked = r.Enabled && r.Domains.Any(_blocked.Contains),
                }),
                settings = _config.Settings,
                cloudflare = _config.Cloudflare,
                agents = _agentLastReport.Count(kv => Stopwatch.GetElapsedTime(kv.Value) < AgentGrace),
                warnings,
            };
        }
    }

    public (int status, string? error) UpdateConfig(List<Rule> rules, Settings settings)
    {
        var (validRules, err) = Policy.ValidateRules(rules);
        if (err is not null) return (400, err);
        err = Policy.ValidateSettings(settings);
        if (err is not null) return (400, err);
        lock (_gate)
        {
            if (!LockLogic.IsUnlocked(_config.Protection, _state.Lock, _clock.UtcNow) && !UninstallPrepared)
            {
                var loosening = Policy.FindLoosening(_config, validRules!, settings);
                if (loosening is not null) return (403, loosening);
            }
            _config.Rules = validRules!;
            _config.Settings = settings;
            // A shorter "Unlock lasts" also shortens the unlock that's open right now
            // (e.g. unlocked "until locked again", then set to 15 minutes -> locks 15 minutes from now).
            if (LockLogic.CapToWindow(_state.Lock, _clock.UtcNow, settings.UnlockWindowMinutes)) _dirty = true;
            _storage.SaveConfig(_config);
            RollDay();
            Recompute();
            Log.Info($"Config updated: {_config.Rules.Count} rules");
            return (200, null);
        }
    }

    public (int, string?) SetProtection(ProtectionMode mode, int delayHours, string? password)
    {
        if (delayHours is < 1 or > 720) return (400, "Delay must be 1–720 hours.");
        var newPassword = !string.IsNullOrEmpty(password);
        if (newPassword && password!.Length < 4) return (400, "Password must be at least 4 characters.");
        if (mode is ProtectionMode.Password or ProtectionMode.PasswordOrDelay && !newPassword && _config.Protection.PasswordHash is null)
            return (400, "Choose a password.");
        lock (_gate)
        {
            var p = _config.Protection;
            if (!LockLogic.IsUnlocked(p, _state.Lock, _clock.UtcNow))
            {
                var loosening = Policy.FindProtectionLoosening(p, mode, delayHours, newPassword);
                if (loosening is not null) return (403, loosening);
            }
            p.Mode = mode;
            p.DelayHours = delayHours;
            if (newPassword) p.PasswordHash = PasswordHasher.Hash(password!);
            if (mode == ProtectionMode.Delay) p.PasswordHash = null;
            if (mode == ProtectionMode.None) p.PasswordHash = null;
            _state.Lock = new LockState(); // lock immediately under the new rules
            _storage.SaveConfig(_config);
            _dirty = true;
            Log.Info($"Lock set to {mode}, delay {delayHours}h");
            return (200, null);
        }
    }

    public (int, string?) UnlockPassword(string password)
    {
        Thread.Sleep(400); // slows down guessing
        lock (_gate)
        {
            var err = LockLogic.UnlockWithPassword(_config.Protection, _state.Lock, _clock.UtcNow,
                _config.Settings.UnlockWindowMinutes, password);
            if (err is null) { _dirty = true; Log.Info("Unlocked with password"); }
            else Log.Warn("Failed password unlock");
            return (err is null ? 200 : 403, err);
        }
    }

    public (int, string?) RequestUnlock()
    {
        lock (_gate)
        {
            var err = LockLogic.RequestDelay(_config.Protection, _state.Lock, _clock.UtcNow);
            if (err is null) { _dirty = true; Log.Info("Delayed unlock requested"); }
            return (err is null ? 200 : 409, err);
        }
    }

    public async Task<(int, string?)> ClaimUnlockAsync()
    {
        if (!_clock.IsTrusted) await SyncClockAsync(_cts.Token);
        lock (_gate)
        {
            var err = LockLogic.ClaimDelay(_config.Protection, _state.Lock, _clock.UtcNow,
                _config.Settings.UnlockWindowMinutes, _clock.IsTrusted);
            if (err is null) { _dirty = true; Log.Info("Delayed unlock claimed"); }
            return (err is null ? 200 : 409, err);
        }
    }

    public (int, string?) CancelUnlock()
    {
        lock (_gate) { LockLogic.CancelDelay(_state.Lock); _dirty = true; return (200, null); }
    }

    public (int, string?) LockNow()
    {
        lock (_gate) { LockLogic.Lock(_state.Lock); _dirty = true; return (200, null); }
    }

    /// <summary>Re-arms everything if the user changes their mind after "prepare uninstall". Always allowed.</summary>
    /// <summary>Global on/off for all limits. Off needs an unlock; on is always allowed.</summary>
    public (int, string?) SetLimits(bool on)
    {
        lock (_gate)
        {
            if (!on && !LockLogic.IsUnlocked(_config.Protection, _state.Lock, _clock.UtcNow))
                return (403, "Turning limits off needs an unlock.");
            if (_state.LimitsOff == !on) return (200, null);
            _state.LimitsOff = !on;
            Recompute();
            Dnsapi.DnsFlushResolverCache();
            Save();
            Log.Info(on ? "Limits turned on" : "Limits turned off");
            return (200, null);
        }
    }

    public (int, string?) CancelUninstall()
    {
        lock (_gate)
        {
            if (!UninstallPrepared) return (200, null);
            _state.UninstallPreparedUntilUtc = null;
            ApplyEnforcementMode(force: false);
            Recompute();
            Save();
            Log.Info("Uninstall cancelled; protection re-armed");
            return (200, null);
        }
    }

    public (int, string?) PrepareUninstall()
    {
        lock (_gate)
        {
            if (!LockLogic.IsUnlocked(_config.Protection, _state.Lock, _clock.UtcNow))
                return (403, "Uninstalling needs an unlock.");
            _state.UninstallPreparedUntilUtc = _clock.UtcNow + UninstallWindow;
            ApplyEnforcementMode(force: false);
            Recompute();
            Save();
            Log.Info("Uninstall prepared: DNS restored, policies removed, service unprotected for 1 hour");
            return (200, null);
        }
    }
}
