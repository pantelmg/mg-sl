// Dependency-free test runner: `dotnet run --project tests/SiteLimiter.Core.Tests`
using SiteLimiter.Core;

var failures = 0;
var count = 0;
void Check(bool cond, string name)
{
    count++;
    if (!cond) { failures++; Console.WriteLine($"FAIL  {name}"); }
}
void Eq<T>(T actual, T expected, string name)
{
    count++;
    if (!EqualityComparer<T>.Default.Equals(actual, expected))
    { failures++; Console.WriteLine($"FAIL  {name}: expected <{expected}>, got <{actual}>"); }
}

// ---- Domain normalization ----
Eq(Domains.Normalize("https://www.YouTube.com/watch?v=1"), "youtube.com", "normalize url");
Eq(Domains.Normalize("*.reddit.com"), "reddit.com", "normalize wildcard");
Eq(Domains.Normalize("m.facebook.com:443"), "m.facebook.com", "normalize port");
Eq(Domains.Normalize("user:pw@news.ycombinator.com/x"), "news.ycombinator.com", "normalize userinfo");
Eq(Domains.Normalize("www.com"), "www.com", "keep www.com");
Eq(Domains.Normalize("localhost"), null, "reject single label");
Eq(Domains.Normalize("bad domain.com"), null, "reject space");
Eq(Domains.Normalize("-x.com"), null, "reject leading hyphen");
Eq(Domains.Normalize("ελληνικά.gr"), "xn--hxargifdar.gr", "idn");

// ---- Address bar parsing ----
Eq(Domains.HostFromAddressBar("youtube.com/watch?v=abc"), "youtube.com", "omnibox no scheme");
Eq(Domains.HostFromAddressBar("https://Old.Reddit.com/r/x"), "old.reddit.com", "omnibox scheme");
Eq(Domains.HostFromAddressBar("how to cook rice"), null, "search text");
Eq(Domains.HostFromAddressBar("chrome://settings"), null, "internal page");
Eq(Domains.HostFromAddressBar("about:blank"), null, "about");
Eq(Domains.HostFromAddressBar(""), null, "empty");

// ---- Matching ----
Check(Domains.Matches("youtube.com", "youtube.com"), "match exact");
Check(Domains.Matches("m.youtube.com", "youtube.com"), "match sub");
Check(!Domains.Matches("notyoutube.com", "youtube.com"), "no match lookalike");
Check(!Domains.Matches("youtube.com.evil.net", "youtube.com"), "no match suffix trick");
var set = new HashSet<string> { "youtube.com", "x.com" };
Check(Domains.IsInSet("www.youtube.com", set), "set sub");
Check(Domains.IsInSet("X.COM.", set), "set case + trailing dot");
Check(!Domains.IsInSet("box.com", set), "set no partial label");

// ---- Day key with reset hour ----
Eq(Policy.DayKey(new DateTime(2026, 11, 7, 4, 59, 0), 5), "2026-11-06", "before 5am belongs to yesterday");
Eq(Policy.DayKey(new DateTime(2026, 11, 7, 5, 0, 0), 5), "2026-11-07", "at 5am new day");
Eq(Policy.DayKey(new DateTime(2026, 11, 7, 0, 0, 0), 0), "2026-11-07", "midnight default");
Eq(Policy.NextReset(new DateTime(2026, 11, 7, 4, 0, 0), 5), new DateTime(2026, 11, 7, 5, 0, 0), "next reset same day");
Eq(Policy.NextReset(new DateTime(2026, 11, 7, 6, 0, 0), 5), new DateTime(2026, 11, 8, 5, 0, 0), "next reset tomorrow");

// ---- Loosening detection ----
var cfg = new AppConfig
{
    Rules = { new Rule { Id = "a", Name = "YT", Domains = { "youtube.com" }, DailyLimitMinutes = 30 },
              new Rule { Id = "b", Name = "Social", Domains = { "x.com", "reddit.com" }, DailyLimitMinutes = 20 },
              new Rule { Id = "c", Name = "Off", Domains = { "tiktok.com" }, DailyLimitMinutes = 10, Enabled = false } },
};
List<Rule> Clone() => cfg.Rules.Select(r => r.Clone()).ToList();
var s0 = cfg.Settings.Clone();

Eq(Policy.FindLoosening(cfg, Clone(), s0), null, "no change");
var lower = Clone(); lower[0].DailyLimitMinutes = 10;
Eq(Policy.FindLoosening(cfg, lower, s0), null, "lower limit ok");
var added = Clone(); added.Add(new Rule { Id = "d", Domains = { "netflix.com" }, DailyLimitMinutes = 60 });
Eq(Policy.FindLoosening(cfg, added, s0), null, "add rule ok");
var addDomain = Clone(); addDomain[1].Domains.Add("instagram.com");
Eq(Policy.FindLoosening(cfg, addDomain, s0), null, "add domain to pack ok");
var dropDisabled = Clone(); dropDisabled.RemoveAt(2);
Eq(Policy.FindLoosening(cfg, dropDisabled, s0), null, "remove disabled rule ok");
var rename = Clone(); rename[0].Name = "YouTube";
Eq(Policy.FindLoosening(cfg, rename, s0), null, "rename ok");
var raise = Clone(); raise[0].DailyLimitMinutes = 31;
Check(Policy.FindLoosening(cfg, raise, s0) is not null, "raise limit blocked");
var remove = Clone(); remove.RemoveAt(0);
Check(Policy.FindLoosening(cfg, remove, s0) is not null, "remove rule blocked");
var disable = Clone(); disable[1].Enabled = false;
Check(Policy.FindLoosening(cfg, disable, s0) is not null, "disable rule blocked");
var dropDomain = Clone(); dropDomain[1].Domains.Remove("x.com");
Check(Policy.FindLoosening(cfg, dropDomain, s0) is not null, "remove domain blocked");
var s1 = s0.Clone(); s1.ResetHour = 5;
Check(Policy.FindLoosening(cfg, Clone(), s1) is not null, "reset hour change blocked");
Eq(s0.IdleTimeoutSeconds, 0, "default idle = don't stop");
Eq(s0.UnlockWindowMinutes, 0, "default unlock = until locked");
var s2 = s0.Clone(); s2.IdleTimeoutSeconds = 600;
Check(Policy.FindLoosening(cfg, Clone(), s2) is not null, "don't-stop -> 600s blocked (counts less)");
var cfgIdle = new AppConfig { Rules = cfg.Rules, Settings = new Settings { IdleTimeoutSeconds = 300, UnlockWindowMinutes = 15 } };
var s2b = cfgIdle.Settings.Clone(); s2b.IdleTimeoutSeconds = 600;
Eq(Policy.FindLoosening(cfgIdle, Clone(), s2b), null, "longer idle timeout ok (counts more)");
var s2c = cfgIdle.Settings.Clone(); s2c.IdleTimeoutSeconds = 0;
Eq(Policy.FindLoosening(cfgIdle, Clone(), s2c), null, "300s -> don't stop ok");
var s3 = cfgIdle.Settings.Clone(); s3.IdleTimeoutSeconds = 60;
Check(Policy.FindLoosening(cfgIdle, Clone(), s3) is not null, "shorter idle timeout blocked");
var s3b = cfgIdle.Settings.Clone(); s3b.UnlockWindowMinutes = 0;
Check(Policy.FindLoosening(cfgIdle, Clone(), s3b) is not null, "15 min -> until locked blocked");
var s3c = s0.Clone(); s3c.UnlockWindowMinutes = 15;
Eq(Policy.FindLoosening(cfg, Clone(), s3c), null, "until locked -> 15 min ok");
Eq(Policy.ValidateSettings(new Settings { IdleTimeoutSeconds = 0, UnlockWindowMinutes = 0 }), null, "0/0 valid");
Check(Policy.ValidateSettings(new Settings { IdleTimeoutSeconds = 10 }) is not null, "idle 10s invalid");
var s4 = s0.Clone(); s4.BrowserProcesses.Remove("firefox");
Check(Policy.FindLoosening(cfg, Clone(), s4) is not null, "drop browser blocked");
var s5 = s0.Clone(); s5.FailClosed = false;
Check(Policy.FindLoosening(cfg, Clone(), s5) is not null, "fail-open blocked");

// ---- Protection changes while locked ----
var pDelay = new Protection { Mode = ProtectionMode.Delay, DelayHours = 24 };
Eq(Policy.FindProtectionLoosening(pDelay, ProtectionMode.Delay, 48, false), null, "longer delay ok");
Check(Policy.FindProtectionLoosening(pDelay, ProtectionMode.Delay, 12, false) is not null, "shorter delay blocked");
Check(Policy.FindProtectionLoosening(pDelay, ProtectionMode.Password, 24, true) is not null, "delay->password blocked");
var pEither = new Protection { Mode = ProtectionMode.PasswordOrDelay, DelayHours = 24, PasswordHash = "x" };
Eq(Policy.FindProtectionLoosening(pEither, ProtectionMode.Password, 24, false), null, "either->password ok");
Eq(Policy.FindProtectionLoosening(pEither, ProtectionMode.Delay, 24, false), null, "either->delay ok");
Eq(Policy.FindProtectionLoosening(new Protection(), ProtectionMode.Password, 24, true), null, "first setup ok");

// ---- Validation ----
var (vr, verr) = Policy.ValidateRules(new[] { new Rule { Id = "", Name = " ", Domains = { "https://www.youtube.com/", "youtube.com" }, DailyLimitMinutes = 30 } });
Eq(verr, null, "validate ok");
Eq(vr![0].Domains.Count, 1, "validate dedup");
Eq(vr[0].Name, "youtube.com", "validate default name");
Check(vr[0].Id.Length == 12, "validate assigns id");
Check(Policy.ValidateRules(new[] { new Rule { Domains = { "not valid" } } }).error is not null, "validate bad domain");
Check(Policy.ValidateRules(new[] { new Rule { Domains = { "a.com" }, DailyLimitMinutes = 2000 } }).error is not null, "validate limit range");

// ---- Lock logic ----
var t0 = new DateTime(2026, 11, 7, 12, 0, 0, DateTimeKind.Utc);
var pw = PasswordHasher.Hash("hunter2");
Check(PasswordHasher.Verify("hunter2", pw), "hash verify");
Check(!PasswordHasher.Verify("hunter3", pw), "hash reject");
Check(!PasswordHasher.Verify("x", "garbage"), "hash garbage");

var prot = new Protection { Mode = ProtectionMode.PasswordOrDelay, PasswordHash = pw, DelayHours = 24 };
var ls = new LockState();
Check(!LockLogic.IsUnlocked(prot, ls, t0), "locked initially");
Check(LockLogic.IsUnlocked(new Protection(), ls, t0), "mode none is unlocked");
Eq(LockLogic.UnlockWithPassword(prot, ls, t0, 15, "nope"), "Wrong password.", "bad password");
Eq(LockLogic.UnlockWithPassword(prot, ls, t0, 15, "hunter2"), null, "good password");
Check(LockLogic.IsUnlocked(prot, ls, t0.AddMinutes(14)), "unlocked within window");
Check(!LockLogic.IsUnlocked(prot, ls, t0.AddMinutes(15)), "relocks after window");
var lsInf = new LockState();
LockLogic.UnlockWithPassword(prot, lsInf, t0, 0, "hunter2");
Check(LockLogic.IsIndefinite(lsInf) && LockLogic.IsUnlocked(prot, lsInf, t0.AddDays(365)), "window 0 = until locked");
Check(!LockLogic.Expire(prot, lsInf, t0.AddDays(365)), "indefinite unlock never expires");
var lsCap = new LockState();
LockLogic.UnlockWithPassword(prot, lsCap, t0, 0, "hunter2");
Check(LockLogic.CapToWindow(lsCap, t0.AddMinutes(30), 15), "cap indefinite unlock");
Check(!LockLogic.IsUnlocked(prot, lsCap, t0.AddMinutes(45)), "capped unlock ends 15 min after the change");
Check(!LockLogic.CapToWindow(lsCap, t0.AddMinutes(31), 60), "longer window doesn't extend");
Check(!LockLogic.CapToWindow(new LockState(), t0, 15), "no unlock, nothing to cap");
LockLogic.Lock(lsInf);
Check(!LockLogic.IsUnlocked(prot, lsInf, t0), "lock ends indefinite unlock");
LockLogic.Expire(prot, ls, t0.AddMinutes(16));
Eq(ls.UnlockedUntilUtc, null, "expire clears unlock");

Eq(LockLogic.RequestDelay(prot, ls, t0), null, "request delay");
LockLogic.RequestDelay(prot, ls, t0.AddHours(5));
Eq(ls.UnlockRequestedUtc, t0, "second request keeps original time");
Check(LockLogic.ClaimDelay(prot, ls, t0.AddHours(23.9), 15, true) is not null, "claim too early");
Check(LockLogic.ClaimDelay(prot, ls, t0.AddHours(24), 15, false) is not null, "claim needs trusted time");
Eq(LockLogic.ClaimDelay(prot, ls, t0.AddHours(24), 15, true), null, "claim on time");
Check(LockLogic.IsUnlocked(prot, ls, t0.AddHours(24).AddMinutes(10)), "unlocked after claim");
Eq(ls.UnlockRequestedUtc, null, "claim consumes request");

var ls2 = new LockState();
LockLogic.RequestDelay(prot, ls2, t0);
LockLogic.Expire(prot, ls2, t0.AddHours(48).AddMinutes(1));
Eq(ls2.UnlockRequestedUtc, null, "unclaimed request expires after grace");
var pwOnly = new Protection { Mode = ProtectionMode.Password, PasswordHash = pw };
Check(LockLogic.RequestDelay(pwOnly, new LockState(), t0) is not null, "no delay in password mode");

// ---- DNS wire format ----
byte[] MakeQuery(ushort id, string name, ushort type)
{
    var bytes = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
    foreach (var label in name.Split('.')) { bytes.Add((byte)label.Length); bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label)); }
    bytes.Add(0); bytes.Add((byte)(type >> 8)); bytes.Add((byte)type); bytes.Add(0); bytes.Add(1);
    return bytes.ToArray();
}
var qa = MakeQuery(0xBEEF, "WWW.YouTube.com", DnsMessage.TypeA);
Check(DnsMessage.TryParseQuery(qa, out var dq), "parse A");
Eq(dq.Name, "www.youtube.com", "parse lowercases");
Eq(dq.Type, DnsMessage.TypeA, "parse type");
Eq(dq.QuestionEnd, qa.Length, "parse end");
var ra = DnsMessage.BuildResponse(qa, dq, DnsMessage.RcodeNoError);
Eq(ra.Length, qa.Length + 16, "A answer length");
Eq((ra[0] << 8) | ra[1], 0xBEEF, "response id");
Eq(ra[2], (byte)0x81, "QR+RD");
Eq(ra[3], (byte)0x80, "RA, NOERROR");
Eq(ra[7], (byte)1, "ancount 1");
Check(ra[^4..].All(b => b == 0), "0.0.0.0");
var q6 = MakeQuery(1, "x.com", DnsMessage.TypeAAAA);
DnsMessage.TryParseQuery(q6, out var d6);
Eq(DnsMessage.BuildResponse(q6, d6, DnsMessage.RcodeNoError).Length, q6.Length + 28, "AAAA answer length");
var qh = MakeQuery(2, "x.com", 65);
DnsMessage.TryParseQuery(qh, out var dh);
var rh = DnsMessage.BuildResponse(qh, dh, DnsMessage.RcodeNoError);
Eq(rh.Length, qh.Length, "HTTPS type -> NODATA");
Eq(rh[7], (byte)0, "NODATA ancount 0");
var rn = DnsMessage.BuildResponse(qa, dq, DnsMessage.RcodeNxDomain);
Eq(rn[3] & 0x0F, 3, "NXDOMAIN rcode");
Eq(rn.Length, qa.Length, "NXDOMAIN no answer");
var resp = (byte[])qa.Clone(); resp[2] |= 0x80;
Check(!DnsMessage.TryParseQuery(resp, out _), "reject responses");
Check(!DnsMessage.TryParseQuery(qa.AsSpan(0, 14), out _), "reject truncated");
Eq(DnsMessage.BuildServFail(qa)![3] & 0x0F, 2, "servfail");

// ---- Usage history ----
var st = new ServiceState { UsageDay = "2026-11-06", UsageSeconds = { ["a"] = 600, ["b"] = 30 } };
Check(!Policy.RollDay(st, "2026-11-06"), "same day no roll");
Check(Policy.RollDay(st, "2026-11-07"), "roll to new day");
Eq(st.History["2026-11-06"]["a"], 600, "history keeps finished day");
Eq(st.UsageSeconds.Count, 0, "new day starts empty");
st.UsageSeconds["a"] = 120;
var recent = Policy.RecentDays(st, 3);
Eq(recent.Count, 3, "recent count");
Eq(recent[0].day, "2026-11-05", "recent oldest first");
Eq(recent[1].usage["b"], 30, "recent yesterday");
Eq(recent[2].usage["a"], 120, "recent today live");
recent[2].usage["a"] = 999;
Eq(st.UsageSeconds["a"], 120, "recent returns copies");
st.History["2025-01-01"] = new() { ["a"] = 1 };
Policy.RollDay(st, "2026-11-08");
Check(!st.History.ContainsKey("2025-01-01"), "prunes beyond retention");
Eq(st.History["2026-11-07"]["a"], 120, "second roll archived");
// reset-hour change can step back into an archived day: usage resumes instead of being lost
Policy.RollDay(st, "2026-11-07");
Eq(st.UsageSeconds["a"], 120, "rolling back resumes archived day");
Check(!st.History.ContainsKey("2026-11-07"), "resumed day leaves history");

// ---- Hosts file guard ----
bool Limited(string h) => new[] { "youtube.com", "reddit.com" }.Any(d => Domains.Matches(h, d));
var hosts = "# comment youtube.com\r\n127.0.0.1 localhost\r\n142.250.1.1 www.youtube.com # sneaky\r\n" +
            "0.0.0.0 reddit.com\r\n10.0.0.5 nas.local\r\n1.2.3.4\tfoo.com Reddit.com.\r\n";
var (cleaned, disabled) = HostsGuard.Clean(hosts, Limited);
Eq(string.Join(",", disabled), "www.youtube.com,reddit.com", "hosts: redirects of limited domains disabled");
Check(cleaned.Contains(HostsGuard.Marker + "142.250.1.1 www.youtube.com # sneaky\r\n"), "hosts: line kept, commented, CRLF kept");
Check(cleaned.Contains("\r\n0.0.0.0 reddit.com\r\n"), "hosts: blocking entry untouched");
Check(cleaned.Contains("\r\n10.0.0.5 nas.local\r\n"), "hosts: unrelated entry untouched");
Check(cleaned.StartsWith("# comment youtube.com\r\n127.0.0.1 localhost"), "hosts: comments and localhost untouched");
var (again, none) = HostsGuard.Clean(cleaned, Limited);
Check(none.Count == 0 && again == cleaned, "hosts: idempotent");

// ---- Cloudflare filter ----
Eq(Resolvers.Cloudflare(CloudflareFilter.Inactive).Count, 0, "cloudflare inactive: no resolvers");
Eq(Resolvers.Cloudflare(CloudflareFilter.Malware)[0], "1.1.1.2", "cloudflare malware primary");
Eq(Resolvers.Cloudflare(CloudflareFilter.MalwareAndAdult)[1], "1.0.0.3", "cloudflare adult secondary");
Eq(Resolvers.Cloudflare(CloudflareFilter.MalwareAndAdult)[2], "2606:4700:4700::1113", "cloudflare adult ipv6");
Check(Resolvers.Cloudflare(CloudflareFilter.Malware).All(ip => System.Net.IPAddress.TryParse(ip, out _)), "cloudflare IPs parse");
Eq(Resolvers.FindLoosening(CloudflareFilter.Inactive, CloudflareFilter.MalwareAndAdult), null, "stricter filter ok");
Eq(Resolvers.FindLoosening(CloudflareFilter.Malware, CloudflareFilter.MalwareAndAdult), null, "malware -> adult ok");
Check(Resolvers.FindLoosening(CloudflareFilter.MalwareAndAdult, CloudflareFilter.Malware) is not null, "adult -> malware needs unlock");
Check(Resolvers.FindLoosening(CloudflareFilter.Malware, CloudflareFilter.Inactive) is not null, "malware -> off needs unlock");
Eq(new AppConfig().Cloudflare, CloudflareFilter.Inactive, "cloudflare default inactive");

Console.WriteLine(failures == 0 ? $"OK  {count} checks passed" : $"{failures}/{count} checks FAILED");
return failures == 0 ? 0 : 1;
