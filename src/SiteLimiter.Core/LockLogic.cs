namespace SiteLimiter.Core;

/// <summary>Pure unlock state machine. All times are trusted UTC.</summary>
public static class LockLogic
{
    /// <summary>How long a matured delay request stays claimable.</summary>
    public static readonly TimeSpan ReadyGrace = TimeSpan.FromHours(24);

    public static bool IsUnlocked(Protection p, LockState s, DateTime now) =>
        p.Mode == ProtectionMode.None || (s.UnlockedUntilUtc is { } u && now < u);

    public static DateTime? ReadyAt(Protection p, LockState s) =>
        p.AllowsDelay && s.UnlockRequestedUtc is { } r ? r.AddHours(p.DelayHours) : null;

    public static bool IsDelayReady(Protection p, LockState s, DateTime now) =>
        ReadyAt(p, s) is { } ready && now >= ready && now < ready + ReadyGrace;

    /// <summary>Clears expired unlocks and stale requests. Returns true if anything changed.</summary>
    public static bool Expire(Protection p, LockState s, DateTime now)
    {
        var changed = false;
        if (s.UnlockedUntilUtc is { } u && now >= u) { s.UnlockedUntilUtc = null; changed = true; }
        if (s.UnlockRequestedUtc is not null &&
            (!p.AllowsDelay || (ReadyAt(p, s) is { } ready && now >= ready + ReadyGrace)))
        {
            s.UnlockRequestedUtc = null; changed = true;
        }
        return changed;
    }

    public static string? RequestDelay(Protection p, LockState s, DateTime now)
    {
        if (!p.AllowsDelay) return "Delay unlock is not enabled.";
        if (IsUnlocked(p, s, now)) return "Already unlocked.";
        s.UnlockRequestedUtc ??= now;
        return null;
    }

    public static void CancelDelay(LockState s) => s.UnlockRequestedUtc = null;

    public static string? ClaimDelay(Protection p, LockState s, DateTime now, int windowMinutes, bool timeTrusted)
    {
        if (!p.AllowsDelay) return "Delay unlock is not enabled.";
        if (s.UnlockRequestedUtc is null) return "No unlock has been requested.";
        if (!timeTrusted) return "Can't verify the time online yet. Connect to the internet and retry.";
        if (!IsDelayReady(p, s, now)) return "The waiting period has not finished.";
        s.UnlockRequestedUtc = null;
        s.UnlockedUntilUtc = UnlockEnd(now, windowMinutes);
        return null;
    }

    public static string? UnlockWithPassword(Protection p, LockState s, DateTime now, int windowMinutes, string password)
    {
        if (!p.AllowsPassword || p.PasswordHash is null) return "Password unlock is not enabled.";
        if (!PasswordHasher.Verify(password, p.PasswordHash)) return "Wrong password.";
        s.UnlockedUntilUtc = UnlockEnd(now, windowMinutes);
        s.UnlockRequestedUtc = null;
        return null;
    }

    public static void Lock(LockState s) => s.UnlockedUntilUtc = null;

    /// <summary>0 minutes = stays unlocked until "Lock now".</summary>
    public static DateTime UnlockEnd(DateTime now, int windowMinutes) =>
        windowMinutes == 0 ? DateTime.MaxValue : now.AddMinutes(windowMinutes);

    public static bool IsIndefinite(LockState s) => s.UnlockedUntilUtc == DateTime.MaxValue;

    /// <summary>
    /// Applies a shorter "Unlock lasts" setting to the unlock that is open right now
    /// (e.g. unlocked "until locked again", then set to 15 min -> locks 15 min from now).
    /// Returns true if the unlock was shortened.
    /// </summary>
    public static bool CapToWindow(LockState s, DateTime now, int windowMinutes)
    {
        if (windowMinutes <= 0 || s.UnlockedUntilUtc is not { } until) return false;
        var cap = now.AddMinutes(windowMinutes);
        if (until <= cap) return false;
        s.UnlockedUntilUtc = cap;
        return true;
    }
}
