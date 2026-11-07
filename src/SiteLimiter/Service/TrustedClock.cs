using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SiteLimiter.Service;

/// <summary>
/// System clock corrected by an SNTP offset, so moving the Windows clock does not skip
/// the unlock delay or reset daily usage early.
/// </summary>
internal sealed class TrustedClock
{
    private static readonly string[] Servers = ["time.windows.com", "time.cloudflare.com", "pool.ntp.org", "time.google.com"];
    private static readonly TimeSpan TrustWindow = TimeSpan.FromHours(2);

    private double _offsetSeconds;
    private long _lastSyncTicks = -1; // Stopwatch timestamp (monotonic)

    public TrustedClock(double persistedOffset) => _offsetSeconds = persistedOffset;

    public double OffsetSeconds => _offsetSeconds;
    public DateTime UtcNow => DateTime.UtcNow.AddSeconds(_offsetSeconds);
    public DateTime LocalNow => TimeZoneInfo.ConvertTimeFromUtc(UtcNow, TimeZoneInfo.Local);

    /// <summary>True when the offset was confirmed against a time server recently (by monotonic time).</summary>
    public bool IsTrusted => _lastSyncTicks >= 0 && Stopwatch.GetElapsedTime(_lastSyncTicks) < TrustWindow;

    public TimeSpan SinceLastSync => _lastSyncTicks < 0 ? TimeSpan.MaxValue : Stopwatch.GetElapsedTime(_lastSyncTicks);

    public async Task<bool> SyncAsync(CancellationToken ct)
    {
        foreach (var server in Servers)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(4));
                var addrs = await Dns.GetHostAddressesAsync(server, AddressFamily.InterNetwork, cts.Token);
                if (addrs.Length == 0) continue;

                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                await udp.ConnectAsync(new IPEndPoint(addrs[0], 123), cts.Token);
                var req = new byte[48];
                req[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
                var t1 = DateTime.UtcNow;
                await udp.SendAsync(req, SocketFlags.None, cts.Token);
                var resp = new byte[48];
                var n = await udp.ReceiveAsync(resp, SocketFlags.None, cts.Token);
                var t4 = DateTime.UtcNow;
                if (n < 48 || (resp[0] & 0x07) != 4) continue;

                var t2 = ReadNtp(resp.AsSpan(32));
                var t3 = ReadNtp(resp.AsSpan(40));
                var offset = ((t2 - t1) + (t3 - t4)).TotalSeconds / 2;
                if (Math.Abs(offset) > 10 * 365 * 86400) continue;

                _offsetSeconds = offset;
                _lastSyncTicks = Stopwatch.GetTimestamp();
                if (Math.Abs(offset) > 120) Log.Warn($"System clock is off by {offset:F0}s; using network time.");
                return true;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;
            }
        }
        return false;
    }

    private static DateTime ReadNtp(ReadOnlySpan<byte> b)
    {
        ulong secs = BinaryPrimitives.ReadUInt32BigEndian(b);
        ulong frac = BinaryPrimitives.ReadUInt32BigEndian(b[4..]);
        var ms = secs * 1000 + frac * 1000 / 0x1_0000_0000UL;
        return new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms);
    }
}
