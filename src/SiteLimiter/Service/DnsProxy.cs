using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using SiteLimiter.Core;

namespace SiteLimiter.Service;

/// <summary>
/// Local DNS server on 127.0.0.1:53 and [::1]:53. Blocked names get 0.0.0.0 / :: answers,
/// everything else is forwarded unchanged to the original upstream resolvers.
/// </summary>
internal sealed class DnsProxy : IDisposable
{
    public enum Verdict { Forward, Block, NxDomain }

    private const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
    private readonly Func<string, Verdict> _classify;
    private readonly Func<IReadOnlyList<IPAddress>> _upstreams;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Socket> _udp = new();
    private readonly List<TcpListener> _tcp = new();

    public DnsProxy(Func<string, Verdict> classify, Func<IReadOnlyList<IPAddress>> upstreams)
    {
        _classify = classify;
        _upstreams = upstreams;
    }

    /// <summary>True when the IPv4 listener is up (the one Windows always uses).</summary>
    public bool IsListening { get; private set; }

    public void Start()
    {
        foreach (var addr in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            try
            {
                var s = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                s.ExclusiveAddressUse = true;
                // Windows reports ICMP "port unreachable" from a past send as a receive error; turn that off.
                if (OperatingSystem.IsWindows()) s.IOControl(SIO_UDP_CONNRESET, [0, 0, 0, 0], null);
                s.Bind(new IPEndPoint(addr, 53));
                _udp.Add(s);
                _ = Task.Run(() => UdpLoop(s));

                var t = new TcpListener(addr, 53);
                t.ExclusiveAddressUse = true;
                t.Start();
                _tcp.Add(t);
                _ = Task.Run(() => TcpLoop(t));

                if (addr.Equals(IPAddress.Loopback)) IsListening = true;
                Log.Info($"DNS proxy listening on {addr}:53");
            }
            catch (Exception ex)
            {
                // IPv6 loopback failing is harmless (IPv6 disabled); IPv4 failing means port 53 is taken.
                var msg = $"DNS proxy could not listen on {addr}:53 ({ex.Message})";
                if (addr.Equals(IPAddress.Loopback)) Log.Error(msg + " — Is another DNS server running?");
                else Log.Warn(msg);
            }
        }
    }

    private async Task UdpLoop(Socket s)
    {
        var buf = new byte[4096];
        EndPoint any = new IPEndPoint(s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try { r = await s.ReceiveFromAsync(buf, SocketFlags.None, any, _cts.Token); }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            var query = buf.AsSpan(0, r.ReceivedBytes).ToArray();
            var client = r.RemoteEndPoint;
            _ = Task.Run(async () =>
            {
                try
                {
                    var answer = await ResolveAsync(query, tcp: false);
                    if (answer is not null) await s.SendToAsync(answer, SocketFlags.None, client);
                }
                catch { /* client went away */ }
            });
        }
    }

    private async Task TcpLoop(TcpListener listener)
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(_cts.Token); }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            _ = Task.Run(async () =>
            {
                using (client)
                {
                    try
                    {
                        client.ReceiveTimeout = 5000;
                        var stream = client.GetStream();
                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                        cts.CancelAfter(TimeSpan.FromSeconds(10));
                        while (true)
                        {
                            var len = new byte[2];
                            await stream.ReadExactlyAsync(len, cts.Token);
                            var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
                            await stream.ReadExactlyAsync(query, cts.Token);
                            var answer = await ResolveAsync(query, tcp: true);
                            if (answer is null) return;
                            var framed = new byte[answer.Length + 2];
                            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)answer.Length);
                            answer.CopyTo(framed, 2);
                            await stream.WriteAsync(framed, cts.Token);
                        }
                    }
                    catch { /* EOF or timeout ends the connection */ }
                }
            });
        }
    }

    private async Task<byte[]?> ResolveAsync(byte[] query, bool tcp)
    {
        if (DnsMessage.TryParseQuery(query, out var q))
        {
            switch (_classify(q.Name))
            {
                case Verdict.Block: return DnsMessage.BuildResponse(query, q, DnsMessage.RcodeNoError);
                case Verdict.NxDomain: return DnsMessage.BuildResponse(query, q, DnsMessage.RcodeNxDomain);
            }
        }

        foreach (var upstream in _upstreams().Take(3))
        {
            try
            {
                var resp = tcp ? await ForwardTcpAsync(query, upstream) : await ForwardUdpAsync(query, upstream);
                if (resp is not null) return resp;
            }
            catch { /* try the next upstream */ }
        }
        return DnsMessage.BuildServFail(query);
    }

    private static async Task<byte[]?> ForwardUdpAsync(byte[] query, IPAddress upstream)
    {
        using var s = new Socket(upstream.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await s.ConnectAsync(new IPEndPoint(upstream, 53), cts.Token);
        await s.SendAsync(query, SocketFlags.None, cts.Token);
        var buf = new byte[4096];
        while (true)
        {
            var n = await s.ReceiveAsync(buf, SocketFlags.None, cts.Token);
            if (n >= 12 && buf[0] == query[0] && buf[1] == query[1]) return buf.AsSpan(0, n).ToArray();
        }
    }

    private static async Task<byte[]?> ForwardTcpAsync(byte[] query, IPAddress upstream)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        using var c = new TcpClient(upstream.AddressFamily);
        await c.ConnectAsync(upstream, 53, cts.Token);
        var stream = c.GetStream();
        var framed = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        await stream.WriteAsync(framed, cts.Token);
        var len = new byte[2];
        await stream.ReadExactlyAsync(len, cts.Token);
        var resp = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
        await stream.ReadExactlyAsync(resp, cts.Token);
        return resp;
    }

    public void Dispose()
    {
        _cts.Cancel();
        foreach (var s in _udp) s.Dispose();
        foreach (var t in _tcp) t.Stop();
        IsListening = false;
    }
}
