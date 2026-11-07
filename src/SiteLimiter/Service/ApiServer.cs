using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SiteLimiter.Core;

namespace SiteLimiter.Service;

/// <summary>
/// Localhost-only HTTP API + dashboard. Every /api call needs the X-SL-Token header, which web
/// pages cannot send cross-origin (no CORS), and the Host header is pinned against DNS rebinding.
/// </summary>
internal sealed class ApiServer : IDisposable
{
    private readonly Engine _engine;
    private readonly HttpListener _listener = new();
    private readonly byte[] _dashboard;
    private readonly string _host = $"127.0.0.1:{Api.Port}";

    public ApiServer(Engine engine)
    {
        _engine = engine;
        using var s = typeof(ApiServer).Assembly.GetManifestResourceStream("dashboard.html")!;
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        _dashboard = ms.ToArray();
        _listener.Prefixes.Add(Api.BaseUrl);
    }

    public void Start()
    {
        try
        {
            _listener.Start();
            _ = Task.Run(AcceptLoop);
            Log.Info($"API listening on {Api.BaseUrl}");
        }
        catch (Exception ex) { Log.Error("API failed to start", ex); }
    }

    private async Task AcceptLoop()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { return; }
            _ = Task.Run(() => HandleAsync(ctx));
        }
    }

    private async Task HandleAsync(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        try
        {
            res.Headers["Cache-Control"] = "no-store";
            res.Headers["X-Content-Type-Options"] = "nosniff";
            res.Headers["X-Frame-Options"] = "DENY";

            if (!string.Equals(req.Headers["Host"], _host, StringComparison.OrdinalIgnoreCase))
            {
                await Send(res, 400, new { error = "Bad host" });
                return;
            }

            var path = req.Url!.AbsolutePath;
            if (req.HttpMethod == "GET" && path is "/" or "/index.html")
            {
                res.ContentType = "text/html; charset=utf-8";
                res.Headers["Content-Security-Policy"] =
                    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'";
                res.ContentLength64 = _dashboard.Length;
                await res.OutputStream.WriteAsync(_dashboard);
                res.Close();
                return;
            }

            if (!path.StartsWith("/api/", StringComparison.Ordinal))
            {
                await Send(res, 404, new { error = "Not found" });
                return;
            }

            var token = req.Headers[Api.TokenHeader] ?? "";
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(_engine.Token)))
            {
                await Send(res, 401, new { error = "Missing or wrong token. Open the dashboard from the tray icon." });
                return;
            }

            if (req.HttpMethod == "GET" && path == "/api/state")
            {
                await Send(res, 200, _engine.GetState());
                return;
            }
            if (req.HttpMethod == "GET" && path == "/api/stats")
            {
                await Send(res, 200, _engine.GetStats());
                return;
            }
            if (req.HttpMethod != "POST")
            {
                await Send(res, 405, new { error = "Method not allowed" });
                return;
            }

            using var body = await JsonDocument.ParseAsync(req.InputStream);
            var root = body.RootElement;
            if (path == "/api/agent/report")
            {
                await Send(res, 200, _engine.Report(root.Deserialize<ReportRequest>(Api.Json)!));
                return;
            }
            (int status, string? error) result = path switch
            {
                "/api/config" => _engine.UpdateConfig(
                    root.GetProperty("rules").Deserialize<List<Rule>>(Api.Json) ?? new(),
                    root.GetProperty("settings").Deserialize<Settings>(Api.Json) ?? new()),
                "/api/protection" => _engine.SetProtection(
                    root.GetProperty("mode").Deserialize<ProtectionMode>(Api.Json),
                    root.GetProperty("delayHours").GetInt32(),
                    root.TryGetProperty("password", out var pw) ? pw.GetString() : null),
                "/api/unlock/password" => _engine.UnlockPassword(root.GetProperty("password").GetString() ?? ""),
                "/api/unlock/request" => _engine.RequestUnlock(),
                "/api/unlock/claim" => await _engine.ClaimUnlockAsync(),
                "/api/unlock/cancel" => _engine.CancelUnlock(),
                "/api/lock" => _engine.LockNow(),
                "/api/uninstall/cancel" => _engine.CancelUninstall(),
                "/api/limits" => _engine.SetLimits(root.GetProperty("on").GetBoolean()),
                "/api/cloudflare" => _engine.SetCloudflare(root.GetProperty("mode").Deserialize<CloudflareFilter>(Api.Json)),
                "/api/uninstall/prepare" => _engine.PrepareUninstall(),
                _ => (404, "Not found"),
            };

            if (result.error is null) await Send(res, result.status, new { ok = true });
            else await Send(res, result.status, new { error = result.error });
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            await Send(res, 400, new { error = "Malformed request" });
        }
        catch (Exception ex)
        {
            Log.Error($"API {req.HttpMethod} {req.Url?.AbsolutePath}", ex);
            try { await Send(res, 500, new { error = "Internal error" }); } catch { }
        }
    }

    private static async Task Send(HttpListenerResponse res, int status, object payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Api.Json);
        res.StatusCode = status;
        res.ContentType = "application/json; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.Close();
    }

    public void Dispose()
    {
        try { _listener.Stop(); _listener.Close(); } catch { }
    }
}
