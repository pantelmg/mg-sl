using System.Net;
using System.Net.Http.Json;
using SiteLimiter.Core;

namespace SiteLimiter.Agent;

internal sealed class ServiceClient : IDisposable
{
    private readonly HttpClient _http = new(new HttpClientHandler { UseProxy = false })
    {
        BaseAddress = new Uri(Api.BaseUrl),
        Timeout = TimeSpan.FromSeconds(5),
    };
    private string? _token;

    public string? Token => _token ??= ReadToken();

    private static string? ReadToken()
    {
        try { return File.ReadAllText(Api.TokenPath).Trim(); }
        catch { return null; }
    }

    public async Task<ReportResponse?> ReportAsync(ReportRequest req)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (Token is null) return null;
            using var msg = new HttpRequestMessage(HttpMethod.Post, "api/agent/report")
            {
                Content = JsonContent.Create(req, options: Api.Json),
            };
            msg.Headers.Add(Api.TokenHeader, Token);
            using var res = await _http.SendAsync(msg);
            if (res.StatusCode == HttpStatusCode.Unauthorized) { _token = null; continue; } // token rotated
            if (!res.IsSuccessStatusCode) return null;
            return await res.Content.ReadFromJsonAsync<ReportResponse>(Api.Json);
        }
        return null;
    }

    public void Dispose() => _http.Dispose();
}
