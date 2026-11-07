using System.Text.Json;
using System.Text.Json.Serialization;

namespace SiteLimiter.Core;

public static class Api
{
    public const int Port = 47811;
    public const string TokenHeader = "X-SL-Token";
    public static string BaseUrl => $"http://127.0.0.1:{Port}/";

    public static string DataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SiteLimiter");
    public static string TokenPath => Path.Combine(DataDir, "api.token");

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
    };

    public static readonly JsonSerializerOptions JsonFile = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
}

public sealed class ReportRequest
{
    public int SessionId { get; set; }
    public Dictionary<string, int> Seconds { get; set; } = new();
}

public sealed class RuleStatus
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public int LimitSeconds { get; set; }
    public int UsedSeconds { get; set; }
    public bool Blocked { get; set; }
}

public sealed class ReportResponse
{
    public bool Enforcing { get; set; }
    public bool SetupNeeded { get; set; }
    public List<string> BlockedDomains { get; set; } = new();
    public List<RuleStatus> Rules { get; set; } = new();
    public int IdleTimeoutSeconds { get; set; }
    public List<string> BrowserProcesses { get; set; } = new();
    public DateTime NextResetUtc { get; set; }
}
