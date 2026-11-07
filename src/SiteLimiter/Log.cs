namespace SiteLimiter;

internal static class Log
{
    private static readonly object Gate = new();
    private static string? _path;
    public static bool Echo { get; set; }

    public static void Init(string directory, string fileName)
    {
        try
        {
            Directory.CreateDirectory(directory);
            _path = Path.Combine(directory, fileName);
        }
        catch { _path = null; }
    }

    public static void Info(string msg) => Write("INFO", msg);
    public static void Warn(string msg) => Write("WARN", msg);
    public static void Error(string msg, Exception? ex = null) => Write("ERROR", ex is null ? msg : $"{msg}: {ex}");

    private static void Write(string level, string msg)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level,-5} {msg}";
        if (Echo) Console.WriteLine(line);
        if (_path is null) return;
        lock (Gate)
        {
            try
            {
                var fi = new FileInfo(_path);
                if (fi.Exists && fi.Length > 1_000_000) File.Move(_path, _path + ".1", overwrite: true);
                File.AppendAllText(_path, line + Environment.NewLine);
            }
            catch { /* logging must never crash the app */ }
        }
    }
}
