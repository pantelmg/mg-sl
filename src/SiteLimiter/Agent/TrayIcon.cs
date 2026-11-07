using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SiteLimiter.Agent;

/// <summary>
/// Loads the MG gauge icon at the tray's pixel size, in the variant that contrasts with the
/// taskbar: dark glyph on a light taskbar, light glyph on a dark one.
/// </summary>
internal static class TrayIcon
{
    private const int SM_CXSMICON = 49, SM_CYSMICON = 50;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateIconFromResourceEx(byte[] bits, uint size, bool icon, uint version, int cx, int cy, uint flags);

    [DllImport("user32.dll")]
    public static extern bool DestroyIcon(IntPtr icon);

    /// <summary>True when the taskbar/system theme is light (Windows 10 1903+).</summary>
    public static bool TaskbarIsLight()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("SystemUsesLightTheme") is int v && v == 1;
        }
        catch { return false; } // older Windows: taskbar is dark
    }

    /// <summary>Creates an HICON the caller must free with DestroyIcon. Returns IntPtr.Zero on failure.</summary>
    public static IntPtr Load()
    {
        var resource = TaskbarIsLight() ? "tray-dark.ico" : "tray-light.ico";
        var cx = Math.Max(16, GetSystemMetrics(SM_CXSMICON));
        var cy = Math.Max(16, GetSystemMetrics(SM_CYSMICON));
        try
        {
            using var s = typeof(TrayIcon).Assembly.GetManifestResourceStream(resource);
            if (s is null) return IntPtr.Zero;
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            var image = PickImage(ms.ToArray(), cx);
            return image is null ? IntPtr.Zero : CreateIconFromResourceEx(image, (uint)image.Length, true, 0x00030000, cx, cy, 0);
        }
        catch (Exception ex)
        {
            Log.Error("Tray icon load failed", ex);
            return IntPtr.Zero;
        }
    }

    /// <summary>From a .ico file, the image data of the smallest entry at least `size` wide (else the largest).</summary>
    private static byte[]? PickImage(byte[] ico, int size)
    {
        var span = ico.AsSpan();
        if (span.Length < 6 || BinaryPrimitives.ReadUInt16LittleEndian(span[2..]) != 1) return null;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(span[4..]);
        int bestW = 0, bestLen = 0, bestOff = 0;
        for (var i = 0; i < count; i++)
        {
            var e = span.Slice(6 + 16 * i, 16);
            var w = e[0] == 0 ? 256 : e[0];
            var len = (int)BinaryPrimitives.ReadUInt32LittleEndian(e[8..]);
            var off = (int)BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
            var better = bestW == 0
                || (w >= size && (bestW < size || w < bestW))
                || (bestW < size && w > bestW);
            if (better) { bestW = w; bestLen = len; bestOff = off; }
        }
        return bestW == 0 || bestOff + bestLen > ico.Length ? null : span.Slice(bestOff, bestLen).ToArray();
    }
}
