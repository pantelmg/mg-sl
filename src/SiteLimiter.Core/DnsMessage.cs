using System.Buffers.Binary;
using System.Text;

namespace SiteLimiter.Core;

public readonly record struct DnsQuestion(ushort Id, string Name, ushort Type, ushort Class, int QuestionEnd);

/// <summary>Minimal DNS wire-format helpers: read the question of a query, synthesize answers.</summary>
public static class DnsMessage
{
    public const ushort TypeA = 1, TypeAAAA = 28;
    public const byte RcodeNoError = 0, RcodeServFail = 2, RcodeNxDomain = 3;

    public static bool TryParseQuery(ReadOnlySpan<byte> msg, out DnsQuestion q)
    {
        q = default;
        if (msg.Length < 17) return false;
        if ((msg[2] & 0x80) != 0) return false;                      // QR set: not a query
        if (BinaryPrimitives.ReadUInt16BigEndian(msg[4..]) == 0) return false;

        var sb = new StringBuilder();
        var pos = 12;
        while (true)
        {
            if (pos >= msg.Length) return false;
            int len = msg[pos++];
            if (len == 0) break;
            if ((len & 0xC0) != 0) return false;                     // no compression in a question
            if (pos + len > msg.Length || sb.Length + len > 254) return false;
            if (sb.Length > 0) sb.Append('.');
            foreach (var b in msg.Slice(pos, len))
                sb.Append(b is >= (byte)'A' and <= (byte)'Z' ? (char)(b + 32) : (char)b);
            pos += len;
        }
        if (pos + 4 > msg.Length) return false;
        q = new DnsQuestion(
            BinaryPrimitives.ReadUInt16BigEndian(msg),
            sb.ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]),
            BinaryPrimitives.ReadUInt16BigEndian(msg[(pos + 2)..]),
            pos + 4);
        return true;
    }

    /// <summary>Answers A with 0.0.0.0, AAAA with ::, anything else with an empty NOERROR (or the given rcode).</summary>
    public static byte[] BuildResponse(ReadOnlySpan<byte> query, DnsQuestion q, byte rcode, uint ttl = 30)
    {
        var addrLen = rcode == RcodeNoError && q.Class == 1
            ? q.Type switch { TypeA => 4, TypeAAAA => 16, _ => 0 }
            : 0;
        var questionLen = q.QuestionEnd - 12;
        var answerLen = addrLen > 0 ? 12 + addrLen : 0;
        var buf = new byte[12 + questionLen + answerLen];

        BinaryPrimitives.WriteUInt16BigEndian(buf, q.Id);
        buf[2] = (byte)(0x80 | (query[2] & 0x79));                     // QR + opcode + RD
        buf[3] = (byte)(0x80 | (rcode & 0x0F));                        // RA + rcode
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(6), (ushort)(addrLen > 0 ? 1 : 0));
        query.Slice(12, questionLen).CopyTo(buf.AsSpan(12));

        if (addrLen > 0)
        {
            var a = buf.AsSpan(12 + questionLen);
            a[0] = 0xC0; a[1] = 0x0C;                                  // pointer to the question name
            BinaryPrimitives.WriteUInt16BigEndian(a[2..], q.Type);
            BinaryPrimitives.WriteUInt16BigEndian(a[4..], 1);
            BinaryPrimitives.WriteUInt32BigEndian(a[6..], ttl);
            BinaryPrimitives.WriteUInt16BigEndian(a[10..], (ushort)addrLen);
            // address bytes stay zero: 0.0.0.0 / ::
        }
        return buf;
    }

    /// <summary>SERVFAIL for a query we could not even parse (keeps the client from hanging).</summary>
    public static byte[]? BuildServFail(ReadOnlySpan<byte> query)
    {
        if (query.Length < 12) return null;
        var buf = new byte[12];
        query[..2].CopyTo(buf);
        buf[2] = (byte)(0x80 | (query[2] & 0x79));
        buf[3] = 0x80 | RcodeServFail;
        return buf;
    }
}
