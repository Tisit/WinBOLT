using System.Runtime.Intrinsics.X86;

namespace WinBolt.Core.Profile;

/// <summary>
/// The front-end capacities hot code competes for: L1 instruction cache and first-level
/// instruction TLB reach. <see cref="Source"/> says where each number came from; the advisor
/// quotes it, so an assumed value is never presented as measured.
/// </summary>
public sealed record CpuModel(int L1iBytes, int LineBytes, int ItlbEntries, string Source)
{
    /// <summary>A common x64 desktop core (32 KB L1i, 64-byte lines, 128-entry 4 KB I-TLB).</summary>
    public static readonly CpuModel Default = new(32 * 1024, 64, 128, "assumed defaults: 32 KB L1i, 64 B lines, 128-entry I-TLB");

    public int L1iLines => L1iBytes / LineBytes;

    /// <summary>
    /// Reads the L1 instruction cache from CPUID: leaf 4 (Intel deterministic cache parameters)
    /// or leaf 0x80000005 (AMD). The I-TLB size stays the default: its CPUID encodings are
    /// vendor- and generation-specific, so it is reported as assumed.
    /// </summary>
    public static CpuModel Detect()
    {
        if (!X86Base.IsSupported)
        {
            return Default;
        }

        var (_, ebx0, ecx0, edx0) = X86Base.CpuId(0, 0);
        string vendor = string.Concat(Chars(ebx0), Chars(edx0), Chars(ecx0));

        if (vendor == "GenuineIntel")
        {
            for (int subleaf = 0; subleaf < 16; subleaf++)
            {
                var (eax, ebx, ecx, _) = X86Base.CpuId(4, subleaf);
                int type = eax & 0x1F, level = (eax >> 5) & 0x7;
                if (type == 0)
                {
                    break;
                }

                if (type == 2 && level == 1) // instruction cache, level 1
                {
                    int ways = ((ebx >> 22) & 0x3FF) + 1, partitions = ((ebx >> 12) & 0x3FF) + 1;
                    int line = (ebx & 0xFFF) + 1, sets = ecx + 1;
                    return Default with
                    {
                        L1iBytes = ways * partitions * line * sets,
                        LineBytes = line,
                        Source = $"CPUID leaf 4: {ways * partitions * line * sets / 1024} KB L1i, {line} B lines; I-TLB 128 entries assumed",
                    };
                }
            }
        }
        else if (vendor == "AuthenticAMD")
        {
            var (_, _, _, edx) = X86Base.CpuId(unchecked((int)0x80000005), 0);
            int kb = (edx >> 24) & 0xFF, line = edx & 0xFF;
            if (kb > 0 && line > 0)
            {
                return Default with
                {
                    L1iBytes = kb * 1024,
                    LineBytes = line,
                    Source = $"CPUID 0x80000005: {kb} KB L1i, {line} B lines; I-TLB 128 entries assumed",
                };
            }
        }

        return Default;
    }

    private static string Chars(int register) =>
        new([(char)(register & 0xFF), (char)((register >> 8) & 0xFF), (char)((register >> 16) & 0xFF), (char)((register >> 24) & 0xFF)]);
}
