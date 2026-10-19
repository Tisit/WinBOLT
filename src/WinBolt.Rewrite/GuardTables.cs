using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// The load config's longjmp and EH-continuation tables in append mode. They list code RVAs the
/// OS accepts as a longjmp or exception continuation target (CFG longjmp checks; /guard:ehcont
/// with user shadow stacks). A moved function's targets run in its copy too (a setjmp call in
/// the copy returns there; an SEH copy's rebased scope table continues there; an FH4 copy's
/// continuations are function-relative), so the output gets new tables in .wbdata: every original
/// entry (the original body stays intact and may still be continued into) plus each moved
/// target's new address, sorted. The load config's table pointer and count are re-pointed.
/// </summary>
internal static class GuardTables
{
    internal const int LongJumpTableField = 0xB0;
    internal const int EhContinuationTableField = 0x108;
    private const int GuardFlagsField = 0x90;
    private const uint GuardCfFunctionTableSizeMask = 0xF0000000;

    /// <summary>The (table VA, count) field pairs present in the image's load config.</summary>
    internal static IEnumerable<int> Fields(BinaryImage image) =>
        new[] { LongJumpTableField, EhContinuationTableField }.Where(f => LoadConfigSize(image) >= f + 16);

    /// <summary>
    /// Null when the tables can be rewritten: a file-backed load config whose guard flags declare
    /// plain 4-byte entries (with flag bytes the entry layout of these tables is not settled).
    /// </summary>
    internal static string? Problem(BinaryImage image)
    {
        if (image.LoadConfig is not { } tables || (tables.GuardLongJumpTargetTable.Count == 0 && (tables.GuardEhContinuationTable?.Count ?? 0) == 0))
        {
            return null;
        }

        if (ConfigOffset(image) is null || LoadConfigSize(image) < GuardFlagsField + 4)
        {
            return "the load config is not file-backed";
        }

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(image.ReadFrom(Config(image)!.Rva + GuardFlagsField).Span);
        return (flags & GuardCfFunctionTableSizeMask) != 0 ? "the guard tables carry flag bytes" : null;
    }

    internal static List<uint> Entries(BinaryImage image, int field) => field == LongJumpTableField
        ? image.LoadConfig?.GuardLongJumpTargetTable ?? []
        : image.LoadConfig?.GuardEhContinuationTable ?? [];

    internal static string Name(int field) => field == LongJumpTableField ? "GuardLongJumpTargetTable" : "GuardEHContinuationTable";

    /// <summary>The table the output needs: the original entries plus the new address of each one inside a moved function.</summary>
    internal static List<uint> Extended(int field, IEnumerable<uint> entries, IReadOnlyList<MovedFunction> moved, Func<MovedFunction, uint, uint?> map)
    {
        var sorted = moved.OrderBy(m => m.Start).ToArray();
        var starts = sorted.Select(m => m.Start).ToArray();
        var result = new SortedSet<uint>();
        foreach (uint t in entries)
        {
            result.Add(t);
            int i = Array.BinarySearch(starts, t);
            i = i >= 0 ? i : ~i - 1;
            if (i >= 0 && t < sorted[i].Start + sorted[i].Length)
            {
                result.Add(map(sorted[i], t) ?? throw new RewriteRefusedException($"{Name(field)}: 0x{t:X} in {sorted[i].Name} has no new address"));
            }
        }

        return result.ToList();
    }

    /// <summary>Points the load config's field pair at a table at <paramref name="rva"/>.</summary>
    internal static void Repoint(BinaryImage image, byte[] output, int field, uint rva, int count)
    {
        int at = ConfigOffset(image)!.Value + field;
        BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(at), image.ImageBase + rva);
        BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(at + 8), (ulong)count);
    }

    /// <summary>RVA ranges of the field pairs a rewrite may change.</summary>
    internal static IEnumerable<(uint Start, uint End)> FieldRanges(BinaryImage image) =>
        Config(image) is { } config ? Fields(image).Select(f => (config.Rva + (uint)f, config.Rva + (uint)f + 16)) : [];

    private static DataDirectory? Config(BinaryImage image) => WholeProgramRewriter.Directory(image, "LoadConfig");

    private static int? ConfigOffset(BinaryImage image) => Config(image) is { } c ? WholeProgramRewriter.FileOffset(image, c.Rva) : null;

    private static uint LoadConfigSize(BinaryImage image) =>
        Config(image) is { } c && image.ReadFrom(c.Rva).Span is { Length: >= 4 } bytes ? BinaryPrimitives.ReadUInt32LittleEndian(bytes) : 0;
}
