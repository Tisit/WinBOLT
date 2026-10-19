using WinBolt.Core.Ir;

namespace WinBolt.Core.Profile;

/// <summary>
/// Hot code footprint at one coverage level: the fewest blocks that account for
/// <see cref="Coverage"/> of profiled executed bytes, and how many 4 KB pages and 64-byte lines
/// they touch now against a packed layout. Page and line counts are what I-TLB and I-cache
/// pressure are made of, so the gap between "now" and "packed" is the headroom layout
/// optimization can recover (DesignDoc Stage 5, "Expected benefit").
/// </summary>
/// <param name="PagesPackedRanges">Hot function ranges packed together: what Stages 4–5 can do (the range is the unit of movement).</param>
/// <param name="PagesPackedBlocks">Hot blocks alone packed together: what Stage 6 can do.</param>
public sealed record FootprintLevel(
    double Coverage,
    int Blocks,
    int Functions,
    int PagesNow,
    int LinesNow,
    int PagesPackedRanges,
    int LinesPackedRanges,
    int PagesPackedBlocks,
    int LinesPackedBlocks);

public static class CodeFootprint
{
    public const int PageSize = 4096;
    public const int LineSize = 64;

    /// <summary>
    /// Blocks are weighted by executions × length (executed bytes) and taken hottest first, so
    /// the selection is the smallest set of bytes reaching each coverage. Packed sizes are ideal
    /// lower bounds that ignore alignment. Needs <see cref="BasicBlock.ExecutionCount"/>.
    /// </summary>
    public static IReadOnlyList<FootprintLevel> Compute(BinaryImage image, params double[] coverages) => Compute(image, null, coverages);

    /// <param name="placement">
    /// Where a block's code lives in a rewritten image (its new start RVA); null for the image as
    /// it is. "Now" pages and lines are then those of the rewritten layout.
    /// </param>
    public static IReadOnlyList<FootprintLevel> Compute(BinaryImage image, Func<Function, BasicBlock, ulong>? placement, params double[] coverages)
    {
        var blocks = image.Functions
            .SelectMany(f => f.BasicBlocks.Where(b => b.ExecutionCount > 0).Select(b => (Function: f, Block: b)))
            .OrderByDescending(x => x.Block.ExecutionCount)
            .ToList();
        double total = blocks.Sum(x => (double)x.Block.ExecutionCount!.Value * x.Block.Length);
        var levels = new List<FootprintLevel>();
        if (total == 0)
        {
            return levels;
        }

        foreach (double coverage in coverages.Order())
        {
            var selected = new List<(Function Function, BasicBlock Block)>();
            double covered = 0;
            foreach (var entry in blocks)
            {
                if (covered >= coverage * total)
                {
                    break;
                }

                selected.Add(entry);
                covered += (double)entry.Block.ExecutionCount!.Value * entry.Block.Length;
            }

            var pages = new HashSet<ulong>();
            var lines = new HashSet<ulong>();
            foreach (var (function, block) in selected)
            {
                ulong start = placement?.Invoke(function, block) ?? block.StartRva;
                for (ulong line = start / LineSize; line <= (start + block.Length - 1) / LineSize; line++)
                {
                    lines.Add(line);
                    pages.Add(line * LineSize / PageSize);
                }
            }

            var ranges = selected
                .Select(x => x.Function.Ranges.First(r => x.Block.StartRva >= r.StartRva && x.Block.StartRva < r.StartRva + r.Length))
                .Distinct()
                .ToList();
            long rangeBytes = ranges.Sum(r => (long)r.Length);
            long blockBytes = selected.Sum(x => (long)x.Block.Length);

            levels.Add(new FootprintLevel(
                coverage,
                selected.Count,
                selected.Select(x => x.Function).Distinct().Count(),
                pages.Count,
                lines.Count,
                Ceiling(rangeBytes, PageSize),
                Ceiling(rangeBytes, LineSize),
                Ceiling(blockBytes, PageSize),
                Ceiling(blockBytes, LineSize)));
        }

        return levels;
    }

    private static int Ceiling(long bytes, int unit) => (int)((bytes + unit - 1) / unit);
}
