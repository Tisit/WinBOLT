using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// Code pages a run touches over time, for a layout (DesignDoc "Step 27"): the trace's first
/// touches (EtwLbrProfile.FirstTouches, in time order) replayed through a rewrite's address map.
/// An address in a moved function runs at its new place; a branch from code that did not move to
/// a moved entry with a trampoline also touches the trampoline's page. Without a rewrite the
/// curve is the original layout's. A model, not a measurement: it sees only sampled code, and
/// the loader maps headers, data and relocated pages too.
/// </summary>
public static class PageModel
{
    public const uint PageSize = 4096;

    /// <summary>Distinct code pages touched by each of <paramref name="fractions"/> of the first run's duration, and in all.</summary>
    public static (int[] ByFraction, int Total) Curve(BinaryImage image, RewriteResult? result, IReadOnlyList<(double Time, uint? From, uint? To)> touches, double[] fractions)
    {
        var moved = (result?.Moved ?? []).OrderBy(m => m.Start).ToArray();
        var starts = moved.Select(m => m.Start).ToArray();
        MovedFunction? Owner(uint rva)
        {
            int i = Array.BinarySearch(starts, rva);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && rva < moved[i].Start + moved[i].Length ? moved[i] : null;
        }

        uint Place(uint rva) => Owner(rva) is { } m
            ? m.AddressMap is null ? m.CopyStart + (rva - m.Start) : m.AddressMap.TryGetValue(rva, out uint at) ? at : m.CopyStart
            : rva;

        var pages = new HashSet<uint>();
        var counts = new int[fractions.Length];
        double begin = touches.Count > 0 ? touches[0].Time : 0, span = touches.Count > 0 ? Math.Max(1e-9, touches[^1].Time - begin) : 1;
        int next = 0;
        foreach (var (time, from, to) in touches)
        {
            while (next < fractions.Length && time - begin > fractions[next] * span)
            {
                counts[next++] = pages.Count;
            }

            if (from is { } f)
            {
                pages.Add(Place(f) / PageSize);
            }

            if (to is { } t)
            {
                pages.Add(Place(t) / PageSize);
                if (Owner(t) is { HasTrampoline: true } callee && t == callee.Start && (from is not { } source || Owner(source) is null))
                {
                    pages.Add(t / PageSize);
                }
            }
        }

        while (next < fractions.Length)
        {
            counts[next++] = pages.Count;
        }

        return (counts, pages.Count);
    }
}
