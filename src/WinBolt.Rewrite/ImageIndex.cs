using System.Runtime.CompilerServices;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// Range lookups over an image's base relocations and .pdata entries, sorted once per image. The
/// rewriters ask "which entries begin in this function" for every function, and a linear scan of
/// those tables per function is quadratic on a 100,000-function image.
/// </summary>
internal sealed class ImageIndex
{
    private static readonly ConditionalWeakTable<BinaryImage, ImageIndex> Cache = [];

    private readonly int _relocationCount;
    private readonly int _exceptionCount;
    private readonly uint[] _dir64;
    private readonly ExceptionInfo[] _entries;
    private readonly uint[] _entryBegins;

    private ImageIndex(BinaryImage image)
    {
        _relocationCount = image.Relocations.Count;
        _exceptionCount = image.ExceptionData.Count;
        _dir64 = image.Relocations.Where(r => r.Type == RelocationType.Dir64).Select(r => (uint)r.Rva).Order().ToArray();

        // A stable sort keeps the file order of entries sharing a begin address.
        _entries = image.ExceptionData.Select((e, i) => (e, i)).OrderBy(x => x.e.BeginAddress).ThenBy(x => x.i).Select(x => x.e).ToArray();
        _entryBegins = _entries.Select(e => e.BeginAddress).ToArray();
    }

    public static ImageIndex For(BinaryImage image)
    {
        if (!Cache.TryGetValue(image, out var index) || index._relocationCount != image.Relocations.Count || index._exceptionCount != image.ExceptionData.Count)
        {
            index = new ImageIndex(image);
            Cache.AddOrUpdate(image, index);
        }

        return index;
    }

    /// <summary>Whether an absolute (Dir64) base relocation lies in [<paramref name="start"/>, <paramref name="end"/>).</summary>
    public bool HasDir64In(uint start, uint end)
    {
        int i = LowerBound(_dir64, start);
        return i < _dir64.Length && _dir64[i] < end;
    }

    /// <summary>The .pdata entries whose begin address is in [<paramref name="start"/>, <paramref name="end"/>), by begin address.</summary>
    public IEnumerable<ExceptionInfo> EntriesBeginningIn(uint start, uint end)
    {
        for (int i = LowerBound(_entryBegins, start); i < _entries.Length && _entryBegins[i] < end; i++)
        {
            yield return _entries[i];
        }
    }

    private static int LowerBound(uint[] sorted, uint value)
    {
        int lo = 0, hi = sorted.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (sorted[mid] < value)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        return lo;
    }
}
