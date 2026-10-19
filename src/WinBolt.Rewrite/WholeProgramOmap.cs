using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// DesignDoc §6.2 milestone W4: the OMAP tables of a whole-program rewrite, the translation
/// Microsoft's post-link rewriter records instead of regenerating symbols (§3.3). A record
/// (Rva, RvaTo) maps [Rva, next record's Rva) to RvaTo + offset; RvaTo 0 has no counterpart.
/// <list type="bullet">
/// <item>A contribution that moved as a unit is one record each way.</item>
/// <item>A rebuilt function is one record per instruction (merged where consecutive
/// instructions stay consecutive); its inserted jumps and padding map to the instruction before
/// them, and its dropped table data and padding have no counterpart.</item>
/// <item>Everything that did not move (headers, data sections, code-section bytes outside the
/// code areas) maps to itself; the appended data section has no counterpart.</item>
/// </list>
/// </summary>
public static class WholeProgramOmap
{
    /// <summary>The image's IMAGE_SECTION_HEADERs, as the PDB's SectionHdr stream holds them.</summary>
    public static byte[] SectionHeaders(byte[] image)
    {
        var layout = new PeLayout(image);
        return image.AsSpan(layout.SectionTable, layout.NumberOfSections * PeLayout.SectionHeaderSize).ToArray();
    }

    /// <returns>OMAP_TO_SRC (new → original) and OMAP_FROM_SRC (original → new), each ascending.</returns>
    public static (List<(uint Rva, uint RvaTo)> ToSource, List<(uint Rva, uint RvaTo)> FromSource) Build(BinaryImage original, WholeProgramResult result)
    {
        var toSource = new List<(uint Start, uint End, uint To)>();
        var fromSource = new List<(uint Start, uint End, uint To)>();

        // What did not move: headers, sections without code, and code sections outside their code areas.
        var areas = WholeProgramRewriter.CodeAreas(original, result).ToList();
        var identity = new List<(uint Start, uint End)> { (0, original.Sections.Min(s => s.Rva)) };
        foreach (var section in original.Sections)
        {
            uint start = section.Rva, end = section.Rva + Math.Max(section.MappedSize, result.GrownSections.GetValueOrDefault(section.Name));
            foreach (var (areaStart, areaEnd) in areas.Where(a => a.Start < end && a.End > start).OrderBy(a => a.Start))
            {
                if (areaStart > start)
                {
                    identity.Add((start, areaStart));
                }

                start = Math.Max(start, areaEnd);
            }

            if (end > start)
            {
                identity.Add((start, end));
            }
        }

        foreach (var (start, end) in identity)
        {
            toSource.Add((start, end, start));
            fromSource.Add((start, end, start));
        }

        foreach (var p in result.Placed)
        {
            var c = p.Contribution;
            if (!result.Rebuilt.TryGetValue(c.Rva, out var r))
            {
                toSource.Add((p.NewRva, p.NewRva + c.Size, c.Rva));
                fromSource.Add((c.Rva, c.Rva + c.Size, p.NewRva));
                continue;
            }

            // Per instruction. A dropped jmp maps to where its target went: the target's own
            // instruction, not the jmp, is what lives at that new address.
            foreach (var x in BlockRebuilder.Instructions(original, r.Function))
            {
                if (!r.AddressMap.TryGetValue((uint)x.IP, out uint at))
                {
                    continue;
                }

                bool dropped = x.IsJmpShortOrNear && r.AddressMap.TryGetValue((uint)x.NearBranchTarget, out uint target) && target == at &&
                               x.NearBranchTarget != x.IP;
                fromSource.Add(((uint)x.IP, (uint)x.NextIP, at));
                if (!dropped)
                {
                    toSource.Add((at, at + (uint)x.Length, (uint)x.IP));
                }
            }
        }

        return (Records(toSource), Records(fromSource));
    }

    /// <summary>
    /// Ascending records from intervals: each starts a record; a gap after an interval gets a
    /// record with no counterpart. Where intervals overlap (a re-encoded instruction is longer
    /// than the original), the later start wins. Consecutive records that continue each other merge.
    /// </summary>
    internal static List<(uint Rva, uint RvaTo)> Records(List<(uint Start, uint End, uint To)> intervals)
    {
        var sorted = intervals.Where(i => i.End > i.Start).OrderBy(i => i.Start).ThenBy(i => i.End).ToList();
        var records = new List<(uint Rva, uint RvaTo)>();
        void Emit(uint rva, uint to)
        {
            if (records.Count > 0 && records[^1].Rva == rva)
            {
                records[^1] = (rva, to);
                return;
            }

            // Merge: the previous record already maps rva to 'to'.
            if (records.Count > 0 && records[^1].RvaTo != 0 && to != 0 && records[^1].RvaTo + (rva - records[^1].Rva) == to)
            {
                return;
            }

            if (records.Count > 0 && records[^1].RvaTo == 0 && to == 0)
            {
                return;
            }

            records.Add((rva, to));
        }

        for (int i = 0; i < sorted.Count; i++)
        {
            var (start, end, to) = sorted[i];
            if (i > 0 && start < sorted[i - 1].End && start == sorted[i - 1].Start)
            {
                continue; // same start: the first (shorter) interval wins
            }

            Emit(start, to);
            if (i + 1 == sorted.Count || sorted[i + 1].Start > end)
            {
                Emit(end, 0);
            }
        }

        return records;
    }
}
