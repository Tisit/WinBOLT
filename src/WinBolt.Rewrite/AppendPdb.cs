using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using WinBolt.Core.Ir;
using WinBolt.Pdb;

namespace WinBolt.Rewrite;

/// <summary>
/// The PDB of an append-mode rewrite (DesignDoc Step 21): the original PDB with OMAP, the way
/// <see cref="WholeProgramOmap"/> does it for whole-program mode. Symbols and line numbers keep their
/// original addresses; a debugger translates an address in the rewritten image to the original one
/// (OMAP_TO_SRC) to name it, and a symbol's original address to where it now is (OMAP_FROM_SRC).
/// <list type="bullet">
/// <item>Everything in the original image maps to itself, in both directions, except the ranges
/// that moved: the trampolines and the stale original bodies keep their names.</item>
/// <item>A moved range maps to its copy (FROM_SRC), and the copy maps back to it (TO_SRC): one record
/// for a byte copy, one per instruction for a rebuilt function (hot and cold parts alike; a dropped
/// <c>jmp</c> maps to where its target went, and has no address of its own).</item>
/// <item>Padding, rebuilt tables and the appended sections have no counterpart.</item>
/// </list>
/// The image's CodeView record must name the new PDB with a new GUID (<see cref="Retire"/>), or
/// debuggers would load the original PDB and apply its addresses to the wrong code.
/// </summary>
public static class AppendPdb
{
    /// <returns>OMAP_TO_SRC (new → original) and OMAP_FROM_SRC (original → new), each ascending.</returns>
    public static (List<(uint Rva, uint RvaTo)> ToSource, List<(uint Rva, uint RvaTo)> FromSource) BuildOmap(BinaryImage original, RewriteResult result)
    {
        // Identity starts at the first section: a record whose target is 0 means "no counterpart", so the
        // headers (RVA 0) have none. Nothing in the headers needs a name.
        uint first = original.Sections.Min(s => s.Rva), end = original.SizeOfImage;
        var toSource = new List<(uint Start, uint End, uint To)> { (first, end, first) };
        var moved = new List<(uint Start, uint End, uint To)>();

        foreach (var m in result.Moved.OrderBy(m => m.Start))
        {
            if (m.AddressMap is null)
            {
                moved.Add((m.Start, m.Start + m.Length, m.CopyStart));
                toSource.Add((m.CopyStart, m.CopyStart + m.Length, m.Start));
                continue;
            }

            var function = original.Functions[m.FunctionId];
            foreach (var x in BlockRebuilder.Instructions(original, function))
            {
                if (!m.AddressMap.TryGetValue((uint)x.IP, out uint at))
                {
                    continue;
                }

                bool dropped = x.IsJmpShortOrNear && m.AddressMap.TryGetValue((uint)x.NearBranchTarget, out uint target) && target == at &&
                               x.NearBranchTarget != x.IP;
                moved.Add(((uint)x.IP, (uint)x.NextIP, at));
                if (!dropped)
                {
                    toSource.Add((at, at + (uint)x.Length, (uint)x.IP));
                }
            }
        }

        // Identity over the original image where nothing moved. A moved function's own bytes that no
        // instruction accounts for (table data inside its range) stay where they are.
        var fromSource = new List<(uint Start, uint End, uint To)>();
        uint cursor = first;
        foreach (var (start, stop, to) in moved.OrderBy(i => i.Start))
        {
            if (start > cursor)
            {
                fromSource.Add((cursor, start, cursor));
            }

            fromSource.Add((start, stop, to));
            cursor = Math.Max(cursor, stop);
        }

        if (end > cursor)
        {
            fromSource.Add((cursor, end, cursor));
        }

        return (WholeProgramOmap.Records(toSource), WholeProgramOmap.Records(fromSource));
    }

    /// <summary>
    /// Points the image's CodeView record at the new PDB: a GUID derived from the original's and the
    /// output's bytes, age 1, and its path (or, if that does not fit the record, its file name); the
    /// PE checksum is recomputed. Runs after verification, which compares the original sections with
    /// the input; only this record and the checksum change.
    /// </summary>
    /// <exception cref="RewriteRefusedException">The name does not fit the record.</exception>
    public static (Guid Guid, uint Age) Retire(BinaryImage original, RewriteResult result, string pdbPath)
    {
        var output = result.Output;
        foreach (var entry in original.DebugEntries.Where(e => e.Type == DebugDirectoryType.CodeView && e.SizeOfData >= 24))
        {
            int at = (int)entry.PointerToRawData;
            if (at + entry.SizeOfData > output.Length || !output.AsSpan(at, 4).SequenceEqual("RSDS"u8))
            {
                continue;
            }

            int capacity = (int)entry.SizeOfData - 24;
            byte[] path = Encoding.UTF8.GetBytes(pdbPath);
            if (path.Length >= capacity)
            {
                path = Encoding.UTF8.GetBytes(Path.GetFileName(pdbPath));
            }

            if (path.Length >= capacity)
            {
                throw new RewriteRefusedException($"the PDB name {Path.GetFileName(pdbPath)} does not fit the image's CodeView record ({capacity - 1} bytes)");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(output.AsSpan(at + 4, 16));
            hash.AppendData(output);
            var guid = new Guid(hash.GetHashAndReset().AsSpan(0, 16));
            guid.TryWriteBytes(output.AsSpan(at + 4, 16));
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at + 20), 1);
            output.AsSpan(at + 24, capacity).Clear();
            path.CopyTo(output, at + 24);

            var layout = new PeLayout(output);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.CheckSumOffset), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.CheckSumOffset), PeChecksum.Compute(output, layout.CheckSumOffset));
            return (guid, 1);
        }

        throw new RewriteRefusedException("the image has no CodeView record to point at a new PDB");
    }

    /// <summary>The PDB for <paramref name="result"/>: <paramref name="sourcePdb"/> plus OMAP, the new section table and the new identity.</summary>
    public static byte[] Write(BinaryImage original, RewriteResult result, byte[] sourcePdb, Guid guid, uint age)
    {
        var (toSource, fromSource) = BuildOmap(original, result);
        return PdbWriter.WithOmap(sourcePdb, guid, age, toSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(),
            fromSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(), WholeProgramOmap.SectionHeaders(result.Output));
    }

    /// <summary>Where the symbol at original address <paramref name="rva"/> is in the rewritten image (a function's entry: its copy).</summary>
    public static uint NewAddress(RewriteResult result, uint rva) =>
        result.Moved.FirstOrDefault(m => m.Start == rva) is { } moved ? moved.Map(rva) : rva;
}
