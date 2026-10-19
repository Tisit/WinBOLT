using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>A code contribution and where the whole-program layout put it (a rebuilt function: its hot part).</summary>
public readonly record struct PlacedContribution(SectionContribution Contribution, uint NewRva)
{
    public int Delta => (int)(NewRva - Contribution.Rva);
}

/// <summary>A function re-encoded in its block order by the whole-program layout (milestone W3).</summary>
public sealed class RebuiltFunction
{
    public required Function Function { get; init; }

    public required BlockOrder Order { get; init; }

    public uint HotStart { get; set; }

    public uint HotLength { get; set; }

    /// <summary>Where the cold blocks went; 0 when the function has none.</summary>
    public uint ColdStart { get; set; }

    public uint ColdLength { get; set; }

    /// <summary>Original instruction RVA → new RVA, plus the unwind entries' and the range's ends.</summary>
    public Dictionary<uint, uint> AddressMap { get; set; } = [];

    /// <summary>Its jump tables, rebuilt in .wbdata.</summary>
    public List<CopiedTable> Tables { get; } = [];

    /// <summary>Its unwind entries at their new addresses (UNWIND_INFO unchanged).</summary>
    public List<CopiedPdata> Pdata { get; } = [];

    /// <summary>One chained entry per cold segment, with a new UNWIND_INFO in .wbdata.</summary>
    public List<CopiedPdata> ColdEntries { get; } = [];

    internal byte[] Bytes { get; set; } = [];

    internal byte[] ColdBytes { get; set; } = [];

    internal IReadOnlyList<ColdSegment> ColdSegments { get; set; } = [];

    internal uint ReservedHot { get; set; }

    internal uint ReservedCold { get; set; }

    internal uint Residue { get; set; }

    internal int ColdCount { get; set; }
}

/// <summary>What a whole-program rewrite did (DesignDoc §6.2, milestones W2 and W3).</summary>
public sealed class WholeProgramResult
{
    public byte[] Output { get; set; } = [];

    public required WholeProgramGateReport Gate { get; init; }

    /// <summary>Every code contribution, in original order, with its new address.</summary>
    public List<PlacedContribution> Placed { get; } = [];

    /// <summary>Rebuilt functions by the RVA of their contribution.</summary>
    public Dictionary<uint, RebuiltFunction> Rebuilt { get; } = [];

    /// <summary>Hot functions that block layout wanted but that moved as whole contributions, with why.</summary>
    public List<(Function Function, string Reason)> NotRebuilt { get; } = [];

    public int FixupsRewritten { get; set; }

    public int ExportsMapped { get; set; }

    public int CfgEntriesMapped { get; set; }

    public int RelocationsMoved { get; set; }

    public List<string> Warnings { get; } = [];

    /// <summary>W4: the GUID the image's CodeView record names for the new PDB; null when no PDB was asked for.</summary>
    public Guid? PdbGuid { get; set; }

    public uint PdbAge { get; set; }

    private uint[]? _starts;

    /// <summary>The exception directory, whose entries are re-sorted after their fields are fixed up.</summary>
    public (uint Rva, uint Size) ExceptionTable { get; set; }

    /// <summary>New index of each original .pdata entry (identity until the table is sorted).</summary>
    public int[] PdataOrder { get; set; } = [];

    /// <summary>
    /// The appended executable section holding the coldest contributions that no longer fit in
    /// their own section (§6.2 "Where the code goes"); Size 0 when nothing spilled.
    /// </summary>
    public (uint Rva, uint Size, uint RawOffset, uint RawSize) Spill { get; set; }

    /// <summary>The appended data section (rebuilt functions: .pdata, jump tables, cold UNWIND_INFO); Size 0 without rebuilt functions.</summary>
    public (uint Rva, uint Size, uint RawOffset, uint RawSize) Data { get; set; }

    /// <summary>Sections the rewrite appended (their headers follow the original ones).</summary>
    public int AddedSections { get; set; }

    public bool InSpill(uint rva) => Spill.Size > 0 && rva >= Spill.Rva && rva - Spill.Rva < Spill.Size;

    /// <summary>CFG tables (RVA, size) the rewrite mapped and re-sorted: their entries are checked as sets, not per fixup.</summary>
    public List<(uint Rva, uint Size)> CfgTables { get; } = [];

    /// <summary>Sections whose virtual size grew into their file-backed slack: name → new virtual size.</summary>
    public Dictionary<string, uint> GrownSections { get; } = [];

    /// <summary>The contribution holding <paramref name="rva"/>, or null outside code contributions.</summary>
    public PlacedContribution? Owner(uint rva)
    {
        _starts ??= Placed.Select(p => p.Contribution.Rva).ToArray();
        int i = Array.BinarySearch(_starts, rva);
        i = i >= 0 ? i : ~i - 1;
        return i >= 0 && rva < Placed[i].Contribution.Rva + Placed[i].Contribution.Size ? Placed[i] : null;
    }

    /// <summary>
    /// New address of a byte: code moves with its contribution (an instruction of a rebuilt
    /// function through its address map), a .pdata field with its sorted entry; everything else stays.
    /// </summary>
    public uint MapSite(uint rva)
    {
        if (Owner(rva) is { } p)
        {
            return Rebuilt.TryGetValue(p.Contribution.Rva, out var r) ? Mapped(r, rva) : (uint)(rva + p.Delta);
        }

        uint offset = rva - ExceptionTable.Rva;
        if (rva >= ExceptionTable.Rva && offset < ExceptionTable.Size && offset / 12 < PdataOrder.Length)
        {
            return ExceptionTable.Rva + (uint)PdataOrder[offset / 12] * 12 + offset % 12;
        }

        return rva;
    }

    /// <summary>
    /// New value of a reference: the linker resolved it against <paramref name="target"/> (a
    /// symbol) plus an addend, so it moves with the target's contribution even when the value
    /// itself is that contribution's end (a .pdata EndAddress), which is the next one's start.
    /// </summary>
    public uint MapValue(uint target, uint value) =>
        Owner(target) is { } p
            ? Rebuilt.TryGetValue(p.Contribution.Rva, out var r) ? Mapped(r, value) : (uint)(value + p.Delta)
            : value;

    private static uint Mapped(RebuiltFunction r, uint rva) =>
        r.AddressMap.TryGetValue(rva, out uint mapped)
            ? mapped
            : throw new RewriteRefusedException($"0x{rva:X} in rebuilt {r.Function.DisplayName} is not an instruction or unwind boundary");
}

/// <summary>
/// DesignDoc §6.2 milestones W2 and W3: whole-program layout. Every code contribution moves as
/// a unit into the requested order, in place in its original section, or, with a block order,
/// hot functions are re-encoded (<see cref="BlockRebuilder"/>): hot parts in function order, cold
/// parts after all hot code. Every reference is re-resolved from the linker's fixup records; the
/// structures the linker synthesized without object relocations (entry point, export table, CFG
/// tables, base relocations, .pdata) are regenerated. Refused unless <see cref="WholeProgramGate"/> passes.
/// </summary>
public static class WholeProgramRewriter
{
    private const uint AlignMask = 0x00F00000;
    private const uint DefaultCodeAlignment = 16;
    private const int RelocDir64 = 10;
    private const int RelocHighLow = 3;
    private const uint GuardCfFunctionTableSizeMask = 0xF0000000;
    private const int JccStep = (int)BlockRebuilder.ShiftStep;
    private const uint PlaceholderTable = BlockRebuilder.PlaceholderTable;
    private const uint TrialColdDistance = BlockRebuilder.TrialColdDistance;
    private const int MaxLayoutRounds = 8;
    public const string SpillName = ".wbcold";
    public const string DataName = ".wbdata";
    private const uint SpillCharacteristics = 0x60000020; // CODE | EXECUTE | READ
    private const uint DataCharacteristics = 0x40000040;  // INITIALIZED_DATA | READ

    /// <summary>One thing the layout places: a contribution (a rebuilt function's hot part), or a rebuilt function's cold part.</summary>
    private readonly record struct Item(SectionContribution Contribution, bool Cold);

    /// <param name="order">
    /// Code contributions to place first, in this order (e.g. the C3 order's functions); every
    /// other contribution follows in its original order. Null keeps the original order (a no-op
    /// apart from the debug record).
    /// </param>
    /// <param name="jccErratum">
    /// Place each contribution holding executed functions at the 4-byte step (modulo 32) that puts
    /// the fewest executed branches on a 32-byte boundary (Intel's JCC erratum; Stage 6 step 5 does
    /// the same for copies); rebuilt functions are padded inside as well.
    /// </param>
    /// <param name="blockOrder">
    /// W3: each executed function's block order (Stage 6 layout, e.g. <see cref="BlockLayout.Order"/>).
    /// Functions that qualify are re-encoded in it, their cold blocks placed after all hot code;
    /// the rest move as whole contributions. Null: whole contributions only (W2).
    /// </param>
    /// <param name="alignLoops">Rebuilt functions: start hot loop heads on a 32-byte boundary.</param>
    /// <param name="layoutShift">
    /// Start the ordered code this many bytes (whole cache lines) later: the same layout at another
    /// alignment, for measuring how much of a difference is layout luck (DesignDoc §6.2).
    /// </param>
    /// <param name="pdbPath">
    /// W4: the path of the PDB that will describe the output (<see cref="WholeProgramOmap"/> plus
    /// the PDB writer): the RSDS record gets its name and a new GUID (<see cref="WholeProgramResult.PdbGuid"/>).
    /// Null: the GUID is only scrambled, so the old PDB is rejected rather than misapplied.
    /// </param>
    /// <exception cref="RewriteRefusedException">The gate or a structural precondition failed.</exception>
    public static WholeProgramResult Rewrite(BinaryImage image, byte[] file, IReadOnlyList<SectionContribution>? order = null, bool jccErratum = false,
        Func<Function, BlockOrder?>? blockOrder = null, bool alignLoops = false, string? pdbPath = null, uint layoutShift = 0)
    {
        if (layoutShift % FunctionRewriter.LayoutShiftUnit != 0)
        {
            throw new ArgumentException($"the layout shift must be a multiple of {FunctionRewriter.LayoutShiftUnit} bytes", nameof(layoutShift));
        }

        FunctionRewriter.RefuseNativeAot(image);
        var gate = WholeProgramGate.Check(image);
        if (!gate.Passed)
        {
            var failed = gate.Checks.First(c => !c.Passed);
            throw new RewriteRefusedException($"whole-program gate: {failed.Name}: {failed.Detail}");
        }

        if (image.ExceptionData.Any(e => (e.UnwindInfoAddress & 1) != 0))
        {
            throw new RewriteRefusedException("indirect unwind chains (.pdata entries naming other .pdata entries) are not supported");
        }

        if (image.LoadConfig is { HasXfg: true })
        {
            throw new RewriteRefusedException("XFG images are not supported yet (type hashes precede function entries)");
        }

        var code = image.SectionContributions.Where(c => image.FindSection(c.Rva) is { IsExecutable: true }).OrderBy(c => c.Rva).ToList();
        var starts = code.Select(c => c.Rva).ToArray();
        SectionContribution? OwnerOf(uint rva)
        {
            int i = Array.BinarySearch(starts, rva);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && rva < code[i].Rva + code[i].Size ? code[i] : null;
        }

        var rank = new Dictionary<uint, int>();
        foreach (var c in order ?? [])
        {
            rank.TryAdd(c.Rva, rank.Count);
        }

        var result = new WholeProgramResult { Gate = gate };

        // Executed functions by the contribution holding their entry (JCC placement, rebuilding).
        var hot = new Dictionary<uint, List<Function>>();
        foreach (var f in image.Functions.Where(f => f.BasicBlocks.Any(b => b.ExecutionCount > 0)))
        {
            if (OwnerOf(f.EntryRva) is { } c)
            {
                (hot.TryGetValue(c.Rva, out var list) ? list : hot[c.Rva] = []).Add(f);
            }
        }

        var rebuilt = blockOrder is not null && order is not null
            ? SelectRebuilt(image, file, code, OwnerOf, order, hot, blockOrder, jccErratum, alignLoops, result)
            : [];

        // .wbdata, when functions are rebuilt: the complete .pdata, their jump tables, cold UNWIND_INFO.
        var headers = new PeLayout(file);
        var last = image.Sections.MaxBy(s => s.Rva)!;
        uint appendRva = PeLayout.Align(last.Rva + last.MappedSize, headers.SectionAlignment);
        uint pdataCount = (uint)(image.ExceptionData.Count + rebuilt.Values.Sum(r => r.ColdCount));
        uint tablesAt = appendRva + 12 * pdataCount;
        uint cursorTables = tablesAt;
        foreach (var (rva, r) in rebuilt)
        {
            var c = code.First(c => c.Rva == rva);
            foreach (var table in r.Function.JumpTables.GroupBy(t => t.Rva).Select(g => g.First()))
            {
                uint dwords = cursorTables;
                cursorTables += 4 * (uint)table.EntryCount;

                // A two-level switch's byte table inside the contribution is not carried over with
                // the re-encoded code: it gets a copy here, after the dword table.
                uint? index = null;
                if (table.IndexTableRva is { } original && original >= c.Rva && original < c.Rva + c.Size)
                {
                    index = cursorTables;
                    cursorTables += (uint)table.IndexEntryCount;
                }

                r.Tables.Add(new CopiedTable((uint)table.Rva, dwords, table.EntryCount, (uint)table.LoadRva!.Value, (uint?)table.IndexLoadRva) { NewIndexRva = index });
                cursorTables = PeLayout.Align(cursorTables, 4);
            }
        }

        uint coldUnwindAt = PeLayout.Align(cursorTables, 4);
        uint dataSize = rebuilt.Count == 0 ? 0 : coldUnwindAt + 16 * (uint)rebuilt.Values.Sum(r => r.ColdCount) - appendRva;
        uint spillBase = dataSize == 0 ? appendRva : PeLayout.Align(appendRva + dataSize, headers.SectionAlignment);

        // Layout, then encode the rebuilt functions at their final addresses; repeat while an
        // encoding outgrew its slot (branch forms depend on distances).
        Dictionary<uint, uint> hotAt = [], coldAt = [];
        List<Item> spilled = [];
        for (int round = 0; ; round++)
        {
            (hotAt, coldAt, spilled) = Layout(image, code, rank, order is not null, rebuilt, hot, jccErratum, alignLoops, spillBase, result, layoutShift);
            uint NewAddress(uint target) => OwnerOf(target) is { } c
                ? rebuilt.ContainsKey(c.Rva) ? hotAt[c.Rva] + (target - c.Rva) : hotAt[c.Rva] + (target - c.Rva)
                : target;

            bool fits = true;
            foreach (var (rva, r) in rebuilt)
            {
                var encoded = EncodeAt(image, r, hotAt[rva], coldAt.GetValueOrDefault(rva, hotAt[rva] + TrialColdDistance), NewAddress, jccErratum, alignLoops, out string? error)
                    ?? throw new RewriteRefusedException($"{r.Function.DisplayName} does not encode at its final address: {error}");
                if (BlockRebuilder.CheckPrologues(image, r.Function, encoded) is { } problem)
                {
                    throw new RewriteRefusedException($"{r.Function.DisplayName}: {problem} at its final address");
                }

                if (encoded.ColdSegments.Count != r.ColdCount)
                {
                    throw new RewriteRefusedException($"{r.Function.DisplayName}: {encoded.ColdSegments.Count} cold segments at the final address, {r.ColdCount} in the trial");
                }

                if (encoded.Bytes.Length > r.ReservedHot || encoded.ColdBytes.Length > r.ReservedCold)
                {
                    r.ReservedHot = Math.Max(r.ReservedHot, (uint)encoded.Bytes.Length);
                    r.ReservedCold = Math.Max(r.ReservedCold, (uint)encoded.ColdBytes.Length);
                    fits = false;
                }

                r.Bytes = encoded.Bytes;
                r.ColdBytes = encoded.ColdBytes;
                r.AddressMap = encoded.AddressMap;

                // The old .pdata still names the dropped table entry: it collapses to an empty
                // range at the function's new end.
                uint rangeEnd = r.Function.EntryRva + r.Function.EntryRange.Length;
                foreach (var e in ImageIndex.For(image).EntriesBeginningIn(r.Function.EntryRva + 1, rangeEnd)
                             .Where(e => BlockRebuilder.IsTableEntry(image, r.Function, e)))
                {
                    r.AddressMap.TryAdd(e.BeginAddress, r.AddressMap[rangeEnd]);
                    r.AddressMap.TryAdd(e.EndAddress, r.AddressMap[rangeEnd]);
                }
                r.ColdSegments = encoded.ColdSegments;
                r.HotStart = hotAt[rva];
                r.HotLength = (uint)encoded.Bytes.Length;
                r.ColdStart = encoded.ColdBytes.Length > 0 ? coldAt[rva] : 0;
                r.ColdLength = (uint)encoded.ColdBytes.Length;
            }

            if (fits)
            {
                break;
            }

            if (round == MaxLayoutRounds)
            {
                throw new RewriteRefusedException($"the layout did not settle in {MaxLayoutRounds} rounds");
            }
        }

        foreach (var (rva, r) in rebuilt)
        {
            result.Rebuilt[rva] = r;
        }

        result.Placed.AddRange(code.Select(c => new PlacedContribution(c, hotAt[c.Rva])));

        // Output: the original file, then .wbdata and .wbcold.
        var output = StripCertificate(file, image, result);
        uint rawEnd = PeLayout.Align((uint)output.Length, headers.FileAlignment);
        if (dataSize > 0)
        {
            result.Data = (appendRva, dataSize, rawEnd, PeLayout.Align(dataSize, headers.FileAlignment));
            rawEnd += result.Data.RawSize;
        }

        if (spilled.Count > 0)
        {
            uint spillEnd = spilled.Max(i => i.Cold ? coldAt[i.Contribution.Rva] + rebuilt[i.Contribution.Rva].ReservedCold
                                                    : hotAt[i.Contribution.Rva] + (rebuilt.TryGetValue(i.Contribution.Rva, out var r) ? r.ReservedHot : i.Contribution.Size));
            result.Spill = (spillBase, spillEnd - spillBase, rawEnd, PeLayout.Align(spillEnd - spillBase, headers.FileAlignment));
            rawEnd += result.Spill.RawSize;
        }

        if (rawEnd > output.Length)
        {
            var grown = new byte[rawEnd];
            output.CopyTo(grown, 0);
            if (result.Spill.Size > 0)
            {
                grown.AsSpan((int)result.Spill.RawOffset, (int)result.Spill.RawSize).Fill(0xCC);
            }

            output = grown;
        }

        if (result.Data.Size > 0)
        {
            AddSection(output, result, DataName, result.Data.Size, result.Data.Rva, result.Data.RawSize, result.Data.RawOffset, DataCharacteristics);
        }

        if (result.Spill.Size > 0)
        {
            AddSection(output, result, SpillName, result.Spill.Size, result.Spill.Rva, result.Spill.RawSize, result.Spill.RawOffset, SpillCharacteristics);
            result.Warnings.Add($"{spilled.Count:N0} cold pieces spilled into {SpillName} (0x{result.Spill.Size:X} bytes): the new layout does not fit in the original code section");
        }

        if (Directory(image, "Exception") is { } exceptions)
        {
            result.ExceptionTable = (exceptions.Rva, exceptions.Size);
            result.PdataOrder = Enumerable.Range(0, (int)(exceptions.Size / 12)).ToArray();
        }

        GrowSections(image, output, result);
        MoveCode(image, file, output, result);
        RewriteFixups(image, file, output, result);
        if (result.Rebuilt.Count > 0)
        {
            WriteRebuiltData(image, output, result, coldUnwindAt);
        }
        else
        {
            SortExceptionTable(image, output, result);
        }

        MapEntryPoint(image, output, result);
        MapExports(image, output, result);
        MapLoadConfig(image, file, output, result);
        RewriteRelocations(image, output, result);
        RetireDebugRecord(image, output, result, pdbPath);

        var layout = new PeLayout(output);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.CheckSumOffset), PeChecksum.Compute(output, layout.CheckSumOffset));
        result.Output = output;
        return result;
    }

    /// <summary>
    /// Places every item: per code section the ordered contributions (rebuilt ones as their hot
    /// part), then the rebuilt functions' cold parts, then everything else in original order;
    /// what no longer fits spills, in the same order, from <paramref name="spillBase"/>.
    /// </summary>
    private static (Dictionary<uint, uint> HotAt, Dictionary<uint, uint> ColdAt, List<Item> Spilled) Layout(BinaryImage image,
        List<SectionContribution> code, Dictionary<uint, int> rank, bool ordered, Dictionary<uint, RebuiltFunction> rebuilt,
        Dictionary<uint, List<Function>> hot, bool jccErratum, bool alignLoops, uint spillBase, WholeProgramResult result, uint layoutShift)
    {
        var hotAt = new Dictionary<uint, uint>();
        var coldAt = new Dictionary<uint, uint>();
        var spilled = new List<Item>();
        result.GrownSections.Clear();

        uint Size(Item item) => item.Cold ? rebuilt[item.Contribution.Rva].ReservedCold
            : rebuilt.TryGetValue(item.Contribution.Rva, out var r) ? r.ReservedHot : item.Contribution.Size;

        uint Start(Item item, uint cursor)
        {
            var c = item.Contribution;
            if (item.Cold)
            {
                return PeLayout.Align(cursor, DefaultCodeAlignment);
            }

            if (rebuilt.TryGetValue(c.Rva, out var r))
            {
                return jccErratum || alignLoops ? PeLayout.Align(cursor, 32) + r.Residue : PeLayout.Align(cursor, DefaultCodeAlignment);
            }

            uint at = PeLayout.Align(cursor, Alignment(c));
            return jccErratum && ordered && hot.TryGetValue(c.Rva, out var functions)
                ? Enumerable.Range(0, 32 / JccStep).Select(k => at + (uint)(k * JccStep))
                    .MinBy(o => functions.Sum(f => LayoutStatistics.ExposureAt(image, f, o - (long)c.Rva)))
                : at;
        }

        void Put(Item item, uint at)
        {
            (item.Cold ? coldAt : hotAt)[item.Contribution.Rva] = at;
        }

        foreach (var section in image.Sections.Where(s => s.IsExecutable))
        {
            var inSection = code.Where(c => section.Contains(c.Rva)).ToList();
            if (inSection.Count == 0)
            {
                continue;
            }

            if (!ordered)
            {
                // No order: the linker's own layout, padding included (an exact no-op).
                inSection.ForEach(c => hotAt[c.Rva] = c.Rva);
                continue;
            }

            var ranked = inSection.Where(c => rank.ContainsKey(c.Rva)).OrderBy(c => rank[c.Rva]).ToList();
            var items = ranked.Select(c => new Item(c, false))
                .Concat(ranked.Where(c => rebuilt.TryGetValue(c.Rva, out var r) && r.ReservedCold > 0).Select(c => new Item(c, true)))
                .Concat(inSection.Where(c => !rank.ContainsKey(c.Rva)).Select(c => new Item(c, false)));

            // Room: the file-backed bytes, up to the next section (a different order can need a
            // little more alignment padding than the linker's; the virtual size then grows).
            uint next = image.Sections.Where(s => s.Rva > section.Rva).Select(s => s.Rva).DefaultIfEmpty(uint.MaxValue).Min();
            uint limit = (uint)Math.Min((long)section.Rva + section.RawSize, next);
            uint cursor = inSection[0].Rva + layoutShift;
            bool full = false;
            foreach (var item in items)
            {
                uint at = Start(item, cursor);
                if (full || at + Size(item) > limit)
                {
                    full = true; // once the section is full, the rest of its (coldest) tail spills
                    spilled.Add(item);
                    continue;
                }

                Put(item, at);
                cursor = at + Size(item);
            }

            if (cursor > section.Rva + section.VirtualSize)
            {
                result.GrownSections[section.Name] = cursor - section.Rva;
            }
        }

        uint spillCursor = spillBase;
        foreach (var item in spilled)
        {
            uint at = Start(item, spillCursor);
            Put(item, at);
            spillCursor = at + Size(item);
        }

        return (hotAt, coldAt, spilled);
    }

    /// <summary>
    /// W3 candidates: executed functions alone in their contribution that the block layout can
    /// re-encode, with a trial encoding to size them. Everything else moves as a unit.
    /// </summary>
    private static Dictionary<uint, RebuiltFunction> SelectRebuilt(BinaryImage image, byte[] file, List<SectionContribution> code,
        Func<uint, SectionContribution?> ownerOf, IReadOnlyList<SectionContribution> order, Dictionary<uint, List<Function>> hot,
        Func<Function, BlockOrder?> blockOrder, bool jccErratum, bool alignLoops, WholeProgramResult result)
    {
        var entriesIn = image.Functions.GroupBy(f => ownerOf(f.EntryRva)?.Rva ?? uint.MaxValue).ToDictionary(g => g.Key, g => g.Count());

        // References into each contribution from outside it, by value.
        var inbound = new Dictionary<uint, HashSet<uint>>();
        foreach (var fixup in image.LinkerFixups)
        {
            if (ownerOf(fixup.Target) is not { } target || ownerOf(fixup.Rva)?.Rva == target.Rva ||
                FileOffset(image, fixup.Rva) is not { } at || Resolve(image, file, fixup, at) is not { } value)
            {
                continue;
            }

            (inbound.TryGetValue(target.Rva, out var set) ? set : inbound[target.Rva] = []).Add(value);
        }

        var longJumps = new HashSet<uint>(image.LoadConfig?.GuardLongJumpTargetTable ?? []);
        longJumps.UnionWith(image.LoadConfig?.GuardEhContinuationTable ?? []);
        var candidates = new Dictionary<uint, RebuiltFunction>();
        foreach (var c in order.DistinctBy(c => c.Rva))
        {
            if (!hot.TryGetValue(c.Rva, out var functions) || functions.Count != 1)
            {
                continue;
            }

            var f = functions[0];
            string? reason = entriesIn.GetValueOrDefault(c.Rva) != 1 || f.EntryRva != c.Rva ? "not alone in its contribution"
                : Reason(image, f, c, longJumps, inbound.GetValueOrDefault(c.Rva) ?? []);
            var wanted = reason is null ? blockOrder(f) : null;
            if (reason is null && wanted is null)
            {
                continue;
            }

            if (reason is null && wanted!.Problem(f) is { } problem)
            {
                throw new ArgumentException($"block order for {f.DisplayName}: {problem}", nameof(blockOrder));
            }

            var r = reason is null
                ? new RebuiltFunction { Function = f, Order = BlockRebuilder.LayoutReason(image, f) is null ? wanted! : BlockOrder.Original(f) }
                : null;
            if (r is not null && Trial(image, r, jccErratum, alignLoops) is { } trialProblem)
            {
                reason = trialProblem;
            }

            if (reason is not null)
            {
                result.NotRebuilt.Add((f, reason));
                continue;
            }

            candidates[c.Rva] = r!;
        }

        // A rebuilt function's own encoding needs the new address of every branch target: only an
        // entry of another rebuilt function is known before that one is encoded.
        for (bool changed = true; changed;)
        {
            changed = false;
            foreach (var r in candidates.Values.ToList())
            {
                uint start = r.Function.EntryRva, end = start + r.Function.EntryRange.Length;
                foreach (var x in BlockRebuilder.Instructions(image, r.Function))
                {
                    ulong t = x.Op0Kind == OpKind.NearBranch64 ? x.NearBranchTarget : x.IsIPRelativeMemoryOperand ? x.IPRelativeMemoryAddress : 0;
                    if (t != 0 && (t < start || t >= end) && ownerOf((uint)t) is { } other && candidates.TryGetValue(other.Rva, out var into) &&
                        (uint)t != into.Function.EntryRva)
                    {
                        candidates.Remove(other.Rva);
                        result.NotRebuilt.Add((into.Function, $"another rebuilt function branches into it at 0x{t:X}"));
                        changed = true;
                    }
                }
            }
        }

        return candidates;
    }

    /// <summary>Why <paramref name="f"/> (alone in <paramref name="c"/>) cannot be rebuilt in place, or null.</summary>
    private static string? Reason(BinaryImage image, Function f, SectionContribution c, HashSet<uint> longJumps, HashSet<uint> inbound)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        if (f.SafetyStatus.Level != Transformability.FullyTransformable)
        {
            return $"not FullyTransformable ({f.SafetyStatus.Level})";
        }

        if (f.Ranges.Count != 1 || end > c.Rva + c.Size)
        {
            return "more than one range, or a range past its contribution";
        }

        if (f.ExceptionHandler is { Kind: not ExceptionHandlerKind.GsCookieCheck })
        {
            return "language handler data would need regenerating";
        }

        if (f.JumpTables.Any(t => t.Encoding == JumpTableEncoding.TableRelativeOffset32))
        {
            return "table-relative jump tables are not rebuilt in whole-program mode";
        }

        if (BlockRebuilder.Reason(image, f) is { } rebuildReason)
        {
            return rebuildReason;
        }

        var entries = BlockRebuilder.Entries(image, f);
        if (entries.Any(e => e.IsChained && (e.ChainedParent is null || e.ChainedParent.BeginAddress < start || e.ChainedParent.BeginAddress >= end)))
        {
            return "unwind chain leaves the range";
        }

        if (longJumps.Any(t => t >= start && t < end))
        {
            return "contains a longjmp or EH-continuation target";
        }

        var instructions = BlockRebuilder.Instructions(image, f).ToList();
        if (instructions.Any(x => x.IsIPRelativeMemoryOperand && x.Mnemonic != Mnemonic.Lea && image.FindSection((uint)x.IPRelativeMemoryAddress) is { IsExecutable: true }))
        {
            return "a RIP-relative operand other than lea reads code";
        }

        // References from outside must land where the address map is defined.
        var mapped = instructions.Select(x => (uint)x.IP).ToHashSet();
        mapped.Add(end);
        mapped.UnionWith(entries.Select(e => e.EndAddress));
        var tableEntries = ImageIndex.For(image).EntriesBeginningIn(start + 1, end).Where(e => BlockRebuilder.IsTableEntry(image, f, e)).ToList();
        mapped.UnionWith(tableEntries.SelectMany(e => new[] { e.BeginAddress, e.EndAddress }));
        if (inbound.FirstOrDefault(v => !mapped.Contains(v)) is var outside && outside != 0)
        {
            return $"a reference from outside lands at 0x{outside:X}, not on an instruction";
        }

        return null;
    }

    /// <summary>Sizes a rebuilt function by encoding it near its original address (plus its start residue modulo 32 under the JCC erratum).</summary>
    private static string? Trial(BinaryImage image, RebuiltFunction r, bool jccErratum, bool alignLoops)
    {
        var f = r.Function;
        var placeholders = f.JumpTables.ToDictionary(t => (uint)t.LoadRva!.Value, _ => PlaceholderTable);
        var trial = BlockRebuilder.TrialEncode(image, f, r.Order, placeholders, jccErratum, alignLoops, 32, out string? error, out uint residue);
        if (residue != 0)
        {
            r.Residue = residue;
        }

        if (trial is null)
        {
            return $"rebuild: {error}";
        }

        if (BlockRebuilder.CheckPrologues(image, f, trial) is { } problem)
        {
            return problem;
        }

        r.ReservedHot = (uint)trial.Bytes.Length;
        r.ReservedCold = (uint)trial.ColdBytes.Length;
        r.ColdCount = trial.ColdSegments.Count;
        return null;
    }

    /// <summary>
    /// Encodes a rebuilt function at its final address, every outside target and lea of code at
    /// its new address. iced's encoder links a branch or RIP-relative operand to any instruction
    /// in the same call whose IP is its target, and the instructions carry their original
    /// addresses: a new address that equals one of them (another function now lives where this
    /// one used to) is encoded against a stand-in that does not, and the field is patched after.
    /// </summary>
    private static RebuiltCode? EncodeAt(BinaryImage image, RebuiltFunction r, uint hot, uint cold, Func<uint, uint> newAddress, bool jccErratum, bool alignLoops,
        out string? error)
    {
        var f = r.Function;
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        var instructions = BlockRebuilder.Instructions(image, f).ToList();
        var ips = instructions.Select(x => (uint)x.IP).ToHashSet();
        var standIn = new Dictionary<uint, uint>(); // stand-in → real new address
        uint Safe(uint address)
        {
            if (!ips.Contains(address))
            {
                return address;
            }

            uint candidate = address + 1;
            while (ips.Contains(candidate) || standIn.ContainsKey(candidate))
            {
                candidate++;
            }

            standIn[candidate] = address;
            return candidate;
        }

        var targets = new Dictionary<uint, uint>();
        var pointers = new Dictionary<uint, uint>();
        foreach (var x in instructions)
        {
            if (x.Op0Kind == OpKind.NearBranch64 && (x.NearBranchTarget < start || x.NearBranchTarget >= end) && !targets.ContainsKey((uint)x.NearBranchTarget))
            {
                targets[(uint)x.NearBranchTarget] = Safe(newAddress((uint)x.NearBranchTarget));
            }

            if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && image.FindSection((uint)x.IPRelativeMemoryAddress) is { IsExecutable: true } &&
                !pointers.ContainsKey((uint)x.IPRelativeMemoryAddress))
            {
                pointers[(uint)x.IPRelativeMemoryAddress] = Safe(newAddress((uint)x.IPRelativeMemoryAddress));
            }
        }

        var tableFields = f.JumpTables.ToDictionary(t => (uint)t.LoadRva!.Value, t => r.Tables.Single(c => c.OriginalRva == t.Rva).NewRva);
        foreach (var t in f.JumpTables)
        {
            if (r.Tables.Single(c => c.OriginalRva == t.Rva).NewIndexRva is { } index)
            {
                tableFields[(uint)t.IndexLoadRva!.Value] = index;
            }
        }

        var code = BlockRebuilder.Encode(image, f, r.Order, hot, cold, targets, tableFields, out error, jccErratum, null, alignLoops, pointers);
        if (code is null || standIn.Count == 0)
        {
            return code;
        }

        foreach (var x in instructions)
        {
            bool branch = x.Op0Kind == OpKind.NearBranch64 && (x.NearBranchTarget < start || x.NearBranchTarget >= end);
            bool lea = x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && pointers.ContainsKey((uint)x.IPRelativeMemoryAddress);
            uint stood = branch ? targets[(uint)x.NearBranchTarget] : lea ? pointers[(uint)x.IPRelativeMemoryAddress] : 0;
            if (!standIn.TryGetValue(stood, out uint real) || !code.AddressMap.TryGetValue((uint)x.IP, out uint at))
            {
                continue;
            }

            bool inHot = at >= hot && at - hot < code.Bytes.Length;
            byte[] bytes = inHot ? code.Bytes : code.ColdBytes;
            int index = (int)(at - (inHot ? hot : cold));
            var decoder = Iced.Intel.Decoder.Create(64, new ByteArrayCodeReader(bytes.AsSpan(index, Math.Min(15, bytes.Length - index)).ToArray()));
            decoder.IP = at;
            var y = decoder.Decode();
            var offsets = decoder.GetConstantOffsets(y);
            (int field, int size) = branch ? (offsets.ImmediateOffset, offsets.ImmediateSize) : (offsets.DisplacementOffset, offsets.DisplacementSize);
            long displacement = (long)real - (long)(at + (uint)y.Length);
            if (size == 1 && displacement is < sbyte.MinValue or > sbyte.MaxValue)
            {
                error = $"the short branch at 0x{x.IP:X} cannot reach 0x{real:X}";
                return null;
            }

            if (size == 1)
            {
                bytes[index + field] = (byte)(sbyte)displacement;
            }
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(index + field), (int)displacement);
            }
        }

        return code;
    }

    /// <summary>
    /// .wbdata for rebuilt functions: a complete new .pdata (every original entry at its new
    /// address, plus a chained entry per cold segment), their jump tables, and the cold parts'
    /// UNWIND_INFO. The exception directory then names the new table.
    /// </summary>
    private static void WriteRebuiltData(BinaryImage image, byte[] output, WholeProgramResult result, uint coldUnwindAt)
    {
        int Data(uint rva) => (int)(result.Data.RawOffset + (rva - result.Data.Rva));
        uint unwindCursor = coldUnwindAt;
        foreach (var r in result.Rebuilt.Values)
        {
            foreach (var e in BlockRebuilder.Entries(image, r.Function))
            {
                r.Pdata.Add(new CopiedPdata(e.BeginAddress, r.AddressMap[e.BeginAddress], r.AddressMap[e.EndAddress], e.UnwindInfoAddress, e.IsChained));
            }

            foreach (var segment in r.ColdSegments)
            {
                var parent = r.Pdata.First(p => p.OriginalBegin == segment.EntryBegin);
                var source = image.ExceptionData.First(e => e.BeginAddress == segment.EntryBegin);
                ColdUnwindInfoBytes(image.ReadFrom(source.UnwindInfoAddress & ~1u).Span[3], parent).CopyTo(output, Data(unwindCursor));
                r.ColdEntries.Add(new CopiedPdata(segment.EntryBegin, segment.Start, segment.End, unwindCursor, Chained: true));
                unwindCursor += 16;
            }

            uint start = r.Function.EntryRva, end = start + r.Function.EntryRange.Length;
            foreach (var (table, jumpTable) in r.Tables.Select(t => (t, r.Function.JumpTables.First(j => (uint)j.Rva == t.OriginalRva))))
            {
                if (table.NewIndexRva is { } index)
                {
                    image.ReadFrom((uint)jumpTable.IndexTableRva!.Value).Span[..jumpTable.IndexEntryCount].CopyTo(output.AsSpan(Data(index)));
                }

                for (int i = 0; i < jumpTable.TargetRvas.Count; i++)
                {
                    uint target = (uint)jumpTable.TargetRvas[i];
                    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(Data(table.NewRva + (uint)i * 4)),
                        target >= start && target < end ? r.AddressMap[target] : result.MapValue(target, target));
                }
            }
        }

        var rebuiltEntries = result.Rebuilt.Values.SelectMany(r => r.Pdata).ToDictionary(p => p.OriginalBegin);
        var pdata = image.ExceptionData
            .Where(e => !(result.Owner(e.BeginAddress) is { } p && result.Rebuilt.ContainsKey(p.Contribution.Rva) && !rebuiltEntries.ContainsKey(e.BeginAddress)))
            .Select(e => rebuiltEntries.TryGetValue(e.BeginAddress, out var p)
                ? (p.Begin, p.End, p.UnwindInfo)
                : (result.MapSite(e.BeginAddress), result.MapValue(e.BeginAddress, e.EndAddress), e.UnwindInfoAddress))
            .Concat(result.Rebuilt.Values.SelectMany(r => r.ColdEntries).Select(c => (c.Begin, c.End, c.UnwindInfo)))
            .OrderBy(e => e.Item1).ToList();
        for (int i = 0; i < pdata.Count; i++)
        {
            int at = Data(result.Data.Rva + (uint)i * 12);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at), pdata[i].Item1);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at + 4), pdata[i].Item2);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at + 8), pdata[i].Item3);
        }

        var layout = new PeLayout(output);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.DataDirectory(PeLayout.ExceptionDirectory)), result.Data.Rva);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.DataDirectory(PeLayout.ExceptionDirectory) + 4), (uint)pdata.Count * 12);
    }

    /// <summary>UNWIND_INFO of a cold part (see <see cref="FunctionRewriter.ColdUnwindInfo"/>).</summary>
    internal static byte[] ColdUnwindInfoBytes(byte frameRegister, CopiedPdata primary) => FunctionRewriter.ColdUnwindInfo(frameRegister, primary);

    /// <summary>IMAGE_SCN_ALIGN_* of the contribution (bits 20-23: 2^(n-1)); 16 when unset.</summary>
    internal static uint Alignment(SectionContribution c)
    {
        uint n = (c.Characteristics & AlignMask) >> 20;
        return n == 0 ? DefaultCodeAlignment : 1u << (int)(n - 1);
    }

    /// <summary>The code areas become int3, then each contribution (or rebuilt function) is written at its new place.</summary>
    private static void MoveCode(BinaryImage image, byte[] file, byte[] output, WholeProgramResult result)
    {
        foreach (var (start, end) in CodeAreas(image, result))
        {
            output.AsSpan(Offset(image, start), (int)(end - start)).Fill(0xCC);
        }

        foreach (var p in result.Placed)
        {
            if (result.Rebuilt.TryGetValue(p.Contribution.Rva, out var r))
            {
                r.Bytes.CopyTo(output, OutOffset(image, result, r.HotStart));
                if (r.ColdLength > 0)
                {
                    r.ColdBytes.CopyTo(output, OutOffset(image, result, r.ColdStart));
                }

                continue;
            }

            file.AsSpan(Offset(image, p.Contribution.Rva), (int)p.Contribution.Size).CopyTo(output.AsSpan(OutOffset(image, result, p.NewRva)));
        }
    }

    /// <summary>The new code spans: contributions, or a rebuilt function's hot and cold parts.</summary>
    internal static IEnumerable<(uint Start, uint End)> NewSpans(WholeProgramResult result)
    {
        foreach (var p in result.Placed)
        {
            if (result.Rebuilt.TryGetValue(p.Contribution.Rva, out var r))
            {
                yield return (r.HotStart, r.HotStart + r.HotLength);
                if (r.ColdLength > 0)
                {
                    yield return (r.ColdStart, r.ColdStart + r.ColdLength);
                }
            }
            else
            {
                yield return (p.NewRva, p.NewRva + p.Contribution.Size);
            }
        }
    }

    /// <summary>
    /// Per original code section, the span its contributions occupied before or occupy now (the
    /// spill section excluded): everything in it that no new code covers becomes int3.
    /// </summary>
    internal static IEnumerable<(uint Start, uint End)> CodeAreas(BinaryImage image, WholeProgramResult result)
    {
        var spans = NewSpans(result).Where(s => !result.InSpill(s.Start)).ToList();
        foreach (var group in result.Placed.GroupBy(p => image.FindSection(p.Contribution.Rva)!))
        {
            var section = group.Key;
            var ranges = group.Select(p => (Start: p.Contribution.Rva, End: p.Contribution.Rva + p.Contribution.Size))
                .Concat(spans.Where(s => s.Start >= section.Rva && s.Start - section.Rva < section.RawSize)).ToList();
            yield return (ranges.Min(r => r.Start), ranges.Max(r => r.End));
        }
    }

    /// <summary>
    /// Every linker-resolved reference, re-resolved at its new site against its target's new
    /// address. Sites inside rebuilt functions are skipped: the encoder wrote those with the final
    /// addresses (and their table data is not carried over).
    /// </summary>
    private static void RewriteFixups(BinaryImage image, byte[] file, byte[] output, WholeProgramResult result)
    {
        foreach (var fixup in image.LinkerFixups)
        {
            if (FileOffset(image, fixup.Rva) is not { } at || Resolve(image, file, fixup, at) is not { } value ||
                result.Owner(fixup.Rva) is { } site0 && result.Rebuilt.ContainsKey(site0.Contribution.Rva))
            {
                continue;
            }

            if (result.Owner(value) is { Delta: not 0 } && result.Owner(fixup.Target) is null)
            {
                throw new RewriteRefusedException($"fixup at 0x{fixup.Rva:X} resolves to moved code 0x{value:X} through the non-code target 0x{fixup.Target:X}");
            }

            uint mapped = result.MapValue(fixup.Target, value);
            uint site = result.MapSite(fixup.Rva);
            int to = OutOffset(image, result, site);
            byte[] before = output.AsSpan(to, fixup.Type == 1 ? 8 : 4).ToArray();
            switch (fixup.Type)
            {
                case 1:
                    BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(to), image.ImageBase + mapped);
                    break;
                case 2:
                    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(to), (uint)(image.ImageBase + mapped));
                    break;
                case 3:
                    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(to), mapped);
                    break;
                default:
                    BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(to), (int)(mapped - (site + 4 + (uint)(fixup.Type - 4))));
                    break;
            }

            if (!before.AsSpan().SequenceEqual(output.AsSpan(to, before.Length)))
            {
                result.FixupsRewritten++;
            }
        }
    }

    /// <summary>The value a fixup's field holds in the original file (types 1, 2, 3 and REL32 to REL32_5).</summary>
    internal static uint? Resolve(BinaryImage image, byte[] bytes, LinkerFixup fixup, int at) => fixup.Type switch
    {
        1 when at + 8 <= bytes.Length => (uint)(BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(at)) - image.ImageBase),
        2 when at + 4 <= bytes.Length => (uint)(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at)) - (uint)image.ImageBase),
        3 when at + 4 <= bytes.Length => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at)),
        >= 4 and <= 9 when at + 4 <= bytes.Length => (uint)(fixup.Rva + 4 + (fixup.Type - 4) + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at))),
        _ => null,
    };

    /// <summary>.pdata fields were fixed up in place; the table must stay sorted by BeginAddress.</summary>
    private static void SortExceptionTable(BinaryImage image, byte[] output, WholeProgramResult result)
    {
        if (result.PdataOrder.Length == 0)
        {
            return;
        }

        int at = Offset(image, result.ExceptionTable.Rva);
        int count = result.PdataOrder.Length;
        var entries = Enumerable.Range(0, count).Select(i => (Index: i, Bytes: output.AsSpan(at + i * 12, 12).ToArray()))
            .OrderBy(e => BinaryPrimitives.ReadUInt32LittleEndian(e.Bytes)).ToList();
        for (int k = 0; k < count; k++)
        {
            entries[k].Bytes.CopyTo(output, at + k * 12);
            result.PdataOrder[entries[k].Index] = k;
        }
    }

    /// <summary>Section headers of code sections the new layout extends into their file-backed slack.</summary>
    private static void GrowSections(BinaryImage image, byte[] output, WholeProgramResult result)
    {
        var layout = new PeLayout(output);
        for (int i = 0; i < layout.NumberOfSections; i++)
        {
            int header = layout.SectionTable + i * PeLayout.SectionHeaderSize;
            string name = System.Text.Encoding.ASCII.GetString(output, header, 8).TrimEnd('\0');
            if (result.GrownSections.TryGetValue(name, out uint size))
            {
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(header + 8), size);
            }
        }
    }

    private static void MapEntryPoint(BinaryImage image, byte[] output, WholeProgramResult result)
    {
        var layout = new PeLayout(output);
        int field = layout.OptionalHeader + 16;
        uint entry = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(field));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(field), result.MapSite(entry));
    }

    /// <summary>Export address table entries (not forwarders, whose RVAs point into the export directory).</summary>
    private static void MapExports(BinaryImage image, byte[] output, WholeProgramResult result)
    {
        if (Directory(image, "Export") is not { } directory)
        {
            return;
        }

        int header = Offset(image, directory.Rva);
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(header + 20));
        int table = Offset(image, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(header + 28)));
        for (int i = 0; i < count; i++)
        {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(table + i * 4));
            if (rva != 0 && (rva < directory.Rva || rva >= directory.Rva + directory.Size) && result.MapSite(rva) != rva)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(table + i * 4), result.MapSite(rva));
                result.ExportsMapped++;
            }
        }
    }

    /// <summary>
    /// The CFG tables the linker synthesized hold code RVAs without fixups: the function table
    /// (each entry followed by flag bytes), the longjmp and EH-continuation tables. Mapped and
    /// re-sorted, since the loader binary-searches them.
    /// </summary>
    private static void MapLoadConfig(BinaryImage image, byte[] file, byte[] output, WholeProgramResult result)
    {
        if (Directory(image, "LoadConfig") is not { } directory)
        {
            return;
        }

        int config = Offset(image, directory.Rva);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(config));
        if (size < 0x98)
        {
            return;
        }

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(config + 0x90));
        int stride = 4 + (int)((flags & GuardCfFunctionTableSizeMask) >> 28);
        MapTable(0x80, 0x88, stride);
        if (size >= 0xC0)
        {
            MapTable(0xB0, 0xB8, 4);
        }

        if (size >= 0x118)
        {
            MapTable(0x108, 0x110, 4);
        }

        void MapTable(int tableField, int countField, int entrySize)
        {
            ulong va = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(config + tableField));
            ulong count = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(config + countField));
            if (va == 0 || count == 0)
            {
                return;
            }

            // From the original bytes: the linker may also have recorded fixups for these entries,
            // which RewriteFixups has already applied to the output.
            int at = Offset(image, (uint)(va - image.ImageBase));
            result.CfgTables.Add(((uint)(va - image.ImageBase), (uint)((int)count * entrySize)));
            var entries = new List<byte[]>();
            for (int i = 0; i < (int)count; i++)
            {
                var entry = file.AsSpan(at + i * entrySize, entrySize).ToArray();
                uint rva = BinaryPrimitives.ReadUInt32LittleEndian(entry);
                uint mapped = result.MapSite(rva);
                if (mapped != rva)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(entry, mapped);
                    result.CfgEntriesMapped++;
                }

                entries.Add(entry);
            }

            int k = 0;
            foreach (var entry in entries.OrderBy(e => BinaryPrimitives.ReadUInt32LittleEndian(e)))
            {
                entry.CopyTo(output, at + k++ * entrySize);
            }
        }
    }

    /// <summary>Relocation sites in moved code move with it; the table is rebuilt in place (it must fit).</summary>
    private static void RewriteRelocations(BinaryImage image, byte[] output, WholeProgramResult result)
    {
        if (Directory(image, "BaseRelocation") is not { } directory)
        {
            return;
        }

        var relocations = image.Relocations.Where(r => r.Type is RelocationType.Dir64 or RelocationType.HighLow)
            .Select(r => (Rva: result.MapSite(r.Rva), Type: r.Type == RelocationType.Dir64 ? RelocDir64 : RelocHighLow, Moved: result.MapSite(r.Rva) != r.Rva))
            .ToList();
        result.RelocationsMoved = relocations.Count(r => r.Moved);
        var table = BuildRelocationTable(relocations.Select(r => (r.Rva, r.Type)));
        var section = image.FindSection(directory.Rva)!;
        uint room = section.Rva + section.RawSize - directory.Rva;
        if (table.Length > room)
        {
            throw new RewriteRefusedException($"the rebuilt relocation table needs {table.Length:N0} bytes, the .reloc section has {room:N0}");
        }

        int at = Offset(image, directory.Rva);
        output.AsSpan(at, (int)Math.Max(directory.Size, (uint)table.Length)).Clear();
        table.CopyTo(output, at);
        var layout = new PeLayout(output);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.DataDirectory(PeLayout.BaseRelocationDirectory) + 4), (uint)table.Length);
    }

    /// <summary>
    /// The PDB describes the old layout and would name the wrong code (§6.2 "Debugging
    /// information"): until OMAP is written, the RSDS GUID changes so debuggers reject it.
    /// </summary>
    private static void RetireDebugRecord(BinaryImage image, byte[] output, WholeProgramResult result, string? pdbPath)
    {
        foreach (var entry in image.DebugEntries.Where(e => e.Type == DebugDirectoryType.CodeView && e.SizeOfData >= 24))
        {
            int at = (int)entry.PointerToRawData;
            if (pdbPath is not null && at + entry.SizeOfData <= output.Length && output.AsSpan(at, 4).SequenceEqual("RSDS"u8))
            {
                // The new PDB's identity: a GUID derived from the original's and the layout, age 1,
                // and its path (or, if that does not fit the record, its file name).
                using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
                hash.AppendData(output.AsSpan(at + 4, 16));
                foreach (var p in result.Placed)
                {
                    hash.AppendData(BitConverter.GetBytes(p.Contribution.Rva));
                    hash.AppendData(BitConverter.GetBytes(p.NewRva));
                }

                foreach (var r in result.Rebuilt.Values.OrderBy(r => r.Function.EntryRva))
                {
                    hash.AppendData(r.Bytes);
                    hash.AppendData(BitConverter.GetBytes(r.ColdStart));
                }

                result.PdbGuid = new Guid(hash.GetHashAndReset().AsSpan(0, 16));
                result.PdbAge = 1;
                int capacity = (int)entry.SizeOfData - 24;
                byte[] path = System.Text.Encoding.UTF8.GetBytes(pdbPath);
                if (path.Length >= capacity)
                {
                    path = System.Text.Encoding.UTF8.GetBytes(Path.GetFileName(pdbPath));
                }

                if (path.Length >= capacity)
                {
                    throw new RewriteRefusedException($"the PDB name {Path.GetFileName(pdbPath)} does not fit the image's CodeView record ({capacity - 1} bytes)");
                }

                result.PdbGuid.Value.TryWriteBytes(output.AsSpan(at + 4, 16));
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at + 20), result.PdbAge);
                output.AsSpan(at + 24, capacity).Clear();
                path.CopyTo(output, at + 24);
                continue;
            }

            if (at + 20 <= output.Length && output.AsSpan(at, 4).SequenceEqual("RSDS"u8))
            {
                for (int i = 4; i < 20; i++)
                {
                    output[at + i] ^= 0x5A;
                }

                result.Warnings.Add("the RSDS GUID was changed: the original PDB describes the old layout and must not be loaded for this image (OMAP is milestone W4)");
            }
        }
    }

    private static byte[] StripCertificate(byte[] file, BinaryImage image, WholeProgramResult result)
    {
        var layout = new PeLayout(file);
        int directory = layout.DataDirectory(PeLayout.SecurityDirectory);
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(directory));
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(directory + 4));
        var copy = file.ToArray();
        if (offset == 0 || size == 0)
        {
            return copy;
        }

        result.Warnings.Add("the Authenticode signature was removed: the rewritten image must be re-signed");
        BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(directory), 0);
        return offset + size == file.Length ? copy[..(int)offset] : copy;
    }

    /// <summary>IMAGE_BASE_RELOCATION blocks per 4 KB page, each padded to a 4-byte multiple.</summary>
    private static byte[] BuildRelocationTable(IEnumerable<(uint Rva, int Type)> relocations)
    {
        var table = new List<byte>();
        foreach (var page in relocations.Distinct().GroupBy(r => r.Rva & ~0xFFFu).OrderBy(g => g.Key))
        {
            var entries = page.OrderBy(r => r.Rva).Select(r => (ushort)((r.Type << 12) | (int)(r.Rva & 0xFFF))).ToList();
            if (entries.Count % 2 == 1)
            {
                entries.Add(0);
            }

            table.AddRange(BitConverter.GetBytes(page.Key));
            table.AddRange(BitConverter.GetBytes((uint)(8 + entries.Count * 2)));
            foreach (ushort entry in entries)
            {
                table.AddRange(BitConverter.GetBytes(entry));
            }
        }

        return table.ToArray();
    }

    internal static DataDirectory? Directory(BinaryImage image, string name) =>
        image.DataDirectories.FirstOrDefault(d => d.Name == name && d.Rva != 0 && d.Size != 0);

    /// <summary>File offset of a file-backed RVA; null in zero-fill or outside every section.</summary>
    /// <remarks>By raw extent too: a grown code section uses file-backed bytes past its old virtual size.</remarks>
    internal static int? FileOffset(BinaryImage image, uint rva) =>
        image.Sections.FirstOrDefault(s => rva >= s.Rva && rva - s.Rva < s.RawSize) is { } s ? (int)(s.FileOffset + (rva - s.Rva)) : null;

    private static int Offset(BinaryImage image, uint rva) =>
        FileOffset(image, rva) ?? throw new RewriteRefusedException($"0x{rva:X} is not file-backed");

    /// <summary>File offset in the output of a new address, which may lie in an appended section.</summary>
    private static int OutOffset(BinaryImage image, WholeProgramResult result, uint rva)
    {
        foreach (var (start, _, rawOffset, rawSize) in new[] { result.Spill, result.Data })
        {
            if (rawSize > 0 && rva >= start && rva - start < rawSize)
            {
                return (int)(rawOffset + (rva - start));
            }
        }

        return Offset(image, rva);
    }

    /// <summary>A section header after the existing ones (it must fit in the header slack), and SizeOfImage.</summary>
    private static void AddSection(byte[] output, WholeProgramResult result, string name, uint virtualSize, uint rva, uint rawSize, uint rawOffset, uint characteristics)
    {
        var layout = new PeLayout(output);
        int header = layout.SectionTable + layout.NumberOfSections * PeLayout.SectionHeaderSize;
        uint firstRaw = Enumerable.Range(0, layout.NumberOfSections)
            .Select(i => BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(layout.SectionTable + i * PeLayout.SectionHeaderSize + 20)))
            .Where(r => r != 0).DefaultIfEmpty(layout.SizeOfHeaders).Min();
        if (header + PeLayout.SectionHeaderSize > Math.Min(layout.SizeOfHeaders, firstRaw) ||
            output.AsSpan(header, PeLayout.SectionHeaderSize).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new RewriteRefusedException($"no room in the headers for {name}");
        }

        PeLayout.WriteSectionHeader(output.AsSpan(header, PeLayout.SectionHeaderSize), name, virtualSize, rva, rawSize, rawOffset, characteristics);
        BinaryPrimitives.WriteUInt16LittleEndian(output.AsSpan(layout.NumberOfSectionsOffset), (ushort)(layout.NumberOfSections + 1));
        uint sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(layout.SizeOfImageOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.SizeOfImageOffset), Math.Max(sizeOfImage, PeLayout.Align(rva + virtualSize, layout.SectionAlignment)));
        result.AddedSections++;
    }
}
