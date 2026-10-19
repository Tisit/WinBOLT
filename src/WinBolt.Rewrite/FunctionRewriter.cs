using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>The input cannot be rewritten safely; nothing was written.</summary>
public sealed class RewriteRefusedException(string message) : Exception(message);

/// <summary>
/// One exception entry of a copy. An unchained entry reuses the original UNWIND_INFO; a chained
/// entry gets its own copy of it in .wbdata, re-pointed at its parent's copied entry.
/// </summary>
public sealed record CopiedPdata(uint OriginalBegin, uint Begin, uint End, uint UnwindInfo, bool Chained);

/// <summary>
/// A jump table rebuilt in .wbdata for a copy: every entry names the copy's case block. The load
/// at <see cref="LoadRva"/> (original address) reads the new table in the copy. A two-level
/// table's byte index table holds no addresses; the load at <see cref="IndexLoadRva"/> reads the
/// copy's index bytes when the index table lies inside the range, otherwise the original.
/// </summary>
public sealed record CopiedTable(uint OriginalRva, uint NewRva, int EntryCount, uint LoadRva, uint? IndexLoadRva)
{
    /// <summary>
    /// A table-relative table (LLVM): entries are offsets from the table itself, and the instructions
    /// whose field is re-pointed at <see cref="NewRva"/> are the base <c>lea</c>s here, not the load.
    /// Empty for the image-relative forms, where it is just <see cref="LoadRva"/>.
    /// </summary>
    public IReadOnlyList<uint> BaseSites { get; init; } = [];

    /// <summary>
    /// Table-relative: the value the base leas loaded originally (entries are relative to it; tables
    /// that share a base register sit at fixed displacements from it) and where it went. The tables
    /// of one base move together, keeping their offsets from it.
    /// </summary>
    public uint OriginalBaseRva { get; init; }

    public uint NewBaseRva { get; init; }

    public bool TableRelative => BaseSites.Count > 0;

    /// <summary>The instructions (original RVAs) whose field names the table.</summary>
    public IEnumerable<uint> FieldSites => TableRelative ? BaseSites : [LoadRva];

    /// <summary>
    /// Whole-program layout: where the byte index table went when it lay in the function's
    /// contribution (its bytes are not carried over there); null when the index load keeps reading the original.
    /// </summary>
    public uint? NewIndexRva { get; init; }
}

/// <summary>Bytes of a range that are data, not code (jump tables inside it), as offsets from the range start.</summary>
public readonly record struct DataSpan(uint Offset, uint Length)
{
    public uint End => Offset + Length;
}

/// <summary>
/// A function copied into .wbtext, with a copied exception entry for every .pdata entry that
/// begins in its range: the primary one and any chained fragments merged into the range (§5.1).
/// </summary>
public sealed record MovedFunction(
    int FunctionId,
    string Name,
    uint Start,
    uint Length,
    uint CopyStart,
    IReadOnlyList<CopiedPdata> Pdata,
    IReadOnlyList<CopiedTable> Tables,
    IReadOnlyList<DataSpan> DataSpans)
{
    /// <summary>
    /// Rebuilt functions only: original instruction RVA → new RVA, plus the range end. A copy
    /// (null map) is at a fixed offset from its original.
    /// </summary>
    public IReadOnlyDictionary<uint, uint>? AddressMap { get; init; }

    /// <summary>Size of the code in .wbtext (a rebuilt function drops padding and table data, and branch sizes change).</summary>
    public uint CopyLength { get; init; }

    /// <summary>Where the function's cold blocks went (Stage 6 splitting); 0 if it has none.</summary>
    public uint ColdStart { get; init; }

    /// <summary>
    /// False when the original entry keeps its bytes: every pointer to the function is aimed at the
    /// copy (<see cref="PointerRedirection"/>), so only direct branches from unmoved code still
    /// reach the original, intact body. Used where a 5-byte jmp does not fit.
    /// </summary>
    public bool HasTrampoline { get; init; } = true;

    public uint ColdLength { get; init; }

    /// <summary>
    /// The cold part's exception entries: one per original entry with cold blocks, covering them
    /// and chained to that entry's copy (<see cref="CopiedPdata.OriginalBegin"/> names it). None
    /// for a leaf function.
    /// </summary>
    public IReadOnlyList<CopiedPdata> ColdEntries { get; init; } = [];

    /// <summary>Indirect calls promoted to a guarded direct call (rebuilt functions): call site RVA → target RVA.</summary>
    public IReadOnlyDictionary<uint, uint> PromotedCalls { get; init; } = new Dictionary<uint, uint>();

    /// <summary>Where the code at an original instruction RVA (or the range end) now is.</summary>
    public uint Map(uint rva) => AddressMap is null ? CopyStart + (rva - Start) : AddressMap[rva];

    /// <summary>Where the code at <paramref name="rva"/> runs now: moved if it is in the moved (entry) range, else in place.</summary>
    public uint Place(uint rva) => rva >= Start && rva < Start + Length ? Map(rva) : rva;
}

public enum RewriteMode
{
    /// <summary>Stage 4: copy each function's bytes, patching fields that leave the range.</summary>
    Copy,

    /// <summary>Stage 6 groundwork: re-encode each function from its CFG (<see cref="BlockRebuilder"/>).</summary>
    Rebuild,
}

public enum FieldKind
{
    /// <summary>A rel32 branch or call leaving the range.</summary>
    Branch,

    /// <summary>A RIP-relative displacement, adjusted so the absolute target is unchanged.</summary>
    RipRelative,

    /// <summary>An image-relative table address (disp32 off __ImageBase) re-pointed at the copy's table.</summary>
    TableAddress,
}

/// <summary>
/// A field the copier rewrote in a copy: the instruction at <see cref="CopySite"/> now resolves
/// to <see cref="Resolved"/>. <see cref="OriginalField"/> is the field's RVA in the original
/// range (what a linker fixup record names).
/// </summary>
public sealed record PatchedField(uint OriginalField, uint CopySite, uint Resolved, FieldKind Kind);

/// <summary>
/// A pointer aimed at a copy (<see cref="PointerRedirection"/>): the <c>lea</c> at
/// <see cref="Site"/>, or the 8-byte value there, now yields the copy of <see cref="Target"/>.
/// <see cref="Site"/> is an output RVA, in an original section or in a copy (<see cref="InCopy"/>).
/// </summary>
public sealed record RedirectedField(uint Site, bool IsLea, uint Target, bool InCopy);

public sealed class RewriteResult
{
    public byte[] Output { get; set; } = [];

    public uint TextRva { get; set; }

    public uint DataRva { get; set; }

    public RewriteMode Mode { get; set; }

    public List<MovedFunction> Moved { get; } = [];

    /// <summary>Functions not moved, with the reason (one entry per function).</summary>
    public List<(Function Function, string Reason)> Skipped { get; } = [];

    /// <summary>Rebuilt functions kept in their original block order although a block order was asked for, with the reason.</summary>
    public List<(Function Function, string Reason)> KeptBlockOrder { get; } = [];

    public List<PatchedField> Patched { get; } = [];

    /// <summary>New base relocation sites in the copies (64-bit absolute values copied verbatim).</summary>
    public List<uint> NewRelocations { get; } = [];

    /// <summary>The pointer redirection plan, when redirection was asked for.</summary>
    public RedirectionPlan? Redirection { get; set; }

    /// <summary>Every pointer field changed by redirection.</summary>
    public List<RedirectedField> Redirected { get; } = [];

    public List<string> Warnings { get; } = [];

    /// <summary>Load config tables rewritten in .wbdata with the moved targets' new addresses, and how many were added.</summary>
    public List<(string Table, int Added)> GuardTablesExtended { get; } = [];
}

/// <summary>
/// Copies functions into an appended .wbtext section and makes every original entry jump to
/// its copy. Without an order this is Stage 4 milestone 1, the verified no-op rewrite: every
/// eligible function, in original order. With an order (Stage 5 layout, e.g.
/// <see cref="FunctionOrdering.C3"/>) only the listed eligible functions move, in that order;
/// the rest stay where the linker put them.
/// Copies are byte-for-byte except fields that leave the range: branches go
/// to the callee's copy when it moved, RIP-relative operands keep their absolute target (so
/// code pointers keep the original, one-value address). Jump tables are rebuilt for the copy.
/// A new sorted exception table, the rebuilt jump tables and a new base relocation table go
/// into .wbdata.
/// </summary>
public static class FunctionRewriter
{
    private const int TrampolineSize = 5;

    /// <summary>
    /// Layout shifts come in whole cache lines: every 32-byte decision (JCC padding, loop
    /// alignment, copy placement) stays valid while cache sets and page boundaries move.
    /// </summary>
    public const uint LayoutShiftUnit = 64;
    private const int CopyAlignment = 16;
    private const uint TextCharacteristics = 0x60000020; // CODE | EXECUTE | READ
    private const uint DataCharacteristics = 0x40000040; // INITIALIZED_DATA | READ
    private const int RelocDir64 = 10;
    private const int RelocHighLow = 3;

    /// <summary>
    /// Refuses a .NET NativeAOT image (DesignDoc R5): the runtime registers one managed-code range and
    /// treats a return address outside it as native code (append-mode output fails fast at the first
    /// GC, verified), funclets sit at fixed offsets from their parent, and GC/EH info is keyed by
    /// offsets from each method's start. No mode handles any of that.
    /// </summary>
    internal static void RefuseNativeAot(BinaryImage image)
    {
        if (image.NativeAot is { } aot)
        {
            throw new RewriteRefusedException(
                $"this is a .NET NativeAOT image ({aot.Evidence}): the runtime registers a single managed-code range and keeps GC/EH info " +
                "and funclets at fixed offsets from each method, so moved code would crash at the first GC or exception (DesignDoc R5)");
        }
    }

    /// <param name="order">Entry RVAs of the functions to move, in layout order; null moves every eligible function in original order.</param>
    /// <param name="mode">Copy bytes (Stage 4), or re-encode each function from its CFG (Stage 6).</param>
    /// <param name="blockOrder">
    /// Rebuild only: each function's block order (Stage 6 layout, e.g. <see cref="BlockLayout.Order"/>),
    /// null for the original order. Cold blocks go to a cold area after all hot code, with an
    /// exception entry chained to the function's. A function whose blocks cannot move
    /// (<see cref="BlockRebuilder.LayoutReason"/>) keeps its order.
    /// </param>
    /// <param name="jccErratum">
    /// Keep executed branches off 32-byte boundaries (Intel's JCC erratum). Rebuild pads them
    /// (copies aligned to 32 bytes so the trial encoding sees the same boundaries); a byte copy
    /// cannot change inside, so each copy's start is chosen among 4-byte steps modulo 32 to put
    /// the fewest executed branches on a boundary (finer steps gain little; 16-byte steps half).
    /// </param>
    /// <param name="alignLoops">Rebuild only: start hot loop heads on a 32-byte boundary.</param>
    /// <param name="redirectPointers">
    /// Aim every pointer to a moved function at its copy where <see cref="PointerRedirection"/>
    /// proves all of them are known, so indirect calls skip the trampoline.
    /// </param>
    /// <param name="layoutEh">
    /// Reorder the blocks of plain unwind-only <c>__CxxFrameHandler4</c> functions too, regenerating
    /// their IP-to-state map (<see cref="Fh4Writer"/>); without it they move only as byte copies.
    /// </param>
    public static RewriteResult Rewrite(BinaryImage image, byte[] file, IReadOnlyList<uint>? order = null, RewriteMode mode = RewriteMode.Copy,
        Func<Function, BlockOrder?>? blockOrder = null, bool jccErratum = false, bool alignLoops = false, bool redirectPointers = false, bool layoutEh = false,
        uint layoutShift = 0, IReadOnlyDictionary<uint, uint>? promoteCalls = null)
    {
        if (layoutShift % LayoutShiftUnit != 0)
        {
            throw new ArgumentException($"the layout shift must be a multiple of {LayoutShiftUnit} bytes (it must not change any 32-byte decision)", nameof(layoutShift));
        }

        RefuseNativeAot(image);

        if ((blockOrder is not null || alignLoops) && mode != RewriteMode.Rebuild)
        {
            throw new ArgumentException("block layout and loop alignment need RewriteMode.Rebuild", nameof(mode));
        }

        uint alignment = (jccErratum || alignLoops) && mode == RewriteMode.Rebuild ? 32u : CopyAlignment;

        if (promoteCalls is { Count: > 0 } && mode != RewriteMode.Rebuild)
        {
            throw new ArgumentException("indirect call promotion needs RewriteMode.Rebuild", nameof(mode));
        }

        // Promotion inserts return addresses; EH tables map return addresses to states, so only
        // functions without handler data (or with a GS cookie only) promote. XFG puts a type hash
        // in r10 before guarded calls: images with it are left alone.
        IReadOnlyDictionary<uint, uint>? PromotionsFor(Function f) =>
            promoteCalls is { Count: > 0 } && image.LoadConfig is not { HasXfg: true } &&
            f.ExceptionHandler?.Kind is null or ExceptionHandlerKind.GsCookieCheck ? promoteCalls : null;

        var layout = new PeLayout(file);
        var eligible = Select(image, layoutEh && mode == RewriteMode.Rebuild, redirectPointers, out var skipped, out var spansOf, out var copyOnly, out var noTrampoline);
        if (order is not null)
        {
            var position = new Dictionary<uint, int>();
            foreach (uint entry in order)
            {
                position.TryAdd(entry, position.Count);
            }

            skipped.AddRange(eligible.Where(f => !position.ContainsKey(f.EntryRva)).Select(f => (f, "not in the layout order")));
            eligible = eligible.Where(f => position.ContainsKey(f.EntryRva)).OrderBy(f => position[f.EntryRva]).ToList();
        }

        // Rebuild: a trial encoding at the original address filters out what does not re-encode
        // cleanly and sizes each function (plus slack: distances change at the final address).
        var size = eligible.ToDictionary(f => f.EntryRva, f => f.EntryRange.Length);
        var coldSize = new Dictionary<uint, uint>();
        var coldEntryCount = new Dictionary<uint, int>();
        var layoutOf = new Dictionary<uint, BlockOrder>();
        var residueOf = new Dictionary<uint, uint>(); // rebuilt copy start past its 32-byte-aligned slot
        var keptOrder = new List<(Function, string)>();
        if (mode == RewriteMode.Rebuild)
        {
            var rebuildable = new List<Function>();
            foreach (var f in eligible)
            {
                if (copyOnly.Contains(f.EntryRva))
                {
                    rebuildable.Add(f); // moved as a byte copy (C++ EH tables shared with the original)
                    continue;
                }

                var placeholders = TableLoads(f).ToDictionary(site => site, _ => PlaceholderTable);
                string? reason = BlockRebuilder.Reason(image, f);
                var blocks = BlockOrder.Original(f);
                if (reason is null && blockOrder?.Invoke(f) is { } custom)
                {
                    if (custom.Problem(f) is { } problem)
                    {
                        throw new ArgumentException($"block order for {f.DisplayName}: {problem}", nameof(blockOrder));
                    }

                    if (BlockRebuilder.LayoutReason(image, f) is { } layoutReason)
                    {
                        keptOrder.Add((f, layoutReason));
                    }
                    else
                    {
                        blocks = custom;
                    }
                }

                if (reason is null)
                {
                    var trial = BlockRebuilder.TrialEncode(image, f, blocks, placeholders, jccErratum, alignLoops, alignment, out string? error, out uint residue, PromotionsFor(f));
                    if (residue != 0)
                    {
                        residueOf[f.EntryRva] = residue;
                    }

                    reason = trial is null ? $"rebuild: {error}" : BlockRebuilder.CheckPrologues(image, f, trial);
                    if (trial is not null)
                    {
                        size[f.EntryRva] = (uint)trial.Bytes.Length + RebuildSlack(f);
                        coldSize[f.EntryRva] = trial.ColdBytes.Length == 0 ? 0 : (uint)trial.ColdBytes.Length + RebuildSlack(f);
                        coldEntryCount[f.EntryRva] = trial.ColdSegments.Count;
                    }
                }

                if (reason is null)
                {
                    rebuildable.Add(f);
                    layoutOf[f.EntryRva] = blocks;
                }
                else
                {
                    skipped.Add((f, reason));
                }
            }

            eligible = rebuildable;
        }

        // Header room for two more section headers.
        uint firstRaw = image.Sections.Where(s => s.RawSize > 0).Min(s => s.FileOffset);
        long headersEnd = layout.SectionTable + (layout.NumberOfSections + 2L) * PeLayout.SectionHeaderSize;
        if (headersEnd > Math.Min(layout.SizeOfHeaders, firstRaw))
        {
            throw new RewriteRefusedException($"no room for two more section headers (headers end at 0x{layout.SizeOfHeaders:X}, need 0x{headersEnd:X})");
        }

        // Virtual layout: .wbtext then .wbdata after the last section.
        var last = image.Sections.MaxBy(s => s.Rva)!;
        uint textRva = PeLayout.Align(last.Rva + last.MappedSize, layout.SectionAlignment);
        var copyOf = new Dictionary<uint, uint>();
        uint offset = layoutShift;
        foreach (var f in eligible)
        {
            offset = PeLayout.Align(offset, alignment) + residueOf.GetValueOrDefault(f.EntryRva);
            if (jccErratum && (mode == RewriteMode.Copy || copyOnly.Contains(f.EntryRva)))
            {
                uint at = offset;
                offset = Enumerable.Range(0, (int)(32 / CopyShiftStep)).Select(k => at + (uint)k * CopyShiftStep)
                    .MinBy(o => LayoutStatistics.ExposureAt(image, f, textRva + o - (long)f.EntryRva));
            }

            copyOf[f.EntryRva] = textRva + offset;
            offset += size[f.EntryRva];
        }

        // Cold parts after all hot code.
        var coldOf = new Dictionary<uint, uint>();
        foreach (var f in eligible.Where(f => coldSize.GetValueOrDefault(f.EntryRva) > 0))
        {
            offset = PeLayout.Align(offset, CopyAlignment);
            coldOf[f.EntryRva] = textRva + offset;
            offset += coldSize[f.EntryRva];
        }

        uint textSize = offset;
        var text = Enumerable.Repeat((byte)0xCC, (int)PeLayout.Align(Math.Max(textSize, 1), layout.FileAlignment)).ToArray();

        var result = new RewriteResult { TextRva = textRva, Mode = mode };
        result.Skipped.AddRange(skipped);
        result.KeptBlockOrder.AddRange(keptOrder);

        result.Redirection = redirectPointers ? PointerRedirection.Plan(image, copyOf) : null;
        var pointerTargets = result.Redirection?.Targets ?? [];

        // A function without room for a trampoline moves only if every pointer to it now yields
        // the copy; otherwise an indirect call would run the original and a comparison could see
        // two values. Its slot in .wbtext stays int3.
        foreach (var f in eligible.Where(f => noTrampoline.ContainsKey(f.EntryRva) && !pointerTargets.ContainsKey(f.EntryRva)).ToList())
        {
            eligible.Remove(f);
            copyOf.Remove(f.EntryRva);
            coldOf.Remove(f.EntryRva);
            string why = result.Redirection!.Excluded.TryGetValue(f.EntryRva, out string? excluded) ? excluded : "no pointer to it";
            result.Skipped.Add((f, $"{noTrampoline[f.EntryRva]}, and not redirected ({why})"));
        }

        var dataSites = (result.Redirection?.Sites ?? []).Where(s => !s.IsLea).OrderBy(s => s.Rva).ToArray();
        var leaSites = (result.Redirection?.Sites ?? []).Where(s => s.IsLea).OrderBy(s => s.Rva).ToArray();

        // .wbdata layout: exception table, rebuilt jump tables, chained UNWIND_INFO copies, relocations.
        // A rebuilt function drops the entry MSVC gives its trailing switch tables (they are rebuilt below).
        var entriesIn = eligible.ToDictionary(f => f.EntryRva, f => EntriesInRange(image, f)
            .Where(e => !(mode == RewriteMode.Rebuild && !copyOnly.Contains(f.EntryRva) && BlockRebuilder.IsTableEntry(image, f, e))).ToList());
        uint dataRva = PeLayout.Align(textRva + textSize, layout.SectionAlignment);
        int coldEntries = eligible.Sum(f => coldEntryCount.GetValueOrDefault(f.EntryRva));
        uint pdataTableSize = (uint)(12 * (image.ExceptionData.Count + entriesIn.Values.Sum(e => e.Count) + coldEntries));
        uint jumpTablesSize = (uint)eligible.Sum(f => TableUnits(f).Sum(u => (long)u.Size));
        var jumpTables = new List<byte>();
        var unwindCopies = new List<byte>();

        foreach (var f in eligible)
        {
            uint start = f.EntryRva, length = f.EntryRange.Length, copy = copyOf[start];
            bool rebuild = mode == RewriteMode.Rebuild && !copyOnly.Contains(start);

            // Rebuilt tables are placed first; their entries need the code's final addresses.
            var tables = new List<CopiedTable>();
            uint tableAt = dataRva + pdataTableSize + (uint)jumpTables.Count;
            foreach (var unit in TableUnits(f))
            {
                foreach (var table in unit.Tables)
                {
                    bool relative = table.Encoding == JumpTableEncoding.TableRelativeOffset32;
                    uint at = relative ? tableAt + ((uint)table.Rva - unit.Start) : tableAt;
                    tables.Add(new CopiedTable((uint)table.Rva, at, table.EntryCount, (uint)table.LoadRva!.Value, (uint?)table.IndexLoadRva)
                    {
                        BaseSites = relative ? BaseSitesOf(f, table.BaseRva) : [],
                        OriginalBaseRva = relative ? (uint)table.BaseRva : 0,
                        NewBaseRva = relative ? tableAt + ((uint)table.BaseRva - unit.Start) : 0,
                    });
                    if (!relative)
                    {
                        tableAt += 4 * (uint)table.EntryCount;
                    }
                }

                if (unit.Tables[0].Encoding == JumpTableEncoding.TableRelativeOffset32)
                {
                    tableAt += unit.Size;
                }
            }

            var tableFields = new Dictionary<uint, uint>();
            foreach (var table in f.JumpTables)
            {
                foreach (ulong site in table.FieldSites)
                {
                    tableFields[(uint)site] = table.Encoding == JumpTableEncoding.TableRelativeOffset32
                        ? tables.First(t => t.TableRelative && t.OriginalBaseRva == table.BaseRva).NewBaseRva
                        : tables.Single(t => t.OriginalRva == table.Rva).NewRva;
                }

                // A copy reads its own index bytes; a rebuilt function drops range data and keeps reading the original's.
                if (!rebuild && table.IndexTableRva is { } index && index >= start && index < start + length)
                {
                    tableFields[(uint)table.IndexLoadRva!.Value] = copy + ((uint)index - start);
                }
            }

            Dictionary<uint, uint>? addressMap = null;
            IReadOnlyDictionary<uint, uint> promotedCalls = new Dictionary<uint, uint>();
            IReadOnlyList<ColdSegment> coldSegments = [];
            uint copyLength = length, coldStart = coldOf.GetValueOrDefault(start), coldLength = 0;
            if (!rebuild)
            {
                var bytes = image.ReadFrom(start).Span[..(int)length].ToArray();
                CopyWithFixups(start, copy, bytes, spansOf[start], copyOf, tableFields, pointerTargets, result);

                // Relocated pointers in the copied bytes (mov r64,imm64) name the copy like every other.
                foreach (var site in In(dataSites, start, start + length))
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan((int)(site.Rva - start)), image.ImageBase + pointerTargets[site.Target]);
                    result.Redirected.Add(new RedirectedField(copy + (site.Rva - start), false, site.Target, InCopy: true));
                }

                // The copy reads its rebuilt tables; left in place, the stale entries would decode
                // as code (and branches) to any analysis of the output. Index bytes stay: the copy reads them.
                foreach (var table in tables.Where(t => t.OriginalRva >= start && t.OriginalRva < start + length))
                {
                    bytes.AsSpan((int)(table.OriginalRva - start), 4 * table.EntryCount).Fill(0xCC);
                }

                bytes.CopyTo(text, (int)(copy - textRva));
            }
            else
            {
                var code = BlockRebuilder.Encode(image, f, layoutOf[start], copy, coldStart, copyOf, tableFields, out string? error, jccErratum, size[start], alignLoops, pointerTargets, PromotionsFor(f))
                    ?? throw new RewriteRefusedException($"{f.DisplayName} no longer encodes at its copy: {error}");
                if (code.Bytes.Length > size[start] || code.ColdBytes.Length > coldSize[start])
                {
                    throw new RewriteRefusedException($"{f.DisplayName}: the final encoding needs {code.Bytes.Length} + {code.ColdBytes.Length} bytes, " +
                                                      $"{size[start]} + {coldSize[start]} reserved");
                }

                if (code.ColdBytes.Length > 0)
                {
                    code.ColdBytes.CopyTo(text, (int)(coldStart - textRva));
                    coldLength = (uint)code.ColdBytes.Length;
                    coldSegments = code.ColdSegments;
                }

                if (BlockRebuilder.CheckPrologues(image, f, code) is { } problem)
                {
                    throw new RewriteRefusedException($"{f.DisplayName}: {problem} at its final address");
                }

                code.Bytes.CopyTo(text, (int)(copy - textRva));
                addressMap = code.AddressMap;
                promotedCalls = code.Promoted;
                copyLength = (uint)code.Bytes.Length;
            }

            uint Map(uint rva) => addressMap is null ? copy + (rva - start) : addressMap[rva];
            foreach (var site in In(leaSites, start, start + length))
            {
                if (addressMap is null || addressMap.ContainsKey(site.Rva))
                {
                    result.Redirected.Add(new RedirectedField(Map(site.Rva), true, site.Target, InCopy: true));
                }
            }

            foreach (var unit in TableUnits(f))
            {
                if (unit.Tables[0].Encoding != JumpTableEncoding.TableRelativeOffset32)
                {
                    foreach (ulong target in unit.Tables[0].TargetRvas)
                    {
                        AppendU32(jumpTables, target >= start && target < start + length ? Map((uint)target) : (uint)target);
                    }

                    continue;
                }

                // Tables sharing a base register keep their offsets from it: the region is copied
                // (bytes between the tables stay as they were), then every entry is rewritten
                // relative to the new base.
                var region = image.ReadFrom(unit.Start).Span[..(int)unit.Size].ToArray();
                uint newBase = tables.First(t => t.TableRelative && t.OriginalBaseRva == unit.Tables[0].BaseRva).NewBaseRva;
                foreach (var table in unit.Tables)
                {
                    for (int i = 0; i < table.TargetRvas.Count; i++)
                    {
                        ulong target = table.TargetRvas[i];
                        uint placed = target >= start && target < start + length ? Map((uint)target) : (uint)target;
                        BinaryPrimitives.WriteUInt32LittleEndian(region.AsSpan((int)((uint)table.Rva - unit.Start) + 4 * i), placed - newBase);
                    }
                }

                jumpTables.AddRange(region);
            }

            foreach (var relocation in image.Relocations)
            {
                if (relocation.Type == RelocationType.Dir64 && relocation.Rva >= start && relocation.Rva < start + length)
                {
                    result.NewRelocations.Add(Map(relocation.Rva));
                }
            }

            // Parents first: fragments may chain to fragments.
            var copied = new Dictionary<uint, CopiedPdata>();
            foreach (var entry in entriesIn[start])
            {
                uint unwind = entry.UnwindInfoAddress;
                if (entry.IsChained)
                {
                    var parent = copied[entry.ChainedParent!.BeginAddress];
                    var info = ChainedUnwindCopy(image, entry.UnwindInfoAddress, parent);
                    while (unwindCopies.Count % 4 != 0)
                    {
                        unwindCopies.Add(0);
                    }

                    unwind = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                    unwindCopies.AddRange(info);
                }
                else if (entry.HasHandler && f.ExceptionHandler?.Kind == ExceptionHandlerKind.CSpecific && !rebuild)
                {
                    while (unwindCopies.Count % 4 != 0)
                    {
                        unwindCopies.Add(0);
                    }

                    unwind = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                    unwindCopies.AddRange(SehUnwindCopy(image, entry, start, start + length, copy - start));
                }
                else if (entry.HasHandler && f.ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler3 && !rebuild)
                {
                    while (unwindCopies.Count % 4 != 0)
                    {
                        unwindCopies.Add(0);
                    }

                    unwind = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                    unwindCopies.AddRange(Fh3UnwindCopy(image, entry, start, start + length, copy - start, unwind));
                }
                else if (entry.HasHandler && rebuild && f.ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler3 && addressMap is not null)
                {
                    // Reordered FH3 function: a new IP-to-state map, FuncInfo and UNWIND_INFO in .wbdata.
                    while (unwindCopies.Count % 4 != 0)
                    {
                        unwindCopies.Add(0);
                    }

                    uint baseRva = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                    var (fh3Bytes, fh3Unwind) = Fh3Writer.Build(image, f, addressMap, baseRva);
                    unwindCopies.AddRange(fh3Bytes);
                    unwind = fh3Unwind;
                }
                else if (entry.HasHandler && rebuild && f.ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler4 && addressMap is not null)
                {
                    // Reordered FH4 function: a new IP-to-state map, FuncInfo4 and UNWIND_INFO in .wbdata.
                    while (unwindCopies.Count % 4 != 0)
                    {
                        unwindCopies.Add(0);
                    }

                    uint baseRva = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                    var (fh4Bytes, fh4Unwind) = Fh4Writer.Build(image, f, addressMap, copy, coldSegments.Select(s => (s.Start, s.End)).ToList(), baseRva);
                    unwindCopies.AddRange(fh4Bytes);
                    unwind = fh4Unwind;
                }

                copied[entry.BeginAddress] = new CopiedPdata(entry.BeginAddress, Map(entry.BeginAddress), Map(entry.EndAddress), unwind, entry.IsChained);
            }

            // Cold code runs with the frame its entry's prologue set up: a chained entry with no
            // unwind codes of its own, pointing at that entry's copy (as MSVC does for separated code).
            var coldPdata = new List<CopiedPdata>();
            foreach (var segment in coldSegments)
            {
                while (unwindCopies.Count % 4 != 0)
                {
                    unwindCopies.Add(0);
                }

                var parent = copied[segment.EntryBegin];
                var source = entriesIn[start].First(e => e.BeginAddress == segment.EntryBegin);
                uint unwind = dataRva + pdataTableSize + jumpTablesSize + (uint)unwindCopies.Count;
                unwindCopies.AddRange(ColdUnwindInfo(image.ReadFrom(source.UnwindInfoAddress & ~1u).Span[3], parent));
                coldPdata.Add(new CopiedPdata(segment.EntryBegin, segment.Start, segment.End, unwind, Chained: true));
            }

            result.Moved.Add(new MovedFunction(f.Id, f.DisplayName, start, length, copy, copied.Values.ToList(), tables, spansOf[start])
            {
                AddressMap = addressMap,
                PromotedCalls = promotedCalls,
                HasTrampoline = !noTrampoline.ContainsKey(start),
                CopyLength = copyLength,
                ColdStart = coldLength > 0 ? coldStart : 0,
                ColdLength = coldLength,
                ColdEntries = coldPdata,
            });
        }

        var pdata = image.ExceptionData.Select(e => (e.BeginAddress, e.EndAddress, e.UnwindInfoAddress))
            .Concat(result.Moved.SelectMany(m => m.Pdata.Concat(m.ColdEntries)).Select(c => (c.Begin, c.End, c.UnwindInfo)))
            .OrderBy(e => e.Item1)
            .ToList();
        var data = new List<byte>();
        foreach (var (begin, end, unwind) in pdata)
        {
            AppendU32(data, begin);
            AppendU32(data, end);
            AppendU32(data, unwind);
        }

        uint pdataSize = (uint)data.Count;
        data.AddRange(jumpTables);
        data.AddRange(unwindCopies);
        while (data.Count % 4 != 0)
        {
            data.Add(0);
        }

        // Longjmp / EH-continuation tables naming the moved targets too (GuardTables).
        var guardTables = new List<(int Field, uint Rva, int Count)>();
        foreach (int field in GuardTables.Fields(image))
        {
            var entries = GuardTables.Entries(image, field);
            var extended = GuardTables.Extended(field, entries, result.Moved, MapMoved);
            if (extended.Count == entries.Count)
            {
                continue;
            }

            guardTables.Add((field, dataRva + (uint)data.Count, extended.Count));
            result.GuardTablesExtended.Add((GuardTables.Name(field), extended.Count - entries.Count));
            foreach (uint entry in extended)
            {
                AppendU32(data, entry);
            }
        }

        uint relocOffset = (uint)data.Count;
        var relocations = image.Relocations
            .Where(r => r.Type is RelocationType.Dir64 or RelocationType.HighLow)
            .Select(r => (r.Rva, Type: r.Type == RelocationType.Dir64 ? RelocDir64 : RelocHighLow))
            .Concat(result.NewRelocations.Select(r => (Rva: r, Type: RelocDir64)));
        data.AddRange(BuildRelocationTable(relocations));
        uint relocSize = (uint)data.Count - relocOffset;
        uint dataSize = (uint)data.Count;
        var dataBytes = new byte[PeLayout.Align(Math.Max(dataSize, 1), layout.FileAlignment)];
        data.CopyTo(dataBytes);

        // File layout: original bytes (minus a trailing certificate), padded, then both sections.
        var baseFile = StripCertificate(file, layout, result);
        uint textRaw = PeLayout.Align((uint)baseFile.Length, layout.FileAlignment);
        uint dataRaw = textRaw + (uint)text.Length;
        var output = new byte[dataRaw + dataBytes.Length];
        baseFile.CopyTo(output, 0);
        text.CopyTo(output, (int)textRaw);
        dataBytes.CopyTo(output, (int)dataRaw);

        // Trampolines at the original entries.
        foreach (var moved in result.Moved.Where(m => m.HasTrampoline))
        {
            var section = image.FindSection(moved.Start)!;
            int at = (int)(section.FileOffset + (moved.Start - section.Rva));
            output[at] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(at + 1), (int)(moved.CopyStart - (moved.Start + TrampolineSize)));
        }

        // Redirected pointers in the original sections, also in moved functions' original bodies
        // (cold ranges and unknown references still run them). A trampoline has replaced the
        // bytes under it: nothing there is decoded any more.
        var trampolineStarts = result.Moved.Where(m => m.HasTrampoline).Select(m => m.Start).Order().ToArray();
        foreach (var site in dataSites.Concat(leaSites))
        {
            var section = image.FindSection(site.Rva)!;
            int at = (int)(section.FileOffset + (site.Rva - section.Rva));
            uint copy = pointerTargets[site.Target];
            uint siteEnd;
            if (site.IsLea)
            {
                var code = image.ReadFrom(site.Rva);
                var decoder = Decoder.Create(64, new ByteArrayCodeReader(code[..Math.Min(code.Length, 15)].ToArray()));
                decoder.IP = site.Rva;
                var lea = decoder.Decode();
                siteEnd = site.Rva + (uint)lea.Length;
                if (UnderTrampoline(trampolineStarts, site.Rva, siteEnd))
                {
                    continue;
                }

                var offsets = decoder.GetConstantOffsets(lea);
                BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(at + offsets.DisplacementOffset), (int)(copy - siteEnd));
            }
            else
            {
                siteEnd = site.Rva + 8;
                if (UnderTrampoline(trampolineStarts, site.Rva, siteEnd))
                {
                    continue;
                }

                BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(at), image.ImageBase + copy);
            }

            result.Redirected.Add(new RedirectedField(site.Rva, site.IsLea, site.Target, InCopy: false));
        }

        foreach (var (field, rva, count) in guardTables)
        {
            GuardTables.Repoint(image, output, field, rva, count);
        }

        // Headers.
        int newHeaders = layout.SectionTable + layout.NumberOfSections * PeLayout.SectionHeaderSize;
        PeLayout.WriteSectionHeader(output.AsSpan(newHeaders, PeLayout.SectionHeaderSize), ".wbtext", Math.Max(textSize, 1), textRva, (uint)text.Length, textRaw, TextCharacteristics);
        PeLayout.WriteSectionHeader(output.AsSpan(newHeaders + PeLayout.SectionHeaderSize, PeLayout.SectionHeaderSize), ".wbdata", Math.Max(dataSize, 1), dataRva, (uint)dataBytes.Length, dataRaw, DataCharacteristics);
        BinaryPrimitives.WriteUInt16LittleEndian(output.AsSpan(layout.NumberOfSectionsOffset), (ushort)(layout.NumberOfSections + 2));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.SizeOfImageOffset), PeLayout.Align(dataRva + Math.Max(dataSize, 1), layout.SectionAlignment));
        uint sizeOfCode = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(layout.SizeOfCodeOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.SizeOfCodeOffset), sizeOfCode + (uint)text.Length);
        WriteDirectory(output, layout, PeLayout.ExceptionDirectory, dataRva, pdataSize);
        WriteDirectory(output, layout, PeLayout.BaseRelocationDirectory, dataRva + relocOffset, relocSize);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.CheckSumOffset), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(layout.CheckSumOffset), PeChecksum.Compute(output, layout.CheckSumOffset));

        result.Output = output;
        result.DataRva = dataRva;
        return result;
    }

    private const uint PlaceholderTable = BlockRebuilder.PlaceholderTable;

    /// <summary>A moved function's new address for an instruction of its range.</summary>
    internal static uint? MapMoved(MovedFunction m, uint rva) =>
        m.AddressMap is null ? m.CopyStart + (rva - m.Start) : m.AddressMap.TryGetValue(rva, out uint at) ? at : null;

    /// <summary>Copy mode with the JCC erratum option: step between candidate copy starts past the 16-byte-aligned slot.</summary>
    private const uint CopyShiftStep = BlockRebuilder.ShiftStep;

    private const byte UnwindChainInfo = 0x4;

    /// <summary>
    /// UNWIND_INFO for a cold part: version 1, UNW_FLAG_CHAININFO, no prologue and no codes, the
    /// parent's frame register, then the parent's (primary) RUNTIME_FUNCTION.
    /// </summary>
    internal static byte[] ColdUnwindInfo(byte frameRegister, CopiedPdata primary)
    {
        var info = new byte[16];
        info[0] = 1 | (UnwindChainInfo << 3);
        info[3] = frameRegister;
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(4), primary.Begin);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(8), primary.End);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(12), primary.UnwindInfo);
        return info;
    }

    /// <summary>Headroom for branches whose form changes between the trial and the final address.</summary>
    private static uint RebuildSlack(Function f) => 16 + 4 * (uint)f.EntryBlocks.Count();

    private static IEnumerable<uint> TableLoads(Function f) =>
        f.JumpTables.SelectMany(t => t.FieldSites).Select(site => (uint)site).Distinct();

    /// <summary>The sites (sorted by RVA) in [<paramref name="start"/>, <paramref name="end"/>).</summary>
    private static IEnumerable<PointerSite> In(PointerSite[] sorted, uint start, uint end)
    {
        int lo = 0, hi = sorted.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (sorted[mid].Rva < start)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        for (int i = lo; i < sorted.Length && sorted[i].Rva < end; i++)
        {
            yield return sorted[i];
        }
    }

    /// <summary>True if [<paramref name="start"/>, <paramref name="end"/>) overlaps a trampoline (5 bytes at each sorted start).</summary>
    private static bool UnderTrampoline(uint[] starts, uint start, uint end)
    {
        int i = Array.BinarySearch(starts, end - 1);
        i = i >= 0 ? i : ~i - 1;
        return i >= 0 && starts[i] + TrampolineSize > start;
    }

    /// <summary>Every base lea of the table-relative table at <paramref name="table"/>, over all dispatch sites that share it.</summary>
    private static List<uint> BaseSitesOf(Function f, ulong baseRva) =>
        f.JumpTables.Where(t => t.Encoding == JumpTableEncoding.TableRelativeOffset32 && t.BaseRva == baseRva)
            .SelectMany(t => t.BaseSites).Select(s => (uint)s).Distinct().Order().ToList();

    /// <summary>
    /// What is moved to .wbdata as one piece: an image-relative table by itself, and all the
    /// table-relative tables that share a base as one region from the lowest table (or the base)
    /// to the end of the highest, since their loads address them by displacement from the base.
    /// </summary>
    private sealed record TableUnit(List<JumpTable> Tables, uint Start, uint Size);

    private static List<TableUnit> TableUnits(Function f)
    {
        var units = new List<TableUnit>();
        foreach (var table in DistinctTables(f).Where(t => t.Encoding != JumpTableEncoding.TableRelativeOffset32))
        {
            units.Add(new TableUnit([table], (uint)table.Rva, 4 * (uint)table.EntryCount));
        }

        foreach (var group in DistinctTables(f).Where(t => t.Encoding == JumpTableEncoding.TableRelativeOffset32).GroupBy(t => t.BaseRva))
        {
            uint start = (uint)Math.Min(group.Key, group.Min(t => t.Rva));
            uint end = (uint)Math.Max(group.Key, group.Max(t => t.Rva + 4 * (ulong)t.EntryCount));
            units.Add(new TableUnit(group.OrderBy(t => t.Rva).ToList(), start, end - start));
        }

        return units;
    }

    /// <summary>One entry per table address: two dispatch sites may share a table.</summary>
    private static IEnumerable<JumpTable> DistinctTables(Function f) => f.JumpTables.GroupBy(t => t.Rva).Select(g => g.First());

    /// <summary>
    /// Milestone 1 eligibility (DesignDoc Stage 4); every other function gets a reason.
    /// <paramref name="copyOnly"/>: functions that may move only as a byte copy (C++ EH tables
    /// shared with the original, or interior code pointers into the original body).
    /// </summary>
    /// <paramref name="noTrampoline"/>: with <paramref name="redirectPointers"/>, functions whose
    /// entry cannot hold a trampoline (entry → why); they move only if redirection covers them.
    private static List<Function> Select(BinaryImage image, bool layoutEh, bool redirectPointers, out List<(Function, string)> skipped,
        out Dictionary<uint, IReadOnlyList<DataSpan>> spansOf, out HashSet<uint> copyOnly, out Dictionary<uint, string> noTrampoline)
    {
        skipped = [];
        spansOf = [];
        copyOnly = [];
        noTrampoline = [];
        // Longjmp and EH-continuation targets move when the output can list their new addresses.
        bool extendGuardTables = GuardTables.Problem(image) is null;
        var longJumps = extendGuardTables ? [] : new HashSet<uint>(image.LoadConfig?.GuardLongJumpTargetTable ?? []);
        var ehContinuations = extendGuardTables ? [] : new HashSet<uint>(image.LoadConfig?.GuardEhContinuationTable ?? []);
        var externalTargets = image.CallSites.Where(c => c.TargetRva is not null).Select(c => c.TargetRva!.Value)
            .Concat(image.CodePointers.Select(p => p.TargetRva))
            .ToHashSet();

        var eligible = new List<Function>();
        foreach (var f in image.Functions.OrderBy(f => f.EntryRva))
        {
            string? reason = Reason(image, f, longJumps, ehContinuations, externalTargets, layoutEh, out var spans, out bool asCopy, out string? trampolineProblem);
            if (reason is null && trampolineProblem is not null)
            {
                if (redirectPointers)
                {
                    noTrampoline[f.EntryRva] = trampolineProblem;
                }
                else
                {
                    reason = trampolineProblem;
                }
            }

            if (reason is null)
            {
                eligible.Add(f);
                spansOf[f.EntryRva] = spans;
                if (asCopy)
                {
                    copyOnly.Add(f.EntryRva);
                }
            }
            else
            {
                skipped.Add((f, reason));
            }
        }

        return eligible;
    }

    /// <param name="trampolineProblem">Why the entry cannot hold a trampoline (the function is otherwise eligible when the result is null).</param>
    private static string? Reason(BinaryImage image, Function f, HashSet<uint> longJumps, HashSet<uint> ehContinuations, HashSet<uint> externalTargets, bool layoutEh,
        out IReadOnlyList<DataSpan> spans, out bool asCopy, out string? trampolineProblem)
    {
        spans = [];
        asCopy = false;
        trampolineProblem = null;
        var level = f.SafetyStatus.Level;

        // The gate freezes an address-taken function whose entry cannot hold a trampoline; that is
        // the only obstacle when it is the only reason, and pointer redirection can remove it.
        if (level == Transformability.Frozen && f.DowngradeReasons.Count > 0 &&
            f.DowngradeReasons.All(r => r.StartsWith("trampoline-window", StringComparison.Ordinal)))
        {
            trampolineProblem = "address-taken, and the trampoline window is blocked";
            level = Transformability.FullyTransformable;
        }

        // RelocatableOnly means "may move as a unit" (§5.5): a byte copy, never rebuilt. Accepted
        // for the reasons a copy keeps valid: C++ EH tables and SEH scope tables (below), and
        // interior code pointers, which keep naming the original body, left intact past the
        // trampoline.
        if (level == Transformability.RelocatableOnly &&
            f.DowngradeReasons.All(r => r.StartsWith("cxx-eh-table", StringComparison.Ordinal) || r.StartsWith("interior-pointer", StringComparison.Ordinal) ||
                                        r.StartsWith("seh-scope-table", StringComparison.Ordinal)))
        {
            asCopy = true;
        }
        else if (level != Transformability.FullyTransformable)
        {
            return $"not FullyTransformable ({f.SafetyStatus.Level})";
        }

        // A function split by PGO or BBT moves its entry range only; its other ranges (cold code)
        // stay in place, branch back into the original body, and keep their chained unwind
        // entries, whose parent is the original primary entry.
        // __CxxFrameHandler4 decodes a function's tables against the start of the unwind entry the
        // frame's IP lies in (DispatcherContext->FunctionEntry->BeginAddress): IP-to-state entries and
        // catch continuations are offsets from it, so a byte copy shares the original tables. Not
        // for separated functions (their segments are keyed by absolute RVA) or catch funclets (the
        // runtime identifies a running catch handler by its entry's RVA).
        if (f.ExceptionHandler is { Kind: ExceptionHandlerKind.CxxFrameHandler4 } &&
            f.CxxEh is { Version: 4, Problem: null, IsSeparated: false, IsCatch: false })
        {
            // With layoutEh, a plain unwind-only FH4 function is reordered and its IP-to-state map
            // regenerated (Fh4Writer); otherwise it moves only as a byte copy sharing the original tables.
            asCopy = !(layoutEh && Fh4Writer.CanLayout(image, f));
        }
        // __C_specific_handler compares the IP with absolute RVAs in the scope table: a copy gets
        // its own UNWIND_INFO with the table rebased (SehUnwindCopy).
        else if (f.ExceptionHandler is { Kind: ExceptionHandlerKind.CSpecific } && f.ScopeTable is { Count: > 0 })
        {
            asCopy = true;
        }
        // __CxxFrameHandler3 looks the state up by absolute RVA in the FuncInfo's IP-to-state map: a
        // copy gets its own UNWIND_INFO naming a copy of the FuncInfo whose map is rebased
        // (Fh3UnwindCopy). Everything else in the FuncInfo (unwind and try block maps, funclets) is shared.
        else if (f.ExceptionHandler is { Kind: ExceptionHandlerKind.CxxFrameHandler3 } && f.CxxEh is { Version: 3, Problem: null })
        {
            // A running catch funclet is identified by its entry's RVA being a catch handler of the
            // FuncInfo: a copy would not be recognized, and the runtime aborts.
            if (WinBolt.Core.Passes.Analysis.CxxEhParser.Fh3CatchHandlers(image, f.CxxEh.FuncInfoRva).Contains(f.EntryRva))
            {
                return "catch funclet: the runtime identifies it by its original entry";
            }

            // With layoutEh, the function is reordered and its map regenerated (Fh3Writer); otherwise a byte copy.
            asCopy = !(layoutEh && Fh3Writer.CanLayout(image, f));
        }
        else if (f.ExceptionHandler is { Kind: not ExceptionHandlerKind.GsCookieCheck })
        {
            return "language handler data would need rebasing";
        }

        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        if (f.EntryRange.Length < TrampolineSize)
        {
            trampolineProblem = "too short for a trampoline";
        }

        if (TableReason(f, start, end, out spans) is { } tableReason)
        {
            return tableReason;
        }

        var entries = ImageIndex.For(image).EntriesBeginningIn(start, end).ToList();
        if (entries.Any(e => e.IsChained && (e.UnwindInfoAddress & 1) != 0))
        {
            return "indirect unwind chain";
        }

        if (entries.Any(e => e.IsChained && (e.ChainedParent is null || e.ChainedParent.BeginAddress < start || e.ChainedParent.BeginAddress >= end)))
        {
            return "unwind chain leaves the range";
        }

        if (entries.Count(e => !e.IsChained) > 1 || entries.Any(e => !e.IsChained && e.BeginAddress != start))
        {
            return "unexpected primary unwind entries in the range";
        }

        if (longJumps.Any(t => t >= start && t < end) || ehContinuations.Any(t => t >= start && t < end))
        {
            return "contains a longjmp or EH-continuation target";
        }

        if (f.EntryBlocks.Any(b => b.StartRva > start && b.StartRva < start + TrampolineSize && b.IsBranchTarget) ||
            Enumerable.Range(1, TrampolineSize - 1).Any(i => externalTargets.Contains(start + (uint)i)))
        {
            trampolineProblem ??= "a branch target lies inside the trampoline window";
        }

        // Linear decode of the code bytes (tables stepped over) must agree with the CFG and stay decodable.
        var bytes = image.ReadFrom(start);
        if (bytes.Length < end - start)
        {
            return "range is not fully file-backed";
        }

        if (DecodeCode(bytes[..(int)(end - start)].ToArray(), start, spans, out string? error) is not { } decoded)
        {
            return error;
        }

        var linear = new Dictionary<uint, (Instruction Instruction, ConstantOffsets Offsets)>();
        foreach (var (instruction, offsets) in decoded)
        {
            linear[(uint)instruction.IP] = (instruction, offsets);
            bool leaves = instruction.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch or FlowControl.Call &&
                          instruction.Op0Kind is OpKind.NearBranch64 &&
                          (instruction.NearBranchTarget < start || instruction.NearBranchTarget >= end);
            if (leaves && (instruction.IsJmpShort || instruction.IsJccShort ||
                           instruction.Mnemonic is Mnemonic.Loop or Mnemonic.Loope or Mnemonic.Loopne or Mnemonic.Jrcxz or Mnemonic.Jecxz))
            {
                return $"rel8 branch leaves the range at 0x{instruction.IP:X}";
            }
        }

        var cfgStarts = f.EntryBlocks
            .SelectMany(b => Enumerable.Range(b.InstructionStart, b.InstructionCount))
            .Select(i => (uint)image.Instructions[i].IP);
        if (!cfgStarts.All(linear.ContainsKey))
        {
            return "linear decoding disagrees with the CFG";
        }

        // Each table load must be the decoded instruction recovery matched, addressing the table
        // through a 32-bit displacement the copier can rewrite.
        foreach (var table in f.JumpTables)
        {
            if (table.Encoding == JumpTableEncoding.TableRelativeOffset32)
            {
                // Every base site is a lea of the table; no other instruction may address the table
                // (it stays in place, but the copy must not mix the old and the new one).
                var sites = BaseSitesOf(f, table.BaseRva).ToHashSet();
                bool leas = sites.All(s => linear.TryGetValue(s, out var l) && l.Instruction is { Mnemonic: Mnemonic.Lea } && l.Instruction.IsIPRelativeMemoryOperand &&
                                          l.Instruction.IPRelativeMemoryAddress == table.BaseRva && l.Offsets.DisplacementSize == 4);
                var units = TableUnits(f).Where(u => u.Tables[0].Encoding == JumpTableEncoding.TableRelativeOffset32).ToList();
                var own = units.Single(u => u.Tables[0].BaseRva == table.BaseRva);
                var stray = linear.Values.Where(l => l.Instruction.IsIPRelativeMemoryOperand && !sites.Contains((uint)l.Instruction.IP) &&
                                                     l.Instruction.IPRelativeMemoryAddress >= own.Start && l.Instruction.IPRelativeMemoryAddress < own.Start + own.Size)
                    .Select(l => (uint)l.Instruction.IP).ToList();
                bool others = stray.Count > 0;
                bool overlap = units.Any(a => units.Any(b => a != b && a.Start < b.Start + b.Size && b.Start < a.Start + a.Size));
                if (!leas || others || overlap)
                {
                    string detail = overlap
                        ? "shared with another table region"
                        : $"not only loaded by lea (also addressed at 0x{(stray.Count > 0 ? stray[0] : 0):X}; base sites {string.Join(",", sites.Select(x => x.ToString("X")))})";
                    return $"table-relative jump table 0x{table.Rva:X}: its base is {detail}";
                }

                continue;
            }

            if (!IsTableLoad(linear, table.LoadRva!.Value, table.Rva) ||
                (table.IndexTableRva is { } index && !IsTableLoad(linear, table.IndexLoadRva!.Value, index)))
            {
                return $"jump table load for 0x{table.Rva:X} is not a disp32 table access";
            }
        }

        return null;
    }

    /// <summary>iced reports a sign-extended disp32 as size 8 in 64-bit mode; the encoded field size is in the constant offsets.</summary>
    private static bool IsTableLoad(Dictionary<uint, (Instruction Instruction, ConstantOffsets Offsets)> linear, ulong site, ulong table) =>
        linear.TryGetValue((uint)site, out var load) &&
        load.Instruction.Op1Kind == OpKind.Memory && !load.Instruction.IsIPRelativeMemoryOperand &&
        load.Offsets.DisplacementSize == 4 && load.Instruction.MemoryDisplacement64 == table;

    /// <summary>Tables the writer can rebuild, and the data spans they occupy inside the range.</summary>
    private static string? TableReason(Function f, uint start, uint end, out IReadOnlyList<DataSpan> spans)
    {
        spans = [];
        var inRange = new List<DataSpan>();
        foreach (var table in f.JumpTables)
        {
            if (table.Encoding is not (JumpTableEncoding.ImageRelativeOffset32 or JumpTableEncoding.TwoLevelMsvc or JumpTableEncoding.TableRelativeOffset32))
            {
                return $"jump table encoding {table.Encoding}";
            }

            if (table.Encoding == JumpTableEncoding.TableRelativeOffset32 &&
                (table.BaseSites.Count == 0 || table.Rva + 0x10000 < table.BaseRva || table.Rva > table.BaseRva + 0x10000 || (table.Rva - table.BaseRva) % 4 != 0))
            {
                return $"table-relative jump table 0x{table.Rva:X} is not at a plausible offset from its base 0x{table.BaseRva:X}";
            }

            if (table.LoadRva is null || (table.IndexTableRva is not null && table.IndexLoadRva is null))
            {
                return "jump table load site unknown";
            }

            // Cases in another range of the function (PGO moves cold cases out) keep their address.
            if (table.TargetRvas.Count != table.EntryCount ||
                table.TargetRvas.Any(t => !f.Ranges.Any(r => t >= r.StartRva && t < r.StartRva + r.Length)))
            {
                return $"jump table 0x{table.Rva:X} has targets outside the function";
            }

            foreach (var (at, size) in new[] { (table.Rva, 4L * table.EntryCount), (table.IndexTableRva ?? 0, (long)table.IndexEntryCount) })
            {
                if (size == 0 || at + (ulong)size <= start || at >= end)
                {
                    continue;
                }

                if (at < start || at + (ulong)size > end)
                {
                    return $"jump table data at 0x{at:X} straddles the range boundary";
                }

                inRange.Add(new DataSpan((uint)(at - start), (uint)size));
            }
        }

        // Merge overlapping spans (shared tables).
        var merged = new List<DataSpan>();
        foreach (var span in inRange.OrderBy(s => s.Offset))
        {
            if (merged.Count > 0 && span.Offset <= merged[^1].End)
            {
                var previous = merged[^1];
                merged[^1] = new DataSpan(previous.Offset, Math.Max(previous.End, span.End) - previous.Offset);
            }
            else
            {
                merged.Add(span);
            }
        }

        spans = merged;
        return null;
    }

    /// <summary>
    /// Linear decode of a range's code, stepping over its data spans. Null, with the reason, if
    /// any byte outside the spans does not decode or an instruction runs into a span.
    /// </summary>
    internal static List<(Instruction Instruction, ConstantOffsets Offsets)>? DecodeCode(byte[] bytes, uint ip, IReadOnlyList<DataSpan> spans, out string? error)
    {
        error = null;
        var reader = new ByteArrayCodeReader(bytes);
        var decoder = Decoder.Create(64, reader);
        var result = new List<(Instruction, ConstantOffsets)>();
        int span = 0;
        uint position = 0;
        while (position < bytes.Length)
        {
            if (span < spans.Count && position >= spans[span].Offset)
            {
                position = spans[span].End;
                span++;
                continue;
            }

            reader.Position = (int)position;
            decoder.IP = ip + position;
            var instruction = decoder.Decode();
            if (instruction.IsInvalid)
            {
                error = $"undecodable bytes at 0x{ip + position:X}";
                return null;
            }

            uint next = position + (uint)instruction.Length;
            if (span < spans.Count && next > spans[span].Offset)
            {
                error = $"instruction at 0x{ip + position:X} runs into jump table data";
                return null;
            }

            result.Add((instruction, decoder.GetConstantOffsets(instruction)));
            position = next;
        }

        return result;
    }

    /// <summary>The .pdata entries beginning in a function's range, parents before the fragments chained to them.</summary>
    private static List<ExceptionInfo> EntriesInRange(BinaryImage image, Function f)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        static int Depth(ExceptionInfo e)
        {
            int depth = 0;
            for (var current = e; current.ChainedParent is { } parent && depth < 32; current = parent)
            {
                depth++;
            }

            return depth;
        }

        return image.ExceptionData
            .Where(e => e.BeginAddress >= start && e.BeginAddress < end)
            .GroupBy(e => e.BeginAddress)
            .Select(g => g.First())
            .OrderBy(Depth)
            .ThenBy(e => e.BeginAddress)
            .ToList();
    }

    /// <summary>
    /// A chained UNWIND_INFO copied verbatim (header and unwind codes), with its trailing parent
    /// RUNTIME_FUNCTION replaced by the parent's copied entry.
    /// </summary>
    internal static byte[] ChainedUnwindCopy(BinaryImage image, uint unwindInfo, CopiedPdata parent)
    {
        var original = image.ReadFrom(unwindInfo).Span;
        int trailer = UnwindTrailerOffset(original);
        var copy = original[..(trailer + 12)].ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(trailer), parent.Begin);
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(trailer + 4), parent.End);
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(trailer + 8), parent.UnwindInfo);
        return copy;
    }

    /// <summary>
    /// An UNWIND_INFO whose handler is <c>__C_specific_handler</c> (or <c>__GSHandlerCheck_SEH</c>),
    /// copied for a byte copy moved by <paramref name="shift"/>: header, unwind codes and handler
    /// RVA verbatim, then the scope table (Count, then { Begin, End, Handler, JumpTarget } RVAs)
    /// with every address inside the function [<paramref name="start"/>, <paramref name="end"/>]
    /// moved, then the bytes that follow it (a GS wrapper's cookie data, at most 12 bytes).
    /// Handler values 0 and 1 are EXCEPTION_* constants, not addresses; a filter or termination
    /// funclet outside the function keeps its RVA.
    /// </summary>
    internal static byte[] SehUnwindCopy(BinaryImage image, ExceptionInfo entry, uint start, uint end, uint shift)
    {
        var original = image.ReadFrom(entry.UnwindInfoAddress).Span;
        int table = (int)(entry.HandlerDataRva - entry.UnwindInfoAddress);
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(original[table..]);
        int tableEnd = table + 4 + 16 * (int)count;
        var copy = original[..Math.Min(original.Length, tableEnd + 12)].ToArray();
        for (int i = 0; i < count; i++)
        {
            for (int field = 0; field < 4; field++)
            {
                int at = table + 4 + 16 * i + 4 * field;
                uint rva = BinaryPrimitives.ReadUInt32LittleEndian(copy.AsSpan(at));
                bool isAddress = field != 2 || rva > 1;
                bool inside = field == 1 ? rva >= start && rva <= end : rva >= start && rva < end;
                if (isAddress && inside)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(at), rva + shift);
                }
            }
        }

        return copy;
    }

    /// <summary>Size of the FuncInfo copied for an FH3 function: the ten fields of the newest layout.</summary>
    internal const int Fh3FuncInfoSize = 40;

    /// <summary>
    /// The bytes appended to .wbdata for a byte copy of an FH3 function (<paramref name="at"/> is where
    /// they will sit): an UNWIND_INFO identical to the original but naming a copy of the FuncInfo
    /// (its 4-byte handler data, followed by a GS wrapper's cookie data verbatim), then that FuncInfo,
    /// which differs from the original only in pointing at a new IP-to-state map, then the map.
    /// The map keeps every state; entries whose address lies in the function move by <paramref name="shift"/>.
    /// Entries elsewhere (the function's catch funclets, whose map this FuncInfo shares) keep their
    /// addresses and come first, so the array stays sorted: copies sit above the original code.
    /// </summary>
    internal static byte[] Fh3UnwindCopy(BinaryImage image, ExceptionInfo entry, uint start, uint end, uint shift, uint at)
    {
        var original = image.ReadFrom(entry.UnwindInfoAddress).Span;
        int data = (int)(entry.HandlerDataRva - entry.UnwindInfoAddress);
        uint funcInfoRva = BinaryPrimitives.ReadUInt32LittleEndian(original[data..]);
        var funcInfo = image.ReadFrom(funcInfoRva).Span;
        uint ipEntries = BinaryPrimitives.ReadUInt32LittleEndian(funcInfo[20..]);
        var ipMap = image.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(funcInfo[24..])).Span;

        int unwindLength = (data + 4 + 12 + 3) & ~3;
        uint funcInfoAt = at + (uint)unwindLength;
        uint mapAt = funcInfoAt + Fh3FuncInfoSize;

        var bytes = new byte[unwindLength + Fh3FuncInfoSize + 8 * (int)ipEntries];
        original[..Math.Min(original.Length, data + 4 + 12)].CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(data), funcInfoAt);
        funcInfo[..Fh3FuncInfoSize].CopyTo(bytes.AsSpan(unwindLength));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(unwindLength + 24), mapAt);

        var outside = new List<(uint Ip, uint State)>();
        var inside = new List<(uint Ip, uint State)>();
        for (int i = 0; i < ipEntries; i++)
        {
            uint ip = BinaryPrimitives.ReadUInt32LittleEndian(ipMap[(8 * i)..]);
            uint state = BinaryPrimitives.ReadUInt32LittleEndian(ipMap[(8 * i + 4)..]);
            (ip >= start && ip < end ? inside : outside).Add((ip >= start && ip < end ? ip + shift : ip, state));
        }

        int position = unwindLength + Fh3FuncInfoSize;
        foreach (var (ip, state) in outside.Concat(inside))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position), ip);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position + 4), state);
            position += 8;
        }

        return bytes;
    }

    /// <summary>UNWIND_INFO: 4-byte header, then CountOfCodes 2-byte codes padded to an even count.</summary>
    internal static int UnwindTrailerOffset(ReadOnlySpan<byte> unwindInfo) => 4 + ((unwindInfo[2] + 1) & ~1) * 2;

    /// <param name="tableFields">Table load sites (original RVA) and the table address their disp32 must name.</param>
    /// <param name="pointerTargets">Redirected entries (original → copy): a <c>lea</c> of one yields the copy.</param>
    private static void CopyWithFixups(uint start, uint copy, byte[] bytes, IReadOnlyList<DataSpan> spans, Dictionary<uint, uint> copyOf, Dictionary<uint, uint> tableFields,
        IReadOnlyDictionary<uint, uint> pointerTargets, RewriteResult result)
    {
        uint end = start + (uint)bytes.Length;
        foreach (var (instruction, offsets) in DecodeCode(bytes.ToArray(), start, spans, out _)!)
        {
            uint at = (uint)instruction.IP - start;
            uint copyNext = copy + at + (uint)instruction.Length;

            if (instruction.Op0Kind == OpKind.NearBranch64 &&
                (instruction.NearBranchTarget < start || instruction.NearBranchTarget >= end))
            {
                uint target = (uint)instruction.NearBranchTarget;
                uint resolved = copyOf.TryGetValue(target, out uint copied) ? copied : target;
                Patch(bytes, at + offsets.ImmediateOffset, offsets.ImmediateSize, (int)(resolved - copyNext));
                result.Patched.Add(new PatchedField(start + at + offsets.ImmediateOffset, copy + at, resolved, FieldKind.Branch));
            }
            else if (instruction.IsIPRelativeMemoryOperand)
            {
                // Keep the absolute target, also inside the range: a code pointer must keep one value.
                // That value is the copy for a redirected function, everywhere.
                uint resolved = (uint)instruction.IPRelativeMemoryAddress;
                if (instruction.Mnemonic == Mnemonic.Lea && pointerTargets.TryGetValue(resolved, out uint pointer))
                {
                    resolved = pointer;
                }

                // The base lea of a table-relative table names the rebuilt table.
                if (tableFields.TryGetValue((uint)instruction.IP, out uint rebuiltTable))
                {
                    resolved = rebuiltTable;
                }

                Patch(bytes, at + offsets.DisplacementOffset, offsets.DisplacementSize, (int)(resolved - copyNext));
                result.Patched.Add(new PatchedField(start + at + offsets.DisplacementOffset, copy + at, resolved, FieldKind.RipRelative));
            }
            else if (tableFields.TryGetValue((uint)instruction.IP, out uint table))
            {
                Patch(bytes, at + offsets.DisplacementOffset, offsets.DisplacementSize, (int)table);
                result.Patched.Add(new PatchedField(start + at + offsets.DisplacementOffset, copy + at, table, FieldKind.TableAddress));
            }
        }
    }

    private static void Patch(byte[] bytes, uint field, int size, int value)
    {
        if (size != 4)
        {
            throw new InvalidOperationException($"expected a 32-bit field at +0x{field:X}, found {size} bytes");
        }

        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan((int)field), value);
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
                entries.Add(0); // IMAGE_REL_BASED_ABSOLUTE padding
            }

            AppendU32(table, page.Key);
            AppendU32(table, (uint)(8 + entries.Count * 2));
            foreach (ushort entry in entries)
            {
                table.Add((byte)entry);
                table.Add((byte)(entry >> 8));
            }
        }

        return table.ToArray();
    }

    /// <summary>
    /// A rewrite invalidates any Authenticode signature (§5.4). A certificate at the end of the
    /// file is removed; the directory is cleared either way.
    /// </summary>
    private static byte[] StripCertificate(byte[] file, PeLayout layout, RewriteResult result)
    {
        int directory = layout.DataDirectory(PeLayout.SecurityDirectory);
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(directory));
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(directory + 4));
        if (offset == 0 || size == 0)
        {
            return file;
        }

        result.Warnings.Add("the Authenticode signature was removed: the rewritten image must be re-signed");
        var copy = file.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(directory), 0);
        return offset + size == file.Length ? copy[..(int)offset] : copy;
    }

    private static void WriteDirectory(byte[] output, PeLayout layout, int index, uint rva, uint size)
    {
        int at = layout.DataDirectory(index);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at), rva);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(at + 4), size);
    }

    private static void AppendU32(List<byte> list, uint value)
    {
        list.Add((byte)value);
        list.Add((byte)(value >> 8));
        list.Add((byte)(value >> 16));
        list.Add((byte)(value >> 24));
    }
}
