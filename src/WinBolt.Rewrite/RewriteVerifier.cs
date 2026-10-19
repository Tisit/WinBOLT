using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;
using WinBolt.Pe;

namespace WinBolt.Rewrite;

public sealed class VerificationReport
{
    /// <summary>Anything here means the output must not be used.</summary>
    public List<string> Failures { get; } = [];

    public List<string> Warnings { get; } = [];

    public int InstructionsCompared { get; set; }

    public int FieldsChecked { get; set; }

    public int FixupsChecked { get; set; }

    public bool OracleAvailable { get; set; }

    /// <summary>Moved functions whose copy WinBolt's own analysis of the output finds as a function entry.</summary>
    public int CopiesRediscovered { get; set; }

    public bool Passed => Failures.Count == 0;
}

/// <summary>
/// Verification for the no-op rewrite (DesignDoc Stage 4, milestone 1): structure of the
/// re-read output, byte-level equality of every copy modulo the fields the move implies, an
/// unchanged original image apart from the trampolines, and the linker fixup oracle when the
/// PDB has fixup records.
/// </summary>
public static class RewriteVerifier
{
    private const int MaxReported = 20;

    /// <summary>The jmp rel32 written at each moved function's original entry.</summary>
    private const uint TrampolineSize = 5;

    public static VerificationReport Verify(BinaryImage original, byte[] originalFile, RewriteResult result)
    {
        var report = new VerificationReport();
        BinaryImage rewritten;
        try
        {
            rewritten = PeImageReader.Read(original.FilePath, result.Output);
        }
        catch (PeFormatException ex)
        {
            report.Failures.Add($"the output does not parse as PE32+: {ex.Message}");
            return report;
        }

        CheckStructure(original, rewritten, result, report);
        CheckCopies(original, rewritten, result, report);
        CheckOriginalImage(original, originalFile, rewritten, result, report);
        CheckOracle(original, rewritten, result, report);
        CheckGuardTables(original, rewritten, result, report);
        CheckReanalysis(original, rewritten, result, report);
        return report;
    }

    private static void CheckStructure(BinaryImage original, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        Expect(report, rewritten.Sections.Count == original.Sections.Count + 2, $"expected {original.Sections.Count + 2} sections, found {rewritten.Sections.Count}");
        Expect(report, rewritten.Sections.Any(s => s.Name == ".wbtext" && s.IsExecutable && s.Rva == result.TextRva), ".wbtext is missing, misplaced or not executable");
        Expect(report, rewritten.Sections.Any(s => s.Name == ".wbdata" && s.Rva == result.DataRva), ".wbdata is missing or misplaced");
        Expect(report, rewritten.EntryPointRva == original.EntryPointRva, "the entry point changed");
        Expect(report, rewritten.Exports.Select(e => e.Rva).SequenceEqual(original.Exports.Select(e => e.Rva)), "export RVAs changed");

        var entries = rewritten.ExceptionData;
        int copiedEntries = result.Moved.Sum(m => m.Pdata.Count + m.ColdEntries.Count);
        Expect(report, entries.Count == original.ExceptionData.Count + copiedEntries,
            $"exception table has {entries.Count} entries, expected {original.ExceptionData.Count} + {copiedEntries}");
        for (int i = 1; i < entries.Count; i++)
        {
            if (entries[i].BeginAddress < entries[i - 1].BeginAddress)
            {
                report.Failures.Add($"exception table is not sorted at entry {i}");
                break;
            }
        }

        // Every original entry that begins in a moved range has a copy at the mapped addresses. An
        // unchained copy shares the original UNWIND_INFO; a chained copy has identical unwind codes
        // and chains to its parent's copy.
        var byBegin = entries.GroupBy(e => e.BeginAddress).ToDictionary(g => g.Key, g => g.First());
        var originals = original.ExceptionData.GroupBy(e => e.BeginAddress).ToDictionary(g => g.Key, g => g.First());
        foreach (var moved in result.Moved)
        {
            uint end = moved.Start + moved.Length;
            int inRange = originals.Keys.Count(b => b >= moved.Start && b < end);
            // A rebuilt copy drops the entry of its trailing switch tables (BlockRebuilder.IsTableEntry).
            if (moved.AddressMap is not null)
            {
                inRange -= original.ExceptionData.Count(e => e.BeginAddress >= moved.Start && e.BeginAddress < moved.Start + moved.Length &&
                                                             BlockRebuilder.IsTableEntry(original, original.Functions[moved.FunctionId], e));
            }

            Expect(report, inRange == moved.Pdata.Count, $"{moved.Name}: {inRange} exception entries in the range but {moved.Pdata.Count} copied");
            foreach (var copied in moved.Pdata)
            {
                var source = originals[copied.OriginalBegin];
                uint Map(uint rva) => TryMap(moved, rva) ?? uint.MaxValue;
                if (!byBegin.TryGetValue(copied.Begin, out var entry) || copied.Begin != Map(source.BeginAddress) || entry.EndAddress != Map(source.EndAddress))
                {
                    report.Failures.Add($"{moved.Name}: copied exception entry for 0x{source.BeginAddress:X} is missing or misplaced");
                    continue;
                }

                if (!source.IsChained && source.HasHandler && original.Functions[moved.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CSpecific && moved.AddressMap is null)
                {
                    CheckSehCopy(original, rewritten, moved, source, entry, report);
                    continue;
                }

                if (!source.IsChained && source.HasHandler && original.Functions[moved.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler3 && moved.AddressMap is null)
                {
                    CheckFh3Copy(original, rewritten, moved, source, entry, report);
                    continue;
                }

                if (!source.IsChained && source.HasHandler && moved.AddressMap is not null &&
                    original.Functions[moved.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler3)
                {
                    CheckFh3Layout(original, rewritten, moved, source, entry, report);
                    continue;
                }

                if (!source.IsChained && source.HasHandler && moved.AddressMap is not null &&
                    original.Functions[moved.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler4)
                {
                    CheckFh4Copy(original, rewritten, moved, source, entry, report);
                    continue;
                }

                if (!source.IsChained)
                {
                    Expect(report, entry.UnwindInfoAddress == source.UnwindInfoAddress, $"{moved.Name}: copied primary entry does not share the original unwind info");
                    continue;
                }

                var before = original.ReadFrom(source.UnwindInfoAddress).Span;
                var after = rewritten.ReadFrom(entry.UnwindInfoAddress).Span;
                int trailer = FunctionRewriter.UnwindTrailerOffset(before);
                Expect(report, after.Length >= trailer && before[..trailer].SequenceEqual(after[..trailer]),
                    $"{moved.Name}: copied unwind codes for 0x{source.BeginAddress:X} differ from the original");
                Expect(report, entry.ChainedParent?.BeginAddress == Map(source.ChainedParent!.BeginAddress),
                    $"{moved.Name}: copied fragment 0x{source.BeginAddress:X} does not chain to its parent's copy");
            }

            // A cold part is tiled by entries with no unwind codes of their own, each chained to the
            // copy of the entry whose cold blocks it holds and sharing its frame register. A leaf
            // function's cold part has none (CheckRebuilt keeps each instruction under its entry).
            if (moved.ColdLength == 0 || moved.Pdata.Count == 0)
            {
                Expect(report, moved.ColdEntries.Count == 0, $"{moved.Name}: exception entries for a cold part that needs none");
                continue;
            }

            uint tiled = moved.ColdStart;
            foreach (var cold in moved.ColdEntries.OrderBy(c => c.Begin))
            {
                var parent = moved.Pdata.FirstOrDefault(c => c.OriginalBegin == cold.OriginalBegin);
                if (cold.Begin != tiled || !byBegin.TryGetValue(cold.Begin, out var coldEntry) || coldEntry.EndAddress != cold.End ||
                    parent is null || coldEntry.ChainedParent?.BeginAddress != parent.Begin || !byBegin.TryGetValue(parent.Begin, out var parentEntry))
                {
                    report.Failures.Add($"{moved.Name}: the cold part's exception entry at 0x{cold.Begin:X} is missing, misplaced or not chained to its entry's copy");
                    break;
                }

                var coldInfo = rewritten.ReadFrom(coldEntry.UnwindInfoAddress).Span;
                var parentInfo = rewritten.ReadFrom(parentEntry.UnwindInfoAddress & ~1u).Span;
                Expect(report, coldInfo.Length >= 16 && coldInfo[0] == 0x21 && coldInfo[1] == 0 && coldInfo[2] == 0 && coldInfo[3] == parentInfo[3],
                    $"{moved.Name}: the cold part's unwind info at 0x{coldEntry.UnwindInfoAddress:X} is not an empty chained entry with its parent's frame register");
                tiled = cold.End;
            }

            Expect(report, tiled == moved.ColdStart + moved.ColdLength, $"{moved.Name}: the cold part's exception entries do not cover it");
        }

        var expectedRelocations = original.Relocations.Where(r => r.Type != RelocationType.Absolute).Select(r => (r.Rva, r.Type))
            .Concat(result.NewRelocations.Select(r => (Rva: r, Type: RelocationType.Dir64)))
            .ToHashSet();
        var actualRelocations = rewritten.Relocations.Where(r => r.Type != RelocationType.Absolute).Select(r => (r.Rva, r.Type)).ToHashSet();
        Expect(report, expectedRelocations.SetEquals(actualRelocations),
            $"base relocations differ: {expectedRelocations.Except(actualRelocations).Count()} missing, {actualRelocations.Except(expectedRelocations).Count()} unexpected");

        var layout = new PeLayout(result.Output);
        Expect(report, rewritten.Checksum == PeChecksum.Compute(result.Output, layout.CheckSumOffset), "the image checksum is wrong");
    }

    /// <summary>
    /// Original range and copy decode in lockstep, stepping over jump table data. Each
    /// instruction must have the same code and length; a branch must reach the mapped target, a
    /// RIP-relative operand the same absolute address, a table load the rebuilt table; every
    /// other byte must be identical, except a copy's rebuilt tables, which are int3-filled in it. Each rebuilt table entry must be the
    /// original entry mapped into the copy.
    /// </summary>
    private static void CheckCopies(BinaryImage original, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        var copyOf = result.Moved.ToDictionary(m => m.Start, m => m.CopyStart);
        var pointerTargets = result.Redirection?.Targets ?? [];
        var dir64 = original.Relocations.Where(r => r.Type == RelocationType.Dir64).Select(r => r.Rva).Order().ToArray();
        foreach (var moved in result.Moved)
        {
            if (moved.AddressMap is not null)
            {
                CheckTables(original, rewritten, moved, report);
                CheckRebuilt(original, rewritten, moved, copyOf, pointerTargets, report);
                continue;
            }

            var before = original.ReadFrom(moved.Start)[..(int)moved.Length].ToArray();
            var after = rewritten.ReadFrom(moved.CopyStart)[..(int)moved.Length].ToArray();
            uint end = moved.Start + moved.Length;
            uint Map(uint rva) => moved.CopyStart + (rva - moved.Start);

            // Relocated pointers to redirected functions hold the copy's address in the copy.
            var redirectedBytes = new HashSet<uint>();
            int first = Array.BinarySearch(dir64, moved.Start);
            for (int r = first >= 0 ? first : ~first; r < dir64.Length && dir64[r] + 8 <= end; r++)
            {
                uint offset = dir64[r] - moved.Start;
                ulong value = BinaryPrimitives.ReadUInt64LittleEndian(before.AsSpan((int)offset));
                if (value >= original.ImageBase && pointerTargets.TryGetValue((uint)(value - original.ImageBase), out uint pointer))
                {
                    ulong now = BinaryPrimitives.ReadUInt64LittleEndian(after.AsSpan((int)offset));
                    Check(report, now == original.ImageBase + pointer, $"{moved.Name}+0x{offset:X}: pointer to redirected 0x{value - original.ImageBase:X} holds 0x{now:X} in the copy");
                    report.FieldsChecked++;
                    redirectedBytes.UnionWith(Enumerable.Range((int)offset, 8).Select(i => (uint)i));
                }
            }

            // Copied tables are int3-filled in the copy (it reads the rebuilt ones); other data, index bytes, is unchanged.
            var filled = new bool[moved.Length];
            foreach (var table in moved.Tables.Where(t => t.OriginalRva >= moved.Start && t.OriginalRva < end))
            {
                filled.AsSpan((int)(table.OriginalRva - moved.Start), Math.Min(4 * table.EntryCount, (int)(end - table.OriginalRva))).Fill(true);
            }

            foreach (var span in moved.DataSpans)
            {
                for (uint i = span.Offset; i < span.End; i++)
                {
                    if (after[i] != (filled[i] ? (byte)0xCC : before[i]))
                    {
                        Fail(report, $"{moved.Name}+0x{i:X}: table data in the copy is 0x{after[i]:X2}, expected {(filled[i] ? "int3 fill" : $"the original 0x{before[i]:X2}")}");
                        break;
                    }
                }
            }

            CheckTables(original, rewritten, moved, report);
            var tableLoads = moved.Tables.SelectMany(t => t.FieldSites.Select(site => (site, (Original: t.TableRelative ? t.OriginalBaseRva : t.OriginalRva, New: t.TableRelative ? t.NewBaseRva : t.NewRva)))).ToDictionary(x => x.site, x => x.Item2);
            var indexLoads = moved.Tables.Where(t => t.IndexLoadRva is not null).Select(t => t.IndexLoadRva!.Value).ToHashSet();

            var a = FunctionRewriter.DecodeCode(before, moved.Start, moved.DataSpans, out string? errorA);
            var b = FunctionRewriter.DecodeCode(after, moved.CopyStart, moved.DataSpans, out string? errorB);
            if (a is null || b is null || a.Count != b.Count)
            {
                Fail(report, $"{moved.Name}: original and copy do not decode alike ({errorA ?? errorB ?? "instruction counts differ"})");
                continue;
            }

            for (int n = 0; n < a.Count; n++)
            {
                var (x, offsets) = a[n];
                var y = b[n].Instruction;
                report.InstructionsCompared++;
                uint at = (uint)x.IP - moved.Start;
                if (x.Code != y.Code || x.Length != y.Length)
                {
                    Fail(report, $"{moved.Name}+0x{at:X}: instruction differs ({x} / {y})");
                    break;
                }

                int field = -1, fieldSize = 0;
                if (tableLoads.TryGetValue((uint)x.IP, out var table))
                {
                    Check(report, x.MemoryDisplacement64 == table.Original && y.MemoryDisplacement64 == table.New,
                        $"{moved.Name}+0x{at:X}: table load reads 0x{y.MemoryDisplacement64:X}, expected the rebuilt table at 0x{table.New:X}");
                    field = offsets.DisplacementOffset;
                    fieldSize = offsets.DisplacementSize;
                }
                else if (indexLoads.Contains((uint)x.IP))
                {
                    // Index bytes are copied unchanged; the copy reads its own when they are in the range.
                    uint index = (uint)x.MemoryDisplacement64;
                    uint expected = index >= moved.Start && index < end ? Map(index) : index;
                    Check(report, y.MemoryDisplacement64 == expected, $"{moved.Name}+0x{at:X}: index load reads 0x{y.MemoryDisplacement64:X}, expected 0x{expected:X}");
                    field = offsets.DisplacementOffset;
                    fieldSize = offsets.DisplacementSize;
                }
                else if (x.Op0Kind == OpKind.NearBranch64)
                {
                    uint target = (uint)x.NearBranchTarget;
                    uint expected = target >= moved.Start && target < end
                        ? moved.CopyStart + (target - moved.Start)
                        : copyOf.GetValueOrDefault(target, target);
                    Check(report, (uint)y.NearBranchTarget == expected, $"{moved.Name}+0x{at:X}: branch reaches 0x{y.NearBranchTarget:X}, expected 0x{expected:X}");
                    field = offsets.ImmediateOffset;
                    fieldSize = offsets.ImmediateSize;
                }
                else if (x.IsIPRelativeMemoryOperand)
                {
                    ulong expected = x.Mnemonic == Mnemonic.Lea && pointerTargets.TryGetValue((uint)x.IPRelativeMemoryAddress, out uint pointer) ? pointer : x.IPRelativeMemoryAddress;
                    Check(report, y.IPRelativeMemoryAddress == expected,
                        $"{moved.Name}+0x{at:X}: RIP-relative operand reaches 0x{y.IPRelativeMemoryAddress:X}, expected 0x{expected:X}");
                    field = offsets.DisplacementOffset;
                    fieldSize = offsets.DisplacementSize;
                }

                if (field >= 0)
                {
                    report.FieldsChecked++;
                }

                for (int i = 0; i < x.Length; i++)
                {
                    bool masked = (field >= 0 && i >= field && i < field + fieldSize) || redirectedBytes.Contains(at + (uint)i);
                    if (!masked && before[at + i] != after[at + i])
                    {
                        Fail(report, $"{moved.Name}+0x{at + i:X}: byte changed outside any fixed-up field");
                        break;
                    }
                }
            }
        }
    }

    /// <summary>
    /// A function re-encoded from its CFG (Stage 6), in any block order: every original
    /// instruction, block by block, has a counterpart at its mapped address, inside the copy or
    /// its cold part. A branch keeps its mnemonic (the form may change) and reaches the mapped
    /// target; a table load reads the rebuilt table; any other instruction is the same
    /// instruction (iced equality, which compares RIP-relative operands by absolute target).
    /// Instructions of a block are contiguous. A block that can fall through reaches its
    /// fall-through successor directly or through a <c>jmp</c> placed right after it. The layout
    /// may also invert a conditional branch (the inverted branch targets the fall-through
    /// successor, and the original target must be reached right after it) and drop a block's
    /// final <c>jmp</c> when its target is placed there (the <c>jmp</c> maps to its target). Each
    /// instruction stays under the unwind entry that described it: its copy, or for the primary
    /// entry, the cold part's entry chained to it.
    /// </summary>
    internal static void CheckRebuilt(BinaryImage original, BinaryImage rewritten, MovedFunction moved, Dictionary<uint, uint> copyOf,
        IReadOnlyDictionary<uint, uint> pointerTargets, VerificationReport report)
    {
        var function = original.Functions[moved.FunctionId];
        var tableLoads = moved.Tables.SelectMany(t => t.FieldSites.Select(site => (site, NewRva: t.TableRelative ? t.NewBaseRva : t.NewRva))).ToDictionary(x => x.site, x => x.NewRva);
        foreach (var t in moved.Tables.Where(t => t is { IndexLoadRva: not null, NewIndexRva: not null }))
        {
            tableLoads[t.IndexLoadRva!.Value] = t.NewIndexRva!.Value;
        }
        uint end = moved.Start + moved.Length;
        var blockStarts = function.EntryBlocks.Select(b => (uint)b.StartRva).ToHashSet();
        var sources = original.ExceptionData.GroupBy(e => e.BeginAddress).ToDictionary(g => g.Key, g => g.First());
        var unwindRanges = moved.Pdata.Select(c => (Begin: c.OriginalBegin, sources[c.OriginalBegin].EndAddress, Copy: c,
            Cold: moved.ColdEntries.Where(k => k.OriginalBegin == c.OriginalBegin).ToList())).ToList();

        bool Placed(uint at) => (at >= moved.CopyStart && at < moved.CopyStart + moved.CopyLength) ||
                                (at >= moved.ColdStart && at < moved.ColdStart + moved.ColdLength);
        uint? Target(uint target) => target >= moved.Start && target < end ? TryMap(moved, target) : copyOf.GetValueOrDefault(target, target);

        // Control arriving at 'at' goes on to 'target': it is there, or a jmp there leads to it,
        // possibly after NOP padding (JCC erratum alignment).
        bool Reaches(uint at, uint? target)
        {
            if (target is not { } t)
            {
                return false;
            }

            for (int nops = 0; nops < 16 && at != t && Placed(at); nops++)
            {
                if (DecodeAt(rewritten, at) is not { } next)
                {
                    return false;
                }

                if (next.IsJmpShortOrNear)
                {
                    return (uint)next.NearBranchTarget == t;
                }

                if (next.Mnemonic != Mnemonic.Nop)
                {
                    return false;
                }

                at += (uint)next.Length;
            }

            return at == t;
        }

        // Within a block only padding may separate two instructions.
        bool Follows(uint at, uint? target)
        {
            for (int nops = 0; nops < 16 && at != target && Placed(at); nops++)
            {
                if (DecodeAt(rewritten, at) is not { Mnemonic: Mnemonic.Nop } nop)
                {
                    return false;
                }

                at += (uint)nop.Length;
            }

            return at == target;
        }

        Check(report, TryMap(moved, moved.Start) == moved.CopyStart, $"{moved.Name}: the entry does not start the copy");
        foreach (var block in function.EntryBlocks.OrderBy(b => b.StartRva))
        {
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var x = original.Instructions[k];
                uint ip = (uint)x.IP;
                bool last = k == block.InstructionStart + block.InstructionCount - 1;
                if (TryMap(moved, ip) is not { } at)
                {
                    Fail(report, $"{moved.Name}: instruction 0x{ip:X} has no counterpart");
                    return;
                }

                report.InstructionsCompared++;
                if (last && k > block.InstructionStart && x.IsJmpShortOrNear && x.NearBranchTarget != x.IP &&
                    x.NearBranchTarget >= moved.Start && x.NearBranchTarget < end && at == TryMap(moved, (uint)x.NearBranchTarget))
                {
                    report.FieldsChecked++;
                    continue; // dropped: its target is placed where it was
                }

                if (!Placed(at) || DecodeAt(rewritten, at) is not { } y)
                {
                    Fail(report, $"{moved.Name}: instruction 0x{ip:X} has no decodable counterpart in the copy");
                    return;
                }

                foreach (var (begin, entryEnd, copy, cold) in unwindRanges)
                {
                    Check(report, ip < begin || ip >= entryEnd || (at >= copy.Begin && at < copy.End) || cold.Any(k => at >= k.Begin && at < k.End),
                        $"{moved.Name}: 0x{ip:X} left the unwind entry for 0x{begin:X}");
                }

                bool inverted = false;
                uint length = (uint)y.Length;
                if (moved.PromotedCalls.TryGetValue(ip, out uint promotedTarget))
                {
                    report.FieldsChecked++;
                    uint value = pointerTargets.TryGetValue(promotedTarget, out uint redirected) ? redirected : promotedTarget;
                    if (CheckPromotedCall(rewritten, x, at, value, Target(promotedTarget), TryMap(moved, (uint)x.NextIP), Placed) is { } sequenceEnd)
                    {
                        length = sequenceEnd - at;
                    }
                    else
                    {
                        Fail(report, $"{moved.Name}: the promoted call {x} at 0x{ip:X} is not 'lea s,[0x{value:X}]; cmp operand,s; je; the call; jmp back; call 0x{Target(promotedTarget):X}'");
                    }
                }
                else if (x.Op0Kind == OpKind.NearBranch64)
                {
                    uint? expected = Target((uint)x.NearBranchTarget);
                    var negated = x;
                    if (x.IsJccShortOrNear)
                    {
                        negated.NegateConditionCode();
                    }

                    report.FieldsChecked++;
                    inverted = x.IsJccShortOrNear && last && y.IsJccShortOrNear && y.Mnemonic == negated.Mnemonic;
                    if (inverted)
                    {
                        Check(report, (uint)y.NearBranchTarget == TryMap(moved, (uint)x.NextIP) && blockStarts.Contains((uint)x.NextIP) && Reaches(at + (uint)y.Length, expected),
                            $"{moved.Name}: {x} at 0x{ip:X} became {y}, which is not its inversion");
                    }
                    else
                    {
                        Check(report, y.Op0Kind == OpKind.NearBranch64 && y.Mnemonic == x.Mnemonic && (uint)y.NearBranchTarget == expected,
                            $"{moved.Name}: {x} at 0x{ip:X} became {y}, expected a branch to 0x{expected:X}");
                    }
                }
                else if (tableLoads.TryGetValue(ip, out uint table))
                {
                    var relocated = x;
                    relocated.MemoryDisplacement64 = table;
                    report.FieldsChecked++;
                    Check(report, y.Code == x.Code && relocated.Equals(y), $"{moved.Name}: table load at 0x{ip:X} became {y}, expected it to read 0x{table:X}");
                }
                else
                {
                    if (x.IsIPRelativeMemoryOperand)
                    {
                        report.FieldsChecked++;
                    }

                    // JCC erratum prefix padding may add a CS/DS/ES/SS segment prefix, which 64-bit
                    // mode ignores; any other difference fails.
                    var unprefixed = y;
                    if (x.SegmentPrefix == Register.None && y.SegmentPrefix is Register.CS or Register.DS or Register.ES or Register.SS)
                    {
                        unprefixed.SegmentPrefix = Register.None;
                    }

                    // A lea of a redirected function yields its copy.
                    var expected = x;
                    if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && pointerTargets.TryGetValue((uint)x.IPRelativeMemoryAddress, out uint pointer))
                    {
                        expected.MemoryDisplacement64 = pointer;
                    }

                    Check(report, y.Code == x.Code && expected.Equals(unprefixed), $"{moved.Name}: {x} at 0x{ip:X} re-encoded as {y}");
                }

                // Contiguity within the block; the fall-through successor is reached after it. A
                // call with no successor block is a noreturn call.
                bool fallsThrough = x.FlowControl is FlowControl.Next or FlowControl.Call or FlowControl.IndirectCall or FlowControl.ConditionalBranch;
                if (!last)
                {
                    Check(report, Follows(at + length, TryMap(moved, (uint)x.NextIP)),
                        $"{moved.Name}: 0x{x.NextIP:X} does not follow 0x{ip:X} directly in the rebuilt code");
                }
                else if (fallsThrough && !inverted)
                {
                    // A call with no successor block is a noreturn call; so is the nop or int3 filler MSVC
                    // puts after one (call / int3 / alignment nop before table data; CFG construction ends such a block there).
                    int before = k - 1;
                    while (before >= block.InstructionStart && original.Instructions[before].Mnemonic is Mnemonic.Nop or Mnemonic.Int3)
                    {
                        before--;
                    }

                    bool afterCall = x.Mnemonic is Mnemonic.Nop or Mnemonic.Int3 && before >= block.InstructionStart &&
                                     original.Instructions[before].FlowControl is FlowControl.Call or FlowControl.IndirectCall;
                    bool noreturn = (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall || afterCall) && !blockStarts.Contains((uint)x.NextIP);
                    Check(report, noreturn || (blockStarts.Contains((uint)x.NextIP) && Reaches(at + length, TryMap(moved, (uint)x.NextIP))),
                        $"{moved.Name}: execution after 0x{ip:X} does not reach 0x{x.NextIP:X} in the rebuilt code");
                }
            }
        }
    }

    /// <summary>
    /// An indirect call promoted by <see cref="BlockRebuilder.Encode"/>, at <paramref name="at"/>:
    /// <c>lea s,[value]</c> with s r10 or r11 and not used by the call's operand; <c>cmp</c> of the
    /// call's own operand with s; <c>je</c> to the direct call; the original call, unchanged; a
    /// <c>jmp</c> to where the call returned (<paramref name="after"/>); then <c>call</c>
    /// <paramref name="direct"/>. NOP padding may sit between them. Returns the end of the sequence,
    /// or null if anything differs.
    /// </summary>
    private static uint? CheckPromotedCall(BinaryImage rewritten, Instruction call, uint at, uint value, uint? direct, uint? after, Func<uint, bool> placed)
    {
        Instruction? Next(ref uint a)
        {
            for (int nops = 0; nops < 16 && placed(a); nops++)
            {
                if (DecodeAt(rewritten, a) is not { } i)
                {
                    return null;
                }

                a += (uint)i.Length;
                if (i.Mnemonic != Mnemonic.Nop)
                {
                    return i;
                }
            }

            return null;
        }

        uint a = at;
        if (Next(ref a) is not { Code: Code.Lea_r64_m, IsIPRelativeMemoryOperand: true } lea || (uint)lea.IPRelativeMemoryAddress != value ||
            lea.Op0Register is not (Register.R10 or Register.R11) || BlockRebuilder.PromotionScratch(call) is null)
        {
            return null;
        }

        var scratch = lea.Op0Register;
        bool usesScratch = call.Op0Kind == OpKind.Register
            ? call.Op0Register.GetFullRegister() == scratch
            : call.MemoryBase.GetFullRegister() == scratch || call.MemoryIndex.GetFullRegister() == scratch;
        if (usesScratch || Next(ref a) is not { Code: Code.Cmp_rm64_r64 } compare || compare.Op1Register != scratch)
        {
            return null;
        }

        bool sameOperand = call.Op0Kind == OpKind.Register
            ? compare.Op0Kind == OpKind.Register && compare.Op0Register == call.Op0Register
            : compare.Op0Kind == OpKind.Memory && compare.MemoryBase == call.MemoryBase && compare.MemoryIndex == call.MemoryIndex &&
              compare.MemoryIndexScale == call.MemoryIndexScale && compare.MemoryDisplacement64 == call.MemoryDisplacement64 &&
              compare.SegmentPrefix == Register.None && call.SegmentPrefix == Register.None;
        if (!sameOperand || Next(ref a) is not { Mnemonic: Mnemonic.Je } je || Next(ref a) is not { } slow || slow.Code != call.Code || !slow.Equals(call) ||
            Next(ref a) is not { } back || !back.IsJmpShortOrNear || (uint)back.NearBranchTarget != after)
        {
            return null;
        }

        // Only padding between the jmp back and the direct call.
        uint fast = (uint)je.NearBranchTarget;
        while (a != fast && placed(a) && DecodeAt(rewritten, a) is { Mnemonic: Mnemonic.Nop } nop)
        {
            a += (uint)nop.Length;
        }

        return a == fast && Next(ref a) is { Code: Code.Call_rel32_64 } directCall && (uint)directCall.NearBranchTarget == direct ? a : null;
    }

    /// <summary>
    /// An SEH function's copy has its own UNWIND_INFO: identical to the original up to the scope
    /// table and after it, with each scope entry's addresses inside the function (Begin, End,
    /// a filter or termination funclet, the __except target) mapped into the copy. Handler values
    /// 0 and 1 are EXCEPTION_* constants.
    /// </summary>
    private static void CheckSehCopy(BinaryImage original, BinaryImage rewritten, MovedFunction moved, ExceptionInfo source, ExceptionInfo copy, VerificationReport report)
    {
        var before = original.ReadFrom(source.UnwindInfoAddress).Span;
        var after = rewritten.ReadFrom(copy.UnwindInfoAddress).Span;
        int table = (int)(source.HandlerDataRva - source.UnwindInfoAddress);
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(before[table..]);
        int tableEnd = table + 4 + 16 * (int)count;
        int tail = Math.Min(12, before.Length - tableEnd);
        if (after.Length < tableEnd + tail || !before[..(table + 4)].SequenceEqual(after[..(table + 4)]) ||
            !before.Slice(tableEnd, tail).SequenceEqual(after.Slice(tableEnd, tail)))
        {
            Fail(report, $"{moved.Name}: the copy's SEH unwind info differs from the original outside the scope table");
            return;
        }

        uint end = moved.Start + moved.Length;
        for (int i = 0; i < count; i++)
        {
            for (int field = 0; field < 4; field++)
            {
                int at = table + 4 + 16 * i + 4 * field;
                uint was = BinaryPrimitives.ReadUInt32LittleEndian(before[at..]);
                uint now = BinaryPrimitives.ReadUInt32LittleEndian(after[at..]);
                bool inside = (field != 2 || was > 1) && was >= moved.Start && (field == 1 ? was <= end : was < end);
                report.FieldsChecked++;
                Check(report, now == (inside ? moved.CopyStart + (was - moved.Start) : was),
                    $"{moved.Name}: scope entry {i} field {field} is 0x{now:X}; the original 0x{was:X} maps elsewhere");
            }
        }
    }

    /// <summary>
    /// An FH3 function's byte copy (FunctionRewriter.Fh3UnwindCopy): its UNWIND_INFO equals the original up
    /// to the handler data, which names a new FuncInfo; that equals the original's except for the pointer
    /// to the IP-to-state map; the map holds the same (address, state) pairs, addresses inside the function
    /// mapped into the copy, sorted ascending.
    /// </summary>
    private static void CheckFh3Copy(BinaryImage original, BinaryImage rewritten, MovedFunction moved, ExceptionInfo source, ExceptionInfo copy, VerificationReport report)
    {
        var before = original.ReadFrom(source.UnwindInfoAddress).Span;
        var after = rewritten.ReadFrom(copy.UnwindInfoAddress).Span;
        int data = (int)(source.HandlerDataRva - source.UnwindInfoAddress);
        int tail = Math.Min(12, before.Length - (data + 4));
        if (after.Length < data + 4 + tail || !before[..data].SequenceEqual(after[..data]) || !before.Slice(data + 4, tail).SequenceEqual(after.Slice(data + 4, tail)))
        {
            Fail(report, $"{moved.Name}: the copy's FH3 unwind info differs from the original outside the FuncInfo pointer");
            return;
        }

        var oldInfo = original.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(before[data..])).Span;
        var newInfo = rewritten.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(after[data..])).Span;
        if (oldInfo.Length < FunctionRewriter.Fh3FuncInfoSize || newInfo.Length < FunctionRewriter.Fh3FuncInfoSize)
        {
            Fail(report, $"{moved.Name}: the FH3 FuncInfo is not file-backed");
            return;
        }

        for (int field = 0; field < FunctionRewriter.Fh3FuncInfoSize / 4; field++)
        {
            report.FieldsChecked++;
            Check(report, field == 6 || BinaryPrimitives.ReadUInt32LittleEndian(oldInfo[(4 * field)..]) == BinaryPrimitives.ReadUInt32LittleEndian(newInfo[(4 * field)..]),
                $"{moved.Name}: the copy's FuncInfo field {field} differs from the original");
        }

        uint count = BinaryPrimitives.ReadUInt32LittleEndian(oldInfo[20..]);
        var oldMap = original.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(oldInfo[24..])).Span;
        var newMap = rewritten.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(newInfo[24..])).Span;
        if (oldMap.Length < 8 * count || newMap.Length < 8 * count)
        {
            Fail(report, $"{moved.Name}: the IP-to-state map is not file-backed");
            return;
        }

        uint end = moved.Start + moved.Length;
        var expected = new List<(uint Ip, uint State)>();
        var actual = new List<(uint Ip, uint State)>();
        for (int i = 0; i < count; i++)
        {
            uint ip = BinaryPrimitives.ReadUInt32LittleEndian(oldMap[(8 * i)..]);
            expected.Add((ip >= moved.Start && ip < end ? moved.CopyStart + (ip - moved.Start) : ip, BinaryPrimitives.ReadUInt32LittleEndian(oldMap[(8 * i + 4)..])));
            actual.Add((BinaryPrimitives.ReadUInt32LittleEndian(newMap[(8 * i)..]), BinaryPrimitives.ReadUInt32LittleEndian(newMap[(8 * i + 4)..])));
        }

        report.FieldsChecked += (int)count;
        Check(report, actual.Zip(actual.Skip(1)).All(p => p.First.Ip <= p.Second.Ip), $"{moved.Name}: the copy's IP-to-state map is not sorted");
        Check(report, actual.OrderBy(e => e.Ip).ThenBy(e => e.State).SequenceEqual(expected.OrderBy(e => e.Ip).ThenBy(e => e.State)),
            $"{moved.Name}: the copy's IP-to-state map does not hold the original pairs with the function's addresses moved");
    }

    /// <summary>
    /// A reordered FH3 function (Fh3Writer): the copy's UNWIND_INFO equals the original up to the FuncInfo
    /// pointer, the new FuncInfo equals the original's except for the IP-to-state map pointer and count,
    /// the map is sorted and keeps the original entries outside the function, and every instruction
    /// (but a dropped jmp), at its new address, has the state it had at its original one.
    /// </summary>
    private static void CheckFh3Layout(BinaryImage original, BinaryImage rewritten, MovedFunction moved, ExceptionInfo source, ExceptionInfo copy, VerificationReport report)
    {
        var function = original.Functions[moved.FunctionId];
        var before = original.ReadFrom(source.UnwindInfoAddress).Span;
        var after = rewritten.ReadFrom(copy.UnwindInfoAddress).Span;
        int data = (int)(source.HandlerDataRva - source.UnwindInfoAddress);
        int tail = Math.Min(12, before.Length - (data + 4));
        if (after.Length < data + 4 + tail || !before[..data].SequenceEqual(after[..data]) || !before.Slice(data + 4, tail).SequenceEqual(after.Slice(data + 4, tail)))
        {
            Fail(report, $"{moved.Name}: the reordered copy's FH3 unwind info differs from the original outside the FuncInfo pointer");
            return;
        }

        uint oldInfoRva = BinaryPrimitives.ReadUInt32LittleEndian(before[data..]);
        uint newInfoRva = BinaryPrimitives.ReadUInt32LittleEndian(after[data..]);
        var oldInfo = original.ReadFrom(oldInfoRva).Span;
        var newInfo = rewritten.ReadFrom(newInfoRva).Span;
        if (oldInfo.Length < FunctionRewriter.Fh3FuncInfoSize || newInfo.Length < FunctionRewriter.Fh3FuncInfoSize)
        {
            Fail(report, $"{moved.Name}: the FH3 FuncInfo is not file-backed");
            return;
        }

        for (int field = 0; field < FunctionRewriter.Fh3FuncInfoSize / 4; field++)
        {
            report.FieldsChecked++;
            Check(report, field is 5 or 6 || BinaryPrimitives.ReadUInt32LittleEndian(oldInfo[(4 * field)..]) == BinaryPrimitives.ReadUInt32LittleEndian(newInfo[(4 * field)..]),
                $"{moved.Name}: the reordered copy's FuncInfo field {field} differs from the original");
        }

        var oldMap = Fh3Writer.ReadMap(original, oldInfoRva);
        var newMap = Fh3Writer.ReadMap(rewritten, newInfoRva);
        Check(report, newMap.Zip(newMap.Skip(1)).All(p => p.First.Ip <= p.Second.Ip), $"{moved.Name}: the reordered copy's IP-to-state map is not sorted");
        uint end = moved.Start + moved.Length;
        var outside = oldMap.Where(e => e.Ip < moved.Start || e.Ip >= end).ToList();
        Check(report, outside.All(newMap.Contains), $"{moved.Name}: the reordered copy's map lost an entry outside the function");

        foreach (var block in function.EntryBlocks)
        {
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var instruction = original.Instructions[k];
                uint ip = (uint)instruction.IP;
                if (TryMap(moved, ip) is not { } at || Fh4Writer.DroppedJump(instruction, moved.AddressMap!))
                {
                    continue; // a dropped jmp occupies no bytes: no control-PC lands on it
                }

                report.FieldsChecked++;
                Check(report, Fh3Writer.StateAt(newMap, at) == Fh3Writer.StateAt(oldMap, ip),
                    $"{moved.Name}: instruction 0x{ip:X} (now 0x{at:X}) has EH state {Fh3Writer.StateAt(newMap, at)}, original {Fh3Writer.StateAt(oldMap, ip)}");
            }
        }
    }

    /// <summary>
    /// A reordered FH4 function (Fh4Writer): the copy's UNWIND_INFO copies the original's header,
    /// unwind codes and handler RVA verbatim (the prologue is preserved), and names a new FuncInfo4
    /// whose unwind map is the original's (funclets do not move) and whose regenerated IP-to-state
    /// map gives every instruction, at its new address, the same state the original map gave it.
    /// </summary>
    private static void CheckFh4Copy(BinaryImage original, BinaryImage rewritten, MovedFunction moved, ExceptionInfo source, ExceptionInfo copy, VerificationReport report)
    {
        var function = original.Functions[moved.FunctionId];
        var before = original.ReadFrom(source.UnwindInfoAddress).Span;
        var after = rewritten.ReadFrom(copy.UnwindInfoAddress).Span;
        int trailer = FunctionRewriter.UnwindTrailerOffset(before);
        if (after.Length < trailer + 8 || !before[..(trailer + 4)].SequenceEqual(after[..(trailer + 4)]))
        {
            Fail(report, $"{moved.Name}: the copy's FH4 unwind info does not copy the original header, codes and handler");
            return;
        }

        // A GS wrapper's cookie data follows the FuncInfo4 RVA and must be copied verbatim.
        if (function.ExceptionHandler!.Name == "__GSHandlerCheck_EH4")
        {
            int gs = Math.Min(8, before.Length - (trailer + 8));
            Check(report, gs > 0 && after.Length >= trailer + 8 + gs && before.Slice(trailer + 8, gs).SequenceEqual(after.Slice(trailer + 8, gs)),
                $"{moved.Name}: the copy's GS cookie data was not preserved after the FuncInfo4");
        }

        var originalLayout = CxxEhParser.ReadFh4Layout(original, function.CxxEh!.FuncInfoRva, moved.Start);
        uint newFuncInfo = BinaryPrimitives.ReadUInt32LittleEndian(after[(trailer + 4)..]);
        var newLayout = CxxEhParser.ReadFh4Layout(rewritten, newFuncInfo, moved.CopyStart);
        if (originalLayout is not { Segments.Count: 1 } || newLayout is not { Segments.Count: >= 1 })
        {
            Fail(report, $"{moved.Name}: the FH4 FuncInfo4 did not decode (original {originalLayout is not null}, copy {newLayout is not null})");
            return;
        }

        // A split function's FuncInfo4 is separated: one code piece for the hot copy, one per cold
        // segment, each keyed to its own start. The unwinder picks the piece by the frame's entry
        // start, so an instruction's state comes from the piece whose start is the largest <= it.
        bool split = moved.ColdLength > 0;
        Check(report, (newLayout.Header & Fh4Layout.IsSeparatedFlag) == (split ? Fh4Layout.IsSeparatedFlag : 0),
            $"{moved.Name}: the copy's FuncInfo4 separated flag does not match its {(split ? "split" : "single")} layout");
        Check(report, (newLayout.Header & ~Fh4Layout.IsSeparatedFlag) == originalLayout.Header,
            $"{moved.Name}: the copy's FuncInfo4 header 0x{newLayout.Header:X} differs from 0x{originalLayout.Header:X} (beyond separated)");
        Check(report, newLayout.UnwindMapRva == originalLayout.UnwindMapRva,
            $"{moved.Name}: the copy's FuncInfo4 unwind map 0x{newLayout.UnwindMapRva:X} is not the original 0x{originalLayout.UnwindMapRva:X}");

        var pieces = newLayout.Segments.OrderBy(s => s.Start).ToList();
        var originalMap = originalLayout.Segments[0].Map;
        int NewState(uint at) => Fh4Layout.StateAt(pieces.Last(s => s.Start <= at).Map, at);
        foreach (var block in function.EntryBlocks)
        {
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var instruction = original.Instructions[k];
                uint ip = (uint)instruction.IP;
                if (TryMap(moved, ip) is not { } at || Fh4Writer.DroppedJump(instruction, moved.AddressMap!))
                {
                    continue; // a dropped jmp occupies no bytes: no control-PC lands on it
                }

                if (at < pieces[0].Start)
                {
                    Fail(report, $"{moved.Name}: instruction 0x{ip:X} maps to 0x{at:X}, before any FuncInfo4 segment");
                    continue;
                }

                report.FieldsChecked++;
                Check(report, NewState(at) == Fh4Layout.StateAt(originalMap, ip),
                    $"{moved.Name}: instruction 0x{ip:X} (now 0x{at:X}) has EH state {NewState(at)}, original {Fh4Layout.StateAt(originalMap, ip)}");
            }
        }
    }

    /// <summary>
    /// A linker reference to a redirected function. A 64-bit absolute holds the copy's address
    /// (in the original section and, if its function was copied, in the copy); a RIP-relative
    /// field is a lea the plan redirected, or a direct call or jump (not a pointer); an
    /// image-relative one should not exist: the plan must have excluded the function.
    /// </summary>
    private static void CheckRedirectedFixup(BinaryImage original, BinaryImage rewritten, LinkerFixup fixup, uint target, uint copy,
        MovedFunction? site, HashSet<uint> leaFields, VerificationReport report)
    {
        switch (fixup.Type)
        {
            case 1:
                foreach (uint at in site is { AddressMap: null } ? new[] { fixup.Rva, site.CopyStart + (fixup.Rva - site.Start) } : [fixup.Rva])
                {
                    bool underTrampoline = site is { HasTrampoline: true } && at == fixup.Rva && fixup.Rva < site.Start + TrampolineSize;
                    if (!underTrampoline && rewritten.ReadFrom(at).Span is { Length: >= 8 } value)
                    {
                        Check(report, BinaryPrimitives.ReadUInt64LittleEndian(value) == rewritten.ImageBase + copy,
                            $"oracle: absolute reference to redirected 0x{target:X} at 0x{at:X} does not hold its copy 0x{copy:X}");
                    }
                }

                break;
            case 3:
                Fail(report, $"oracle: image-relative reference to redirected 0x{target:X} at 0x{fixup.Rva:X}; its address would not be the copy's");
                break;
            case >= 4 and <= 9 when !leaFields.Contains(fixup.Rva):
                bool branch = new[] { 1u, 2u }.Any(d => DecodeAt(original, fixup.Rva - d) is { } x &&
                    x.Op0Kind == OpKind.NearBranch64 && (uint)x.NearBranchTarget == target && x.IP + (ulong)x.Length == fixup.Rva + 4);
                Check(report, branch, $"oracle: RIP-relative reference to redirected 0x{target:X} at 0x{fixup.Rva:X} is neither a redirected lea nor a direct branch");
                break;
        }
    }

    private static (Instruction Instruction, ConstantOffsets Offsets)? DecodeWithOffsets(BinaryImage image, uint rva)
    {
        var bytes = image.ReadFrom(rva);
        if (bytes.Length == 0)
        {
            return null;
        }

        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes[..Math.Min(bytes.Length, 15)].ToArray()));
        decoder.IP = rva;
        var instruction = decoder.Decode();
        return instruction.IsInvalid ? null : (instruction, decoder.GetConstantOffsets(instruction));
    }

    private static Instruction? DecodeAt(BinaryImage image, uint rva)
    {
        var bytes = image.ReadFrom(rva);
        if (bytes.Length == 0)
        {
            return null;
        }

        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes[..Math.Min(bytes.Length, 15)].ToArray()));
        decoder.IP = rva;
        var instruction = decoder.Decode();
        return instruction.IsInvalid ? null : instruction;
    }

    /// <summary>Where an original code address now is: a copy's fixed offset, or a rebuilt function's map (null if it is not an instruction start).</summary>
    private static uint? TryMap(MovedFunction moved, uint rva) =>
        moved.AddressMap is null ? moved.CopyStart + (rva - moved.Start)
        : moved.AddressMap.TryGetValue(rva, out uint mapped) ? mapped : null;

    /// <summary>
    /// Each rebuilt table lies in .wbdata and holds the original entries, read from the original
    /// image, mapped into the copy; an entry naming another range of the function (a case PGO
    /// moved to cold code) keeps its address.
    /// </summary>
    private static void CheckTables(BinaryImage original, BinaryImage rewritten, MovedFunction moved, VerificationReport report)
    {
        uint end = moved.Start + moved.Length;
        var ranges = original.Functions[moved.FunctionId].Ranges;
        foreach (var table in moved.Tables)
        {
            Check(report, rewritten.FindSection(table.NewRva)?.Name == ".wbdata", $"{moved.Name}: rebuilt table 0x{table.NewRva:X} is not in .wbdata");
            var before = original.ReadFrom(table.OriginalRva).Span;
            var after = rewritten.ReadFrom(table.NewRva).Span;
            if (before.Length < 4 * table.EntryCount || after.Length < 4 * table.EntryCount)
            {
                Fail(report, $"{moved.Name}: table 0x{table.OriginalRva:X} is not file-backed");
                continue;
            }

            for (int i = 0; i < table.EntryCount; i++)
            {
                uint target = BinaryPrimitives.ReadUInt32LittleEndian(before[(4 * i)..]);
                uint entry = BinaryPrimitives.ReadUInt32LittleEndian(after[(4 * i)..]);
                if (table.TableRelative)
                {
                    // Entries are signed offsets from the table itself.
                    target += table.OriginalBaseRva;
                    entry += table.NewBaseRva;
                }

                report.FieldsChecked++;
                bool inside = target >= moved.Start && target < end;
                bool otherRange = !inside && ranges.Any(r => target >= r.StartRva && target < r.StartRva + r.Length);
                Check(report, inside ? entry == TryMap(moved, target) : otherRange && entry == target,
                    $"{moved.Name}: entry {i} of table 0x{table.OriginalRva:X} is 0x{entry:X}; the original 0x{target:X} maps elsewhere");
            }
        }
    }

    /// <summary>
    /// Check 4 (DesignDoc Stage 4): WinBolt's analysis, run on the output as on any input
    /// binary, must find every copy as a function entry: from its exception entry, or, for a
    /// leaf without one, as the target of its trampoline. A copy the analysis cannot see would
    /// be invisible to any later pass run on the rewritten image. The output keeps the input's
    /// debug record, so it is analysed with the same PDB symbols, which still name every original
    /// function at its RVA (a function known only from its symbol is reached through its trampoline).
    /// </summary>
    private static void CheckReanalysis(BinaryImage original, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        rewritten.Symbols.AddRange(original.Symbols);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(rewritten, context);
        }

        var entries = rewritten.Functions.Select(f => f.EntryRva).ToHashSet();
        foreach (var moved in result.Moved)
        {
            if (entries.Contains(moved.CopyStart))
            {
                report.CopiesRediscovered++;
            }
            else
            {
                var inside = rewritten.Functions.FirstOrDefault(f => f.Ranges.Any(r => moved.CopyStart >= r.StartRva && moved.CopyStart < r.StartRva + r.Length));
                Fail(report, $"{moved.Name}: re-analysis of the output does not find the copy at 0x{moved.CopyStart:X} as a function" +
                             (inside is null ? " (no function covers it)" : $" (inside the function at 0x{inside.EntryRva:X}: {string.Join(", ", inside.Ranges.Select(r => $"0x{r.StartRva:X}+0x{r.Length:X}"))})"));
            }
        }

        // One value (§6.1): in the output, nothing the analysis finds still yields a redirected
        // function's original address, neither a relocated value nor a lea, in copies or not.
        var redirected = result.Redirection?.Targets ?? [];
        if (redirected.Count == 0)
        {
            return;
        }

        foreach (var relocation in rewritten.Relocations.Where(r => r.Type == RelocationType.Dir64))
        {
            if (rewritten.ReadFrom(relocation.Rva).Span is { Length: >= 8 } slot && BinaryPrimitives.ReadUInt64LittleEndian(slot) is var va &&
                va >= rewritten.ImageBase && redirected.ContainsKey((uint)(va - rewritten.ImageBase)))
            {
                Fail(report, $"one value: the relocated value at 0x{relocation.Rva:X} still names redirected 0x{va - rewritten.ImageBase:X}");
            }
        }

        for (int k = 0; k < rewritten.Instructions.Count; k++)
        {
            ref readonly var x = ref rewritten.Instructions[k];
            if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && redirected.ContainsKey((uint)x.IPRelativeMemoryAddress))
            {
                Fail(report, $"one value: the lea at 0x{x.IP:X} still yields redirected 0x{x.IPRelativeMemoryAddress:X}");
            }
        }
    }

    /// <summary>
    /// Every original section is unchanged except the 5-byte trampolines, each a jmp to its copy,
    /// and, with pointer redirection, every pointer to a redirected function (found here from the
    /// input, not taken from the writer): relocated values hold the copy's address, and each
    /// <c>lea</c> of one reaches the copy with only its disp32 changed. Only bytes a trampoline
    /// replaced are exempt.
    /// </summary>
    private static void CheckOriginalImage(BinaryImage original, byte[] originalFile, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        var trampolines = result.Moved.Where(m => m.HasTrampoline).ToDictionary(m => m.Start);
        var pointerTargets = result.Redirection?.Targets ?? [];
        var starts = trampolines.Keys.Order().ToArray();

        // A function moved without a trampoline keeps its original entry, so it must be one whose
        // every pointer yields the copy, and nothing outside the image may call it by address.
        var outside = new HashSet<uint>(original.Exports.Select(e => e.Rva)) { original.EntryPointRva };
        outside.UnionWith(original.TlsCallbacks);
        outside.UnionWith(original.ExceptionHandlers.Keys);
        foreach (var moved in result.Moved.Where(m => !m.HasTrampoline))
        {
            Check(report, pointerTargets.TryGetValue(moved.Start, out uint copy) && copy == moved.CopyStart,
                $"{moved.Name}: moved without a trampoline, but pointers to it are not redirected to its copy");
            Check(report, !outside.Contains(moved.Start),
                $"{moved.Name}: moved without a trampoline, but it is called from outside the image by its original address");
        }
        bool UnderTrampoline(uint start, uint end)
        {
            int i = Array.BinarySearch(starts, end - 1);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && starts[i] + TrampolineSize > start;
        }

        var slots = new Dictionary<uint, uint>();
        var leas = new Dictionary<uint, Instruction>();
        if (pointerTargets.Count > 0)
        {
            foreach (var relocation in original.Relocations.Where(r => r.Type == RelocationType.Dir64))
            {
                if (original.ReadFrom(relocation.Rva).Span is { Length: >= 8 } slot && BinaryPrimitives.ReadUInt64LittleEndian(slot) is var va &&
                    va >= original.ImageBase && pointerTargets.TryGetValue((uint)(va - original.ImageBase), out uint copy) && !UnderTrampoline(relocation.Rva, relocation.Rva + 8))
                {
                    slots[relocation.Rva] = copy;
                }
            }

            for (int k = 0; k < original.Instructions.Count; k++)
            {
                ref readonly var x = ref original.Instructions[k];
                if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && pointerTargets.ContainsKey((uint)x.IPRelativeMemoryAddress) &&
                    !UnderTrampoline((uint)x.IP, (uint)x.NextIP))
                {
                    leas[(uint)x.IP] = x;
                }
            }
        }
        var guardFields = GuardTables.FieldRanges(original).ToList();
        foreach (var section in original.Sections)
        {
            var before = original.ReadFrom(section.Rva).Span;
            var after = rewritten.ReadFrom(section.Rva).Span;
            if (before.Length != after.Length)
            {
                Fail(report, $"section {section.Name} changed size");
                continue;
            }

            for (int i = 0; i < before.Length; i++)
            {
                uint rva = section.Rva + (uint)i;
                if (trampolines.TryGetValue(rva, out var moved))
                {
                    var jump = Decoder.Create(64, new ByteArrayCodeReader(after.Slice(i, 5).ToArray()));
                    jump.IP = rva;
                    var instruction = jump.Decode();
                    Check(report, instruction.Code == Code.Jmp_rel32_64 && (uint)instruction.NearBranchTarget == moved.CopyStart,
                        $"{moved.Name}: trampoline at 0x{rva:X} does not jump to its copy");
                    i += 4;
                    continue;
                }

                if (slots.TryGetValue(rva, out uint slotCopy) && i + 8 <= after.Length)
                {
                    report.FieldsChecked++;
                    Check(report, BinaryPrimitives.ReadUInt64LittleEndian(after[i..]) == original.ImageBase + slotCopy,
                        $"{section.Name}: pointer at 0x{rva:X} to a redirected function does not hold its copy's address 0x{slotCopy:X}");
                    i += 7;
                    continue;
                }

                if (leas.TryGetValue(rva, out var lea))
                {
                    var decoder = Decoder.Create(64, new ByteArrayCodeReader(after.Slice(i, Math.Min(15, after.Length - i)).ToArray()));
                    decoder.IP = rva;
                    var now = decoder.Decode();
                    var expected = lea;
                    expected.MemoryDisplacement64 = pointerTargets[(uint)lea.IPRelativeMemoryAddress];
                    report.FieldsChecked++;
                    Check(report, now.Code == lea.Code && now.Length == lea.Length && now.Equals(expected),
                        $"{section.Name}: {lea} at 0x{rva:X} became {now}, expected it to reach the copy 0x{expected.MemoryDisplacement64:X}");
                    i += lea.Length - 1;
                    continue;
                }

                // The load config's longjmp / EH-continuation table pointers: CheckGuardTables.
                if (guardFields.Any(g => rva >= g.Start && rva < g.End))
                {
                    continue;
                }

                if (before[i] != after[i])
                {
                    Fail(report, $"{section.Name}: byte at 0x{rva:X} changed outside a trampoline");
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Longjmp and EH-continuation tables: the output's must hold every original entry and the new
    /// address of each entry inside a moved function, sorted, nothing else; a changed table lives in .wbdata.
    /// </summary>
    private static void CheckGuardTables(BinaryImage original, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        foreach (int field in GuardTables.Fields(original))
        {
            var before = GuardTables.Entries(original, field);
            var after = GuardTables.Entries(rewritten, field);
            List<uint> expected;
            try
            {
                expected = GuardTables.Extended(field, before, result.Moved, TryMap);
            }
            catch (RewriteRefusedException ex)
            {
                Fail(report, ex.Message);
                continue;
            }

            report.FieldsChecked += after.Count;
            Check(report, after.SequenceEqual(expected), $"{GuardTables.Name(field)} has {after.Count} entries, expected the {before.Count} original ones and {expected.Count - before.Count} moved targets");
        }

        foreach (var (start, _) in GuardTables.FieldRanges(original))
        {
            ulong va = BinaryPrimitives.ReadUInt64LittleEndian(rewritten.ReadFrom(start).Span);
            ulong was = BinaryPrimitives.ReadUInt64LittleEndian(original.ReadFrom(start).Span);
            Check(report, va == was || rewritten.FindSection((uint)(va - rewritten.ImageBase))?.Name == ".wbdata",
                $"the load config field at 0x{start:X} names 0x{va:X}, neither its original table nor one in .wbdata");
        }
    }

    /// <summary>
    /// The linker fixup oracle (DesignDoc Stage 4). A fixup resolves to target symbol + addend,
    /// computed from the site bytes by its COFF AMD64 relocation type.
    /// </summary>
    private static void CheckOracle(BinaryImage original, BinaryImage rewritten, RewriteResult result, VerificationReport report)
    {
        if (original.LinkerFixups.Count == 0)
        {
            report.Warnings.Add("no linker fixup records in the PDB: the fixup oracle did not run (link with /DEBUGTYPE:CV,FIXUP)");
            return;
        }

        report.OracleAvailable = true;
        var moved = result.Moved.OrderBy(m => m.Start).ToArray();
        var starts = moved.Select(m => m.Start).ToArray();
        MovedFunction? Owner(uint rva)
        {
            int i = Array.BinarySearch(starts, rva);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && rva < moved[i].Start + moved[i].Length ? moved[i] : null;
        }

        // Where a moved function's data now lives: rebuilt tables, then the copy of the range.
        static uint MapData(MovedFunction m, uint rva)
        {
            foreach (var table in m.Tables)
            {
                if (rva >= table.OriginalRva && rva < table.OriginalRva + 4 * (uint)table.EntryCount)
                {
                    return table.NewRva + (rva - table.OriginalRva);
                }
            }

            // A rebuilt function drops its range's data (index tables) and keeps reading the original's.
            return rva >= m.Start && rva < m.Start + m.Length && m.AddressMap is null ? m.CopyStart + (rva - m.Start) : rva;
        }

        uint? ReadOutput(uint rva) => rewritten.ReadFrom(rva).Span is { Length: >= 4 } bytes ? BinaryPrimitives.ReadUInt32LittleEndian(bytes) : null;

        var tableEntries = new Dictionary<uint, MovedFunction>();
        foreach (var m in moved)
        {
            foreach (var table in m.Tables)
            {
                for (int i = 0; i < table.EntryCount; i++)
                {
                    tableEntries[table.OriginalRva + 4 * (uint)i] = m;
                }
            }
        }

        var patched = result.Patched.Select(p => p.OriginalField).ToHashSet();

        // A byte copy leaves its original body intact past the trampoline, so references WinBolt
        // knows into it stay valid: C++ EH catch continuations and interior code pointers.
        var copies = result.Moved.Where(m => m.AddressMap is null).Select(m => original.Functions[m.FunctionId]).ToList();
        var knownInterior = original.CodePointers.Select(p => p.TargetRva)
            .Concat(copies.SelectMany(f => f.CxxEh?.ContinuationRvas ?? []))
            .Concat(copies.SelectMany(f => f.ScopeTable ?? []).SelectMany(e => new[] { e.BeginRva, e.EndRva, e.HandlerRva, e.JumpTargetRva }))
            .ToHashSet();

        // Branches from outside a moved range into it (a PGO-split function's cold ranges, or cold
        // fragments discovered as functions of their own) land in the original body, which stays
        // intact past the trampoline, whether the function was copied or rebuilt.
        var branchedInto = original.CallSites.Where(c => c.TargetRva is not null).Select(c => c.TargetRva!.Value)
            .Concat(result.Moved.Select(m => original.Functions[m.FunctionId])
                .SelectMany(f => f.BasicBlocks.Except(f.EntryBlocks).SelectMany(b => b.Successors).Select(e => (uint)e.Target.StartRva)))
            .ToHashSet();
        var copyOf = result.Moved.ToDictionary(m => m.Start, m => m.CopyStart);
        var exceptionData = ExceptionDataFields(original);
        var pointerTargets = result.Redirection?.Targets ?? [];
        var leaFields = new HashSet<uint>();
        for (int k = 0; pointerTargets.Count > 0 && k < original.Instructions.Count; k++)
        {
            ref readonly var x = ref original.Instructions[k];
            if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Mnemonic.Lea && pointerTargets.ContainsKey((uint)x.IPRelativeMemoryAddress) &&
                DecodeWithOffsets(original, (uint)x.IP) is { } decoded)
            {
                leaFields.Add((uint)x.IP + (uint)decoded.Offsets.DisplacementOffset);
            }
        }

        var newRelocations = result.NewRelocations.ToHashSet();
        var fixupSites = new HashSet<uint>();
        int unknownInterior = 0;
        int otherTypes = 0;

        foreach (var fixup in original.LinkerFixups)
        {
            if (Resolve(original, fixup) is not { } resolved)
            {
                otherTypes++;
                continue;
            }

            report.FixupsChecked++;
            fixupSites.Add(fixup.Rva);

            if (pointerTargets.TryGetValue(resolved, out uint pointerCopy) && !exceptionData.Contains(fixup.Rva))
            {
                CheckRedirectedFixup(original, rewritten, fixup, resolved, pointerCopy, Owner(fixup.Rva), leaFields, report);
            }

            // A jump table entry of a moved function: its rebuilt entry must name the mapped target.
            if (tableEntries.TryGetValue(fixup.Rva, out var owner))
            {
                Check(report, fixup.Type == 3 && ReadOutput(MapData(owner, fixup.Rva)) == (resolved >= owner.Start && resolved < owner.Start + owner.Length ? TryMap(owner, resolved) : resolved),
                    $"oracle: table entry 0x{fixup.Rva:X} of {owner.Name} targets 0x{resolved:X}, but its rebuilt entry does not map it");
                continue;
            }

            var site = Owner(fixup.Rva);
            var into = Owner(resolved);

            if (site is { AddressMap: not null })
            {
                CheckRebuiltFixup(original, rewritten, site, fixup, resolved, copyOf, MapData(site, resolved), pointerTargets, report);
            }
            else if (site is not null)
            {
                bool leaves = resolved < site.Start || resolved >= site.Start + site.Length;
                switch (fixup.Type)
                {
                    case >= 4 and <= 9 when leaves && !patched.Contains(fixup.Rva):
                        Fail(report, $"oracle: {site.Name} references 0x{resolved:X} at field 0x{fixup.Rva:X}, but the copier did not fix that field");
                        break;
                    case 1 when !newRelocations.Contains(site.CopyStart + (fixup.Rva - site.Start)):
                        Fail(report, $"oracle: {site.Name} has a 64-bit absolute reference at 0x{fixup.Rva:X} with no relocation in the copy");
                        break;
                    case 1 when !leaves:
                        Fail(report, $"oracle: {site.Name} holds an absolute reference to its own code at 0x{fixup.Rva:X}; the copy would use the original's address");
                        break;
                    case 3 when ReadOutput(MapData(site, fixup.Rva)) is var value && value != MapData(site, resolved):
                        Fail(report, $"oracle: {site.Name} has an image-relative reference to 0x{resolved:X} at 0x{fixup.Rva:X}; the copy holds 0x{value:X}, expected 0x{MapData(site, resolved):X}");
                        break;
                }
            }

            // References from exception data (.pdata entries, chained unwind trailers) are rebuilt
            // for the copies; CheckStructure verifies them.
            // A reference into a moved function past its entry runs the original body, left intact
            // past the trampoline (§6.1: an undiscovered reference still reaches valid code, it only
            // misses the optimization). Only the trampoline's bytes are no longer the original code.
            if (into is not null && into != site && resolved != into.Start && !exceptionData.Contains(fixup.Rva) &&
                !(into.AddressMap is null && knownInterior.Contains(resolved)) && !branchedInto.Contains(resolved))
            {
                if (into.HasTrampoline && resolved < into.Start + TrampolineSize)
                {
                    Fail(report, $"oracle: a reference at 0x{fixup.Rva:X} targets 0x{resolved:X}, inside {into.Name}'s trampoline; WinBolt did not know about it");
                }
                else
                {
                    unknownInterior++;
                }
            }
        }

        if (unknownInterior > 0)
        {
            report.Warnings.Add($"oracle: {unknownInterior} references WinBolt did not know land inside moved functions past the trampoline: " +
                                "they run the original code (correct, not optimized)");
        }

        // The converse: fields the copier changed that the linker does not list as references.
        int extra = result.Patched.Count(p => !fixupSites.Contains(p.OriginalField));
        if (extra > 0)
        {
            report.Warnings.Add($"oracle: {extra} fields the copier fixed have no linker fixup record (references resolved at compile time)");
        }

        if (otherTypes > 0)
        {
            report.Warnings.Add($"oracle: {otherTypes} fixup records of other types were not checked");
        }
    }

    /// <summary>
    /// A fixup inside a rebuilt function: the instruction holding the field must resolve to the
    /// mapped target in its new encoding. Relative fields are branches (to the mapped block, or a
    /// moved callee's copy) or RIP-relative operands (same absolute address); image-relative
    /// fields are displacements (table loads name the rebuilt table, other data is unchanged).
    /// </summary>
    private static void CheckRebuiltFixup(BinaryImage original, BinaryImage rewritten, MovedFunction site, LinkerFixup fixup, uint resolved,
        Dictionary<uint, uint> copyOf, uint mappedData, IReadOnlyDictionary<uint, uint> pointerTargets, VerificationReport report)
    {
        var starts = site.AddressMap!.Keys.Where(k => k < site.Start + site.Length).Order().ToArray();
        int index = Array.BinarySearch(starts, fixup.Rva);
        index = index >= 0 ? index : ~index - 1;
        if (index < 0 || DecodeAt(original, starts[index]) is not { } x || fixup.Rva >= x.NextIP ||
            DecodeAt(rewritten, site.AddressMap[starts[index]]) is not { } y)
        {
            Fail(report, $"oracle: fixup at 0x{fixup.Rva:X} in {site.Name} is not inside a rebuilt instruction");
            return;
        }

        uint end = site.Start + site.Length;
        bool ok = fixup.Type switch
        {
            >= 4 and <= 9 when x.Op0Kind == OpKind.NearBranch64 =>
                (uint)y.NearBranchTarget == (resolved >= site.Start && resolved < end ? TryMap(site, resolved) : copyOf.GetValueOrDefault(resolved, resolved)),
            >= 4 and <= 9 when x.IsIPRelativeMemoryOperand => y.IsIPRelativeMemoryOperand && (uint)y.IPRelativeMemoryAddress ==
                (x.Mnemonic == Mnemonic.Lea && pointerTargets.TryGetValue(resolved, out uint pointer) ? pointer : resolved),
            3 when !x.IsIPRelativeMemoryOperand && (uint)x.MemoryDisplacement64 == resolved => (uint)y.MemoryDisplacement64 == mappedData,
            _ => false,
        };
        Check(report, ok, $"oracle: {site.Name} references 0x{resolved:X} at 0x{fixup.Rva:X} (type {fixup.Type}); the rebuilt {y} does not resolve to it");
    }

    /// <summary>Field RVAs of the exception table and of every chained UNWIND_INFO's parent entry.</summary>
    private static HashSet<uint> ExceptionDataFields(BinaryImage image)
    {
        var fields = new HashSet<uint>();
        if (image.DataDirectories.FirstOrDefault(d => d.Name == "Exception") is { } table)
        {
            for (uint rva = table.Rva; rva < table.Rva + table.Size; rva += 4)
            {
                fields.Add(rva);
            }
        }

        foreach (var entry in image.ExceptionData.Where(e => e.IsChained && (e.UnwindInfoAddress & 1) == 0))
        {
            var info = image.ReadFrom(entry.UnwindInfoAddress).Span;
            if (info.Length >= 4)
            {
                uint trailer = entry.UnwindInfoAddress + (uint)FunctionRewriter.UnwindTrailerOffset(info);
                fields.UnionWith([trailer, trailer + 4, trailer + 8]);
            }
        }

        return fields;
    }

    private static uint? Resolve(BinaryImage image, LinkerFixup fixup)
    {
        var site = image.ReadFrom(fixup.Rva).Span;
        return fixup.Type switch
        {
            1 when site.Length >= 8 => (uint)(BinaryPrimitives.ReadUInt64LittleEndian(site) - image.ImageBase),
            3 when site.Length >= 4 => BinaryPrimitives.ReadUInt32LittleEndian(site),
            >= 4 and <= 9 when site.Length >= 4 => (uint)(fixup.Rva + 4 + (fixup.Type - 4) + BinaryPrimitives.ReadInt32LittleEndian(site)),
            _ => null,
        };
    }

    private static void Expect(VerificationReport report, bool condition, string failure)
    {
        if (!condition)
        {
            report.Failures.Add(failure);
        }
    }

    private static void Check(VerificationReport report, bool condition, string failure)
    {
        if (!condition)
        {
            Fail(report, failure);
        }
    }

    private static void Fail(VerificationReport report, string failure)
    {
        if (report.Failures.Count < MaxReported)
        {
            report.Failures.Add(failure);
        }
        else if (report.Failures.Count == MaxReported)
        {
            report.Failures.Add("... more failures not shown");
        }
    }
}