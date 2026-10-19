using System.Buffers.Binary;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pe;

namespace WinBolt.Rewrite;

/// <summary>Outcome of verifying a whole-program rewrite.</summary>
public sealed class WholeProgramVerification
{
    public List<string> Failures { get; } = [];

    public List<string> Warnings { get; } = [];

    public int FixupsChecked { get; set; }

    public long BytesCompared { get; set; }

    /// <summary>Instructions of rebuilt functions checked at their new addresses.</summary>
    public int InstructionsCompared { get; set; }

    public int FunctionsFound { get; set; }

    public bool Passed => Failures.Count == 0;
}

/// <summary>
/// Verification of a whole-program rewrite (DesignDoc §6.2 "Verification"): with the gate passed,
/// the fixup records are the complete list of linker-resolved references, so checking each one
/// at its new site, plus byte identity of everything else, covers the image. The output is
/// re-read with WinBolt's own PE reader and re-analysed.
/// </summary>
public static class WholeProgramVerifier
{
    private const int MaxFailures = 20;

    public static WholeProgramVerification Verify(BinaryImage original, byte[] originalFile, WholeProgramResult result)
    {
        var report = new WholeProgramVerification();
        var output = result.Output;
        BinaryImage rewritten;
        try
        {
            rewritten = PeImageReader.Read("rewritten.exe", output);
        }
        catch (PeFormatException ex)
        {
            report.Failures.Add($"the output does not parse: {ex.Message}");
            return report;
        }

        var exempt = new HashSet<long>();
        void Exempt(long offset, int length)
        {
            for (int i = 0; i < length; i++)
            {
                exempt.Add(offset + i);
            }
        }

        CheckFixups(original, originalFile, rewritten, result, report, Exempt);
        CheckCode(original, originalFile, rewritten, result, report);
        CheckRebuiltFunctions(original, rewritten, result, report);
        CheckStructures(original, rewritten, result, report, Exempt);
        CheckUnchanged(original, originalFile, result, report, exempt);
        CheckReanalysis(original, rewritten, result, report);
        return report;
    }

    /// <summary>Every fixup resolves, at its new site, to its target's new address.</summary>
    private static void CheckFixups(BinaryImage original, byte[] originalFile, BinaryImage rewritten, WholeProgramResult result,
        WholeProgramVerification report, Action<long, int> exempt)
    {
        foreach (var fixup in original.LinkerFixups)
        {
            if (result.CfgTables.Any(t => fixup.Rva >= t.Rva && fixup.Rva < t.Rva + t.Size))
            {
                continue; // re-sorted: CheckStructures compares the tables as sets
            }

            if (result.Owner(fixup.Rva) is { } owner && result.Rebuilt.ContainsKey(owner.Contribution.Rva))
            {
                continue; // re-encoded: CheckRebuiltFunctions checks every instruction's target
            }

            if (WholeProgramRewriter.FileOffset(original, fixup.Rva) is not { } at ||
                WholeProgramRewriter.Resolve(original, originalFile, fixup, at) is not { } value)
            {
                continue;
            }

            uint site = result.MapSite(fixup.Rva);
            var moved = fixup with { Rva = site };
            int to = WholeProgramRewriter.FileOffset(rewritten, site)!.Value;
            exempt(to, fixup.Type == 1 ? 8 : 4);
            report.FixupsChecked++;
            uint expected = result.MapValue(fixup.Target, value);
            if (WholeProgramRewriter.Resolve(rewritten, result.Output, moved, to) is not { } actual || actual != expected)
            {
                Fail(report, $"fixup at 0x{fixup.Rva:X} (now 0x{site:X}, type {fixup.Type}) resolves to 0x{WholeProgramRewriter.Resolve(rewritten, result.Output, moved, to):X}, expected 0x{expected:X}");
            }
        }
    }

    /// <summary>Each contribution's bytes are the original's at the new place, apart from fixup fields; gaps are int3.</summary>
    private static void CheckCode(BinaryImage original, byte[] originalFile, BinaryImage rewritten, WholeProgramResult result, WholeProgramVerification report)
    {
        var fields = new HashSet<uint>();
        foreach (var fixup in original.LinkerFixups.Where(f => result.Owner(f.Rva) is not null))
        {
            for (uint i = 0; i < (fixup.Type == 1 ? 8u : 4u); i++)
            {
                fields.Add(fixup.Rva + i);
            }
        }

        foreach (var p in result.Placed.Where(p => !result.Rebuilt.ContainsKey(p.Contribution.Rva)))
        {
            int from = WholeProgramRewriter.FileOffset(original, p.Contribution.Rva)!.Value;
            int to = WholeProgramRewriter.FileOffset(rewritten, p.NewRva)!.Value;
            for (uint i = 0; i < p.Contribution.Size; i++)
            {
                report.BytesCompared++;
                if (!fields.Contains(p.Contribution.Rva + i) && originalFile[from + i] != result.Output[to + i])
                {
                    Fail(report, $"contribution 0x{p.Contribution.Rva:X} (now 0x{p.NewRva:X}): byte +0x{i:X} changed outside a fixup field");
                    break;
                }
            }
        }

        // Every code area (each original section's, and the spill section) is contributions and int3.
        var areas = WholeProgramRewriter.CodeAreas(original, result).ToList();
        if (result.Spill.Size > 0)
        {
            areas.Add((result.Spill.Rva, result.Spill.Rva + result.Spill.Size));
            Check(report, rewritten.FindSection(result.Spill.Rva) is { IsExecutable: true } spill && spill.Name == WholeProgramRewriter.SpillName,
                $"the spill section {WholeProgramRewriter.SpillName} is missing or not executable");
        }

        var placed = WholeProgramRewriter.NewSpans(result).OrderBy(s => s.Start).ToList();
        foreach (var (start, end) in areas)
        {
            var spans = placed.Where(s => s.End > start && s.Start < end).ToList();
            int k = 0;
            for (uint rva = start; rva < end; rva++)
            {
                while (k < spans.Count && spans[k].End <= rva)
                {
                    k++;
                }

                bool inside = k < spans.Count && rva >= spans[k].Start;
                if (!inside && result.Output[WholeProgramRewriter.FileOffset(rewritten, rva)!.Value] != 0xCC)
                {
                    Fail(report, $"0x{rva:X} lies between contributions but is not int3");
                    break;
                }
            }
        }
    }

    /// <summary>Entry point, exports, .pdata, CFG tables and relocations are the originals, mapped.</summary>
    private static void CheckStructures(BinaryImage original, BinaryImage rewritten, WholeProgramResult result, WholeProgramVerification report,
        Action<long, int> exempt)
    {
        var layout = new PeLayout(result.Output);
        exempt(layout.OptionalHeader + 16, 4);
        exempt(layout.CheckSumOffset, 4);
        exempt(layout.DataDirectory(PeLayout.SecurityDirectory), 8);
        exempt(layout.DataDirectory(PeLayout.BaseRelocationDirectory) + 4, 4);
        if (result.AddedSections > 0)
        {
            exempt(layout.NumberOfSectionsOffset, 2);
            exempt(layout.SizeOfImageOffset, 4);
            exempt(layout.SectionTable + (layout.NumberOfSections - result.AddedSections) * PeLayout.SectionHeaderSize, result.AddedSections * PeLayout.SectionHeaderSize);
        }

        if (result.Data.Size > 0)
        {
            exempt(layout.DataDirectory(PeLayout.ExceptionDirectory), 8);
            Check(report, rewritten.DataDirectories.FirstOrDefault(d => d.Name == "Exception")?.Rva == result.Data.Rva,
                $"the exception directory does not name the regenerated table in {WholeProgramRewriter.DataName}");
        }

        for (int i = 0; i < layout.NumberOfSections; i++)
        {
            int header = layout.SectionTable + i * PeLayout.SectionHeaderSize;
            string name = System.Text.Encoding.ASCII.GetString(result.Output, header, 8).TrimEnd('\0');
            if (result.GrownSections.TryGetValue(name, out uint size))
            {
                Check(report, BinaryPrimitives.ReadUInt32LittleEndian(result.Output.AsSpan(header + 8)) == size, $"{name}: virtual size not grown to 0x{size:X}");
                exempt(header + 8, 4);
            }
        }

        Check(report, rewritten.EntryPointRva == result.MapSite(original.EntryPointRva),
            $"entry point is 0x{rewritten.EntryPointRva:X}, expected 0x{result.MapSite(original.EntryPointRva):X}");

        Check(report, rewritten.Exports.Count == original.Exports.Count &&
                      rewritten.Exports.Zip(original.Exports).All(e => e.First.Rva == (e.Second.Forwarder is null ? result.MapSite(e.Second.Rva) : e.Second.Rva)),
            "the export table does not hold the mapped export addresses");
        if (WholeProgramRewriter.Directory(original, "Export") is { } exports)
        {
            int header = WholeProgramRewriter.FileOffset(original, exports.Rva)!.Value;
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(result.Output.AsSpan(header + 20));
            uint table = BinaryPrimitives.ReadUInt32LittleEndian(result.Output.AsSpan(header + 28));
            exempt(WholeProgramRewriter.FileOffset(original, table)!.Value, (int)count * 4);
        }

        // A rebuilt function's trailing table entry (BlockRebuilder.IsTableEntry) is dropped.
        var rebuiltBegins = result.Rebuilt.Values.SelectMany(r => r.Pdata).Select(p => p.OriginalBegin).ToHashSet();
        var expectedPdata = original.ExceptionData
            .Where(e => !(result.Owner(e.BeginAddress) is { } p && result.Rebuilt.TryGetValue(p.Contribution.Rva, out var r) &&
                          !rebuiltBegins.Contains(e.BeginAddress) && BlockRebuilder.IsTableEntry(original, r.Function, e)))
            .Select(e => (Begin: result.MapSite(e.BeginAddress), End: result.MapValue(e.BeginAddress, e.EndAddress), Unwind: result.MapValue(e.UnwindInfoAddress, e.UnwindInfoAddress)))
            .Concat(result.Rebuilt.Values.SelectMany(r => r.ColdEntries).Select(c => (Begin: c.Begin, End: c.End, Unwind: c.UnwindInfo)))
            .OrderBy(e => e.Begin).ToList();
        var actualPdata = rewritten.ExceptionData.Select(e => (Begin: e.BeginAddress, End: e.EndAddress, Unwind: e.UnwindInfoAddress)).ToList();
        Check(report, expectedPdata.SequenceEqual(actualPdata), "the exception table is not the mapped original, sorted");
        if (WholeProgramRewriter.Directory(original, "Exception") is { } pdata)
        {
            exempt(WholeProgramRewriter.FileOffset(original, pdata.Rva)!.Value, (int)pdata.Size);
        }

        if (original.LoadConfig is { } before && rewritten.LoadConfig is { } after)
        {
            static bool Same(IEnumerable<uint> expected, IEnumerable<uint> actual) => expected.Order().SequenceEqual(actual);
            Check(report, Same(before.GuardCfFunctionTable.Select(result.MapSite), after.GuardCfFunctionTable), "GuardCFFunctionTable is not the mapped original, sorted");
            Check(report, Same(before.GuardLongJumpTargetTable.Select(result.MapSite), after.GuardLongJumpTargetTable), "GuardLongJumpTargetTable is not the mapped original, sorted");
            Check(report, Same((before.GuardEhContinuationTable ?? []).Select(result.MapSite), after.GuardEhContinuationTable ?? []), "GuardEHContinuationTable is not the mapped original, sorted");
            ExemptLoadConfigTables(original, result.Output, exempt);
        }

        var expectedRelocations = original.Relocations.Where(r => r.Type != RelocationType.Absolute).Select(r => (result.MapSite(r.Rva), r.Type)).ToHashSet();
        var actualRelocations = rewritten.Relocations.Where(r => r.Type != RelocationType.Absolute).Select(r => (r.Rva, r.Type)).ToHashSet();
        Check(report, expectedRelocations.SetEquals(actualRelocations), $"relocations: {expectedRelocations.Except(actualRelocations).Count()} expected missing, {actualRelocations.Except(expectedRelocations).Count()} unexpected");
        if (WholeProgramRewriter.Directory(original, "BaseRelocation") is { } relocs)
        {
            var section = original.FindSection(relocs.Rva)!;
            exempt(WholeProgramRewriter.FileOffset(original, relocs.Rva)!.Value, (int)(section.Rva + section.RawSize - relocs.Rva));
        }

        foreach (var entry in original.DebugEntries.Where(e => e.Type == DebugDirectoryType.CodeView))
        {
            exempt(entry.PointerToRawData + 4, result.PdbGuid is null ? 16 : (int)entry.SizeOfData - 4);
        }

        if (result.PdbGuid is { } guid)
        {
            Check(report, rewritten.CodeView is { } codeView && codeView.Guid == guid && codeView.Age == result.PdbAge,
                "the CodeView record does not name the new PDB's GUID and age");
        }

        Check(report, rewritten.CodeView?.Guid != original.CodeView?.Guid || original.CodeView is null,
            "the RSDS GUID still names the original PDB, which describes the old layout");
    }

    /// <summary>
    /// Rebuilt functions: every instruction at its new address (the append verifier's per-block
    /// check, with every outside target at its new address), their rebuilt jump tables, and the
    /// cold parts' UNWIND_INFO chained to the hot entry.
    /// </summary>
    private static void CheckRebuiltFunctions(BinaryImage original, BinaryImage rewritten, WholeProgramResult result, WholeProgramVerification report)
    {
        foreach (var r in result.Rebuilt.Values)
        {
            var f = r.Function;
            uint start = f.EntryRva, end = start + f.EntryRange.Length;
            var targets = new Dictionary<uint, uint>();
            var pointers = new Dictionary<uint, uint>();
            foreach (var x in BlockRebuilder.Instructions(original, f))
            {
                if (x.Op0Kind == Iced.Intel.OpKind.NearBranch64 && (x.NearBranchTarget < start || x.NearBranchTarget >= end))
                {
                    targets[(uint)x.NearBranchTarget] = result.MapValue((uint)x.NearBranchTarget, (uint)x.NearBranchTarget);
                }

                if (x.IsIPRelativeMemoryOperand && x.Mnemonic == Iced.Intel.Mnemonic.Lea)
                {
                    pointers[(uint)x.IPRelativeMemoryAddress] = result.MapValue((uint)x.IPRelativeMemoryAddress, (uint)x.IPRelativeMemoryAddress);
                }
            }

            var moved = new MovedFunction(f.Id, f.DisplayName, start, f.EntryRange.Length, r.HotStart, r.Pdata, r.Tables, [])
            {
                AddressMap = r.AddressMap,
                CopyLength = r.HotLength,
                ColdStart = r.ColdLength > 0 ? r.ColdStart : 0,
                ColdLength = r.ColdLength,
                ColdEntries = r.ColdEntries,
            };
            var inner = new VerificationReport();
            RewriteVerifier.CheckRebuilt(original, rewritten, moved, targets, pointers, inner);
            report.InstructionsCompared += inner.InstructionsCompared;
            foreach (string failure in inner.Failures)
            {
                Fail(report, failure);
            }

            foreach (var table in r.Tables)
            {
                var jumpTable = f.JumpTables.First(t => (uint)t.Rva == table.OriginalRva);
                if (table.NewIndexRva is { } index)
                {
                    Check(report, rewritten.ReadFrom(index).Span is var copied && copied.Length >= jumpTable.IndexEntryCount &&
                                  copied[..jumpTable.IndexEntryCount].SequenceEqual(original.ReadFrom((uint)jumpTable.IndexTableRva!.Value).Span[..jumpTable.IndexEntryCount]),
                        $"{f.DisplayName}: the byte table copied to 0x{index:X} differs from the original");
                }

                var bytes = rewritten.ReadFrom(table.NewRva).Span;
                for (int i = 0; i < jumpTable.TargetRvas.Count; i++)
                {
                    uint target = (uint)jumpTable.TargetRvas[i];
                    uint expected = target >= start && target < end ? r.AddressMap[target] : result.MapValue(target, target);
                    Check(report, bytes.Length >= 4 * (i + 1) && BinaryPrimitives.ReadUInt32LittleEndian(bytes[(4 * i)..]) == expected,
                        $"{moved.Name}: entry {i} of the table rebuilt at 0x{table.NewRva:X} is not 0x{expected:X}");
                }
            }

            foreach (var cold in r.ColdEntries)
            {
                var parent = r.Pdata.First(p => p.OriginalBegin == cold.OriginalBegin);
                var info = rewritten.ReadFrom(cold.UnwindInfo).Span;
                Check(report, info.Length >= 16 && info[0] == (1 | (0x4 << 3)) && info[2] == 0 &&
                              BinaryPrimitives.ReadUInt32LittleEndian(info[4..]) == parent.Begin &&
                              BinaryPrimitives.ReadUInt32LittleEndian(info[8..]) == parent.End &&
                              BinaryPrimitives.ReadUInt32LittleEndian(info[12..]) == parent.UnwindInfo,
                    $"{moved.Name}: the cold part's UNWIND_INFO at 0x{cold.UnwindInfo:X} is not an empty chain to its hot entry");
            }
        }
    }

    private static void ExemptLoadConfigTables(BinaryImage original, byte[] output, Action<long, int> exempt)
    {
        if (WholeProgramRewriter.Directory(original, "LoadConfig") is not { } directory)
        {
            return;
        }

        int config = WholeProgramRewriter.FileOffset(original, directory.Rva)!.Value;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(config));
        uint flags = size >= 0x94 ? BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(config + 0x90)) : 0;
        foreach (var (tableField, countField, stride) in new[] { (0x80, 0x88, 4 + (int)(flags >> 28)), (0xB0, 0xB8, 4), (0x108, 0x110, 4) })
        {
            if (size < countField + 8)
            {
                continue;
            }

            ulong va = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(config + tableField));
            ulong count = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(config + countField));
            if (va != 0 && WholeProgramRewriter.FileOffset(original, (uint)(va - original.ImageBase)) is { } at)
            {
                exempt(at, (int)count * stride);
            }
        }
    }

    /// <summary>Outside the code areas and the fields the rewrite regenerates, the file is byte-identical.</summary>
    private static void CheckUnchanged(BinaryImage original, byte[] originalFile, WholeProgramResult result, WholeProgramVerification report, HashSet<long> exempt)
    {
        var codeAreas = WholeProgramRewriter.CodeAreas(original, result).Select(a =>
        {
            long from = WholeProgramRewriter.FileOffset(original, a.Start)!.Value;
            return (From: from, To: from + (a.End - a.Start));
        }).ToList();

        int length = Math.Min(originalFile.Length, result.Output.Length);
        for (long i = 0; i < length; i++)
        {
            if (originalFile[i] != result.Output[i] && !exempt.Contains(i) && !codeAreas.Any(a => i >= a.From && i < a.To))
            {
                Fail(report, $"file offset 0x{i:X} changed outside the code, the fixup fields and the regenerated structures");
                return;
            }
        }
    }

    /// <summary>WinBolt's analysis of the output finds every original function at its new address.</summary>
    private static void CheckReanalysis(BinaryImage original, BinaryImage rewritten, WholeProgramResult result, WholeProgramVerification report)
    {
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(rewritten, context);
        }

        var entries = rewritten.Functions.Select(f => f.EntryRva).ToHashSet();
        var pdataEntries = original.ExceptionData.Where(e => !e.IsChained).Select(e => e.BeginAddress).ToHashSet();
        int missing = 0;
        foreach (var f in original.Functions)
        {
            if (entries.Contains(result.MapSite(f.EntryRva)))
            {
                report.FunctionsFound++;
            }
            else if (pdataEntries.Contains(f.EntryRva))
            {
                Fail(report, $"re-analysis does not find {f.DisplayName} at 0x{result.MapSite(f.EntryRva):X}");
            }
            else
            {
                missing++;
            }
        }

        if (missing > 0)
        {
            report.Warnings.Add($"re-analysis (without the PDB) does not find {missing} leaf functions the original analysis found with it");
        }
    }

    private static void Check(WholeProgramVerification report, bool condition, string failure)
    {
        if (!condition)
        {
            Fail(report, failure);
        }
    }

    private static void Fail(WholeProgramVerification report, string failure)
    {
        if (report.Failures.Count < MaxFailures)
        {
            report.Failures.Add(failure);
        }
        else if (report.Failures.Count == MaxFailures)
        {
            report.Failures.Add("(more failures not listed)");
        }
    }
}
