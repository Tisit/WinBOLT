using Iced.Intel;
using WinBolt.Core.Ir;
using Decoder = Iced.Intel.Decoder;

namespace WinBolt.Rewrite;

/// <summary>One check of the whole-program gate, with what it counted.</summary>
public sealed record GateCheck(string Name, bool Passed, string Detail);

/// <summary>The gate's verdict: whole-program rewriting is allowed only when every check passed.</summary>
public sealed class WholeProgramGateReport
{
    public List<GateCheck> Checks { get; } = [];

    public bool Passed => Checks.Count > 0 && Checks.All(c => c.Passed);

    /// <summary>Linker fixups whose site lies in code no function decoded (Frozen or uncovered bytes): not cross-checked, moved with their contribution.</summary>
    public int UndecodedCodeFixups { get; set; }

    /// <summary>Functions whose handler data is not understood: they can move only as whole contributions (§6.2 check 6).</summary>
    public int OpaqueHandlerFunctions { get; set; }
}

/// <summary>
/// DesignDoc §6.2's gate for whole-program (in-place) rewriting: the linker's fixup records must
/// be present and complete, which the gate establishes by checking them against everything the
/// analysis found independently, in both directions. One disagreement refuses the image. Runs on
/// an analysed image with its PDB loaded.
/// </summary>
public static class WholeProgramGate
{
    private const int Addr64 = 1, Addr32 = 2, Addr32Nb = 3;
    private const ushort DynamicBase = 0x0040;
    private static readonly byte[] PaddingBytes = [0xCC, 0x90, 0x00];

    /// <summary>How many examples a failing check lists.</summary>
    private const int Examples = 3;

    public static WholeProgramGateReport Check(BinaryImage image)
    {
        var report = new WholeProgramGateReport();
        if (!Records(image, report))
        {
            return report;
        }

        var fixups = image.LinkerFixups.GroupBy(f => f.Rva).ToDictionary(g => g.Key, g => g.First());
        var contributions = image.SectionContributions
            .Where(c => image.FindSection(c.Rva) is { IsExecutable: true })
            .OrderBy(c => c.Rva).ToArray();

        IncrementalLink(image, contributions, report);
        Relocations(image, fixups, report);
        Tiling(image, contributions, report);
        Decoding(image, fixups, contributions, report);
        Structures(image, fixups, report);
        report.OpaqueHandlerFunctions = image.Functions.Count(f => f.ExceptionHandler is { Kind: ExceptionHandlerKind.Unknown });
        return report;
    }

    /// <summary>Check 1: a matching PDB with fixup records and section contributions, and no OMAP.</summary>
    private static bool Records(BinaryImage image, WholeProgramGateReport report)
    {
        string? problem = image.Pdb switch
        {
            null => "no matching PDB was loaded",
            { HasOmap: true } => "the PDB has OMAP: the image was already rewritten after linking",
            _ when image.LinkerFixups.Count == 0 => "the PDB has no linker fixup records (link with /DEBUGTYPE:CV,FIXUP)",
            _ when image.SectionContributions.Count == 0 => "the PDB has no section contributions",
            _ => null,
        };
        report.Checks.Add(new GateCheck("records present", problem is null,
            problem ?? $"{image.LinkerFixups.Count:N0} fixups, {image.SectionContributions.Count:N0} section contributions"));
        return problem is null;
    }

    /// <summary>
    /// Check 2: no incremental-link thunk table. An ILT is a code contribution made only of
    /// <c>jmp rel32</c> thunks; references to its functions go through it without object fixups.
    /// </summary>
    private static void IncrementalLink(BinaryImage image, SectionContribution[] contributions, WholeProgramGateReport report)
    {
        bool Thunks(SectionContribution c)
        {
            var bytes = image.ReadFrom(c.Rva).Span;
            if (c.Size < 10 || c.Size % 5 != 0 || bytes.Length < c.Size)
            {
                return false;
            }

            for (int i = 0; i < c.Size; i += 5)
            {
                if (bytes[i] != 0xE9)
                {
                    return false;
                }
            }

            return true;
        }

        var thunkTables = contributions.Where(Thunks).ToList();
        report.Checks.Add(new GateCheck("no incremental linking", thunkTables.Count == 0,
            thunkTables.Count == 0 ? "no jump thunk table" : $"jump thunk table (ILT) at 0x{thunkTables[0].Rva:X}: relink with /INCREMENTAL:NO"));
    }

    /// <summary>Check 3: every base relocation has an absolute fixup and, in a DYNAMIC_BASE image, the reverse.</summary>
    private static void Relocations(BinaryImage image, Dictionary<uint, LinkerFixup> fixups, WholeProgramGateReport report)
    {
        var relocated = image.Relocations.Where(r => r.Type != RelocationType.Absolute).Select(r => r.Rva).ToHashSet();
        var unfixed = relocated.Where(r => !fixups.TryGetValue(r, out var f) || f.Type is not (Addr64 or Addr32)).Order().ToList();
        var unrelocated = (image.DllCharacteristics & DynamicBase) == 0
            ? []
            : fixups.Values.Where(f => f.Type is Addr64 or Addr32 && image.FindSection(f.Rva) is not null && !relocated.Contains(f.Rva))
                .Select(f => f.Rva).Order().ToList();
        var otherTypes = image.LinkerFixups.Where(f => f.Type is not (Addr64 or Addr32 or Addr32Nb) and not (>= 4 and <= 9)).ToList();
        var otherIntoCode = otherTypes.Where(f => image.FindSection(f.Rva) is not null && image.FindSection(f.Target) is { IsExecutable: true }).ToList();

        var problems = new List<string>();
        if (unfixed.Count > 0)
        {
            problems.Add($"{unfixed.Count:N0} relocations without an absolute fixup ({Hex(unfixed)})");
        }

        if (unrelocated.Count > 0)
        {
            problems.Add($"{unrelocated.Count:N0} absolute fixups without a relocation ({Hex(unrelocated)})");
        }

        if (otherIntoCode.Count > 0)
        {
            problems.Add($"{otherIntoCode.Count:N0} fixups of other types in mapped sections target code ({Hex(otherIntoCode.Select(f => f.Rva))})");
        }

        report.Checks.Add(new GateCheck("relocations agree", problems.Count == 0,
            problems.Count == 0 ? $"{relocated.Count:N0} relocations, each with its fixup; {otherTypes.Count:N0} fixups of other types, none into code" : string.Join("; ", problems)));
    }

    /// <summary>Check 4: contributions tile the code sections (gaps are padding) and every fixup into code lands in one.</summary>
    private static void Tiling(BinaryImage image, SectionContribution[] contributions, WholeProgramGateReport report)
    {
        var problems = new List<string>();
        var overlaps = contributions.Zip(contributions.Skip(1)).Where(p => p.First.Rva + p.First.Size > p.Second.Rva).Select(p => p.Second.Rva).ToList();
        if (overlaps.Count > 0)
        {
            problems.Add($"{overlaps.Count:N0} overlapping contributions ({Hex(overlaps)})");
        }

        var gaps = new List<uint>();
        long gapBytes = 0;
        foreach (var section in image.Sections.Where(s => s.IsExecutable))
        {
            var inSection = contributions.Where(c => section.Contains(c.Rva)).ToArray();
            uint cursor = section.Rva, end = section.Rva + (uint)Math.Min(section.Data.Length, section.MappedSize);
            foreach (var c in inSection.Append(new SectionContribution(end, 0, 0, -1)))
            {
                for (uint rva = cursor; rva < Math.Min(c.Rva, end); rva++)
                {
                    gapBytes++;
                    if (Array.IndexOf(PaddingBytes, section.Data.Span[(int)(rva - section.Rva)]) < 0)
                    {
                        gaps.Add(rva);
                        break;
                    }
                }

                cursor = Math.Max(cursor, c.Rva + c.Size);
            }
        }

        if (gaps.Count > 0)
        {
            problems.Add($"{gaps.Count:N0} gaps between contributions hold code or data ({Hex(gaps)})");
        }

        var outside = image.LinkerFixups.Where(f => image.FindSection(f.Target) is { IsExecutable: true } && Owner(contributions, f.Target) is null)
            .Select(f => f.Target).Distinct().Order().ToList();
        if (outside.Count > 0)
        {
            problems.Add($"{outside.Count:N0} fixup targets in code outside every contribution ({Hex(outside)})");
        }

        report.Checks.Add(new GateCheck("contributions tile the code", problems.Count == 0,
            problems.Count == 0 ? $"{contributions.Length:N0} code contributions; {gapBytes:N0} gap bytes, all padding" : string.Join("; ", problems)));
    }

    /// <summary>
    /// Check 5: decoding agrees with the records both ways. Every decoded branch or RIP-relative
    /// operand that leaves its contribution has a fixup on its field (an rel8 branch cannot:
    /// x64 COFF has no 8-bit relocation), and every fixup inside decoded code is on an operand
    /// field of the instruction holding it. Recovered jump table entries are fixed up too.
    /// </summary>
    private static void Decoding(BinaryImage image, Dictionary<uint, LinkerFixup> fixups, SectionContribution[] contributions, WholeProgramGateReport report)
    {
        var missing = new List<uint>();
        var shortBranches = new List<uint>();
        var fields = new HashSet<uint>();
        var starts = new List<(uint Start, uint End)>();
        long references = 0;

        // A function whose decode ran into bytes that are not code holds junk "instructions": its
        // code counts as undecoded (it moves only as a whole contribution).
        var junk = new HashSet<int>();
        foreach (var f in image.Functions.Where(f => f.DowngradeReasons.Any(r => r.StartsWith("undecodable", StringComparison.Ordinal) ||
                                                                                 r.StartsWith("falls-into-data", StringComparison.Ordinal))))
        {
            foreach (var block in f.BasicBlocks)
            {
                for (int k = 0; k < block.InstructionCount; k++)
                {
                    junk.Add(block.InstructionStart + k);
                }
            }
        }

        var readers = image.Sections.Where(s => s.IsExecutable).ToDictionary(s => s, s => new ByteArrayCodeReader(s.Data.ToArray()));
        var decoders = readers.ToDictionary(kv => kv.Key, kv => Decoder.Create(64, kv.Value));
        for (int id = 0; id < image.Instructions.Count; id++)
        {
            if (junk.Contains(id))
            {
                continue;
            }

            ref readonly var x = ref image.Instructions[id];
            uint ip = (uint)x.IP;
            starts.Add((ip, (uint)x.NextIP));
            if (image.FindSection(ip) is not { IsExecutable: true } section)
            {
                continue;
            }

            bool branch = x.Op0Kind is OpKind.NearBranch64 or OpKind.NearBranch32 or OpKind.NearBranch16;
            if (!branch && !x.IsIPRelativeMemoryOperand)
            {
                continue;
            }

            var reader = readers[section];
            var decoder = decoders[section];
            reader.Position = (int)(ip - section.Rva);
            decoder.IP = ip;
            var again = decoder.Decode();
            var offsets = decoder.GetConstantOffsets(again);

            uint target = branch ? (uint)x.NearBranchTarget : (uint)x.IPRelativeMemoryAddress;
            uint field = branch ? ip + (uint)offsets.ImmediateOffset : ip + (uint)offsets.DisplacementOffset;
            fields.Add(field);
            var owner = Owner(contributions, ip);
            if (owner is { } o && target >= o.Rva && target < o.Rva + o.Size)
            {
                continue; // resolved by the compiler inside the contribution
            }

            references++;
            if (branch && offsets.ImmediateSize == 1)
            {
                shortBranches.Add(ip);
            }
            else if (!fixups.ContainsKey(field))
            {
                missing.Add(ip);
            }
        }

        var tableEntries = new HashSet<uint>();
        foreach (var table in image.Functions.SelectMany(f => f.JumpTables).DistinctBy(t => t.Rva))
        {
            for (int i = 0; i < table.EntryCount; i++)
            {
                uint entry = (uint)table.Rva + (uint)i * 4;
                tableEntries.Add(entry);
                references++;
                if (!fixups.ContainsKey(entry))
                {
                    missing.Add(entry);
                }
            }
        }

        // The other direction: fixups inside decoded instructions must sit on an operand field.
        starts.Sort();
        var startArray = starts.Select(s => s.Start).ToArray();
        var misplaced = new List<uint>();
        int inCode = 0;
        foreach (var fixup in fixups.Values.Where(f => image.FindSection(f.Rva) is { IsExecutable: true }))
        {
            int i = Array.BinarySearch(startArray, fixup.Rva);
            i = i >= 0 ? i : ~i - 1;
            bool inside = i >= 0 && fixup.Rva < starts[i].End;
            if (!inside)
            {
                if (!tableEntries.Contains(fixup.Rva))
                {
                    report.UndecodedCodeFixups++;
                }

                continue;
            }

            inCode++;
            if (!fields.Contains(fixup.Rva) && !ImmediateField(image, starts[i].Start, fixup))
            {
                misplaced.Add(fixup.Rva);
            }
        }

        var problems = new List<string>();
        if (missing.Count > 0)
        {
            problems.Add($"{missing.Count:N0} decoded references leave their contribution without a fixup ({Hex(missing)})");
        }

        if (shortBranches.Count > 0)
        {
            problems.Add($"{shortBranches.Count:N0} rel8 branches leave their contribution ({Hex(shortBranches)})");
        }

        if (misplaced.Count > 0)
        {
            problems.Add($"{misplaced.Count:N0} fixups inside decoded instructions are not on an operand field ({Hex(misplaced)})");
        }

        report.Checks.Add(new GateCheck("decoding agrees with the fixups", problems.Count == 0,
            problems.Count == 0
                ? $"{references:N0} references leaving their contribution, each with its fixup; {inCode:N0} fixups in decoded code, each on an operand; {report.UndecodedCodeFixups:N0} in undecoded code"
                : string.Join("; ", problems)));
    }

    /// <summary>An absolute fixup on an instruction's immediate (<c>mov r64, imm64</c>, or an imm32 of an image-relative value).</summary>
    private static bool ImmediateField(BinaryImage image, uint ip, LinkerFixup fixup)
    {
        var code = image.ReadFrom(ip);
        var decoder = Decoder.Create(64, new ByteArrayCodeReader(code[..Math.Min(code.Length, 15)].ToArray()));
        decoder.IP = ip;
        var x = decoder.Decode();
        var offsets = decoder.GetConstantOffsets(x);
        return (offsets.HasImmediate && ip + (uint)offsets.ImmediateOffset == fixup.Rva && offsets.ImmediateSize >= 4) ||
               (offsets.HasDisplacement && ip + (uint)offsets.DisplacementOffset == fixup.Rva && offsets.DisplacementSize >= 4);
    }

    /// <summary>
    /// Check 6: the exception structures that hold code RVAs are fixed up (.pdata fields and
    /// handler RVAs); functions with handler data WinBolt does not understand are counted, since
    /// they can move only as whole contributions.
    /// </summary>
    private static void Structures(BinaryImage image, Dictionary<uint, LinkerFixup> fixups, WholeProgramGateReport report)
    {
        var missing = new List<uint>();
        int fields = 0;
        if (image.DataDirectories.FirstOrDefault(d => d.Name == "Exception") is { } directory)
        {
            for (uint at = directory.Rva; at + 12 <= directory.Rva + directory.Size; at += 12)
            {
                foreach (uint field in new[] { at, at + 4, at + 8 })
                {
                    fields++;
                    if (!fixups.ContainsKey(field))
                    {
                        missing.Add(field);
                    }
                }
            }
        }

        foreach (var entry in image.ExceptionData.Where(e => e is { IsChained: false, HasHandler: true }))
        {
            fields++;
            if (!fixups.ContainsKey(entry.HandlerDataRva - 4))
            {
                missing.Add(entry.HandlerDataRva - 4);
            }
        }

        report.Checks.Add(new GateCheck("exception structures fixed up", missing.Count == 0,
            missing.Count == 0 ? $"{fields:N0} .pdata and handler fields, each with its fixup" : $"{missing.Count:N0} of {fields:N0} fields without a fixup ({Hex(missing)})"));
    }

    private static SectionContribution? Owner(SectionContribution[] contributions, uint rva)
    {
        int lo = 0, hi = contributions.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (contributions[mid].Rva <= rva)
            {
                found = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return found >= 0 && rva < contributions[found].Rva + contributions[found].Size ? contributions[found] : null;
    }

    private static string Hex(IEnumerable<uint> values)
    {
        var list = values.Take(Examples + 1).ToList();
        return "e.g. " + string.Join(", ", list.Take(Examples).Select(v => $"0x{v:X}")) + (list.Count > Examples ? ", ..." : string.Empty);
    }
}
