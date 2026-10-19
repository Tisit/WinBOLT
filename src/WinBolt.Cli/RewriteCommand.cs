using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;
using WinBolt.Rewrite;

/// <summary>
/// <c>winbolt rewrite &lt;in&gt; &lt;out&gt;</c>: without a profile, a verified no-op rewrite; with <c>--profile</c>,
/// C3 function layout, optionally with rebuilt functions, block layout, JCC padding and pointer
/// redirection; with <c>--whole-program</c>, an in-place rewrite from linker fixups. The output
/// is written only if every verification check passes (DesignDoc Stage 4).
/// </summary>
internal static class RewriteCommand
{
    public static int Run(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: winbolt rewrite <input-pe> <output-pe> [--pdb <file>] [--symbols <dir>]... [--profile <etl> [--profile-binary <exe>] [--process <name>] [--order c3|first-use] [--page-model] [--profile-during <function>] [--ip-only [--ip-estimator max|mean]] [--blocks [--no-split] [--block-order chains|ext-tsp]]] [--rebuild] [--jcc-erratum] [--align-loops] [--redirect-pointers] [--promote-calls] [--layout-eh] [--layout-shift N] [--no-pdb] | [--whole-program]");
            Console.WriteLine("  Copies eligible functions into an appended section and redirects their entries.");
            Console.WriteLine("  Without a profile: every eligible function in original order (a verified no-op rewrite).");
            Console.WriteLine("  With a profile: only the hot functions, in C3 call-chain order (Stage 5 layout).");
            Console.WriteLine("  --profile-binary: the trace was recorded on this other build of the program (a stale profile): it is applied");
            Console.WriteLine("                there and carried over to the input by matching functions (PDB names, else content) and blocks (content).");
            Console.WriteLine("  --order: function order, c3 (default: call chains by heat) or first-use (every executed function in the order");
            Console.WriteLine("                it first ran: startup code together, fewer pages touched early).");
            Console.WriteLine("  --page-model: replay the trace's first run through the original and the new layout and print the code pages touched.");
            Console.WriteLine("  --profile-during: keep only samples between the first and last execution of this function (decorated name).");
            Console.WriteLine("  --ip-only: build the profile from sampled instruction pointers alone (no branch records; an estimate).");
            Console.WriteLine("  --ip-estimator: how --ip-only turns samples into block counts: max (default) or mean.");
            Console.WriteLine("  --no-pdb: do not write <output>.pdb (the image then still names the original PDB).");
            Console.WriteLine("  --rebuild: re-encode each function from its CFG instead of copying bytes.");
            Console.WriteLine("  --blocks: also reorder each hot function's blocks by the profile and split never-executed blocks");
            Console.WriteLine("            into a cold area (Stage 6; implies --rebuild). --no-split keeps cold blocks in the function.");
            Console.WriteLine("            --block-order: chains (default, greedy Pettis-Hansen) or ext-tsp (BOLT's; slower on speedtest1).");
            Console.WriteLine("  --jcc-erratum: keep executed branches off 32-byte boundaries (Intel's JCC erratum): rebuilt functions are padded,");
            Console.WriteLine("                copies are placed where the fewest executed branches sit on a boundary.");
            Console.WriteLine("  --align-loops: start hot loop heads on a 32-byte boundary (implies --rebuild).");
            Console.WriteLine("  --redirect-pointers: aim pointers to moved functions (vtables, function pointer tables, lea) at the copies,");
            Console.WriteLine("                for every function whose every pointer is provably known (one value); indirect calls skip the trampoline.");
            Console.WriteLine("  --promote-calls: indirect calls with one profiled target (>= 90% of their calls) become a compare and a direct");
            Console.WriteLine("                call, the indirect call kept for other targets (rebuilt functions without EH tables; needs --profile).");
            Console.WriteLine("  --layout-eh: also reorder blocks of plain unwind-only __CxxFrameHandler4 functions, regenerating their IP-to-state map.");
            Console.WriteLine("  --whole-program: rewrite in place (DesignDoc 6.2): every function moves as a unit into C3 order (original order");
            Console.WriteLine("                without a profile), references re-resolved from the linker's fixups. Needs a PDB with fixup records");
            Console.WriteLine("                (/DEBUGTYPE:CV,FIXUP) that passes the whole-program gate; no trampolines, no size growth.");
            Console.WriteLine("  --layout-shift N: start the laid-out code N bytes later (a multiple of 64): the same layout at another");
            Console.WriteLine("                cache/page alignment, to tell a real difference from layout luck (bench groups: name=a.exe,b.exe).");
            Console.WriteLine("  The output is written only if verification passes.");
            return 1;
        }

        string input = Path.GetFullPath(args[0]), output = Path.GetFullPath(args[1]);
        string? pdbPath = null, profilePath = null, processName = null, profileDuring = null, profileBinary = null;
        bool ipOnly = false;
        var ipEstimator = WinBolt.Core.Profile.IpEstimator.Max;
        var mode = RewriteMode.Copy;
        bool blocks = false, split = true, jccErratum = false, alignLoops = false, redirectPointers = false, layoutEh = false, wholeProgram = false, noPdb = false, promoteCalls = false, firstUse = false, pageModel = false;
        uint layoutShift = 0;
        var blockAlgorithm = BlockLayoutAlgorithm.Chains;
        var symbols = new List<string>();
        for (int i = 2; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--pdb" when i + 1 < args.Length:
                    pdbPath = args[++i];
                    break;
                case "--symbols" when i + 1 < args.Length:
                    symbols.Add(args[++i]);
                    break;
                case "--profile" when i + 1 < args.Length:
                    profilePath = args[++i];
                    break;
                case "--profile-binary" when i + 1 < args.Length:
                    profileBinary = Path.GetFullPath(args[++i]);
                    break;
                case "--process" when i + 1 < args.Length:
                    processName = args[++i];
                    break;
                case "--ip-only":
                    ipOnly = true;
                    break;
                case "--ip-estimator" when i + 1 < args.Length && args[i + 1] is "mean" or "max":
                    ipEstimator = args[++i] == "max" ? WinBolt.Core.Profile.IpEstimator.Max : WinBolt.Core.Profile.IpEstimator.Mean;
                    break;
                case "--profile-during" when i + 1 < args.Length:
                    profileDuring = args[++i];
                    break;
                case "--rebuild":
                    mode = RewriteMode.Rebuild;
                    break;
                case "--blocks":
                    blocks = true;
                    mode = RewriteMode.Rebuild;
                    break;
                case "--jcc-erratum":
                    jccErratum = true;
                    break;
                case "--align-loops":
                    alignLoops = true;
                    mode = RewriteMode.Rebuild;
                    break;
                case "--no-split":
                    split = false;
                    break;
                case "--redirect-pointers":
                    redirectPointers = true;
                    break;
                case "--layout-shift" when i + 1 < args.Length && uint.TryParse(args[i + 1], out uint shift) && shift % FunctionRewriter.LayoutShiftUnit == 0:
                    layoutShift = shift;
                    i++;
                    break;
                case "--order" when i + 1 < args.Length && args[i + 1] is "c3" or "first-use":
                    firstUse = args[++i] == "first-use";
                    break;
                case "--page-model":
                    pageModel = true;
                    break;
                case "--promote-calls":
                    promoteCalls = true;
                    mode = RewriteMode.Rebuild;
                    break;
                case "--layout-eh":
                    layoutEh = true;
                    break;
                case "--whole-program":
                    wholeProgram = true;
                    break;
                case "--no-pdb":
                    noPdb = true;
                    break;
                case "--block-order" when i + 1 < args.Length && args[i + 1] is "ext-tsp" or "chains":
                    blockAlgorithm = args[++i] == "chains" ? BlockLayoutAlgorithm.Chains : BlockLayoutAlgorithm.ExtTsp;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown or incomplete option: {args[i]}");
                    return 1;
            }
        }

        if (wholeProgram && (redirectPointers || layoutEh || (mode == RewriteMode.Rebuild && !blocks && !alignLoops)))
        {
            Console.Error.WriteLine("--whole-program has one address per function (no --redirect-pointers needed); --layout-eh and plain --rebuild are not available with it yet.");
            return 1;
        }

        if (profileBinary is not null && (profilePath is null || firstUse || pageModel))
        {
            Console.Error.WriteLine("--profile-binary needs --profile, and does not combine with --order first-use or --page-model (they replay the trace on the input).");
            return 1;
        }

        if ((firstUse || pageModel) && profilePath is null)
        {
            Console.Error.WriteLine("--order first-use and --page-model need --profile.");
            return 1;
        }

        if (promoteCalls && (profilePath is null || wholeProgram))
        {
            Console.Error.WriteLine("--promote-calls needs --profile (the targets come from it) and append mode.");
            return 1;
        }

        if (blocks && profilePath is null)
        {
            Console.Error.WriteLine("--blocks needs --profile: block layout follows the profiled edge counts.");
            return 1;
        }

        if (string.Equals(input, output, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("The output must not overwrite the input.");
            return 1;
        }

        byte[] file = File.ReadAllBytes(input);
        var image = PeImageReader.Read(input, file);
        var pdb = PdbSymbolLoader.Load(image, pdbPath, symbols);
        CliCommon.Analyze(image);

        List<OrderedFunction>? order = null;
        if (profilePath is not null)
        {
            if (profileBinary is not null)
            {
                var profiled = PeImageReader.Read(profileBinary, File.ReadAllBytes(profileBinary));
                PdbSymbolLoader.Load(profiled, null, symbols);
                CliCommon.Analyze(profiled);
                if (!CliCommon.TryApplyProfile(profiled, profilePath, processName ?? (input.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? Path.GetFileName(profileBinary) : null),
                        profileDuring, ipOnly, ipEstimator))
                {
                    return 2;
                }

                var transfer = WinBolt.Core.Profile.StaleProfile.Transfer(profiled, image);
                Console.Error.WriteLine($"Stale profile: {transfer.FunctionsMatched:N0} of {transfer.FunctionsProfiled:N0} executed functions matched, " +
                                        $"{transfer.WeightTransferred:P1} of executed instructions, {transfer.EdgesTransferred:P1} of edge executions carried over");
            }
            else if (!CliCommon.TryApplyProfile(image, profilePath, processName, profileDuring, ipOnly, ipEstimator))
            {
                return 2;
            }

            order = firstUse ? FunctionOrdering.FirstUse(image, EtwLbrProfile.FirstTouch(image, profilePath, processName)) : FunctionOrdering.C3(image);
        }

        if (wholeProgram)
        {
            return WholeProgram(image, file, input, output, order, pdb, jccErratum, blocks ? f => BlockLayout.Order(f, split, blockAlgorithm) : null, alignLoops, layoutShift);
        }

        RewriteResult result;
        try
        {
            result = FunctionRewriter.Rewrite(image, file, order?.Select(o => o.Function.EntryRva).ToList(), mode,
                blocks ? f => BlockLayout.Order(f, split, blockAlgorithm) : null, jccErratum, alignLoops, redirectPointers, layoutEh, layoutShift,
                promoteCalls ? CallPromotion.Plan(image) : null);
        }
        catch (RewriteRefusedException ex)
        {
            Console.Error.WriteLine($"Rewrite refused: {ex.Message}");
            return 2;
        }

        Console.WriteLine($"WinBolt rewrite ({(order is null ? "Stage 4, no-op" : firstUse ? "Stage 5, first-use function order" : "Stage 5, C3 function layout")}{(mode == RewriteMode.Rebuild ? ", functions rebuilt from their CFG" : "")}" +
                          $"{(blocks ? $", Stage 6 block layout ({blockAlgorithm}){(split ? " with hot/cold splitting" : "")}" : "")}{(jccErratum ? ", JCC erratum padding" : "")}{(alignLoops ? ", hot loops aligned" : "")}): {input}");
        Console.WriteLine($"  PDB: {(image.Pdb is { } info ? info.Path : $"none ({pdb.Message})")}");
        if (order is not null)
        {
            var moved = result.Moved.Select(m => m.Start).ToHashSet();
            ulong total = order.Aggregate(0UL, (sum, o) => sum + o.Weight);
            ulong placed = order.Where(o => moved.Contains(o.Function.EntryRva)).Aggregate(0UL, (sum, o) => sum + o.Weight);
            Console.WriteLine($"  Profile: {image.ProfileSummary!.Binding}");
            Console.WriteLine($"  Layout: {order.Count:N0} executed functions in {order.Select(o => o.Cluster).Distinct().Count():N0} clusters; " +
                              $"{result.Moved.Count:N0} placed, carrying {(total == 0 ? 0 : 100.0 * placed / total):F1}% of executed instructions");

            var reasons = result.Skipped.ToDictionary(x => x.Function.Id, x => x.Reason);
            foreach (var o in order.Where(o => !moved.Contains(o.Function.EntryRva)).OrderByDescending(o => o.Weight).Take(5))
            {
                Console.WriteLine($"    not placed: {o.Function.DisplayName,-32} {100.0 * o.Weight / total,5:F1}% of executed instructions  ({reasons.GetValueOrDefault(o.Function.Id, "?")}" +
                                  $"{(o.Function.DowngradeReasons.Count > 0 ? ": " + string.Join(", ", o.Function.DowngradeReasons) : "")})");
            }

            if (blocks)
            {
                var rebuilt = result.Moved.Where(m => m.AddressMap is not null).ToList();
                Console.WriteLine($"  Blocks: {rebuilt.Count - result.KeptBlockOrder.Count(k => rebuilt.Any(m => m.FunctionId == k.Function.Id)):N0} functions laid out, " +
                                  $"{rebuilt.Count(m => m.ColdLength > 0):N0} split; hot code {rebuilt.Sum(m => (long)m.CopyLength):N0} bytes, cold {rebuilt.Sum(m => (long)m.ColdLength):N0} bytes");
                var transfers = LayoutStatistics.Measure(image, result);
                if (transfers.Transfers > 0)
                {
                    Console.WriteLine($"    profiled block transfers that fall through (no taken branch): {transfers.FallThroughBefore / transfers.Transfers:P1} before, " +
                                      $"{transfers.FallThroughAfter / transfers.Transfers:P1} after");
                }

                foreach (var group in result.KeptBlockOrder.GroupBy(k => Category(k.Reason)).OrderByDescending(g => g.Count()))
                {
                    Console.WriteLine($"    original block order kept: {group.Key,-50} {group.Count(),6:N0} functions");
                }
            }

            var (branches, onBoundaryBefore, onBoundaryAfter, executed, padding) = LayoutStatistics.JccErratum(image, result);
            if (branches > 0)
            {
                Console.WriteLine($"  Executed branches of moved functions crossing or ending on a 32-byte boundary (JCC erratum, not DSB-cached): " +
                                  $"{onBoundaryBefore / branches:P1} before, {onBoundaryAfter / branches:P1} after" +
                                  (padding > 0 ? $"; padding NOPs are {padding / executed:P2} of executed instructions" : ""));
            }

            // Hot footprint at the new addresses, against the original layout and the packed-range bound.
            var copies = result.Moved.ToDictionary(m => m.FunctionId);
            ulong Placement(WinBolt.Core.Ir.Function f, WinBolt.Core.Ir.BasicBlock b) =>
                copies.TryGetValue(f.Id, out var m) ? m.Place((uint)b.StartRva) : b.StartRva;
            var before = WinBolt.Core.Profile.CodeFootprint.Compute(image, 0.9, 0.99);
            var after = WinBolt.Core.Profile.CodeFootprint.Compute(image, Placement, 0.9, 0.99);
            foreach (var (b, a) in before.Zip(after))
            {
                Console.WriteLine($"  Hot footprint at {b.Coverage:P0}: {b.PagesNow:N0} pages / {b.LinesNow:N0} lines before, " +
                                  $"{a.PagesNow:N0} / {a.LinesNow:N0} after (packed-range bound {b.PagesPackedRanges:N0} / {b.LinesPackedRanges:N0})");
            }
        }

        long movedBytes = result.Moved.Sum(m => (long)m.Length);
        long allBytes = image.Functions.Sum(f => (long)f.TotalLength);
        Console.WriteLine($"  Moved {result.Moved.Count:N0} of {image.Functions.Count:N0} functions, {movedBytes:N0} of {allBytes:N0} bytes " +
                          $"({(allBytes == 0 ? 0 : 100.0 * movedBytes / allBytes):F1}%), into .wbtext at 0x{result.TextRva:X}");
        Console.WriteLine($"  Fields fixed: {result.Patched.Count(p => p.Kind == FieldKind.Branch):N0} branches, {result.Patched.Count(p => p.Kind == FieldKind.RipRelative):N0} RIP-relative operands, " +
                          $"{result.Patched.Count(p => p.Kind == FieldKind.TableAddress):N0} table addresses; {result.Moved.Sum(m => m.Tables.Count):N0} jump tables rebuilt; " +
                          $"{result.NewRelocations.Count:N0} new base relocations");
        if (result.Redirection is { } plan)
        {
            if (plan.Refused is not null)
            {
                Console.WriteLine($"  Pointer redirection refused: {plan.Refused}");
            }
            else
            {
                Console.WriteLine($"  Pointers redirected to copies: {plan.Targets.Count:N0} functions, {result.Redirected.Count(r => !r.IsLea):N0} relocated values and " +
                                  $"{result.Redirected.Count(r => r.IsLea):N0} lea sites changed; {plan.Excluded.Count:N0} pointed-to moved functions left alone:");
                foreach (var group in plan.Excluded.GroupBy(e => e.Value).OrderByDescending(g => g.Count()))
                {
                    Console.WriteLine($"    {group.Key,-50} {group.Count(),6:N0} functions");
                }

                if (result.Moved.Count(m => !m.HasTrampoline) is var noTrampoline and > 0)
                {
                    Console.WriteLine($"    moved without a trampoline (entry too short or a branch target; every pointer redirected): {noTrampoline:N0} functions");
                }

                if (image.ProfileSummary is { } summary)
                {
                    long calls = summary.IndirectTargets.Values.Sum(t => t.Values.Sum());
                    long direct = summary.IndirectTargets.Values.Sum(t => t.Where(kv => plan.Targets.ContainsKey(kv.Key)).Sum(kv => kv.Value));
                    Console.WriteLine($"    profiled indirect calls that now skip the trampoline: {(calls == 0 ? 0 : 100.0 * direct / calls):F1}%");
                }
            }
        }

        if (pageModel)
        {
            double[] fractions = [0.01, 0.1, 0.25, 0.5];
            var touches = EtwLbrProfile.FirstTouches(image, profilePath!, processName);
            var (before, beforeTotal) = PageModel.Curve(image, null, touches, fractions);
            var (after, afterTotal) = PageModel.Curve(image, result, touches, fractions);
            Console.WriteLine($"  Page model (code pages the first run touches, by share of its duration; {touches.Count:N0} distinct touches):");
            Console.WriteLine($"    {"",-10} {string.Join(" ", fractions.Select(f => $"{f,8:P0}"))} {"all",8}");
            Console.WriteLine($"    {"original",-10} {string.Join(" ", before.Select(c => $"{c,8:N0}"))} {beforeTotal,8:N0}");
            Console.WriteLine($"    {"rewritten",-10} {string.Join(" ", after.Select(c => $"{c,8:N0}"))} {afterTotal,8:N0}");
        }

        if (promoteCalls)
        {
            var promotion = CallPromotion.Plan(image);
            var done = result.Moved.SelectMany(m => m.PromotedCalls.Keys).ToHashSet();
            var summary = image.ProfileSummary!;
            long calls = summary.IndirectTargets.Values.Sum(t => t.Values.Sum());
            long promoted = summary.IndirectTargets.Where(kv => done.Contains(kv.Key)).Sum(kv => kv.Value.GetValueOrDefault(promotion[kv.Key]));
            Console.WriteLine($"  Call promotion: {done.Count:N0} of {promotion.Count:N0} planned sites promoted, " +
                              $"{(calls == 0 ? 0 : 100.0 * promoted / calls):F1}% of profiled indirect calls now direct");
        }

        foreach (var (table, added) in result.GuardTablesExtended)
        {
            Console.WriteLine($"  {table}: rewritten in .wbdata with {added:N0} moved targets");
        }

        Console.WriteLine("  Not moved:");
        foreach (var group in result.Skipped.GroupBy(s => Category(s.Reason)).OrderByDescending(g => g.Sum(s => (long)s.Function.TotalLength)))
        {
            Console.WriteLine($"    {group.Key,-50} {group.Count(),6:N0} functions, {group.Sum(s => (long)s.Function.TotalLength),10:N0} bytes");
        }

        var report = RewriteVerifier.Verify(image, file, result);
        Console.WriteLine();
        Console.WriteLine($"  Verification: {report.InstructionsCompared:N0} instructions compared, {report.FieldsChecked:N0} fixed fields checked, " +
                          (report.OracleAvailable ? $"{report.FixupsChecked:N0} linker fixups checked" : "no fixup oracle") +
                          $", {report.CopiesRediscovered:N0} copies found by re-analysis");
        foreach (string warning in result.Warnings.Concat(report.Warnings))
        {
            Console.WriteLine($"    warning: {warning}");
        }

        if (!report.Passed)
        {
            foreach (string failure in report.Failures)
            {
                Console.WriteLine($"    FAILED: {failure}");
            }

            Console.WriteLine("  Verification failed: nothing was written.");
            return 3;
        }

        // The original PDB, with OMAP: symbols keep their addresses and the OMAP translates (AppendPdb).
        string? pdbOutput = null;
        if (!noPdb && image.Pdb is { } sourcePdb)
        {
            pdbOutput = Path.ChangeExtension(output, ".pdb");
            if (SamePath(pdbOutput, sourcePdb.Path))
            {
                Console.Error.WriteLine($"The output PDB {pdbOutput} would overwrite the input's PDB; choose another output name or pass --no-pdb.");
                return 1;
            }

            var (guid, age) = AppendPdb.Retire(image, result, pdbOutput);
            File.WriteAllBytes(pdbOutput, AppendPdb.Write(image, result, File.ReadAllBytes(sourcePdb.Path), guid, age));

            var (loaded, expected, wrong) = CheckOutputPdb(image, output, result.Output, pdbOutput, rva => AppendPdb.NewAddress(result, rva));
            Console.WriteLine($"  PDB: {pdbOutput}: {expected - wrong.Count:N0} of {expected:N0} function symbols resolve to their copy or their original address");
            if (!loaded.Loaded || wrong.Count > 0)
            {
                return FailPdb(pdbOutput, loaded, wrong);
            }
        }
        else if (image.Pdb is not null)
        {
            Console.WriteLine("    note: --no-pdb: the image still names the original PDB, which does not describe the copies");
        }

        File.WriteAllBytes(output, result.Output);
        Console.WriteLine($"  Verification passed. Wrote {output} ({result.Output.Length:N0} bytes, was {file.Length:N0}){(pdbOutput is null ? "" : $" and {Path.GetFileName(pdbOutput)}")}.");
        return 0;
    }

    private static int WholeProgram(BinaryImage image, byte[] file, string input, string output, List<OrderedFunction>? order, PdbLoadResult pdb, bool jccErratum,
        Func<Function, BlockOrder?>? blockOrder, bool alignLoops, uint layoutShift)
    {
        // The C3 order's functions, as the code contributions holding their entries.
        var code = image.SectionContributions.Where(c => image.FindSection(c.Rva) is { IsExecutable: true }).OrderBy(c => c.Rva).ToArray();
        var starts = code.Select(c => c.Rva).ToArray();
        SectionContribution? Owner(uint rva)
        {
            int i = Array.BinarySearch(starts, rva);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && rva < code[i].Rva + code[i].Size ? code[i] : null;
        }

        var contributions = order?.Select(o => Owner(o.Function.EntryRva)).OfType<SectionContribution>().Distinct().ToList();

        Console.WriteLine($"WinBolt rewrite (whole program, DesignDoc 6.2 W2: {(order is null ? "original order, a no-op" : "C3 function order")}{(blockOrder is not null ? ", block layout (W3)" : "")}{(jccErratum ? ", JCC erratum placement" : "")}{(alignLoops ? ", hot loops aligned" : "")}): {input}");
        Console.WriteLine($"  PDB: {(image.Pdb is { } info ? info.Path : $"none ({pdb.Message})")}");
        WholeProgramResult result;
        try
        {
            result = WholeProgramRewriter.Rewrite(image, file, contributions, jccErratum, blockOrder, alignLoops,
                image.Pdb is not null ? Path.ChangeExtension(output, ".pdb") : null, layoutShift);
        }
        catch (RewriteRefusedException ex)
        {
            Console.Error.WriteLine($"Rewrite refused: {ex.Message}");
            return 2;
        }

        if (order is not null)
        {
            Console.WriteLine($"  Profile: {image.ProfileSummary!.Binding}");
            Console.WriteLine($"  Layout: {order.Count:N0} executed functions in {order.Select(o => o.Cluster).Distinct().Count():N0} clusters, " +
                              $"{contributions!.Count:N0} contributions placed first");
        }

        Console.WriteLine($"  Gate: passed ({result.Gate.Checks.Count} checks)");
        Console.WriteLine($"  Moved {result.Placed.Count(p => p.Delta != 0):N0} of {result.Placed.Count:N0} code contributions; " +
                          $"{result.FixupsRewritten:N0} fixup fields rewritten, {result.RelocationsMoved:N0} relocations moved, " +
                          $"{result.ExportsMapped:N0} exports and {result.CfgEntriesMapped:N0} CFG table entries mapped");

        if (blockOrder is not null)
        {
            var rebuilt = result.Rebuilt.Values.ToList();
            Console.WriteLine($"  Blocks: {rebuilt.Count:N0} functions rebuilt, {rebuilt.Count(r => r.ColdLength > 0):N0} split; hot code {rebuilt.Sum(r => (long)r.HotLength):N0} bytes, " +
                              $"cold {rebuilt.Sum(r => (long)r.ColdLength):N0} bytes");
            if (order is not null)
            {
                var weight = order.ToDictionary(o => o.Function.Id, o => o.Weight);
                ulong total = order.Aggregate(0UL, (sum, o) => sum + o.Weight);
                ulong covered = rebuilt.Aggregate(0UL, (sum, r) => sum + weight.GetValueOrDefault(r.Function.Id));
                Console.WriteLine($"    rebuilt functions carry {(total == 0 ? 0 : 100.0 * covered / total):F1}% of executed instructions; the rest move as whole contributions:");
                foreach (var group in result.NotRebuilt.GroupBy(n => Category(n.Reason)).OrderByDescending(g => g.Sum(n => (double)weight.GetValueOrDefault(n.Function.Id))))
                {
                    double share = total == 0 ? 0 : 100.0 * group.Sum(n => (double)weight.GetValueOrDefault(n.Function.Id)) / total;
                    Console.WriteLine($"      {group.Key,-70} {group.Count(),5:N0} functions, {share,5:F1}% of executed instructions");
                }
            }
        }

        var report = WholeProgramVerifier.Verify(image, file, result);
        Console.WriteLine();
        Console.WriteLine($"  Verification: {report.FixupsChecked:N0} fixups checked, {report.BytesCompared:N0} code bytes compared, " +
                          $"{report.InstructionsCompared:N0} rebuilt instructions checked, {report.FunctionsFound:N0} functions found by re-analysis");
        foreach (string warning in result.Warnings.Concat(report.Warnings))
        {
            Console.WriteLine($"    warning: {warning}");
        }

        if (!report.Passed)
        {
            foreach (string failure in report.Failures)
            {
                Console.WriteLine($"    FAILED: {failure}");
            }

            Console.WriteLine("  Verification failed: nothing was written.");
            return 3;
        }

        // W4: the PDB with OMAP, checked by loading it for the output like any image's PDB.
        string? pdbOutput = null;
        if (image.Pdb is { } source && result.PdbGuid is { } guid)
        {
            pdbOutput = Path.ChangeExtension(output, ".pdb");
            if (SamePath(pdbOutput, source.Path))
            {
                Console.Error.WriteLine($"The output PDB {pdbOutput} would overwrite the input's PDB; choose another output name.");
                return 1;
            }

            var (toSource, fromSource) = WholeProgramOmap.Build(image, result);
            byte[] headers = WholeProgramOmap.SectionHeaders(result.Output);
            byte[] pdbBytes = PdbWriter.WithOmap(File.ReadAllBytes(source.Path), guid, result.PdbAge,
                toSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(), fromSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(), headers);
            File.WriteAllBytes(pdbOutput, pdbBytes);

            var (loaded, expected, wrong) = CheckOutputPdb(image, output, result.Output, pdbOutput, result.MapSite);
            Console.WriteLine($"  PDB: {pdbOutput}: {toSource.Count:N0} OMAP_TO_SRC and {fromSource.Count:N0} OMAP_FROM_SRC records; " +
                              $"{expected - wrong.Count:N0} of {expected:N0} function symbols resolve to their new address");
            if (!loaded.Loaded || wrong.Count > 0)
            {
                return FailPdb(pdbOutput, loaded, wrong);
            }
        }

        File.WriteAllBytes(output, result.Output);
        Console.WriteLine($"  Verification passed. Wrote {output} ({result.Output.Length:N0} bytes, was {file.Length:N0}){(pdbOutput is null ? "" : $" and {Path.GetFileName(pdbOutput)}")}.");
        return 0;
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Loads the output PDB for the output image like any image's PDB, and lists the uniquely named
    /// function symbols of the input that do not resolve to <paramref name="newAddress"/> of their address.
    /// </summary>
    private static (PdbLoadResult Loaded, int Expected, List<Symbol> Wrong) CheckOutputPdb(BinaryImage image, string output, byte[] outputImage,
        string pdbOutput, Func<uint, uint> newAddress)
    {
        var check = PeImageReader.Read(output, outputImage);
        var loaded = PdbSymbolLoader.Load(check, pdbOutput);
        var expected = image.Symbols.Where(s => s.IsFunction).GroupBy(s => s.Name).Where(g => g.Count() == 1).Select(g => g.Single()).ToList();
        var actual = check.Symbols.Where(s => s.IsFunction).GroupBy(s => s.Name).ToDictionary(g => g.Key, g => g.First().Rva);
        var wrong = expected.Where(s => !actual.TryGetValue(s.Name, out uint rva) || rva != newAddress(s.Rva)).ToList();
        return (loaded, expected.Count, wrong);
    }

    private static int FailPdb(string pdbOutput, PdbLoadResult loaded, List<Symbol> wrong)
    {
        File.Delete(pdbOutput);
        Console.WriteLine($"    FAILED: {(loaded.Loaded ? $"{wrong.Count} symbols misplaced, e.g. {wrong[0].Name}" : loaded.Message)}");
        Console.WriteLine("  Verification failed: nothing was written.");
        return 3;
    }

    /// <summary>Groups skip reasons by their stable prefix (addresses stripped).</summary>
    private static string Category(string reason)
    {
        int at = reason.IndexOf(" at 0x", StringComparison.Ordinal);
        return at >= 0 ? reason[..at] : reason;
    }
}
