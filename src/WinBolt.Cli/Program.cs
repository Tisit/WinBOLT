using WinBolt.Core.Analysis;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;

if (args.Length > 0 && args[0] == "rewrite")
{
    return RewriteCommand.Run(args[1..]);
}

if (args.Length > 0 && args[0] == "residency")
{
    return ResidencyCommand.Run(args[1..]);
}

if (args.Length > 0 && args[0] == "bench")
{
    return BenchCommand.Run(args[1..]);
}

if (args.Length < 2 || args[0] != "analyze")
{
    Console.WriteLine("Usage: winbolt rewrite <input-pe> <output-pe> [--pdb <file>] [--symbols <dir>]... [--profile <etl>]   (run without arguments for details)");
    Console.WriteLine("Usage: winbolt residency <input-pe> <rewritten-pe> --profile <etl of the rewritten image> [--process <name>]   (run without arguments for details)");
    Console.WriteLine("Usage: winbolt bench <baseline-exe> <candidate-exe>... [--rounds N] -- <program arguments>");
    Console.WriteLine("Usage: winbolt analyze <path-to-pe> [--pdb <file>] [--symbols <dir>]... [--profile <etl> [--process <name>] [--profile-during <function>]] [--html <file>]");
    Console.WriteLine("  --pdb      a specific PDB to use (must match the image's GUID and age)");
    Console.WriteLine("  --symbols  a directory to search, flat or symbol-store layout; repeatable.");
    Console.WriteLine("             Local directories in _NT_SYMBOL_PATH are searched too. Nothing is downloaded.");
    Console.WriteLine("  --profile  an ETW trace with LBR stacks (tools/profile/Capture-Lbr.ps1) to apply");
    Console.WriteLine("  --process  the process to take the profile from (default: the image itself when it is an .exe)");
    Console.WriteLine("  --profile-during  keep only samples between the first and last execution of this function (decorated name),");
    Console.WriteLine("             e.g. a per-frame update, to leave out loading and shutdown");
    Console.WriteLine("  --html     also write a self-contained HTML report (with a profile: heat map and hot paths)");
    return 1;
}

string path = args[1];
string? pdbPath = null;
string? profilePath = null;
string? processName = null;
string? profileDuring = null;
bool ipOnly = false;
var ipEstimator = WinBolt.Core.Profile.IpEstimator.Max;
string? htmlPath = null;
var symbolDirectories = new List<string>();
for (int i = 2; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--pdb" when i + 1 < args.Length:
            pdbPath = args[++i];
            break;
        case "--symbols" when i + 1 < args.Length:
            symbolDirectories.Add(args[++i]);
            break;
        case "--profile" when i + 1 < args.Length:
            profilePath = args[++i];
            break;
        case "--process" when i + 1 < args.Length:
            processName = args[++i];
            break;
        case "--profile-during" when i + 1 < args.Length:
            profileDuring = args[++i];
            break;
        case "--ip-only":
            ipOnly = true;
            break;
        case "--ip-estimator" when i + 1 < args.Length && args[i + 1] is "mean" or "max":
            ipEstimator = args[++i] == "max" ? WinBolt.Core.Profile.IpEstimator.Max : WinBolt.Core.Profile.IpEstimator.Mean;
            break;
        case "--html" when i + 1 < args.Length:
            htmlPath = args[++i];
            break;
        default:
            Console.Error.WriteLine($"Unknown or incomplete option: {args[i]}");
            return 1;
    }
}

if (!File.Exists(path))
{
    Console.Error.WriteLine($"File not found: {path}");
    return 1;
}

try
{
    var image = PeImageReader.Read(path);
    var pdb = PdbSymbolLoader.Load(image, pdbPath, symbolDirectories);
    var context = CliCommon.Analyze(image);

    if (profilePath is not null)
    {
        if (!CliCommon.TryApplyProfile(image, profilePath, processName, profileDuring, ipOnly, ipEstimator))
        {
            return 1;
        }
    }

    PrintReport(image, pdb);
    var reports = new List<WinBolt.Core.Passes.Report>();
    foreach (var provider in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateReportProviders())
    {
        if (!provider.AppliesTo(image))
        {
            continue;
        }

        var report = provider.Generate(image, context);
        reports.Add(report);
        Console.WriteLine();
        Console.WriteLine($"  {report.Title} (confidence: {report.Confidence})");
        foreach (string line in report.Body.TrimEnd().Split('\n'))
        {
            Console.WriteLine($"    {line.TrimEnd('\r')}");
        }
    }

    var gate = WinBolt.Rewrite.WholeProgramGate.Check(image);
    Console.WriteLine();
    Console.WriteLine($"  Whole-program rewrite gate (§6.2): {(gate.Passed ? "passed" : "refused; the default append mode still applies")}");
    foreach (var check in gate.Checks)
    {
        Console.WriteLine($"    [{(check.Passed ? "ok" : "FAIL")}] {check.Name}: {check.Detail}");
    }

    if (gate.Checks.Count > 1 && gate.OpaqueHandlerFunctions > 0)
    {
        Console.WriteLine($"    {gate.OpaqueHandlerFunctions:N0} functions have handler data WinBolt does not understand: they would move only as whole contributions");
    }

    if (htmlPath is not null)
    {
        HtmlReport.Write(htmlPath, image, reports);
        Console.WriteLine();
        Console.WriteLine($"  HTML report: {Path.GetFullPath(htmlPath)}");
    }

    return 0;
}
catch (PeFormatException ex)
{
    Console.Error.WriteLine($"Not a supported PE image: {ex.Message}");
    return 1;
}

static void PrintReport(BinaryImage image, PdbLoadResult pdb)
{
    Console.WriteLine($"WinBolt analysis: {image.FilePath}");
    Console.WriteLine();
    if (image.Pdb is { } info)
    {
        string omap = info.HasOmap
            ? $", addresses translated through OMAP (post-link rewritten); {info.DroppedSymbols:N0} symbols have no counterpart in the image"
            : string.Empty;
        Console.WriteLine($"  PDB: {info.Path}");
        Console.WriteLine($"       {info.PublicSymbols:N0} public symbols{omap}");
    }
    else
    {
        Console.WriteLine($"  PDB: none ({pdb.Message})");
    }

    Console.WriteLine();
    Console.WriteLine($"  ImageBase        0x{image.ImageBase:X}");
    Console.WriteLine($"  SizeOfImage      0x{image.SizeOfImage:X} ({image.SizeOfImage:N0} bytes)");
    Console.WriteLine($"  TimeDateStamp    0x{image.TimeDateStamp:X}");
    Console.WriteLine($"  Checksum         0x{image.Checksum:X}");
    Console.WriteLine();

    Console.WriteLine($"  Sections ({image.Sections.Count})");
    foreach (var section in image.Sections)
    {
        string exec = section.IsExecutable ? "  [X]" : string.Empty;
        Console.WriteLine(
            $"    {section.Name,-10} rva=0x{section.Rva:X8} vsize=0x{section.VirtualSize:X8} raw=0x{section.RawSize:X8}{exec}");
    }

    Console.WriteLine();

    int chainedCount = image.ExceptionData.Count(e => e.IsChained);
    Console.WriteLine($"  Exception directory (.pdata): {image.ExceptionData.Count} entries, {chainedCount} chained (§5.1)");
    Console.WriteLine($"  Base relocations (.reloc):    {image.Relocations.Count} entries");
    Console.WriteLine();

    if (image.LoadConfig is { } loadConfig)
    {
        Console.WriteLine("  Load config / CFGuard (§5.4)");
        Console.WriteLine($"    Control Flow Guard: {(loadConfig.HasCfg ? "enabled" : "not enabled")}");

        if (loadConfig.HasCfg)
        {
            Console.WriteLine($"      GuardCFFunctionTable:            {loadConfig.GuardCfFunctionTable.Count} targets");
            Console.WriteLine($"      GuardAddressTakenIatEntryTable:  {loadConfig.GuardAddressTakenIatEntryTable.Count} entries");
            Console.WriteLine($"      GuardLongJumpTargetTable:        {loadConfig.GuardLongJumpTargetTable.Count} entries");

            if (loadConfig.GuardEhContinuationTable is { } ehTable)
            {
                Console.WriteLine($"      GuardEHContinuationTable:        {ehTable.Count} entries (/guard:ehcont)");
            }
        }

        Console.WriteLine($"    Extended Flow Guard (XFG): {(loadConfig.HasXfg ? "enabled" : "not enabled")}");
    }
    else
    {
        Console.WriteLine(
            "  Load config / CFGuard: absent — indirect-call target enumeration will rely on heuristics only (§5.4)");
    }

    Console.WriteLine();

    var provenance = LayoutProvenanceClassifier.Classify(image);
    Console.WriteLine($"  Layout provenance: {provenance.Origin}");
    Console.WriteLine($"    Debug directory: {string.Join(", ", image.DebugEntries.Select(e => e.TypeName))}");
    foreach (var line in provenance.Evidence)
    {
        Console.WriteLine($"    - {line}");
    }

    Console.WriteLine();
    PrintFunctions(image);

}

static void PrintFunctions(BinaryImage image)
{
    var functions = image.Functions;
    Console.WriteLine($"  Functions: {functions.Count:N0} ({image.Exports.Count(e => !e.IsForwarder):N0} exports, {image.TlsCallbacks.Count} TLS callbacks)");

    int fromPdata = functions.Count(f => f.DiscoveredBy.HasFlag(DiscoverySource.Pdata));
    Console.WriteLine($"    from .pdata:        {fromPdata:N0}");
    Console.WriteLine($"    leaf (no .pdata):   {functions.Count - fromPdata:N0}");
    foreach (var source in Enum.GetValues<DiscoverySource>().Where(s => s is not (DiscoverySource.None or DiscoverySource.Pdata)))
    {
        int leaves = functions.Count(f => !f.DiscoveredBy.HasFlag(DiscoverySource.Pdata) && f.DiscoveredBy.HasFlag(source));
        if (leaves > 0)
        {
            Console.WriteLine($"      via {source,-17} {leaves:N0}");
        }
    }

    var multiRange = functions.Where(f => f.Ranges.Count > 1).ToList();
    Console.WriteLine($"    with >1 range:      {multiRange.Count:N0}" +
                      (multiRange.Count > 0 ? $" (max {multiRange.Max(f => f.Ranges.Count)} ranges)" : string.Empty));

    ulong codeBytes = (ulong)image.Sections.Where(s => s.IsExecutable).Sum(s => (long)s.MappedSize);
    ulong claimed = (ulong)functions.Sum(f => (long)f.TotalLength);
    Console.WriteLine();
    Console.WriteLine($"  Executable bytes: {codeBytes:N0}, claimed by functions {claimed:N0} ({Percent(claimed, codeBytes)})");
    foreach (var kind in Enum.GetValues<UnclaimedKind>())
    {
        var ranges = image.UnclaimedCode.Where(u => u.Kind == kind).ToList();
        if (ranges.Count > 0)
        {
            ulong bytes = (ulong)ranges.Sum(u => (long)u.Length);
            Console.WriteLine($"    {kind,-21} {bytes,12:N0} bytes in {ranges.Count:N0} ranges ({Percent(bytes, codeBytes)})");
        }
    }

    Console.WriteLine();
    int blocks = functions.Sum(f => f.BasicBlocks.Count);
    int edges = functions.Sum(f => f.BasicBlocks.Sum(b => b.Successors.Count));
    Console.WriteLine($"  CFG: {blocks:N0} basic blocks, {edges:N0} edges, {image.Instructions.Count:N0} instructions");
    Console.WriteLine($"  Call graph: {image.CallSites.Count:N0} call sites");
    foreach (var group in image.CallSites.GroupBy(c => c.Kind).OrderBy(g => g.Key))
    {
        int resolved = group.Count(c => c.CalleeId is not null);
        Console.WriteLine($"    {group.Key,-20} {group.Count(),10:N0}" + (group.Key is CallKind.IndirectCall or CallKind.IndirectTailJump ? string.Empty : $"   ({resolved:N0} to a known function entry)"));
    }

    var pointers = image.CodePointers;
    if (pointers.Count > 0)
    {
        int entries = pointers.Count(p => p.IsEntry);
        int interior = pointers.Count(p => p is { IsEntry: false, TargetFunctionId: not null });
        int addressTaken = pointers.Where(p => p.IsEntry).Select(p => p.TargetFunctionId).Distinct().Count();
        Console.WriteLine($"  Code pointers (lea [rip+X] into code): {pointers.Count:N0}: {entries:N0} to function entries " +
                          $"({addressTaken:N0} functions address-taken), {interior:N0} inside functions, " +
                          $"{pointers.Count - entries - interior:N0} outside any function");
    }

    PrintExceptionHandlers(image);
    PrintSafetyGate(image, codeBytes);
}

static void PrintExceptionHandlers(BinaryImage image)
{
    var withHandler = image.Functions.Where(f => f.ExceptionHandler is not null).ToList();
    if (withHandler.Count == 0)
    {
        return;
    }

    Console.WriteLine();
    Console.WriteLine($"  Exception handlers: {withHandler.Count:N0} functions use {image.ExceptionHandlers.Count} distinct handlers");
    foreach (var group in withHandler.GroupBy(f => f.ExceptionHandler!.Kind).OrderByDescending(g => g.Count()))
    {
        var names = group.Select(f => f.ExceptionHandler!.Name ?? $"0x{f.ExceptionHandler.HandlerRva:X}").Distinct().Take(3);
        Console.WriteLine($"    {group.Key,-18} {group.Count(),8:N0} functions {group.Sum(f => (long)f.TotalLength),12:N0} bytes   ({string.Join(", ", names)})");
    }

    var byPdb = image.ExceptionHandlers.Values.Where(h => h.NamedByPdb).ToList();
    if (byPdb.Count > 0)
    {
        Console.WriteLine($"    identified by PDB name only (statically linked): {string.Join(", ", byPdb.Select(h => $"{h.Name} at 0x{h.HandlerRva:X}"))}");
    }

    var inferred = image.ExceptionHandlers.Values.Where(h => h.InferredFromData).ToList();
    if (inferred.Count > 0)
    {
        Console.WriteLine($"    inferred from the handler data of all their users: {string.Join(", ", inferred.Select(h => $"{h.Name} at 0x{h.HandlerRva:X}"))}");
    }

    int scopeTables = withHandler.Count(f => f.ScopeTable is not null);
    if (scopeTables > 0)
    {
        Console.WriteLine($"    SEH scope tables validated: {scopeTables:N0}, {withHandler.Sum(f => f.ScopeTable?.Count ?? 0):N0} entries");
    }
}

static void PrintSafetyGate(BinaryImage image, ulong codeBytes)
{
    var functions = image.Functions;
    Console.WriteLine();
    Console.WriteLine("  Safety gate (§5.5): what later stages may touch");
    if (image.NativeAot is { } aot)
    {
        string range = aot.Source == ManagedRangeSource.Unknown ? "unknown" : $"[0x{aot.ManagedStart:X}, 0x{aot.ManagedEnd:X})";
        Console.WriteLine($"    .NET NativeAOT image: managed code {range} ({aot.Evidence}); {aot.ManagedFunctions:N0} functions downgraded (gc-info), " +
                          $"{aot.FuncletFunctions:N0} of them funclets or parents of funclets. Rewriting is refused (DesignDoc R5).");
    }

    foreach (var level in new[] { Transformability.FullyTransformable, Transformability.RelocatableOnly, Transformability.Frozen, Transformability.Unanalyzed })
    {
        var atLevel = functions.Where(f => f.SafetyStatus.Level == level).ToList();
        if (atLevel.Count == 0)
        {
            continue;
        }

        ulong bytes = (ulong)atLevel.Sum(f => (long)f.TotalLength);
        Console.WriteLine($"    {level,-20} {atLevel.Count,8:N0} functions ({Percent((ulong)atLevel.Count, (ulong)functions.Count),6}), {bytes,12:N0} bytes ({Percent(bytes, codeBytes)} of code)");
    }

    var downgraded = functions.Where(f => f.SafetyStatus.DowngradeReason is not null).ToList();
    if (downgraded.Count == 0)
    {
        return;
    }

    // "Only" = the reason is the sole code blocking the function: fixing it frees the function.
    Console.WriteLine($"    Downgrade reasons ({downgraded.Count:N0} functions; a function can have several):");
    Console.WriteLine($"      {"reason",-28} {"functions",9} {"bytes",12}   {"only reason",11} {"bytes",12}");
    var codesByFunction = downgraded.ToDictionary(f => f, f => f.DowngradeReasons.Select(ReasonCode).ToHashSet());
    foreach (var code in codesByFunction.Values.SelectMany(c => c).Distinct()
                 .OrderByDescending(c => codesByFunction.Where(kv => kv.Value.Contains(c)).Sum(kv => (long)kv.Key.TotalLength)))
    {
        var having = codesByFunction.Where(kv => kv.Value.Contains(code)).Select(kv => kv.Key).ToList();
        var only = codesByFunction.Where(kv => kv.Value.Count == 1 && kv.Value.Contains(code)).Select(kv => kv.Key).ToList();
        Console.WriteLine($"      {code,-28} {having.Count,9:N0} {having.Sum(f => (long)f.TotalLength),12:N0}   {only.Count,11:N0} {only.Sum(f => (long)f.TotalLength),12:N0}");
        Console.WriteLine($"        e.g. {Describe(having[0], code)}");
    }
}

static string Percent(ulong part, ulong whole) => whole == 0 ? "-" : $"{100.0 * part / whole:F1}%";

static string ReasonCode(string reason) => reason.Split(':')[0];

static string Describe(Function f, string code) =>
    $"{f.DisplayName}: {f.DowngradeReasons.First(r => ReasonCode(r) == code)}";
