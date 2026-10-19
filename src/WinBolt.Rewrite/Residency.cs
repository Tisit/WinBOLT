using System.Buffers.Binary;
using System.Text;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>Where an address of a rewritten (append-mode) image lies.</summary>
public enum CodePlace
{
    /// <summary>Appended code (.wbtext and later sections): copies and rebuilt functions.</summary>
    Optimized,

    /// <summary>The 5-byte jmp at a moved function's original entry.</summary>
    Trampoline,

    /// <summary>A moved function's original body past its trampoline: the intact old code.</summary>
    OriginalBody,

    /// <summary>A function that did not move.</summary>
    Unmoved,

    /// <summary>Inside the image but in no function (padding, data, unclaimed code).</summary>
    Other,

    /// <summary>Outside the image (another module, or an address the trace did not resolve).</summary>
    Outside,
}

/// <summary>
/// A function the rewrite moved: its entry range stays in the image as an intact original body
/// (<see cref="Start"/>, <see cref="Length"/>), behind a trampoline to <see cref="CopyEntry"/>
/// unless every pointer to it was redirected (then <see cref="CopyEntry"/> is null).
/// </summary>
public sealed record MovedOriginal(Function Function, uint Start, uint Length, uint? CopyEntry)
{
    public bool HasTrampoline => CopyEntry is not null;
}

/// <summary>
/// Which functions of the input an append-mode output moved, read off the output itself: a
/// <c>jmp rel32</c> at the original entry into code past the input's SizeOfImage is a trampoline,
/// and an entry the output's exception table no longer begins at moved without one
/// (<c>--redirect-pointers</c>). Leaf functions moved without a trampoline have neither mark and
/// count as unmoved.
/// </summary>
public sealed class ResidencyMap
{
    private const int TrampolineSize = 5;

    private readonly (uint Start, uint End, Function Function)[] ranges;
    private readonly Dictionary<Function, MovedOriginal> movedOf = [];

    private ResidencyMap(BinaryImage input, BinaryImage output, (uint, uint, Function)[] ranges)
    {
        Input = input;
        Output = output;
        this.ranges = ranges;
    }

    public BinaryImage Input { get; }

    public BinaryImage Output { get; }

    public IReadOnlyCollection<MovedOriginal> Moved => movedOf.Values;

    /// <param name="input">The analyzed input image.</param>
    /// <param name="output">The rewritten image (read only, not analyzed).</param>
    public static ResidencyMap Build(BinaryImage input, BinaryImage output)
    {
        var ranges = input.Functions
            .SelectMany(f => f.Ranges.Select(r => ((uint)r.StartRva, (uint)r.StartRva + r.Length, f)))
            .OrderBy(r => r.Item1).ToArray();
        var map = new ResidencyMap(input, output, ranges);
        var outputBegins = output.ExceptionData.Select(e => e.BeginAddress).ToHashSet();
        var inputBegins = input.ExceptionData.Where(e => !e.IsChained).Select(e => e.BeginAddress).ToHashSet();
        foreach (var f in input.Functions)
        {
            uint entry = f.EntryRva;
            var range = f.EntryRange;
            var bytes = output.ReadFrom(entry).Span;
            if (bytes.Length >= TrampolineSize && bytes[0] == 0xE9)
            {
                uint target = (uint)(entry + TrampolineSize + BinaryPrimitives.ReadInt32LittleEndian(bytes[1..]));
                if (target >= input.SizeOfImage && output.FindSection(target) is { IsExecutable: true })
                {
                    map.movedOf[f] = new MovedOriginal(f, entry, range.Length, target);
                    continue;
                }
            }

            if (inputBegins.Contains(entry) && !outputBegins.Contains(entry))
            {
                map.movedOf[f] = new MovedOriginal(f, entry, range.Length, null);
            }
        }

        return map;
    }

    public MovedOriginal? MovedOf(Function f) => movedOf.GetValueOrDefault(f);

    /// <summary>Where <paramref name="rva"/> lies, and the input function it belongs to.</summary>
    public (CodePlace Place, Function? Function) Locate(uint? rva)
    {
        if (rva is not { } x)
        {
            return (CodePlace.Outside, null);
        }

        if (x >= Input.SizeOfImage)
        {
            return Output.FindSection(x) is { IsExecutable: true } ? (CodePlace.Optimized, null) : (CodePlace.Other, null);
        }

        if (FunctionAt(x) is not { } f)
        {
            return (CodePlace.Other, null);
        }

        if (movedOf.TryGetValue(f, out var moved) && x >= moved.Start && x - moved.Start < moved.Length)
        {
            return (moved.HasTrampoline && x - moved.Start < TrampolineSize ? CodePlace.Trampoline : CodePlace.OriginalBody, f);
        }

        // Other ranges of a moved function (PGO-split parts, chained fragments) run in place.
        return (CodePlace.Unmoved, f);
    }

    private Function? FunctionAt(uint rva)
    {
        int lo = 0, hi = ranges.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (ranges[mid].Start <= rva)
            {
                found = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        // Ranges may overlap (range-overlap downgrades): look back a little for one that contains it.
        for (int i = found; i >= 0 && i > found - 8; i--)
        {
            if (rva < ranges[i].End)
            {
                return ranges[i].Function;
            }
        }

        return null;
    }

    /// <summary>The kind of branch instruction at <paramref name="rva"/> in the output (an LBR record's source).</summary>
    public string BranchKind(uint? rva)
    {
        if (rva is not { } x)
        {
            return "from outside the image";
        }

        var bytes = Output.ReadFrom(x);
        if (bytes.IsEmpty)
        {
            return "unknown";
        }

        var decoder = Iced.Intel.Decoder.Create(64, new ByteArrayCodeReader(bytes[..Math.Min(bytes.Length, 15)].ToArray()));
        decoder.IP = x;
        var instruction = decoder.Decode();
        return instruction.FlowControl switch
        {
            FlowControl.Call => "direct call",
            FlowControl.IndirectCall => "indirect call",
            FlowControl.UnconditionalBranch => "direct jmp",
            FlowControl.IndirectBranch => "indirect jmp",
            FlowControl.ConditionalBranch => "conditional branch",
            FlowControl.Return => "ret",
            _ => "other",
        };
    }
}

/// <summary>
/// DesignDoc §6.1 "Dual residency", measured: applies a trace of the rewritten image to a
/// <see cref="ResidencyMap"/> and reports where time and branches still land in original code.
/// Three findings come out of it: trampoline traffic by source and, for indirect calls, why
/// pointer redirection left the target alone; unmoved code that is hot or calls through
/// trampolines; and execution inside a moved function's original body, which is either a known
/// case (a C++ catch continuation, a direct branch from unmoved code) or a reference the analysis
/// never found.
/// </summary>
public sealed class ResidencyAnalysis(ResidencyMap map)
{
    private readonly Dictionary<CodePlace, long> ipByPlace = [];
    private readonly Dictionary<Function, long> ipOf = [];
    private readonly Dictionary<Function, Dictionary<(CodePlace Place, string Kind), long>> trampolineHits = [];
    private readonly Dictionary<Function, long> trampolineCallers = [];
    private readonly Dictionary<Function, Dictionary<(uint? From, CodePlace Place, string Kind, uint To), long>> bodyEntries = [];
    private readonly Dictionary<Function, long> bodyBranches = [];
    private readonly Dictionary<uint, string> kindCache = [];

    public long IpSamples { get; private set; }

    public long Branches { get; private set; }

    public long TrampolineBranches => trampolineHits.Values.Sum(d => d.Values.Sum());

    public long OriginalBodyEntries => bodyEntries.Values.Sum(d => d.Values.Sum());

    public ResidencyMap Map => map;

    /// <summary>Entries into moved functions' original bodies: (function, source, its place, branch kind, target, count).</summary>
    public IEnumerable<(Function Function, uint? From, CodePlace Place, string Kind, uint To, long Count)> BodyEntries =>
        bodyEntries.SelectMany(p => p.Value.Select(e => (p.Key, e.Key.From, e.Key.Place, e.Key.Kind, e.Key.To, e.Value)));

    /// <summary>Branches into trampolines per moved function, by source place and branch kind.</summary>
    public IReadOnlyDictionary<Function, Dictionary<(CodePlace Place, string Kind), long>> TrampolineHits => trampolineHits;

    public void AddIpSample(uint rva)
    {
        IpSamples++;
        var (place, f) = map.Locate(rva);
        ipByPlace[place] = ipByPlace.GetValueOrDefault(place) + 1;
        if (f is not null && place is CodePlace.Unmoved or CodePlace.OriginalBody or CodePlace.Trampoline)
        {
            ipOf[f] = ipOf.GetValueOrDefault(f) + 1;
        }
    }

    public void AddBranch(uint? from, uint? to)
    {
        Branches++;
        var (fromPlace, fromFunction) = map.Locate(from);
        var (toPlace, toFunction) = map.Locate(to);
        if (fromPlace == CodePlace.OriginalBody && fromFunction is not null)
        {
            bodyBranches[fromFunction] = bodyBranches.GetValueOrDefault(fromFunction) + 1;
        }

        if (toFunction is null)
        {
            return;
        }

        if (toPlace == CodePlace.Trampoline && to == map.MovedOf(toFunction)!.Start)
        {
            string kind = Kind(from);
            var hits = trampolineHits.TryGetValue(toFunction, out var h) ? h : trampolineHits[toFunction] = [];
            hits[(fromPlace, kind)] = hits.GetValueOrDefault((fromPlace, kind)) + 1;
            if (fromFunction is not null && fromPlace == CodePlace.Unmoved)
            {
                trampolineCallers[fromFunction] = trampolineCallers.GetValueOrDefault(fromFunction) + 1;
            }

            return;
        }

        // Into an original body from anywhere but the same body (a body's own branches are not entries).
        if (toPlace == CodePlace.OriginalBody && !(fromPlace == CodePlace.OriginalBody && fromFunction == toFunction))
        {
            var key = (from, fromPlace, Kind(from), to!.Value);
            var entries = bodyEntries.TryGetValue(toFunction, out var e) ? e : bodyEntries[toFunction] = [];
            entries[key] = entries.GetValueOrDefault(key) + 1;
        }
    }

    private string Kind(uint? from)
    {
        if (from is not { } x)
        {
            return map.BranchKind(null);
        }

        if (!kindCache.TryGetValue(x, out string? kind))
        {
            kind = kindCache[x] = map.BranchKind(x);
        }

        return kind;
    }

    /// <summary>Why execution entered an original body at this entry: a known case, or unexplained.</summary>
    public static string Explain(Function f, CodePlace fromPlace, string kind)
    {
        if (kind == "ret")
        {
            return "return to a call made from the original body";
        }

        if (f.ExceptionHandler?.Kind is ExceptionHandlerKind.CxxFrameHandler3 or ExceptionHandlerKind.CxxFrameHandler4 && fromPlace is CodePlace.Outside or CodePlace.Unmoved)
        {
            return "C++ EH: catch continuations stay in the original body";
        }

        if (fromPlace == CodePlace.Unmoved && kind is "direct call" or "direct jmp" or "conditional branch")
        {
            return "direct branch from unmoved code";
        }

        return "UNEXPLAINED: a reference the analysis did not find?";
    }

    /// <summary>The report. <paramref name="plan"/> (for the trampolined functions) explains indirect traffic.</summary>
    public string Format(RedirectionPlan? plan, int top = 15)
    {
        var input = map.Input;
        var text = new StringBuilder();
        int moved = map.Moved.Count, trampolined = map.Moved.Count(m => m.HasTrampoline);
        text.AppendLine($"Moved functions found in the output: {moved:N0} ({trampolined:N0} with a trampoline, {moved - trampolined:N0} without)");
        if (moved == 0)
        {
            text.AppendLine("Nothing moved: not an append-mode output of this input (whole-program outputs have no trampolines).");
        }

        double Pct(long part, long whole) => part * 100.0 / Math.Max(1, whole);
        string Level(Function f) => f.SafetyStatus.Level + (f.DowngradeReasons.Count > 0 ? $" ({string.Join(", ", f.DowngradeReasons.Distinct())})" : string.Empty);

        text.AppendLine();
        text.AppendLine($"Time (instruction-pointer samples in the image: {IpSamples:N0})");
        foreach (var place in Enum.GetValues<CodePlace>().Where(p => p != CodePlace.Outside))
        {
            long n = ipByPlace.GetValueOrDefault(place);
            text.AppendLine($"  {Describe(place),-34} {n,12:N0} {Pct(n, IpSamples),7:F2}%");
        }

        long trampolineTotal = TrampolineBranches;
        text.AppendLine();
        text.AppendLine($"Branch records touching the image: {Branches:N0}; into trampolines: {trampolineTotal:N0} ({Pct(trampolineTotal, Branches):F2}%)");
        foreach (var group in trampolineHits.Values.SelectMany(d => d)
                     .GroupBy(p => $"{p.Key.Kind} from {Describe(p.Key.Place).ToLowerInvariant()}")
                     .Select(g => (g.Key, Count: g.Sum(p => p.Value))).OrderByDescending(g => g.Count))
        {
            text.AppendLine($"  {group.Key,-50} {group.Count,12:N0} {Pct(group.Count, trampolineTotal),7:F2}%");
        }

        string Redirection(Function f)
        {
            if (plan is null)
            {
                return "";
            }

            if (plan.Refused is not null)
            {
                return "image refused: " + plan.Refused;
            }

            return plan.Targets.ContainsKey(f.EntryRva) ? "redirectable (--redirect-pointers)"
                : plan.Excluded.TryGetValue(f.EntryRva, out string? reason) ? reason
                : "no pointer to it found in the image";
        }

        static bool Indirect(string kind) => kind is "indirect call" or "indirect jmp";

        if (trampolineHits.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Hottest trampolines (branch records; indirect = indirect call/jmp share; redirection status)");
            foreach (var (f, hits) in trampolineHits.OrderByDescending(p => p.Value.Values.Sum()).Take(top))
            {
                long n = hits.Values.Sum(), indirect = hits.Where(h => Indirect(h.Key.Kind)).Sum(h => h.Value);
                text.AppendLine($"  {n,10:N0} {Pct(n, trampolineTotal),6:F2}%  indirect {Pct(indirect, n),3:F0}%  {f.DisplayName}  [{Redirection(f)}]");
            }

            if (plan is not null)
            {
                var byReason = trampolineHits
                    .Select(p => (Reason: Redirection(p.Key), Count: p.Value.Where(h => Indirect(h.Key.Kind)).Sum(h => h.Value)))
                    .Where(r => r.Count > 0).GroupBy(r => r.Reason)
                    .Select(g => (g.Key, Count: g.Sum(r => r.Count), Functions: g.Count())).OrderByDescending(g => g.Count).ToList();
                long indirectTotal = byReason.Sum(r => r.Count);
                text.AppendLine();
                text.AppendLine($"Indirect trampoline traffic by redirection status ({indirectTotal:N0} records)");
                foreach (var (reason, count, functions) in byReason)
                {
                    text.AppendLine($"  {count,10:N0} {Pct(count, indirectTotal),6:F2}%  {functions,5} fns  {reason}");
                }
            }
        }

        if (trampolineCallers.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Unmoved code calling through trampolines (branch records)");
            foreach (var (f, n) in trampolineCallers.OrderByDescending(p => p.Value).Take(top))
            {
                text.AppendLine($"  {n,10:N0}  {f.DisplayName}  {Level(f)}");
            }
        }

        var unmoved = ipOf.Where(p => map.MovedOf(p.Key) is null).OrderByDescending(p => p.Value).Take(top).ToList();
        if (unmoved.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Hottest unmoved functions (IP samples, share of the image)");
            foreach (var (f, n) in unmoved)
            {
                text.AppendLine($"  {n,10:N0} {Pct(n, IpSamples),6:F2}%  {f.DisplayName}  {Level(f)}");
            }
        }

        text.AppendLine();
        long bodySamples = ipByPlace.GetValueOrDefault(CodePlace.OriginalBody);
        text.AppendLine($"Original bodies of moved functions still executing: {bodyEntries.Count:N0} functions, {OriginalBodyEntries:N0} entry records, {bodySamples:N0} IP samples");
        foreach (var (f, entries) in bodyEntries.OrderByDescending(p => p.Value.Values.Sum()).Take(top))
        {
            text.AppendLine($"  {f.DisplayName}: {entries.Values.Sum():N0} entries, {bodyBranches.GetValueOrDefault(f):N0} branches inside, {ipOf.GetValueOrDefault(f):N0} IP samples");
            foreach (var ((from, place, kind, to), n) in entries.OrderByDescending(e => e.Value).Take(5))
            {
                var (_, source) = map.Locate(from);
                string where = from is { } x ? $"0x{x:X} ({source?.DisplayName ?? Describe(place).ToLowerInvariant()})" : "outside the image";
                text.AppendLine($"    {n,8:N0}  {kind} at {where} -> +0x{to - f.EntryRva:X}  {Explain(f, place, kind)}");
            }
        }

        return text.ToString();
    }

    private static string Describe(CodePlace place) => place switch
    {
        CodePlace.Optimized => "Optimized (appended code)",
        CodePlace.Trampoline => "Trampolines",
        CodePlace.OriginalBody => "Original bodies of moved functions",
        CodePlace.Unmoved => "Unmoved functions",
        CodePlace.Other => "Other (no function)",
        _ => "Outside the image",
    };
}
