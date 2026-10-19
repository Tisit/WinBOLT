using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// Safety gate computation (§5.5), the last analysis step. Earlier passes downgrade
/// whatever they cannot model. This pass adds the function-level checks that need the whole
/// picture, then promotes every function still <see cref="Transformability.Unanalyzed"/> to
/// <see cref="Transformability.FullyTransformable"/>. A function is only promoted if nothing
/// along the way objected.
/// <list type="bullet">
/// <item>Exception handlers, by kind: a GS cookie check holds no code addresses and costs
/// nothing. A validated SEH scope table (<c>seh-scope-table</c>) makes the function
/// <see cref="Transformability.RelocatableOnly"/>: its code RVAs are known, so the function
/// can move as a unit with the table rebased, but block reordering would have to keep every
/// try range contiguous, which is not modelled. A C++ EH table whose every code address checks
/// out (<c>cxx-eh-table</c>) is likewise <see cref="Transformability.RelocatableOnly"/>: block
/// reordering would have to regenerate the IP-to-state map. A C++ EH table that could not be
/// read or does not fit (<c>cxx-eh</c>), and unidentified handlers (<c>handler-data</c>),
/// freeze the function.</item>
/// <item><c>interior-pointer</c>: a <c>lea [rip+X]</c> takes the address of code inside the
/// function, which makes it <see cref="Transformability.RelocatableOnly"/>.</item>
/// <item><c>gc-info</c>: a .NET NativeAOT method, whose UNWIND_INFO is followed by GC and EH info
/// keyed by offsets from its start (<see cref="NativeAotGate"/>).</item>
/// <item><c>trampoline-window</c>: the function is address-taken (including by a <c>lea</c>), so relocating it needs a
/// 5-byte entry trampoline at the original address (§6.1), and the first 5 bytes are too short
/// or are a branch target.</item>
/// </list>
/// </summary>
[RegisterPass(DependsOn = [CfgConstructionPass.PassName])]
public sealed class SafetyGatePass : IAnalysisPass
{
    public const string PassName = "SafetyGate";

    /// <summary>jmp rel32: reaches an appended section anywhere within ±2 GB.</summary>
    public const int TrampolineSize = 5;

    private const DiscoverySource AddressTakenSources =
        DiscoverySource.Export | DiscoverySource.EntryPoint | DiscoverySource.TlsCallback |
        DiscoverySource.CfgTarget | DiscoverySource.RelocationTarget | DiscoverySource.CodePointer;

    public string Name => PassName;

    public void Run(BinaryImage image, PassContext context)
    {
        NativeAotGate.Run(image);

        // Branch targets from other functions, to check trampoline windows against.
        var externalTargets = image.CallSites
            .Where(c => c.TargetRva is not null && c.Kind is CallKind.TailJump or CallKind.ConditionalTailJump or CallKind.Call)
            .Select(c => c.TargetRva!.Value)
            .ToHashSet();

        var cxxEh = new CxxEhValidator(image);

        // An interior code address that escapes into a register: the function can move as a
        // unit with the lea re-pointed, but reordering blocks around an address that may be
        // compared or offset is not modelled (§5.5: table-driven jumps to interior blocks).
        foreach (var pointer in image.CodePointers)
        {
            if (pointer is { IsEntry: false, TargetFunctionId: { } target })
            {
                var owner = image.Functions[target];
                owner.Downgrade(Transformability.RelocatableOnly,
                    $"interior-pointer: lea at 0x{pointer.SiteRva:X} takes the address of 0x{pointer.TargetRva:X}, " +
                    $"+0x{pointer.TargetRva - owner.EntryRva:X} inside the function");
            }
        }

        foreach (var function in image.Functions)
        {
            GateExceptionHandler(function, cxxEh);

            if ((function.DiscoveredBy & AddressTakenSources) != 0 && TrampolineProblem(function, externalTargets) is { } problem)
            {
                function.Downgrade(Transformability.Frozen, $"trampoline-window: address-taken, and {problem}");
            }

            if (function.SafetyStatus.Level == Transformability.Unanalyzed)
            {
                function.SafetyStatus = SafetyStatus.FullyTransformable();
            }
        }
    }

    private static void GateExceptionHandler(Function function, CxxEhValidator cxxEh)
    {
        if (function.ExceptionHandler is not { } handler)
        {
            return;
        }

        string name = handler.Name ?? $"handler at 0x{handler.HandlerRva:X}";
        switch (handler.Kind)
        {
            case ExceptionHandlerKind.GsCookieCheck:
                return; // handler data is a frame offset, not a code address

            case ExceptionHandlerKind.CSpecific when function.ScopeTable is { } table:
                function.Downgrade(Transformability.RelocatableOnly,
                    $"seh-scope-table: {table.Count} scope entries hold code RVAs; the function can move as a unit with the table " +
                    "rebased, but block reordering must keep try ranges contiguous, which is not modelled");
                return;

            case ExceptionHandlerKind.CSpecific:
                return; // CFG construction already froze it with a scope-table reason

            case ExceptionHandlerKind.CxxFrameHandler3 or ExceptionHandlerKind.CxxFrameHandler4:
                if (function.CxxEh is not { } cxxTable)
                {
                    function.Downgrade(Transformability.Frozen, $"cxx-eh: {name} handler data could not be read");
                }
                else if (cxxEh.Problem(function, cxxTable) is { } problem)
                {
                    function.Downgrade(Transformability.Frozen, $"cxx-eh: {name} FuncInfo at 0x{cxxTable.FuncInfoRva:X}: {problem}");
                }
                else
                {
                    function.Downgrade(Transformability.RelocatableOnly,
                        $"cxx-eh-table: {name} FuncInfo at 0x{cxxTable.FuncInfoRva:X} holds " +
                        $"{cxxTable.FuncletRvas.Count + cxxTable.ContinuationRvas.Count + cxxTable.IpStateRvas.Count} code addresses, all accounted for; " +
                        "the function can move as a unit with the table rebased, but block reordering must regenerate the IP-to-state map, " +
                        "which is not modelled");
                }

                return;

            default:
                function.Downgrade(Transformability.Frozen,
                    $"handler-data: unidentified exception handler ({name}, {handler.Evidence}); its handler data may hold code RVAs");
                return;
        }
    }

    /// <summary>
    /// Checks a parsed C++ EH table against discovered code. Funclets must be function entries.
    /// Catch continuations must lie in the function. IP-to-state addresses must lie in the
    /// function, in a funclet it names, or, for FH3, in another function that shares the same
    /// FuncInfo (a parent and its catch funclets do). A range's end address is accepted as the
    /// final state transition.
    /// </summary>
    private sealed class CxxEhValidator
    {
        private readonly Dictionary<uint, Function> _byEntry = [];
        private readonly ILookup<uint, Function> _byFuncInfo;

        public CxxEhValidator(BinaryImage image)
        {
            foreach (var function in image.Functions)
            {
                _byEntry.TryAdd(function.EntryRva, function);
            }

            _byFuncInfo = image.Functions.Where(f => f.CxxEh is not null).ToLookup(f => f.CxxEh!.FuncInfoRva);
        }

        public string? Problem(Function function, CxxEhInfo table)
        {
            if (table.Problem is { } parseProblem)
            {
                return parseProblem;
            }

            foreach (uint funclet in table.FuncletRvas)
            {
                if (!_byEntry.ContainsKey(funclet))
                {
                    return $"funclet or destructor 0x{funclet:X} is not a known function entry";
                }
            }

            foreach (uint continuation in table.ContinuationRvas)
            {
                if (!Contains(function, continuation))
                {
                    return $"catch continuation 0x{continuation:X} is outside the function";
                }
            }

            var owners = _byFuncInfo[table.FuncInfoRva]
                .Concat(table.FuncletRvas.Select(_byEntry.GetValueOrDefault).OfType<Function>())
                .Append(function)
                .Distinct()
                .ToList();
            foreach (uint ip in table.IpStateRvas)
            {
                if (!owners.Any(owner => Contains(owner, ip)))
                {
                    return $"IP-to-state entry 0x{ip:X} is outside the function and its funclets";
                }
            }

            return null;
        }

        private static bool Contains(Function function, uint rva) =>
            function.Ranges.Any(r => rva >= r.StartRva && rva <= r.StartRva + r.Length);
    }

    private static string? TrampolineProblem(Function function, HashSet<uint> externalTargets)
    {
        uint entry = function.EntryRva;
        if (function.EntryRange.Length < TrampolineSize)
        {
            return $"the entry range is {function.EntryRange.Length} bytes, too short for a {TrampolineSize}-byte jmp";
        }

        foreach (var block in function.BasicBlocks)
        {
            if (block.StartRva > entry && block.StartRva < entry + TrampolineSize && block.IsBranchTarget)
            {
                return $"0x{block.StartRva:X}, inside the first {TrampolineSize} bytes, is a branch target";
            }
        }

        for (uint rva = entry + 1; rva < entry + TrampolineSize; rva++)
        {
            if (externalTargets.Contains(rva))
            {
                return $"another function branches to 0x{rva:X}, inside the first {TrampolineSize} bytes";
            }
        }

        return null;
    }
}
