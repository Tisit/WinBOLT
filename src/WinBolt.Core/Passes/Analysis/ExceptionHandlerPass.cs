using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Arch;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// Identifies the language-specific exception handlers named by .pdata entries, and parses the
/// handler data whose layout is known (§5.2: exception tables are code-address tables).
/// <para>
/// Identification, in order of confidence: an export of that name at the handler RVA; a
/// <c>jmp [rip+slot]</c> thunk whose IAT slot is a named import (direct <c>jmp rel32</c> hops are
/// followed); for the statically linked <c>__GSHandlerCheck</c>, an exact match of its
/// instruction sequence; for other statically linked CRT handlers, an exact public symbol name
/// from the matching PDB at a .pdata function start (<see cref="ExceptionHandlerInfo.NamedByPdb"/>).
/// Anything else stays <see cref="ExceptionHandlerKind.Unknown"/>, and the safety gate freezes
/// functions that use it.
/// </para>
/// <para>
/// Scope tables and C++ EH FuncInfo are parsed here but validated against function ranges only
/// later, once functions exist. Discovery uses the funclet RVAs in both as function starts.
/// </para>
/// </summary>
[RegisterPass]
public sealed class ExceptionHandlerPass : IAnalysisPass
{
    public const string PassName = "ExceptionHandlers";

    private const int MaxThunkHops = 4;
    private const uint MaxScopeEntries = 4096;

    // Offset of HandlerData in DISPATCHER_CONTEXT (x64).
    private const long DispatcherContextHandlerData = 0x38;

    public string Name => PassName;

    public void Run(BinaryImage image, PassContext context)
    {
        var imports = new Dictionary<uint, ImportedSymbol>();
        foreach (var import in image.Imports)
        {
            imports.TryAdd(import.IatSlotRva, import);
        }

        var exports = new Dictionary<uint, string>();
        foreach (var export in image.Exports)
        {
            if (!export.IsForwarder && export.Name is not null)
            {
                exports.TryAdd(export.Rva, export.Name);
            }
        }

        // Handler names from the matching PDB: exact names, at a .pdata function start, one name per address.
        var pdataStarts = image.ExceptionData.Where(e => !e.IsChained).Select(e => e.BeginAddress).ToHashSet();
        var pdbHandlers = image.Symbols
            .Where(s => s.IsFunction && PdbHandlerNames.Contains(s.Name) && pdataStarts.Contains(s.Rva))
            .GroupBy(s => s.Rva)
            .Where(g => g.Select(s => s.Name).Distinct().Count() == 1)
            .ToDictionary(g => g.Key, g => g.First().Name);

        // A name holds along jmp hops: a thunk and its target are one function (a rewriter's
        // trampoline and its copy, which the copies of other handlers call).
        foreach (var (at, name) in pdbHandlers.ToList())
        {
            foreach (uint hop in JumpHops(image, context.Architecture, at).Skip(1))
            {
                if (pdataStarts.Contains(hop) && pdbHandlers.GetValueOrDefault(hop, name) == name)
                {
                    pdbHandlers[hop] = name;
                }
            }
        }

        var names = new HandlerNames(imports, exports, pdbHandlers);

        var withHandler = image.ExceptionData.Where(e => !e.IsChained && e.HasHandler).ToList();
        foreach (var entry in withHandler)
        {
            if (!image.ExceptionHandlers.ContainsKey(entry.HandlerRva))
            {
                image.ExceptionHandlers[entry.HandlerRva] = Identify(image, context.Architecture, entry.HandlerRva, names);
            }
        }

        IdentifyGsWrappers(image, context.Architecture, names);
        InferFromData(image, withHandler);

        foreach (var entry in withHandler)
        {
            switch (image.ExceptionHandlers[entry.HandlerRva].Kind)
            {
                case ExceptionHandlerKind.CSpecific when TryReadScopeTable(image, entry.HandlerDataRva) is { } table:
                    image.ScopeTables[entry.BeginAddress] = table;
                    break;

                // For both C++ handlers the handler data is the RVA of the FuncInfo.
                case ExceptionHandlerKind.CxxFrameHandler3 when ReadU32(image, entry.HandlerDataRva) is { } funcInfo:
                    image.CxxEhTables[entry.BeginAddress] = CxxEhParser.ParseFh3(image, funcInfo);
                    break;

                case ExceptionHandlerKind.CxxFrameHandler4 when ReadU32(image, entry.HandlerDataRva) is { } funcInfo:
                    image.CxxEhTables[entry.BeginAddress] = CxxEhParser.ParseFh4(image, funcInfo, entry.BeginAddress);
                    break;
            }
        }
    }

    /// <summary>
    /// Names a statically linked handler may carry in the PDB. <c>__GSHandlerCheck</c> is listed
    /// only to report a PDB name its code does not match: it is trusted by its instruction sequence alone.
    /// </summary>
    private static readonly HashSet<string> PdbHandlerNames =
        ["__CxxFrameHandler3", "__CxxFrameHandler4", "__C_specific_handler", "_C_specific_handler", "__C_specific_handler_noexcept", "__GSHandlerCheck"];

    private sealed record HandlerNames(
        Dictionary<uint, ImportedSymbol> Imports, Dictionary<uint, string> Exports, Dictionary<uint, string> PdbHandlers);

    /// <summary>
    /// Export, then import thunk (following jmp hops), then the __GSHandlerCheck sequence, then an
    /// exact PDB handler name at the handler or a hop. The last lets a statically linked CRT handler
    /// be identified; its table is still parsed and validated against the functions before the
    /// gate accepts it.
    /// </summary>
    private static ExceptionHandlerInfo Identify(BinaryImage image, IArchitecture architecture, uint handlerRva, HandlerNames names)
    {
        var visited = new List<uint>();
        uint target = handlerRva;
        for (int hop = 0; hop < MaxThunkHops; hop++)
        {
            visited.Add(target);
            if (names.Exports.TryGetValue(target, out var exported))
            {
                return ByName(handlerRva, exported, $"export {exported}{PdbDisagrees(exported)}");
            }

            if (DecodeAt(image, architecture, target, 1) is not [var first])
            {
                break;
            }

            if (first.FlowControl == FlowControl.IndirectBranch && first.IsIPRelativeMemoryOperand)
            {
                return names.Imports.TryGetValue((uint)first.IPRelativeMemoryAddress, out var import) && import.Name is not null
                    ? ByName(handlerRva, import.Name, $"import thunk for {import.Dll}!{import.Name}{PdbDisagrees(import.Name)}")
                    : new ExceptionHandlerInfo(handlerRva, ExceptionHandlerKind.Unknown, null, "thunk through an unnamed pointer");
            }

            if (!first.IsJmpNear)
            {
                break;
            }

            target = (uint)first.NearBranchTarget;
        }

        if (IsGsHandlerCheck(DecodeAt(image, architecture, target, 8)))
        {
            return new ExceptionHandlerInfo(handlerRva, ExceptionHandlerKind.GsCookieCheck, "__GSHandlerCheck", "matches the __GSHandlerCheck instruction sequence");
        }

        foreach (uint at in visited)
        {
            if (names.PdbHandlers.TryGetValue(at, out var named))
            {
                return named == "__GSHandlerCheck"
                    ? new ExceptionHandlerInfo(handlerRva, ExceptionHandlerKind.Unknown, null, "not identified: the PDB names it __GSHandlerCheck, but its code does not match")
                    : ByName(handlerRva, named, $"named {named} by the PDB at 0x{at:X}", namedByPdb: true);
            }
        }

        return new ExceptionHandlerInfo(handlerRva, ExceptionHandlerKind.Unknown, null, "not identified");

        string PdbDisagrees(string name) =>
            visited.Select(v => names.PdbHandlers.GetValueOrDefault(v)).FirstOrDefault(n => n is not null && n != name) is { } other
                ? $" (the PDB names it {other})"
                : "";
    }

    /// <summary>
    /// <c>__GSHandlerCheck_SEH</c>, <c>_EH</c> and <c>_EH4</c> check the stack cookie, then call
    /// <c>__C_specific_handler</c> or <c>__CxxFrameHandler3/4</c> with the same dispatcher context.
    /// Their handler data therefore starts with the inner handler's table (GS data follows it),
    /// and they are treated as that inner handler.
    /// <para>
    /// Accepted only if the whole .pdata range of the candidate decodes cleanly, has no
    /// indirect call or jump, and calls or jumps out to exactly two places. One is the helper
    /// that a pattern-verified <c>__GSHandlerCheck</c> calls. The other is an identified SEH or
    /// C++ handler. An image where no function uses plain <c>__GSHandlerCheck</c> has no
    /// verified helper; there the PDB must name the candidate exactly as the wrapper its inner
    /// handler implies, and the structure must hold all the same. Otherwise nothing is accepted.
    /// </para>
    /// </summary>
    private static void IdentifyGsWrappers(BinaryImage image, IArchitecture architecture, HandlerNames names)
    {
        var gsHelpers = new HashSet<uint>();
        foreach (var handler in image.ExceptionHandlers.Values)
        {
            if (handler.Kind == ExceptionHandlerKind.GsCookieCheck &&
                DecodeAt(image, architecture, JumpHops(image, architecture, handler.HandlerRva)[^1], 8) is { } body && IsGsHandlerCheck(body))
            {
                gsHelpers.Add((uint)body[4].NearBranchTarget);
            }
        }

        var symbolNames = image.Symbols.Where(s => s.Name.StartsWith("__GSHandlerCheck_", StringComparison.Ordinal))
            .GroupBy(s => s.Rva).ToDictionary(g => g.Key, g => g.First().Name);
        if (gsHelpers.Count == 0 && symbolNames.Count == 0)
        {
            return;
        }

        var pdataEnd = new Dictionary<uint, uint>();
        foreach (var entry in image.ExceptionData)
        {
            if (!entry.IsChained)
            {
                pdataEnd.TryAdd(entry.BeginAddress, entry.EndAddress);
            }
        }

        foreach (var unknown in image.ExceptionHandlers.Values.Where(h => h.Kind == ExceptionHandlerKind.Unknown).ToList())
        {
            // The wrapper may sit behind jmp hops (an incremental-linking thunk, or a rewriter's
            // trampoline, whose .pdata range still holds the stale original body): check the body.
            var visited = JumpHops(image, architecture, unknown.HandlerRva);
            uint body = visited[^1];
            if (!pdataEnd.TryGetValue(body, out uint end) ||
                ExternalTargets(image, architecture, body, end) is not { Count: 2 } targets)
            {
                continue;
            }

            var inner = targets
                .Select(t => image.ExceptionHandlers.GetValueOrDefault(t) ?? Identify(image, architecture, t, names))
                .Where(h => h.Kind is ExceptionHandlerKind.CSpecific or ExceptionHandlerKind.CxxFrameHandler3 or ExceptionHandlerKind.CxxFrameHandler4)
                .ToList();
            if (inner.Count != 1)
            {
                continue;
            }

            string name = inner[0].Kind switch
            {
                ExceptionHandlerKind.CSpecific => "__GSHandlerCheck_SEH",
                ExceptionHandlerKind.CxxFrameHandler3 => "__GSHandlerCheck_EH",
                _ => "__GSHandlerCheck_EH4",
            };
            bool verifiedHelper = targets.Count(gsHelpers.Contains) == 1;
            bool namedByPdb = gsHelpers.Count == 0 && visited.Any(v => symbolNames.GetValueOrDefault(v) == name);
            if (!verifiedHelper && !namedByPdb)
            {
                continue;
            }

            image.ExceptionHandlers[unknown.HandlerRva] = new ExceptionHandlerInfo(
                unknown.HandlerRva, inner[0].Kind, name,
                verifiedHelper
                    ? $"calls the __GSHandlerCheck helper and {inner[0].Name} and nothing else"
                    : $"named {name} by the PDB; calls {inner[0].Name} and one other function and nothing else (no verified __GSHandlerCheck in the image)");
        }
    }

    private const int MinInferenceUsers = 2;

    /// <summary>
    /// Handlers still unidentified (a statically linked CRT or runtime without a PDB) are classified
    /// by the data every function using them hands them. A handler is taken as
    /// <c>__CxxFrameHandler3</c>, <c>__C_specific_handler</c> or <c>__CxxFrameHandler4</c> only if
    /// <b>all</b> its users (at least <see cref="MinInferenceUsers"/>) carry data that parses as that
    /// kind's table and whose code addresses land inside some .pdata range (funclets: in an
    /// executable section). Hypotheses are tried in that order; FH3 first because its
    /// FuncInfo has a magic number. Anything short of that stays Unknown.
    /// </summary>
    private static void InferFromData(BinaryImage image, List<ExceptionInfo> withHandler)
    {
        foreach (var group in withHandler.GroupBy(e => e.HandlerRva))
        {
            if (image.ExceptionHandlers[group.Key].Kind != ExceptionHandlerKind.Unknown)
            {
                continue;
            }

            var users = group.ToList();
            if (users.Count < MinInferenceUsers)
            {
                continue;
            }

            (ExceptionHandlerKind Kind, string Name, Func<ExceptionInfo, bool> Fits)[] hypotheses =
            [
                (ExceptionHandlerKind.CxxFrameHandler3, "__CxxFrameHandler3", u => Fh3Fits(image, u)),
                (ExceptionHandlerKind.CSpecific, "__C_specific_handler", u => ScopeTableFits(image, u)),
                (ExceptionHandlerKind.CxxFrameHandler4, "__CxxFrameHandler4", u => Fh4Fits(image, u)),
            ];
            foreach (var (kind, name, fits) in hypotheses)
            {
                if (users.All(fits))
                {
                    image.ExceptionHandlers[group.Key] = new ExceptionHandlerInfo(group.Key, kind, name,
                        $"inferred: the handler data of all {users.Count} functions using it parses as a {name} table with every code address inside a .pdata range",
                        InferredFromData: true);
                    break;
                }
            }
        }
    }

    private static bool InExecutable(BinaryImage image, uint rva) => image.FindSection(rva) is { IsExecutable: true };

    /// <summary>
    /// Whether <paramref name="rva"/> lies in some .pdata range: a split function's other fragments
    /// (cold blocks LLVM places elsewhere) are chained entries, so a table may name addresses outside
    /// its own entry.
    /// </summary>
    private static bool InPdata(BinaryImage image, uint rva)
    {
        var starts = PdataStarts(image);
        int i = Array.BinarySearch(starts.Begin, rva);
        i = i >= 0 ? i : ~i - 1;
        return i >= 0 && rva < starts.End[i];
    }

    private static (uint[] Begin, uint[] End) PdataStarts(BinaryImage image)
    {
        if (pdataIndex is { } cached && ReferenceEquals(cached.Owner, image))
        {
            return (cached.Begin, cached.End);
        }

        var sorted = image.ExceptionData.OrderBy(e => e.BeginAddress).ToList();
        var index = (Owner: image, Begin: sorted.Select(e => e.BeginAddress).ToArray(), End: sorted.Select(e => e.EndAddress).ToArray());
        pdataIndex = index;
        return (index.Begin, index.End);
    }

    [ThreadStatic]
    private static (BinaryImage Owner, uint[] Begin, uint[] End)? pdataIndex;

    private static bool ScopeTableFits(BinaryImage image, ExceptionInfo user)
    {
        if (TryReadScopeTable(image, user.HandlerDataRva) is not { } table)
        {
            return false;
        }

        return table.All(s => s.BeginRva < s.EndRva && InPdata(image, s.BeginRva) && InPdata(image, s.EndRva - 1) &&
                              (s.JumpTargetRva == 0 || InPdata(image, s.JumpTargetRva)) &&
                              (s.HandlerRva == 1 || (s.HandlerRva > 1 && InExecutable(image, s.HandlerRva))) &&
                              (s.JumpTargetRva != 0 || s.HandlerRva > 1));
    }

    private static bool Fh3Fits(BinaryImage image, ExceptionInfo user) =>
        ReadU32(image, user.HandlerDataRva) is { } funcInfo &&
        CxxEhParser.ParseFh3(image, funcInfo) is { Problem: null } info &&
        info.FuncletRvas.All(f => InExecutable(image, f)) && info.IpStateRvas.All(ip => InPdata(image, ip));

    private static bool Fh4Fits(BinaryImage image, ExceptionInfo user) =>
        ReadU32(image, user.HandlerDataRva) is { } funcInfo &&
        CxxEhParser.ParseFh4(image, funcInfo, user.BeginAddress) is { Problem: null } info &&
        info.FuncletRvas.Concat(info.ContinuationRvas).All(a => InExecutable(image, a)) &&
        (info.IsSeparated || info.IpStateRvas.All(ip => InPdata(image, ip)));

    /// <summary><paramref name="rva"/>, then each direct jmp target from there, up to <see cref="MaxThunkHops"/> hops.</summary>
    private static List<uint> JumpHops(BinaryImage image, IArchitecture architecture, uint rva)
    {
        var hops = new List<uint> { rva };
        while (hops.Count <= MaxThunkHops && DecodeAt(image, architecture, hops[^1], 1) is [{ IsJmpNear: true } jump])
        {
            hops.Add((uint)jump.NearBranchTarget);
        }

        return hops;
    }

    /// <summary>
    /// Direct call and jump targets leaving [start, end), or null if the range does not decode
    /// cleanly or contains an indirect call or jump.
    /// </summary>
    private static HashSet<uint>? ExternalTargets(BinaryImage image, IArchitecture architecture, uint start, uint end)
    {
        var code = image.ReadFrom(start);
        int length = (int)Math.Min(code.Length, end - start);
        if (length <= 0)
        {
            return null;
        }

        var targets = new HashSet<uint>();
        var decoder = architecture.CreateDecoder(code[..length], start);
        while (decoder.TryDecodeNext(out var instruction))
        {
            if (instruction.IsInvalid || instruction.FlowControl is FlowControl.IndirectCall or FlowControl.IndirectBranch)
            {
                return null;
            }

            if (instruction.IsCallNear || instruction.IsJmpShortOrNear || instruction.IsJccShortOrNear)
            {
                uint target = (uint)instruction.NearBranchTarget;
                if (target < start || target >= end)
                {
                    targets.Add(target);
                }
            }
        }

        return targets;
    }

    private static ExceptionHandlerInfo ByName(uint handlerRva, string name, string evidence, bool namedByPdb = false)
    {
        var kind = name switch
        {
            "__C_specific_handler" or "_C_specific_handler" or "__C_specific_handler_noexcept" => ExceptionHandlerKind.CSpecific,
            // msvcrt.dll's older name for the FH3-format handler.
            "__CxxFrameHandler3" or "__CxxFrameHandler" => ExceptionHandlerKind.CxxFrameHandler3,
            "__CxxFrameHandler4" => ExceptionHandlerKind.CxxFrameHandler4,
            "__GSHandlerCheck" => ExceptionHandlerKind.GsCookieCheck,
            _ => ExceptionHandlerKind.Unknown,
        };
        return new ExceptionHandlerInfo(handlerRva, kind, name, evidence, namedByPdb);
    }

    /// <summary>
    /// The MSVC <c>__GSHandlerCheck</c> body, exactly:
    /// <code>
    /// sub rsp,N / mov r8,[r9+38h] / mov rcx,rdx / mov rdx,r9 /
    /// call __GSHandlerCheckCommon / mov eax,1 / add rsp,N / ret
    /// </code>
    /// It passes (EstablisherFrame, DispatcherContext, HandlerData) to one helper and always
    /// returns ExceptionContinueSearch: it never transfers control anywhere the handler data
    /// could name. The helper compares the frame's stack cookie; its data is a frame offset.
    /// </summary>
    private static bool IsGsHandlerCheck(Instruction[]? code)
    {
        if (code is not { Length: 8 } ||
            code[0] is not { Mnemonic: Mnemonic.Sub, Op0Register: Register.RSP } ||
            !IsImmediate(code[0].Op1Kind))
        {
            return false;
        }

        ulong frameSize = code[0].GetImmediate(1);
        bool loadsHandlerData = code[1] is
        {
            Mnemonic: Mnemonic.Mov, Op0Register: Register.R8, Op1Kind: OpKind.Memory,
            MemoryBase: Register.R9, MemoryIndex: Register.None,
        } && code[1].MemoryDisplacement64 == DispatcherContextHandlerData;

        // EstablisherFrame (rdx) must reach rcx before rdx is overwritten with DispatcherContext.
        bool movesArguments = IsRegMove(code[2], Register.RCX, Register.RDX) && IsRegMove(code[3], Register.RDX, Register.R9);

        return loadsHandlerData && movesArguments &&
               code[4].IsCallNear &&
               code[5] is { Mnemonic: Mnemonic.Mov, Op0Register: Register.EAX, Op1Kind: OpKind.Immediate32, Immediate32: 1 } &&
               code[6] is { Mnemonic: Mnemonic.Add, Op0Register: Register.RSP } && IsImmediate(code[6].Op1Kind) &&
               code[6].GetImmediate(1) == frameSize &&
               code[7].Mnemonic == Mnemonic.Ret;
    }

    private static bool IsImmediate(OpKind kind) => kind is OpKind.Immediate8to64 or OpKind.Immediate32to64;

    private static bool IsRegMove(in Instruction instruction, Register destination, Register source) =>
        instruction is { Mnemonic: Mnemonic.Mov, Op0Kind: OpKind.Register, Op1Kind: OpKind.Register } &&
        instruction.Op0Register == destination && instruction.Op1Register == source;

    private static Instruction[]? DecodeAt(BinaryImage image, IArchitecture architecture, uint rva, int count)
    {
        var code = image.ReadFrom(rva);
        if (code.IsEmpty || image.FindSection(rva) is not { IsExecutable: true })
        {
            return null;
        }

        var decoder = architecture.CreateDecoder(code[..Math.Min(code.Length, count * 15)], rva);
        var result = new Instruction[count];
        for (int i = 0; i < count; i++)
        {
            if (!decoder.TryDecodeNext(out result[i]) || result[i].IsInvalid)
            {
                return null;
            }
        }

        return result;
    }

    private static uint? ReadU32(BinaryImage image, uint rva)
    {
        var data = image.ReadFrom(rva).Span;
        return data.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data) : null;
    }

    /// <summary>SCOPE_TABLE: u32 Count, then Count × { BeginAddress, EndAddress, HandlerAddress, JumpTarget }.</summary>
    private static List<ScopeEntry>? TryReadScopeTable(BinaryImage image, uint dataRva)
    {
        var data = image.ReadFrom(dataRva).Span;
        if (data.Length < 4)
        {
            return null;
        }

        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (count == 0 || count > MaxScopeEntries || data.Length < 4 + count * 16)
        {
            return null;
        }

        var entries = new List<ScopeEntry>((int)count);
        for (int i = 0; i < count; i++)
        {
            var record = data.Slice(4 + i * 16, 16);
            entries.Add(new ScopeEntry(
                BinaryPrimitives.ReadUInt32LittleEndian(record),
                BinaryPrimitives.ReadUInt32LittleEndian(record[4..]),
                BinaryPrimitives.ReadUInt32LittleEndian(record[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(record[12..])));
        }

        return entries;
    }
}
