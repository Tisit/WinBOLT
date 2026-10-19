using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>The control flow graph a function's builder has decoded so far, seen backward.</summary>
internal interface IControlFlow
{
    /// <summary>
    /// The instructions that can execute immediately before the one at <paramref name="ip"/>, and
    /// whether each got there by its branch (<c>Taken</c>) rather than by falling through. Null
    /// when control can also arrive from outside the known graph: a function entry, an exception
    /// or code-pointer root, or a table target no recovered table explains.
    /// </summary>
    IReadOnlyList<(Instruction Instruction, bool Taken)>? Predecessors(uint ip);
}

/// <summary>
/// Recognizes MSVC x64 switch dispatch (§5.2) by a requirement-driven backward walk over every
/// control flow path into <c>jmp reg</c>:
/// <code>
/// cmp   idx, N            ; unsigned bound: ja/jae falling through, or jbe/jb taken
/// ja    default
/// lea   b1, [rip → 0]     ; __ImageBase, anywhere earlier on the path, possibly another register
/// movzx idx, byte [b2 + j + indexTable]        ; two-level form only (the bound is then on j)
/// mov   r32, [b3 + idx*4 + table]              ; image-relative dword entry
/// add   r, b4
/// jmp   r
/// </code>
/// Requirements: the jump register is <c>add r, b</c> of a dword table load; every base register
/// used (b1..b4) is proven to hold <c>__ImageBase</c> by its nearest earlier write being
/// <c>lea b,[rip → 0]</c>; the index reaching the load is bounded by an unsigned compare,
/// following register copies, in-place sign extension (<c>cdqe</c>, <c>movsxd</c>) and
/// <c>lea idx,[x + c]</c>; if the compare is on a different register than the index, it must be
/// a copy of it (or the same <c>x + c</c>) with neither rewritten in between; a compare on an 8-
/// or 16-bit register also needs the register's upper bits proven zero. The index may also be
/// a rounded size, <c>((x + c) &amp; mask) >> k</c> (the CRT's memmove: <c>lea r9,[r8+1Fh]</c>,
/// <c>and r9,-20h</c>, <c>shr r11,5</c>): the bound on x then bounds the index arithmetically.
/// <para>
/// Every path must discharge every requirement. Paths fork at joins; a path reaching a state it
/// has already visited is dropped (it went round a loop that writes nothing the proof needs, so
/// the other paths decide); a path reaching an unknown entry with requirements open fails the
/// proof. Paths may bound the index differently: the table extent is the largest bound. The
/// caller re-runs the proof once the graph is complete, because case blocks reached only through
/// the table can branch back into the dispatch sequence.
/// </para>
/// Anything that does not fit is a failure with a reason, never a guess.
/// </summary>
internal static class JumpTableRecovery
{
    private const int MaxDepth = 128;
    private const int MaxStates = 20_000;
    private const int MaxEntries = 4096;
    private const int MaxBetween = 8;

    public sealed record Result(JumpTable? Table, string? Failure);

    // iced's factory reuses internal buffers: one per thread (analyses may run concurrently, e.g. in tests).
    [ThreadStatic]
    private static InstructionInfoFactory? infoFactory;

    /// <summary>Table-relative base <c>lea</c>s met on any explored path of the current proof.</summary>
    [ThreadStatic]
    private static HashSet<uint>? baseSites;

    /// <summary>
    /// What a path still has to prove, walking backward. <see cref="Stage"/> 0 wants
    /// <c>add target, base</c>, 1 the dword load, 2 is past the load. The index is a register, or
    /// <see cref="IndexBase"/> + <see cref="IndexOffset"/> after a <c>lea</c>. After the bound,
    /// <see cref="Compared"/> must equal <see cref="EqualTo"/> + <see cref="EqualOffset"/> and
    /// <see cref="UpperZero"/> must have its bits above <see cref="UpperBits"/> clear. A rounded
    /// index is <c>((Index + Add) &amp; Mask) >> Shift</c> (Mask 0: none), met backward in that
    /// order: shifts, then masks, then adds. <see cref="Signed"/>: the entry load is <c>movsxd</c> (LLVM's table-relative form, entries relative to <see cref="BaseRva"/>, the address the base registers' <c>lea</c> loads; 0 is <c>__ImageBase</c>). <see cref="IndexBits"/> non-zero: the index is the
    /// zero-extended low bits of <see cref="Index"/> (<c>movzx eax, al</c> after the compare), so a
    /// compare on those bits bounds it without the upper bits.
    /// </summary>
    private readonly record struct State(
        int Stage,
        Register Target,
        ushort NeedBase,
        Register Index,
        Register IndexBase,
        int IndexOffset,
        bool Bounded,
        long Count,
        Register Compared,
        Register EqualTo,
        int EqualOffset,
        Register UpperZero,
        int UpperBits,
        uint Table,
        uint IndexTable,
        bool TwoLevel,
        uint Load,
        uint IndexLoad,
        int Shift = 0,
        ulong Mask = 0,
        uint Add = 0,
        int IndexBits = 0,
        bool Signed = false,
        bool BaseSeen = false,
        uint BaseRva = 0,
        bool Unbounded = false)
    {
        public bool Rounded => Shift != 0 || Mask != 0;

        // A table with no bound on the code's paths is accepted only in LLVM's signed table-relative
        // form, where a default-less switch is what the compiler emits. MSVC always bounds its
        // tables, so an unproven bound there is a gap in this analysis, not a property of the code.
        public bool Done => Stage == 2 && NeedBase == 0 &&
                            ((Unbounded && Signed) || (Bounded && Compared == Register.None && UpperZero == Register.None));
    }

    /// <param name="inFunction">Whether an address lies inside the function being built.</param>
    /// <param name="nextObject">
    /// The first data address above the argument that the function references (another table's
    /// base, say), or null. Used only for a switch with no bound check: the table then extends to
    /// the first entry that does not target the function, or to that address.
    /// </param>
    public static Result TryRecover(BinaryImage image, in Instruction jump, IControlFlow flow, Func<uint, bool> inFunction, Func<uint, uint?>? nextObject = null)
    {
        var bounded = TryRecover(image, jump, flow, inFunction, nextObject, unbounded: false);
        if (bounded.Table is not null || nextObject is null)
        {
            return bounded;
        }

        // No bound on the paths: the extent comes from the data, but the base, the load and the
        // add must still be proven, or nothing is claimed.
        return TryRecover(image, jump, flow, inFunction, nextObject, unbounded: true) is { Table: not null } inferred ? inferred : bounded;
    }

    private static Result TryRecover(BinaryImage image, in Instruction jump, IControlFlow flow, Func<uint, bool> inFunction, Func<uint, uint?>? nextObject, bool unbounded)
    {
        if (jump.Op0Kind != OpKind.Register)
        {
            return Fail("jump through memory");
        }

        var start = new State(0, jump.Op0Register.GetFullRegister(), 0, Register.None, Register.None, 0, false, 0,
            Register.None, Register.None, 0, Register.None, 0, 0, 0, false, 0, 0, Unbounded: unbounded);
        baseSites = [];
        var work = new Stack<(uint At, State State, int Depth)>();
        var visited = new HashSet<(uint, State)>();
        work.Push(((uint)jump.IP, start, 0));
        State? proven = null;
        long count = 0;

        while (work.TryPop(out var item))
        {
            if (!visited.Add((item.At, item.State)))
            {
                continue;
            }

            if (visited.Count > MaxStates)
            {
                return Fail("too many paths into the dispatch");
            }

            if (item.Depth > MaxDepth)
            {
                return Fail($"pattern not found within reach of 0x{jump.IP:X}");
            }

            if (flow.Predecessors(item.At) is not { Count: > 0 } predecessors)
            {
                return Fail(item.State.Stage < 2
                    ? $"control enters the dispatch sequence at 0x{item.At:X} from outside the known flow"
                    : $"a path reaches 0x{item.At:X}, an entry from outside the known flow, before {Missing(item.State)}");
            }

            foreach (var (instruction, taken) in predecessors)
            {
                var (next, failure) = Step(instruction, taken, item.State, flow, out uint resume);
                if (failure is not null)
                {
                    return Fail(failure);
                }

                if (next.Done)
                {
                    // All paths must agree on everything but the bound.
                    if (proven is { } p && (p.Table, p.TwoLevel, p.IndexTable, p.Load, p.IndexLoad, p.BaseRva) != (next.Table, next.TwoLevel, next.IndexTable, next.Load, next.IndexLoad, next.BaseRva))
                    {
                        return Fail($"paths into 0x{jump.IP:X} dispatch through different tables or loads");
                    }

                    if (next.Unbounded && next.TwoLevel)
                    {
                        return Fail($"the two-level form at 0x{jump.IP:X} has no bound check");
                    }

                    if (next.Signed && next.TwoLevel)
                    {
                        return Fail($"the two-level form at 0x{jump.IP:X} uses a table-relative base");
                    }

                    proven = next;
                    count = Math.Max(count, next.Count);
                    continue;
                }

                work.Push((resume, next, item.Depth + 1));
            }
        }

        return proven is { } result
            ? ReadTables(image, (uint)jump.IP, result.Signed ? result.BaseRva + result.Table : result.Table, result.Signed ? result.BaseRva : null, result.TwoLevel ? result.IndexTable : null, (int)count, inFunction, result.Load, result.TwoLevel ? result.IndexLoad : null, unbounded ? nextObject : null, unbounded)
            : Fail("pattern not found within reach");
    }

    private static string Missing(State state) => state switch
    {
        { Stage: < 2 } => "the table load",
        { NeedBase: not 0 } => $"{BaseRegisters(state.NeedBase)} is proven to be __ImageBase",
        { Bounded: false } => "the index is bounded",
        { Compared: not Register.None } => $"the compared {state.Compared} is linked to the index",
        _ => $"{state.UpperZero}'s upper bits are proven zero",
    };

    /// <summary>
    /// Walks back over one predecessor: the state before it, or a failure. <paramref name="resume"/>
    /// is where the walk continues (the instruction itself, or the <c>cmp</c> of a bound check).
    /// </summary>
    private static (State, string?) Step(in Instruction instruction, bool taken, State s, IControlFlow flow, out uint resume)
    {
        uint at = (uint)instruction.IP;
        resume = at;
        var writes = Writes(instruction);

        // A call clobbers the volatile registers without iced listing them as written.
        if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall &&
            Live(s).FirstOrDefault(IsVolatile) is var clobbered && clobbered != Register.None)
        {
            return (s, $"call at 0x{at:X} clobbers {clobbered}, which the dispatch relies on");
        }

        // Jump register: add, then the load that feeds it.
        if (s.Stage < 2 && writes.Contains(s.Target))
        {
            if (s.Stage == 0)
            {
                if (instruction is not { Mnemonic: Mnemonic.Add, Op0Kind: OpKind.Register, Op1Kind: OpKind.Register } ||
                    instruction.Op0Register.GetFullRegister() != s.Target)
                {
                    return (s, $"0x{at:X} writes the jump register but is not 'add reg, base'");
                }

                return (s with { Stage = 1, NeedBase = With(s.NeedBase, instruction.Op1Register.GetFullRegister()) }, null);
            }

            if (instruction is not { Mnemonic: Mnemonic.Mov or Mnemonic.Movsxd, Op0Kind: OpKind.Register, Op1Kind: OpKind.Memory, MemoryIndexScale: 4 } ||
                instruction.MemorySize is not (MemorySize.UInt32 or MemorySize.Int32) ||
                (instruction.Mnemonic == Mnemonic.Movsxd && instruction.Op0Register.GetSize() != 8) ||
                instruction.MemoryBase == Register.None || instruction.MemoryIndex == Register.None)
            {
                return (s, $"0x{at:X} does not load a dword from [base + index*4 + table]");
            }

            bool signed = instruction.Mnemonic == Mnemonic.Movsxd;
            if (s.BaseSeen && signed != (s.BaseRva != 0))
            {
                return (s, $"the entry load at 0x{at:X} is {(signed ? "signed" : "unsigned")}, but the base is {(s.BaseRva != 0 ? "a table address" : "__ImageBase")}");
            }

            return (s with
            {
                Signed = signed,
                Stage = 2,
                NeedBase = With(s.NeedBase, instruction.MemoryBase.GetFullRegister()),
                Index = instruction.MemoryIndex.GetFullRegister(),
                Table = (uint)instruction.MemoryDisplacement64,
                Load = at,
            }, null);
        }

        // Base registers: the nearest earlier write must be lea reg,[rip → 0].
        foreach (var register in writes)
        {
            if (Has(s.NeedBase, register))
            {
                if (instruction is not { Mnemonic: Mnemonic.Lea } || !instruction.IsIPRelativeMemoryOperand)
                {
                    return (s, $"base register {register} is not __ImageBase or a table address (written at 0x{at:X})");
                }

                // Address 0 is __ImageBase (unsigned image-relative entries); anything else is the
                // base of LLVM's signed table-relative entries. Every base must agree.
                uint address = (uint)instruction.IPRelativeMemoryAddress;
                if ((s.BaseSeen && s.BaseRva != address) || (address != 0 && s.Stage < 2) ||
                    (s.Stage == 2 && s.Signed != (address != 0)))
                {
                    return (s, $"base register {register} (0x{at:X}) does not match the other bases or the entry load");
                }

                if (address != 0)
                {
                    baseSites?.Add(at);
                }

                s = s with { NeedBase = Without(s.NeedBase, register), BaseSeen = true, BaseRva = address };
            }
        }

        if (s.Stage < 2)
        {
            return (s, null);
        }

        if (s.Unbounded)
        {
            return (s, null);
        }

        if (!s.Bounded)
        {
            if (instruction.FlowControl == FlowControl.ConditionalBranch)
            {
                return BoundCheck(instruction, taken, s, flow, ref resume);
            }

            if (s.Index != Register.None && writes.Contains(s.Index))
            {
                return FollowIndex(instruction, s) is { } followed ? (followed, null) : (s, $"index register is computed at 0x{at:X} in an unrecognized way ({instruction})");
            }

            if (s.IndexBase != Register.None && writes.Contains(s.IndexBase))
            {
                return (s, $"0x{at:X} rewrites {s.IndexBase}, which the index was computed from, before the bound check");
            }

            return (s, null);
        }

        // Compared register and index differ: the compared value must be the index's value.
        if (s.Compared != Register.None && (writes.Contains(s.Compared) || writes.Contains(s.EqualTo)))
        {
            bool linked = writes.Contains(s.Compared)
                ? (s.EqualOffset == 0 && IsCopy(instruction, s.Compared, s.EqualTo)) || IsLea(instruction, s.Compared, s.EqualTo, s.EqualOffset)
                : s.EqualOffset == 0 && IsCopy(instruction, s.EqualTo, s.Compared);
            if (!linked)
            {
                return (s, $"bound check is on {s.Compared}, but 0x{at:X} breaks its link to the index");
            }

            s = s with { Compared = Register.None, EqualTo = Register.None, EqualOffset = 0 };
        }

        if (s.UpperZero != Register.None && writes.Contains(s.UpperZero))
        {
            if (!ZeroExtends(instruction, s.UpperZero, s.UpperBits))
            {
                return (s, $"the bound is on the low {s.UpperBits} bits of {s.UpperZero}, but 0x{at:X} does not clear the rest");
            }

            s = s with { UpperZero = Register.None, UpperBits = 0 };
        }

        return (s, null);
    }

    /// <summary>
    /// An unsigned bound: <c>cmp reg, N</c> then <c>ja</c>/<c>jae</c> not taken, or <c>jbe</c>/<c>jb</c>
    /// taken. A compare of the index that does not bound it on this edge fails the proof (the
    /// path carries an unchecked index); other conditional branches are passed through.
    /// </summary>
    private static (State, string?) BoundCheck(in Instruction branch, bool taken, State s, IControlFlow flow, ref uint resume)
    {
        uint at = (uint)branch.IP;

        // Schedulers put flag-neutral instructions (lea, mov) between the compare and its branch.
        var between = new List<Instruction>();
        Instruction compare = default;
        uint cursor = at;
        for (int i = 0; i <= MaxBetween; i++)
        {
            if (flow.Predecessors(cursor) is not [(var previous, false)])
            {
                return (s, null);
            }

            if (previous.Mnemonic == Mnemonic.Cmp)
            {
                compare = previous;
                break;
            }

            if (previous.RflagsModified != RflagsBits.None || previous.FlowControl != FlowControl.Next || i == MaxBetween)
            {
                return (s, null);
            }

            between.Add(previous);
            cursor = (uint)previous.IP;
        }

        if (compare is not { Op0Kind: OpKind.Register } ||
            compare.Op1Kind is not (OpKind.Immediate8 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32 or OpKind.Immediate32to64))
        {
            return (s, null);
        }

        var compared = compare.Op0Register.GetFullRegister();
        bool ofIndex = compared == s.Index || compared == s.IndexBase;
        // Equality pins the value: jne not taken or je taken, index == N.
        bool equal = (branch.Mnemonic == Mnemonic.Jne && !taken) || (branch.Mnemonic == Mnemonic.Je && taken);
        bool bounds = equal || (branch.Mnemonic is Mnemonic.Ja or Mnemonic.Jae && !taken) || (branch.Mnemonic is Mnemonic.Jbe or Mnemonic.Jb && taken);
        if (!bounds)
        {
            return ofIndex
                ? (s, $"bound check at 0x{at:X} is not an unsigned ja/jae (or a taken jbe/jb) on this path")
                : (s, null);
        }

        ulong n = compare.GetImmediate(1);
        long count = equal || branch.Mnemonic is Mnemonic.Ja or Mnemonic.Jbe ? (long)n + 1 : (long)n;
        if (s.Rounded && n <= uint.MaxValue && count > 0)
        {
            // Largest index: the transformation is monotone in x (add without overflow, and-mask
            // at most its input, shift), so it is reached at the largest x.
            ulong largest = ((ulong)(count - 1) + s.Add) & (s.Mask == 0 ? ulong.MaxValue : s.Mask);
            count = (long)(largest >> s.Shift) + 1;
        }

        if (n > (ulong)MaxEntries << (s.Rounded ? Math.Min(s.Shift, 16) : 0) || count <= 0 || count > MaxEntries)
        {
            return (s, $"implausible bound {n}");
        }

        // The instructions between compare and branch must leave the compared value and the index
        // alone; the rest of their effect (a base register's lea) is applied as on any other path.
        foreach (var skipped in between)
        {
            var written = Writes(skipped);
            if (written.Contains(compared) || written.Contains(s.Index) || (s.IndexBase != Register.None && written.Contains(s.IndexBase)))
            {
                return (s, $"0x{skipped.IP:X} rewrites the compared value between the compare and its branch at 0x{at:X}");
            }

            var (stepped, failure) = Step(skipped, false, s, flow, out _);
            if (failure is not null)
            {
                return (s, failure);
            }

            s = stepped;
        }

        resume = (uint)compare.IP;
        int bits = compare.Op0Register.GetSize() * 8;
        var bounded = s with { Bounded = true, Count = count };
        if (s.Index != compared || s.IndexBase != Register.None)
        {
            bounded = s.IndexBase != Register.None
                ? bounded with { Compared = compared, EqualTo = s.IndexBase, EqualOffset = s.IndexOffset }
                : bounded with { Compared = compared, EqualTo = s.Index, EqualOffset = 0 };
        }

        if (bits < 32 && !(s.IndexBits != 0 && compared == s.Index && bits >= s.IndexBits))
        {
            bounded = bounded with { UpperZero = compared, UpperBits = bits };
        }

        return (bounded, null);
    }

    /// <summary>Registers the path still needs unchanged across a call.</summary>
    private static IEnumerable<Register> Live(State s)
    {
        if (s.Stage < 2)
        {
            yield return s.Target;
        }

        for (int i = 0; i < 16; i++)
        {
            if ((s.NeedBase & (1 << i)) != 0)
            {
                yield return Register.RAX + i;
            }
        }

        if (!s.Bounded && !s.Unbounded)
        {
            yield return s.Index;
            yield return s.IndexBase;
        }

        yield return s.Compared;
        yield return s.EqualTo;
        yield return s.UpperZero;
    }

    /// <summary>Caller-saved in the Windows x64 ABI.</summary>
    private static bool IsVolatile(Register register) =>
        register is Register.RAX or Register.RCX or Register.RDX or Register.R8 or Register.R9 or Register.R10 or Register.R11;

    private static ushort With(ushort mask, Register register) => (ushort)(mask | Bit(register));

    private static ushort Without(ushort mask, Register register) => (ushort)(mask & ~Bit(register));

    private static bool Has(ushort mask, Register register) => (mask & Bit(register)) != 0;

    private static int Bit(Register register) => register is >= Register.RAX and <= Register.R15 ? 1 << (register - Register.RAX) : 0;

    private static string BaseRegisters(ushort mask) =>
        string.Join("/", Enumerable.Range(0, 16).Where(i => (mask & (1 << i)) != 0).Select(i => (Register.RAX + i).ToString()));

    private static bool IsCopy(in Instruction instruction, Register destination, Register source) =>
        instruction.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx &&
        instruction is { Op0Kind: OpKind.Register, Op1Kind: OpKind.Register } &&
        instruction.Op0Register.GetFullRegister() == destination &&
        instruction.Op1Register.GetFullRegister() == source;

    /// <summary><c>lea destination, [source + offset]</c> (no index register).</summary>
    private static bool IsLea(in Instruction instruction, Register destination, Register source, int offset) =>
        instruction is { Mnemonic: Mnemonic.Lea, Op0Kind: OpKind.Register, MemoryIndex: Register.None } &&
        instruction.Op0Register.GetFullRegister() == destination &&
        instruction.MemoryBase.GetFullRegister() == source &&
        (int)instruction.MemoryDisplacement64 == offset;

    /// <summary><c>movzx reg, r/m</c> from at most <paramref name="bits"/> bits, or <c>and reg, mask</c> within them.</summary>
    private static bool ZeroExtends(in Instruction instruction, Register register, int bits)
    {
        if (instruction.Op0Kind != OpKind.Register || instruction.Op0Register.GetFullRegister() != register)
        {
            return false;
        }

        if (instruction.Mnemonic == Mnemonic.Movzx)
        {
            int sourceBits = instruction.Op1Kind == OpKind.Register ? instruction.Op1Register.GetSize() * 8 : instruction.MemorySize.GetSize() * 8;
            return sourceBits <= bits && instruction.Op0Register.GetSize() >= 4;
        }

        return instruction.Mnemonic == Mnemonic.And && instruction.Op0Register.GetSize() >= 4 &&
               instruction.Op1Kind is OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 &&
               instruction.GetImmediate(1) < 1UL << bits;
    }

    /// <summary>
    /// A write to the index register before the bound (walking back from the load). The
    /// two-level form's <c>movzx idx, byte [base + j + indexTable]</c> switches tracking to j (and
    /// adds base to the image-base requirements); a register copy switches tracking to the
    /// source; <c>cdqe</c> and <c>movsxd reg, reg32-of-itself</c> extend in place;
    /// <c>lea idx, [x + c]</c> (or <c>add/sub/inc/dec idx</c> in place) makes the index the expression x + c.
    /// </summary>
    private static State? FollowIndex(in Instruction instruction, State s)
    {
        if (instruction is { Mnemonic: Mnemonic.Movzx, Op1Kind: OpKind.Memory, MemorySize: MemorySize.UInt8, MemoryIndexScale: 1 } &&
            !s.TwoLevel && instruction.MemoryBase != Register.None && instruction.MemoryIndex != Register.None)
        {
            // With scale 1 the encoding's base/index order says nothing: the image base is the
            // register the dword load already needs (__GSHandlerCheckCommon: [rax+rbp+table]).
            var (imageBase, index) = (instruction.MemoryBase.GetFullRegister(), instruction.MemoryIndex.GetFullRegister());
            if (Has(s.NeedBase, index) && !Has(s.NeedBase, imageBase))
            {
                (imageBase, index) = (index, imageBase);
            }

            return s with
            {
                TwoLevel = true,
                IndexTable = (uint)instruction.MemoryDisplacement64,
                IndexLoad = (uint)instruction.IP,
                NeedBase = With(s.NeedBase, imageBase),
                Index = index,
            };
        }

        if (instruction.Mnemonic is Mnemonic.Cdqe && s.Index == Register.RAX && !s.Rounded)
        {
            return s;
        }

        // Rounded index, backward: shr, then and, then an add (lea idx,[x + c], c >= 0).
        bool onIndex = instruction.Op0Kind == OpKind.Register && instruction.Op0Register.GetFullRegister() == s.Index &&
                       instruction.Op0Register.GetSize() >= 4 && s.IndexBase == Register.None && !s.TwoLevel;
        if (onIndex && instruction is { Mnemonic: Mnemonic.Shr, Op1Kind: OpKind.Immediate8 } && s.Mask == 0 && s.Add == 0 &&
            s.Shift + instruction.Immediate8 < 32)
        {
            return s with { Shift = s.Shift + instruction.Immediate8 };
        }

        if (onIndex && instruction.Mnemonic == Mnemonic.And && s.Shift != 0 && s.Add == 0 &&
            instruction.Op1Kind is OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64)
        {
            ulong mask = instruction.GetImmediate(1) & (instruction.Op0Register.GetSize() == 4 ? uint.MaxValue : ulong.MaxValue);
            return s with { Mask = s.Mask == 0 ? mask : s.Mask & mask };
        }

        if (s.Rounded && instruction is { Mnemonic: Mnemonic.Lea, Op0Kind: OpKind.Register, MemoryIndex: Register.None } &&
            !instruction.IsIPRelativeMemoryOperand && instruction.MemoryBase != Register.None && s.Add == 0 &&
            instruction.MemoryDisplacement64 < 0x1_0000)
        {
            return s with { Index = instruction.MemoryBase.GetFullRegister(), Add = (uint)instruction.MemoryDisplacement64 };
        }

        if (s.Rounded && s.Add != 0 && instruction.Mnemonic is not (Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx))
        {
            return null;
        }

        if (instruction is { Mnemonic: Mnemonic.Movzx, Op0Kind: OpKind.Register, Op1Kind: OpKind.Register } && !s.Rounded)
        {
            int bits = instruction.Op1Register.GetSize() * 8;
            return s with { Index = instruction.Op1Register.GetFullRegister(), IndexBits = s.IndexBits == 0 ? bits : Math.Min(s.IndexBits, bits) };
        }

        if (instruction.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx &&
            instruction is { Op0Kind: OpKind.Register, Op1Kind: OpKind.Register })
        {
            return s with { Index = instruction.Op1Register.GetFullRegister() };
        }

        if (s.IndexBits != 0)
        {
            return null; // arithmetic on a zero-extended value: not modelled
        }

        if (instruction is { Mnemonic: Mnemonic.Lea, Op0Kind: OpKind.Register, MemoryIndex: Register.None } &&
            !instruction.IsIPRelativeMemoryOperand && instruction.MemoryBase != Register.None && !s.Rounded)
        {
            return s with { Index = Register.None, IndexBase = instruction.MemoryBase.GetFullRegister(), IndexOffset = (int)instruction.MemoryDisplacement64 };
        }

        // The same expression computed in place: add/sub idx, c and inc/dec idx (x is idx's
        // earlier value). MSVC compares a lea copy and adjusts the index itself (IL2CPP:
        // lea ecx,[rax-5]; cmp ecx,7; ja; add eax,-5).
        if (instruction.Op0Kind == OpKind.Register && instruction.Op0Register.GetFullRegister() == s.Index &&
            instruction.Op0Register.GetSize() >= 4 && s.IndexBase == Register.None && !s.Rounded && !s.TwoLevel &&
            InPlaceOffset(instruction) is { } offset)
        {
            return s with { Index = Register.None, IndexBase = s.Index, IndexOffset = offset };
        }

        return null;
    }

    private static int? InPlaceOffset(in Instruction instruction)
    {
        bool immediate = instruction.Op1Kind is OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64;
        long value = immediate ? (long)instruction.GetImmediate(1) : 0;
        return instruction.Mnemonic switch
        {
            Mnemonic.Add when immediate && value is >= int.MinValue and <= int.MaxValue => (int)value,
            Mnemonic.Sub when immediate && value is > int.MinValue and <= int.MaxValue => (int)-value,
            Mnemonic.Inc => 1,
            Mnemonic.Dec => -1,
            _ => null,
        };
    }

    private static Result ReadTables(BinaryImage image, uint site, uint table, uint? relativeTo, uint? indexTable, int count, Func<uint, bool> inFunction, uint load, uint? indexLoad,
        Func<uint, uint?>? nextObject = null, bool inferExtent = false)
    {
        if (inferExtent)
        {
            // The extent is read off the data: entries while they target the function and stay
            // below the next object the function references.
            uint? limit = nextObject?.Invoke(table);
            var raw = image.ReadFrom(table).Span;
            int n = 0;
            while (n < MaxEntries && (n + 1) * 4 <= raw.Length && (limit is not { } stop || table + 4 * (uint)n < stop))
            {
                uint value = BinaryPrimitives.ReadUInt32LittleEndian(raw[(n * 4)..]);
                uint address = relativeTo is { } origin ? (uint)(origin + (long)(int)value) : value;
                if (!inFunction(address))
                {
                    break;
                }

                n++;
            }

            if (n == 0)
            {
                return Fail($"no bound check, and the table at 0x{table:X} has no entry that targets the function");
            }

            count = n;
        }

        int entries = count;
        byte[]? indexes = null;
        if (indexTable is { } byteTable)
        {
            var bytes = image.ReadFrom(byteTable).Span;
            if (bytes.Length < count)
            {
                return Fail($"index table at 0x{byteTable:X} is outside file-backed data");
            }

            indexes = bytes[..count].ToArray();
            entries = indexes.Max() + 1;
        }

        var data = image.ReadFrom(table).Span;
        if (data.Length < entries * 4)
        {
            return Fail($"table at 0x{table:X} is outside file-backed data");
        }

        var result = new JumpTable
        {
            SiteRva = site,
            Rva = table,
            Encoding = relativeTo is not null ? JumpTableEncoding.TableRelativeOffset32 : indexTable is null ? JumpTableEncoding.ImageRelativeOffset32 : JumpTableEncoding.TwoLevelMsvc,
            BaseRva = relativeTo ?? 0,
            ExtentInferred = inferExtent,
            BaseSites = relativeTo is null ? [] : (baseSites ?? []).Order().Select(x => (ulong)x).ToList(),
            EntryCount = entries,
            IndexTableRva = indexTable,
            IndexEntryCount = indexes?.Length ?? 0,
            LoadRva = relativeTo is null ? load : (baseSites ?? []).Min(),
            IndexLoadRva = indexLoad,
        };

        for (int i = 0; i < entries; i++)
        {
            uint target = BinaryPrimitives.ReadUInt32LittleEndian(data[(i * 4)..]);
            if (relativeTo is { } origin)
            {
                target = (uint)(origin + (long)(int)target);
            }

            if (!inFunction(target))
            {
                return Fail($"entry {i} of the table at 0x{table:X} targets 0x{target:X}, outside the function");
            }

            result.TargetRvas.Add(target);
        }

        return new Result(result, null);
    }

    private static HashSet<Register> Writes(in Instruction instruction)
    {
        var writes = new HashSet<Register>();
        foreach (var used in (infoFactory ??= new InstructionInfoFactory()).GetInfo(instruction).GetUsedRegisters())
        {
            if (used.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
            {
                writes.Add(used.Register.GetFullRegister());
            }
        }

        return writes;
    }

    private static Result Fail(string reason) => new(null, reason);
}
