using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// The safety gate's NativeAOT check (DesignDoc R5, "NativeAOT survey", item 2). A managed method's
/// UNWIND_INFO has no handler flag, but runtime data follows it: an UnwindBlockFlags byte (funclet
/// kind, has-EH-info, ...), optional EH-info and associated-data RVAs, then the GC info. GC info and
/// EH clauses are keyed by offsets from the method start, so a byte copy keeps them valid and anything
/// that re-encodes or splits the method (<c>--rebuild</c>, <c>--blocks</c>) silently breaks them:
/// managed methods are at most <see cref="Transformability.RelocatableOnly"/> (<c>gc-info</c>).
/// Funclets and their parents are <see cref="Transformability.Frozen"/>: the runtime finds a handler
/// at the parent's start plus the clause's handler offset and walks back from a funclet's .pdata entry
/// to its parent's, so neither can move alone. The image-level blockers (one registered managed-code
/// range, verified at run time) are the rewriters' business: they refuse NativeAOT images outright.
/// </summary>
internal static class NativeAotGate
{
    public const string DebugHeaderExport = "DotNetRuntimeDebugHeader";

    private const byte FuncKindMask = 0x03; // UBF_FUNC_KIND_MASK: 0 root, 1 handler, 2 filter
    private const byte UnwFlagHandlers = 0x03; // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER
    private const byte UnwFlagChainInfo = 0x04;

    [ThreadStatic]
    private static InstructionInfoFactory? infoFactory;

    public static void Run(BinaryImage image)
    {
        if (!image.Exports.Any(e => e.Name == DebugHeaderExport && !e.IsForwarder))
        {
            return;
        }

        var info = FromSymbols(image) ?? FromRegistrationCall(image)
            ?? new NativeAotInfo(ManagedRangeSource.Unknown, 0, 0,
                $"{DebugHeaderExport} export; no __managedcode_a/z symbols and no RhRegisterOSModule call found");
        image.NativeAot = info;

        if (info.Source == ManagedRangeSource.Unknown)
        {
            // Without the range, a trailing UnwindBlockFlags byte cannot be told from whatever follows
            // a native UNWIND_INFO: freeze everything.
            foreach (var function in image.Functions)
            {
                function.Downgrade(Transformability.Frozen,
                    "gc-info: NativeAOT image whose managed-code range is unknown; any function may carry GC and EH info after its UNWIND_INFO");
            }

            info.ManagedFunctions = image.Functions.Count;
            return;
        }

        // Funclet kinds of the managed .pdata entries, in .pdata order (the order the runtime walks back in).
        var entries = image.ExceptionData
            .Where(e => !e.IsChained && info.IsManaged(e.BeginAddress))
            .OrderBy(e => e.BeginAddress)
            .ToList();
        var kinds = entries.ToDictionary(e => e.BeginAddress, e => FuncletKind(image, e));
        var parentOf = new Dictionary<uint, uint>();
        uint? root = null;
        foreach (var entry in entries)
        {
            if (kinds[entry.BeginAddress] == 0)
            {
                root = entry.BeginAddress;
            }
            else if (root is { } parent)
            {
                parentOf[entry.BeginAddress] = parent;
            }
        }

        var parents = parentOf.Values.ToHashSet();
        foreach (var function in image.Functions)
        {
            uint entry = function.EntryRva;
            if (!info.IsManaged(entry))
            {
                continue;
            }

            info.ManagedFunctions++;
            if (!kinds.TryGetValue(entry, out int kind))
            {
                function.Downgrade(Transformability.RelocatableOnly,
                    $"gc-info: in the NativeAOT managed-code range [0x{info.ManagedStart:X}, 0x{info.ManagedEnd:X}) without a .pdata entry of its own");
            }
            else if (kind != 0)
            {
                info.FuncletFunctions++;
                string parent = parentOf.TryGetValue(entry, out uint p) ? $"0x{p:X}" : "none found";
                function.Downgrade(Transformability.Frozen,
                    $"gc-info: NativeAOT funclet (UnwindBlockFlags kind {(kind < 0 ? "unreadable" : kind.ToString())}, parent {parent}); " +
                    "the runtime finds it at a fixed offset from its parent's start and walks back to the parent's .pdata entry");
            }
            else if (parents.Contains(entry))
            {
                info.FuncletFunctions++;
                function.Downgrade(Transformability.Frozen,
                    "gc-info: NativeAOT method with funclets, which the runtime finds at fixed offsets from its start; " +
                    "the method and its funclets cannot move apart");
            }
            else
            {
                function.Downgrade(Transformability.RelocatableOnly,
                    "gc-info: NativeAOT managed method; GC info and EH clauses after its UNWIND_INFO are keyed by offsets from its start, " +
                    "so it can only move as a byte copy (re-encoding or splitting would need a GC-info encoder)");
            }
        }
    }

    /// <summary>
    /// UnwindBlockFlags' funclet kind (0 root, 1 handler, 2 filter) of a managed .pdata entry, or -1
    /// when the UNWIND_INFO cannot be read or is native-shaped (handler or chain flag), which counts as
    /// not a root.
    /// </summary>
    private static int FuncletKind(BinaryImage image, ExceptionInfo entry)
    {
        if ((entry.UnwindInfoAddress & 1) != 0)
        {
            return -1;
        }

        var bytes = image.ReadFrom(entry.UnwindInfoAddress).Span;
        if (bytes.Length < 4)
        {
            return -1;
        }

        int flags = bytes[0] >> 3;
        if ((flags & (UnwFlagHandlers | UnwFlagChainInfo)) != 0)
        {
            return -1;
        }

        // Right after the codes: without a handler there is no even-count padding (the runtime's
        // GetUnwindDataBlob aligns only before a handler RVA). Read padded, every parent of a funclet
        // would also have to carry UBF_FUNC_HAS_EHINFO, and on aotbench 920 would not.
        int offset = 4 + 2 * bytes[2];
        return offset < bytes.Length ? bytes[offset] & FuncKindMask : -1;
    }

    private static NativeAotInfo? FromSymbols(BinaryImage image)
    {
        uint? Find(string name) => image.Symbols
            .FirstOrDefault(s => s.Name == name || s.Name.StartsWith($"?{name}@@", StringComparison.Ordinal))?.Rva;

        return Find("__managedcode_a") is { } start && Find("__managedcode_z") is { } end && Valid(image, start, end)
            ? new NativeAotInfo(ManagedRangeSource.PdbSymbols, start, end, "__managedcode_a/z from the PDB")
            : null;
    }

    /// <summary>
    /// Native startup code registers the managed range with
    /// <c>RhRegisterOSModule(module, __managedcode_a, z - a, __unbox_a, unbox_z - unbox_a, ...)</c>:
    /// in one block before a call, <c>rdx</c> holds <c>lea [rip+a]</c> and <c>r8</c> holds
    /// <c>lea [rip+z]</c> minus <c>rdx</c>, both code addresses. Accepted only when exactly one such
    /// range exists in the image.
    /// </summary>
    private static NativeAotInfo? FromRegistrationCall(BinaryImage image)
    {
        var factory = infoFactory ??= new InstructionInfoFactory();
        var found = new Dictionary<(uint Start, uint End), uint>();
        var address = new Dictionary<Register, uint>();
        var length = new Dictionary<Register, (uint Start, uint End)>();

        foreach (var function in image.Functions)
        {
            foreach (var block in function.BasicBlocks)
            {
                address.Clear();
                length.Clear();
                foreach (ref readonly var instruction in image.Instructions.Slice(block.InstructionStart, block.InstructionCount))
                {
                    if (instruction.FlowControl == FlowControl.Call)
                    {
                        if (address.TryGetValue(Register.RDX, out uint a) && length.TryGetValue(Register.R8, out var range) && range.Start == a)
                        {
                            found.TryAdd(range, (uint)instruction.IP);
                        }

                        address.Clear();
                        length.Clear();
                        continue;
                    }

                    var target = instruction.Op0Kind == OpKind.Register ? instruction.Op0Register.GetFullRegister() : Register.None;
                    if (instruction.Mnemonic == Mnemonic.Lea && instruction.IsIPRelativeMemoryOperand &&
                        image.FindSection((uint)instruction.IPRelativeMemoryAddress) is { IsExecutable: true })
                    {
                        length.Remove(target);
                        address[target] = (uint)instruction.IPRelativeMemoryAddress;
                        continue;
                    }

                    if (instruction.Mnemonic == Mnemonic.Sub && instruction.Op1Kind == OpKind.Register &&
                        address.TryGetValue(target, out uint end) && address.TryGetValue(instruction.Op1Register.GetFullRegister(), out uint start) &&
                        instruction.Op0Register.GetSize() >= 4 && instruction.Op0Register.GetSize() == instruction.Op1Register.GetSize())
                    {
                        address.Remove(target);
                        length[target] = (start, end);
                        continue;
                    }

                    foreach (var used in factory.GetInfo(instruction).GetUsedRegisters())
                    {
                        if (used.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
                        {
                            address.Remove(used.Register.GetFullRegister());
                            length.Remove(used.Register.GetFullRegister());
                        }
                    }
                }
            }
        }

        var valid = found.Where(f => Valid(image, f.Key.Start, f.Key.End)).ToList();
        return valid.Count == 1
            ? new NativeAotInfo(ManagedRangeSource.RegistrationCall, valid[0].Key.Start, valid[0].Key.End,
                $"RhRegisterOSModule call at 0x{valid[0].Value:X}")
            : null;
    }

    private static bool Valid(BinaryImage image, uint start, uint end) =>
        start < end && image.FindSection(start) is { IsExecutable: true } section && end <= section.Rva + section.MappedSize;
}
