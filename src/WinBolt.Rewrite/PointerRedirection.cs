using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// A place in the original image that yields a function's address: an 8-byte relocated value
/// (<see cref="IsLea"/> false; vtables, pointer tables, <c>mov r64,imm64</c>) or a
/// <c>lea reg,[rip+X]</c> instruction at <see cref="Rva"/>. <see cref="Target"/> is the entry.
/// </summary>
public sealed record PointerSite(uint Rva, bool IsLea, uint Target);

/// <summary>Which moved entries have every pointer to them aimed at the copy, and where those pointers are.</summary>
public sealed class RedirectionPlan
{
    /// <summary>Original entry → copy entry, for every redirected function.</summary>
    public Dictionary<uint, uint> Targets { get; } = [];

    /// <summary>Every site that yields a redirected entry.</summary>
    public List<PointerSite> Sites { get; } = [];

    /// <summary>Moved, pointed-to functions left alone (entry → the first reason found).</summary>
    public Dictionary<uint, string> Excluded { get; } = [];

    /// <summary>Set when the image as a whole does not allow redirection.</summary>
    public string? Refused { get; set; }
}

/// <summary>
/// Aims pointers to moved functions at their copies, so indirect calls skip the trampoline
/// (DesignDoc Step 11: the cost is small in C, larger in C++ with virtual calls).
/// <para>
/// A function pointer must keep one value (§6.1): a comparison must never see the original
/// and the copy. So a function is redirected only if every way the image can form its address
/// is known and patched: relocated 64-bit values and RIP-relative <c>lea</c> in decoded code.
/// Anything else excludes it: a 32-bit RVA of it anywhere (data tables, immediates,
/// displacements; also the export table, a CFG table, catchable-type copy constructors), a
/// possible RIP-relative reference in bytes the analysis did not decode (every such operand has
/// ModRM mod=00 rm=101 right before its disp32, so the scan is exhaustive), other RIP-relative
/// operands, 32-bit absolute relocations, and callers from outside the image (exports, the entry
/// point, TLS callbacks, exception handlers and funclets). The image must have relocations and
/// be DYNAMIC_BASE, so that no absolute pointer exists without a relocation.
/// </para>
/// </summary>
public static class PointerRedirection
{
    private const ushort DynamicBase = 0x0040;

    public static RedirectionPlan Plan(BinaryImage image, IReadOnlyDictionary<uint, uint> copyOf)
    {
        var plan = new RedirectionPlan();
        if ((image.DllCharacteristics & DynamicBase) == 0 || image.Relocations.Count == 0)
        {
            plan.Refused = "the image is not DYNAMIC_BASE with base relocations: absolute pointers need not have a relocation";
            return plan;
        }

        var excluded = new Dictionary<uint, string>();
        void Exclude(uint entry, string reason)
        {
            if (copyOf.ContainsKey(entry))
            {
                excluded.TryAdd(entry, reason);
            }
        }

        // Callers from outside the image, which see the original address.
        foreach (var export in image.Exports)
        {
            Exclude(export.Rva, "exported");
        }

        Exclude(image.EntryPointRva, "entry point");
        foreach (uint callback in image.TlsCallbacks)
        {
            Exclude(callback, "TLS callback");
        }

        foreach (uint handler in image.ExceptionHandlers.Keys)
        {
            Exclude(handler, "exception handler");
        }

        foreach (var f in image.Functions.Where(f => f.DiscoveredBy.HasFlag(DiscoverySource.ExceptionTable)))
        {
            Exclude(f.EntryRva, "exception funclet");
        }

        // Relocated values.
        var sites = new Dictionary<uint, PointerSite>();
        foreach (var relocation in image.Relocations)
        {
            var slot = image.ReadFrom(relocation.Rva).Span;
            if (relocation.Type == RelocationType.Dir64 && slot.Length >= 8)
            {
                ulong va = BinaryPrimitives.ReadUInt64LittleEndian(slot);
                if (va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage && copyOf.ContainsKey((uint)(va - image.ImageBase)))
                {
                    sites[relocation.Rva] = new PointerSite(relocation.Rva, false, (uint)(va - image.ImageBase));
                }
            }
            else if (relocation.Type == RelocationType.HighLow && slot.Length >= 4)
            {
                Exclude(BinaryPrimitives.ReadUInt32LittleEndian(slot) - (uint)image.ImageBase, "32-bit absolute relocation");
            }
        }

        // Decoded code: lea sites; any other use of the address excludes it.
        var decoded = new bool[image.SizeOfImage];
        for (int i = 0; i < image.Instructions.Count; i++)
        {
            ref readonly var instruction = ref image.Instructions[i];
            uint ip = (uint)instruction.IP;
            if (ip + (uint)instruction.Length <= decoded.Length)
            {
                decoded.AsSpan((int)ip, instruction.Length).Fill(true);
            }

            if (instruction.IsIPRelativeMemoryOperand)
            {
                uint target = (uint)instruction.IPRelativeMemoryAddress;
                if (!copyOf.ContainsKey(target))
                {
                    continue;
                }

                if (instruction.Mnemonic == Mnemonic.Lea)
                {
                    sites[ip] = new PointerSite(ip, true, target);
                }
                else
                {
                    Exclude(target, "RIP-relative operand other than lea");
                }

                continue;
            }

            for (int op = 0; op < instruction.OpCount; op++)
            {
                if (instruction.GetOpKind(op) is OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64 or OpKind.Immediate8to64 or OpKind.Immediate16 &&
                    instruction.GetImmediate(op) is var value && value <= uint.MaxValue)
                {
                    Exclude((uint)value, "RVA as an immediate");
                }
                else if (instruction.GetOpKind(op) == OpKind.Memory && instruction.MemoryDisplacement64 <= uint.MaxValue)
                {
                    Exclude((uint)instruction.MemoryDisplacement64, "RVA as a displacement");
                }
            }
        }

        // Bytes nobody decoded, and data: RVAs, and (in code) possible RIP-relative operands.
        // RUNTIME_FUNCTION begin/end addresses (read by the unwinder only: the exception table and the
        // parent entry at the end of a chained UNWIND_INFO) and relocation page RVAs are not pointers.
        var skipped = image.DataDirectories.Where(d => d.Name is "Exception" or "BaseRelocation").ToList();
        var chainTrailers = new HashSet<uint>();
        foreach (var entry in image.ExceptionData.Where(e => e.IsChained && (e.UnwindInfoAddress & 1) == 0))
        {
            var info = image.ReadFrom(entry.UnwindInfoAddress).Span;
            if (info.Length >= 4 && info.Length >= FunctionRewriter.UnwindTrailerOffset(info) + 12)
            {
                uint trailer = entry.UnwindInfoAddress + (uint)FunctionRewriter.UnwindTrailerOffset(info);
                chainTrailers.UnionWith([trailer, trailer + 4, trailer + 8]);
            }
        }

        // UNWIND_INFO headers and unwind code arrays hold no addresses: version/flags, prologue size,
        // code count and frame register, then 2-byte codes (offsets and register numbers). Read as
        // 32-bit words they still collide with function RVAs (Factorio: `10 54 25 00`, save rbp, is
        // 0x00255410, a hot virtual function). What follows them (handler RVA, handler data) is scanned.
        var unwindCodes = new HashSet<uint>();
        foreach (uint unwind in image.ExceptionData.Where(e => (e.UnwindInfoAddress & 1) == 0).Select(e => e.UnwindInfoAddress).Distinct())
        {
            var info = image.ReadFrom(unwind).Span;
            if (unwind % 4 == 0 && info.Length >= 4 && info.Length >= FunctionRewriter.UnwindTrailerOffset(info))
            {
                for (uint word = unwind; word < unwind + FunctionRewriter.UnwindTrailerOffset(info); word += 4)
                {
                    unwindCodes.Add(word);
                }
            }
        }
        foreach (var section in image.Sections)
        {
            var bytes = section.Data.Span;
            if (section.IsExecutable)
            {
                for (int p = 0; p + 4 <= bytes.Length; p++)
                {
                    uint rva = section.Rva + (uint)p;
                    if (rva < decoded.Length && decoded[rva])
                    {
                        continue;
                    }

                    int value = BinaryPrimitives.ReadInt32LittleEndian(bytes[p..]);
                    Exclude((uint)value, "RVA-like value in undecoded code");
                    if (p > 0 && (bytes[p - 1] & 0xC7) == 0x05)
                    {
                        for (uint immediate = 0; immediate <= 4; immediate++)
                        {
                            Exclude((uint)(rva + 4 + immediate + value), "possible RIP-relative reference in undecoded code");
                        }
                    }
                }
            }
            else
            {
                for (int p = 0; p + 4 <= bytes.Length; p += 4)
                {
                    uint rva = section.Rva + (uint)p;
                    if (chainTrailers.Contains(rva) || unwindCodes.Contains(rva) || skipped.Any(d => rva >= d.Rva && rva - d.Rva < d.Size))
                    {
                        continue;
                    }

                    Exclude(BinaryPrimitives.ReadUInt32LittleEndian(bytes[p..]), "RVA in data");
                }
            }
        }

        var pointedTo = sites.Values.Select(s => s.Target).ToHashSet();
        foreach (var (entry, reason) in excluded.Where(e => pointedTo.Contains(e.Key)))
        {
            plan.Excluded[entry] = reason;
        }

        foreach (var site in sites.Values.Where(s => !excluded.ContainsKey(s.Target)).OrderBy(s => s.Rva))
        {
            plan.Sites.Add(site);
            plan.Targets[site.Target] = copyOf[site.Target];
        }

        return plan;
    }
}
