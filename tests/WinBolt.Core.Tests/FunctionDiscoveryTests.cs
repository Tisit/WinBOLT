using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Core.Tests;

public class FunctionDiscoveryTests
{
    private const ulong ImageBase = 0x140000000;
    private const uint TextRva = 0x1000;
    private const uint RdataRva = 0x2000;
    private const uint ExecuteRead = 0x60000020;

    // Hand-assembled .text layout:
    //   0x1000 A:        sub rsp,28h / call 0x1020 / add rsp,28h / ret        (.pdata, 0x1000-0x100E)
    //   0x1020 leaf:     mov eax,1 / ret                                      (reached only by A's call)
    //   0x1030 Branchy:  test ecx,ecx / jz 0x103A / mov eax,1 / ret / xor eax,eax / ret   (exported)
    //   0x1040 frag:     add rsp,28h / ret                                    (.pdata, chained to A)
    //   0x1050 data:     16 x FF                                              (pointed at by a relocation)
    //   everything else: int3 padding
    private static BinaryImage BuildImage(Action<BinaryImage>? customize = null)
    {
        var text = Enumerable.Repeat((byte)0xCC, 0x100).ToArray();
        Put(text, 0x1000, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3);
        Put(text, 0x1020, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3);
        Put(text, 0x1030, 0x85, 0xC9, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x31, 0xC0, 0xC3);
        Put(text, 0x1040, 0x48, 0x83, 0xC4, 0x28, 0xC3);
        Put(text, 0x1050, Enumerable.Repeat((byte)0xFF, 16).ToArray());

        var rdata = BitConverter.GetBytes(ImageBase + 0x1050);

        var image = new BinaryImage
        {
            FilePath = "synthetic.dll",
            ImageBase = ImageBase,
            SizeOfImage = 0x3000,
            TimeDateStamp = 0,
            Checksum = 0,
        };
        image.Sections.Add(new Section
        {
            Name = ".text", Rva = TextRva, VirtualSize = 0x100, RawSize = 0x100, FileOffset = 0x400,
            Characteristics = ExecuteRead, Data = text,
        });
        image.Sections.Add(new Section
        {
            Name = ".rdata", Rva = RdataRva, VirtualSize = 8, RawSize = 0x200, FileOffset = 0x600,
            Characteristics = 0x40000040, Data = rdata,
        });

        var a = Pdata(0x1000, 0x100E);
        image.ExceptionData.Add(a);
        image.ExceptionData.Add(Pdata(0x1040, 0x1045, parent: a, chained: true));
        image.Exports.Add(new ExportedSymbol("Branchy", 1, 0x1030, null));
        image.Relocations.Add(new Relocation { Rva = RdataRva, Type = RelocationType.Dir64 });

        customize?.Invoke(image);
        new FunctionDiscoveryPass().Run(image, new PassContext());
        return image;
    }

    private static void Put(byte[] text, uint rva, params byte[] bytes) => bytes.CopyTo(text, (int)(rva - TextRva));

    private static ExceptionInfo Pdata(uint begin, uint end, ExceptionInfo? parent = null, bool chained = false) => new()
    {
        BeginAddress = begin,
        EndAddress = end,
        UnwindInfoAddress = 0,
        IsChained = chained,
        ChainedParent = parent,
    };

    private static Function At(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    [Fact]
    public void Chained_fragment_becomes_a_second_range_of_its_root()
    {
        var a = At(BuildImage(), 0x1000);

        Assert.Equal(DiscoverySource.Pdata, a.DiscoveredBy & DiscoverySource.Pdata);
        Assert.Equal(2, a.Ranges.Count);
        Assert.Equal((0x1000ul, 0xEu), (a.EntryRange.StartRva, a.EntryRange.Length));
        Assert.Equal((0x1040ul, 5u, false), (a.Ranges[1].StartRva, a.Ranges[1].Length, a.Ranges[1].IsEntryRange));
    }

    [Fact]
    public void Leaf_reached_by_a_call_is_discovered_with_its_extent()
    {
        var leaf = At(BuildImage(), 0x1020);

        Assert.Equal(DiscoverySource.CallTarget, leaf.DiscoveredBy);
        Assert.Equal(6u, leaf.TotalLength);
        Assert.Equal(Transformability.Unanalyzed, leaf.SafetyStatus.Level);
    }

    [Fact]
    public void Leaf_sweep_continues_past_a_ret_that_a_forward_branch_jumps_over()
    {
        var branchy = At(BuildImage(), 0x1030);

        Assert.Equal("Branchy", branchy.Name);
        Assert.Equal(0xDu, branchy.TotalLength); // both returns
        Assert.Equal(Transformability.Unanalyzed, branchy.SafetyStatus.Level);
    }

    [Fact]
    public void Relocation_target_that_is_not_code_is_left_unattributed()
    {
        var image = BuildImage();

        Assert.DoesNotContain(image.Functions, f => f.EntryRva == 0x1050);
        Assert.Contains(image.UnclaimedCode, u => u is { Rva: 0x1050, Length: 16, Kind: UnclaimedKind.Unattributed });
    }

    [Fact]
    public void Int3_between_functions_is_padding()
    {
        var image = BuildImage();

        Assert.Contains(image.UnclaimedCode, u => u is { Rva: 0x100E, Kind: UnclaimedKind.Padding });
        Assert.Equal(0x100u, (uint)image.Functions.Sum(f => f.TotalLength) + (uint)image.UnclaimedCode.Sum(u => u.Length));
    }

    [Fact]
    public void Export_inside_a_function_freezes_it()
    {
        var image = BuildImage(i => i.Exports.Add(new ExportedSymbol("Interior", 2, 0x1004, null)));
        var a = At(image, 0x1000);

        Assert.Equal(Transformability.Frozen, a.SafetyStatus.Level);
        Assert.StartsWith("interior-entry:", a.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Invalid_chain_fragment_is_not_attributed_to_any_function()
    {
        var image = BuildImage(i => i.ExceptionData.Add(Pdata(0x1060, 0x1070, parent: null, chained: true)));

        Assert.Contains(image.UnclaimedCode, u => u is { Rva: 0x1060, Length: 0x10, Kind: UnclaimedKind.InvalidChainFragment });
        Assert.DoesNotContain(image.Functions, f => f.Ranges.Any(r => r.StartRva == 0x1060));
    }

    [Fact]
    public void Duplicate_pdata_entries_yield_one_entry_range()
    {
        var image = BuildImage(i => i.ExceptionData.Add(Pdata(0x1000, 0x100E)));

        Assert.Single(At(image, 0x1000).Ranges, r => r.IsEntryRange);
    }

    // Two exported thunks (jmp at the entry) to two adjacent leaves, as a rewriter's trampolines
    // name its copies. X's tail jump to Z lies past Y: without an entry-asserting bound at Y, X's
    // sweep treats it as internal and runs through Y and Z.
    //   0x1080 X:  test ecx,ecx / jnz 0x10A0 / ret
    //   0x1090 Y:  mov eax,2 / ret
    //   0x10A0 Z:  ret
    //   0x10C0 T1: jmp 0x1080      0x10C8 T2: jmp 0x1090
    [Fact]
    public void Target_of_a_jmp_at_a_known_entry_bounds_leaf_sweeps()
    {
        var image = BuildImage(i =>
        {
            System.Runtime.InteropServices.MemoryMarshal.TryGetArray(i.Sections[0].Data, out var segment);
            var text = segment.Array!;
            Put(text, 0x1080, 0x85, 0xC9, 0x75, 0x1C, 0xC3);
            Put(text, 0x1090, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3);
            Put(text, 0x10A0, 0xC3);
            Put(text, 0x10C0, 0xE9, 0xBB, 0xFF, 0xFF, 0xFF);
            Put(text, 0x10C8, 0xE9, 0xC3, 0xFF, 0xFF, 0xFF);
            i.Exports.Add(new ExportedSymbol("T1", 2, 0x10C0, null));
            i.Exports.Add(new ExportedSymbol("T2", 3, 0x10C8, null));
        });

        Assert.Equal(5u, At(image, 0x1080).TotalLength);
        Assert.Equal(DiscoverySource.EntryJump, At(image, 0x1090).DiscoveredBy);
        Assert.Equal(DiscoverySource.JumpTarget, At(image, 0x10A0).DiscoveredBy);
    }

    // As above, but X is exported: X and the thunk T are candidates of the same round, and T's
    // target Y must bound X's sweep in that round, not arrive a round later inside X.
    //   0x1080 X: test ecx,ecx / jnz 0x10A0 / ret   (exported)
    //   0x1090 Y: mov eax,2 / ret
    //   0x10A0 Z: ret
    //   0x10C8 T: jmp 0x1090                        (exported)
    [Fact]
    public void Thunk_target_bounds_leaf_sweeps_of_the_same_round()
    {
        var image = BuildImage(i =>
        {
            System.Runtime.InteropServices.MemoryMarshal.TryGetArray(i.Sections[0].Data, out var segment);
            var text = segment.Array!;
            Put(text, 0x1080, 0x85, 0xC9, 0x75, 0x1C, 0xC3);
            Put(text, 0x1090, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3);
            Put(text, 0x10A0, 0xC3);
            Put(text, 0x10C8, 0xE9, 0xC3, 0xFF, 0xFF, 0xFF);
            i.Exports.Add(new ExportedSymbol("X", 2, 0x1080, null));
            i.Exports.Add(new ExportedSymbol("T", 3, 0x10C8, null));
        });

        Assert.Equal(5u, At(image, 0x1080).TotalLength);
        Assert.Equal(Transformability.Unanalyzed, At(image, 0x1080).SafetyStatus.Level);
        Assert.Equal(DiscoverySource.EntryJump, At(image, 0x1090).DiscoveredBy);
    }

    // MSVC rotates a frameless leaf's loop: the entry jumps forward to the loop condition.
    //   0x1080 L: jmp 0x1086 / add rcx,1 / cmp rcx,rdx / jne 0x1082 / ret   (exported)
    [Fact]
    public void Jmp_at_the_entry_into_the_function_itself_is_not_a_thunk()
    {
        var image = BuildImage(i =>
        {
            System.Runtime.InteropServices.MemoryMarshal.TryGetArray(i.Sections[0].Data, out var segment);
            Put(segment.Array!, 0x1080, 0xEB, 0x04, 0x48, 0x83, 0xC1, 0x01, 0x48, 0x39, 0xD1, 0x75, 0xF7, 0xC3);
            i.Exports.Add(new ExportedSymbol("L", 2, 0x1080, null));
        });

        Assert.Equal(12u, At(image, 0x1080).TotalLength);
        Assert.DoesNotContain(image.Functions, f => f.EntryRva == 0x1086);
    }

    [Fact]
    public void Downgrade_never_raises_the_level()
    {
        var f = new Function { Id = 0 };
        f.Downgrade(Transformability.Frozen, "first");
        f.Downgrade(Transformability.RelocatableOnly, "second");

        Assert.Equal(new SafetyStatus(Transformability.Frozen, "first"), f.SafetyStatus);
    }
}
