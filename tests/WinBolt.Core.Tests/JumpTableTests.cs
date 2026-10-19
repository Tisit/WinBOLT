using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class JumpTableTests
{
    // MSVC single-level switch over ecx in 0..2, function at 0x1000:
    //   1000 cmp ecx,2 / 1003 ja default / 1005 lea rdx,[rip → 0] / 100C mov ecx,[rdx+rcx*4+1100h]
    //   1013 add rcx,rdx / 1016 jmp rcx / 1018 case 0: mov eax,1; ret / 101E case 1: xor eax,eax; ret
    //   1021 case 2 (2 bytes) / default: or eax,-1; ret
    private static SyntheticImage Switch(byte ja = 0x77, byte[]? case2 = null, byte jaOffset = 0x1D)
    {
        case2 ??= [0xC3];
        uint defaultCase = 0x1021 + (uint)case2.Length;
        return new SyntheticImage()
            .Code(0x1000, 0x83, 0xF9, 0x02, ja, jaOffset,
                0x48, 0x8D, 0x15, 0xF4, 0xEF, 0xFF, 0xFF,
                0x8B, 0x8C, 0x8A, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
                0x31, 0xC0, 0xC3)
            .Code(0x1021, case2)
            .Code(defaultCase, 0x83, 0xC8, 0xFF, 0xC3)
            .Pdata(0x1000, defaultCase + 4)
            .Data(0x1100, 0x1018, 0x101E, 0x1021);
    }

    private static Function At(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    // LLVM/lld switch over ecx in 0..2, function at 0x1000: signed entries relative to the table.
    //   1000 cmp ecx,2 / 1003 ja default / 1005 lea rdx,[rip → 1100h] / 100C movsxd rcx,[rdx+rcx*4]
    //   1010 add rcx,rdx / 1013 jmp rcx / 1015 case 0 / 101B case 1 / 101E case 2 / 101F default
    private static SyntheticImage LlvmSwitch(byte[]? load = null, byte[]? betweenCompareAndBranch = null)
    {
        byte[] extra = betweenCompareAndBranch ?? [];
        int shift = extra.Length;
        byte[] code =
        [
            0x83, 0xF9, 0x02,
            .. extra,
            0x77, (byte)(0x1A + shift),
            0x48, 0x8D, 0x15, (byte)(0xF4 - shift), 0x00, 0x00, 0x00,
            .. load ?? [0x48, 0x63, 0x0C, 0x8A],
            0x48, 0x01, 0xD1,
            0xFF, 0xE1,
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
            0x31, 0xC0, 0xC3,
            0xC3,
            0x83, 0xC8, 0xFF, 0xC3,
        ];
        return new SyntheticImage()
            .Code(0x1000, code)
            .Pdata(0x1000, (uint)(0x1023 + shift))
            .Data(0x1100, unchecked((uint)(0x1015 + shift - 0x1100)), unchecked((uint)(0x101B + shift - 0x1100)), unchecked((uint)(0x101E + shift - 0x1100)));
    }

    [Fact]
    public void Llvm_table_relative_switch_is_recovered()
    {
        var f = At(LlvmSwitch().Analyze(), 0x1000);

        var table = Assert.Single(f.JumpTables);
        Assert.Equal((0x1013ul, 0x1100ul, JumpTableEncoding.TableRelativeOffset32, 3), (table.SiteRva, table.Rva, table.Encoding, table.EntryCount));
        Assert.Equal(0x1100ul, table.BaseRva);
        Assert.Equal([0x1015ul, 0x101B, 0x101E], table.TargetRvas);
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Llvm_scheduled_instruction_between_compare_and_branch_is_skipped()
    {
        // lea rax,[rsi+8] does not touch the flags or ecx.
        var table = Assert.Single(At(LlvmSwitch(betweenCompareAndBranch: [0x48, 0x8D, 0x46, 0x08]).Analyze(), 0x1000).JumpTables);
        Assert.Equal(3, table.EntryCount);
    }

    [Fact]
    public void Llvm_instruction_between_compare_and_branch_that_rewrites_the_index_leaves_the_extent_to_the_data()
    {
        // mov ecx,5 after the compare: the branch no longer tests the index, so the bound is not
        // proven; the table's extent is then read off the data.
        var f = At(LlvmSwitch(betweenCompareAndBranch: [0xB9, 0x05, 0x00, 0x00, 0x00]).Analyze(), 0x1000);
        Assert.True(Assert.Single(f.JumpTables).ExtentInferred);
    }

    [Fact]
    public void Llvm_table_with_an_unsigned_load_is_not_recognized()
    {
        // mov ecx,[rdx+rcx*4] zero-extends: a table-relative entry would be read as a huge positive offset.
        var f = At(LlvmSwitch(load: [0x8B, 0x0C, 0x8A]).Analyze(), 0x1000);

        Assert.Empty(f.JumpTables);
    }

    [Fact]
    public void Msvc_switch_is_recovered_with_indirect_edges()
    {
        var image = Switch().Analyze();
        var f = At(image, 0x1000);

        var table = Assert.Single(f.JumpTables);
        Assert.Equal((0x1016ul, 0x1100ul, JumpTableEncoding.ImageRelativeOffset32, 3), (table.SiteRva, table.Rva, table.Encoding, table.EntryCount));
        Assert.Equal([0x1018ul, 0x101E, 0x1021], table.TargetRvas);

        var dispatch = f.BasicBlocks.Single(b => b.StartRva <= 0x1016 && 0x1016 < b.StartRva + b.Length);
        Assert.Equal([0x1018ul, 0x101E, 0x1021], dispatch.Successors.Where(e => e.Kind == EdgeKind.IndirectBranch).Select(e => e.Target.StartRva).Order().ToList());
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Two_level_switch_is_recovered()
    {
        // 1000 cmp ecx,4 / ja 1029 / lea rdx,[rip → 0] / movzx ecx,byte [rdx+rcx+1180h]
        // mov ecx,[rdx+rcx*4+1100h] / add rcx,rdx / jmp rcx / 1020: case A / 1026: case B / 1029: default
        var image = new SyntheticImage()
            .Code(0x1000, 0x83, 0xF9, 0x04, 0x77, 0x24,
                0x48, 0x8D, 0x15, 0xF4, 0xEF, 0xFF, 0xFF,
                0x0F, 0xB6, 0x8C, 0x0A, 0x80, 0x11, 0x00, 0x00,
                0x8B, 0x8C, 0x8A, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
                0x31, 0xC0, 0xC3,
                0x83, 0xC8, 0xFF, 0xC3)
            .Pdata(0x1000, 0x102D)
            .Data(0x1100, 0x1020, 0x1026)
            .Code(0x1180, 0, 1, 1, 0, 1)
            .Analyze();

        var table = Assert.Single(At(image, 0x1000).JumpTables);
        Assert.Equal(JumpTableEncoding.TwoLevelMsvc, table.Encoding);
        Assert.Equal((0x1180ul, 5, 2), (table.IndexTableRva!.Value, table.IndexEntryCount, table.EntryCount));
        Assert.Equal(Transformability.FullyTransformable, At(image, 0x1000).SafetyStatus.Level);
    }

    [Fact]
    public void Signed_bound_check_is_not_trusted()
    {
        var f = At(Switch(ja: 0x7F).Analyze(), 0x1000); // jg instead of ja

        Assert.Empty(f.JumpTables);
        Assert.Contains(f.DowngradeReasons, r => r.StartsWith("indirect-branch:") && r.Contains("unsigned"));
    }

    [Fact]
    public void Branch_into_the_dispatch_sequence_voids_the_table()
    {
        // case 2 becomes "jmp 100C": it enters after the bound check. Walking that path back
        // through the case block (reached from the dispatch itself) meets 'add rcx,rdx' as the
        // index's definition, so the index there is unbounded.
        var f = At(Switch(case2: [0xEB, 0xE9], jaOffset: 0x1E).Analyze(), 0x1000);

        Assert.Empty(f.JumpTables);
        Assert.Contains(f.DowngradeReasons, r => r.StartsWith("indirect-branch: unresolved jmp at 0x1016: index register is computed at 0x1013"));
    }

    // 1000 lea rdx,[rip → 0] / 1007 cmp ecx,2 / 100A ja 1022 / 100C mov ecx,[rdx+rcx*4+1100h]
    // 1013 add rcx,rdx / 1016 jmp rcx / 1018 case 0: <reentry> / 1022 cases 1, 2 and default: ret
    private static Function Reentry(params byte[] reentry)
    {
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x15, 0xF9, 0xEF, 0xFF, 0xFF,
                0x83, 0xF9, 0x02, 0x77, 0x16,
                0x8B, 0x8C, 0x8A, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1)
            .Code(0x1018, reentry)
            .Code(0x1022, 0xC3)
            .Pdata(0x1000, 0x1023)
            .Data(0x1100, 0x1018, 0x1022, 0x1022)
            .Analyze();
        return At(image, 0x1000);
    }

    [Fact]
    public void Case_block_reentering_the_dispatch_with_its_own_bound_is_proven_on_every_path()
    {
        // 1018 mov ecx,1 / 101D cmp ecx,2 / 1020 jbe 100C: the taken jbe bounds this path too.
        var f = Reentry(0xB9, 0x01, 0x00, 0x00, 0x00, 0x83, 0xF9, 0x02, 0x76, 0xEA);

        var table = Assert.Single(f.JumpTables);
        Assert.Equal(3, table.EntryCount);
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Case_block_reentering_the_dispatch_without_a_bound_voids_the_table()
    {
        // 1018 mov ecx,5 / 101D jmp 100C / 101F int3 padding
        var f = Reentry(0xB9, 0x05, 0x00, 0x00, 0x00, 0xEB, 0xED, 0xCC, 0xCC, 0xCC);

        Assert.Empty(f.JumpTables);
        Assert.Contains(f.DowngradeReasons, r => r.Contains("index register is computed at 0x1018"));
    }

    [Fact]
    public void Index_recomputed_by_the_same_lea_as_the_compare_is_bounded()
    {
        // 1000 lea rdx,[rip → 0] / 1007 lea eax,[r8-20h] / 100B cmp eax,2 / 100E ja 1020
        // 1010 lea eax,[r8-20h] / 1014 mov ecx,[rdx+rax*4+1100h] / 101B add rcx,rdx / 101E jmp rcx / 1020 ret
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x15, 0xF9, 0xEF, 0xFF, 0xFF,
                0x41, 0x8D, 0x40, 0xE0,
                0x83, 0xF8, 0x02, 0x77, 0x10,
                0x41, 0x8D, 0x40, 0xE0,
                0x8B, 0x8C, 0x82, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xC3)
            .Pdata(0x1000, 0x1021)
            .Data(0x1100, 0x1020, 0x1020, 0x1020)
            .Analyze();

        Assert.Equal(3, Assert.Single(At(image, 0x1000).JumpTables).EntryCount);
    }

    // 1000 lea rdx,[rip → 0] / 1007 lea eax,[r8-20h] / 100B cmp eax,2 / 100E ja 1021
    // 1010 add r8d,<adjust> / 1014 mov ecx,[rdx+r8*4+1100h] / 101C add rcx,rdx / 101F jmp rcx / 1021 ret
    private static Function InPlaceAdjust(byte adjust) => At(new SyntheticImage()
        .Code(0x1000, 0x48, 0x8D, 0x15, 0xF9, 0xEF, 0xFF, 0xFF,
            0x41, 0x8D, 0x40, 0xE0,
            0x83, 0xF8, 0x02, 0x77, 0x11,
            0x41, 0x83, 0xC0, adjust,
            0x42, 0x8B, 0x8C, 0x82, 0x00, 0x11, 0x00, 0x00,
            0x48, 0x03, 0xCA,
            0xFF, 0xE1,
            0xC3)
        .Pdata(0x1000, 0x1022)
        .Data(0x1100, 0x1021, 0x1021, 0x1021)
        .Analyze(), 0x1000);

    [Fact]
    public void Index_adjusted_in_place_like_the_compared_lea_is_bounded()
    {
        var f = InPlaceAdjust(0xE0); // add r8d,-20h: the compared value

        Assert.Equal(3, Assert.Single(f.JumpTables).EntryCount);
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Index_adjusted_in_place_by_another_amount_is_not_bounded()
    {
        var f = InPlaceAdjust(0xE1); // add r8d,-1Fh: not what was compared

        Assert.Empty(f.JumpTables);
        Assert.Contains(f.DowngradeReasons, r => r.Contains("breaks its link to the index"));
    }

    // [prefix] / lea rdx,[rip → 0] / cmp cl,2 / ja default / mov ecx,[rdx+rcx*4+1100h] / add rcx,rdx / jmp rcx / ret
    private static Function ByteCompare(params byte[] prefix)
    {
        uint at = 0x1000 + (uint)prefix.Length;
        int disp = -(int)(at + 7);
        uint ret = at + 7 + 5 + 7 + 3 + 2;
        var image = new SyntheticImage()
            .Code(0x1000, [.. prefix,
                0x48, 0x8D, 0x15, (byte)disp, (byte)(disp >> 8), (byte)(disp >> 16), (byte)(disp >> 24),
                0x80, 0xF9, 0x02, 0x77, 0x0C,
                0x8B, 0x8C, 0x8A, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xC3])
            .Pdata(0x1000, ret + 1)
            .Data(0x1100, ret, ret, ret)
            .Analyze();
        return At(image, 0x1000);
    }

    [Fact]
    public void Byte_compare_bounds_the_index_only_when_the_upper_bits_are_proven_zero()
    {
        var unproven = ByteCompare();
        Assert.Empty(unproven.JumpTables);
        Assert.Contains(unproven.DowngradeReasons, r => r.Contains("upper bits are proven zero"));

        var zeroExtended = ByteCompare(0x0F, 0xB6, 0xC9); // movzx ecx,cl
        Assert.Equal(3, Assert.Single(zeroExtended.JumpTables).EntryCount);
    }

    [Fact]
    public void Table_after_a_noreturn_call_inside_the_range_is_data_not_code()
    {
        // As Switch(), but case 0 is "call 1180 (noreturn) / int3" and the table sits right after
        // it, inside the .pdata range: 1018 call / 101D int3 / 1020 table / 102C case 1 / 102F case 2 / 1030 default
        var image = new SyntheticImage()
            .Code(0x1000, 0x83, 0xF9, 0x02, 0x77, 0x2B,
                0x48, 0x8D, 0x15, 0xF4, 0xEF, 0xFF, 0xFF,
                0x8B, 0x8C, 0x8A, 0x20, 0x10, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xE8, 0x63, 0x01, 0x00, 0x00, 0xCC)
            .Data(0x1020, 0x1018, 0x102C, 0x102F)
            .Code(0x102C, 0x31, 0xC0, 0xC3, 0xC3, 0x83, 0xC8, 0xFF, 0xC3)
            .Pdata(0x1000, 0x1034)
            .Code(0x1180, 0xC3)
            .Analyze();
        var f = At(image, 0x1000);

        Assert.Single(f.JumpTables);
        Assert.Empty(f.DowngradeReasons);
        Assert.DoesNotContain(f.BasicBlocks, b => b.StartRva >= 0x1020 && b.StartRva < 0x102C);
    }

    [Fact]
    public void Table_whose_first_byte_does_not_decode_is_found_after_a_noreturn_call()
    {
        // The first exploration decodes past the noreturn call and stops at the table's first
        // byte, 0x37 (invalid in 64-bit mode), without decoding any of it: that must trigger the
        // second exploration too. Factorio: CraftingMachine::update, AlertCenter::update.
        // 1000 cmp ecx,3 / ja 1033 / lea rdx,[rip → 0] / mov ecx,[rdx+rcx*4+1020h] / add rcx,rdx / jmp rcx
        // 1018 call 1180 / int3 / xchg ax,ax / 1020 table / 1030 case / 1033 default / 1037 case
        var image = new SyntheticImage()
            .Code(0x1000, 0x83, 0xF9, 0x03, 0x77, 0x2E,
                0x48, 0x8D, 0x15, 0xF4, 0xEF, 0xFF, 0xFF,
                0x8B, 0x8C, 0x8A, 0x20, 0x10, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xE8, 0x63, 0x01, 0x00, 0x00, 0xCC, 0x66, 0x90)
            .Data(0x1020, 0x1037, 0x1018, 0x1030, 0x1030)
            .Code(0x1030, 0x31, 0xC0, 0xC3, 0x83, 0xC8, 0xFF, 0xC3, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3)
            .Pdata(0x1000, 0x103D)
            .Code(0x1180, 0xC3)
            .Analyze();
        var f = At(image, 0x1000);

        Assert.Equal(4, Assert.Single(f.JumpTables).EntryCount);
        Assert.Empty(f.DowngradeReasons);
    }

    // 1000 lea r10,[rip → 0] / 1007 cmp r8,100h / 100E jae 1033 / 1014 lea r9,[r8+1Fh] / 1018 and r9,-20h
    // 101C mov r11,r9 / 101F shr r11,5 / 1023 mov r11d,[r10+r11*4+1100h] / 102B add r11,r10 / 102E jmp r11
    // 1031 case: ret / 1032 case: ret / 1033 default: xor eax,eax; ret
    private static SyntheticImage RoundedIndex(byte[] and) => new SyntheticImage()
        .Code(0x1000, [0x4C, 0x8D, 0x15, 0xF9, 0xEF, 0xFF, 0xFF,
            0x49, 0x81, 0xF8, 0x00, 0x01, 0x00, 0x00,
            0x0F, 0x83, 0x1F, 0x00, 0x00, 0x00,
            0x4D, 0x8D, 0x48, 0x1F,
            .. and,
            0x4D, 0x8B, 0xD9,
            0x49, 0xC1, 0xEB, 0x05,
            0x47, 0x8B, 0x9C, 0x9A, 0x00, 0x11, 0x00, 0x00,
            0x4D, 0x03, 0xDA,
            0x41, 0xFF, 0xE3,
            0xC3, 0xC3, 0x31, 0xC0, 0xC3])
        .Pdata(0x1000, 0x1036)
        // Nine entries, then a value outside the function: a count past nine fails the proof.
        .Data(0x1100, 0x1031, 0x1032, 0x1031, 0x1032, 0x1031, 0x1032, 0x1031, 0x1032, 0x1031, 0x5000);

    [Fact]
    public void Rounded_size_index_is_bounded_arithmetically()
    {
        // The CRT's memmove: index = ((n + 31) & ~31) >> 5 with n < 256, so at most 8.
        var f = At(RoundedIndex([0x49, 0x83, 0xE1, 0xE0]).Analyze(), 0x1000);

        var table = Assert.Single(f.JumpTables);
        Assert.Equal((0x1100ul, 9), (table.Rva, table.EntryCount));
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Rounded_index_with_an_unmodelled_step_is_not_trusted()
    {
        // or r9,1Fh instead of the and: not part of the modelled ((x + c) & mask) >> k.
        var f = At(RoundedIndex([0x49, 0x83, 0xC9, 0x1F]).Analyze(), 0x1000);

        Assert.Empty(f.JumpTables);
        Assert.Contains(f.DowngradeReasons, r => r.StartsWith("indirect-branch: unresolved jmp at 0x102E"));
    }

    [Fact]
    public void Equality_bound_on_a_byte_with_image_base_as_the_encoded_index_is_recovered()
    {
        // __GSHandlerCheckCommon's form: cmp cl,2 / jne default bounds by equality; movzx eax,cl
        // after the compare makes the upper bits irrelevant; the byte table load encodes the
        // image base as the index register ([rax+rbp+1180h]).
        // 1000 lea rbp,[rip → 0] / 1007 cmp cl,2 / 100A jne 102C / 100C movzx eax,cl
        // 100F movzx eax,byte [rax+rbp+1180h] / 1017 mov ecx,[rbp+rax*4+1100h] / 101E add rcx,rbp / 1021 jmp rcx
        // 1023 case A / 1029 case B / 102C default
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x2D, 0xF9, 0xEF, 0xFF, 0xFF,
                0x80, 0xF9, 0x02, 0x75, 0x20,
                0x0F, 0xB6, 0xC1,
                0x0F, 0xB6, 0x84, 0x28, 0x80, 0x11, 0x00, 0x00,
                0x8B, 0x8C, 0x85, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCD,
                0xFF, 0xE1,
                0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
                0x31, 0xC0, 0xC3,
                0x83, 0xC8, 0xFF, 0xC3)
            .Pdata(0x1000, 0x1030)
            .Data(0x1100, 0x1023, 0x1029)
            .Code(0x1180, 0, 1, 0)
            .Analyze();
        var f = At(image, 0x1000);

        var table = Assert.Single(f.JumpTables);
        Assert.Equal((JumpTableEncoding.TwoLevelMsvc, 3, 2), (table.Encoding, table.IndexEntryCount, table.EntryCount));
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    // 1000 test rcx,rcx / je 100E / mov rax,[rcx] / jmp qword [rax+10h] / padding / 100E: tail
    private static SyntheticImage VirtualTailCall(byte[] tail) => new SyntheticImage()
        .Code(0x1000, 0x48, 0x85, 0xC9, 0x74, 0x09, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x10)
        .Code(0x100E, tail)
        .Pdata(0x1000, 0x100E + (uint)tail.Length);

    [Fact]
    public void Indirect_jump_that_cannot_land_inside_its_function_is_a_tail_call()
    {
        var image = VirtualTailCall([0x31, 0xC0, 0xC3]).Analyze();

        Assert.Contains(image.CallSites, c => c is { SiteRva: 0x1008, Kind: CallKind.IndirectTailJump });
        Assert.Equal(Transformability.FullyTransformable, At(image, 0x1000).SafetyStatus.Level);
    }

    [Fact]
    public void Indirect_jump_in_a_function_that_loads_the_image_base_is_frozen()
    {
        // The tail loads __ImageBase (lea rax,[rip → 0] / ret): an image-relative table could exist.
        var image = VirtualTailCall([0x48, 0x8D, 0x05, 0xEB, 0xEF, 0xFF, 0xFF, 0xC3]).Analyze();

        Assert.Contains(At(image, 0x1000).DowngradeReasons, r => r.StartsWith("indirect-branch: unresolved jmp at 0x1008"));
    }

    // 1000 sub rsp,28h / test rcx,rcx / je 1014 / mov rax,[rcx] / 100C <teardown> / 1010 rex.w jmp [rax+10h]
    // 1014 add rsp,28h / lea rax,[rip → 0] / ret. The function loads __ImageBase, so only the epilogue
    // form can make the jmp a tail call.
    private static SyntheticImage EpilogueTailCall(params byte[] teardown) => new SyntheticImage()
        .Code(0x1000, [0x48, 0x83, 0xEC, 0x28, 0x48, 0x85, 0xC9, 0x74, 0x0B, 0x48, 0x8B, 0x01, .. teardown, 0x48, 0xFF, 0x60, 0x10,
            0x48, 0x83, 0xC4, 0x28, 0x48, 0x8D, 0x05, 0xE1, 0xEF, 0xFF, 0xFF, 0xC3])
        .Pdata(0x1000, 0x1020);

    [Fact]
    public void Rex_w_indirect_jump_ending_an_epilogue_is_a_tail_call()
    {
        var image = EpilogueTailCall(0x48, 0x83, 0xC4, 0x28).Analyze(); // add rsp,28h

        Assert.Contains(image.CallSites, c => c is { SiteRva: 0x1010, Kind: CallKind.IndirectTailJump });
        Assert.Equal(Transformability.FullyTransformable, At(image, 0x1000).SafetyStatus.Level);
    }

    [Fact]
    public void Rex_w_indirect_jump_without_a_frame_teardown_before_it_is_frozen()
    {
        var image = EpilogueTailCall(0x90, 0x90, 0x90, 0x90).Analyze();

        Assert.Contains(At(image, 0x1000).DowngradeReasons, r => r.StartsWith("indirect-branch: unresolved jmp at 0x1010"));
    }

    [Fact]
    public void Llvm_switch_without_a_bound_takes_its_extent_from_the_data_up_to_the_next_referenced_object()
    {
        // No compare at all (a default-less switch). 1000 lea r8,[rip → 110Ch] / 1007 lea rdx,[rip → 1100h] /
        // movsxd rcx,[rdx+rcx*4] / add rcx,rdx / jmp rcx / cases at 1017, 101D, 1020.
        // The table is 3 entries; the dword at 110Ch would also read as a target inside the function,
        // but 110Ch is another object the function addresses, so the extent stops there.
        var image = new SyntheticImage()
            .Code(0x1000, 0x4C, 0x8D, 0x05, 0x05, 0x01, 0x00, 0x00,
                0x48, 0x8D, 0x15, 0xF2, 0x00, 0x00, 0x00,
                0x48, 0x63, 0x0C, 0x8A,
                0x48, 0x01, 0xD1,
                0xFF, 0xE1,
                0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
                0x31, 0xC0, 0xC3,
                0xC3)
            .Pdata(0x1000, 0x1021)
            .Data(0x1100, unchecked((uint)(0x1017 - 0x1100)), unchecked((uint)(0x101D - 0x1100)), unchecked((uint)(0x1020 - 0x1100)),
                unchecked((uint)(0x1017 - 0x1100)))
            .Analyze();
        var f = At(image, 0x1000);

        var table = Assert.Single(f.JumpTables);
        Assert.True(table.ExtentInferred);
        Assert.Equal([0x1017ul, 0x101D, 0x1020], table.TargetRvas);
        Assert.True(f.SafetyStatus.Level == Transformability.FullyTransformable, string.Join("; ", f.DowngradeReasons));
    }

    [Fact]
    public void Msvc_form_without_a_bound_check_is_not_inferred()
    {
        // As Switch() but the compare and branch are removed (both replaced by nops): the image-relative
        // form is never accepted without a proven bound.
        var image = new SyntheticImage()
            .Code(0x1000, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x48, 0x8D, 0x15, 0xF4, 0xEF, 0xFF, 0xFF,
                0x8B, 0x8C, 0x8A, 0x00, 0x11, 0x00, 0x00,
                0x48, 0x03, 0xCA,
                0xFF, 0xE1,
                0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
                0x31, 0xC0, 0xC3,
                0xC3)
            .Pdata(0x1000, 0x1022)
            .Data(0x1100, 0x1018, 0x101E, 0x1021)
            .Analyze();

        Assert.Empty(At(image, 0x1000).JumpTables);
    }
}
