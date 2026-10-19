using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class ExceptionHandlerTests
{
    // mov eax,1 / ret
    private static readonly byte[] ReturnOne = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

    // __GSHandlerCheck at 0x1100, calling a helper at 0x1180:
    // sub rsp,28h / mov r8,[r9+38h] / mov rcx,rdx / mov rdx,r9 / call 0x1180 / mov eax,1 / add rsp,28h / ret
    private static readonly byte[] GsHandlerCheck =
    [
        0x48, 0x83, 0xEC, 0x28, 0x4D, 0x8B, 0x41, 0x38, 0x48, 0x8B, 0xCA, 0x49, 0x8B, 0xD1,
        0xE8, 0x6D, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3,
    ];

    private static Function Only(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    [Fact]
    public void GsHandlerCheck_is_recognized_and_costs_nothing()
    {
        var image = new SyntheticImage()
            .Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1100, handlerDataRva: 0x11C0)
            .Code(0x1100, GsHandlerCheck).Pdata(0x1100, 0x111D)
            .Code(0x1180, 0xC3)
            .Data(0x11C0, 0x20) // GS data: cookie offset
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.GsCookieCheck, f.ExceptionHandler!.Kind);
        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void GsHandlerCheck_lookalike_with_arguments_in_the_wrong_order_is_not_trusted()
    {
        var swapped = (byte[])GsHandlerCheck.Clone();
        byte[] movRdxR9 = [0x49, 0x8B, 0xD1], movRcxRdx = [0x48, 0x8B, 0xCA];
        movRdxR9.CopyTo(swapped, 8);
        movRcxRdx.CopyTo(swapped, 11);

        var image = new SyntheticImage()
            .Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1100, handlerDataRva: 0x11C0)
            .Code(0x1100, swapped).Pdata(0x1100, 0x111D)
            .Code(0x1180, 0xC3)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.Unknown, f.ExceptionHandler!.Kind);
        Assert.StartsWith("handler-data:", f.SafetyStatus.DowngradeReason);
    }

    // 0x1000: nop / nop / ret     try range [0x1000, 0x1002)
    // 0x1003: xor eax,eax / ret   __except block, reached only through the scope table
    // 0x1020: mov eax,1 / ret     filter funclet, no .pdata entry
    private static SyntheticImage SehFunction(uint jumpTarget) => new SyntheticImage()
        .Code(0x1000, 0x90, 0x90, 0xC3, 0x31, 0xC0, 0xC3)
        .Pdata(0x1000, 0x1006, handlerRva: 0x1190, handlerDataRva: 0x11C0)
        .Code(0x1020, ReturnOne)
        .Code(0x1190, 0xC3).Export("__C_specific_handler", 0x1190)
        .Data(0x11C0, 1, 0x1000, 0x1002, 0x1020, jumpTarget);

    [Fact]
    public void Scope_table_makes_the_except_block_reachable_and_the_function_relocatable()
    {
        var image = SehFunction(jumpTarget: 0x1003).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CSpecific, f.ExceptionHandler!.Kind);
        Assert.Equal([new ScopeEntry(0x1000, 0x1002, 0x1020, 0x1003)], f.ScopeTable!);
        Assert.Contains(f.BasicBlocks, b => b.StartRva == 0x1003);
        Assert.DoesNotContain(f.DowngradeReasons, r => r.StartsWith("uncovered-bytes:"));
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
        Assert.StartsWith("seh-scope-table:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Filter_funclet_named_only_by_the_scope_table_is_discovered()
    {
        var image = SehFunction(jumpTarget: 0x1003).Analyze();

        Assert.True(Only(image, 0x1020).DiscoveredBy.HasFlag(DiscoverySource.ExceptionTable));
    }

    [Fact]
    public void Scope_table_that_does_not_fit_the_function_freezes_it()
    {
        var image = SehFunction(jumpTarget: 0x1100).Analyze(); // __except target outside the function
        var f = Only(image, 0x1000);

        Assert.Null(f.ScopeTable);
        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
        Assert.Contains(f.DowngradeReasons, r => r.StartsWith("scope-table:"));
    }

    // 0x1000: nop / ret (FH3, via import thunk 0x1180); 0x1060: unwind funclet, no .pdata
    private static SyntheticImage CxxFunction(uint ipEntry) => new SyntheticImage()
        .Code(0x1000, 0x90, 0xC3).Pdata(0x1000, 0x1002, handlerRva: 0x1180, handlerDataRva: 0x11F8)
        .Code(0x1060, 0x48, 0x8D, 0x4A, 0x70, 0xC3) // lea rcx,[rdx+70h] / ret
        .Code(0x1180, 0xFF, 0x25, 0x6A, 0x00, 0x00, 0x00).Import("__CxxFrameHandler3", 0x11F0)
        .Data(0x11F8, 0x1100)
        .Data(0x1100, 0x19930522, 1, 0x1140, 0, 0, 1, 0x1150, 0, 0, 0)
        .Data(0x1140, 0xFFFFFFFF, 0x1060)
        .Data(0x1150, ipEntry, 0);

    [Fact]
    public void Cxx_table_whose_addresses_all_check_out_makes_the_function_relocatable()
    {
        var image = CxxFunction(ipEntry: 0x1001).Analyze();
        var f = image.Functions.Single(f => f.EntryRva == 0x1000);

        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
        Assert.StartsWith("cxx-eh-table:", f.SafetyStatus.DowngradeReason);
        Assert.True(image.Functions.Single(f => f.EntryRva == 0x1060).DiscoveredBy.HasFlag(DiscoverySource.ExceptionTable));
    }

    [Fact]
    public void Cxx_table_with_an_address_outside_the_function_freezes_it()
    {
        var image = CxxFunction(ipEntry: 0x1040).Analyze();
        var f = image.Functions.Single(f => f.EntryRva == 0x1000);

        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
        Assert.Contains("IP-to-state entry 0x1040", f.SafetyStatus.DowngradeReason);
    }

    // The same FH3 function with a statically linked handler at 0x1180 (its own .pdata entry),
    // named only by a PDB public.
    private static SyntheticImage StaticCxxFunction(uint ipEntry) => new SyntheticImage()
        .Code(0x1000, 0x90, 0xC3).Pdata(0x1000, 0x1002, handlerRva: 0x1180, handlerDataRva: 0x11F8)
        .Code(0x1060, 0x48, 0x8D, 0x4A, 0x70, 0xC3)
        .Code(0x1180, ReturnOne).Pdata(0x1180, 0x1186)
        .Data(0x11F8, 0x1100)
        .Data(0x1100, 0x19930522, 1, 0x1140, 0, 0, 1, 0x1150, 0, 0, 0)
        .Data(0x1140, 0xFFFFFFFF, 0x1060)
        .Data(0x1150, ipEntry, 0);

    [Fact]
    public void Statically_linked_handler_named_by_the_pdb_is_identified_and_its_table_validated()
    {
        var image = StaticCxxFunction(ipEntry: 0x1001).Symbol("__CxxFrameHandler3", 0x1180).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CxxFrameHandler3, f.ExceptionHandler!.Kind);
        Assert.True(f.ExceptionHandler.NamedByPdb);
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
        Assert.StartsWith("cxx-eh-table:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Pdb_name_follows_a_trampoline_to_its_target()
    {
        // As in a rewritten image: the PDB names the original (now jmp 0x1180 at 0x1188), and the
        // copies call the handler's copy at 0x1180.
        var image = StaticCxxFunction(ipEntry: 0x1001)
            .Code(0x1188, 0xE9, 0xF3, 0xFF, 0xFF, 0xFF).Pdata(0x1188, 0x118D).Symbol("__CxxFrameHandler3", 0x1188)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CxxFrameHandler3, f.ExceptionHandler!.Kind);
        Assert.True(f.ExceptionHandler.NamedByPdb);
    }

    [Fact]
    public void Pdb_named_handler_whose_table_does_not_fit_still_freezes_the_function()
    {
        var image = StaticCxxFunction(ipEntry: 0x1040).Symbol("__CxxFrameHandler3", 0x1180).Analyze();
        var f = Only(image, 0x1000);

        Assert.True(f.ExceptionHandler!.NamedByPdb);
        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
    }

    [Fact]
    public void Pdb_name_where_no_pdata_function_starts_is_ignored()
    {
        var image = StaticCxxFunction(ipEntry: 0x1001).Symbol("__CxxFrameHandler3", 0x1181).Symbol("__CxxFrameHandler3", 0x1000).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.Unknown, f.ExceptionHandler!.Kind);
        Assert.StartsWith("handler-data:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Conflicting_pdb_names_at_one_address_are_ignored()
    {
        var image = StaticCxxFunction(ipEntry: 0x1001).Symbol("__CxxFrameHandler3", 0x1180).Symbol("__CxxFrameHandler4", 0x1180).Analyze();

        Assert.Equal(ExceptionHandlerKind.Unknown, Only(image, 0x1000).ExceptionHandler!.Kind);
    }

    [Fact]
    public void Pdb_named_c_specific_handler_validates_the_scope_table()
    {
        var image = new SyntheticImage()
            .Code(0x1000, 0x90, 0x90, 0xC3, 0x31, 0xC0, 0xC3)
            .Pdata(0x1000, 0x1006, handlerRva: 0x1190, handlerDataRva: 0x11C0)
            .Code(0x1020, ReturnOne)
            .Code(0x1190, 0xC3).Pdata(0x1190, 0x1191).Symbol("__C_specific_handler", 0x1190)
            .Data(0x11C0, 1, 0x1000, 0x1002, 0x1020, 0x1003)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CSpecific, f.ExceptionHandler!.Kind);
        Assert.True(f.ExceptionHandler.NamedByPdb);
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
        Assert.StartsWith("seh-scope-table:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Pdb_name_does_not_make_a_gs_handler_check_lookalike_trusted()
    {
        var image = new SyntheticImage()
            .Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1100, handlerDataRva: 0x11C0)
            .Code(0x1100, ReturnOne).Pdata(0x1100, 0x1106).Symbol("__GSHandlerCheck", 0x1100)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.Unknown, f.ExceptionHandler!.Kind);
        Assert.Contains("does not match", f.ExceptionHandler.Evidence);
        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
    }

    [Fact]
    public void Export_name_wins_over_a_disagreeing_pdb_name()
    {
        var image = SehFunction(jumpTarget: 0x1003).Pdata(0x1190, 0x1191).Symbol("__CxxFrameHandler4", 0x1190).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CSpecific, f.ExceptionHandler!.Kind);
        Assert.False(f.ExceptionHandler.NamedByPdb);
        Assert.Contains("the PDB names it __CxxFrameHandler4", f.ExceptionHandler.Evidence);
    }

    // __GSHandlerCheck_SEH behind a jmp (an incremental-linking thunk, or a rewriter's trampoline):
    //   0x1000: user of __GSHandlerCheck (0x1100), which verifies the helper at 0x1180
    //   0x1010: SEH function whose handler is the thunk 0x1130
    //   0x1130: jmp 0x1140     0x1140: call 0x1180 / jmp 0x1190 (the wrapper, own .pdata)
    //   0x1190: __C_specific_handler (export)
    [Fact]
    public void Gs_wrapper_behind_a_jmp_is_identified_by_its_body()
    {
        var image = new SyntheticImage()
            .Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1100, handlerDataRva: 0x11C0)
            .Code(0x1010, 0x90, 0x90, 0xC3, 0x31, 0xC0, 0xC3).Pdata(0x1010, 0x1016, handlerRva: 0x1130, handlerDataRva: 0x11D0)
            .Code(0x1100, GsHandlerCheck).Pdata(0x1100, 0x111D)
            .Code(0x1130, 0xE9, 0x0B, 0x00, 0x00, 0x00)
            .Code(0x1140, 0xE8, 0x3B, 0x00, 0x00, 0x00, 0xE9, 0x46, 0x00, 0x00, 0x00).Pdata(0x1140, 0x114A)
            .Code(0x1180, 0xC3)
            .Code(0x1190, 0xC3).Export("__C_specific_handler", 0x1190)
            .Data(0x11C0, 0x20)
            .Data(0x11D0, 1, 0x1010, 0x1012, 1, 0x1013)
            .Analyze();
        var f = Only(image, 0x1010);

        Assert.Equal(ExceptionHandlerKind.CSpecific, f.ExceptionHandler!.Kind);
        Assert.Equal("__GSHandlerCheck_SEH", f.ExceptionHandler.Name);
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
    }

    [Fact]
    public void Import_thunk_names_a_cxx_handler_which_freezes_the_function()
    {
        // 0x1180: jmp [rip+0x6A] -> IAT slot 0x11F0
        var image = new SyntheticImage()
            .Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1180, handlerDataRva: 0x11C0)
            .Code(0x1180, 0xFF, 0x25, 0x6A, 0x00, 0x00, 0x00)
            .Import("__CxxFrameHandler4", 0x11F0)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CxxFrameHandler4, f.ExceptionHandler!.Kind);
        Assert.Contains("import thunk", f.ExceptionHandler.Evidence);
        Assert.StartsWith("cxx-eh:", f.SafetyStatus.DowngradeReason);
        Assert.True(Only(image, 0x1180).DiscoveredBy.HasFlag(DiscoverySource.ExceptionTable));
    }

    // Two SEH functions sharing a statically linked, unexported handler at 0x1190 (no PDB, no import).
    private static SyntheticImage TwoSehFunctions(uint secondJumpTarget, bool second = true)
    {
        var image = new SyntheticImage()
            .Code(0x1000, 0x90, 0x90, 0xC3, 0x31, 0xC0, 0xC3)
            .Pdata(0x1000, 0x1006, handlerRva: 0x1190, handlerDataRva: 0x11C0)
            .Code(0x1020, ReturnOne)
            .Code(0x1190, 0xC3).Pdata(0x1190, 0x1191)
            .Data(0x11C0, 1, 0x1000, 0x1002, 0x1020, 0x1003);
        return second
            ? image.Code(0x1010, 0x90, 0x90, 0xC3, 0x31, 0xC0, 0xC3)
                .Pdata(0x1010, 0x1016, handlerRva: 0x1190, handlerDataRva: 0x11E0)
                .Data(0x11E0, 1, 0x1010, 0x1012, 0x1020, secondJumpTarget)
            : image;
    }

    [Fact]
    public void Static_handler_whose_users_all_carry_scope_tables_is_inferred_as_c_specific()
    {
        var image = TwoSehFunctions(secondJumpTarget: 0x1013).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CSpecific, f.ExceptionHandler!.Kind);
        Assert.True(f.ExceptionHandler.InferredFromData);
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
        Assert.Equal(Transformability.RelocatableOnly, Only(image, 0x1010).SafetyStatus.Level);
    }

    [Fact]
    public void One_user_that_does_not_fit_leaves_the_handler_unknown_for_all()
    {
        var image = TwoSehFunctions(secondJumpTarget: 0x1100).Analyze(); // __except target outside its function

        Assert.Equal(ExceptionHandlerKind.Unknown, Only(image, 0x1000).ExceptionHandler!.Kind);
        Assert.Equal(Transformability.Frozen, Only(image, 0x1000).SafetyStatus.Level);
    }

    [Fact]
    public void A_single_user_is_not_enough_to_infer_a_handler()
    {
        var image = TwoSehFunctions(secondJumpTarget: 0x1013, second: false).Analyze();

        Assert.Equal(ExceptionHandlerKind.Unknown, Only(image, 0x1000).ExceptionHandler!.Kind);
    }

    [Fact]
    public void Static_handler_whose_users_all_carry_fh3_func_infos_is_inferred_as_fh3()
    {
        var image = new SyntheticImage()
            .Code(0x1000, 0x90, 0xC3).Pdata(0x1000, 0x1002, handlerRva: 0x1180, handlerDataRva: 0x11F8)
            .Code(0x1010, 0x90, 0xC3).Pdata(0x1010, 0x1012, handlerRva: 0x1180, handlerDataRva: 0x11F0)
            .Code(0x1060, 0x48, 0x8D, 0x4A, 0x70, 0xC3)
            .Code(0x1070, 0x48, 0x8D, 0x4A, 0x70, 0xC3)
            .Code(0x1180, ReturnOne).Pdata(0x1180, 0x1186)
            .Data(0x11F8, 0x1100)
            .Data(0x1100, 0x19930522, 1, 0x1140, 0, 0, 1, 0x1150, 0, 0, 0)
            .Data(0x1140, 0xFFFFFFFF, 0x1060)
            .Data(0x1150, 0x1001, 0)
            .Data(0x11F0, 0x1080)
            .Data(0x1080, 0x19930522, 1, 0x10B0, 0, 0, 1, 0x10C0, 0, 0, 0)
            .Data(0x10B0, 0xFFFFFFFF, 0x1070)
            .Data(0x10C0, 0x1011, 0)
            .Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(ExceptionHandlerKind.CxxFrameHandler3, f.ExceptionHandler!.Kind);
        Assert.True(f.ExceptionHandler.InferredFromData);
        Assert.Equal(Transformability.RelocatableOnly, f.SafetyStatus.Level);
    }
}
