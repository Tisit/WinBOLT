using WinBolt.Core.Ir;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Core.Tests;

public class CxxEhParserTests
{
    [Fact]
    public void Fh3_FuncInfo_yields_funclets_and_ip_map_addresses()
    {
        var image = new SyntheticImage()
            // FuncInfo: magic, maxState 2, unwind map, 1 try block, try map, 2 IP entries, IP map, unwindHelp, ESTypeList, EHFlags
            .Data(0x1100, 0x19930522, 2, 0x1140, 1, 0x1150, 2, 0x1180, 0, 0, 0)
            .Data(0x1140, 0xFFFFFFFF, 0x1060, 0, 0)                // unwind map: {-1, funclet 0x1060}, {0, none}
            .Data(0x1150, 0, 0, 1, 1, 0x1164)                      // try block: 1 catch, handler array at 0x1164
            .Data(0x1164, 0, 0, 0, 0x1070, 0x38)                   // HandlerType: catch funclet 0x1070
            .Data(0x1180, 0x1000, 0xFFFFFFFF, 0x1004, 0)           // IP map
            .Build();

        var info = CxxEhParser.ParseFh3(image, 0x1100);

        Assert.Null(info.Problem);
        Assert.Equal([0x1060u, 0x1070], info.FuncletRvas);
        Assert.Equal([0x1000u, 0x1004], info.IpStateRvas);
        Assert.Empty(info.ContinuationRvas);
    }

    [Fact]
    public void Fh3_with_a_bad_magic_number_reports_a_problem()
    {
        var image = new SyntheticImage().Data(0x1100, 0x12345678, 0, 0, 0, 0, 0, 0, 0).Build();

        Assert.StartsWith("bad FuncInfo magic", CxxEhParser.ParseFh3(image, 0x1100).Problem);
    }

    [Fact]
    public void Fh4_compressed_FuncInfo_decodes_every_integer_width()
    {
        var image = new SyntheticImage()
            // header: UnwindMap | TryBlockMap; dispUnwindMap, dispTryBlockMap, dispIPtoStateMap
            .Code(0x1100, 0x18, 0x20, 0x11, 0x00, 0x00, 0x30, 0x11, 0x00, 0x00, 0x50, 0x11, 0x00, 0x00)
            // unwind map: 2 entries; RVA-type funclet 0x1060; dtor 0x1080 on object 0x12345678 (5-byte uint)
            .Code(0x1120, 0x04, 0x06, 0x60, 0x10, 0x00, 0x00, 0x02, 0x80, 0x10, 0x00, 0x00, 0x0F, 0x78, 0x56, 0x34, 0x12)
            // try map: 1 block {0, 0, 1}, handler array at 0x1140
            .Code(0x1130, 0x02, 0x00, 0x00, 0x02, 0x40, 0x11, 0x00, 0x00)
            // handler array: 1 handler; header dispType | one continuation (offset form);
            // dispType 0, catch funclet 0x1070, continuation offset 0x5000 (3-byte uint)
            .Code(0x1140, 0x02, 0x12, 0x00, 0x00, 0x00, 0x00, 0x70, 0x10, 0x00, 0x00, 0x03, 0x80, 0x02)
            // IP map: 2 entries {+0, state -1}, {+200 (2-byte uint), state 0}
            .Code(0x1150, 0x04, 0x00, 0x00, 0x21, 0x03, 0x02)
            .Build();

        var info = CxxEhParser.ParseFh4(image, 0x1100, functionStart: 0x1000);

        Assert.Null(info.Problem);
        Assert.Equal([0x1060u, 0x1080, 0x1070], info.FuncletRvas);
        Assert.Equal([0x6000u], info.ContinuationRvas);
        Assert.Equal([0x1000u, 0x10C8], info.IpStateRvas);
    }

    [Fact]
    public void Fh4_table_running_off_the_image_reports_a_problem()
    {
        var image = new SyntheticImage().Code(0x1100, 0x00, 0xF0, 0xFF, 0x00, 0x00).Build(); // IP map far outside

        Assert.Contains("file-backed data", CxxEhParser.ParseFh4(image, 0x1100, 0x1000).Problem);
    }
}
