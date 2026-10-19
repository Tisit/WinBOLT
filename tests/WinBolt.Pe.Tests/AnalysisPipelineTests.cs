using WinBolt.Core.Ir;
using WinBolt.Core.Passes;

namespace WinBolt.Pe.Tests;

/// <summary>Structural invariants of the full Stage 1 pipeline on real binaries.</summary>
public class AnalysisPipelineTests
{
    public static TheoryData<string> SystemBinaries => FunctionDiscoveryTests.SystemBinaries;

    private static BinaryImage? Analyze(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var image = PeImageReader.Read(path);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return image;
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Every_function_gets_a_safety_verdict_with_a_reason_when_downgraded(string path)
    {
        if (Analyze(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.All(image.Functions, f =>
        {
            Assert.NotEqual(Transformability.Unanalyzed, f.SafetyStatus.Level);
            Assert.Equal(f.SafetyStatus.Level != Transformability.FullyTransformable, f.SafetyStatus.DowngradeReason is not null);
        });
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Blocks_are_contiguous_instructions_inside_their_function(string path)
    {
        if (Analyze(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        foreach (var function in image.Functions)
        {
            foreach (var block in function.BasicBlocks)
            {
                var instructions = image.Instructions.Slice(block.InstructionStart, block.InstructionCount);
                for (int i = 1; i < instructions.Length; i++)
                {
                    Assert.Equal(instructions[i - 1].NextIP, instructions[i].IP);
                }

                Assert.Contains(function.Ranges, r =>
                    block.StartRva >= r.StartRva && block.StartRva + block.Length <= r.StartRva + r.Length);
            }
        }
    }

    [SkippableTheory]
    [InlineData(@"C:\Windows\System32\ntdll.dll")]
    [InlineData(@"C:\Windows\System32\kernel32.dll")]
    public void Handlers_are_identified_and_every_scope_table_validates(string path)
    {
        if (Analyze(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        // Confirmed against Microsoft's public symbols for these builds: the dominant handler is
        // __GSHandlerCheck, and __C_specific_handler comes from ntdll's export or an import thunk.
        var kinds = image.Functions.Where(f => f.ExceptionHandler is not null).Select(f => f.ExceptionHandler!.Kind).ToHashSet();
        Assert.Contains(ExceptionHandlerKind.GsCookieCheck, kinds);
        Assert.Contains(ExceptionHandlerKind.CSpecific, kinds);

        var seh = image.Functions.Where(f => f.ExceptionHandler?.Kind == ExceptionHandlerKind.CSpecific).ToList();
        Assert.All(seh, f => Assert.NotNull(f.ScopeTable));
    }

    [SkippableFact]
    public void GS_wrapper_handlers_are_identified_as_their_inner_handler()
    {
        // In this build (confirmed against its public symbols) ActivationManager.dll links all
        // three wrappers; each must resolve to its inner handler's kind.
        if (Analyze(@"C:\Windows\System32\ActivationManager.dll") is not { } image)
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var byName = image.ExceptionHandlers.Values.Where(h => h.Name is not null).ToLookup(h => h.Name!, h => h.Kind);
        Assert.Contains(ExceptionHandlerKind.CSpecific, byName["__GSHandlerCheck_SEH"]);
        Assert.Contains(ExceptionHandlerKind.CxxFrameHandler3, byName["__GSHandlerCheck_EH"]);
        Assert.Contains(ExceptionHandlerKind.CxxFrameHandler4, byName["__GSHandlerCheck_EH4"]);
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Every_cxx_eh_funclet_is_a_function_entry(string path)
    {
        if (Analyze(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var entries = image.Functions.Select(f => f.EntryRva).ToHashSet();
        Assert.All(image.CxxEhTables.Values.SelectMany(t => t.FuncletRvas), rva => Assert.Contains(rva, entries));
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Every_edge_is_recorded_at_both_ends(string path)
    {
        if (Analyze(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        foreach (var block in image.Functions.SelectMany(f => f.BasicBlocks))
        {
            Assert.All(block.Successors, e => Assert.Contains(e, e.Target.Predecessors));
            Assert.All(block.Predecessors, e => Assert.Contains(e, e.Source.Successors));
        }
    }
}
