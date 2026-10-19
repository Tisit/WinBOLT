using WinBolt.Core.Ir;
using WinBolt.Core.Passes;

namespace WinBolt.Core.Tests;

[RegisterPass]
public sealed class FirstPass : IAnalysisPass
{
    public string Name => "First";
    public void Run(BinaryImage image, PassContext context) { }
}

[RegisterPass(DependsOn = ["First"])]
public sealed class SecondPass : IAnalysisPass
{
    public string Name => "Second";
    public void Run(BinaryImage image, PassContext context) { }
}

[RegisterPass(DependsOn = ["Second"])]
public sealed class ThirdPass : IAnalysisPass
{
    public string Name => "Third";
    public void Run(BinaryImage image, PassContext context) { }
}

public class PassRegistryTests
{
    [Fact]
    public void CreateAnalysisPasses_OrdersByDependency()
    {
        var registry = PassRegistry.Discover(typeof(PassRegistryTests).Assembly);
        var passes = registry.CreateAnalysisPasses();

        var names = passes.Select(p => p.Name).ToList();

        Assert.True(names.IndexOf("First") < names.IndexOf("Second"));
        Assert.True(names.IndexOf("Second") < names.IndexOf("Third"));
    }

    [Fact]
    public void CreateAnalysisPasses_IncludesAllRegisteredPasses()
    {
        var registry = PassRegistry.Discover(typeof(PassRegistryTests).Assembly);
        var passes = registry.CreateAnalysisPasses();

        Assert.Contains(passes, p => p.Name == "First");
        Assert.Contains(passes, p => p.Name == "Second");
        Assert.Contains(passes, p => p.Name == "Third");
    }
}
