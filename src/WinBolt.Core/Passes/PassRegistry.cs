using System.Reflection;

namespace WinBolt.Core.Passes;

/// <summary>
/// Discovers <see cref="RegisterPassAttribute"/>-marked pass types via reflection and
/// orders them by declared dependencies (§11). Adding a new pass class with the attribute
/// is sufficient for it to be discovered — no framework modification required.
/// </summary>
public sealed class PassRegistry
{
    private readonly List<(Type Type, string[] DependsOn)> _analysisPasses = [];
    private readonly List<(Type Type, string[] DependsOn)> _optimizationPasses = [];
    private readonly List<(Type Type, string[] DependsOn)> _validationPasses = [];
    private readonly List<(Type Type, string[] DependsOn)> _reportProviders = [];

    public static PassRegistry Discover(params Assembly[] assemblies)
    {
        var registry = new PassRegistry();

        foreach (var assembly in assemblies)
        {
            foreach (var type in assembly.GetTypes())
            {
                if (type.IsAbstract)
                {
                    continue;
                }

                var attribute = type.GetCustomAttribute<RegisterPassAttribute>();
                if (attribute is null)
                {
                    continue;
                }

                if (typeof(IAnalysisPass).IsAssignableFrom(type))
                {
                    registry._analysisPasses.Add((type, attribute.DependsOn));
                }

                if (typeof(IOptimizationPass).IsAssignableFrom(type))
                {
                    registry._optimizationPasses.Add((type, attribute.DependsOn));
                }

                if (typeof(IValidationPass).IsAssignableFrom(type))
                {
                    registry._validationPasses.Add((type, attribute.DependsOn));
                }

                if (typeof(IReportProvider).IsAssignableFrom(type))
                {
                    registry._reportProviders.Add((type, attribute.DependsOn));
                }
            }
        }

        return registry;
    }

    public IReadOnlyList<IAnalysisPass> CreateAnalysisPasses() =>
        Instantiate<IAnalysisPass>(_analysisPasses, p => p.Name);

    public IReadOnlyList<IOptimizationPass> CreateOptimizationPasses() =>
        Instantiate<IOptimizationPass>(_optimizationPasses, p => p.Name);

    public IReadOnlyList<IValidationPass> CreateValidationPasses() =>
        Instantiate<IValidationPass>(_validationPasses, p => p.Name);

    public IReadOnlyList<IReportProvider> CreateReportProviders() =>
        Instantiate<IReportProvider>(_reportProviders, p => p.Name);

    private static List<T> Instantiate<T>(
        List<(Type Type, string[] DependsOn)> registrations,
        Func<T, string> getName)
    {
        var instances = registrations
            .Select(r => ((T)Activator.CreateInstance(r.Type)!, r.DependsOn))
            .ToList();

        var byName = instances.ToDictionary(i => getName(i.Item1), i => i);

        return TopologicalSort(instances, getName, byName);
    }

    private static List<T> TopologicalSort<T>(
        List<(T Instance, string[] DependsOn)> instances,
        Func<T, string> getName,
        Dictionary<string, (T Instance, string[] DependsOn)> byName)
    {
        var result = new List<T>();
        var visited = new HashSet<string>();
        var visiting = new HashSet<string>();

        void Visit(string name)
        {
            if (visited.Contains(name))
            {
                return;
            }

            if (!byName.TryGetValue(name, out var entry))
            {
                // Dependency on something outside this registration set (a different pass
                // kind, or a name from an assembly not passed to Discover) — nothing more
                // to order here.
                return;
            }

            if (!visiting.Add(name))
            {
                throw new InvalidOperationException($"Cyclic pass dependency detected involving '{name}'.");
            }

            foreach (var dependency in entry.DependsOn)
            {
                Visit(dependency);
            }

            visiting.Remove(name);
            visited.Add(name);
            result.Add(entry.Instance);
        }

        foreach (var name in byName.Keys)
        {
            Visit(name);
        }

        return result;
    }
}
