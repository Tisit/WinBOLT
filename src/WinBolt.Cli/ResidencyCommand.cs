using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;
using WinBolt.Rewrite;

/// <summary>
/// <c>winbolt residency &lt;input&gt; &lt;output&gt; --profile &lt;etl&gt;</c>: where a trace of an append-mode
/// output still runs original code (DesignDoc §6.1 "Dual residency"): trampolines and why their
/// indirect callers were not redirected, hot unmoved functions, and execution inside moved
/// functions' original bodies, which is either a known case or an undiscovered reference.
/// </summary>
internal static class ResidencyCommand
{
    public static int Run(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: winbolt residency <input-pe> <rewritten-pe> --profile <etl of the rewritten image> [--process <name>] [--profile-during <function>] [--pdb <file>] [--symbols <dir>]... [--top N]");
            Console.WriteLine("  Reads a trace of the rewritten image (tools/profile/Capture-Lbr.ps1 or -SamplingOnly) and reports where it still");
            Console.WriteLine("  runs original code: trampolines (with the reason pointer redirection left each indirect target alone),");
            Console.WriteLine("  unmoved hot functions, and moved functions' original bodies that still execute.");
            Console.WriteLine("  --profile-during: keep only samples between the first and last execution of this function (decorated name),");
            Console.WriteLine("             found in the input and followed to its copy in the output.");
            Console.WriteLine("  --pdb/--symbols: the INPUT's PDB (names and analysis).");
            return 1;
        }

        string input = Path.GetFullPath(args[0]), output = Path.GetFullPath(args[1]);
        string? pdbPath = null, profilePath = null, processName = null, profileDuring = null;
        int top = 15;
        var symbols = new List<string>();
        for (int i = 2; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--pdb" when i + 1 < args.Length:
                    pdbPath = args[++i];
                    break;
                case "--symbols" when i + 1 < args.Length:
                    symbols.Add(args[++i]);
                    break;
                case "--profile" when i + 1 < args.Length:
                    profilePath = args[++i];
                    break;
                case "--process" when i + 1 < args.Length:
                    processName = args[++i];
                    break;
                case "--profile-during" when i + 1 < args.Length:
                    profileDuring = args[++i];
                    break;
                case "--top" when i + 1 < args.Length && int.TryParse(args[i + 1], out int n) && n > 0:
                    top = n;
                    i++;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown or incomplete option: {args[i]}");
                    return 1;
            }
        }

        if (profilePath is null)
        {
            Console.Error.WriteLine("--profile is required: a trace of the rewritten image.");
            return 1;
        }

        foreach (string path in new[] { input, output, profilePath })
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"File not found: {path}");
                return 1;
            }
        }

        var original = PeImageReader.Read(input);
        PdbSymbolLoader.Load(original, pdbPath, symbols);
        CliCommon.Analyze(original);
        var rewritten = PeImageReader.Read(output);
        var map = ResidencyMap.Build(original, rewritten);
        var analysis = new ResidencyAnalysis(map);
        (uint Start, uint End)[]? duringRanges = null;
        if (profileDuring is not null)
        {
            // The function's code in the output: its original ranges, plus its copy (the output's
            // unwind entry at the copy's start gives the hot part's extent).
            var functions = original.Functions.Where(f => f.Name == profileDuring).ToList();
            if (functions.Count == 0)
            {
                Console.Error.WriteLine($"--profile-during: no function named {profileDuring} in the input (use the decorated PDB name)");
                return 1;
            }

            duringRanges = functions.SelectMany(f => f.Ranges).Select(r => ((uint)r.StartRva, (uint)r.StartRva + r.Length))
                .Concat(functions.Select(map.MovedOf).OfType<MovedOriginal>().Where(m => m.HasTrampoline)
                    .SelectMany(m => rewritten.ExceptionData.Where(e => e.BeginAddress == m.CopyEntry).Select(e => (e.BeginAddress, e.EndAddress))))
                .ToArray();
        }

        string? window;
        try
        {
            window = EtwLbrProfile.ReadRaw(rewritten, profilePath, processName, analysis.AddBranch, analysis.AddIpSample, profileDuring, duringRanges);
        }
        catch (ProfileBindingException ex)
        {
            Console.Error.WriteLine($"Profile rejected: {ex.Message}");
            return 1;
        }
        catch (ProfileWindowException ex)
        {
            Console.Error.WriteLine($"--profile-during: {ex.Message}");
            return 1;
        }

        var copyOf = map.Moved.Where(m => m.HasTrampoline).ToDictionary(m => m.Start, m => m.CopyEntry!.Value);
        var plan = PointerRedirection.Plan(original, copyOf);
        Console.WriteLine($"Residency of {output}");
        Console.WriteLine($"  input {input}, trace {profilePath}{window}");
        foreach (string line in analysis.Format(plan, top).TrimEnd().Split('\n'))
        {
            Console.WriteLine($"  {line.TrimEnd('\r')}");
        }

        return 0;
    }
}
