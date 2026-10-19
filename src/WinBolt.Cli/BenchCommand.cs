using System.Diagnostics;
using System.Runtime.InteropServices;
using WinBolt.Core.Measurement;

/// <summary>
/// <c>winbolt bench &lt;baseline&gt; &lt;candidate&gt;... -- &lt;arguments&gt;</c>: the Stage 5 benchmark
/// harness. Every round runs the baseline, a byte-identical copy of it (the noise floor) and
/// each candidate once, in a shuffled order, so drift (turbo, thermals, background load) hits
/// all of them alike. Reports distributions and paired confidence intervals of wall time and
/// CPU cycles, and claims a change only when it clears the noise floor (DesignDoc Stage 5).
/// CPU cycles come from QueryProcessCycleTime: TotalProcessorTime ticks in 15.6 ms steps,
/// too coarse to compare runs of about a second.
/// <para>
/// A candidate may be a group, <c>name=a.exe,b.exe,...</c>: builds of the same layout at
/// different alignments (<c>rewrite --layout-shift</c>). Every round runs every member, and the
/// group's time for the round is their mean, so a comparison is between layouts on average,
/// not between two lucky or unlucky placements (DesignDoc §6.2: ~0.5-1.5 points of layout noise).
/// </para>
/// </summary>
internal static class BenchCommand
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryProcessCycleTime(IntPtr process, out ulong cycles);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMemoryCounters
    {
        public uint Cb;
        public uint PageFaultCount;
        public nuint PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage,
            QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage;
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "K32GetProcessMemoryInfo")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMemoryInfo(IntPtr process, out ProcessMemoryCounters counters, uint size);

    public static int Run(string[] args)
    {
        int separator = Array.IndexOf(args, "--");
        var options = separator >= 0 ? args[..separator] : args;
        var programArguments = separator >= 0 ? args[(separator + 1)..] : [];
        int rounds = 20, warmup = 2;
        bool copyBeside = false;
        var binaries = new List<string>();
        var groups = new List<(string Label, List<string> Members)>();
        for (int i = 0; i < options.Length; i++)
        {
            switch (options[i])
            {
                case "--rounds" when i + 1 < options.Length && int.TryParse(options[i + 1], out int n) && n >= 5:
                    rounds = n;
                    i++;
                    break;
                case "--copy-beside":
                    copyBeside = true;
                    break;
                case "--warmup" when i + 1 < options.Length && int.TryParse(options[i + 1], out int w) && w >= 0:
                    warmup = w;
                    i++;
                    break;
                case var group when binaries.Count > 0 && group.Contains('=') && !File.Exists(group):
                    int equals = group.IndexOf('=');
                    groups.Add((group[..equals], group[(equals + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Path.GetFullPath).ToList()));
                    break;
                default:
                    if (binaries.Count == 0)
                    {
                        binaries.Add(Path.GetFullPath(options[i]));
                    }
                    else
                    {
                        groups.Add(($"candidate {groups.Count + 1}", [Path.GetFullPath(options[i])]));
                    }

                    break;
            }
        }

        if (binaries.Count != 1 || groups.Count == 0 || groups.Any(g => g.Members.Count == 0) ||
            binaries.Concat(groups.SelectMany(g => g.Members)).Any(b => !File.Exists(b)))
        {
            Console.WriteLine("Usage: winbolt bench <baseline-exe> <candidate>... [--rounds N] [--warmup N] [--copy-beside] -- <program arguments>");
            Console.WriteLine("  --copy-beside: put the noise-floor copy next to the baseline (<name>-benchcopy.exe, removed afterwards),");
            Console.WriteLine("                 for programs that find their data next to the exe.");
            Console.WriteLine("  A candidate is an exe, or a group name=a.exe,b.exe,... (the same layout at several --layout-shift");
            Console.WriteLine("  values): each round runs every member and the group counts their mean.");
            Console.WriteLine("  Alternates runs of the baseline, a byte-identical copy of it (noise floor) and each");
            Console.WriteLine("  candidate, and reports wall/CPU time distributions with paired 95% intervals; with two or");
            Console.WriteLine("  more candidates, also each one against the first.");
            return 1;
        }

        string scratch = Directory.CreateTempSubdirectory("winbolt-bench-").FullName;
        try
        {
            // The copy keeps the baseline's name and PDB-free directory layout: only the path differs.
            string copy = copyBeside
                ? Path.Combine(Path.GetDirectoryName(binaries[0])!, Path.GetFileNameWithoutExtension(binaries[0]) + "-benchcopy" + Path.GetExtension(binaries[0]))
                : Path.Combine(scratch, "copy", Path.GetFileName(binaries[0]));
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            File.Copy(binaries[0], copy, overwrite: copyBeside);
            var labels = new List<string> { "baseline", "baseline copy" };
            labels.AddRange(groups.Select(g => g.Label));
            var members = new List<List<string>> { new() { binaries[0] }, new() { copy } };
            members.AddRange(groups.Select(g => g.Members));
            var runs = members.SelectMany((m, group) => m.Select(path => (Group: group, Path: path))).ToList();

            Console.WriteLine($"WinBolt bench: {rounds} rounds (+{warmup} warm-up), arguments: {string.Join(' ', programArguments)}");
            for (int i = 0; i < labels.Count; i++)
            {
                Console.WriteLine($"  {labels[i],-14} {(i == 1 ? "(copy of the baseline)" : members[i].Count == 1 ? members[i][0] : $"group of {members[i].Count}: {string.Join(", ", members[i].Select(Path.GetFileName))}")}");
            }

            var wall = labels.Select(_ => new List<double>()).ToList();
            var cpu = labels.Select(_ => new List<double>()).ToList();
            var pageFaults = labels.Select(_ => new List<double>()).ToList();
            var random = new Random(12345);
            string workDirectory = Path.Combine(scratch, "work");
            Directory.CreateDirectory(workDirectory);
            for (int round = 0; round < warmup + rounds; round++)
            {
                var roundWall = new double[labels.Count];
                var roundCpu = new double[labels.Count];
                var roundFaults = new double[labels.Count];
                foreach (var run in runs.OrderBy(_ => random.Next()))
                {
                    var (seconds, gigacycles, faults, exitCode) = Measure(run.Path, programArguments, workDirectory);
                    if (exitCode != 0)
                    {
                        Console.Error.WriteLine($"{labels[run.Group]} ({Path.GetFileName(run.Path)}) exited with {exitCode} in round {round + 1}; stopping.");
                        return 3;
                    }

                    roundWall[run.Group] += seconds / members[run.Group].Count;
                    roundCpu[run.Group] += gigacycles / members[run.Group].Count;
                    roundFaults[run.Group] += (double)faults / members[run.Group].Count;
                }

                if (round >= warmup)
                {
                    for (int i = 0; i < labels.Count; i++)
                    {
                        wall[i].Add(roundWall[i]);
                        cpu[i].Add(roundCpu[i]);
                        pageFaults[i].Add(roundFaults[i]);
                    }
                }

                Console.Error.Write($"\r  round {round + 1}/{warmup + rounds}");
            }

            Console.Error.WriteLine();
            Print("Wall time (s)", labels, wall);
            Print("CPU cycles, all threads (Gcycles, QueryProcessCycleTime)", labels, cpu);
            Print("Page faults (soft and hard, GetProcessMemoryInfo; image pages are a part of them)", labels, pageFaults);
            Console.WriteLine();
            Console.WriteLine("  PMU counters are not captured (DesignDoc Stage 5): attribute a win to front-end stalls with VTune.");
            return 0;
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
            if (copyBeside)
            {
                File.Delete(Path.Combine(Path.GetDirectoryName(binaries[0])!, Path.GetFileNameWithoutExtension(binaries[0]) + "-benchcopy" + Path.GetExtension(binaries[0])));
            }
        }
    }

    private static (double Seconds, double Gigacycles, long PageFaults, int ExitCode) Measure(string exe, string[] arguments, string workDirectory)
    {
        var info = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workDirectory,
        };
        foreach (string argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        var stopwatch = Stopwatch.StartNew();
        using var process = Process.Start(info)!;
        var drainOut = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        var drainErr = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        process.WaitForExit();
        stopwatch.Stop();
        Task.WaitAll(drainOut, drainErr);
        if (!QueryProcessCycleTime(process.Handle, out ulong cycles))
        {
            throw new InvalidOperationException($"QueryProcessCycleTime failed ({Marshal.GetLastPInvokeError()})");
        }

        // The counters outlive the process while its handle is open.
        if (!GetProcessMemoryInfo(process.Handle, out var memory, (uint)Marshal.SizeOf<ProcessMemoryCounters>()))
        {
            throw new InvalidOperationException($"GetProcessMemoryInfo failed ({Marshal.GetLastPInvokeError()})");
        }

        return (stopwatch.Elapsed.TotalSeconds, cycles / 1e9, memory.PageFaultCount, process.ExitCode);
    }

    private static void Print(string title, List<string> labels, List<List<double>> times)
    {
        Console.WriteLine();
        Console.WriteLine($"  {title}");
        Console.WriteLine($"    {"",-14} {"median",9} {"mean",9} {"stddev",8} {"min",9} {"max",9}");
        for (int i = 0; i < labels.Count; i++)
        {
            var s = BenchmarkStatistics.Summarize(times[i]);
            Console.WriteLine($"    {labels[i],-14} {s.Median,9:F4} {s.Mean,9:F4} {s.StdDev,8:F4} {s.Min,9:F4} {s.Max,9:F4}");
        }

        var noise = BenchmarkStatistics.Compare(times[0], times[1]);
        Console.WriteLine($"    noise floor (copy / baseline): median {Percent(noise.MedianRatio)}, 95% CI [{Percent(noise.Low)}, {Percent(noise.High)}]");
        for (int i = 2; i < labels.Count; i++)
        {
            var comparison = BenchmarkStatistics.Compare(times[0], times[i]);
            var verdict = BenchmarkStatistics.Judge(comparison, noise);
            Console.WriteLine($"    {labels[i]} / baseline: median {Percent(comparison.MedianRatio)}, 95% CI [{Percent(comparison.Low)}, {Percent(comparison.High)}] -> {Describe(verdict)}");
        }

        // Candidates against the first: the question an A/B asks.
        for (int i = 3; i < labels.Count; i++)
        {
            var comparison = BenchmarkStatistics.Compare(times[2], times[i]);
            var verdict = BenchmarkStatistics.Judge(comparison, noise);
            Console.WriteLine($"    {labels[i]} / {labels[2]}: median {Percent(comparison.MedianRatio)}, 95% CI [{Percent(comparison.Low)}, {Percent(comparison.High)}] -> {Describe(verdict)}");
        }
    }

    private static string Describe(Verdict verdict) => verdict switch
    {
        Verdict.Faster => "FASTER (clears the noise floor)",
        Verdict.Slower => "SLOWER (clears the noise floor)",
        _ => "no change distinguishable from noise",
    };

    private static string Percent(double ratio) => $"{(ratio - 1) * 100:+0.00;-0.00;0.00}%";
}
