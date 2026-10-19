using System.Buffers.Binary;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;

namespace WinBolt.Profile;

/// <summary>The trace holds no profile for this exact image (DesignDoc Stage 2 mismatch policy: reject).</summary>
public sealed class ProfileBindingException(string message) : Exception(message);

/// <summary>The <c>--profile-during</c> function is unknown to the image or was never executed in the trace.</summary>
public sealed class ProfileWindowException(string message) : ArgumentException(message);

/// <summary>
/// Reads an ETW trace with LBR stacks (tools/profile/Capture-Lbr.ps1) and applies it to an
/// analyzed image through <see cref="LbrProfileBuilder"/>. Implements the reader rules in
/// DesignDoc Stage 2, "Prototype result":
/// <list type="number">
/// <item>Only the user-mode entries newer than the newest kernel entry are used: the LBR is not
/// cleared on a context switch, so older entries may belong to another thread.</item>
/// <item>Module maps are per process, reset on process start (PIDs are reused), and follow
/// image unloads.</item>
/// <item>A process is bound only if it loaded this image: same file name, same SizeOfImage,
/// and the same TimeDateStamp and checksum unless the event omits them (image rundown for
/// already-running processes carries no timestamp).</item>
/// <item>Records the CFG cannot place are counted as unmatched, never assigned to an edge
/// (the builder's job).</item>
/// <item>Only the target process is profiled: by default the image itself when it is an
/// .exe, otherwise every process that loaded it (reported).</item>
/// </list>
/// </summary>
public static class EtwLbrProfile
{
    /// <summary>LBR stack events: classic kernel event, task GUID below, opcode 0x20.</summary>
    internal static readonly Guid LbrTask = new("99134383-5248-43fc-834b-529454e75df3");

    internal const int HeaderSize = 24;
    internal const int EntrySize = 24;
    private const ulong KernelSpace = 0x0000800000000000;

    private sealed class ProcessState(string name)
    {
        public string Name { get; } = name;

        public ulong? TargetBase { get; set; }
    }

    /// <param name="processName">Executable name of the process to profile (e.g. "app.exe"); see the class summary for the default.</param>
    /// <param name="during">
    /// Name of a function that marks the phase to profile: per process, only samples between the
    /// first and the last sample that touches it are kept (e.g. a per-tick update, to leave out
    /// loading and shutdown). Null keeps the whole trace.
    /// </param>
    /// <exception cref="ProfileBindingException">No process in the trace loaded this exact image.</exception>
    /// <exception cref="ProfileWindowException"><paramref name="during"/> names no function, or no bound process executed it.</exception>
    /// <param name="etlPath">The trace, captured by tools/profile/Capture-Lbr.ps1.</param>
    /// <param name="ipSamplesOnly">
    /// Ignore the branch records and build the profile from the sampled instruction pointers alone
    /// (<see cref="IpProfileBuilder"/>): an estimate of <see cref="ProfileFidelity.SamplingOnly"/>, for
    /// machines without LBR and to measure what the branch records are worth.
    /// </param>
    /// <param name="estimator">How block counts are estimated from IP samples; used only with <paramref name="ipSamplesOnly"/>.</param>
    public static ProfileSummary Apply(BinaryImage image, string etlPath, string? processName = null, string? during = null,
        bool ipSamplesOnly = false, IpEstimator estimator = IpEstimator.Max)
    {
        Dictionary<int, (double First, double Last)>? windows = null;
        string? windowNote = null;
        if (during is not null)
        {
            var ranges = image.Functions.Where(f => f.Name == during).SelectMany(f => f.Ranges)
                .Select(r => ((uint)r.StartRva, (uint)r.StartRva + r.Length)).ToArray();
            if (ranges.Length == 0)
            {
                throw new ProfileWindowException($"no function named {during} in the image (use the decorated PDB name)");
            }

            (windows, windowNote) = Window(image, etlPath, processName, during, ranges);
        }

        var (summary, _) = Scan(image, etlPath, processName, ipSamplesOnly ? null : new LbrProfileBuilder(image), null, windows,
            ipSamplesOnly ? new IpProfileBuilder(image, estimator) : null);
        summary!.Binding += windowNote;
        image.ProfileSummary = summary;
        return summary;
    }

    /// <summary>
    /// Per bound process, the time between the first and the last sample touching any of
    /// <paramref name="ranges"/> (the code of the function <paramref name="during"/>), and a note for the binding text.
    /// </summary>
    private static (Dictionary<int, (double First, double Last)> Windows, string Note) Window(BinaryImage image, string etlPath,
        string? processName, string during, (uint Start, uint End)[] ranges)
    {
        bool Hits(uint? rva) => rva is { } x && ranges.Any(r => x >= r.Start && x < r.End);
        var found = new Dictionary<int, (double First, double Last)>();
        var (_, samples) = Scan(image, etlPath, processName, null, (pid, time, from, to, _) =>
        {
            if (Hits(from) || Hits(to))
            {
                found[pid] = found.TryGetValue(pid, out var w) ? (w.First, time) : (time, time);
            }
        });
        if (found.Count == 0)
        {
            throw new ProfileWindowException($"no profiled process executed {during} in the trace");
        }

        int kept = samples.Count(t => found.TryGetValue(t.Pid, out var w) && t.Time >= w.First && t.Time <= w.Last);
        string note = $"; window: while {during} runs (" +
            string.Join(", ", found.Select(w => $"pid {w.Key} {w.Value.First / 1000:F1}-{w.Value.Last / 1000:F1} s")) +
            $"), {kept * 100.0 / Math.Max(1, samples.Count):F1}% of LBR samples kept";
        return (found, note);
    }

    /// <summary>
    /// Reads the trace's raw data for this exact image, without applying it to a CFG (the image need
    /// not be analyzed): every LBR record of a bound process that touches the image (RVAs, null for
    /// an address outside it) and every sampled instruction pointer inside it. Used to profile a
    /// rewritten image, whose new code no analysis covers (DesignDoc §6.1 "Dual residency").
    /// </summary>
    /// <exception cref="ProfileBindingException">No process in the trace loaded this exact image.</exception>
    /// <param name="during">
    /// With <paramref name="duringRanges"/> (that function's code in this image), keep only samples between
    /// the first and the last one touching it, as <see cref="Apply"/> does. Returns the window note, or null.
    /// </param>
    public static string? ReadRaw(BinaryImage image, string etlPath, string? processName, Action<uint?, uint?> branch, Action<uint> ipSample,
        string? during = null, (uint Start, uint End)[]? duringRanges = null)
    {
        Dictionary<int, (double First, double Last)>? windows = null;
        string? note = null;
        if (during is not null && duringRanges is not null)
        {
            (windows, note) = Window(image, etlPath, processName, during, duringRanges);
        }

        Scan(image, etlPath, processName, null, (pid, time, from, to, isIp) =>
        {
            if (windows is not null && !(windows.TryGetValue(pid, out var w) && time >= w.First && time <= w.Last))
            {
                return;
            }

            if (isIp)
            {
                ipSample(from!.Value);
            }
            else
            {
                branch(from, to);
            }
        });
        return note;
    }

    /// <summary>
    /// When each function first ran: per function id, the time (ms into the trace) of the first
    /// LBR record or IP sample of a bound process touching its code. The earliest bound process
    /// counts (one run of the program is the startup being ordered). Functions never touched are absent.
    /// </summary>
    /// <exception cref="ProfileBindingException">No process in the trace loaded this exact image.</exception>
    public static Dictionary<int, double> FirstTouch(BinaryImage image, string etlPath, string? processName = null)
    {
        var ranges = image.Functions.SelectMany(f => f.Ranges.Select(r => (Start: (uint)r.StartRva, End: (uint)r.StartRva + r.Length, f.Id)))
            .OrderBy(r => r.Start).ToArray();
        var starts = ranges.Select(r => r.Start).ToArray();
        int? Owner(uint? rva)
        {
            if (rva is not { } x)
            {
                return null;
            }

            int i = Array.BinarySearch(starts, x);
            i = i >= 0 ? i : ~i - 1;
            return i >= 0 && x < ranges[i].End ? ranges[i].Id : null;
        }

        var first = new Dictionary<int, double>();
        int? pidSeen = null;
        Scan(image, etlPath, processName, null, (pid, time, from, to, _) =>
        {
            pidSeen ??= pid;
            if (pid != pidSeen)
            {
                return;
            }

            foreach (var id in new[] { Owner(from), Owner(to) })
            {
                if (id is { } f && !first.ContainsKey(f))
                {
                    first[f] = time;
                }
            }
        });
        return first;
    }

    /// <summary>
    /// The first run's distinct code touches in time order: each LBR (from, to) pair of the earliest
    /// bound process the first time it appears, and each sampled instruction pointer (from = to)
    /// the first time. Input to the page model (WinBolt.Rewrite PageModel).
    /// </summary>
    public static List<(double Time, uint? From, uint? To)> FirstTouches(BinaryImage image, string etlPath, string? processName = null)
    {
        var seen = new HashSet<ulong>();
        var touches = new List<(double, uint?, uint?)>();
        int? pidSeen = null;
        Scan(image, etlPath, processName, null, (pid, time, from, to, _) =>
        {
            pidSeen ??= pid;
            if (pid == pidSeen && seen.Add(((ulong)(from ?? uint.MaxValue) << 32) | (to ?? uint.MaxValue)))
            {
                touches.Add((time, from, to));
            }
        });
        return touches;
    }

    /// <summary>
    /// One pass over the trace. With a builder, applies the samples inside <paramref name="windows"/>
    /// (all when null) and returns its summary. <paramref name="probe"/> sees every bound LBR record
    /// and IP sample (from = to = IP, last argument true) as (pid, time in ms, from, to, is IP sample). Also returns the pid and time of
    /// every LBR sample touching the image.
    /// </summary>
    private static (ProfileSummary? Summary, List<(int Pid, double Time)> Samples) Scan(BinaryImage image, string etlPath,
        string? processName, LbrProfileBuilder? builder, Action<int, double, uint?, uint?, bool>? probe,
        Dictionary<int, (double First, double Last)>? windows = null, IpProfileBuilder? ipBuilder = null)
    {
        string target = Path.GetFileName(image.FilePath);
        bool isExe = target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        string? filter = processName ?? (isExe ? target : null);

        var processes = new Dictionary<int, ProcessState>();
        var bound = new HashSet<(int Pid, string Name)>();
        var samples = new List<(int Pid, double Time)>();
        int rejectedLoads = 0;
        long lbrEvents = 0;
        var records = new BranchRecord[32];
        bool InWindow(int pid, double time) =>
            windows is null || (windows.TryGetValue(pid, out var w) && time >= w.First && time <= w.Last);

        using (var source = new ETWTraceEventSource(etlPath))
        {
            var kernel = new KernelTraceEventParser(source);

            void Started(ProcessTraceData d) => processes[d.ProcessID] = new ProcessState(d.ImageFileName);
            kernel.ProcessStart += Started;
            kernel.ProcessDCStart += Started;

            void Loaded(ImageLoadTraceData d)
            {
                if (!Path.GetFileName(d.FileName).Equals(target, StringComparison.OrdinalIgnoreCase) ||
                    !processes.TryGetValue(d.ProcessID, out var process) ||
                    (filter is not null && !process.Name.Equals(filter, StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                bool same = (ulong)d.ImageSize == image.SizeOfImage &&
                            (d.TimeDateStamp == 0 || (uint)d.TimeDateStamp == image.TimeDateStamp) &&
                            (d.ImageChecksum == 0 || (uint)d.ImageChecksum == image.Checksum);
                if (!same)
                {
                    rejectedLoads++;
                    return;
                }

                process.TargetBase = d.ImageBase;
                bound.Add((d.ProcessID, process.Name));
            }

            kernel.ImageLoad += Loaded;
            kernel.ImageDCStart += Loaded;
            kernel.ImageUnload += d =>
            {
                if (processes.TryGetValue(d.ProcessID, out var process) && process.TargetBase == d.ImageBase)
                {
                    process.TargetBase = null;
                }
            };

            kernel.PerfInfoSample += d =>
            {
                if (Rva(processes, d.ProcessID, d.InstructionPointer, image.SizeOfImage) is { } rva)
                {
                    probe?.Invoke(d.ProcessID, d.TimeStampRelativeMSec, rva, rva, true);
                    if (InWindow(d.ProcessID, d.TimeStampRelativeMSec))
                    {
                        builder?.AddIpSample(rva);
                        ipBuilder?.AddSample(rva);
                    }
                }
            };

            source.AllEvents += e =>
            {
                if (ipBuilder is not null || e.TaskGuid != LbrTask || e.EventDataLength < HeaderSize + EntrySize)
                {
                    return;
                }

                lbrEvents++;
                var data = e.EventData();
                int pid = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8));
                if (!processes.TryGetValue(pid, out var process) || process.TargetBase is null)
                {
                    return;
                }

                int count = Decode(data, records, a => Rva(processes, pid, a, image.SizeOfImage));
                if (count == 0)
                {
                    return;
                }

                double time = e.TimeStampRelativeMSec;
                samples.Add((pid, time));
                if (probe is not null)
                {
                    foreach (var record in records.AsSpan(0, count))
                    {
                        probe(pid, time, record.From, record.To, false);
                    }
                }

                if (builder is not null && InWindow(pid, time))
                {
                    builder.AddSample(records.AsSpan(0, count));
                }
            };

            source.Process();
        }

        if (bound.Count == 0)
        {
            throw new ProfileBindingException(
                $"no process{(filter is null ? string.Empty : $" named {filter}")} in the trace loaded {target} " +
                $"with SizeOfImage 0x{image.SizeOfImage:X} and TimeDateStamp 0x{image.TimeDateStamp:X}" +
                (rejectedLoads > 0 ? $" ({rejectedLoads} loads of that name are a different version)" : string.Empty));
        }

        if (ipBuilder is not null)
        {
            ipBuilder.Finish();
            var estimate = ipBuilder.Summary;
            estimate.Binding =
                BoundProcesses(bound.Count, filter) +
                "; INSTRUCTION-POINTER SAMPLES ONLY: block, edge and call counts are estimates, not measurements" +
                (rejectedLoads > 0 ? $"; {rejectedLoads} loads of a different version ignored" : string.Empty);
            return (estimate, samples);
        }

        if (builder is null)
        {
            return (null, samples);
        }

        builder.Finish();
        var summary = builder.Summary;
        summary.Fidelity = summary.Records > 0 ? ProfileFidelity.EdgeAccurate : ProfileFidelity.SamplingOnly;
        summary.Binding =
            BoundProcesses(bound.Count, filter) +
            (rejectedLoads > 0 ? $"; {rejectedLoads} loads of a different version ignored" : string.Empty) +
            $"; {lbrEvents:N0} LBR events in the trace";
        return (summary, samples);
    }

    private static string BoundProcesses(int count, string? filter) =>
        $"{count} process(es) loaded this exact image" +
        (filter is null ? " (all processes: pass a process name to profile only one)" : $" (process {filter})");

    /// <summary>
    /// Decodes one LBR event's entries (newest first) into image RVAs, stopping at the first
    /// kernel-mode entry (rule 1). Returns how many records were written; 0 when none touches
    /// the image.
    /// </summary>
    internal static int Decode(ReadOnlySpan<byte> data, Span<BranchRecord> records, Func<ulong, uint?> toRva)
    {
        int count = 0;
        bool touches = false;
        for (int offset = HeaderSize; offset + EntrySize <= data.Length && count < records.Length; offset += EntrySize)
        {
            ulong from = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
            ulong to = BinaryPrimitives.ReadUInt64LittleEndian(data[(offset + 8)..]);
            if (from >= KernelSpace || to >= KernelSpace || from == 0)
            {
                break;
            }

            var record = new BranchRecord(toRva(from), toRva(to));
            touches |= record.From is not null || record.To is not null;
            records[count++] = record;
        }

        return touches ? count : 0;
    }

    private static uint? Rva(Dictionary<int, ProcessState> processes, int pid, ulong address, uint size) =>
        processes.TryGetValue(pid, out var process) && process.TargetBase is { } b && address >= b && address - b < size
            ? (uint)(address - b)
            : null;
}
