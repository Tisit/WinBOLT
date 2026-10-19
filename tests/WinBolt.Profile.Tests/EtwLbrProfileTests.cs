using System.Buffers.Binary;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;
using WinBolt.Pe;

namespace WinBolt.Profile.Tests;

public class LbrDecodeTests
{
    private const ulong Base = 0x7FF6_0000_0000;

    /// <summary>An LBR event payload: 24-byte header, then (from, to, info) entries, newest first.</summary>
    private static byte[] Event(params (ulong From, ulong To)[] entries)
    {
        var data = new byte[EtwLbrProfile.HeaderSize + entries.Length * EtwLbrProfile.EntrySize];
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(8), 1234);
        for (int i = 0; i < entries.Length; i++)
        {
            int offset = EtwLbrProfile.HeaderSize + i * EtwLbrProfile.EntrySize;
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset), entries[i].From);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 8), entries[i].To);
        }

        return data;
    }

    private static uint? InImage(ulong address) => address >= Base && address < Base + 0x10000 ? (uint)(address - Base) : null;

    [Fact]
    public void Entries_become_rvas_newest_first_with_outside_ends_null()
    {
        var records = new BranchRecord[32];
        int count = EtwLbrProfile.Decode(Event((Base + 0x1010, 0x7FF9_0000_1000), (Base + 0x1002, Base + 0x100B)), records, InImage);

        Assert.Equal(2, count);
        Assert.Equal(new BranchRecord(0x1010, null), records[0]);
        Assert.Equal(new BranchRecord(0x1002, 0x100B), records[1]);
    }

    [Fact]
    public void Decoding_stops_at_the_first_kernel_entry()
    {
        // Entries older than a kernel entry may belong to another thread: the LBR survives context switches.
        var records = new BranchRecord[32];
        int count = EtwLbrProfile.Decode(
            Event((Base + 0x1010, Base + 0x1020), (0xFFFFF807_0000_1000, Base + 0x1000), (Base + 0x1002, Base + 0x100B)),
            records, InImage);

        Assert.Equal(1, count);
    }

    [Fact]
    public void Sample_that_never_touches_the_image_is_skipped()
    {
        var records = new BranchRecord[32];

        Assert.Equal(0, EtwLbrProfile.Decode(Event((0x7FF9_0000_1000, 0x7FF9_0000_2000)), records, InImage));
    }
}

/// <summary>
/// Against the trace tools/profile/Capture-Lbr.ps1 writes to artifacts/lbr.etl, when present.
/// That trace is machine-specific and never committed; these tests return early without it.
/// </summary>
public class TraceTests
{
    private static string? Trace()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "lbr.etl");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static BinaryImage Analyze(string file)
    {
        var image = PeImageReader.Read(Path.Combine(@"C:\Windows\System32", file));
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return image;
    }

    [SkippableFact]
    public void Findstr_profile_matches_the_cfg()
    {
        if (Trace() is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var image = Analyze("findstr.exe");
        ProfileSummary summary;
        try
        {
            summary = EtwLbrProfile.Apply(image, trace);
        }
        catch (ProfileBindingException)
        {
throw new SkipException("a trace captured with a different workload");
        }

        Assert.Equal(ProfileFidelity.EdgeAccurate, summary.Fidelity);
        Assert.True(summary.MatchedRecords >= summary.Records * 0.999, $"{summary.MatchedRecords} of {summary.Records} matched");
        Assert.True(summary.FallThroughRuns >= (summary.FallThroughRuns + summary.UnexplainedRuns) * 0.99);
        Assert.Contains(image.Functions, f => f.BasicBlocks.Any(b => b.Successors.Any(e => e is { Kind: EdgeKind.FallThrough, ExecutionCount: > 0 })));
    }

    [SkippableFact]
    public void Profile_window_keeps_only_samples_while_the_marker_runs()
    {
        if (Trace() is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var image = Analyze("findstr.exe");
        ProfileSummary whole;
        try
        {
            whole = EtwLbrProfile.Apply(image, trace);
        }
        catch (ProfileBindingException)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        // The hottest function marks a phase inside the run (no PDB here: it is named for the test).
        uint marker = image.Functions.MaxBy(f => f.BasicBlocks.Sum(b => (long)(b.ExecutionCount ?? 0)))!.EntryRva;
        var fresh = Analyze("findstr.exe");
        fresh.Functions.Single(f => f.EntryRva == marker).Name = "marker";
        var windowed = EtwLbrProfile.Apply(fresh, trace, during: "marker");

        Assert.Contains("window: while marker", windowed.Binding);
        Assert.InRange(windowed.Records, 1L, whole.Records);
        Assert.Throws<ProfileWindowException>(() => EtwLbrProfile.Apply(Analyze("findstr.exe"), trace, during: "no such function"));
    }

    [SkippableFact]
    public void Image_not_in_the_trace_is_rejected()
    {
        if (Trace() is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        // notepad.exe does not run in the capture's workload.
        var image = Analyze("notepad.exe");

        Assert.Throws<ProfileBindingException>(() => EtwLbrProfile.Apply(image, trace, "findstr.exe"));
        Assert.Null(image.ProfileSummary);
    }
}
