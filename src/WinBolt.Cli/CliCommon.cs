using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;
using WinBolt.Profile;

/// <summary>What the <c>analyze</c> and <c>rewrite</c> commands share: running the analysis passes and applying a profile.</summary>
internal static class CliCommon
{
    /// <summary>Runs every registered analysis pass over <paramref name="image"/>.</summary>
    public static PassContext Analyze(BinaryImage image)
    {
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return context;
    }

    /// <summary>
    /// Applies the profile in <paramref name="etlPath"/> to the analyzed image. False, with the reason
    /// written to stderr, when the trace does not match the image or names no such function
    /// (DesignDoc Stage 2 mismatch policy: no match means reject, never proceed).
    /// </summary>
    public static bool TryApplyProfile(BinaryImage image, string etlPath, string? processName, string? profileDuring, bool ipOnly, IpEstimator estimator)
    {
        try
        {
            EtwLbrProfile.Apply(image, etlPath, processName, profileDuring, ipOnly, estimator);
            return true;
        }
        catch (ProfileBindingException ex)
        {
            Console.Error.WriteLine($"Profile rejected: {ex.Message}");
        }
        catch (ProfileWindowException ex)
        {
            Console.Error.WriteLine($"--profile-during: {ex.Message}");
        }

        return false;
    }
}
