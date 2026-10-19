namespace WinBolt.Core.Measurement;

/// <summary>Distribution of one binary's run times (seconds).</summary>
public sealed record TimingSummary(int Runs, double Median, double Mean, double StdDev, double Min, double Max);

/// <summary>
/// Paired comparison of a candidate against the baseline: per-round time ratios
/// (candidate / baseline from the same round), their median, and a bootstrap 95% confidence
/// interval of that median. A ratio below 1 is faster.
/// </summary>
public sealed record Comparison(double MedianRatio, double Low, double High)
{
    public bool ExcludesOne => High < 1 || Low > 1;
}

public enum Verdict
{
    /// <summary>The interval includes no change, or the change does not clear the noise floor.</summary>
    NoChange,
    Faster,
    Slower,
}

/// <summary>
/// DesignDoc Stage 5 measurement rules: alternating runs, distributions and confidence
/// intervals rather than single numbers, and a noise floor from the baseline measured against
/// a byte-identical copy of itself. A change is claimed only if its interval excludes 1 and
/// lies entirely beyond the noise floor's interval.
/// </summary>
public static class BenchmarkStatistics
{
    public const int BootstrapResamples = 2000;

    public static TimingSummary Summarize(IReadOnlyList<double> times)
    {
        var sorted = times.Order().ToArray();
        double mean = sorted.Average();
        double variance = sorted.Length > 1 ? sorted.Sum(t => (t - mean) * (t - mean)) / (sorted.Length - 1) : 0;
        return new TimingSummary(sorted.Length, Median(sorted), mean, Math.Sqrt(variance), sorted[0], sorted[^1]);
    }

    /// <param name="baseline">Baseline time per round.</param>
    /// <param name="candidate">Candidate time per round, same rounds.</param>
    /// <param name="seed">Bootstrap seed, fixed so a report is reproducible from its data.</param>
    public static Comparison Compare(IReadOnlyList<double> baseline, IReadOnlyList<double> candidate, int seed = 1)
    {
        if (baseline.Count != candidate.Count || baseline.Count == 0)
        {
            throw new ArgumentException("paired comparison needs the same, non-zero number of rounds");
        }

        var ratios = baseline.Zip(candidate, (b, c) => c / b).ToArray();
        var random = new Random(seed);
        var medians = new double[BootstrapResamples];
        var sample = new double[ratios.Length];
        for (int r = 0; r < BootstrapResamples; r++)
        {
            for (int i = 0; i < sample.Length; i++)
            {
                sample[i] = ratios[random.Next(ratios.Length)];
            }

            Array.Sort(sample);
            medians[r] = Median(sample);
        }

        Array.Sort(medians);
        return new Comparison(Median(ratios.Order().ToArray()), medians[(int)(0.025 * BootstrapResamples)], medians[(int)(0.975 * BootstrapResamples) - 1]);
    }

    /// <summary>
    /// A candidate is faster (slower) only when its whole interval lies below (above) 1 and
    /// below (above) the noise floor's interval: the baseline against its copy.
    /// </summary>
    public static Verdict Judge(Comparison candidate, Comparison noiseFloor)
    {
        if (candidate.High < 1 && candidate.High < noiseFloor.Low)
        {
            return Verdict.Faster;
        }

        if (candidate.Low > 1 && candidate.Low > noiseFloor.High)
        {
            return Verdict.Slower;
        }

        return Verdict.NoChange;
    }

    private static double Median(double[] sorted) =>
        sorted.Length % 2 == 1 ? sorted[sorted.Length / 2] : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2;
}
