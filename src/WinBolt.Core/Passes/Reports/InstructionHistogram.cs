using System.Text;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Reports;

/// <summary>
/// CPU feature tiers, from the x86-64 baseline up. Every x64 CPU has SSE2, so anything above
/// <see cref="Sse2Baseline"/> needs either runtime CPU dispatch or a build that targets a newer
/// CPU. That is what Stage 3's dispatch findings and Stage 7's specialization care about.
/// </summary>
public enum FeatureTier
{
    Base,
    X87,
    Sse2Baseline,
    BitManipulation,
    Sse3To42,
    Crypto,
    Avx,
    Fma,
    Avx2,
    Avx512,
}

/// <summary>Static instruction statistics over code reached by CFG construction (Stage 1 report output).</summary>
public sealed record InstructionHistogram(
    long Instructions,
    long Bytes,
    IReadOnlyList<(Mnemonic Mnemonic, long Count)> Mnemonics,
    IReadOnlyDictionary<FlowControl, long> ControlFlow,
    IReadOnlyDictionary<FeatureTier, long> TierInstructions,
    IReadOnlyDictionary<FeatureTier, int> TierFunctions)
{
    /// <summary>Counts every instruction in every function's basic blocks.</summary>
    public static InstructionHistogram Compute(BinaryImage image)
    {
        var mnemonics = new Dictionary<Mnemonic, long>();
        var flow = new Dictionary<FlowControl, long>();
        var tierInstructions = new Dictionary<FeatureTier, long>();
        var tierFunctions = new Dictionary<FeatureTier, int>();
        long instructions = 0, bytes = 0;

        foreach (var function in image.Functions)
        {
            var tiersHere = new HashSet<FeatureTier>();
            foreach (var block in function.BasicBlocks)
            {
                foreach (ref readonly var instruction in image.Instructions.Slice(block.InstructionStart, block.InstructionCount))
                {
                    instructions++;
                    bytes += instruction.Length;
                    mnemonics[instruction.Mnemonic] = mnemonics.GetValueOrDefault(instruction.Mnemonic) + 1;
                    flow[instruction.FlowControl] = flow.GetValueOrDefault(instruction.FlowControl) + 1;

                    var tier = TierOf(instruction);
                    tierInstructions[tier] = tierInstructions.GetValueOrDefault(tier) + 1;
                    tiersHere.Add(tier);
                }
            }

            foreach (var tier in tiersHere)
            {
                tierFunctions[tier] = tierFunctions.GetValueOrDefault(tier) + 1;
            }
        }

        return new InstructionHistogram(
            instructions,
            bytes,
            mnemonics.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value)).ToList(),
            flow,
            tierInstructions,
            tierFunctions);
    }

    /// <summary>The highest tier among the instruction's CPUID features.</summary>
    public static FeatureTier TierOf(in Instruction instruction)
    {
        var tier = FeatureTier.Base;
        foreach (var feature in instruction.CpuidFeatures)
        {
            var candidate = TierOf(feature);
            if (candidate > tier)
            {
                tier = candidate;
            }
        }

        return tier;
    }

    private static FeatureTier TierOf(CpuidFeature feature)
    {
        string name = feature.ToString();
        return name switch
        {
            _ when name.StartsWith("AVX512", StringComparison.Ordinal) || name.StartsWith("AVX10", StringComparison.Ordinal) => FeatureTier.Avx512,
            "AVX2" or "AVX_VNNI" or "AVX_IFMA" or "AVX_NE_CONVERT" or "AVX_VNNI_INT8" or "AVX_VNNI_INT16" => FeatureTier.Avx2,
            "FMA" or "FMA4" => FeatureTier.Fma,
            "AVX" or "F16C" => FeatureTier.Avx,
            "AES" or "PCLMULQDQ" or "VAES" or "VPCLMULQDQ" or "SHA" or "GFNI" or "SHA512" or "SM3" or "SM4" => FeatureTier.Crypto,
            "SSE3" or "SSSE3" or "SSE4_1" or "SSE4_2" or "SSE4A" => FeatureTier.Sse3To42,
            "BMI1" or "BMI2" or "LZCNT" or "POPCNT" or "ADX" or "MOVBE" or "TBM" => FeatureTier.BitManipulation,
            "SSE" or "SSE2" => FeatureTier.Sse2Baseline,
            _ when name.StartsWith("FPU", StringComparison.Ordinal) => FeatureTier.X87,
            _ => FeatureTier.Base,
        };
    }
}

/// <summary>Renders <see cref="InstructionHistogram"/> as the Stage 1 "Instruction Mix" report (§12).</summary>
[RegisterPass]
public sealed class InstructionHistogramReport : IReportProvider
{
    private const int TopMnemonics = 15;

    public string Name => "InstructionMix";

    public Report Generate(BinaryImage image, PassContext context)
    {
        var histogram = InstructionHistogram.Compute(image);
        var body = new StringBuilder();
        body.AppendLine($"{histogram.Instructions:N0} reachable instructions, {histogram.Bytes:N0} bytes " +
                        $"(average {(histogram.Instructions == 0 ? 0 : (double)histogram.Bytes / histogram.Instructions):F2} bytes)");

        body.AppendLine();
        body.AppendLine("Top mnemonics:");
        foreach (var (mnemonic, count) in histogram.Mnemonics.Take(TopMnemonics))
        {
            body.AppendLine($"  {mnemonic.ToString().ToLowerInvariant(),-12} {count,12:N0}  {Percent(count, histogram.Instructions),6}");
        }

        body.AppendLine();
        body.AppendLine("Control flow:");
        foreach (var (kind, count) in histogram.ControlFlow.Where(kv => kv.Key != FlowControl.Next).OrderByDescending(kv => kv.Value))
        {
            body.AppendLine($"  {kind,-20} {count,12:N0}");
        }

        body.AppendLine();
        body.AppendLine("CPU feature tier (highest feature each instruction needs; x86-64 guarantees up to SSE2):");
        foreach (var tier in Enum.GetValues<FeatureTier>())
        {
            if (histogram.TierInstructions.GetValueOrDefault(tier) is var count && count > 0)
            {
                string note = tier > FeatureTier.Sse2Baseline ? "  needs dispatch or a raised target" : string.Empty;
                body.AppendLine($"  {tier,-16} {count,12:N0} instructions in {histogram.TierFunctions.GetValueOrDefault(tier),7:N0} functions{note}");
            }
        }

        return new Report { Title = "Instruction Mix", Body = body.ToString(), Confidence = ReportConfidence.High };
    }

    private static string Percent(long part, long whole) => whole == 0 ? "-" : $"{100.0 * part / whole:F1}%";
}
