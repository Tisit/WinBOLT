using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Profile;

/// <summary>How much of a profile <see cref="StaleProfile.Transfer"/> carried over.</summary>
/// <param name="FunctionsMatched">Profiled source functions with a counterpart in the target.</param>
/// <param name="FunctionsProfiled">Source functions with executed blocks.</param>
/// <param name="WeightTransferred">Share of the source's executed instructions whose block found a counterpart.</param>
/// <param name="EdgesTransferred">Share of the source's edge executions that found the corresponding target edge.</param>
public sealed record StaleTransfer(int FunctionsMatched, int FunctionsProfiled, double WeightTransferred, double EdgesTransferred);

/// <summary>
/// Moves a profile from the binary it was recorded on (<c>source</c>, analyzed, profile applied)
/// to another build of the same program (<c>target</c>, analyzed): a stale profile (DesignDoc
/// "Step 28"; BOLT's stale profile matching does the same for ELF). A rebuild changes addresses
/// everywhere, so the trace cannot bind to the new image; most functions and blocks are unchanged
/// in content, though, and their counts still describe the new code.
/// <list type="number">
/// <item>Functions: same PDB name (unique on both sides); without names, the same content hash
/// (unique on both sides).</item>
/// <item>Blocks of a matched pair: entry to entry; then blocks whose strict hash (opcode forms,
/// registers, immediates and displacements that are not addresses) occurs equally often on both
/// sides, paired in address order; then the same with a loose hash (mnemonics only).</item>
/// <item>Edge counts go to the target edge between the matched blocks (dropped if the target CFG
/// has none); block counts are recomputed from them as <see cref="LbrProfileBuilder.Finish"/> does,
/// at least the source block's count. Call counts follow the call's position among its block's
/// calls; indirect call targets map through the function match.</item>
/// </list>
/// Anything without a counterpart is dropped, never guessed.
/// </summary>
public static class StaleProfile
{
    public static StaleTransfer Transfer(BinaryImage source, BinaryImage target)
    {
        var summary = source.ProfileSummary ?? throw new InvalidOperationException("the source image has no profile");

        // 1. Functions.
        var targetByName = target.Functions.Where(f => f.Name is not null).GroupBy(f => f.Name!).Where(g => g.Count() == 1)
            .ToDictionary(g => g.Key, g => g.First());
        var sourceNames = source.Functions.Where(f => f.Name is not null).GroupBy(f => f.Name!).ToDictionary(g => g.Key, g => g.Count());
        Dictionary<ulong, Function>? targetByHash = null;
        Dictionary<ulong, int>? sourceHashes = null;
        var functionMap = new Dictionary<int, Function>();
        var claimed = new HashSet<int>();
        foreach (var f in source.Functions)
        {
            Function? counterpart = null;
            if (f.Name is { } name && sourceNames[name] == 1 && targetByName.TryGetValue(name, out var named))
            {
                counterpart = named;
            }
            else if (f.Name is null || !targetByName.ContainsKey(f.Name))
            {
                targetByHash ??= target.Functions.GroupBy(g => FunctionHash(target, g)).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First());
                sourceHashes ??= source.Functions.GroupBy(g => FunctionHash(source, g)).ToDictionary(g => g.Key, g => g.Count());
                ulong hash = FunctionHash(source, f);
                if (sourceHashes[hash] == 1 && targetByHash.TryGetValue(hash, out var same))
                {
                    counterpart = same;
                }
            }

            if (counterpart is not null && claimed.Add(counterpart.Id))
            {
                functionMap[f.Id] = counterpart;
            }
        }

        // 2-3. Blocks, edges, block counts.
        double weight = 0, carried = 0, edgeTotal = 0, edgeCarried = 0;
        int profiled = 0, matched = 0;
        var blockMap = new Dictionary<BasicBlock, BasicBlock>();
        foreach (var f in source.Functions)
        {
            bool executed = f.BasicBlocks.Any(b => b.ExecutionCount > 0);
            double functionWeight = f.BasicBlocks.Sum(b => (double)(b.ExecutionCount ?? 0) * b.InstructionCount);
            weight += functionWeight;
            edgeTotal += f.BasicBlocks.SelectMany(b => b.Successors).Sum(e => (double)(e.ExecutionCount ?? 0));
            if (!executed)
            {
                continue;
            }

            profiled++;
            if (!functionMap.TryGetValue(f.Id, out var g))
            {
                continue;
            }

            matched++;
            var blocks = MatchBlocks(source, f, target, g);
            foreach (var (s, t) in blocks)
            {
                blockMap[s] = t;
                carried += (double)(s.ExecutionCount ?? 0) * s.InstructionCount;
            }

            foreach (var (s, t) in blocks)
            {
                foreach (var edge in s.Successors.Where(e => e.ExecutionCount > 0))
                {
                    if (blocks.TryGetValue(edge.Target, out var to) &&
                        (t.Successors.FirstOrDefault(e => e.Target == to && e.Kind == edge.Kind) ?? t.Successors.FirstOrDefault(e => e.Target == to)) is { } counterpart)
                    {
                        counterpart.ExecutionCount = (counterpart.ExecutionCount ?? 0) + edge.ExecutionCount;
                        edgeCarried += edge.ExecutionCount!.Value;
                    }
                }
            }

            foreach (var block in g.BasicBlocks)
            {
                ulong incoming = block.Predecessors.Aggregate(0UL, (sum, e) => sum + (e.ExecutionCount ?? 0));
                ulong outgoing = block.Successors.Aggregate(0UL, (sum, e) => sum + (e.ExecutionCount ?? 0));
                ulong count = Math.Max(incoming, outgoing);
                block.ExecutionCount = count > 0 ? count : null;
            }

            foreach (var (s, t) in blocks.Where(p => p.Key.ExecutionCount > 0))
            {
                t.ExecutionCount = Math.Max(t.ExecutionCount ?? 0, s.ExecutionCount!.Value);
            }

            g.Profile = new ProfileInfo { SampleCount = f.Profile?.SampleCount ?? 0, HasEdgeCounts = f.Profile?.HasEdgeCounts ?? false };
        }

        // Calls: by position among the calls of the matched block.
        var sourceIndex = new BlockIndex(source);
        var siteMap = new Dictionary<uint, uint>();
        uint? MapSite(uint site)
        {
            if (siteMap.TryGetValue(site, out uint known))
            {
                return known;
            }

            if (sourceIndex.Find(site) is not { Function: var owner, Block: var s })
            {
                return null;
            }

            // A call can be counted in a function no block count reached (a call record alone).
            if (!blockMap.ContainsKey(s) && functionMap.TryGetValue(owner.Id, out var counterpart))
            {
                foreach (var (from, to) in MatchBlocks(source, owner, target, counterpart))
                {
                    blockMap.TryAdd(from, to);
                }
            }

            if (!blockMap.TryGetValue(s, out var t))
            {
                return null;
            }

            var sourceCalls = Calls(source, s);
            var targetCalls = Calls(target, t);
            int index = sourceCalls.IndexOf(site);
            if (index < 0 || sourceCalls.Count != targetCalls.Count)
            {
                return null;
            }

            return siteMap[site] = targetCalls[index];
        }

        var entryMap = functionMap.ToDictionary(kv => source.Functions[kv.Key].EntryRva, kv => kv.Value.EntryRva);
        var transferred = new ProfileSummary
        {
            Fidelity = summary.Fidelity,
            Samples = summary.Samples,
            Records = summary.Records,
            TakenBranches = summary.TakenBranches,
            Calls = summary.Calls,
            Returns = summary.Returns,
            TailCalls = summary.TailCalls,
            FallThroughRuns = summary.FallThroughRuns,
            FallThroughEdges = summary.FallThroughEdges,
            UnexplainedRuns = summary.UnexplainedRuns,
            IpSamples = summary.IpSamples,
        };
        foreach (var (site, count) in summary.CallCounts)
        {
            if (MapSite(site) is { } at)
            {
                transferred.CallCounts[at] = transferred.CallCounts.GetValueOrDefault(at) + count;
            }
        }

        foreach (var (site, targets) in summary.IndirectTargets)
        {
            if (MapSite(site) is not { } at)
            {
                continue;
            }

            var mapped = transferred.IndirectTargets.TryGetValue(at, out var existing) ? existing : transferred.IndirectTargets[at] = [];
            foreach (var (callee, count) in targets)
            {
                uint? to = callee == ProfileSummary.OutsideImage ? callee : entryMap.TryGetValue(callee, out uint e) ? e : null;
                if (to is { } t)
                {
                    mapped[t] = mapped.GetValueOrDefault(t) + count;
                }
            }
        }

        foreach (var (reason, count) in summary.Unmatched)
        {
            transferred.Unmatched[reason] = count;
        }

        var result = new StaleTransfer(matched, profiled, weight == 0 ? 0 : carried / weight, edgeTotal == 0 ? 0 : edgeCarried / edgeTotal);
        transferred.Binding = $"stale profile from {Path.GetFileName(source.FilePath)} ({summary.Binding}): " +
                              $"{result.FunctionsMatched:N0} of {result.FunctionsProfiled:N0} executed functions matched, " +
                              $"{result.WeightTransferred:P1} of executed instructions and {result.EdgesTransferred:P1} of edge executions carried over";
        target.ProfileSummary = transferred;
        return result;
    }

    /// <summary>Source block → target block for one matched function pair.</summary>
    private static Dictionary<BasicBlock, BasicBlock> MatchBlocks(BinaryImage source, Function f, BinaryImage target, Function g)
    {
        var map = new Dictionary<BasicBlock, BasicBlock>();
        var taken = new HashSet<BasicBlock>();
        var sourceBlocks = f.BasicBlocks.OrderBy(b => b.StartRva).ToList();
        var targetBlocks = g.BasicBlocks.OrderBy(b => b.StartRva).ToList();
        if (sourceBlocks.FirstOrDefault(b => b.StartRva == f.EntryRva) is { } entry && targetBlocks.FirstOrDefault(b => b.StartRva == g.EntryRva) is { } targetEntry)
        {
            map[entry] = targetEntry;
            taken.Add(targetEntry);
        }

        foreach (bool strict in new[] { true, false })
        {
            var left = sourceBlocks.Where(b => !map.ContainsKey(b)).GroupBy(b => BlockHash(source, b, strict)).ToDictionary(x => x.Key, x => x.ToList());
            var right = targetBlocks.Where(b => !taken.Contains(b)).GroupBy(b => BlockHash(target, b, strict)).ToDictionary(x => x.Key, x => x.ToList());
            foreach (var (hash, blocks) in left)
            {
                if (right.TryGetValue(hash, out var candidates) && candidates.Count == blocks.Count)
                {
                    for (int i = 0; i < blocks.Count; i++)
                    {
                        map[blocks[i]] = candidates[i];
                        taken.Add(candidates[i]);
                    }
                }
            }
        }

        return map;
    }

    /// <summary>
    /// A block's content without its addresses. Strict: each instruction's opcode form, registers,
    /// and its immediates and memory displacements unless they are addresses (branch targets,
    /// RIP-relative operands, or values the size of an image address). Loose: mnemonics only.
    /// </summary>
    private static ulong BlockHash(BinaryImage image, BasicBlock block, bool strict)
    {
        var hash = new HashCode();
        foreach (var instruction in image.Instructions.Slice(block.InstructionStart, block.InstructionCount))
        {
            if (!strict)
            {
                hash.Add(instruction.Mnemonic);
                continue;
            }

            hash.Add(instruction.Code);
            for (int i = 0; i < instruction.OpCount; i++)
            {
                switch (instruction.GetOpKind(i))
                {
                    case OpKind.Register:
                        hash.Add(instruction.GetOpRegister(i));
                        break;
                    case OpKind.Memory when !instruction.IsIPRelativeMemoryOperand:
                        hash.Add(instruction.MemoryBase);
                        hash.Add(instruction.MemoryIndex);
                        hash.Add(instruction.MemoryIndexScale);
                        if (instruction.MemoryDisplacement64 < 0x10000 || instruction.MemoryDisplacement64 > ulong.MaxValue - 0x10000)
                        {
                            hash.Add(instruction.MemoryDisplacement64);
                        }

                        break;
                    case OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64 or
                        OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
                        ulong value = instruction.GetImmediate(i);
                        if (value < 0x10000 || value > ulong.MaxValue - 0x10000)
                        {
                            hash.Add(value);
                        }

                        break;
                }
            }
        }

        return (ulong)(uint)hash.ToHashCode() | ((ulong)block.InstructionCount << 32);
    }

    /// <summary>A function's content: its blocks' loose hashes in address order.</summary>
    private static ulong FunctionHash(BinaryImage image, Function f)
    {
        var hash = new HashCode();
        foreach (var block in f.BasicBlocks.OrderBy(b => b.StartRva))
        {
            hash.Add(BlockHash(image, block, strict: true));
        }

        return (ulong)(uint)hash.ToHashCode() | ((ulong)f.BasicBlocks.Count << 32);
    }

    private static List<uint> Calls(BinaryImage image, BasicBlock block)
    {
        var calls = new List<uint>();
        foreach (var instruction in image.Instructions.Slice(block.InstructionStart, block.InstructionCount))
        {
            if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
            {
                calls.Add((uint)instruction.IP);
            }
        }

        return calls;
    }
}
