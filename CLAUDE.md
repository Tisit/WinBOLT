# WinBolt — Project Notes for Claude Code

## Version control: fossil, NOT git

This repository uses **Fossil**, not git. There is no `.git` directory and none should be
created.

* Fossil executable: `D:\aplikacje\fossil.exe` (not on PATH — invoke by full path, or add
  it to PATH for the session).
* Repository file: `D:\projekty\WinBOLT\WinBolt.fossil` (the actual repo database).
* Checkout root: `D:\projekty\WinBOLT` (already opened via `fossil open ... -k`).

Do not run `git` commands in this repository — there is no git repo here, and running
`git init` would create a second, unwanted VCS alongside fossil.

### Fossil command equivalents

| git                          | fossil                                          |
| ----------------------------- | ------------------------------------------------ |
| `git status`                  | `fossil changes` / `fossil status`                |
| `git diff`                    | `fossil diff`                                     |
| `git add <file>`              | `fossil add <file>` (new files only; tracked files are auto-included) |
| `git commit -m "..."`         | `fossil commit -m "..."`                          |
| `git log`                     | `fossil timeline`                                 |
| `git branch`                  | `fossil branch list`                              |
| `git checkout -b <name>`      | `fossil branch new <name>`; `fossil update <name>`|
| `git checkout <rev>`          | `fossil update <rev>`                             |
| `.gitignore`                  | `fossil settings ignore-glob "<patterns>"` (already set to `bin/*,obj/*,*.user,.vs/*,artifacts/*,*/bin/*,*/obj/*`) |

Only commit with `fossil commit` when the user explicitly asks — same rule as git commits
in the base instructions.

## Project

WinBolt is a post-link optimizer for Windows x64 PE executables (BOLT-inspired), written
in C#/.NET. Full design is in [DesignDoc.md](DesignDoc.md) — read it before making
architectural changes; it is authoritative over anything summarized here.

Key decisions from the design doc worth remembering while coding:

* Custom PE32+ reader — `System.Reflection.PortableExecutable.PEReader` is explicitly
  rejected as the production path (§3.3); it may only be used in tests for cross-checking.
* `iced` is the x64 decode/encode dependency; avoid adding LLVM or other heavy deps (§3.3).
* IR instruction storage must be flat arrays indexed by int ID, not one object per
  instruction (§5.3) — a 100MB image can have 10⁷–10⁸ instructions.
* `Function` owns a *list* of `FunctionRange`, never a single start/end (§5.1).
* Output strategy is append-a-new-section, not in-place rewriting (§6.1) — this is a
  settled decision with recorded rationale, not open for casual revisiting. The one exception
  is whole-program rewriting gated on complete linker fixup records (§6.2, agreed with the
  user; milestones W1-W4). W1 is done: `WholeProgramGate` (Rewrite), printed by `analyze`;
  section contributions from the PDB (`BinaryImage.SectionContributions`); every target build passes,
  Factorio is refused (no fixups). W2 is done: `WholeProgramRewriter` / `WholeProgramVerifier`,
  `rewrite --whole-program [--profile ..] [--jcc-erratum]` moves contributions in place, re-resolves
  every fixup (value moves with owner(fixup.Target)), re-sorts .pdata/CFG tables, rebuilds .reloc,
  changes the RSDS GUID, spills the cold tail into `.wbcold` when padding does not fit. Reversed and
  shuffled orders of 10 builds run identically. C3+JCC: zopfli -1.49%, speedtest1 -2.33% (append
  mode, same order: -0.97%, -1.67%). W3 is done: `--whole-program --profile .. --blocks
  [--jcc-erratum] [--align-loops]` re-encodes hot functions (`RebuiltFunction`), cold parts after all
  hot code, regenerated .pdata + tables + cold UNWIND_INFO in `.wbdata`. iced links targets to same-call
  instruction IPs: new addresses colliding with the function's old IPs are encoded via a stand-in and
  patched (`EncodeAt`). Best: speedtest1 -5.47% (append -4.36%), zopfli -8.40% (-8.24%), zopflipng
  -18.98% (-18.94%), outputs 7-11% larger than the original (append 64-88%). Two-level switch byte
  tables in the contribution are copied to .wbdata (`CopiedTable.NewIndexRva`): speedtest1 97.9% rebuilt.
  W4 is done: `--whole-program` writes `<output>.pdb` (`WholeProgramOmap`, `PdbWriter.WithOmap`,
  `MsfWriter` in WinBolt.Pdb) with OMAP_TO/FROM_SRC and SectionHdrOrig, the image's RSDS names it.
  MSF stream 0 (old directory) must be written empty or dbghelp rejects the PDB. Checked by our loader,
  dbghelp tests (`WholeProgramPdbTests`) and cdb by hand (breakpoints, stack traces, inline frames).
  Table-only chained unwind entries (MSVC's entry for switch tables after the last instruction, no
  codes; SQLite builds only) are dropped from rebuilt functions (`BlockRebuilder.IsTableEntry`, both
  modes): speedtest1 99.8% of execution rebuilt in whole-program mode. Its measured speed moved -1.4
  points, traced to layout sensitivity (shifting all later hot code), not the function: profile
  verified by raw LBR and IP samples; placed last, split/unsplit/unit are within ~0.45 points.
  Benchmark speedtest1 with `--memdb --size 25` (the traced workload; plain `--size 25` uses a file).
  Single-build A/Bs carry ~0.5-1.5 points of layout noise: `rewrite --layout-shift N` (multiple of 64,
  both modes) builds the same layout at another alignment; `winbolt bench name=a.exe,b.exe,...` runs a
  group and compares its per-round mean (and each candidate against the first). Layout-averaged,
  speedtest1 --memdb: append -4.34%, whole-program -4.66% (-0.54 vs append), table-entry rebuild ~0.26
  points worse (within resolution); 4 shifts of one build span 0.63 points.
* Safety gate (`Transformability`: FullyTransformable / RelocatableOnly / Frozen) governs
  what any optimization pass may touch (§5.5) — default on anything unrecognized is
  downgrade, not proceed.
* Passes are attribute-registered in the main assembly for Stages 1–5, not dynamically
  loaded plugins (§11).

## Solution layout

```
WinBolt.slnx        (SDK 10 generates the new XML solution format, not .sln)
src/
  WinBolt.Core/     IR types, analysis passes, safety gate, pass registration
  WinBolt.Pe/        PE32+ reader (headers, sections, data directories, .pdata, load config)
  WinBolt.Pdb/       PDB reader (MSF, DBI, publics, OMAP) and PDB locator
  WinBolt.Profile/   ETW + LBR profile reader (TraceEvent dependency lives only here)
  WinBolt.Rewrite/   Stage 4-6 writer: FunctionRewriter, BlockRebuilder, BlockLayout/ExtTsp, LayoutStatistics, RewriteVerifier (incl. fixup oracle), FunctionOrdering (C3), PeLayout/PeChecksum
  WinBolt.Cli/       `winbolt analyze foo.exe [--pdb f] [--symbols dir] [--profile etl [--process name]] [--html f]`
tools/profile/       Capture-Lbr.ps1: elevated LBR trace capture (user runs it)
tools/targets/       Build-Targets.ps1: builds the optimization targets into artifacts/targets
tools/survey/        Survey.ps1: coverage survey of third-party binaries (winbolt analyze, tabulated)
tests/
  WinBolt.Core.Tests/  synthetic-image pass tests (SyntheticImage)
  WinBolt.Pe.Tests/    real System32 binaries
  WinBolt.Pdb.Tests/   OMAP unit tests; real PDBs from bft's symbol cache when present
  WinBolt.Profile.Tests/ LBR decode unit tests; artifacts/lbr.etl when present
  WinBolt.Rewrite.Tests/ no-op rewrite of artifacts/targets zopfli/speedtest1 (verify, tamper, runtime output); forced and profiled block layouts (BlockLayoutTests);
                       C3 unit tests; C3 layout of speedtest1 when artifacts/lbr-speedtest1.etl exists
```

Roadmap stages are tracked in DesignDoc.md §8. Current work targets **Stage 1** (binary
analysis, no rewriting) per §2.1's release mapping.

## Current status

Implemented and tested (real end-to-end run against `C:\Windows\System32\notepad.exe`):

* `WinBolt.Core`: IR types (§5), `Transformability`/`SafetyStatus` (§5.5), flat
  `InstructionStore` (§5.3), `IArchitecture`/x64 iced-backed decoder (§3.2), pass
  interfaces and attribute-based `PassRegistry` (§7, §11).
* `WinBolt.Pe`: hand-written PE32+ reader — DOS/NT/section headers, data directories,
  `.reloc` (base relocations), `.pdata` including `UNW_FLAG_CHAININFO` parent-chain
  resolution (§5.1), load config directory / CFGuard tables including
  `GuardCFFunctionTable`, `GuardAddressTakenIatEntryTable`, `GuardLongJumpTargetTable`,
  `GuardEHContinuationTable`, with each optional field gated on the directory's own `Size`
  for clean degradation across SDK versions. Chains in the indirect form (UnwindData low
  bit set, used by BBT) are followed too. Debug directory and POGO entry are parsed.
* Layout provenance (DesignDoc Stage 1): `LayoutProvenanceClassifier` classifies an image as
  compiler PGO / post-link rewrite / LTCG / etc. from PE evidence only, ported from the
  sibling project `D:\projekty\AssemblyOptimizationDetection` (`bft`). PDB evidence (OMAP
  streams, SectionHdrOrig) is added when the PDB reader lands, and that reader must apply
  OMAP translation to symbol addresses (DesignDoc §3.3).
* Function discovery (`FunctionDiscoveryPass`, DesignDoc Stage 1): `.pdata` functions with
  chained fragments attached as extra ranges; leaf functions from exports, entry point, TLS
  callbacks, CFGuard table, relocation targets and direct call/jump targets, with extent from
  a bounded sweep; every remaining executable byte recorded in `UnclaimedCode` as padding,
  known data, invalid-chain fragment or unattributed. Discovery downgrades (`interior-entry`,
  `leaf-extent`, `leaf-calls`, `range-overlap`) go through `Function.Downgrade`, which never
  raises the level. The PE reader also provides section bytes, exports, TLS callbacks and
  data directories.
* CFG construction (`CfgConstructionPass`): recursive descent per function (never a linear
  sweep), basic blocks in the flat `InstructionStore`, fall-through/branch edges, and the call
  graph (`BinaryImage.CallSites`). Calls do not end blocks; int3/nop after a call at a range
  end is a noreturn call, not falling off.
* Safety gate (`SafetyGatePass`, runs last): `handler-data` and `trampoline-window` checks,
  then promotes anything still `Unanalyzed` to `FullyTransformable`. `Function.DowngradeReasons`
  keeps every reason; the CLI reports per reason how many functions it is the *only* blocker
  for. First R2 numbers are recorded in DesignDoc §16 R2.
* `ExceptionInfo` carries the language-specific handler RVA and handler data RVA.
* Exception handlers (`ExceptionHandlerPass`, runs first): identified by export name, import
  thunk (`jmp [rip+IAT]`, needs the import table, now parsed), or, for statically linked
  `__GSHandlerCheck`, its exact instruction sequence (confirmed against Microsoft PDBs for
  ntdll/kernel32). SEH scope tables are parsed; CFG construction validates them against the
  function's ranges and roots the `__except` targets. Gate: GS-only costs nothing, SEH with a
  valid table is `RelocatableOnly` (`seh-scope-table`), C++ EH is `Frozen` (`cxx-eh`),
  unidentified is `Frozen` (`handler-data`). Handler RVAs and scope-table funclets are
  discovery candidates (`DiscoverySource.ExceptionTable`).
* C++ EH (`CxxEhParser`): FH3 FuncInfo and FH4 compressed FuncInfo4 yield funclets
  (unwind actions, catch handlers, FH4 destructors), FH4 catch continuations (CFG roots) and
  IP-to-state addresses. Funclets are discovery candidates. The gate validates every address
  against discovered functions (FH3 tables are shared by a parent and its catch funclets):
  valid is `RelocatableOnly` (`cxx-eh-table`), otherwise `Frozen` (`cxx-eh`).
* Code pointers: `lea reg,[rip+X]` into code. Discovery uses targets as weak candidates;
  CFG construction pre-scans for interior targets (extra roots, which also covers FH3 catch
  continuations) and records confirmed ones in `BinaryImage.CodePointers`. Entry targets mark
  the function address-taken (`DiscoverySource.CodePointer`, trampoline check); interior
  targets make it `RelocatableOnly` (`interior-pointer`). CFGuard's table is not complete:
  nvcuvid.dll (CFG on) has 89 lea-taken functions missing from it (DesignDoc §5.4).
* Jump tables (`JumpTableRecovery`): MSVC single-level and two-level image-relative tables,
  proven by a requirement-driven backward walk over *every* CFG path (`IControlFlow`
  predecessors from the builder: fall-through, direct branches, recovered tables' dispatch
  edges; image base per register, unsigned bound incl. taken jbe/jb, index copies and
  `lea x+c`, upper-zero proof for 8/16-bit compares, call clobbers). The builder re-proves
  all tables each round until stable; a refuted table is never retried. Targets must be
  inside the function. iced's `InstructionInfoFactory` is not thread-safe (xUnit runs test
  classes in parallel): keep it `[ThreadStatic]`. Recovered tables are data barriers: the CFG builder
  buffers its results and re-explores once if a table overlaps decoded bytes (tables after
  noreturn calls inside the range). Unexplained indirect jumps are tail calls only if no
  interior address of the function can exist (no lea into it, no relocation into it, no
  `__ImageBase` load in it); otherwise `Frozen` (`indirect-branch`).
* GS wrappers (`__GSHandlerCheck_SEH/_EH/_EH4`) are identified structurally as their inner
  handler: the whole .pdata range decodes cleanly, no indirect branches, and exactly two
  external targets: the verified `__GSHandlerCheck` helper and an identified inner handler.
  All identifications were checked against PDBs (see DesignDoc R2).
* PDB (`WinBolt.Pdb`): `PdbSymbolLoader.Load` finds the PDB matching the image's RSDS
  GUID/age (next to the binary, RSDS path, `--symbols` dirs, `_NT_SYMBOL_PATH` local dirs;
  no downloads) and fills `BinaryImage.Symbols` in image RVAs, through `SectionHdrOrig` +
  `OMAP_FROM_SRC` when the image was rewritten (§3.3). Function symbols are strong discovery
  candidates (`DiscoverySource.Symbol`) and names. Verified: 100% of function symbols land on
  discovered entries in five binaries, including OMAP-translated sqlncli11.
* Profiles (Stage 2): `LbrProfileBuilder` (Core, no ETW dependency) applies branch records
  (image RVAs, newest first, same thread) to the CFG: taken branches count their edge, runs
  between consecutive records count fall-through edges; anything that does not fit is
  counted unmatched, never applied. `EtwLbrProfile` (WinBolt.Profile) reads the .etl and
  implements the reader rules and binding (DesignDoc Stage 2); no bound process means
  `ProfileBindingException` (reject). `ProfileReport` prints binding, match rates and hot
  functions. On the prototype trace: 100% of records matched, 99.3-99.7% of runs explained.
  `LbrProfileBuilder.Finish` derives `BasicBlock.ExecutionCount`; `ProfileSummary.CallCounts`
  counts call sites (`CallSite.PointerRva` names import calls via the IAT). `CodeFootprint`
  computes the hot code footprint (pages/lines now vs packed by range and by block).
  `--html` (Cli `HtmlReport`) writes a self-contained page: heat map, hot paths, all reports.
* Stage 3 advisor (`Advisor`, `AdvisorReport`, needs a profile): front-end triage as a proxy
  (90% hot footprint against L1i from CPUID and an assumed 128-entry I-TLB, `CpuModel`;
  ETW cannot supply top-down metrics, so VTune confirms positives), forward taken-biased
  branches (loops excluded), cold code in hot functions, hot tiny functions, and indirect
  call sites with a dominant target or an AVX2+ single target (CPU dispatch). Indirect call
  targets come from `ProfileSummary.IndirectTargets` (register/non-RIP calls only).
* CFG is "enabled" only when the image's DllCharacteristics has GUARD_CF (0x4000) *and* the
  load config has CF_INSTRUMENTED: MSVC images linked with /guard:cf CRT objects carry the
  flag without being CFG-enforced. `LoadConfigTables.HasCfg` means enforced; the function
  table is read whenever present.
* Reports: `IReportProvider`s are attribute-registered like passes (`PassRegistry.CreateReportProviders`)
  and printed by the CLI after the structural report. `InstructionHistogramReport`: top
  mnemonics, control-flow mix, and CPU feature tier per instruction/function (anything above
  the x64 SSE2 baseline needs dispatch or a raised target).
* To check an identification against real symbols: bft's symbol cache at
  `%LOCALAPPDATA%\BinaryFingerprint\symcache` has PDBs for many System32 binaries, and
  `llvm-pdbutil dump -publics` (VS `VC\Tools\Llvm\x64\bin`) prints `section:offset` with
  the offset in *decimal*.
* `WinBolt.Cli`: `winbolt analyze <path>` prints the structural report above.
* Stage 4 milestone 1 (DesignDoc "Milestone 1: verified no-op rewrite", results there):
  `winbolt rewrite <in> <out> [--pdb] [--symbols]` copies eligible functions into `.wbtext`,
  puts the new .pdata table, chained UNWIND_INFO copies and the new reloc table in `.wbdata`,
  writes `jmp rel32` trampolines at original entries, and writes the file only if
  `RewriteVerifier` passes (exit 3 otherwise). The fixup oracle uses PDB linker fixups
  (`PdbFile.Fixups`, `BinaryImage.LinkerFixups`; targets link with `/DEBUGTYPE:CV,FIXUP`).
  zopfli o2/guardcf: 140/148 functions moved, verified, byte-identical output, no slowdown.
  Chained .pdata fragments merged into one range each need a copied entry (parents first).
  Jump tables are rebuilt in `.wbdata` (`CopiedTable`) and the load's disp32 re-pointed
  (`JumpTable.LoadRva`/`IndexLoadRva` from recovery); table bytes inside the range are
  `DataSpan`s the linear decode (`NoOpRewriter.DecodeCode`) steps over. speedtest1: 96.7%
  of code moved incl. the interpreter, identical `--verify` hash, timing within noise.
  iced gotcha: `MemoryDisplSize` is 8 for a disp32 in 64-bit mode; use `ConstantOffsets`.
* Stage 6 step 1 (DesignDoc "Step 1: verified rebuild"): `winbolt rewrite --rebuild` /
  `RewriteMode.Rebuild` re-encodes functions from their CFG (`BlockRebuilder`, one iced
  `BlockEncoder` call per function; only branches, RIP-relative operands and table loads are
  re-encoded, other instructions keep their bytes via `Instruction.CreateDeclareByte`).
  `MovedFunction.AddressMap`/`Map` give original -> new addresses; `CheckRebuilt` and the
  oracle verify block by block. zopfli and speedtest1: ~98% rebuilt, verified, identical output.
* Stage 5 (DesignDoc "Stage 5 ... First implementation and results"): `winbolt rewrite in out
  --profile etl [--process name]` orders executed functions with `FunctionOrdering.C3` and
  moves only those (`FunctionRewriter.Rewrite(image, file, order)`), printing the hottest
  unplaced functions and the hot footprint before/after. `winbolt bench base cand... [--rounds N]
  -- args` is the harness (baseline copy = noise floor, bootstrap CIs, `BenchmarkStatistics`
  in Core; CPU cycles via QueryProcessCycleTime). speedtest1: no-op +0.7% slower (trampolines),
  C3 = original (honest zero: pages 100->51 but L1i lines unchanged; needs Stage 6).
* Stage 6 step 2 (DesignDoc "Step 2: block reordering and hot/cold splitting"): `winbolt
  rewrite in out --profile etl --blocks [--no-split]`. `BlockLayout.Order` (Pettis-Hansen
  chains) gives a `BlockOrder` (hot, entry first; cold); `BlockRebuilder.Encode` encodes any
  order: inserted jmps, inverted jcc, dropped jmp, int3 after noreturn calls; inserted
  instructions get IPs >= 0xF000_0000_0000_0000 (iced links RIP-relative operands to IP 0).
  Blocks are laid out per unwind entry (segment); blocks beginning inside a segment's
  prologue stay first in original order. Cold blocks go after all hot code, one chained
  empty UNWIND_INFO per segment (`MovedFunction.ColdEntries`). CFG: unwind entry starts are
  block leaders; `BasicBlock.IsBranchTarget` for the trampoline-window checks. Tests force
  random layouts and "calls cold" (unwindtest, with a negative control). speedtest1: 90%
  footprint 40 pages / 676 lines (was 100 / 925); **-1.6% cycles net of the noise floor,
  first win beyond noise**; PGO -6%.
* Stage 6 step 3 (DesignDoc "Step 3: ext-TSP block order, a negative result"): `ExtTsp`,
  `--block-order ext-tsp`. More fall-throughs (82.3% vs 81.9%, `LayoutStatistics`, printed by
  `rewrite --blocks`) but reproducibly slower (-1.1% vs -1.6%): greedy chains stay default.
* Stage 6 step 4 (DesignDoc "Step 4: front-end attribution and JCC erratum padding"):
  `tools/profile/Collect-TopDown.ps1` (user runs it elevated; VTune sampled at 0.1 ms,
  -allow-multiple-runs, 3 repeats; VTune's counting mode is broken here). PGO's lead is
  mostly -4.3% instructions (inlining, out of reach); layouts cut ICache misses but lost DSB
  coverage to the JCC erratum (i5-9600K). `--jcc-erratum` pads executed branches (and fused
  cmp+jcc) off 32-byte boundaries with NOPs (never before the entry, in a prologue or in cold
  code; copies 32-aligned; verifier accepts NOP padding). Prefix padding first (up to 3
  redundant CS prefixes on raw-byte, non-branch, non-VEX instructions after the previous
  branch; verifier accepts CS/DS/ES/SS), NOPs for the rest. speedtest1: **chains + prefix
  padding -4.4% cycles** (NOP padding -3.6%, chains alone -1.5%, PGO -6.1%). Opt-in:
  CPU-specific.
* Stage 6 step 5 (DesignDoc "Step 5: second target, zopfli"): trace artifacts/lbr-zopfli.etl,
  input artifacts/bench/zopfli-input.bin (first 512 KB of sqlite3.c; zopfli-text2.bin and
  zopfli-binary.bin are unseen inputs). **--blocks --jcc-erratum -8.0% cycles, PGO -3.6%**;
  unseen text -9.5% (PGO -4.7%), binary -5.7% (PGO -2.2%). C3 functions alone were +1.5%
  slower: copies moved branches onto 32-byte boundaries. `--jcc-erratum` in copy mode now
  places each copy (4-byte steps mod 32, `LayoutStatistics.ExposureAt`): zopfli -2.0%,
  speedtest1 -0.85%. Rebuilt code: padding goes to the cheapest place (dead gap after
  jmp/ret/int3, then prefixes, then least-executed NOP spot), and each rebuilt function's start
  offset (4-byte steps mod 32) is chosen by trial encoding (fewest unpaddable exposures, then
  fewest executed NOPs; `RebuiltCode.UnfixedExecutions/PaddingExecutions`). Executed NOPs:
  speedtest1 0.38%, zopfli 1.74%; **speedtest1 -4.45%, zopfli -8.31%** (same-session
  comparisons: between-session variation is ~0.8 points).
* Stage 6 step 6 (DesignDoc "Step 6: hot loop alignment"): `--align-loops` starts hot loop
  heads (back edges >= 4x entries) on 32 bytes, padding where the loop is entered
  (`BlockRebuilder` `Place`, shared with JCC padding). Same-session gain 0.25-0.5 points on
  both targets; best command: `--profile .. --blocks --jcc-erratum --align-loops`.
* Stage 6 step 7 (DesignDoc "Step 7: moving functions with C++ EH tables"): FH4 functions
  (not separated; catch funclets included) and RelocatableOnly functions whose only reasons are
  cxx-eh-table / interior-pointer move as byte copies sharing the original tables, also inside
  --rebuild/--blocks runs (`FunctionRewriter.Select` copyOnly). Verified against the CRT source
  (FH4 decodes against FunctionEntry->BeginAddress; ExecutionInCatch uses isCatch). GS wrappers
  are identified by PDB name when no plain __GSHandlerCheck is verified; re-analysis (check 4)
  uses the input's PDB symbols. Runtime test: tools/targets/cxxehtest, `CxxEhTests`.
  zopflipng no-op moves 99.0% of code (was 81%), identical PNG.
* Stage 6 step 8 (DesignDoc "Step 8: third target, zopflipng"): trace artifacts/lbr-zopflipng.etl,
  inputs artifacts/bench/zopflipng-256.png (benchmark, PGO training) and zopflipng-unseen.png.
  Hot code is all zopfli C; o2 has 20.5% of executed branches on 32-byte boundaries.
  **--blocks --jcc-erratum -18.8% cycles (unseen -19.3%), PGO -10.4%**; --align-loops is
  0.5 points worse here, so it stays opt-in and the recommended command is
  `--profile .. --blocks --jcc-erratum`.
* Stage 6 step 9 (DesignDoc "Step 9: moving SEH functions with rebased scope tables"): SEH
  functions (RelocatableOnly seh-scope-table, CSpecific handler) move as byte copies with their
  own UNWIND_INFO in .wbdata, scope entries inside the function rebased
  (`FunctionRewriter.SehUnwindCopy`, verified by `RewriteVerifier.CheckSehCopy`). unwindtest now
  finds main's frame by stack address and adds a __finally and a filter. No-op coverage (was 99.6% / 140 of 148 fns / 81%):
  speedtest1 99.8%, zopfli 99.0%, zopflipng 99.6%.
* Stage 6 step 10 (DesignDoc "Step 10: front-end attribution of the padded layouts"): VTune
  confirms the mechanism. DSB coverage o2 -> padded: speedtest1 44.5 -> 54.7%, zopfli 72.2 ->
  91.6%, zopflipng 50.1 -> 95.3%; Front-End Bound falls 4-26 points; zopfli/zopflipng run
  1.8-2.6% more instructions (NOPs) yet 8-16% fewer cycles. Results artifacts/vtune/*-s<n>,
  summary artifacts/vtune/summary-padded.csv.

* Factorio (`D:\SteamLibrary\SteamApps\common\Factorio\bin\x64\factorio.exe`, 43 MB, LTCG, static CRT, matching
  PDB; never write into the Steam folder, outputs in artifacts/factorio): no-op rewrite verified, 58,660 functions
  moved. Fixes it needed: byte copies int3-fill their in-range jump tables (the copy reads the rebuilt ones; the stale
  entries decoded as code with bogus branch targets in re-analysis), and `DiscoverySource.EntryJump` (target of a jmp
  at a known entry, only when outside the sweep: MSVC's rotated loops also start with a jmp) bounds leaf sweeps, so
  adjacent leaf copies are not swallowed (thunk targets are added before each leaf round's sweeps).
  Statically linked CRT handlers are identified by exact PDB public name at a .pdata start
  (`ExceptionHandlerInfo.NamedByPdb`; export/import take priority, `__GSHandlerCheck` still needs its
  sequence, tables are still validated); names follow jmp hops (trampoline -> copy), and GS wrappers are
  checked at their body behind jmp hops (ILT, trampoline). Factorio: Frozen 63.8% -> 0.7% of code; no-op
  rewrite moves 99,475 functions (98.9%), verified. Runtime test: `mt` variant (/MT) of cxxehtest and
  unwindtest (`-Variants mt -Targets cxxehtest,unwindtest`).
  Factorio benchmark: `factorio.exe --benchmark <save> --benchmark-ticks N --disable-audio`, run with
  Start-Process from bin\x64 (candidates are copied there as factorio-<name>.exe; the user allowed that);
  metric is its own "Performed N updates in X ms", correctness its game-state checksum. Trace
  artifacts/lbr-factorio.etl (SpaceAgeCleanGleba.zip, 10000 ticks, includes the save load). 10000 ticks x 15
  alternating rounds: no-op +5.2%, `--blocks --jcc-erratum` -1.4%, **with `--redirect-pointers` -5.0%**
  [-5.6, -4.5] (DesignDoc Step 13). The verifier accepts call / int3 / alignment nop before table data as
  a noreturn call.
* Block layout inside C++ EH functions (`--layout-eh`, `Fh4Writer`, DesignDoc Step 14): reorders and
  hot/cold splits plain unwind-only `__CxxFrameHandler4` functions (no try blocks, not separated/catch,
  single range) and regenerates the IP-to-state map + FuncInfo4 + UNWIND_INFO (GS wrapper cookie data
  preserved). A split function's FuncInfo4 is separated: one map piece per code piece (hot copy at
  copyStart, each cold segment at coldStart), keyed to its own start because the CRT keys a separated
  function's map by `FunctionEntry->BeginAddress` (the cold chained entry's begin for a cold PC). A dropped
  jmp contributes no map point (`Fh4Writer.DroppedJump`). Verifier re-parses the output, picks each
  instruction's piece by new address, checks its state. Factorio: 4,366 fns laid out (was 2,703), 3,506 split;
  90% footprint 167 pages (was 176). Consistently ~1.4 points faster than without `--layout-eh` across three
  same-session A/Bs (e.g. -5.7% vs -4.3%); splitting cuts footprint over reorder-only but extra wall-clock is
  within noise. Runtime tests: cxxehtest o2/mt reorder and split (`Fh4LayoutTests`), negative control on a stale map.
* Pointer redirection (`--redirect-pointers`, `PointerRedirection.Plan`, DesignDoc Step 13): keeps the
  one-value rule by redirecting a function only when every form of its address is a relocated value or a
  decoded `lea` (any RVA of it, undecoded ModRM-05 pattern, other RIP operand, export/entry/TLS/EH use
  excludes it); needs DYNAMIC_BASE. Verifier: independent enumeration in original sections and copies,
  one-value check on the re-analysed output, oracle (refs must be redirected values/leas or direct
  branches, never RVAs). `RewriteResult.Redirection` / `Redirected`. Opt-in.
* Profiles: straight-line runs count the blocks they cross (`LbrProfileBuilder`), so single-block
  functions (tiny virtuals) get an ExecutionCount and C3 places them.
* DesignDoc Step 16 (Factorio): `--profile-during <decorated name>` keeps only samples between the
  first and last sample touching that function (Factorio: `?update@Surface@@QEAAXXZ`, leaves out the
  save load; 90% footprint 167 -> 99 pages). With `--redirect-pointers`, functions whose entry cannot
  hold a trampoline move without one when every pointer is redirected (`MovedFunction.HasTrampoline`;
  verifier checks). CFG builder re-explores when decoding hit an invalid byte inside a recovered table
  (tables after noreturn calls); jump table recovery models rounded indexes `((x+c)&mask)>>k` (CRT
  memmove). Factorio Frozen 276 -> 104 functions. Bench: all Step 14/16 builds ~-7%, differences within
  noise. Long tick trace `artifacts/lbr-factorio-ticks.etl` (50000 ticks): **-8.2%**, 0.7 points
  better than Step 14 (outside noise). Open: luaV_execute (LTCG keeps r9 across calls: needs an
  interprocedural clobber analysis), absolute-pointer tables ("jump through memory").

Coverage survey of 20 third-party binaries (DesignDoc §16 R2, "Coverage survey across toolchains"):
MSVC engines (Unity, Godot MSVC) are 95-97% FullyTransformable; LLVM builds (clang-cl/lld: VS Code,
clang, lld, ANGLE, Godot-lld) freeze 13-25% because LLVM's table-relative switch encoding (`lea b,[table];
movsxd r,[b+idx*4]; add r,b; jmp r`) is not recognized; statically linked CRT handlers are unidentified
without a PDB (Rust ripgrep 53% frozen, IL2CPP GameAssembly 16-18%); 7-Zip imports msvcrt's
`__CxxFrameHandler`. No third-party binary but Factorio has a PDB. 23 of 56 Steam games are 32-bit.
Re-run with `tools/survey/Survey.ps1` (needs a Release CLI build; paths are this machine's; output in
artifacts/survey).

**NativeAOT survey: done (DesignDoc R5, "NativeAOT survey").** ilc.exe, RgDotnet.Cli and a sample
(`artifacts/aot/src/aotbench`, publish needs the VS Installer dir on PATH for vswhere): 82-85% Fully, 9-10% Frozen,
97-99% of it RyuJIT's switch (`lea t,[table]; mov e,[t+i*4]; lea b,[label in fn]; add; jmp`, unsigned, bounded).
**NativeAOT images are refused by every rewriter** (`FunctionRewriter.RefuseNativeAot`, exit 2): GC/EH info trails managed
UNWIND_INFO (method-relative offsets; block layout would break it), the runtime registers one managed-code range `[__managedcode_a, z)` (append-mode
output fails fast at the first GC, verified), and funclets sit at fixed offsets from their parent (verified).
`NativeAotGate` (run by `SafetyGatePass`, `BinaryImage.NativeAot`): `DotNetRuntimeDebugHeader` export; range from the PDB
symbols, else the `RhRegisterOSModule` call (`rdx = lea a`, `r8 = lea z - rdx` before a call), else everything Frozen. Managed
methods `gc-info` RelocatableOnly, funclets and their parents Frozen. UnwindBlockFlags follows the codes **unpadded** (the
first survey read it padded and overcounted funclets). aotbench: 8,155 fns `gc-info`, Fully 16.6% of code (native runtime only). ILC emits all
managed code as one section contribution without internal fixups, so whole-program mode passes its gate with
`/DEBUGTYPE:CV,FIXUP` but cannot reorder anything.

**LLVM switch tables: done (uncommitted at the time of writing).** `JumpTableRecovery` accepts
`lea b,[rip+X]; movsxd r,[b+idx*4+d]; add r,b; jmp r` (`JumpTableEncoding.TableRelativeOffset32`,
`JumpTable.BaseRva`; signed entries, every base must be the same `lea` address, signed load <-> non-zero
base, never two-level). Rewriters refuse such functions (`BlockRebuilder.Reason`, `TableReason`).
Frozen share of code: lld-link 25% -> 9.8%, clang 25% -> ~11% (tests: `Llvm_*`). `BoundCheck` skips up to 8
flag-neutral instructions (lea/mov) between the `cmp` and its `jcc` (they must not write the compared
value or the index; base-register `lea`s among them are still applied). What still fails in lld-link
(~1000 switches), checked by disassembly: they are **switches without a default** (LLVM proved the range
from `unreachable`): the index is loaded from memory/an argument and adjusted (`dec edx`,
`add eax,-2`) with no compare anywhere, so **no code-level range analysis can bound them** (a range
analysis was scoped and dropped for that reason). Only a table-extent heuristic could (scan entries
until one leaves the function; over-approximates when tables are adjacent), and it would gain
coverage of case blocks, not transformability, since the rewriters refuse this encoding.

**Exception handlers without a PDB: done (uncommitted at the time of writing).**
`ExceptionHandlerPass.InferFromData`: a handler still Unknown after name/import/sequence/PDB
identification is classified by the handler data of *all* its users (at least 2): FH3 (FuncInfo magic,
`ParseFh3` without problem), `__C_specific_handler` (strict scope table: begin < end, jump target 0 or
in a .pdata range, handler 1 or executable, a finally needs a funclet), FH4 (`ParseFh4` without
problem); every code address must lie in some .pdata range (split functions chain their cold
fragments, so not only the user's own entry) and funclets in executable sections. One misfit user
leaves the handler Unknown for everybody. `ExceptionHandlerInfo.InferredFromData`, printed by the CLI.
msvcrt's `__CxxFrameHandler` import maps to FH3. The gate still validates the parsed tables against the
discovered functions. Frozen share: ripgrep 53% -> 11.5%, 7z.dll 47.5% -> 0.0%, Blue Prince
GameAssembly (IL2CPP) 16-18% -> 1.2%. Tests: `Static_handler_*`, `One_user_*`, `A_single_user_*`.

**ripgrep end to end (append mode, no PDB): works, -3.0% / -4.05% cycles.** `artifacts/rg/rg.exe` is a
copy of VS Code's ripgrep 15.0.0. Two workloads: `artifacts/rg/corpus` (292 MB in thousands of files) is
**2/3 kernel file-system time** (VTune: rg.exe is 31% of cycles; inside it the padded layout is -9.7%
cycles, DSB coverage 26 -> 33%), which hides user-mode changes in a benchmark. Use
`artifacts/rg/big/part0.txt` (one 290 MB file = the corpus concatenated) with
`rg -j1 -uu -c -i '[A-Z][a-z]+_[a-z]+\s*\(\s*\w+\s*,' <file>` (~0.65 s, noise floor 0.03-0.2%),
trace `artifacts/lbr-rg-big.etl` (`tools/profile/Capture-Rg.ps1`, elevated), bench needs absolute paths.
Result, 20 rounds: **C3 only -0.2% (noise), `--blocks --jcc-erratum` -3.0%, `+ --align-loops` -4.05%**;
output identical (hash) on both workloads and on a second regex. 88.7% of executed instructions placed.
What it took (all committed with tests):
* Writers move `TableRelativeOffset32` tables (append mode; whole-program refuses them). Tables that
  share a base register (LLVM hoists one `lea` into a register and loads by displacement) form one
  `TableUnit` region copied as a whole, entries rewritten relative to the new base
  (`CopiedTable.OriginalBaseRva/NewBaseRva`, `JumpTable.BaseSites/FieldSites`, sites unioned over the
  dispatch sites sharing a base; the builder replaces a table when its BaseSites change).
* **Unbounded switches** (`JumpTable.ExtentInferred`): LLVM/Rust default-less switches have no compare
  anywhere. If base, signed load and add are proven but no bound, the extent is read off the data:
  entries while they target the function, stopping at the next address any code references
  (`PreScanCodePointers` collects RIP-relative targets outside all functions). Sound for the target set
  (every real entry is a valid in-function target); only over-approximates. **Only for the signed
  table-relative form**: MSVC always bounds its tables, so an unproven bound there is an analysis gap
  (allowing it broke the /MT oracle tests: strpbrk's two adjacent tables, addressed by disp32 not RIP).
  Frozen share: ripgrep 53 -> 2.4%, lld-link 25 -> 1.8%, clang 25 -> 2.1%.
* Discovery: a forward `jmp` whose skipped bytes are all padding is a thunk, not a rotated loop
  (`JumpsOverPadding`): a copy of a thunk right before its target's copy was swallowed by its sweep.
**FH3 (`__CxxFrameHandler3`) copies: done** (`FunctionRewriter.Fh3UnwindCopy`, `RewriteVerifier.CheckFh3Copy`,
tests `Fh3Tests` on the new `fh3` (/MD /d2FH4-, imported handler) and `fh3mt` (/MT) variants of cxxehtest,
`Build-Targets.ps1 -Variants fh3,fh3mt -Targets cxxehtest,unwindtest`, run from PowerShell, not `-File`).
A byte copy of an FH3 function gets its own UNWIND_INFO (verbatim up to the handler data, GS cookie data
kept) naming a copy of the FuncInfo (40 bytes, only dispIPtoStateMap differs) and a new IP-to-state map:
same states, entries inside the function moved to the copy, entries elsewhere (its catch funclets share
the map) first so the array stays sorted. Everything else is shared with the original (unwind/try maps,
funclets; a catch funclet returns a continuation address in the original body, which stays intact).
**Catch funclets cannot move**: the runtime identifies a running catch funclet by its entry's
BeginAddress being a HandlerType.dispOfHandler; a copy is not recognized and FindHandler aborts (found by
the fh3 test; `CxxEhParser.Fh3CatchHandlers`). ripgrep: 97.5% of code moves in a no-op rewrite
(was 48%), 99.1% of executed instructions placed; speed unchanged (-2.7% / -4.0%: the FH3 functions were
~10% of executed instructions). Survey (share of code in FH3 functions): 7z.dll 47.5%, ripgrep 45%,
ELDEN RING 11.9%, MGS V 8.6%, others ~0: the FH3 formats are old MSVC and Rust. FH4: Factorio 63%, IL2CPP 11-15%.
`analyze` now prints bytes per handler kind.

**FH3 block layout (`--layout-eh`): done** (`Fh3Writer`, `RewriteVerifier.CheckFh3Layout`, `Fh3LayoutTests`):
one sorted map over the hot copy and all cold segments, one entry per state change; try-block functions are
laid out too (catch continuations are absolute addresses in the original-body funclets, no regeneration).
ripgrep with `--layout-eh`: 144 functions laid out, 123 split, output identical, -3.6% (same as without).
**DesignDoc**: Steps 17-19 (ripgrep/LLVM tables/default-less switches, handlers without a PDB, FH3) and the
re-run survey table (R2) are written. Survey now: Frozen <= 6.5% everywhere except ELDEN RING (15.7%, protected).

**7-Zip (7z.dll, 47.5% FH3, no PDB, append mode): done, DesignDoc Step 20.** Archives byte-identical for
every build; 20 rounds, noise 0.04%: C3 -1.43%, `--blocks --jcc-erratum` -5.85%, `+ --align-loops` -6.00%,
`+ --layout-eh` -6.09%. (Setup notes:) `artifacts/7z/base` = copy of
`C:\Program Files-Zipz.exe` + `7z.dll` (7-Zip 26.01), input `artifacts/7z/input.txt` (4 MB of text),
workload `7z.exe a -y -mx=5 -mmt=1 <archive> <input>` (1.03 s, deterministic archive, hash 9D5FD9C5F782...).
Trace: `tools/profile/Capture-7z.ps1` (user runs it elevated) -> `artifacts/lbr-7z.etl`. Then rewrite **7z.dll**
(`--profile ... --process 7z.exe`), put it next to a copy of 7z.exe in another folder, bench the two exes
(absolute paths), and compare archives byte for byte.

**PDB for append mode: done** (`AppendPdb`, `AppendPdbTests`, DesignDoc Step 21): `rewrite` writes
`<output>.pdb` (original + OMAP, new GUID in the CodeView record) whenever the input has a PDB; `--no-pdb`
skips. Checked with our loader, dbghelp and cdb (breakpoint by name, stack names, source lines).

**Profiles without LBR: done, DesignDoc Step 22** (`IpProfileBuilder`, `--ip-only [--ip-estimator max|mean]` on
`analyze` and `rewrite`, `Capture-Lbr.ps1 -SamplingOnly`): block counts from IP samples (max per block),
edge counts by iterative proportional fitting, unsampled blocks cold only with >= 500 samples in a predecessor.
Against branch-record builds: zopfli -8.40 vs -7.98%, ripgrep -4.05 vs -4.06, 7z.dll -5.58 vs -6.01,
speedtest1 -2.4 vs -4.66. Also fixed: iced cannot widen a short branch to an external target (BlockRebuilder
`externalBranches`, fixed-size near placeholders patched after encoding).

**Residency of an output, mispredicts, inlining ceiling: DesignDoc Step 23.** `winbolt residency <input> <output>
--profile <trace of the output>` (`ResidencyMap`/`ResidencyAnalysis` in WinBolt.Rewrite, `EtwLbrProfile.ReadRaw`) reports
time per place (appended / trampoline / original body / unmoved), trampoline traffic by source with the redirection
status of indirect targets, and entries into moved functions' original bodies (unexplained = a reference the analysis
missed). speedtest1 `--blocks --jcc-erratum`: 98.7% of samples in appended code, 1.1% on trampolines, no original
body executed; all trampoline traffic (65 fns, indirect) is redirectable. Factorio factorio-ticks.exe with
`--profile-during` (residency supports it): 97.2% appended, 0.13% trampolines, 2.6% unmoved, no original body
executed. It exposed a planner false positive, fixed: UNWIND_INFO headers/codes were scanned as possible RVAs
(752 vs 746 functions redirected, verified). ETW LBR entries carry no mispredict bit (info qword always 0): use VTune.
Leaf inlining and CPU-specific instruction substitution (BMI2, AVX2 width, FMA)
measured at <= 0.1% of instructions on all targets (FMA also changes results): not built.

**Longjmp / EH-continuation targets move: done, DesignDoc Step 24** (`GuardTables`, `EhContinuationTests`, variant `ehcont`:
/guard:cf /guard:ehcont /CETCOMPAT, `-Variants ehcont -Targets cxxehtest,unwindtest`). With plain 4-byte guard table
entries the output gets new `GuardLongJumpTargetTable` / `GuardEHContinuationTable` in .wbdata (original entries + each
moved target's new address, sorted; load config pointer/count re-pointed); otherwise such functions stay unmoved. The
verifier lets only those load config fields change. No CET here: enforcement is not exercised at run time.

**Tail calls and switch indexes: done, DesignDoc Step 25.** `CfgConstructionPass.EndsEpilogue`: a REX.W `FF /4` right
after a frame teardown (`add/lea rsp`, pops) in its block is a tail call even when the function has interior addresses
(the ABI's epilogue form; none of ~60k recovered switch dispatches has it). `JumpTableRecovery.FollowIndex`: `add/sub idx,c`,
`inc/dec idx` in place = `lea idx,[x+c]`. Vampire Survivors GameAssembly Frozen 6.5% -> 2.9%. Jumps through memory
(absolute tables) are <= 0.2% of code everywhere: not built. The scratch classifier of unresolved jump shapes is not in
the repo (reasons are in `Function.DowngradeReasons`).

**Indirect call promotion: done, DesignDoc Step 26** (`--promote-calls`, `CallPromotion.Plan`, `BlockRebuilder.Encode`
promotions, `RewriteVerifier.CheckPromotedCall`, `CallPromotionTests` incl. a wrong-target build that must still run
correctly). Rebuilt functions without EH tables; `lea r11,[V]; cmp op,r11; je fast; call op; jmp after; fast: call T`.
7-Zip: -0.95% / -1.31% cycles over the same layout in two sessions (second CI [-2.16, -0.49]); zopfli -0.11% (noise).
Benchmark builds in artifacts/bench-icp.

**Startup order and page model: done, DesignDoc Step 27** (`--order first-use`, `--page-model`, `EtwLbrProfile.FirstTouch`/
`FirstTouches`, `FunctionOrdering.FirstUse`, `PageModel`). Model: Factorio code pages touched in the first 1% of the trace
151 (original) / 120 (C3) / 36 (first-use). Measured with a warm cache: nothing (Factorio 1-tick startup, first-use vs C3
-0.06%, page faults equal, ~301k/run, mostly data). Cold-cache measurement needs an elevated standby flush: not done.
`bench` now prints page faults per run and has `--copy-beside` (noise-floor copy next to the baseline: Factorio needs it).
Candidates factorio-su-c3.exe / factorio-su-fu.exe were copied into Factorio's bind.

**Stale profiles: done, DesignDoc Step 28** (`rewrite new.exe out.exe --profile old.etl --profile-binary old.exe`,
`StaleProfile.Transfer` in Core, `StaleProfileTests`). Functions by unique PDB name / content hash, blocks by strict then
loose content hash. Carried over from o2 zopfli: self 100% (counts identical), hot-function edit 99.6%, /guard:cf 89%,
LTCG 45%. The edited build (artifacts/targets-mod, source copy artifacts/zopfli-mod) with the stale profile: -10.9%
cycles vs itself (fresh profile on o2: -8.4%).

**Next (not yet agreed):** a capture on a CPU without LBR to confirm the sampling-only path end to end; lld-link/clang as further LLVM targets (a compile workload); PMC/VTune check of
the 7-Zip gain; whole-program mode needs fixups (only self-built targets). Intel PT as a dynamic oracle for
PDB-less outputs (DesignDoc §14: inbox ipt.sys works here, snapshot ring buffers, probe results recorded).

Every Stage 1 deliverable in DesignDoc §8 exists. **Known gaps** within them:

* Code-address table recovery (§5.2) — remaining switch encodings (absolute-pointer tables
  from other toolchains, tables whose image base is loaded in another block, which needs
  dataflow; jump tables in leaf functions, whose extent the discovery sweep ends at the
  `jmp`), vtables, coroutine resume/destroy pairs, computed `goto`.
* Parsed EH tables in merged `.rdata`-in-`.text` images (sqlncli11) could be labelled
  `KnownData` instead of unattributed.

Pick up here: Stage 6 steps 2-8 work and are measured on three targets (DesignDoc Step 8
table): with `--blocks --jcc-erratum`, speedtest1 about -5% (PGO -6.1%, mostly fewer
instructions), zopfli -8 to -9.6% (PGO -3.6 to -4.7%), zopflipng -19% (PGO -10.4%). Next:
FH3 functions
(default MSVC emits FH4), block layout inside C++ EH / SEH functions (IP-to-state map and
scope table regeneration; none is hot in the targets), an unaffected CPU to check padding's
cost where the erratum does not apply.
WinBolt on top of PGO (DesignDoc "Step 12"): PGO-split functions move their entry range
(`Function.EntryBlocks`, `MovedFunction.Place`); the oracle fails only for unknown references
into a trampoline (deeper ones run the intact original: warning). Traces artifacts/lbr-pgo-*.etl.
**PGO + `--rebuild --jcc-erratum` is the best binary on all three targets**: speedtest1
-9.35% vs o2 (PGO -6.6%), zopfli -12.05% (PGO -3.5%), zopflipng -20.2% (PGO -10.6%); our
block layout over PGO's is 0.3-0.7 points worse. Recommended: PGO build ->
`--profile .. --rebuild --jcc-erratum`; non-PGO build -> `--profile .. --blocks --jcc-erratum`.
Trampoline cost is measured (DesignDoc "Step 11"): redirecting every pointer to moved
functions gains ~0.2% on speedtest1, so a whole-binary / in-place rewrite is not worth a
relinker for speed (only for size, one copy per function, OMAP). Revisit padding's cost on a
CPU without the JCC erratum some day (user's call). Unwinding through moved/rebuilt/cold frames is
tested at run time (`unwindtest`, `UnwindTests`, `BlockLayoutTests`, `CxxEhTests`). Build only new variants (`-Variants ltcg,pgo`): rebuilding o2 changes its timestamp and
unbinds `artifacts/lbr-speedtest1.etl`. Verification check 4 (re-analysis of the
output) is done. Still open: PMU capture. The speedtest1 trace is `artifacts/lbr-speedtest1.etl` (a copy of
the user's capture, which landed in C:\Windows\System32\artifacts because an elevated
shell starts in System32: always give the user absolute paths for elevated commands). Later: in-place mode
when fixups exist, OMAP emission. Open Stage 2/3 items: coverage threshold, PMC capture, CPUID-flag dispatch.
`tools/profile/Capture-Lbr.ps1` must be run elevated by the user; its traces include every
process on the machine, so they stay in `artifacts/` (ignored) and are never published.

## Optimization targets (Stage 4+)

Agreed with the user: **zopfli** (`D:\zopfli-master`, C, deterministic output: the
correctness target) and **SQLite** (`D:\projekty\SQLite`, a fossil checkout of
https://sqlite.org/src at tag `version-3.53.4`, repository file `sqlite.fossil` in that
folder; `fossil update <tag>` to move). The old 3.8.7 tree was renamed to
`D:\projekty\SQLite-3.8.7-old` for the user to delete. zopfli also contains zopflipng (C++),
a later target for C++ EH paths.

`tools/targets/Build-Targets.ps1` also builds zopflipng.exe (C++, /EHsc, zopfli + lodepng) and
cxxehtest.exe (the C++ EH runtime test); `-Targets` selects (rebuilding a target unbinds its
LBR traces). It builds zopfli.exe and SQLite's speedtest1.exe (amalgamation
generated from the checkout; SQLITE_ENABLE_RTREE for the default test set) in variants `o2`
and `guardcf` (default), `ltcg` and `pgo` (MSVC PGO trained on the benchmark workload) into
`artifacts/targets/<variant>/`, with PDBs. It clears
NoDefaultCurrentDirectoryInExePath for its own child cmd only (SQLite's build runs the
jimsh0.exe it compiles by bare name). Benchmarks: `zopfli --i5 <file>` (deterministic
output: compare bytes), `speedtest1 --size 25` (~0.9 s). Analysis of the builds: 95-96% of
code FullyTransformable; speedtest1's interpreter loop (sqlite3VdbeExec) switch is recovered.

## Build

```bash
dotnet build WinBolt.slnx
dotnet test WinBolt.slnx
```

`winbolt analyze <path-to-pe> [--pdb <file>] [--symbols <dir>]` runs the Stage 1 analysis:
structure, layout provenance, function discovery, CFG and call graph, exception tables,
jump tables, and the safety gate summary (see "Current status" above). The real-binary
tests use C:\Windows\System32 and, for PDBs, bft's symbol cache; they return early when
those are absent.
