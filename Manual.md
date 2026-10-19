# WinBolt User Manual

WinBolt is a post-link optimizer for Windows x64 PE executables (BOLT-inspired). It analyzes a
finished `.exe`/`.dll`, optionally reads a runtime profile, and writes a new binary with a better
code layout. Terms are explained in [Glossary.md](Glossary.md); design and measurements are in
[DesignDoc.md](DesignDoc.md) (authoritative).

The output is written **only if verification passes**, and the same program output was seen on every
target tested. Treat it as an optimization you validate with your own tests, not a guarantee.

## 1. Quick start

```
dotnet build WinBolt.slnx -c Release

# 1. Look at the binary (no profile needed)
winbolt analyze app.exe --pdb app.pdb

# 2. Capture a profile of a representative run (elevated PowerShell, see section 4)
.\tools\profile\Capture-Lbr.ps1 -Output D:\work\app.etl -Workload { & D:\work\app.exe <args> }

# 3. Rewrite (recommended command for a normal, non-PGO MSVC build)
winbolt rewrite app.exe app.opt.exe --pdb app.pdb --profile D:\work\app.etl --blocks --jcc-erratum

# 4. Compare speed, then check your own correctness tests
winbolt bench D:\work\app.exe D:\work\app.opt.exe --rounds 20 -- <args>
```

Always use **absolute paths** for traces and benchmark binaries (elevated shells start in
`C:\Windows\System32`).

## 2. Commands

| Command | Purpose |
| --- | --- |
| `analyze` | Structural report, safety classification, optional profile reports. Changes nothing. |
| `rewrite` | Produces the optimized binary (and PDB). |
| `residency` | Shows where a trace of a rewritten binary still runs original code. |
| `bench` | Statistically careful speed comparison of binaries. |

Exit codes of `rewrite`: `0` written; `1` bad usage or would overwrite an input; `2` rewrite refused
or profile rejected; `3` verification failed (nothing written).

### 2.1 Options shared by `analyze`, `rewrite` and `residency`

| Option | Meaning |
| --- | --- |
| `--pdb <file>` | PDB to use. Must match the image's GUID and age. |
| `--symbols <dir>` | Directory to search for the PDB (flat or symbol-store layout). Repeatable. Local directories in `_NT_SYMBOL_PATH` are searched too. Nothing is downloaded. |
| `--profile <etl>` | ETW trace with LBR stacks (from `Capture-Lbr.ps1`). The trace must match the image (same build); a mismatch is rejected, never guessed. For a trace of an earlier build, see `rewrite --profile-binary`. |
| `--process <name>` | Process in the trace to take the profile from. Default: the image itself when it is an `.exe`. **Required for a DLL** (e.g. `--process 7z.exe`). |
| `--profile-during <function>` | Keep only samples between the first and last execution of this function (decorated name, e.g. `?update@Surface@@QEAAXXZ`). Excludes loading and shutdown. |
| `--ip-only` | Build the profile from sampled instruction pointers only (no branch records). An estimate; for CPUs without LBR. |
| `--ip-estimator max\|mean` | How `--ip-only` turns samples into block counts. Default `max`. |

### 2.2 `analyze`

```
winbolt analyze <pe> [--pdb f] [--symbols dir]... [--profile etl [--process n] [--profile-during fn] [--ip-only]] [--html file]
```

Prints: PE structure, layout provenance (compiler PGO / already rewritten / LTCG), function
discovery, CFG and call graph, exception handling kinds, jump tables, the safety gate summary (how
much code is FullyTransformable / RelocatableOnly / Frozen and why), instruction histogram and CPU
feature tiers, and the whole-program rewrite gate verdict. With a profile it adds the match rate,
hot functions, hot-code footprint and the Stage 3 advisor.

* `--html <file>`: also writes a self-contained report (with a profile: heat map and hot paths).

Use `analyze` first on any new binary: if a large share of the code is Frozen, a rewrite will gain
little. With a PDB the numbers are better (names, handler identification).

### 2.3 `rewrite`

```
winbolt rewrite <input> <output> [options]
```

The output must be a different file. A PDB named `<output>.pdb` is written next to it when the
input has one.

**Modes (what is moved):**

| Invocation | Result |
| --- | --- |
| no `--profile` | Verified **no-op rewrite**: every eligible function copied into `.wbtext`, entries get trampolines. Proves the machinery on your binary; no speed change (slightly slower). |
| `--profile` | Only executed functions are moved, in C3 (call-chain) order. |
| `--rebuild` | Functions are re-encoded from their CFG instead of byte-copied. |
| `--blocks` | Reorders blocks by the profile and splits never-executed blocks into a cold area. Needs `--profile`. Implies `--rebuild`. |
| `--whole-program` | In-place rewrite from linker fixups (see 2.3.2). |

**Options:**

| Option | Meaning |
| --- | --- |
| `--no-split` | With `--blocks`: keep cold blocks inside the function (reorder only). |
| `--block-order chains\|ext-tsp` | Block ordering algorithm. `chains` (default, greedy Pettis-Hansen). `ext-tsp` gives more fall-throughs but was measured slower; keep the default. |
| `--jcc-erratum` | Pad executed branches off 32-byte boundaries (Intel JCC erratum): prefix padding first, NOPs for the rest; copies placed to minimize exposure. **CPU-specific** (see section 5). |
| `--align-loops` | Start hot loop heads on 32-byte boundaries. Implies `--rebuild`. Opt-in. |
| `--redirect-pointers` | Re-aim pointers to moved functions (vtables, function pointer tables, `lea`) at the copies, for functions whose every address use is provably known. Indirect calls then skip the trampoline. Needs DYNAMIC_BASE. Opt-in; the big win on Factorio. |
| `--promote-calls` | Indirect calls whose profiled calls go >= 90% to one function become a compare and a direct call, with the original indirect call kept for any other target. Rebuilt functions without C++ EH/SEH tables only; not on XFG images. Needs `--profile`; implies `--rebuild`. Opt-in: pays where such calls are a few percent of taken branches (7-Zip -1.3%), noise elsewhere. |
| `--profile-binary <exe>` | The `--profile` trace was recorded on this **other build** of the program (a stale profile). The trace is applied there and carried over to the input by matching functions (PDB names, else content) and blocks (content); what does not match is dropped. The rewrite prints how much carried over (a small source edit: ~99%; changed compiler flags: ~90%; LTCG vs non-LTCG: ~45%). Give the old build's PDB next to it or via `--symbols`. |
| `--order c3\|first-use` | Function order. `c3` (default): call chains by heat. `first-use`: every executed function in the order it first ran, so startup code sits together. Measured with a warm file cache it gained nothing (Factorio startup); it may help cold starts. |
| `--page-model` | Also print how many code pages the profiled run touches over time (1/10/25/50%, all) in the original and the new layout. A model from the trace's samples, not a measurement. Needs `--profile`. |
| `--layout-eh` | Also reorder/split blocks of C++ EH functions (FH3 and plain FH4), regenerating their IP-to-state maps. Opt-in. |
| `--layout-shift N` | Start laid-out code N bytes later (multiple of 64): same layout at another alignment. Use it to measure layout luck (see 3.2). |
| `--no-pdb` | Do not write `<output>.pdb` (the image then still names the original PDB, which does not describe the copies). |

Rejected combinations: `--blocks` without `--profile`; `--whole-program` with `--redirect-pointers`,
`--layout-eh`, `--promote-calls` or plain `--rebuild`; `--promote-calls`, `--order first-use` or `--page-model` without
`--profile`; `--profile-binary` with `--order first-use` or `--page-model`.

The report printed by `rewrite` tells you: how many functions moved and the share of executed
instructions they carry, the top functions *not* placed and why, functions laid out and split,
fall-through rate before/after, executed branches on 32-byte boundaries before/after, hot footprint
(pages/lines) before/after, patched fields, what was not moved by reason, and the verification
result. Read the "not placed" lines: they show what limits the gain.

#### 2.3.1 Append mode (default)

Moved code is copied into new sections (`.wbtext` code, `.wbdata` tables); originals remain, with
`jmp` trampolines at entries. The file grows (64-88% in whole-program comparisons) but works without
linker information, on third-party binaries, with or without a PDB. Settled design (§6.1).

Images built with `/guard:ehcont` (or with a longjmp table): functions holding listed continuation or longjmp targets
move too, and the output gets new tables in `.wbdata` listing both the original and the moved addresses (when the
tables have plain 4-byte entries; otherwise those functions stay in place).

#### 2.3.2 `--whole-program`

Moves every function as a unit and re-resolves references using the linker's fixup records. No
trampolines, output only 7-11% larger. Requirements: a PDB with fixup records (the program must be
linked with `/DEBUGTYPE:CV,FIXUP`) and passing the whole-program gate (`analyze` prints the verdict).
Only for binaries you build yourself. Compatible with `--profile`, `--blocks`, `--jcc-erratum`,
`--align-loops`. The PDB written carries OMAP tables so debuggers translate addresses.

### 2.4 `residency`

```
winbolt residency <input> <rewritten> --profile <etl of the REWRITTEN image> [--process n] [--profile-during fn] [--pdb f] [--symbols dir]... [--top N]
```

Capture a new trace of the rewritten binary, then run this. It reports time per place (appended code,
trampolines, original bodies, unmoved), trampoline traffic by source with the reason pointer
redirection left an indirect target alone, and entries into moved functions' original bodies
(anything there is a reference the analysis missed). `--pdb/--symbols` are the **input's**. `--top N`
(default 15) limits listed entries.

### 2.5 `bench`

```
winbolt bench <baseline> <candidate>... [--rounds N] [--warmup N] [--copy-beside] -- <program arguments>
```

Each round runs the baseline, a byte-identical copy of it (the noise floor) and every candidate once
in shuffled order. It reports wall time and CPU cycles with paired 95% bootstrap intervals and claims a
change only when it clears the noise floor. Defaults: 20 rounds (minimum 5), 2 warm-up. With two or more
candidates each is also compared to the first.

* A candidate may be a **group** `name=a.exe,b.exe,...` (the same layout built with different
  `--layout-shift` values); the group counts as the mean of its members. Use this for any A/B that
  matters (3.2).
* Use absolute paths. Program arguments follow `--`.
* Page faults per run (soft and hard, `GetProcessMemoryInfo`) are reported too. Image pages are only part of
  them; data usually dominates.
* `--copy-beside`: put the noise-floor copy next to the baseline (`<name>-benchcopy.exe`, removed afterwards)
  instead of a temporary folder, for programs that find their data next to the exe (Factorio). Put candidates in
  the same folder.

## 3. Recommendations

### 3.1 Which command to use

| Situation | Command |
| --- | --- |
| Non-PGO MSVC build (the usual case) | `--profile .. --blocks --jcc-erratum` |
| MSVC PGO build | `--profile .. --rebuild --jcc-erratum` (best binary on every target; our block layout over PGO's is 0.3-0.7 points worse) |
| Large C++ program with many vtables / function pointers | add `--redirect-pointers` (Factorio: -1.4% to -5.0%) and `--layout-eh` (about 1.4 points more) |
| Many hot virtual / function-pointer calls with one dominant target | try `--promote-calls` with `--blocks` (7-Zip: -1.3% over the same layout; zopfli: noise); measure |
| The binary was rebuilt after the trace was taken | `--profile old.etl --profile-binary old.exe`: no new capture needed after a small change; check the carried-over share it prints |
| CPU without LBR (AMD, most VMs) | capture with `-SamplingOnly`, rewrite with `--ip-only`. Less accurate (speedtest1 -2.4% vs -4.66%; zopfli and ripgrep close) |
| Code with long-running hot loops, on an Intel CPU affected by the JCC erratum | try `--align-loops`: +0.25-0.5 points on some targets, 0.5 points *worse* on zopflipng and cost-neutral elsewhere; measure |
| Build you control, linked with `/DEBUGTYPE:CV,FIXUP` | `--whole-program` for smaller output and no trampolines (gain over append: about 0.5 points) |
| Just checking the tool works on your binary | `rewrite` without a profile; compare output with the original |

C3 function ordering alone is usually within noise on small hot sets; the gains come from block
layout and branch padding.

### 3.2 Measuring honestly

* One build can be 0.5-1.5 points faster or slower from alignment alone. For an A/B that matters,
  build each variant at several `--layout-shift` values (e.g. 0, 64, 128, 192) and use a `bench` group.
* Use `winbolt bench`, not a stopwatch; the baseline copy shows the noise floor. Between separate
  sessions, results differ by up to about 0.8 points: compare within one session.
* Benchmark a workload that is user-mode CPU bound. File-heavy workloads (ripgrep over thousands of files
  was two thirds kernel time) hide user-mode changes.
* SQLite `speedtest1`: use `--memdb --size 25`.
* Check correctness with output equality (hash) on the benchmark **and on an input the profile never saw**.
  Measured gains on unseen inputs held up.
* A no-op rewrite is slower (trampolines, about +0.7% to +5%); only profile-driven layouts win.

### 3.3 Profiling

* Profile a **representative, steady-state workload** of a few seconds, long enough for many samples; the
  trace must be of exactly the binary you rewrite (rebuilding it changes the timestamp and unbinds the trace).
  Keep the profiled build: with `--profile-binary` its trace can lay out a later build (a stale profile). Re-capture
  after large changes (compiler flags, LTCG), where much less carries over.
* Use `--profile-during <function>` to drop startup and shutdown when the interesting phase has a recognizable
  function (Factorio: footprint 167 -> 99 pages).
* DLLs: trace the host process and pass `--process <host.exe>`; rewrite the DLL.
* Traces include every process on the machine, so they stay in `artifacts/` and are never published.

### 3.4 Where the gain comes from, and limits

* Gains measured so far: SQLite speedtest1 about -5%, zopfli -8 to -9.6%, zopflipng -19%, ripgrep -4%,
  7-Zip -6%, Factorio -5% to -8% (Intel i5-9600K, a CPU with the JCC erratum). Most of it is front-end:
  better decoded-instruction-cache (DSB) coverage and fewer pages touched.
* It cannot replace compiler work: PGO's inlining (fewer instructions) is out of reach.
* Frozen functions (exotic exception handlers, unrecognized jump tables, unidentified static CRT handlers) are left
  alone. `analyze` shows the share; a PDB reduces it.
* Catch funclets, functions with unrecognized handlers and anything the safety gate cannot prove are never moved.
  The default for anything unrecognized is to leave it.
* Padding is deliberately CPU-specific: its cost on CPUs without the JCC erratum has not been measured.

### 3.5 Debugging and symbols

* Append mode writes `<output>.pdb` (original plus OMAP, new GUID); debuggers show names, stack traces and
  source lines for moved code. Keep the pair together. Do not overwrite the original PDB (the tool refuses).
* With `--no-pdb` the output still names the original PDB, which does not describe the copies.
* Never write outputs into protected locations (e.g. a Steam folder); copy the target elsewhere first.

## 4. Capturing profiles

Scripts live in `tools/profile/`. They must be **run elevated** by the user; give them absolute paths.

| Script | Purpose |
| --- | --- |
| `Capture-Lbr.ps1` | General capture: NT Kernel Logger with sampling and LBR, runs `-Workload`, merges to `-Output` (.etl). Parameters: `-Output`, `-Seconds` (default workload length), `-Filters` (xperf `-LastBranch` filters; empty records everything), `-Workload` (scriptblock), `-SamplingOnly` (no LBR; use with `--ip-only`). |
| `Capture-7z.ps1`, `Capture-Rg.ps1` | Ready-made captures for 7-Zip and ripgrep workloads. |
| `Collect-TopDown.ps1` | VTune top-down collection (3 repeats, 0.1 ms sampling) for front-end attribution. Needs Intel VTune. |

Other tools: `tools/targets/Build-Targets.ps1` builds the test targets (`-Variants o2,guardcf,ltcg,pgo,mt,fh3,fh3mt,ehcont`,
`-Targets ...`; `-Zopfli <source copy> -Output <folder>` builds a modified zopfli elsewhere); `tools/survey/Survey.ps1` surveys third-party binaries (needs a Release CLI build). Build only the
variants you need: rebuilding a target unbinds its traces.

## 5. CPU notes

* LBR (branch records) need Intel hardware support. AMD and most VMs: use `-SamplingOnly` / `--ip-only`.
* `--jcc-erratum` targets Skylake-family Intel cores (the JCC erratum). Padded code runs 1.8-2.6% more
  instructions but fewer cycles on the test CPU (i5-9600K). On a CPU without the erratum it costs cycles: on an
  Intel N100 (Gracemont, no uop cache), `--blocks --jcc-erratum` was 1.7-2.0% slower than `--blocks` alone
  (zopfli and zopflipng, 20 rounds, clear of the noise floor), roughly the executed-NOP overhead. Use it only
  for deployments known to run on affected cores. AMD and newer Intel cores are unmeasured.
* ETW LBR entries carry no mispredict bit; use VTune for misprediction data.

## 6. Troubleshooting

| Symptom | Cause / action |
| --- | --- |
| `Profile rejected: ...` | The trace does not match the image (different build, or the process was not found). Re-capture against this exact binary, or pass the build the trace was recorded on with `--profile-binary`; pass `--process` for DLLs. |
| `--profile-during: ...` | The decorated function name was not found or never executed in the trace. |
| `Rewrite refused: ...` | The safety gate refused (e.g. whole-program without fixups). Use append mode. |
| exit code 3, `Verification failed` | An internal check failed and nothing was written. Report it with the binary; do not work around it. |
| `No PDB` shown by `analyze` | Pass `--pdb` or `--symbols`; the PDB must match the image's GUID and age. |
| Large "not placed" share | Look at the listed reasons; Frozen/unrecognized functions are the limit. Try with a PDB. |
| `--layout-shift` ignored | Value must be a multiple of 64. |
| Output larger than input | Normal in append mode (originals are kept). Use `--whole-program` where possible. |

## 7. Building and testing the tool

```
dotnet build WinBolt.slnx
dotnet test WinBolt.slnx
```

Tests that need real binaries use `C:\Windows\System32` and artifacts under `artifacts/`; they return early
when those are absent. This repository uses Fossil, not git (see CLAUDE.md).
