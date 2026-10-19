# WinBolt Glossary

Terms used in this project, in alphabetical order within each group. [DesignDoc.md](DesignDoc.md)
is authoritative for design; section numbers (§) refer to it. Project-specific meanings are
stated where they differ from the general one.

## Project and process

| Term | Meaning |
| --- | --- |
| **WinBolt** | Post-link optimizer for Windows x64 PE executables, inspired by LLVM BOLT. C#/.NET. |
| **BOLT** | LLVM's Binary Optimization and Layout Tool; the model for this project. |
| **Append mode** | Default output strategy (§6.1): moved/rebuilt code goes into a new section appended to the PE; originals stay in place. Settled decision. |
| **Whole-program mode** | `rewrite --whole-program` (§6.2, milestones W1-W4): moves linker contributions in place. Needs complete linker fixup records, so only self-built targets. |
| **W1-W4** | Whole-program milestones: W1 gate, W2 contribution moving, W3 block rebuild, W4 OMAP/PDB output. |
| **Stage 1-8** | Roadmap stages in §8 (analysis, profile, advisor, safe rewriting, function layout, block reordering, specialization, research). |
| **Step N** | Numbered sub-results in DesignDoc's Stage 5/6 sections (e.g. Step 13 pointer redirection). |
| **Target** | A binary used for optimizing and benchmarking: zopfli, zopflipng, speedtest1 (SQLite), Factorio, ripgrep, 7-Zip. |
| **Fossil** | The version control system used here (not git). See CLAUDE.md. |
| **bft** | Sibling project `AssemblyOptimizationDetection` (BinaryFingerprint); source of the provenance classifier and the symbol cache. |
| **Noise floor** | Run-to-run variation of a benchmark, measured with a baseline copy of the same binary. |
| **Layout noise** | Speed difference caused only by where code lands (alignment), not by what it does; 0.5-1.5 points. `--layout-shift` measures it. |

## PE format

| Term | Meaning |
| --- | --- |
| **PE / PE32+** | Portable Executable, the Windows binary format; PE32+ is the 64-bit variant. |
| **RVA** | Relative virtual address: offset from the image base once loaded. The unit for all addresses here. |
| **Image base** | Preferred load address; `__ImageBase` is the linker symbol for it. |
| **Section** | Named region of the image (`.text`, `.rdata`, `.pdata`, ...). |
| **`.wbtext` / `.wbdata` / `.wbcold`** | Sections WinBolt appends: rewritten code, new tables (.pdata, UNWIND_INFO, relocs, jump tables), and spilled cold code (whole-program mode). |
| **`.pdata`** | Table of RUNTIME_FUNCTION entries (begin, end, unwind info) for every non-leaf function. |
| **UNWIND_INFO** | Per-function record describing prologue effects so the OS can unwind the stack; may chain to a parent. |
| **Chained entry (CHAININFO)** | A `.pdata` entry whose UNWIND_INFO points at a parent entry; how split functions (hot/cold) are described. |
| **Leaf function** | Function with no `.pdata` entry (no stack frame use); found by other means in discovery. |
| **`.reloc` / base relocation** | Table of absolute addresses the loader patches when the image is not loaded at its preferred base. |
| **DYNAMIC_BASE** | DllCharacteristics flag (ASLR); required for pointer redirection. |
| **IAT** | Import Address Table: slots filled by the loader with imported function addresses. |
| **Import thunk** | `jmp [rip+IAT slot]` stub. |
| **Load config directory** | PE directory holding security metadata (CFGuard tables, GS cookie, SEH tables). |
| **EH-continuation table (`/guard:ehcont`)** | `GuardEHContinuationTable` in the load config: the only addresses an exception may resume at when user-mode shadow stacks (CET) are enforced. Append mode writes an extended copy in `.wbdata` when functions holding targets move (`GuardTables`, Step 24). |
| **Longjmp table** | `GuardLongJumpTargetTable`: valid `longjmp` return addresses (the instructions after `setjmp` calls); handled like the EH-continuation table. |
| **CET / shadow stack** | Intel Control-flow Enforcement Technology; a hardware copy of return addresses. Enforces the EH-continuation table; absent on the test CPU. |
| **RSDS** | CodeView debug record naming the PDB, with its GUID and age. WinBolt changes the GUID in outputs. |
| **POGO** | Profile-guided optimization debug entry; evidence of MSVC PGO. |
| **TLS callback** | Function run by the loader on thread start/exit; a function entry point that code does not call directly. |
| **Image checksum** | `PeChecksum`; recomputed on output. |

## Control flow and code analysis

| Term | Meaning |
| --- | --- |
| **CFG (control flow graph)** | IR structure of basic blocks and edges. Not to be confused with CFGuard. |
| **CFGuard / CFG-enabled** | Control Flow Guard exploit mitigation; the image lists valid indirect-call targets. "Enabled" here means GUARD_CF flag *and* CF_INSTRUMENTED in the load config. |
| **Basic block** | Straight-line instruction run with one entry and one exit. |
| **Fall-through** | Execution continuing into the next block without a taken branch. |
| **Call graph** | Callers/callees; call sites are in `BinaryImage.CallSites`. |
| **Noreturn call** | A call that never returns (e.g. `abort`); an `int3`/`nop` after it at a range end is not falling off. |
| **Function discovery** | Finding function entries and extents from `.pdata`, exports, entry point, TLS, CFGuard, relocations, call targets, symbols. |
| **Discovery source** | Why a function was found (`DiscoverySource`: Symbol, ExceptionTable, CodePointer, EntryJump...). |
| **Unclaimed code** | Executable bytes not attributed to any function (padding, known data, invalid fragment, unattributed). |
| **FunctionRange** | One contiguous piece of a function; a `Function` owns a list of them (§5.1). |
| **Split function / cold fragment** | Function whose cold part sits elsewhere, tied by a chained `.pdata` entry. |
| **Entry blocks** | Blocks of a PGO-split function's entry range. |
| **Tail call** | A `jmp` to another function in place of call+ret. |
| **Epilogue tail call** | Indirect tail call right after a frame teardown (`add rsp`/pops), encoded with a REX.W prefix (`48 FF /4`) as the x64 ABI requires for epilogues; accepted as a tail call even in functions with interior addresses (`EndsEpilogue`, Step 25). |
| **Thunk** | Tiny function that only jumps to another (e.g. ILT stub, trampoline). |
| **Rotated loop** | MSVC loop form that starts with a `jmp` to the loop test; must not be mistaken for a thunk. |
| **Jump table** | Table of code addresses for a `switch`; recovered by `JumpTableRecovery`. |
| **Single-/two-level table** | MSVC forms: one table of offsets, or a byte table indexing into an offset table. |
| **Table-relative offset 32** | LLVM encoding: signed 32-bit entries relative to a base `lea`. |
| **In-place index adjustment** | `add/sub/inc/dec` of a switch index in place (`add eax,-5`), treated like `lea idx,[x+c]` when proving the table bound (Step 25). |
| **Jump through memory** | `jmp [mem]` that no table explains (absolute-pointer tables, memory-indirect tail calls); left Frozen, at most 0.2% of code anywhere. |
| **Extent inferred** | Table size read off the data (entries that target the function) when no compare bounds it; only for signed table-relative form. |
| **Table unit** | Several tables sharing one base register, copied and rebased as a whole. |
| **Data barrier** | Recovered table bytes inside a function that decoding must not run into. |
| **Code pointer** | `lea reg,[rip+X]` into code; marks a function address-taken (entry) or `RelocatableOnly` (interior). |
| **Address-taken** | Function whose address escapes into data or registers, so its original entry must stay valid. |
| **Interior pointer** | Pointer into the middle of a function. |
| **CPU dispatch** | Runtime choice between code variants by CPU features (AVX2 etc.). |

## Safety

| Term | Meaning |
| --- | --- |
| **Transformability** | Per-function level the passes must respect: `FullyTransformable`, `RelocatableOnly`, `Frozen` (§5.5). |
| **FullyTransformable** | May be re-laid out freely. |
| **RelocatableOnly** | May be moved as a byte copy but not re-encoded. |
| **Frozen** | Must not be touched. |
| **Safety gate** | `SafetyGatePass`; assigns the level; default on anything unrecognized is downgrade. |
| **Downgrade reason** | Recorded cause of a downgrade (`interior-entry`, `handler-data`, `cxx-eh`, `indirect-branch`, ...). Never raises the level. |
| **Verifier / oracle** | `RewriteVerifier` and its fixup oracle: independent checks that an output is correct; output is written only if they pass. |
| **Re-analysis (check 4)** | Verifier step that analyses the produced output again. |
| **One-value rule** | A function address must have a single value everywhere; why pointer redirection is all-or-nothing per function. |

## Exception handling

| Term | Meaning |
| --- | --- |
| **SEH** | Structured Exception Handling (`__try/__except/__finally`), handled by `__C_specific_handler` and a scope table. |
| **Scope table** | SEH table of protected ranges, handlers and filters. |
| **C++ EH** | C++ exception handling; MSVC handlers `__CxxFrameHandler3` (FH3) and `4` (FH4). |
| **FH3 / FuncInfo** | Older format: uncompressed FuncInfo with IP-to-state map, unwind map, try map. |
| **FH4 / FuncInfo4** | Newer compressed format, keyed to the function entry's begin address. |
| **IP-to-state map** | Maps instruction addresses to EH state; must be regenerated when code is reordered (`Fh3Writer`, `Fh4Writer`). |
| **Funclet** | Out-of-line handler body: unwind action, catch block, `__finally`. |
| **Catch funclet** | Funclet running a catch; cannot be moved (runtime identifies it by its entry). |
| **Catch continuation** | Address in the parent where execution resumes after a catch. |
| **GS handler / `__GSHandlerCheck`** | Buffer-security-check handler; wrappers `_SEH/_EH/_EH4` pair it with an inner handler. |
| **Handler data** | Per-function data after UNWIND_INFO that the language handler reads. |
| **`--layout-eh`** | Option enabling block layout inside C++ EH functions. |

## Profiles and measurement

| Term | Meaning |
| --- | --- |
| **ETW** | Event Tracing for Windows; source of traces (.etl). |
| **LBR** | Last Branch Record: CPU hardware log of recent taken branches (Intel). |
| **Branch records** | LBR entries (from, to), applied to the CFG by `LbrProfileBuilder`. |
| **IP sampling / `--ip-only`** | Profile from instruction-pointer samples only (no LBR); block counts estimated (`IpProfileBuilder`, max or mean estimator). |
| **Profile binding** | Matching a trace to the image (process, timestamp/checksum); mismatch is rejected. |
| **Stale profile (`--profile-binary`)** | A trace of an earlier build carried over to a new one by matching functions (PDB name, else content hash) and blocks (strict, then loose content hash); unmatched counts are dropped (`StaleProfile`, Step 28). |
| **Strict / loose block hash** | Block content without addresses: opcode forms, registers and non-address constants (strict), or mnemonics only (loose). |
| **Execution count** | Per-block (or edge) number of times executed. |
| **`--profile-during`** | Keeps only samples between first and last touching a named function (excludes load phase). |
| **Hot / cold** | Executed vs not (or rarely) executed code. |
| **Footprint** | Pages/cache lines holding the hot code (90% footprint: covering 90% of executed instructions). |
| **L1i, I-TLB** | Instruction cache and instruction TLB; front-end resources the advisor reasons about. |
| **Front-end bound** | CPU stalls waiting for instructions rather than executing them. |
| **DSB (decoded-uop cache)** | Intel's decoded micro-op cache; coverage rises with the padded layouts. |
| **Top-down** | Intel methodology classifying stalls; collected with VTune (`Collect-TopDown.ps1`). |
| **VTune** | Intel profiler used to confirm mechanisms (ETW cannot give top-down metrics or mispredicts). |
| **PGO** | Profile-guided optimization by the compiler (MSVC); the comparison baseline. |
| **LTCG** | Link-time code generation (MSVC whole-program optimization). |
| **Residency** | Where samples land in an output: appended code, trampolines, original bodies, unmoved (`winbolt residency`). |
| **Bench** | `winbolt bench`: interleaved rounds, baseline copy for noise, bootstrap CIs; CPU cycles via QueryProcessCycleTime; page faults via GetProcessMemoryInfo. `--copy-beside` puts the baseline copy next to the baseline. |
| **Page model (`--page-model`)** | Distinct code pages the profiled run touches over time, replayed through a layout's address map (`PageModel`, Step 27); a model, not a measurement. |
| **Variants** | Target builds: `o2`, `guardcf`, `ltcg`, `pgo`, `mt` (/MT), `fh3`, `fh3mt`, `ehcont` (/guard:ehcont /CETCOMPAT). |

## Layout and rewriting

| Term | Meaning |
| --- | --- |
| **No-op rewrite** | Moves code without changing it; the baseline proving the machinery (Milestone 1). |
| **Copy mode** | Function moved as a byte copy (`FunctionRewriter`). |
| **Rebuild (`--rebuild`)** | Function re-encoded from its CFG (`BlockRebuilder`) in original order. |
| **`--blocks`** | Rebuild with block reordering and hot/cold splitting. |
| **Trampoline** | `jmp rel32` left at an original function entry pointing to the moved copy. |
| **Pointer redirection (`--redirect-pointers`)** | Rewriting every pointer to a moved function to its new address so no trampoline is needed (§Step 13). |
| **C3** | Call-Chain Clustering: the function ordering algorithm (`FunctionOrdering`). |
| **First-use order (`--order first-use`)** | Functions in the order the trace first ran them, for startup locality (`FunctionOrdering.FirstUse`, Step 27). |
| **Indirect call promotion (`--promote-calls`)** | An indirect call with one dominant profiled target becomes `cmp` + direct call, keeping the indirect call for other targets (`CallPromotion`, Step 26). |
| **Scratch register** | r11 (or r10) used by a promoted call's compare: volatile and never an argument under the ABI. |
| **Pettis-Hansen** | Greedy chain-building block order; the default (`BlockLayout`). |
| **ExtTSP** | Extended Travelling Salesman block order (`--block-order ext-tsp`); measured slower here. |
| **Chain** | Sequence of blocks placed contiguously. |
| **Hot/cold splitting** | Moving cold blocks after all hot code, one chained UNWIND_INFO per segment. |
| **Segment** | Part of a function covered by one unwind entry; blocks are laid out per segment. |
| **Prologue** | Opening instructions covered by unwind codes; blocks starting inside stay first. |
| **`--align-loops`** | Starts hot loop heads on 32-byte boundaries. |
| **`--layout-shift N`** | Rebuilds the same layout at another alignment, to measure layout noise. |
| **JCC erratum** | Intel Skylake-family bug: jumps crossing or ending on 32-byte boundaries lose DSB coverage. `--jcc-erratum` pads branches off boundaries. |
| **Prefix padding** | Padding with redundant CS/DS/ES/SS prefixes instead of NOPs. |
| **Exposure** | A branch (or fused cmp+jcc) touching a 32-byte boundary. |
| **Place** | `BlockRebuilder` mechanism choosing alignment/padding positions. |
| **AddressMap / Map** | `MovedFunction` mapping from original to new addresses. |
| **Stand-in encoding (`EncodeAt`)** | Workaround for iced linking targets to instruction IPs that collide with old addresses. |
| **Declare byte** | iced `CreateDeclareByte`: keeps an instruction's original bytes during re-encode. |
| **OMAP** | Debug-info address maps (OMAP_TO_SRC / OMAP_FROM_SRC) translating between original and rewritten addresses; written with `SectionHdrOrig`. |
| **Section contribution** | Linker's record of which object contributed which byte range of a section (from the PDB). |
| **Linker fixup** | PDB record of every place the linker resolved a reference (`/DEBUGTYPE:CV,FIXUP`); enables whole-program rewriting and the oracle. |
| **MSF** | Multi-Stream File, the PDB container format. |
| **DBI** | Debug Information stream of a PDB. |
| **Publics** | PDB's public symbol stream. |
| **ILT** | Incremental linking thunk table. |

## Libraries and tools

| Term | Meaning |
| --- | --- |
| **iced** | The x64 decoder/encoder dependency (`BlockEncoder`, `InstructionInfoFactory`). |
| **InstructionStore** | Flat arrays of instructions indexed by int ID (§5.3). |
| **Pass / PassRegistry** | Analysis steps registered by attribute in the main assembly (§7, §11). |
| **IReportProvider** | Attribute-registered report printed by the CLI. |
| **SyntheticImage** | Test helper building artificial PE images. |
| **TraceEvent** | Microsoft ETW library; used only in WinBolt.Profile. |
| **llvm-pdbutil** | LLVM tool for dumping PDBs (in VS `VC\Tools\Llvm\x64\bin`). |
| **dbghelp / cdb** | Windows debug library and debugger used to check output PDBs. |
| **Provenance** | Classification of how an image's layout came about (compiler PGO, post-link rewrite, LTCG...). |
| **Advisor** | Stage 3 static performance advisor (`Advisor`, `AdvisorReport`). |
