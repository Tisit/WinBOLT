# WinBolt – Design Document

**Version:** 0.2
**Language:** C# (.NET)
**Target:** Windows x64 PE executables

---

## Terminology

Two unrelated concepts abbreviate to "CFG" in this problem domain. This document
disambiguates them throughout:

* **CFG** — control flow graph. The IR structure of basic blocks and edges.
* **CFGuard** — Control Flow Guard, the Windows exploit mitigation that records valid
  indirect-call targets in the load config directory. See §5.4.

---

# 1. Vision

WinBolt is a post-link optimizer for Windows native executables inspired by LLVM BOLT.

Unlike compiler optimizers, WinBolt operates directly on an already linked PE executable using runtime profile information.

Primary goals:

* Improve performance of existing native executables.
* Require no source code.
* Require no recompilation.
* Be modular enough for experimentation with new optimization techniques.
* Provide high confidence that rewritten binaries preserve behavior.

WinBolt intentionally does **not** attempt to replace Windows Performance Analyzer (WPA) or traditional profilers.

Instead it answers questions such as:

* Can this binary be laid out better?
* Which optimizations are possible because of observed runtime behavior?
* Can compatibility overhead be removed for a specific deployment target?
* Can binary-level analysis produce actionable recommendations for developers?

## 1.1 Relationship to compiler PGO

MSVC already offers profile-guided optimization (`/GENPROFILE`, `/USEPROFILE`,
`/LTCG:PGO`) and the linker already supports explicit function ordering (`/ORDER`).
Where source and a working build are available, those tools are the correct choice and
WinBolt does not compete with them.

WinBolt targets the case they cannot serve: a binary that is already linked, whose source
is unavailable, unbuildable, or too expensive to re-instrument and rebuild. Third-party
components, shipped binaries under investigation, and stripped release artifacts all fall
into this category.

A secondary difference: compiler PGO must decide layout before it knows the final image,
while a post-link optimizer sees the real, complete binary. That is worth something even
when source exists, but it is not the primary justification.

---

# 2. Scope and Non-goals

## 2.1 Release mapping

The roadmap in §8 has eight stages. They map to releases as follows:

| Release | Stages  | Capability                                     |
| ------- | ------- | ---------------------------------------------- |
| 0.x     | 1–2     | Analysis and profiling, no output binary       |
| 1.0     | 3       | Static performance advisor, reports only       |
| 2.0     | 4–5     | Function-granularity rewriting and layout      |
| 3.0     | 6       | Basic block reordering                         |
| research| 7–8     | Specialization and experimental passes         |

"Version 1" below refers to release 1.0.

## 2.2 Non-goals

Release 1.0 explicitly does **not** aim to support:

* automatic vectorization
* source decompilation
* compiler replacement
* arbitrary algorithm recovery
* managed JIT optimization
* ARM64
* x86 (32-bit)
* binary obfuscation removal

These remain research topics.

---

# 3. Guiding Principles

## 3.1 Correctness before performance

A correct binary with no improvement is preferable to a faster binary that is incorrect.

Every optimization pass must preserve semantics.

---

## 3.2 Native binaries only

Initial support:

* PE32+
* x64

Possible future:

* ARM64
* NativeAOT
* ReadyToRun

Only x64 is implemented, but the instruction and register abstractions are defined behind
an architecture interface from Stage 1. Windows on ARM is a real target and ARM64 appears
in §14; retrofitting an architecture boundary through a codebase that assumed x64
everywhere is far more expensive than maintaining a thin interface that currently has one
implementation. The cost is a handful of interfaces, not an abstraction layer with runtime
overhead.

---

## 3.3 Minimal dependencies

Preferred libraries:

* **iced** — x64 decoding and encoding. Its `BlockEncoder` performs branch resizing and
  displacement fixups when code is relocated, which removes most of the mechanical
  difficulty from Stage 6. Its `Instruction` is a value type, which matters for §5.3.
* **System.IO.Pipelines** (optional) — bulk I/O.

Avoid depending on LLVM.

* **Microsoft.Diagnostics.Tracing.TraceEvent** (`WinBolt.Profile` only) — reads ETW `.etl`
  traces for Stage 2. The ETL container and kernel event formats are large and only partly
  documented. Reading them by hand would cost more than the rest of the profile reader,
  and a Microsoft-maintained reader is the reference implementation. It is isolated in one
  project, so analysis and rewriting never depend on it.

### PE parsing

`System.Reflection.Metadata` is **not** a suitable dependency for this project. It exists
to read *managed* assembly metadata. The type that looks relevant,
`System.Reflection.PortableExecutable.PEReader`, ships inside it but is oriented toward
managed images: it exposes headers and section tables, and does not expose the load config
directory, `.pdata` / `.xdata`, the CFGuard tables, or the base relocation table — all of
which §5.4 shows are load-bearing for this project.

WinBolt therefore implements its own PE32+ reader. `PEReader` may be used for header
cross-checking in tests, not as the production path.

### PDB reading

Symbol reading is a Stage 1 dependency, not a future one. Symbols improve function
discovery and every report produced from Stage 3 onward is unreadable without them.
WinBolt must degrade cleanly to symbol-free operation, since stripped binaries are an
explicit target, but it should exploit a PDB when one is available.

**Addresses in a PDB are not always addresses in the image.** When an image has already
been through a post-link rewriter — Microsoft's BBT/Vulcan, which ships Visual Studio and
SQL Server among others — the linker's original layout survives in the PDB and the image
does not match it. The rewriter records the mapping instead of regenerating symbols: two
OMAP tables (`OMAP_FROM_SRC`, original → new; `OMAP_TO_SRC`, new → original) and the
pre-rewrite section table (`SectionHdrOrig`), all reachable from the DBI optional debug
header. Public symbols and section contributions keep the *original* section numbering
and offsets.

`dbghelp` applies this translation silently, which is why it is easy to forget. A
hand-written reader does not, and the failure is silent: symbol-assisted function
discovery would name the wrong code, with no error anywhere. Requirements:

* Resolve every symbol address against `SectionHdrOrig` (not `SectionHdr`) when that
  stream exists, then map it through `OMAP_FROM_SRC`. An address that maps to `0`, or into
  a range whose OMAP entry has `rvaTo = 0`, has no counterpart in the image and must be
  dropped, not guessed.
* An OMAP block is roughly one basic block (median 9–11 bytes on the binaries measured).
  A symbol's *start* maps cleanly; its *extent* does not. The size of a function must come
  from `.pdata` and disassembly of the final image, never from symbol size.
* Layout provenance (Stage 1) reports whether OMAP is present, so the report states which
  path symbol addresses took.

**Implemented** (`WinBolt.Pdb`). A PDB is used only if its GUID and age match the image's
RSDS record. It is found next to the binary, at the RSDS path, in `--symbols` directories
(flat or symbol-store layout), or in the local directories of `_NT_SYMBOL_PATH`. Nothing
is downloaded. Public symbols are translated as above, and addresses with no counterpart
are dropped (586 of 13,423 in `sqlncli11.dll`). Function symbols are strong discovery
evidence and name functions after export names.

Measured: every function symbol lands exactly on a discovered function entry, in
`ntdll.dll`, `kernel32.dll`, `ActivationManager.dll`, `AADAuthHelper.dll` and the
OMAP-translated `sqlncli11.dll` (4,529 of 4,529). The same symbols at their untranslated
addresses mostly miss, which is the silent failure described above. Symbol-free discovery
missed at most 2 functions per binary, so on these binaries a PDB adds names, not
coverage.

PDB *writing* remains a future concern (§14).

---

## 3.4 Modular architecture

Every optimization is a plug-in.

The framework should encourage experimentation.

---

# 4. High-level Architecture

```text
                    +----------------+
                    |   ETW/Profile  |
                    +-------+--------+
                            |
                            |
+--------+          +--------v---------+
|  PE    |--------->| Binary Model     |
| Reader |          | (IR)             |
+--------+          +--------+---------+
                            |
                +-----------+-----------+
                |                       |
        +-------v------+       +--------v--------+
        | Analysis     |       | Optimization    |
        | Passes       |       | Passes          |
        +-------+------+       +--------+--------+
                |                        |
                +-----------+------------+
                            |
                     +------v------+
                     | Binary      |
                     | Writer      |
                     +-------------+
```

---

# 5. Internal Representation

Everything operates on a common IR.

```text
Binary

 ├── Sections

 ├── Functions

 │      ├── Ranges          (one or more; see 5.1)

 │      ├── BasicBlocks

 │      │      └── Instructions

 │      ├── JumpTables      (see 5.2)

 │      ├── SafetyStatus    (see 5.5)

 │      └── Profile

 ├── Relocations

 ├── ExceptionData

 ├── LoadConfig            (see 5.4)

 └── Metadata
```

Core types:

```
BinaryImage
Section
Function
FunctionRange
BasicBlock
Instruction
Edge
JumpTable
Relocation
ProfileInfo
ExceptionInfo
LoadConfigTables
SafetyStatus
```

No optimization should manipulate raw bytes directly.

---

## 5.1 Functions are not contiguous

A `Function` owns a **list** of `FunctionRange`, not a single start/end pair.

Two mechanisms make discontiguous functions the normal case rather than an edge case:

* `UNW_FLAG_CHAININFO` allows one logical function to be described by several
  `RUNTIME_FUNCTION` entries with chained unwind information.
* MSVC's own PGO and basic-block transformation already perform hot/cold splitting. Any
  binary built with `/LTCG:PGO` — precisely the kind of optimized input this project
  cares about — arrives with functions already split into separated ranges.

Designing for a single range and retrofitting multi-range support later would touch every
pass. The IR carries the list from the start.

Measured scale, which rules out treating the list as "usually one or two":

* Compiler PGO (`ntdll.dll` and the other core System32 DLLs) places cold fragments more
  than 64 KB from their primary entry.
* Post-link-rewritten Microsoft binaries are split at basic-block granularity. In SQL
  Server's `sqlmin.dll`, single functions are cut into hundreds of ranges (up to 797)
  spread over 15–25 MB, and the first 10% of `.text` is mostly pieces of split functions,
  a packed hot region.

**Chained does not mean split.** A chained entry next to its parent is ordinary: the
statically linked C runtime alone contributes about 200 such entries (partial-prolog
chains, not moved cold code), and they stay adjacent to their parent even in a large
image. Only *distance* from the parent indicates hot/cold separation. Reports and passes
must not treat chain count as a measure of splitting.

**A chain may be invalid.** Some shipped images carry chained entries whose parent RVA is
not the `BeginAddress` of any `RUNTIME_FUNCTION`: damaged, deliberately scrambled, or
produced by a tool WinBolt does not know (all 18 far-looking fragments in one scanned game
executable were of this kind). Such an entry is not attached to any `Function`. It is
unattributed code, handled under §5.5.

Consequences: "reorder functions" in Stage 4 means relocating a *set* of ranges. The unit
of movement is the **range**, not the function. The separation between a function's ranges
is deliberate (it is the output of the hot/cold decision that produced them), so it is
not an invariant to preserve. What must be preserved is each range's internal layout and
the hot/cold assignment of each range. The entry range must remain identifiable, and every
moved chained range's unwind info must still name its parent's (possibly new)
`BeginAddress` (§5.4).

---

## 5.2 Code addresses in data

Arrays of code addresses stored in data sections are the central analysis problem of this
project. Switch jump tables are the best-known instance but not the only one, and solving
switch tables alone would leave the CFG unsound.

If a table of code addresses is not recovered:

* the CFG is unsound — real successors appear as an unresolved indirect branch;
* the table contents are indistinguishable from ordinary read-only data, so nothing
  updates them when code moves;
* Stage 6 block reordering will silently produce a binary that jumps into the middle of
  unrelated code.

This is the most common source of miscorrection in binary rewriters and it is not
optional work. Recovery is a Stage 1 deliverable (§Stage 1) and its failure mode feeds
directly into the safety gate (§5.5): a function containing an indirect branch whose
targets could not be enumerated is not transformable.

### Switch jump tables

Every optimizing compiler emits jump tables for dense `switch` — this is not an MSVC
characteristic. What varies by toolchain is the **entry encoding**, and each encoding
needs its own recognition pattern and its own fixup logic when code moves:

| Toolchain              | Typical x64 entry encoding                | Carries relocations |
| ---------------------- | ----------------------------------------- | ------------------- |
| MSVC (PE)              | 4-byte offset relative to `__ImageBase`   | **No**              |
| GCC / Clang, ELF PIC   | 4-byte offset relative to the table       | No                  |
| GCC / Clang, non-PIC   | 8-byte absolute pointer                   | Yes                 |
| Delphi                 | absolute addresses                        | Yes                 |

The MSVC form materializes the image base into a register and adds it to the loaded
offset — roughly `lea r9, __ImageBase` / `mov eax, [r9+rax*4+table]` / `add rax, r9` /
`jmp rax`. MSVC additionally uses a two-level form, a byte-sized index table feeding the
dword table, where many cases share a target. That is a separate pattern, not a variant
of the first.

**The relocation column drives the difficulty.** Absolute-pointer tables are the easy
case: `.reloc` enumerates every one of those pointers, so relocation-walking finds them
without any pattern matching. Image-relative tables carry no relocations at all — which is
exactly why MSVC chose that encoding for PE — and are therefore invisible to the cheapest
discovery method available. The encoding this project will meet most often is the one that
requires the most work to find.

Toolchain provenance is not always knowable, and a single image can mix conventions
through static libraries. Recovery must be pattern-driven rather than
compiler-identity-driven.

**Implemented (MSVC forms).** The recognizer walks backward from `jmp reg` and discharges
requirements rather than matching a fixed sequence:
- every base register is proven to hold `__ImageBase` by its nearest earlier write;
- the index is bounded by an unsigned compare: `ja`/`jae` falling through, or `jbe`/`jb`
  taken. The walk follows copies, in-place sign extension, and `lea idx,[x+c]` when the
  compare is on the same `x+c`;
- a compare on an 8- or 16-bit register (`cmp cl,N`) also needs the upper bits proven zero
  (`movzx`, or `and` with a small mask);
- a call between a volatile register's definition and its use voids the proof.

**Every path (Sep 2026).** The walk runs over all CFG predecessors, not just the
fall-through path:
- **Edges:** fall-through, taken edges of direct branches, and edges from recovered tables'
  dispatch jumps into their case blocks.
- **Forks and loops:** paths fork at joins, and each must discharge every requirement. A
  path that returns to a state it has already visited is dropped. That is sound for these
  "must" requirements: it went around a loop that writes nothing the proof needs, so the
  other paths decide.
- **Unknown entries:** reaching one with requirements open fails the proof. Unknown entries
  are function entries, exception and code-pointer roots, and targets of tables no longer
  recovered.
- **Several bounds:** paths may bound the index differently, and the table extent is the
  largest bound.

Case blocks reached only through a table can branch back into its dispatch sequence, so the
first proof is optimistic. The builder re-proves every table after each exploration round,
on the graph as it stands. A proof that later fails refutes the table for good, which keeps
the loop monotone. The loop ends when a round changes nothing, so every accepted table is
proven on the final graph.

This replaced the earlier fall-through-only proof, which rejected a table whenever a
branch target lay inside the matched sequence. On speedtest1, recovered tables went from 29
to 43, frozen functions from 22 to 11, and the no-op rewrite moved 99.6% of code (was
96.7%). The fixup oracle independently confirms the table extents: an under-counted table
would leave linker fixups for its missed entries pointing into the function.

Every table target must lie inside the function. Recovered tables become data barriers: MSVC can place a table inside a function's range
right after a call to a noreturn function, and decoding must stop there instead of reading
the table as code.

**Indirect jumps that are not switches.** A `jmp` through a register or memory that no
table explains is often a tail call: a vtable call after the epilogue, or a dispatch
thunk. It is classified as a tail call only when it provably cannot land inside its own
function. That holds when no address inside the function exists as a value anywhere: no
`lea` into it (§5.4), no relocated pointer into it, and no `__ImageBase` materialized in it
(the prerequisite of an image-relative table). Otherwise the function is frozen.

### Other code-address tables

The same recovery and fixup burden applies to:

* C++ vtables — absolute pointers, relocated
* IAT and delay-load descriptors
* `.CRT$XC*` static initializer arrays
* the TLS callback array
* C++20 coroutine resume/destroy function pointer pairs
* x64 exception funclet addresses, stored as image-relative RVAs in `.xdata` scope tables
* computed `goto` (`&&label`, a GCC/Clang extension)

Computed `goto` is the hardest of these and deserves explicit mention: its targets are
*inside* a function rather than function entries, so unlike the others it breaks block
reordering specifically rather than function relocation. A function containing one is
`RelocatableOnly` at best.

Recovery is pattern-based and therefore incomplete by nature. The design requirement is
not that recovery always succeeds — it is that failure is always *detected* and always
downgrades the function rather than proceeding on an incomplete CFG.

---

## 5.3 Instruction storage

`Instruction` is listed above as a core type but must **not** be a class with one managed
object per decoded instruction.

A 100 MB image holds on the order of 10⁷–10⁸ instructions. One object each — with header,
references, and allocation — puts the working set into the gigabytes and makes GC
dominate analysis time. This is the difference between a tool that analyses a large binary
in seconds and one that does not finish.

Design:

* instruction-level data is held in flat arrays, indexed by an integer instruction ID;
* `BasicBlock` stores an index range into those arrays, not a list of objects;
* iced's `Instruction` value type is used directly as the storage element where possible;
* classes are reserved for `Function` and `BasicBlock`, which number in the 10⁴–10⁵ range
  and are cheap.

Passes see an accessor API, not raw arrays, so the layout can change without touching
pass code.

---

## 5.4 PE structures that constrain code motion

Moving code in a Windows x64 image is not simply a matter of writing bytes at a different
offset. Several structures hold addresses or maintain invariants tied to code placement,
and every one of them must be updated in the same transaction as the move. Missing any of
them produces a binary that loads and often *mostly* runs — failing only on the path that
touches the stale structure, which is the worst possible failure mode.

**Exception data (`.pdata` / `.xdata`).** The exception directory must remain **sorted in
ascending order of `BeginAddress`**; `RtlLookupFunctionEntry` binary-searches it at
runtime. Reordering functions therefore requires re-sorting `.pdata`, not merely
rewriting the RVAs in place. `.xdata` unwind information must follow its function, and
chained entries (§5.1) must keep pointing at the right parent.

**Load config / CFGuard tables.** Where the image is built with Control Flow Guard, the
load config directory carries RVA tables that the loader consumes:

* `GuardCFFunctionTable` — every valid indirect-call target
* `GuardAddressTakenIatEntryTable`
* `GuardLongJumpTargetTable`
* `GuardEHContinuationTable` — present with `/guard:ehcont`
* XFG type hashes, where extended Flow Guard is in use

These are sorted RVA tables. If a moved function's entry is not updated, indirect calls to
it fail the guard check and the process is terminated. There is no partial-correctness
mode here.

*CFGuard is also an analysis asset, not only an obligation.* On a `/guard:cf` image,
`GuardCFFunctionTable` enumerates every address-taken function the compiler knew about —
authoritative ground truth for a question that is otherwise pure heuristics. It bounds the
indirect-call target set for §5.2, informs the safety gate in §5.5, and identifies exactly
the functions that need identity-preserving treatment under §6.1. Where the tables are
present, analysis should prefer them over inference; where they are absent, that absence is
itself worth reporting as a confidence reduction.

*But the table is not complete, even when `/guard:cf` is on.* The linker lists address-taken
functions only from objects compiled with `/guard:cf`, so a static library built without it
contributes none. On `nvcuvid.dll` (CFG enabled), 89 functions whose address is loaded by
`lea [rip+X]` in reachable code are missing from `GuardCFFunctionTable`. On the Microsoft
binaries measured, the table missed at most one. Code pointers are therefore always tracked
as well (`lea [rip+X]` into code, which x64 uses to take a function's address without any
relocation). The table is a floor, not the whole answer. Without CFG, code pointers are the
main evidence: on `sqlncli11.dll` they reveal 129 address-taken functions nothing else
does.

**Base relocations (`.reloc`).** Every relocation whose target moved needs its RVA
updated, and relocations *pointing into* moved code need their site RVAs updated.

**Other address-bearing structures.** TLS callback array, delay-load descriptors, debug
directory, resource directory, IAT, and the entry point itself.

**PE checksum.** Must be recomputed. Required for drivers and for some loader paths.

**Authenticode.** Any rewrite invalidates the signature. This is unavoidable and not a
defect. Consumers of WinBolt output must be prepared to re-sign, and the tool should warn
plainly when it strips a signature rather than emitting a silently unverifiable binary.

A single component owns this list. Passes never touch these structures directly; they
declare code movement and the writer reconciles all dependent structures. A validation
pass re-derives every table from the final image and compares (§9).

---

## 5.5 The safety gate

§3.1 asserts correctness before performance. That principle needs a mechanism, or it is
only an intention.

Every `Function` carries a `SafetyStatus` computed during analysis:

```
enum Transformability
    FullyTransformable      // blocks may be reordered and rewritten
    RelocatableOnly         // may be moved as a unit; contents frozen
    Frozen                  // must remain byte-identical at its original address
```

A function is downgraded — never silently, always with a recorded machine-readable
reason — when analysis meets something it cannot model:

* an indirect branch whose targets could not be resolved (§5.2)
* data embedded in the code stream that could not be classified
* a `RUNTIME_FUNCTION` range that disassembly could not fully cover
* recognizable hand-written assembly, `setjmp`/`longjmp`, or SEH patterns outside the
  modelled set
* address-taken in a way the analysis cannot enumerate
* a computed `goto` or other table-driven jump to an interior block (§5.2) — downgrades to
  `RelocatableOnly`, since the function may still move as a unit
* an address-taken function whose entry-trampoline byte range cannot be shown free of
  incoming jumps (§6.1)
* a chained `RUNTIME_FUNCTION` whose parent is not a `.pdata` entry, or whose chain
  cannot be followed (§5.1). The fragment is not attributed to any function. It is
  reported as unattributed code and is never moved. Any function that branches into it
  is `Frozen`, because the fragment's unwind behaviour cannot be modelled from its
  chain. Resolving the chain to "no parent" and carrying on as if the entry were
  unchained would build a wrong unwind model silently.

Downgrade reasons are reported. A binary where most functions end up `Frozen` is telling
the user something useful about either the binary or WinBolt's coverage, and that signal
should be visible rather than buried.

The default on any unrecognized construct is downgrade, not proceed.

---

# 6. Pipeline

```
Read PE

↓

Disassemble

↓

Recover CFG

↓

Load runtime profile

↓

Analysis

↓

Optimization

↓

Validation

↓

Emit new PE
```

---

## 6.1 Rewriting strategy

Two strategies are available for producing the output image, and the choice shapes the
entire risk profile of Stages 4–6.

**In-place rewriting.** Optimized code replaces the original bytes. Produces a
same-size-ish image with no dead weight. Requires that *every* reference to a moved
address has been discovered — one missed reference is a wrong-code bug, and the analysis
that guarantees complete reference discovery on stripped optimized binaries does not
exist.

**Append a new section.** Optimized code is emitted into a new executable section at the
end of the image. Original code is left in place, untouched. Entry points are redirected.
Any reference the analysis failed to discover still resolves to the original, valid,
correct code — it merely fails to benefit from the optimization.

**WinBolt uses the append-a-new-section strategy.**

### Why — and what the claim actually is

The argument is *not* that appending is safe. It is that appending requires a much smaller
thing to be true.

In-place relocation requires proving a negative: that **no** undiscovered reference to any
moved address exists anywhere in the image. On a stripped, optimized binary with computed
addresses and pattern-recovered jump tables (§5.2), that is not provable. It can only be
approximated, and the approximation reports its failures as crashes in the field rather
than as diagnostics at build time.

Appending requires only that the functions actually copied were transformed correctly and
that the installed redirects point where intended. Undiscovered references stop being a
correctness input and become a performance input.

That is the whole case: it shrinks the trusted computing base of the analysis. It does not
make anything inherently safe.

### What appending breaks that in-place does not

Appending is not strictly safer — it is *differently* unsafe, and the failure modes it
introduces must be designed for rather than discovered:

* **Function pointer identity.** Two addresses now exist for one function. If a callback
  is registered through a redirected site (yielding the new copy) and later compared
  through a non-redirected path (yielding the original), the comparison fails where it
  previously succeeded. Callback deregistration, vtable identity checks, and member
  function pointer comparison all depend on this holding. In-place rewriting has exactly
  one address and cannot produce this bug.
* **Widened CFGuard target set.** The new copy must be added to `GuardCFFunctionTable` to
  be indirect-callable. Leaving the original entry in place enlarges the set of valid
  indirect-call targets — a small but real mitigation regression that in-place rewriting
  does not incur.
* **Dual residency.** A hot indirect call that keeps reaching the original copy does not
  yield a neutral "missed optimization": both copies are now live in the instruction cache,
  increasing the footprint this project exists to reduce. Partial redirect is mildly
  negative, not zero. (As built, with entry trampolines below, what stays resident is the
  trampoline's line and page plus one extra jump, not the whole body: 0.2% on speedtest1
  (Step 11), 5% on Factorio before pointer redirection (Step 13). Code that still runs an
  original body is measured by `winbolt residency`, Step 23.)

The decisive property is not that these are small. It is that they are **enumerable and
testable**, whereas in-place's failure mode — a reference somewhere that was not found —
is not enumerable even in principle.

### Entry trampolines for address-taken functions

Pointer identity is resolved by not duplicating address-taken functions at all.

For any function whose address is observably taken — CFGuard's table where present, plus
exports, relocation targets and `lea [rip+X]` code pointers (§5.4) — write an entry trampoline at the original
address forwarding to the optimized copy, rather than leaving a full second body. The
original address remains the one true value of `&F`, so identity comparisons behave
exactly as before, and indirect calls reach optimized code at the cost of one jump.

This reintroduces a discovery obligation: nothing may jump into the function within the
bytes the trampoline overwrites. That obligation is real, but it is scoped to a few bytes
at a known function entry rather than to every reference in the image — a far smaller
thing to establish, and one where failure to establish it downgrades the function under
§5.5 rather than proceeding.

Functions that are not address-taken are copied without a trampoline.

### Other consequences

* Original code becomes cold. It should be placed so it does not consume I-cache or
  I-TLB capacity — the point of the exercise is front-end pressure, and leaving a dead
  copy interleaved with hot code would be self-defeating.
* `.pdata` must describe the new locations, and the original ranges must either be
  removed from the exception directory or kept consistent — this needs a decision per
  transformation, recorded in Stage 4.
* Image size growth is a reportable metric, and a configurable budget (§R6).

BOLT uses this strategy, which is the strongest empirical evidence available: it is the
most heavily exercised tool in this category, and the one that would most obviously have
adopted in-place relocation had that proved tractable.

`Frozen` functions (§5.5) are simply never copied to the new section.

That holds for BOLT *without* relocations. Given linker-emitted relocations
(`--emit-relocs`), BOLT rewrites the whole `.text` instead, and recommends that mode. §6.2
is the same split for WinBolt: appending stays the default, and whole-program rewriting is
allowed only when the linker's fixup records make the reference list complete.

## 6.2 Whole-program rewriting when fixups exist (design, Sep 2026)

§6.1 rejects in-place rewriting because nobody can prove that disassembly found every
reference. That objection disappears when the linker supplies the list. With
`/DEBUGTYPE:CV,FIXUP` the PDB holds a record for every reference the linker resolved:
absolute, image-relative and RIP-relative, in code and in data. Microsoft's BBT relays
Windows binaries out in place for exactly this reason. It is a relinker working from the
linker's records, not a disassembler guessing at them. This section adds that mode behind a
gate. It does not change the default: a binary without fixup records is rewritten by
appending, as before, and that covers nearly every third-party binary (Factorio's PDB has
public symbols and no fixups).

**What it buys** (Step 11 measured the trampoline part):
- no trampolines, and no duplicate code: one address per function, so the pointer-identity
  hazard of §6.1 and pointer redirection (Step 13) are both unnecessary;
- no size growth beyond padding and inserted jumps (the no-op append doubles the file:
  zopfli 77 KB → 133 KB, speedtest1 1.2 MB → 2.3 MB);
- no widened CFGuard target set: the function table is regenerated, not extended (§R7);
- a layout over *all* code: cold functions pack after hot ones instead of staying scattered
  through the original `.text`.

Expected speed gain over append with redirection is small (trampolines cost ~0.2% on
speedtest1, Step 11). This mode is about size, one copy per function, and a clean result,
more than speed.

### Where references come from

In a linked image, a reference to another address is one of the following:
1. **Resolved by the linker.** It has a fixup record: type 1 (ADDR64), 3 (ADDR32NB) or
   4–9 (REL32 to REL32_5), with site and target RVA (`PdbFile.Fixups`). This covers calls
   and jumps between functions, RIP-relative data and code operands, vtables and other
   pointer tables, jump table entries, `.pdata`, UNWIND_INFO handler RVAs, SEH scope tables
   and C++ EH tables (all relocated in the object file).
2. **Resolved by the compiler inside one section contribution.** It has no relocation and
   no fixup: branches within a function, and the offsets inside FH4's compressed
   IP-to-state map, which are relative to the function start. Moving the contribution as a
   unit keeps them correct without looking at them. Reordering *inside* it needs the CFG,
   which is what `BlockRebuilder` already does.
3. **Synthesized by the linker without an object relocation.** Entry point, export table,
   `GuardCFFunctionTable` and the other load-config tables, import and delay-load thunks,
   and incremental-link thunks (ILT). These are PE structures (§5.4): WinBolt parses each of
   them and regenerates it from the address map.

The DBI **section contribution** substream records where each contribution (one COMDAT per
function under `/Gy`, which LTCG always uses) begins and ends. WinBolt does not read it yet.
It gives the unit that can move without disassembly: whatever a linker may place with
`/ORDER`, WinBolt may place too.

Measured on the no-op append rewrites: every cross-range field the copier fixed has a
fixup record (zopfli 1,997 fixups, speedtest1 42,328, zopflipng 5,435; the oracle reports
no fixed field without one). That is necessary for this mode, not sufficient: the gate
below also checks the opposite direction.

### The gate

Whole-program mode runs only if all of these hold. Otherwise `rewrite --whole-program`
refuses with the failing check and suggests the default append mode. It never falls back
silently: the user asked for one output shape and would get another.
1. **Records present.** A PDB matching the image's RSDS GUID and age, with a non-empty
   fixup stream and a section contribution substream. No OMAP in the PDB: an image that was
   already rewritten post-link is refused.
2. **No incremental linking.** An image with an ILT (a `jmp` thunk table at the start of
   `.text`, `/INCREMENTAL`) is refused. Its thunks carry no object fixups.
3. **Relocations agree.** Every DIR64 base relocation has a type-1 fixup at the same RVA,
   and, in a DYNAMIC_BASE image, every type-1 fixup has a relocation. Fixup types other than
   1, 3 and 4–9 may appear only in sections the loader does not map (debug), and never
   target code.
4. **Contributions tile the code.** Every executable byte lies in exactly one contribution
   or is padding (§5.1's unclaimed-code classes). Every fixup that targets code lands in a
   contribution.
5. **Decoding agrees with the records, both ways.** Every reference the analysis found that
   leaves its contribution — a direct branch, a RIP-relative operand, a recovered jump table
   entry, an exception-table address, a relocated pointer to code — has a fixup with the
   same target. And every fixup whose site is inside decoded code sits inside a decoded
   instruction's operand field. One disagreement refuses the image: either the analysis or
   the records are wrong, and in-place rewriting cannot tolerate either.
6. **Every structure that holds code addresses is understood.** The PE structures of point
   3 above, `.pdata`, UNWIND_INFO (including chains), and the language handler data of every
   function whose *blocks* move (§5.5 levels still apply). A function whose handler data is
   not understood still moves as a whole contribution, since its tables are
   function-relative or fixed up. It is not reordered.

The gate replaces reference *discovery* with reference *checking*, which is the step §6.1
said was missing. Checks 3 and 5 are the ones the no-op append rewrites already partly
pass; check 5's second direction and check 4 are new.

### Units and layout

- A contribution **moves as a unit** whenever its function is not reordered: byte copy, then
  every fixup whose site is in it is re-resolved through the address map. This needs no
  disassembly, so Frozen functions (§5.5) move too, exactly as a linker would move them.
  Frozen means "do not reorder its blocks", not "do not move".
- A `FullyTransformable` function with a profile is **rebuilt** in the chosen block order
  (`BlockRebuilder`, Stage 6 steps 1–6): hot part with the other hot code, cold part after
  all hot code. FH4 functions reorder through `Fh4Writer` (Step 14), SEH functions only
  where the scope table can be regenerated.
- **Order:** hot functions in C3 order (Stage 5), their hot blocks with JCC erratum padding
  and loop alignment where asked; then cold parts; then every function with no samples in
  its original relative order. Alignment of each contribution is at least its original
  alignment modulo 16 (MSVC aligns functions to 16).
- **Where the code goes.** Non-code sections keep their RVAs: moving data would require
  the same completeness proof for data references, for no front-end gain. The new code fills
  the original `.text` from its start. If it no longer fits (padding and inserted jumps
  grow it), the coldest tail spills into an appended executable section. A `.text` that
  shrinks keeps its virtual size, with the tail filled with int3.

### What gets rewritten

With one address map (original RVA → new RVA, per instruction for rebuilt functions, per
contribution offset otherwise):
- every fixup site in code and data, including sites that themselves moved;
- `.pdata`, regenerated and sorted, and UNWIND_INFO chains re-pointed; handler data for
  reordered functions regenerated (FH4 IP-to-state, SEH scope ranges);
- base relocations: sites in code move, others stay;
- entry point, exports (forwarders untouched), TLS callbacks (fixed up already, via the
  callback array), load config: `GuardCFFunctionTable` rebuilt and sorted with each entry's
  flag byte kept, `GuardLongJumpTargetTable` and `GuardEHContinuationTable` mapped. An XFG
  hash in front of an entry moves with it;
- the debug directory: see below.

Instruction bytes that hold no reference are never changed outside rebuilt functions.

### Debugging information

The old PDB describes the old layout. A debugger or crash reporter that loads it for the
new image would name the wrong functions, which is worse than no symbols. Until WinBolt can
write OMAP (`OMAP_TO_SRC` / `OMAP_FROM_SRC` + `SectionHdrOrig`, exactly what BBT emits and
what §3.3's reader already consumes), the output's RSDS record gets a new GUID, so the old
PDB is rejected rather than misapplied, and the report says so. OMAP writing is the second
milestone of this mode, not an afterthought: without it, the output cannot be debugged or
symbolized from crash dumps.

### Verification

The append verifier's checks carry over, with the oracle promoted from a cross-check to
the specification:
1. **Every fixup**, resolved in the input to target T, must resolve in the output, at its
   mapped site, to map(T), or to T when T is data. With the gate passed, this is the
   complete list of linker-resolved references.
2. **Every compiler-resolved reference** in a rebuilt function (branches, IP-to-state) is
   checked block by block, as in rebuild mode.
3. **Byte identity** of each moved contribution outside its fixup fields.
4. **Structures:** `.pdata` covers exactly the new ranges and parses; CFG, exports and entry
   map; relocations are exactly the moved set.
5. **Re-analysis** of the output finds every function at its new address, the same function
   count, and no reference to an old address of moved code. Unlike in append mode, the old
   addresses hold other code now, so a stale reference is a wrong jump, not a slow path.
6. **Runtime:** zopfli, speedtest1 and zopflipng outputs, and unwindtest / cxxehtest in o2
   and `/MT` builds (unwinding and C++ EH through moved and reordered frames).
7. **Negative controls:** deleting one fixup record from the PDB must make the gate refuse
   (check 5), and a tampered field must fail check 1.

### Milestones

- **W1: gate and census.** Read section contributions; `winbolt analyze` reports the gate
  checks and the verdict. Targets: every build of our three targets and the test programs
  pass; Factorio is refused (no fixups); a PDB with one record removed is refused.
- **W2: whole-program function order.** Every contribution moves as a unit into C3 order
  (the equivalent of the linker's `/ORDER`), all references from the address map. The
  natural oracle: link the same target with `/ORDER` from the same C3 list and compare
  layouts and timing.
- **W3: block layout.** Rebuilt hot/cold functions with padding, as in append mode's best
  command, across the whole image. Compare with append mode on the three targets for time
  and size.
- **W4: OMAP.** Write a PDB with the OMAP streams (§14 PDB rewriting), and check it with
  WinBolt's own reader and `dbghelp`.

Not planned: rewriting data sections, and whole-program mode without fixups (§6.1 still
holds there).

### W1 results (Sep 2026)

`WholeProgramGate.Check` (WinBolt.Rewrite) implements checks 1–6. `winbolt analyze` prints the
verdict and each check. `PdbFile` reads the section contribution substream (Ver60 and V2 entries),
and `PdbSymbolLoader` maps it to `BinaryImage.SectionContributions` (not when OMAP is present).
Implementation notes:
- Check 5 skips instructions of functions whose decode ran into non-code (`undecodable`,
  `falls-into-data`). That code counts as undecoded, and such functions move only as
  contributions.
- Check 6 covers every `.pdata` field and every handler RVA. Linker-synthesized structures
  (exports, load config) are regenerated in W2, not checked here.

**Every build of every target passes**: zopfli, speedtest1 and zopflipng in o2, guardcf, ltcg and
pgo, plus cxxehtest and unwindtest in o2 and `/MT`. On speedtest1 o2 the gate reports:
- 42,328 fixups and 1,957 code contributions, with 13,736 gap bytes, all padding;
- 1,594 relocations, each with its type-1 fixup;
- 22,630 references that leave their contribution, each with a fixup;
- 22,300 fixups in decoded code, each on an operand field, and none in undecoded code;
- 11,084 `.pdata` and handler fields, each fixed up.

Factorio is refused at check 1 (no fixup records).

The first run failed check 5 on every target, at the same CRT function: `__GSHandlerCheckCommon`.
Its switch table was unrecovered, so its bytes had been decoded as code. The gate had found a real
analysis gap, not a gate bug. Recovery now handles its form:
- an equality bound (`cmp cl,N; jne` not taken, or `je` taken, means index == N);
- an index zero-extended *after* the compare (`movzx eax,al`: the compared low bits are the
  whole index, so no upper-bits proof is needed);
- a byte-table load that encodes `__ImageBase` as the index register (`[rax+rbp+table]`): with
  scale 1, the base is whichever register the dword load already needs.

Tests (`WholeProgramGateTests`) cover:
- the targets passing;
- an image without records refused at check 1;
- five negative controls, each removing one fixup record (a call, a RIP-relative operand, a
  relocation, a jump table entry, a `.pdata` field) and requiring the matching check to fail.

Next: W2, whole-program function order.

### W2 results (Sep 2026)

`WholeProgramRewriter` implements it, with `winbolt rewrite in out --whole-program [--profile etl]
[--jcc-erratum]`. Each code contribution moves as a unit. Unordered, the layout is the linker's own,
an exact no-op. With a profile, the C3 order's contributions go first and everything else follows
in original order. The rewrite then does, in order:
- every fixup is re-resolved at its new site;
- `.pdata` is re-sorted, and the permutation is recorded so fields map to their entry's new slot;
- the entry point, the export address table and the CFG tables (function, longjmp and
  EH-continuation) are mapped and re-sorted. These are read from the original bytes: the linker
  also records fixups for the CFG function table, so reading the output would map them twice;
- `.reloc` is rebuilt in place;
- the RSDS GUID is changed until W4 writes OMAP.

`WholeProgramVerifier` checks the output:
- every fixup resolves at its new site to its target's new address;
- every contribution is byte-identical apart from its fixup fields;
- everything between contributions is int3;
- nothing else in the file changed;
- `.pdata`, entry, exports, CFG tables and relocations are the mapped originals;
- re-analysis finds every function at its new address.

**A fixup's `Target` is a symbol.** Measured on speedtest1 o2 and pgo and on cxxehtest `/MT`,
every fixup's value lies inside its target's contribution or exactly at its end, never elsewhere.
So a value moves with its target's contribution, and a `.pdata` EndAddress (the next contribution's
start) stays with its own function.

**Room.** A different order needs a little more alignment padding than the linker's. The code
section first grows into its file-backed slack, up to the next section. With JCC placement, each
executed function starts at the 4-byte step modulo 32 with the fewest executed branches on a
32-byte boundary, as Stage 6 step 5 does for copies. That padding does not fit, so the coldest
tail spills into an appended executable section, `.wbcold` (§6.2 "Where the code goes"):
134 contributions (7.8 KB) for speedtest1, 37 (0.5 KB) for zopfli. Output size: speedtest1
1.23 MB (original 1.22 MB, append mode 1.93 MB), zopfli 78 KB (77 KB, 118 KB).

**Correctness under hostile orders.** Ten builds were reversed or shuffled, so that nearly every
reference in the image changes. They verify and behave identically:
- zopfli: compressed bytes;
- speedtest1 o2, guardcf (CFG enforced) and pgo: the verification hash;
- zopflipng: the PNG;
- cxxehtest and unwindtest, o2 and `/MT`: C++ EH and SEH unwinding through reordered frames.

The profiled C3 + JCC layout, with its spill, also verifies and runs identically. A negative
control (one call left at its old displacement) is caught.

**The `/ORDER` oracle** from the milestone plan was not run. speedtest1 is the SQLite
amalgamation, most of its functions are `static`, and `/ORDER` needs their names. Only the PDB's
module symbols have them, and WinBolt reads only publics. An `/ORDER` link would place a fraction
of the list, so it could not reproduce the layout.

**Timing** (CPU cycles vs o2, `winbolt bench`, same C3 order in both modes):

| | zopfli (20 rounds) | speedtest1 (30 rounds; noise floor −0.67%) |
|---|---|---|
| append mode, C3 + JCC placement | −0.97% [−1.45, −0.64] | −1.67% [−1.82, −1.18] |
| **whole-program, C3 + JCC placement** | **−1.49%** [−1.96, −0.61] | **−2.33%** [−2.64, −1.45] |
| whole-program, C3 only | +2.32% | −1.71% |

Whole-program beats append mode by ~0.5–0.7 points with the same order. That is more than the
~0.2% Step 11 attributed to trampolines on speedtest1: there are also no dual-resident copies,
and the callers and cold code form one layout. The C3-only row reproduces Step 5's finding. On
zopfli, moving functions without JCC placement is slower, because branches land on 32-byte
boundaries.

Next: W3, block layout (rebuilt hot/cold functions with padding) in whole-program mode, compared
with append mode's best command.

### W3 results (Sep 2026)

`winbolt rewrite in out --whole-program --profile etl --blocks [--no-split] [--jcc-erratum]
[--align-loops]`. `WholeProgramRewriter` now re-encodes hot functions with `BlockRebuilder`
(`RebuiltFunction`). A function is rebuilt when:
- it is executed and alone in its contribution;
- it is `FullyTransformable`, single-range, and has no language handler beyond the GS check;
- `BlockRebuilder` accepts it;
- no RIP-relative operand other than `lea` reads code;
- no two-level switch keeps its byte table in the contribution;
- no longjmp or EH-continuation target lies in it;
- every reference from outside lands on an instruction or unwind boundary;
- no other rebuilt function branches into its interior.

Everything else moves as a whole contribution, as in W2.

The layout order is:
1. every ordered contribution (a rebuilt function as its hot part: 32-aligned plus its chosen
   residue under `--jcc-erratum`);
2. the rebuilt functions' cold parts;
3. everything else, in original order.

The cold tail spills into `.wbcold`. Sizes come from a trial encoding. The layout is repeated
with grown slots until every final encoding fits (at most 8 rounds).

A new `.wbdata` section holds:
- a complete, regenerated `.pdata`: every original entry at its new address (a rebuilt
  function's through its address map), plus one chained entry per cold segment;
- the rebuilt jump tables;
- the cold parts' empty chained UNWIND_INFO.

The exception directory names the new table. Chained entries' UNWIND_INFO trailers stay where
they are: their parent fields have fixups, which map through the address map.

**An encoder hazard specific to in-place layout.** iced's `BlockEncoder` links a branch or
RIP-relative operand to any instruction in the same encode call whose IP is its target, and the
instructions carry their original addresses. In append mode a copy's targets never fall inside
the function's original range. In place they can: `ZopfliCalculateBitLengths` moved to 0x4960,
inside `sub_3710`'s old range, and the call was linked to `sub_3710`'s own instruction there.
The verifier caught it (the call became `call 0x89D4`, not 0x4960). A colliding target is now
encoded against a nearby non-colliding stand-in, and the field is patched to the real address
after encoding.

**Verification.** For rebuilt functions, the append verifier's per-instruction check
(`RewriteVerifier.CheckRebuilt`) runs with every outside target at its new address. The
rebuilt jump tables and cold UNWIND_INFO are checked, and the regenerated `.pdata` is compared
with the mapped original plus the cold entries. All other checks are as in W2.

Tests:
- five builds with every function executed, its blocks shuffled and split, and the functions
  shuffled; they run identically (zopfli, speedtest1 o2 and guardcf, zopflipng);
- unwindtest (o2 and `/MT`) with every calling block cold: stack walks and SEH unwinding
  through cold parts, including a shrink-wrapped chained entry. A negative control removes the
  cold entries and must break the walk;
- the profiled layouts of zopfli and speedtest1.

**Results** (CPU cycles vs o2; `--profile .. --blocks --jcc-erratum` in both modes; output size):

| target | append mode | **whole-program** | size: append → whole-program (original) |
|---|---|---|---|
| speedtest1 (30 rounds) | −4.36% [−4.61, −4.09] | **−5.47%** [−5.90, −5.01] | 2.30 MB → 1.35 MB (1.22 MB) |
| zopfli (20) | −8.24% [−8.82, −8.08] | −8.40% [−8.98, −8.03] | 139 KB → 86 KB (77 KB) |
| zopflipng (15) | −18.94% [−19.11, −18.81] | −18.98% [−19.09, −18.69] | 358 KB → 236 KB (219 KB) |

Reading:
- **speedtest1 gains 1.1 points** over append mode. It has the most indirect calls into moved
  code and the most hot functions calling cold, unmoved ones; in append mode those still
  reached trampolines and scattered original bodies.
- **zopfli and zopflipng are unchanged within noise.** Their hot code is a few tight C loops
  that append mode already covered completely.
- **Size:** whole-program outputs are 7–11% larger than the originals, against 64–88% for append
  mode.
- **Not rebuilt on speedtest1:** 10 hot functions (5.3% of executed instructions) move only as
  contributions, because their two-level switch keeps its byte table inside the contribution.
  Copying those bytes into `.wbdata` and re-pointing the index load is the obvious next step.

Next: W4 (OMAP, so the output can be debugged and symbolized), and the two-level switch gap.

**Two-level switches (closed).** A byte index table that lies in the rebuilt function's
contribution now gets a copy in `.wbdata`, after its dword table
(`CopiedTable.NewIndexRva`). The index load's displacement is re-pointed at it. The verifier
checks that load like the dword load, and compares the copied bytes with the original's.
speedtest1: rebuilt functions now carry 97.9% of executed instructions (was 92.5%). The largest
remaining case (1.9%) is a function whose last chained unwind entry covers only its switch
tables after the final `ret`, so no instruction starts it.

**Table-only unwind entries (closed).** Across the SQLite builds, MSVC gives the switch tables
it places after a function's last instruction a chained unwind entry of their own:
- three functions in o2 (sqlite3_config, sub_54BC0 and the hot sub_56080);
- four in ltcg (among them sqlite3_step);
- none in zopfli or zopflipng.

Every such entry is chained, with no prologue and no unwind codes, and its bytes are all
recovered table data. No instruction runs under it, so unwinding never consults it.
`BlockRebuilder.IsTableEntry` recognizes it (table bytes or int3 only). It is then handled so:
- `BlockRebuilder` ignores it in the rebuild check, the per-entry segments and the prologue check;
- both rewriters drop it from a rebuilt function's `.pdata`, since the tables are rebuilt in
  `.wbdata`, and both verifiers expect it dropped;
- in whole-program mode, the old `.pdata` fields that still name it collapse to an empty range
  at the function's new end.

speedtest1: rebuilt functions now carry **99.8%** of executed instructions (97.9% before). What
remains is one function sharing its contribution (0.2%). Append-mode rebuilds of the o2 and
ltcg builds verify, including the linker fixup oracle, and run identically.
`Functions_with_a_table_only_unwind_entry_are_rebuilt` rebuilds all of them in shuffled
layouts, checks that the new `.pdata` does not name the tables, and runs speedtest1.

**What rebuilding sub_56080 did to speed: layout sensitivity, not a slower function.** The
build with this change was 1.4 points slower on speedtest1 (−4.05% vs −5.48% for the build
before it). The investigation:

1. *Workload.* The speedtest1 benchmarks in W2, W3 and here used `--size 25`. The LBR trace is 20
   runs of `--memdb --size 25` (§Stage 5), the documented benchmark workload. Without `--memdb`,
   SQLite runs on a temporary file, through pager and file code the profile never saw. Those W2/W3
   numbers are same-session A/B comparisons and stand as such, but they are on a workload the
   profile does not describe. With `--memdb` the drop persisted: split −3.89%, unit −4.79%.
2. *Profile.* sub_56080 has 167 blocks, of which 49 are hot. The raw LBR stacks show the early
   return after its entry call was never taken (4,790 of 4,790 records took the other branch).
   All 1,771 IP samples in the function land in hot blocks and none in cold ones. The cold blocks
   are genuinely cold. (The entry block's count of 9,288 is about twice its executions: a call
   inside a block splits each pass into two straight-line runs, and both count a visit. It
   inflates the count, not the hot/cold split.)
3. *Position.* With sub_56080 placed last in the hot order, its size change shifts no other hot
   function (`--memdb --size 25`, one session): split −4.59%, not split −5.04%, unit −4.91%. At
   its C3 position, split gave −3.85%. Most of the drop came from shifting every later hot
   function when the split shrank sub_56080's hot part. The rest (~0.45 points) is the size of
   the variation between equivalent builds: two builds that both moved sub_56080 as a unit
   differed by 0.46 points.

Conclusion: the rebuild is correct and its profile is sound. The speedtest1 number moves by up to
~1.5 points with where hot code lands (cache sets, pages, DSB), independent of the change under
test. Comparisons between single builds that differ in layout are only as good as that noise. A
fair A/B needs several layout perturbations per candidate, e.g. shifting the hot area by a few
cache lines (the Stabilizer approach). `winbolt bench` measures run-to-run noise, not layout
noise.

### Layout-averaged benchmarks (Sep 2026)

Two additions make such comparisons trustworthy:
- **`rewrite --layout-shift N`**, in both modes: the laid-out code starts N bytes later. N is a
  multiple of 64 (`FunctionRewriter.LayoutShiftUnit`), so every 32-byte decision stays valid
  (JCC padding, loop alignment, copy placement): the same layout at another cache-set and page
  alignment. A test checks that rebuilt functions keep their encodings under a shift, that both
  modes verify and run, and that a 32-byte shift is rejected.
- **Groups in `winbolt bench`**: `name=a.exe,b.exe,...`. Every round runs every member, and the
  group's time for the round is their mean, so the paired intervals compare layouts on average.
  With two or more candidates, each is also compared with the first directly.

**speedtest1, re-measured on the traced workload** (`--memdb --size 25`, 30 rounds). Each
candidate is a group of four layouts, shifted 0, 1088, 2176 and 3264 bytes (17-line steps
across a 4 KB page). CPU cycles:

| candidate | vs o2 | vs append mode |
|---|---|---|
| A: append mode, `--blocks --jcc-erratum` | −4.34% [−4.70, −4.02] | — |
| B: whole-program, same options (table-only entries rebuilt) | −4.66% [−5.43, −4.28] | −0.54% [−0.91, −0.06] |
| C: B without rebuilding the three table-entry functions | −4.92% [−5.62, −4.63] | −0.82% [−1.05, −0.44] |

The four layouts of B measured individually (20 rounds, another session) span −4.96% to −5.59%:
0.63 points from alignment alone, with nothing else changed.

Corrections to single-build numbers above:
- **Rebuilding the table-entry functions** costs about 0.26 points averaged over layouts (C vs B,
  overlapping intervals), not the 1.4 one layout pair showed. It stays on: it is correct, and the
  difference is at the resolution of this method.
- **Whole-program over append mode** on speedtest1 is about 0.5–0.8 points on the traced
  workload, not the 1.1 measured on single builds without `--memdb` (W3 results). It is still a
  consistent gain: both groups' intervals vs append exclude zero.

Method from now on: compare groups of shifted layouts, on the workload the profile was taken from.

### W4 results (Sep 2026): OMAP

`--whole-program` now writes `<output>.pdb` whenever the input's PDB was loaded:
- **`WholeProgramOmap.Build`** produces `OMAP_TO_SRC` and `OMAP_FROM_SRC`:
  - one record per contribution moved as a unit;
  - one per instruction in rebuilt functions, merged where consecutive. A dropped `jmp` maps
    only from source, since its new address belongs to its target;
  - identity for headers, data sections, and code-section bytes outside the code areas;
  - no counterpart for padding, dropped table data and `.wbdata`.
- **`PdbWriter.WithOmap`** (WinBolt.Pdb) copies every stream of the original PDB into a new MSF
  container (`MsfWriter`):
  - adds the two OMAP streams and the new section table;
  - moves the old section table to `SectionHdrOrig`;
  - sets the new GUID and age in the info and DBI streams.
  Symbols keep their original addresses, exactly as BBT leaves them (§3.3).
- **The image's CodeView record** names that PDB: a GUID hashed from the original's and the
  layout, age 1, and the PDB's path (its file name if the path does not fit the record).

**One MSF detail mattered.** Stream 0 is the previous transaction's stream directory. The first
writer copied it unchanged. dbghelp then rejected even an unchanged round trip ("file system or
network error reading pdb"), while llvm-pdbutil read it. Stream 0's block numbers are
meaningless in a new layout, so it is now written empty, as lld does, and dbghelp loads the file.

**Checks:**
- **CLI:** before writing, the CLI loads the new PDB for the output with WinBolt's own
  `PdbSymbolLoader` (§3.3 OMAP path). Every function symbol must resolve to its function's
  new address: zopfli 126 of 126, speedtest1 442 of 442.
- **Tests (dbghelp):** in the zopfli rewrite (blocks shuffled and split, functions reversed),
  dbghelp resolves every C-named rebuilt function to its hot start. More than 50 instructions
  deep in rebuilt functions, hot and cold, are named by their function and original offset.
- **Tests (MSF):** zopfli's and speedtest1's PDBs round-trip through `MsfWriter` stream for
  stream.
- **By hand, in cdb:**
  - private symbols, types and line numbers load;
  - `bp zopfli_w4!ZopfliCalculateBitLengths` hits at the function's new address;
  - the stack trace names every reordered frame correctly, including inlined frames, which
    come from line information translated through OMAP.

Not done: rewriting the PDB's own `.pdata`/`xdata` copies (the Pdata/Xdata debug streams;
debuggers read the image's). The fixup stream still describes the original layout. WinBolt
ignores fixups when OMAP is present, and the gate refuses an OMAP'd image anyway.

---

# 7. Extensibility Model

Every stage is implemented as a pass.

```
interface IAnalysisPass

interface IOptimizationPass

interface IValidationPass

interface IProfileProvider

interface IReportProvider
```

The optimizer executes passes in dependency order.

New passes require no framework modifications.

---

# 8. Project Stages

---

# Stage 1 — Binary Analysis

Goal:

Reliable binary analysis without rewriting.

Deliverables:

* PE parser (§3.3 — purpose-built, not `System.Reflection.Metadata`)
* PDB reader, with clean degradation when absent
* Function discovery
* Code-address table recovery — switch jump tables in each encoding, plus the other
  address-bearing tables enumerated in §5.2
* CFG reconstruction
* Relocation parsing
* Exception metadata parsing, including chained `RUNTIME_FUNCTION` entries (§5.1)
* Load config / CFGuard table parsing (§5.4)
* Safety gate computation (§5.5)
* Call graph generation
* Layout provenance detection (below)

### Layout provenance

Before WinBolt optimizes a binary's layout, it should know whether something already did,
and what. Both compiler PGO and a post-link rewriter produce split functions and
reordered code, but each leaves different records behind, and the difference matters:

| Evidence | Where | Means |
| --- | --- | --- |
| `OMAP_TO_SRC` / `OMAP_FROM_SRC` (debug types 7/8) | PE debug directory | post-link rewrite |
| OMAP streams, `SectionHdrOrig` | PDB DBI optional debug header | post-link rewrite |
| Debug type 10 (`Reserved10`, undocumented) | PE debug directory | post-link rewrite. Empirical: present on all 93, and only, rewritten images among 4,289 Microsoft binaries with PDBs |
| `POGO` (debug type 13) signature `PGU`/`PGO` | PE debug directory | compiler PGO |
| `POGO` signature `PGI` / `LTCG` | PE debug directory | instrumented build / LTCG without profile |
| chained `.pdata` entries > 64 KB from their parent | `.pdata` | split code, whoever split it |

Verdicts: `PostLinkRewrite`, `LikelyPostLinkRewrite` (type 10 without a PDB to confirm),
`CompilerPgo`, `PgoInstrumented`, `LtcgNoProfile`, `Inconclusive` (far fragments with
nothing to attribute them to), `NoProfileGuidedLayout`. Invalid chains (§5.1) are counted
and excluded from the far-fragment evidence.

Why it matters:

* `PostLinkRewrite` switches the PDB reader to the OMAP path (§3.3).
* Any profile-guided verdict means the incoming hot/cold split is deliberate and Stage 4
  must preserve it (Stage 4).
* It sets headroom expectations in Stage 3 triage. Microsoft's largest binaries, the
  natural front-end-bound candidates, are nearly all already `CompilerPgo` or
  `PostLinkRewrite`.

Absence of evidence is weak. A binary with no OMAP only shows that no rewriter left
address maps behind. The PE-only checks work without a PDB; the PDB checks are added
when the PDB reader lands.

### Function discovery on x64 PE

Worth stating explicitly, because it is a structural advantage over the ELF/Linux
equivalent of this problem: **x64 Windows requires unwind data for every non-leaf
function**, so `.pdata` yields near-complete function boundaries directly, even for fully
stripped binaries. This is the primary discovery mechanism, not a supplement to
heuristic scanning.

Two gaps remain and must be filled by other means:

* leaf functions that allocate no stack and save no non-volatile registers may
  legitimately have no `.pdata` entry;
* entries describe ranges, not logical functions — §5.1 applies.

Remaining coverage comes from call-target discovery, symbols where present, and
relocation targets. Anything still unattributed is reported as unclaimed code, which is
itself a useful analysis output.

Not all evidence is equal. Exports, the entry point, TLS callbacks, CFGuard targets and
direct call targets *assert* that execution enters at an address: such a start bounds its
neighbours' extents, and one landing inside a known function is an interior entry that
freezes that function (§5.5). Relocation targets and jump targets assert nothing. A
relocation may point at data placed in `.text`, and a jump may land mid-function. Weak
candidates never bound other extents, and are accepted only if their sweep terminates
cleanly. Otherwise the bytes stay unattributed. On a BBT-rewritten image, accepting weak
candidates unconditionally turned thousands of data blocks into "functions".

Known gap: C++ EH unwind funclets are referenced only by RVAs inside the EH tables in
`.xdata` (§5.2), with no relocation and no direct call. Until those tables are parsed, the
funclets show up as unattributed code. They account for most of the unattributed bytes
in `sqlncli11.dll`.

Output:

```
analyze foo.exe
```

Produces:

* CFG
* call graph
* function statistics
* instruction histogram
* safety gate summary — the fraction of functions, and of hot code, reaching each
  `Transformability` level, with downgrade reasons. This number decides whether Stage 6
  is worth building (§R2).

Validation:

* compare against objdump
* compare against IDA
* compare against Ghidra
* unit tests using synthetic binaries
* compare against matching PDBs: function symbols as ground truth for discovered entries
  (§3.3), and public names for identifications made without symbols (exception handlers,
  §16 R2)

No binary rewriting.

---

# Stage 2 — Profile Integration

Goal:

Understand runtime behavior.

## Profile fidelity is the critical path

This stage carries the project's central technical risk, and it is worth being precise
about what each profile source can and cannot supply — because the later stages have hard
dependencies on the difference.

**Instruction-pointer sampling** (ETW CPU sampling plus call stacks) produces a
statistical distribution of *where* time is spent. From it:

* function hotness — yes, directly and reliably
* basic block hotness — yes, with sampling noise; adequate for hot/cold partitioning
* call frequency and caller/callee attribution — approximately, via stack walks
* **branch frequencies — no**

IP sampling records the address a thread was executing when the timer fired. It carries no
record of *which edge was taken* to arrive there. Edge counts cannot be derived from it;
they can only be guessed at from block hotness, and the guess breaks down exactly where it
matters — blocks with multiple predecessors, which is where layout decisions are made.

**Edge-accurate profiling** requires hardware branch capture (LBR, Intel PT) or
instrumentation. This is what BOLT is built on, and it is the reason BOLT's layout results
are trustworthy.

### Consequence for the roadmap

Stage 5 (function ordering, branch layout) and Stage 6 (basic block reordering) consume
edge counts. Scheduling edge-accurate profiling as future work while promising those
stages is not a viable plan — Stage 6 in particular cannot begin without it.

Therefore:

**In Stage 2 scope:**

* ETW CPU sampling + call stacks — the fast path, sufficient for Stage 3 in full and for
  the coarse hot/cold decisions in Stage 5
* At least one edge-accurate source, brought forward from "future". Hardware branch
  capture on Windows means a PMU/processor-trace capture path and is substantially more
  engineering than opening an ETW session; the schedule must reflect that.

**Remaining future work:**

* additional hardware sources beyond the first
* custom instrumentation as a fallback where hardware capture is unavailable

Every profile consumer declares which fidelity it requires. A pass that needs edge counts
must refuse to run — not silently degrade — when handed a sampling-only profile.

### Decision: ETW with LBR, VTune as a cross-check (Sep 2026)

The first edge-accurate source is **ETW with LBR**. On each sample, the Windows kernel logger
can dump the CPU's Last Branch Record stack (`xperf -LastBranch`), which gives real
taken-branch (from, to) pairs. It is built into Windows, its trace format is readable
without third-party tools, and the trace's image-load events give exactly the module
base, timestamp and size that profile binding needs (below).

**Intel VTune** was considered as the profile source and rejected as a dependency. As far as
is known, it offers no documented export of raw branch records, and it adds its own kernel
drivers (§3.3). It stays useful run by hand: as ground truth for Stage 3's front-end-bound
triage (its top-down metrics) and for hot-path findings.

Feasibility on the development machine: an Intel i5-9600K (LBR available), VBS and Hyper-V
off (nothing blocks PMU access), and `xperf` 10.0.26100 accepting `-LastBranch Profile`
and `PmcInterrupt`. Capturing needs an elevated session; unelevated attempts fail before
any session starts. `tools/profile/Capture-Lbr.ps1` is the capture prototype.

**Prototype result (Sep 2026): the capture path works.** A 3-minute trace held 3.6 million
LBR events, one per timer sample. Each is kernel task
`{99134383-5248-43fc-834b-529454e75df3}`, opcode 0x20, version 2, 792 bytes: a 24-byte
header (u64 timestamp, u32 process ID, u32 thread ID, 8 reserved bytes), then 32 entries
of (u64 from, u64 to, u64 info), newest first. The info word was always zero on this CPU,
so there is no mispredict or cycle data. The header's process and thread IDs match the
paired sample every time.

Mapped to image RVAs and classified against WinBolt's analysis of the same files, 8.45
million user-mode entries from `findstr.exe`, `KernelBase.dll` and `ntdll.dll` gave:
- 47–92% of entries per module are direct branches on CFG edges, with zero missing edges;
- calls reach their targets, and returns land right after a decoded call;
- zero switch targets outside a recovered table, and zero "tail calls" that landed inside
  their own function (§5.2 soundness rules).

About 1,500 entries (0.02%) did not fit, all explained: ntdll syscall stubs that Chromium's
sandbox patches at runtime (the code in memory is not the file), and interrupts arriving at
non-branch instructions. **R1's capture question is answered positively on this machine.**

Rules the profile reader must follow, each learned from a wrong first attempt:
1. Use only the user-mode entries newer than the newest kernel-mode entry. The LBR is not
   cleared on a context switch, which only happens in the kernel, so older entries may
   belong to another thread or process.
2. Keep module maps per process, reset them on process start (PIDs are reused) and apply
   image unloads.
3. Bind each entry to the module version: same size, and the same timestamp or none (image
   rundown for already-running processes carries none). A trace can hold several versions
   of a system DLL, for example the 32-bit ntdll of WOW64 processes. Without this, 0.2–0.5%
   of entries looked like executed code missing from the CFG.
4. An entry whose source is not a decoded instruction is counted as unmatched (runtime
   patches, hooks) and never assigned to an edge.
5. Profile the target process by default: other processes can patch shared DLLs.

**Reader implemented** (`WinBolt.Profile`, `winbolt analyze … --profile trace.etl [--process
name]`). It follows the five rules above. Taken branches increment their CFG edge. The
straight-line run between two consecutive entries increments every fall-through edge it
crosses, which is the only evidence of not-taken conditional branches, since LBR records
only taken ones. On the prototype trace:

| Image (process `findstr.exe`) | Branch records | Matched to the CFG | Runs explained by fall-through edges |
| --- | --- | --- | --- |
| `findstr.exe` | 265,666 | 100.0% | 99.7% (241,249 fall-through executions) |
| `KernelBase.dll` | 1,381,245 | 100.0% | 99.3% (2,232,762 fall-through executions) |

A trace in which no process loaded the exact image is rejected with a diagnostic, and
analysis does not proceed with it (mismatch policy above). Binding uses file name,
SizeOfImage, and TimeDateStamp and checksum where the event has them; binding by PDB GUID
through the trace's image-identity events is a possible refinement.

Not measured yet: how much of a hot function a given sampling rate covers (edges with a
count against all edges, reported per function), and the coverage threshold the mismatch
policy asks for.

## Profile / binary binding

ETW reports absolute addresses within a loaded module. Converting them to RVAs requires
the module load address from the trace's image-load events, per process and per load.

A profile must be provably bound to the exact image being optimized. Applying a profile
from a different build is a correctness hazard, not merely an accuracy one: it produces
confident layout decisions based on function identities that no longer hold.

Binding key: PDB GUID and age where available, otherwise PE timestamp plus SizeOfImage.

Mismatch policy:

* **No match** — reject, with a clear diagnostic. Never proceed.
* **Match, but functions in the profile are absent from the binary** — proceed, report
  the unmatched fraction, and treat it as a confidence signal in reports.
* **Match, but a coverage threshold is not met** — refuse optimization stages, allow
  analysis stages. The threshold is configurable and its default must be justified by
  measurement, not chosen arbitrarily.

Stale-profile handling is a named deliverable of this stage, not an error path to be
filled in later.

## Outputs

heat maps

call frequency

hot path visualization

profile coverage and binding report

No optimization yet.

Implemented: the profile report (binding, match rates, fall-through recovery, hottest
functions with edge coverage), call frequency per call site (import calls named through
the IAT slot), and `--html`, a self-contained page with a per-page heat map of each
executable section and a hot-path view of the hottest functions. Block execution counts
are derived from edge counts. The report also adds a **hot code footprint**: the fewest
blocks covering 90% and 99% of executed bytes, and the 4 KB pages and 64-byte lines they
touch now against ideal packed layouts. It feeds Stage 5's expected benefit directly.

---

# Stage 3 — Static Performance Advisor

Goal:

Produce recommendations without modifying binaries.

Examples:

* hot virtual dispatch
* highly biased branches
* hot tiny functions
* potential devirtualization candidates
* CPU dispatch always selects same implementation
* excessive cold code in hot functions

## Front-end bottleneck triage

The first report WinBolt should produce about any binary is whether that binary can
benefit from what WinBolt does at all.

BOLT-class layout optimization recovers instruction-cache and instruction-TLB pressure.
A workload that is back-end bound, memory bound, or branch-misprediction bound will gain
nothing from perfect code layout, and no amount of profile quality changes that. Running
Stages 5–6 against such a binary spends the correctness risk budget for a guaranteed
zero return.

Triage uses PMU counters gathered alongside the Stage 2 profile — front-end bound
fraction, instruction cache and I-TLB miss rates, and code footprint relative to cache
size — to answer one question up front: *is this binary front-end bound, and how much
headroom is there?*

Layout provenance (Stage 1) is part of the headroom answer. A front-end-bound binary that
is already `CompilerPgo` or `PostLinkRewrite` has had its layout optimized once, so the
report should say so and set expectations lower than for a binary with no profile-guided
layout at all.

This makes Stage 3 substantially more useful on its own, and it acts as the gate on
whether Stages 5 and 6 are worth applying to a given target. Both properties are worth
more than any individual recommendation in the list above.

**What ETW can and cannot supply here (Sep 2026).** Top-down "front-end bound" needs
model-specific PMU events (issue-slot and uop-delivery counters). `xperf` only exposes a
fixed list of generic profile sources: cycles, instructions retired, branch mispredicts,
generic cache misses. None of those is an I-cache or I-TLB event. WinBolt's triage is
therefore a proxy it can measure exactly: the image's hot code footprint (Stage 2) against
the L1 instruction cache (from CPUID) and I-TLB reach (an assumed default, labelled as
such). The verdict uses the 90% footprint, the steady-state working set. The 99% tail is
shown but not judged, because it is often one-time start-up code. The footprint is a lower
bound on pressure, since other modules share both structures. So "fits" means "little
headroom from laying out this image", not a proof. VTune's Front-End Bound metric is the
ground truth to confirm a positive before optimizing.

**Implemented** (`Advisor`, report "Advisor (Stage 3)", needs a profile). Each finding carries
its confidence and names the stage or source change that acts on it:
- front-end triage (proxy, above);
- taken-biased *forward* conditional branches, whose cold side is the fall-through, as
  branch layout candidates. Backward branches are excluded: a mostly-taken backward branch
  is a loop, correctly laid out;
- cold code in hot functions: under half of a hot function's bytes executed, as hot/cold
  splitting candidates;
- hot tiny functions, as inlining candidates, which a post-link tool cannot do;
- indirect call sites with a dominant observed target, as promotion or devirtualization
  candidates. A single observed target that needs a CPU feature above the x64 baseline is
  reported as a CPU dispatch that never varies.

Hot virtual dispatch and devirtualization are covered by the indirect call findings. "CPU
dispatch always selects the same implementation" is covered only where the dispatch is an
indirect call; dispatch through direct branches on a CPUID-derived flag is not detected
yet.

Important:

This complements WPA rather than replacing it.

WPA explains:

"What happened."

WinBolt explains:

"What binary or source changes are suggested."

Deliverable:

HTML / Markdown report.

---

# Stage 4 — Safe Binary Rewriting

Goal:

Rewrite only at function granularity.

Allowed:

* reorder functions
* reorder sections
* hot/cold grouping

Not allowed:

* split functions further than the input already splits them
* modify instructions

A function that arrives already split across several ranges (§5.1) is moved **range by
range**. Each range keeps its internal layout, is never cut further, and keeps the
hot/cold assignment it arrived with. The distance between a function's ranges is not
preserved and need not be.

Moving the whole function as one span with its relative layout intact is not viable on
the inputs this project targets. For a compiler-PGO function, it drags the cold fragment
back next to the hot code, undoing the split. For a post-link-rewritten function whose
ranges span 25 MB, it has no meaning. When profile data disagrees with the incoming
hot/cold assignment, this stage records the disagreement in the report and does not act on
it. Re-deciding which ranges are hot is a Stage 5 concern. Recombining pre-split ranges is
a Stage 6 concern, not this stage's.

Every moved chained range must have its unwind info re-pointed at its parent's final
`BeginAddress`, and `.pdata` re-sorted (§5.4). A range whose chain is invalid is never
moved (§5.5).

Validation:

* **byte-identical verification of unchanged functions, modulo relocation and
  RIP-relative fixups.** Strict byte-for-byte comparison is not achievable and stating it
  as the criterion would guarantee the check gets weakened ad hoc later. Moving code
  legitimately changes RIP-relative displacements and relocated absolute addresses. The
  verifier normalizes both — decoding each instruction, masking the displacement and
  immediate fields covered by a known relocation or a resolved RIP-relative reference,
  and comparing the remainder — and then separately verifies that each masked field
  holds the value the move implies.
* relocation verification
* re-derivation and comparison of every structure in §5.4, in particular the `.pdata`
  sort invariant and the CFGuard tables
* checksum validation

This stage establishes trust.

## Milestone 1: verified no-op rewrite (design, Sep 2026)

The first binary WinBolt writes changes nothing a program could observe. Selected
functions are copied into an appended section, in their original order, and every path
into them is redirected to the copy. It exercises the whole writer (§6.1) and all of §5.4's
bookkeeping without any layout decision, so any failure is a writer bug, not an
optimization bug. First target: zopfli, whose output is deterministic (§10).

**Output layout.** Two sections are appended, and existing sections keep their RVAs and
file offsets:
- `.wbtext` (read and execute) holds the copied ranges.
- `.wbdata` (read-only) holds the new, complete exception table and the new base
  relocation table.

The exception and relocation data directories are re-pointed at `.wbdata`. The old tables
stay in place as unused bytes. SizeOfImage grows, and the checksum is recomputed. The two
section headers must fit in the existing header slack (before the first section's raw
data). If they do not, the rewrite is refused rather than relocating the whole file. An
Authenticode signature, if any, is removed with a warning (§5.4). Data after the last
section (an overlay) keeps its file offset, and new raw data goes after it.

**Copying.** Each moved range is copied byte for byte. Branches inside a range keep their
relative offsets, so they stay correct without change. Only references that leave the
range are fixed:
- Direct `call`/`jmp`/`jcc` to another function go to that function's copy if it was
  moved, otherwise to its original address.
- RIP-relative data references keep their absolute target; only the displacement changes.
- A RIP-relative `lea` of code keeps pointing at the **original** address. A function
  pointer must keep one value (§6.1), and the original entry leads to the copy anyway.
- Absolute addresses covered by base relocations inside a copied range get new
  relocation entries at the copy.

An `rel8` branch that leaves its range cannot be retargeted without re-encoding. Such a
function is not moved in this milestone.

**Jump tables.** An MSVC switch table holds image-relative case addresses, so the copy
cannot share it. Each recovered dword table is rebuilt in `.wbdata`, with every entry
mapped to the copy's case block. The table load (`mov r32,[base+idx*4+disp32]`, recorded by
recovery) gets its disp32 re-pointed at the rebuilt table. A two-level table's byte index
table holds no addresses. When it lies in the range, the copy reads its own copy of it;
otherwise it reads the original. MSVC places both tables inside the function's .pdata range,
after the code. The linear decode steps over them as data, and the copy carries them
unchanged, as dead bytes for the dword table.

**Redirection.** Every moved function's original entry is overwritten with a 5-byte `jmp
rel32` to its copy. Undiscovered references, exports, the entry point, callbacks and
indirect calls all still land on the original entry, and so reach the copy. The rest of
the original body stays unchanged: it is valid code, but no longer reached from the entry.

**Exception data.** The new table holds every original entry (original bodies still exist)
plus a copy of every entry that begins in a moved range, at the mapped addresses. An
unchained entry reuses the original's UNWIND_INFO. That is valid because unwind codes are
offsets from the entry's start, and handler RVAs point at the unchanged handler. A chained
entry cannot share its UNWIND_INFO, because the trailing parent RUNTIME_FUNCTION names the
original parent. Its UNWIND_INFO is copied into `.wbdata` with the trailer re-pointed at
the parent's copy. Parents are copied before their fragments, since fragments chain to
fragments. MSVC emits such chains for shrink-wrapped functions, and discovery merges them
into one range (§5.1). The table is sorted by BeginAddress.

**CFG.** Nothing changes. Indirect calls still target original entries, which stay in
`GuardCFFunctionTable`, and a copy is reached only by a direct jump, which CFG does not
check. Functions containing a `GuardLongJumpTargetTable` or `GuardEHContinuationTable`
address are not moved: setjmp and EH continuations would return into the copy at
addresses those tables do not list.

**Eligibility in this milestone.** A function is moved only if it is:
- `FullyTransformable` and a single range;
- with jump tables only in the MSVC image-relative encodings, with known load sites
  addressing them through a disp32, targets inside the range, and table data not straddling
  the range boundary;
- without a language handler other than a GS cookie check (handler data would need
  rebasing);
- without an `rel8` branch that leaves its range;
- without longjmp or EH-continuation targets;
- with exception entries the copy can reproduce: one unchained entry, at the entry point;
  chained fragments only in the direct form; and every chain parent inside the range;
- with a trampoline window: an entry range of at least 5 bytes, and no branch target from
  any function inside its first 5 bytes.

Everything else stays where it is and is reported with its reason. Widening this set
(re-encoding with iced's `BlockEncoder`, rebased handler data, multi-range functions) is
Stage 4 proper.

**Verification**, before the output is written, and again on the re-read file:
1. Structural: re-read the output with WinBolt's PE reader. Sections, the exception table
   (sorted, one entry per original and per copy), the relocation table, and the checksum
   must parse and match what was intended.
2. Byte level (the rule above): decode each original range and its copy instruction by
   instruction. Lengths and non-displacement bytes must be identical. Each changed field
   must hold exactly the value the move implies: a branch target is the mapped target,
   and a RIP-relative address is unchanged.
3. Trampolines: each patched entry decodes as `jmp rel32` to its copy, and nothing else in
   the original image changed.
4. Analysis of the output: running WinBolt's own analysis on it must find the copies as
   functions.
5. Runtime: the rewritten zopfli must produce byte-identical compressed files for several
   inputs and iteration counts. Then the same on speedtest1 (§10), whose results must
   match.
6. **Fixup oracle.** Our targets are built from source, so they are linked with
   `/DEBUGTYPE:CV,FIXUP`. The PDB then holds the linker's fixup records: every reference
   the linker resolved, absolute, image-relative and relative. That is the complete list
   that Microsoft's post-link rewriter works from, and WinBolt checks itself against it.
   Every fixup whose site lies in a moved range must be one the copier handled with the
   right target. No fixup from outside a moved function may target its interior, which
   would be a reference WinBolt failed to discover. The oracle is for validation only:
   third-party binaries do not have it, and WinBolt must not depend on it.

**Relation to Microsoft's rewriter.** BBT relays the image out in place, at basic-block
granularity, with no dead copies. It keeps debuggers working through OMAP (§3.3). It can do
that because the linker's fixup records give it every reference. This milestone instead
appends copies and redirects entries, much like LLVM BOLT without relocations. That is the
right default for binaries without fixup records, since appending tolerates a missed
reference that in-place moving would turn into a crash (§6.1). Two BBT techniques are
recorded for later:
- an **in-place mode** when fixup records are available (no growth, no trampolines, no
  dead code), designed in §6.2;
- **OMAP entries** that map the copies back to their original addresses, so the existing
  PDB symbolizes them without regenerating symbols. This needs PDB writing (§14).

Not in this milestone: PDB updates (debuggers will not symbolize the copies), removing the
now-unreachable original bodies, and any reordering.

**Results (Sep 2026).** `winbolt rewrite` on zopfli, both builds:
- **o2:** 140 of 148 functions moved (98.0% of code bytes). 302 branch fields and 693
  RIP-relative fields fixed. Verification compared 12,210 instructions and checked 1,997
  linker fixups.
- **guardcf:** same function set, 2,020 fixups checked.
- **Not moved:** 6 functions not `FullyTransformable`, and 2 shorter than a trampoline. No
  base relocations fell inside moved code.

On the first run, the oracle caught a real writer bug. Chained fragments merged into a
moved range got no exception entry at their copy. `ZopfliZlibCompress` has a primary entry
plus six nested fragments, so exceptions or stack walks there would have failed. The
chained UNWIND_INFO trailers were the "interior references" the oracle flagged. The fix is
the chained-entry copying described above.

The oracle now excludes references from exception data (the table itself, chained
trailers), because the table is rebuilt and check 1 verifies it per entry.

The rewritten binaries produce byte-identical gzip, zlib and deflate output for source,
text and binary inputs at `--i1` and `--i15`. The run time is unchanged within noise (9.8 s
for 3 MB at `--i15`).

Tests in `WinBolt.Rewrite.Tests` cover:
- the rewrite and its verification;
- the chained entries;
- the runtime output comparison;
- tamper detection: a RIP-relative field, a branch field, a trampoline and a chained trailer
  are each altered, with the checksum recomputed, and verification must fail.

**speedtest1 (Sep 2026).** Without jump tables, 83.6% of the code moved. All 29 functions
with switches stayed behind, including the interpreter loop. That build ran 0.5–1% slower
than the original, probably because the hot unmoved interpreter now called helpers about
1 MB away.

With rebuilt tables, all 29 tables were rebuilt (922 entries), and the moved share rose to:
- **o2:** 1,921 of 1,957 functions (96.7% of code bytes);
- **guardcf:** 1,931 of 1,968 (96.8%).

What still stays: 31–32 functions not `FullyTransformable`, 3 with a trampoline-window
target, and 2 too short.

Checks:
- **Verification:** passes, with 42,328 (o2) and 43,727 (guardcf) linker fixups checked.
  The oracle checks each jump table entry's fixup against its rebuilt entry, and each
  image-relative reference in a copy against the mapped value.
- **Results:** identical 6 MB query output and `--verify` hash across all test sets, on both
  builds.
- **Live tables:** corrupting the rebuilt tables crashes the program, so the copies really
  dispatch through them.
- **Timing:** within noise: o2 0.879 s vs 0.875 s, guardcf 0.881 s vs 0.890 s
  (`--size 25`, mean of 7 runs).

Recovery had to record the table load sites. Also, iced reports a sign-extended disp32 as
displacement size 8 in 64-bit mode, so the encoded field size comes from the constant
offsets instead.

Check 4 (re-analysing the output) is implemented (`CheckReanalysis`, Sep 2026). The
verifier runs WinBolt's full analysis on the output and requires every copy to be found as
a function entry. It passes for every copy of zopfli, speedtest1 and unwindtest, in both
copy and rebuild mode.

It is a weak check. A copy is discovered from its exception entry, or, for a leaf, as its
trampoline's jump target, so a copy with a missing exception entry is still found. Unwind
correctness is covered by the structural check (1) and, at run time, by unwindtest
(Stage 6, step 1).

The no-op rewrite is now the baseline for Stage 5 layout on speedtest1.

---

# Stage 5 — Profile Guided Layout Optimization

Add:

* function ordering
* hot/cold section placement
* branch layout improvements
* alignment optimization
* **benchmark harness** — see below

Still avoid rewriting inside functions.

## Measurement

The benchmark harness is a deliverable of this stage, not a convenience. Without it,
"expected benefit" is an assertion rather than a result, and there is no way to tell a
real 3% win from measurement noise — which on Windows, with turbo, scheduling, and
address-space layout variation, comfortably exceeds 3% between runs of an unmodified
binary.

Requirements:

* repeated alternating runs of original and optimized binaries, not sequential batches
* report distribution and confidence interval, never a single number
* establish the noise floor by measuring the original against itself, and refuse to claim
  any improvement that does not clear it
* record PMU counters alongside wall time, so that a win can be attributed to reduced
  front-end stalls rather than merely observed

## Expected benefit

2–10% **on front-end-bound workloads with large code footprints** — the class identified
by the Stage 3 triage report.

Stated without that qualifier the number is misleading. Binaries whose hot code already
fits comfortably in L1i have no headroom to recover and should be expected to show no
change. Reporting an honest zero on those targets is a correct outcome for this stage.

Headroom can be estimated before any rewriting, from the Stage 2 hot code footprint. On the
prototype trace (the findstr workload), the code covering 99% of executed bytes in
`ntdll.dll` touches 56 pages now. Packed by range (what Stages 4–5 can move) it would fit
in 16 pages; packed by block (Stage 6), in 5. For `KernelBase.dll` at 90% coverage the
figures are 6, 2 and 1. These are ideal lower bounds from one small workload, not a
predicted speedup. They show which binaries have footprint worth recovering, and how much
of it needs Stage 6 rather than Stage 5.

## First implementation and results (Sep 2026)

**Function ordering.** C3 call-chain clustering (Ottoni and Maher, CGO 2017; the algorithm
behind HFSort and BOLT's function reordering) lives in `FunctionOrdering.C3`:
- **Weight:** a function's executed instructions, from block execution counts.
- **Call graph edges:** profiled call counts per site, the observed targets of indirect
  calls, and unconditional tail jumps weighted by their block's count.
- **Merging:** walking functions from hottest down, each one's cluster is appended to the
  cluster of its hottest caller. A merge is skipped if the result would exceed a page, or if
  the caller's cluster is less than 1/8 as dense (weight per byte) as the callee's.
- **Output:** clusters in descending density.

`winbolt rewrite --profile` moves only the ordered (executed) functions, in that order,
through the Stage 4 writer and its full verification. Unexecuted code stays where the
linker put it. Hot/cold placement is therefore simply "hot in `.wbtext`, cold in `.text`".

**Benchmark harness.** `winbolt bench <baseline> <candidate>... -- <args>`:
- Each round runs the baseline, a byte-identical copy of it (the noise floor) and every
  candidate, in shuffled order, after warm-up rounds.
- It reports wall time and CPU cycles (`QueryProcessCycleTime`; `TotalProcessorTime` ticks
  in 15.6 ms steps, too coarse).
- For each candidate it gives the median per-round ratio to the baseline with a bootstrap
  95% interval. A change is claimed only if that interval excludes 1 and lies beyond the
  noise floor's interval.
- PMU counters are still not captured; VTune is the attribution tool (Stage 2 decision).

**speedtest1 (o2, `--memdb --size 25`, 40 rounds).** The profile is 20 speedtest1 runs,
3.3 M branch records, 99.5% matched. 764 functions executed. C3 grouped them into 414
clusters and placed 752, carrying 91.4% of executed instructions.

The 90% hot footprint went from 100 pages / 923 lines to 51 / 885 (the packed-range bound
is 44 pages). At 99% it went from 184 to 104 pages.

| vs original | wall time | CPU cycles |
|---|---|---|
| noise floor (copy) | −0.09% [−0.50, +0.18] | −0.11% [−0.34, +0.28] |
| no-op rewrite | **+0.69% [+0.27, +1.41]**, slower | **+0.78% [+0.50, +1.16]**, slower |
| C3 layout | −0.03% [−0.50, +0.23], no change | −0.16% [−0.44, +0.29], no change |

Reading:
- The no-op rewrite has a small real cost. Every indirect call to a moved function (SQLite
  calls its VFS and allocator methods through pointers) takes the extra trampoline jump.
- C3 recovers that cost, so it is about 0.8% faster than the no-op, but not faster than
  the original. This is the honest zero the qualifier above anticipates:
  - Function ordering halved the hot pages, but 100 pages were already inside the 128-entry
    I-TLB.
  - Hot lines barely moved. The L1i pressure the triage flagged (90% of executed bytes span
    180% of L1i) is made of hot and cold blocks interleaved *within* functions. Only Stage 6
    (block reordering, hot/cold splitting) reaches it: the packed-by-block bound is 7 pages /
    446 lines.

**What limited Stage 5 on this target.** At first, the functions not placed carried 8.6% of
executed instructions. The five hottest were all `Frozen` because a switch dispatch was
not recovered:
- a branch entered the dispatch sequence;
- the `__ImageBase` `lea` sat in another predecessor block;
- an index was recomputed by `lea` (`sqlite3_str_vappendf`).

The every-path proof (§5.2) fixed all of them. C3 then placed 762 of 764 executed functions
(100.0% of executed instructions), and the 90% footprint fell to 46 pages (bound 44).
Remeasured, over 40 rounds:
- wall time −0.52% [−1.05, +0.05];
- CPU cycles −0.66% [−0.97, −0.48].

That still does not clear the noise floor, whose interval in that run was [−0.60, +0.06].
It remains a zero, as the L1i analysis above predicts.

**Against MSVC's own options (Sep 2026).** `Build-Targets.ps1 -Variants ltcg,pgo` builds
speedtest1 two more ways:
- **ltcg:** `/GL` + `/LTCG`, whole-program optimization without a profile;
- **pgo:** MSVC PGO, trained on the benchmark workload itself (`--memdb --size 25`, the
  same workload the LBR profile came from), so the comparison is like for like. The link
  reports 100% of functions optimized with profile data.

All three builds give the same `--verify` hash. Benchmark, 40 rounds, relative to o2:

| candidate | wall time | CPU cycles |
|---|---|---|
| noise floor (copy) | +0.47% [−1.87, +1.30] | +0.23% [−0.61, +0.61] |
| WinBolt C3 layout | +0.24% [−0.48, +1.49] | +0.20% [−0.20, +0.46] |
| ltcg | +0.58% [−0.41, +1.87] | +0.26% [−0.13, +0.90] |
| **pgo** | **−6.21% [−7.42, −5.63]** | **−6.31% [−6.68, −6.05]** |

PGO's 6% comes from the profile, not from whole-program optimization, since ltcg alone
changes nothing. MSVC PGO also makes it smaller: 1,034,752 bytes against 1,220,096 for o2,
with 81% of profiled functions compiled for speed and the rest for size.

The profile-driven parts a post-link optimizer can reproduce are:
- block ordering inside functions;
- hot/cold splitting;
- switch case ordering.

Profile-guided inlining and per-function speed/size choices are out of its reach. The 6%
is therefore an upper bound on what Stage 6 can recover here, not a target.

Next steps:
- Stage 6: block reordering and hot/cold splitting, measured against this PGO build.
- A trace of the PGO build would show how much of its gain is footprint (pages and lines
  touched), which is what Stage 6 can recover.
- Consider redirecting relocated function-pointer slots to the copies, to remove the
  trampoline cost. This conflicts with the one-value rule of §6.1, so it needs a proof
  that no pointer comparison can see both values.

---

# Stage 6 — Basic Block Reordering

Major milestone.

Requires:

* branch rewriting
* RIP-relative relocation updates
* CFG editing
* instruction relocation
* jump table rewriting (§5.2) — entries point at blocks this stage moves, and the fixup
  differs per encoding: image-relative, table-relative, and absolute entries each need
  their own adjustment
* `.xdata` regeneration — unwind information describes prologue and epilogue offsets, so
  it does not survive block reordering unchanged
* an edge-accurate profile (§Stage 2); this stage cannot begin without one

Restricted to functions marked `FullyTransformable` (§5.5).

Enables:

* hot trace formation
* fall-through optimization
* branch inversion

Validation expands significantly.

## Step 1: verified rebuild in original order (Sep 2026)

As with Stage 4, the first step changes nothing observable. `winbolt rewrite --rebuild`
(`RewriteMode.Rebuild`) re-encodes each function from its CFG with iced's `BlockEncoder`
(`BlockRebuilder`), in the original block order, instead of copying its bytes. Everything
downstream reuses the Stage 4 writer, through a per-function address map from original to
new addresses:
- exception entries, including chained fragments;
- rebuilt jump tables;
- trampolines and the fixup oracle.

**Encoding rules.**
- **What is re-encoded:** only address-dependent instructions: branches, RIP-relative
  operands and table loads. Every other instruction is emitted as its original bytes (a
  `db` pseudo-instruction that keeps the original IP, so branches still link to it).
  Re-encoding them would drop redundant prefixes, such as MSVC's 2-byte `push rbx` kept for
  hot-patching. That shifts prologue offsets, and unwind codes locate prologue instructions
  by offset.
- **One encoder call per function.** The encoder links any branch *or RIP-relative operand*
  whose target is an instruction in the same call. Encoding functions together would point
  `lea reg,[f]` at f's copy and break the one-value rule (§6.1). Calls and jumps to other
  moved functions are retargeted to their copies explicitly.
- **Padding and table data between blocks are dropped.** Index tables of two-level switches
  are read from the original; dword tables are rebuilt as in Stage 4.
- **Sizing:** a trial encoding at the original address filters and sizes each function.
  Space is reserved with slack (16 bytes + 4 per block), because branch forms can change at
  the final address.

**Additional eligibility.** A function is not rebuilt if it has:
- 64-bit absolute addresses in its code;
- a RIP-relative operand into its own code;
- an unwind entry that does not start on an instruction (on speedtest1, entries covering
  only jump table data);
- unwind info version 2 (epilogue codes);
- prologue instruction offsets that do not survive the encoding.

An entry that ends at table data or padding maps to the end of the code before it.

**Verification** (`CheckRebuilt`, plus the oracle), block by block:
- every original instruction has a counterpart at its mapped address;
- a branch keeps its mnemonic (the form may change) and reaches the mapped target, or a
  moved callee's copy;
- a table load names the rebuilt table;
- every other instruction is the same instruction, compared with iced equality, which
  compares RIP-relative operands by absolute target;
- instructions of a block are contiguous, and a block that can fall through is followed
  directly by its successor;
- the oracle finds the instruction holding each fixup and checks that its new operand
  resolves to the mapped target.

**Results.**
- **zopfli:** 140 of 148 functions rebuilt (all the copy mode moves).
- **speedtest1:** 1,922 of 1,957 (98.4% of bytes; guardcf 1,933). About 250,000
  instructions were compared and 42–44k linker fixups checked.
- **Runtime:** output is byte-identical on both targets and both builds, and speedtest1's
  `--verify` hash matches.
- **Tamper tests:** altering a rebuilt call's target or a byte of an address-independent
  instruction fails verification.

**Open.**
- Exception unwinding through rebuilt frames is proven only structurally. Neither target
  throws, so a runtime test needs a target that unwinds through moved frames.
- The reserved slack makes `.wbtext` larger than needed; the final layout can pack to the
  actual sizes.

Step 2 is block reordering and hot/cold splitting on top of this.

## Step 2: block reordering and hot/cold splitting (Sep 2026)

`winbolt rewrite --profile etl --blocks [--no-split]` (implies `--rebuild`) lays out the
blocks of every function it moves. The order comes from `BlockLayout.Order`; the rebuilder
(`BlockRebuilder.Encode`) accepts any `BlockOrder` (hot list, entry first; cold list), which
is how the tests drive it with layouts no profile would produce.

**Layout.** Pettis–Hansen bottom-up chaining:
- Hot blocks are those the profile executed, plus the entry.
- Edges between hot blocks are taken heaviest first; an edge u→v joins the chain ending in u to
  the chain starting at v, so the hot successor becomes the fall-through.
- The entry's chain comes first, the other chains follow by density (executions per byte).
- Never-executed blocks keep their original order and go to a cold area after all hot code
  (with `--no-split`, after the function's hot chains instead).

**Encoding a layout.** Per block, against the block placed next:
- If the fall-through successor is not placed next, a `jmp` to it is inserted.
- If the block ends in a conditional branch to the block placed next, the branch is inverted
  to target the fall-through successor instead (no `jmp`).
- A final `jmp` to the block placed next is dropped; its original address maps to the target.
- A call with no successor block (noreturn) gets an `int3`, so its return address stays in
  the function.
- Inserted instructions get unique IPs above any RVA. The encoder links branches *and
  RIP-relative operands* to whatever instruction has the target as IP; with IP 0, the
  inserted `jmp` captured `lea reg,[__ImageBase]`. The verifier caught this.

**Unwind data.** Frame state is looked up by address, so every instruction must stay under
the unwind entry that described it:
- Blocks are laid out per unwind entry (a segment), segments in their original order. 312 of
  the 746 functions of the first speedtest1 layout had several entries (MSVC shrink-wraps:
  a primary entry for the first saves, chained entries for the rest), so this is not a
  corner case.
- Each segment starts with every block that begins inside its prologue, in original order
  and hot. Unwind codes locate prologue instructions by offset, and a prologue can span
  blocks: `sqlite3VdbeExec`'s chained entry has a 0xED-byte prologue with branches and a call
  between the saves of rdi, r15 and xmm6–11. Until this rule existed, the prologue check
  refused the interpreter (27% of executed instructions).
- A segment's cold blocks get a new entry: UNWIND_INFO version 1, `UNW_FLAG_CHAININFO`, no
  prologue and no codes, the segment's frame register, chained to the segment's copied entry.
  Cold code runs with the frame the prologue built, so applying the parent's codes (all of
  them: the offset from the parent's start is past its prologue) unwinds it. This is what
  MSVC emits for separated code.
- Jumps between parts stay non-epilogues: the unwinder treats a `jmp` whose target lies in an
  entry chained to the same primary as a jump within the function.
- Cold parts of leaf functions (no entry) need none.
- The CFG now starts a block at every unwind entry start (a shrink-wrapped fragment used to
  begin mid-block). The trampoline-window gate therefore counts only blocks entered other
  than by fall-through (`BasicBlock.IsBranchTarget`) as branch targets in the first 5 bytes.

**Eligibility** (`BlockRebuilder.LayoutReason`; otherwise the function is rebuilt in original
order): every block lies wholly inside one entry, all code is covered when there are entries,
each entry begins a block, and no block falls through into something that is not a block.
On speedtest1, no laid-out function needed the fallback.

**Verification** (`CheckRebuilt`, extended; the same code verifies step 1):
- every instruction is placed inside the copy's hot part or its cold part, and inside the copy
  of its original unwind entry or one of that entry's cold entries;
- a block's fall-through successor is reached directly or through a `jmp` placed right after
  it;
- an inverted branch has the negated condition, targets the fall-through successor, and is
  followed by the original target (directly or through a `jmp`);
- a dropped `jmp` maps to its target;
- the entry block starts the copy;
- cold entries tile the cold part exactly, chain to the right copy, and have empty chained
  UNWIND_INFO with the parent's frame register.

**Tests.** Besides the profile layout:
- random layouts (shuffled blocks, each cold with probability ½) of zopfli and speedtest1
  verify and run with identical output;
- unwindtest with every non-entry block that calls something made cold unwinds correctly
  (stack walk and SEH) through cold frames, including shrink-wrapped `Busy`'s cold part
  chained to its chained entry. Dropping the cold entries breaks it (negative control);
- negating an inverted branch, or changing a cold entry's frame register, fails verification.

**Results on speedtest1 (o2, `--memdb --size 25`).** 750 functions laid out, carrying 98.4%
of executed instructions; 693 split. Hot code in `.wbtext` is 281 KB, cold 335 KB. The 90%
hot footprint went from 100 pages / 925 lines (original) and 51 / 898 (C3 functions only)
to 40 / 676. The verify hash is unchanged.

Benchmark, 40 rounds, relative to o2:

| candidate | wall time | CPU cycles |
|---|---|---|
| noise floor (copy) | −1.13% [−1.67, −0.26] | −0.70% [−1.14, −0.46] |
| C3 functions only | −1.29% [−2.05, −1.03], no change | −1.29% [−1.55, −0.94], no change |
| **C3 + blocks, split** | **−2.72% [−3.22, −2.16]** | **−2.36% [−2.70, −2.18]** |
| C3 + blocks, no split | −2.30% [−2.79, −1.69] | −2.31% [−2.55, −1.79] |
| MSVC PGO | −6.81% [−7.41, −6.52] | −6.62% [−6.82, −6.30] |

Reading:
- This is WinBolt's first change that clears the noise floor. Against the copy it is about
  1.6% in cycles.
- Splitting adds little over reordering alone. Most of the gain is fall-through and line
  density inside hot functions, not moving cold code out.
- PGO is still 4% ahead. Part of that is out of reach (inlining, per-function speed/size
  choices; §Stage 5). Within reach:
  - the trampoline on every indirect call to a moved function;
  - a better block order than greedy chaining (ext-TSP, as BOLT uses);
  - switch case ordering.

**Open.**
- Remeasure over more runs, and profile the laid-out binary to confirm the hot-line numbers
  translate into fewer L1i misses (VTune).
- Functions still not rebuilt: prologue offsets that do not survive re-encoding (7 small
  functions), entries that do not start on an instruction (2), RIP-relative references into
  their own code (3).
- Cold code keeps no `__GSHandlerCheck` (a chained entry has no handler). Only the cookie
  check during exception dispatch is skipped for frames in cold code, which is harmless, but a
  language handler with real data (SEH, C++ EH) would need its tables regenerated; those
  functions are not moved at all yet.

## Step 3: ext-TSP block order, a negative result (Sep 2026)

`--block-order ext-tsp` (`ExtTsp`, `BlockLayoutAlgorithm.ExtTsp`) implements extended TSP
(Newell and Pupyrev, IEEE TC 2020), BOLT's default block layout.

**Objective.** Every profiled edge scores by where its target lands relative to the end of its
source:
- a fall-through scores the edge's count;
- a forward jump of up to 1024 bytes, or a backward one of up to 640, scores a tenth of it,
  falling linearly with distance;
- anything farther scores nothing.

**Algorithm.** Each hot block starts as its own chain. The adjacent pair of chains whose
merge gains most is merged, trying X·Y and Y·X and, for chains of up to 128 blocks, every
split X1·Y·X2, Y·X2·X1 and X2·X1·Y. A merge that would move the entry off the front is not
allowed. Only the edges between the chains, plus the split chain's own edges, are rescored,
so speedtest1 lays out in seconds. Remaining chains follow the entry's by density.

**Measurement.** `LayoutStatistics` measures on the output how many profiled block-to-block
transfers fall through (no taken branch); `winbolt rewrite --blocks` prints it.

| speedtest1 (o2) | fall-through share | 90% footprint | CPU cycles vs o2 (50 rounds) |
|---|---|---|---|
| original layout | 53.4% | 100 pages / 925 lines | |
| noise floor (copy) | | | −0.14% [−0.37, +0.04] |
| greedy chains (step 2) | 81.9% | 40 / 676 | **−1.56% [−1.75, −1.44]** |
| ext-TSP | 82.3% | 40 / 687 | −1.12% [−1.36, −1.00] |

The same ordering held in a 40-round run: chains −1.60%, ext-TSP −1.00%, PGO −5.96%, with a
noise floor of +0.08%. That run also puts step 2's earlier −2.36% in context: its noise
floor was −0.70%, so both runs agree on about −1.6% net.

Reading:
- ext-TSP wins the objective it maximizes and loses at run time, reproducibly. Greedy
  chaining already turns most of the profiled transfers into fall-throughs; the extra 0.4
  points came with a slightly larger hot footprint (11 more lines).
- A 0.4% difference between two layouts is also within the range code alignment alone can
  produce (loop heads crossing 32- and 64-byte boundaries). Telling these apart needs front-end
  counters (DSB, L1i misses), i.e. VTune.
- Greedy chains stay the default. ext-TSP stays available and tested (the speedtest1 layout
  verifies and gets at least as many fall-throughs).

## Step 4: front-end attribution and JCC erratum padding (Sep 2026)

**Attribution.** `tools/profile/Collect-TopDown.ps1` (run elevated) collects VTune
microarchitecture exploration for o2, the two layouts and PGO:
- 3 interleaved repeats per build;
- a 0.1 ms sampling interval;
- `-allow-multiple-runs`, so no event group is multiplexed.

Two approaches failed first:
- One default collection per build is too coarse. At a 1 ms interval, instructions retired
  was ~1,700 samples (±2.4%), and dozens of multiplexed groups made the top-down breakdown
  swap categories between builds.
- VTune's counting mode (`pmu-collection-mode=summary`) counted only a varying part of each
  run on this machine: 0.23–0.75 G of the program's fixed ~6.4 G instructions.

Results (i5-9600K, Coffee Lake; the repeats agree to about ±1%):

| build | cycles | instructions | CPI | ICache misses | DSB coverage | MITE bandwidth |
|---|---|---|---|---|---|---|
| o2 | 3.534 G | 6.524 G | 0.541 | 2.7% | 44.5% | 15.8% |
| chains | −1.8% | −1.0% | 0.537 | 2.2% | 40.3% | 17.0% |
| ext-TSP | −1.1% | −0.9% | 0.540 | 2.1% | 34.7% | 17.7% |
| PGO | −6.1% | −4.3% | 0.531 | 2.0% | 38.5% | 17.7% |

Reading:
- **PGO's lead is mostly fewer instructions**: −4.3%, about 70% of its cycle gain. Per
  function, the reduction sits in `sqlite3VdbeExec`, with signs of different inlining
  (`pcache1FetchNoMutex` disappears into its caller). A post-link optimizer cannot reproduce
  that. The layout-reachable part of PGO's gain is its CPI, 1.8%.
- **The layouts fixed what they target.** ICache misses fell as far as PGO's. The dropped
  jumps even removed 1% of the executed instructions.
- **But they cost decoded-ICache (DSB) coverage**, and ext-TSP most. This CPU has the JCC
  erratum microcode: a 32-byte window holding a jump, call or return that crosses or ends on
  a 32-byte boundary is not cached in the DSB and is decoded again by MITE.
  `LayoutStatistics.JccErratum` measures the exposure, weighted by the profile: 15.8% of
  executed branches in o2, 15.6% with chains, 17.6% with ext-TSP. That explains ext-TSP's
  deficit. Chains lost DSB coverage without more exposure, so denser hot code (more uops per
  32-byte window) likely costs some too.

**Padding.** `winbolt rewrite --jcc-erratum` (`FunctionRewriter.Rewrite(..., jccErratum)`)
moves executed jumps, calls and returns off 32-byte boundaries, counting a macro-fused
compare and jcc as one instruction:
- Multi-byte NOPs go in front of the branch, or in front of the compare it fuses with.
- The rebuilder pads in order and re-encodes, until no executed branch in the hot part is on a
  boundary (at most 8 rounds; pads only grow).
- Never before the entry (trampolines and calls land on the copy's first byte), never inside
  a prologue (unwind codes locate its instructions by offset), never in cold code.
- Copies are aligned to 32 bytes, so the trial encoding sees the same boundaries as the
  final one. A pad that would outgrow the reserved space is skipped.
- The verifier accepts NOPs between two instructions of a block and before a fall-through
  successor. Turning such a NOP into anything else fails verification (tested).

**Results on speedtest1**:
- Exposure falls from 15.8% to 0.1% of executed branches; hot code grows 4% (281 → 293 KB).
- Benchmark, 40 rounds, CPU cycles relative to o2, noise floor −0.07% [−0.24, +0.18]:

| candidate | CPU cycles |
|---|---|
| chains | −1.51% [−1.72, −1.37] |
| **chains + padding** | **−3.48% [−3.58, −3.26]** |
| C3 functions + padding, no block layout | −0.41% [−0.51, −0.19], no change |
| PGO | −6.13% [−6.25, −6.01] |

A second run confirmed it: chains + padding −3.45% [−3.71, −3.33]; ext-TSP + padding
−3.16% [−3.44, −2.92].

Reading:
- Padding more than doubles the layout's gain, yet does little on its own. The layout turns
  branches into fall-throughs and packs hot code; the padding keeps that code in the DSB.
- ext-TSP narrows the gap but stays behind chains.
- Against PGO's layout-reachable part (CPI, about 1.8%), WinBolt now gets more: −3.5% cycles
  with 1% fewer instructions.

**Scope.** The erratum affects Intel Skylake-derived cores (Skylake through Comet Lake and
Cascade Lake) with the 2019 microcode, not Ice Lake and later or AMD. On those, padding
only costs code size and a few NOPs. So it is opt-in: the machine that matters is the one
the binary runs on, not the one that optimizes it.

**Prefix padding.** Executed padding NOPs were 3.5% of executed instructions on speedtest1
(`LayoutStatistics.JccErratum` counts them), each taking a slot in the 4-wide pipeline. So
the padding now first adds redundant CS segment prefixes (`0x2E`, ignored in 64-bit mode) to
instructions in front of the branch, as GNU as does for this erratum, and uses NOPs only for
what remains. Rules:
- only instructions kept as raw bytes, after the previous executed branch (a branch checked
  earlier in the pass must not move), up to 8 instructions back;
- never on branches: `0x3E` on an indirect branch is CET's notrack, and `0x2E` / `0x3E` on a
  jcc are branch hints;
- never on instructions with a segment prefix, a lock prefix, or a VEX, EVEX or XOP encoding,
  and never in a prologue;
- at most 3 added prefixes per instruction, 15 bytes in all.

The verifier accepts a CS, DS, ES or SS prefix that the original lacks; a changed prefix fails
(an FS in its place is tested).

On speedtest1, executed padding NOPs fall to 1.25% of instructions, with the same code
size. Benchmark, 40 rounds, CPU cycles relative to o2 (noise floor −0.02%):
- NOP padding: −3.61% [−3.91, −3.30];
- **prefix padding: −4.40% [−4.56, −4.06]**.

A second run gave −4.32%. Allowing 5 prefixes and a 16-instruction window (NOPs down to 1.01%)
changes nothing measurable (−4.29%), so the limits stay conservative.

**Open.**
- Re-collect top-down metrics for the padded builds to confirm DSB coverage recovered.
- Align hot loop heads.
- Offer to derive `--jcc-erratum` from a target CPU model.

## Step 5: second target, zopfli (Sep 2026)

Every result above came from speedtest1. zopfli (o2) tests whether they generalize.

**Setup:**
- The benchmark input is `artifacts/bench/zopfli-input.bin`, the first 512 KB of the SQLite
  amalgamation `sqlite3.c`. `zopfli --i5` on it takes about 0.9 s.
- The LBR trace, `artifacts/lbr-zopfli.etl`, covers 20 runs on that input: 100% of records
  matched, 99.1% of straight-line runs explained.
- MSVC PGO's zopfli was trained on `speedtest1.c`, the same kind of input but not the same
  file.
- Every candidate produces the same 131,536-byte gzip stream as o2.

**Profile.** zopfli's hot code is small: 90% of execution touches 8 pages / 96 lines, far
inside L1i. So a gain here cannot come from the instruction footprint.

**Layout statistics:**
- 51 executed functions, all placed; 41 split.
- Fall-throughs go from 40.0% to 80.4% of profiled transfers.
- Block layout alone raises JCC exposure from 13.4% to 21.9% of executed branches; padding
  removes it (0.0%).
- Executed padding NOPs stay at 2.7% of instructions even with prefixes: zopfli's tight loops
  leave few instructions in front of their branches to carry prefixes.

Benchmark, CPU cycles relative to o2 (40 rounds, noise floor −0.21%):

| candidate | benchmark input | repeat run | unseen text (25 rounds) | binary input (25 rounds) |
|---|---|---|---|---|
| C3 functions only | **+1.52%**, slower | | | |
| C3 + blocks | −0.76% | | | |
| **C3 + blocks + JCC padding** | **−7.88%** | −8.04% | **−9.52%** | **−5.71%** |
| MSVC PGO | −3.51% | −3.60% | −4.73% | −2.17% |

The unseen inputs are another 512 KB of `sqlite3.c` (from offset 4 MB), and the first
384 KB of the o2 `speedtest1.exe`.

Reading:
- On zopfli WinBolt beats MSVC PGO by a factor of about two, on inputs that neither profile
  saw as well. So the gain is not overfitted to the profiled input.
- As on speedtest1, the gain needs both parts. Block layout without padding raised JCC
  exposure and gained little; padding without the layout was no change on speedtest1.
- Function layout alone is 1.5% slower: the copies' new addresses put more executed branches on
  32-byte boundaries (explained and fixed below).
- Unlike speedtest1 (4.3% fewer instructions), PGO's zopfli advantage is not instruction count
  alone, which leaves more of it within a layout tool's reach. VTune on zopfli would show it.

**Why function layout alone was slower, and the fix.** `LayoutStatistics.JccErratum` now
also covers byte copies, and every profiled rewrite prints it. Function layout (C3, copy mode)
moves each function to a new address, and with it where its branches fall relative to
32-byte boundaries:
- on zopfli, exposure went from 13.4% to 16.2% of executed branches, and it ran 1.5% slower;
- on speedtest1, it went from 15.9% to 12.3%, and it was slightly faster.

A byte copy cannot be padded inside. With `--jcc-erratum` in copy mode, each copy's start is
chosen among 4-byte steps past its 16-byte-aligned slot, modulo 32, to put the fewest executed
branches on a boundary (`LayoutStatistics.ExposureAt`).

| step | zopfli exposure | speedtest1 exposure | zopfli CPU cycles vs o2 (40 rounds) |
|---|---|---|---|
| unplaced | 16.2% | 12.3% | **+1.27%**, slower |
| 16 bytes (2 choices) | 10.1% | 8.0% | −0.84% |
| **4 bytes** | 5.6% | 4.4% | **−1.96%** |
| 1 byte | 4.8% | 3.6% | (not measured) |

On speedtest1, unplaced copies measured −0.25% (no change) and placed ones −0.85%. The
verify hash and zopfli's output are unchanged, and the zopfli profile test checks that
placed copies verify, halve the exposure of unplaced ones and compress identically.

**Where padding goes.** A pad only has to shift its branch, so it can go anywhere after the
previous executed branch. The pass now places it where it costs least:
- a gap right after an unconditional `jmp`, `ret` or `int3`: never executed, so free;
- otherwise redundant prefixes (as before);
- the remaining NOPs where the fewest profiled executions pass, not directly in front of
  the branch.

`LayoutStatistics` no longer counts NOPs in such gaps as executed.

zopfli's tight loops leave no such gap: every stretch between two executed branches runs on
each iteration. For those, the whole function moves instead. Every start offset of a
rebuilt function (4-byte steps modulo 32) is trial-encoded, and the rewriter keeps the one
that leaves the fewest executed branches unpaddable (on a boundary inside a prologue, where
nothing may be inserted), then the fewest executed padding NOPs. Minimizing NOPs alone left
0.6% of zopfli's executed branches on a boundary.

| | executed padding NOPs, speedtest1 | zopfli | CPU cycles vs o2, speedtest1 | zopfli |
|---|---|---|---|---|
| prefixes, NOPs before the branch (committed) | 1.25% | 2.72% | −3.54% [−3.79, −3.27] | −8.08% [−8.20, −7.88] |
| **cheapest place + best start offset** | **0.38%** | **1.74%** | **−4.45%** [−4.65, −4.25] | **−8.31%** [−8.46, −8.16] |

Each pair was measured in the same session, 40 rounds. The speedtest1 test requires executed
padding NOPs under 1% of instructions.

**Measurement note.** The same binary measured −4.40% and −3.54% against o2 in two sessions:
between-session variation of about 0.8 points, which the bootstrap interval of one session
does not show. So candidates are compared only within one session; differences below that
across sessions are not claimed.

**Open.**
- Top-down (VTune) comparison of zopfli o2, WinBolt and PGO.
- The remaining executed padding NOPs (1.7% on zopfli) sit in loops dense with branches.

## Step 6: hot loop alignment (Sep 2026)

`winbolt rewrite --align-loops` (implies `--rebuild`; `FunctionRewriter.Rewrite(..., alignLoops)`)
starts every hot loop head on a 32-byte boundary, one decoded-ICache window:
- **What counts as a loop head:** a block that a block placed at or after it branches back
  to, with at least 4 iterations per entry on average (back-edge count at least 4 times the
  entry count).
- **Where the padding goes:** through the same placement as JCC padding. First a gap nothing
  falls into, then prefixes, then NOPs where the loop is entered (the back edge jumps past
  them).
- **Interaction with branch padding:** later padding never moves an aligned head. Loop heads
  and branches are handled in one pass, and a function's start offset is chosen with both in
  place.

It is separate from `--jcc-erratum`: 32-byte decoded-ICache windows exist on all recent
Intel cores, not only on those with the erratum. It was measured together with it.

Results, CPU cycles against o2, each pair in one session (40 rounds):

| | speedtest1 | speedtest1, again | zopfli | zopfli, unseen text |
|---|---|---|---|---|
| `--blocks --jcc-erratum` | −4.88% | −4.97% | −8.08% | −9.60% |
| **+ `--align-loops`** | **−5.23%** | **−5.21%** | **−8.48%** | **−10.07%** |

The gain is small (0.25–0.5 points) but in the same direction in all four runs. It costs
more executed padding (speedtest1 0.38% → 0.52% of instructions, zopfli 1.74% → 2.09%) and a
little code (hot code +5 KB on speedtest1).

The speedtest1 sessions had a noise floor of about −1.1% (the byte-identical copy ran faster
than the baseline), so these absolute numbers are about 1 point more negative than in
earlier sessions. Only the within-session comparison is claimed.

## Step 7: moving functions with C++ EH tables (Sep 2026)

Until now, a function with a language handler other than the GS cookie check was never
moved ("language handler data would need rebasing"). For C++ code that is a large gap: in
zopflipng, 21 functions with `__CxxFrameHandler4` tables (18% of the code) stayed in place.

**Why a byte copy can share the original tables.** From the CRT source shipped with Visual
Studio (vcruntime `risctrnsctrl.cpp`, `frame.cpp`, `ehdata4_export.h`):
- **Function start.** `__CxxFrameHandler4` decodes a FuncInfo4 against
  `DispatcherContext->FunctionEntry->BeginAddress`, the start of the unwind entry the frame's IP
  lies in. IP-to-state entries and non-RVA catch continuations are offsets from it. For a frame
  in a byte copy, that is the copy's entry, and every offset is unchanged.
- **Where execution resumes after a catch.** With FH4 metadata, a catch funclet returns an
  index, and the CRT resumes at `functionStart + offset`, which is inside the copy.
  RVA-encoded continuations (`contIsRVA`) resume in the original body. That body stays intact
  past the trampoline, so they remain valid.
- **Catch funclets.** A running catch funclet is recognized by its FuncInfo's `isCatch` flag
  (`ExecutionInCatch`), not by address, so catch funclets can move too. FH3 is different: it
  compares the funclet's entry RVA with the table, so FH3 functions stay excluded.
- **Separated functions.** Their segments are matched by absolute RVA (`isSeparated`), so they
  stay excluded.

**What changed:**
- **Eligibility** (`FunctionRewriter.Reason`): a function moves as a byte copy, never rebuilt, if
  - it has FH4 tables that parsed completely and are not separated, or
  - it is `RelocatableOnly` only for `cxx-eh-table` or `interior-pointer`: "may move as a unit"
    (§5.5), and an interior code pointer keeps naming the intact original body.
  In `--rebuild` and `--blocks` runs such functions are copied while the rest are rebuilt.
  `CxxEhInfo` now records the FH4 `IsSeparated` and `IsCatch` flags.
- **Verifier oracle:** references into a copied function's original body are expected when
  WinBolt knows them (FH4 continuation RVAs, interior code pointers).
- **GS wrappers:** `__GSHandlerCheck_EH4` and its siblings were identified only through a
  pattern-verified plain `__GSHandlerCheck` elsewhere in the image. An image with no GS-only
  function has none (cxxehtest). There the PDB must name the wrapper exactly as its inner
  handler implies, and the structural check must still hold.
- **Re-analysis check (4):** it now analyses the output with the input's PDB symbols. The
  output keeps the input's debug record, and every original function keeps its RVA. Functions
  known only from their symbol (two tiny destructors in cxxehtest) are then reached through
  their trampolines.
- **Noreturn calls:** a `nop` or `int3` right after a noreturn call ends its block without a
  fall-through (verifier and `LayoutReason`). Catch funclets end in `call _CxxThrowException;
  nop`.

**Tests.** `tools/targets/cxxehtest` (C++, `/EHsc`) throws through the moved functions in
every way the tables describe: destructors while unwinding, try/catch with objects on both
sides, catch and continue, rethrow, a throw from inside a catch, catch by base class, and a
frame that catches and then throws again from a later state. `CxxEhTests` rewrites o2 and
guardcf builds in copy and rebuild mode:
- at least 4 functions with C++ EH tables must move, all as byte copies;
- the output must be identical;
- dropping the copies' exception entries must break it (negative control).

**zopflipng** (o2, now a build target; `zopflipng --iterations=5 -y` on a 256×256 crop of a
Windows lock-screen image, `artifacts/bench/zopflipng-256.png`):
- the no-op rewrite moves 99.0% of the code, up from 81%;
- copy and rebuild mode both verify, and the output PNG is byte-identical.

**Open.**
- FH3 (`__CxxFrameHandler3`) functions: their catch funclets would need their table entries
  rebased.
- SEH scope tables (`__C_specific_handler`) hold absolute RVAs of try ranges; copies would need
  rebased tables.
- Block layout inside C++ EH functions would need the IP-to-state map regenerated.

## Step 8: third target, zopflipng (Sep 2026)

**Setup:**
- Build: zopflipng o2 (C++, `/EHsc`), and MSVC PGO trained on the benchmark input.
- Benchmark input: `zopflipng --iterations=5 -y` on `artifacts/bench/zopflipng-256.png`, about
  2.7 s per run.
- Unseen input: `zopflipng-unseen.png`, another 256×256 crop of the same image.
- Profile: `artifacts/lbr-zopflipng.etl`, 10 runs on the benchmark input. 100% of records
  matched, 99.2% of straight-line runs explained.
- Every candidate writes a byte-identical PNG.

**Profile.** All the hot code is zopfli's C core (`ZopfliFindLongestMatch` alone is 61% of
samples), and all of it is `FullyTransformable`. No function with C++ EH tables is hot, so on
this program the C++ EH work of step 7 buys coverage (99% of the code movable), not speed. The
hot footprint is small: 60 lines cover 90% of execution.

**Layout statistics:**
- 88 of 89 executed functions placed; 84 laid out, 71 split.
- Fall-throughs go from 43.4% to 78.8% of profiled transfers.
- JCC exposure is unusually high in o2: 20.5% of executed branches sit on a 32-byte boundary.
  Copy placement brings that to 6.8% and padding to 0.0%, at 2.5% executed padding NOPs.

CPU cycles relative to o2:

| candidate | benchmark input (25 rounds) | unseen image (20 rounds) |
|---|---|---|
| noise floor (copy) | −0.15% | −0.08% |
| C3 functions, copies placed (`--jcc-erratum`) | −9.53% | |
| **C3 + blocks + JCC padding** | **−18.84%** [−19.08, −18.72] | **−19.25%** [−19.41, −18.85] |
| + `--align-loops` | −18.41% | −18.56% |
| MSVC PGO | −10.41% | −10.31% |

Reading:
- The largest gain of the three targets comes from the largest JCC exposure. Keeping hot
  branches out of the erratum's reach is worth more here than all of PGO's optimizations
  together, on an input neither profile saw as well.
- Loop alignment costs about 0.5 points on zopflipng, against 0.25–0.5 points of gain on the
  other two targets. It stays opt-in, and `--blocks --jcc-erratum` is the recommended command.

**Across the three targets** (CPU cycles vs o2, `--blocks --jcc-erratum`, same-session
comparisons):

| target | WinBolt | MSVC PGO |
|---|---|---|
| speedtest1 | about −5% | −6.1% |
| zopfli | −8.1 to −9.6% | −3.6 to −4.7% |
| zopflipng | −18.8 to −19.3% | −10.3 to −10.4% |

Only on speedtest1 is PGO ahead, and there most of its gain is fewer instructions (inlining,
step 4), which a post-link tool cannot reproduce.

## Step 9: moving SEH functions with rebased scope tables (Sep 2026)

`__C_specific_handler` (and the `__GSHandlerCheck_SEH` wrapper) compares the IP with absolute
RVAs in the function's scope table (vcruntime `riscchandler.cpp`). Unlike FH4's offsets, these
do not survive a move. So a byte copy of an SEH function gets its own UNWIND_INFO in
`.wbdata` (`FunctionRewriter.SehUnwindCopy`):
- header, unwind codes and handler RVA verbatim;
- then the scope table (Count, then `{ Begin, End, Handler, JumpTarget }`), with every address
  inside the function moved into the copy;
- then up to 12 following bytes verbatim (a GS wrapper's cookie data).

Handler values 0 and 1 are `EXCEPTION_*` constants, not addresses. A filter or termination
funclet outside the function keeps its RVA; it runs from its own copy through its trampoline.
Chained copies chain to the new primary entry as before.

**Eligibility.** A function that is `RelocatableOnly` for `seh-scope-table` (a validated table),
with a `CSpecific` handler, moves as a byte copy, also inside `--rebuild` and `--blocks` runs.

**Verification:**
- `CheckSehCopy` compares the copy's UNWIND_INFO with the original: identical outside the scope
  table, and every scope entry mapped by the rule above.
- The oracle accepts the original table's references into the original body, which stays
  intact.
- A tamper test sets a rebased entry back to the original address and must fail.

**Test.** `unwindtest` now:
- finds `main`'s frame by stack address (`_AddressOfReturnAddress`), not by comparing function
  entries with `&main`, which names the original once `main` moves;
- adds `Guarded`, whose `__finally` must run while the exception unwinds;
- catches in `main` through a filter function.

In copy and rebuild mode, on o2 and guardcf, the output is identical: the walk, the catch and
the termination handler. Dropping the copies' exception entries still breaks it.
`UnwindTests` requires at least two SEH functions to move with their own UNWIND_INFO.

**Coverage.** Share of code a no-op rewrite moves (o2):

| target | before steps 7–9 | now |
|---|---|---|
| speedtest1 | 99.6% | 99.8% (1,942 of 1,957 functions) |
| zopfli | 140 of 148 functions | 99.0% (142 of 148) |
| zopflipng | 81.0% | 99.6% (367 of 375) |

The rest is mostly the CRT's frozen `__GSHandlerCheckCommon` family, functions too short for a
trampoline, and 2 zopflipng functions with unsupported handler data.

## Step 10: front-end attribution of the padded layouts (Sep 2026)

VTune microarchitecture exploration (`Collect-TopDown.ps1`: 0.1 ms sampling, no multiplexing,
3 repeats) of each target's o2 build against its padded layout (`--blocks --jcc-erratum`,
the benchmarked binaries). The repeats agree to about ±0.3% in cycles and ±0.1 points in DSB
coverage. Averages:

| | speedtest1 o2 | padded | zopfli o2 | padded | zopflipng o2 | padded |
|---|---|---|---|---|---|---|
| cycles | 3.532 G | −4.2% | 3.583 G | −8.0% | 10.966 G | −16.2% |
| instructions | 6.519 G | −0.6% | 6.811 G | +1.8% | 21.011 G | +2.6% |
| CPI | 0.54 | 0.52 | 0.53 | 0.48 | 0.52 | 0.43 |
| **DSB coverage** | **44.5%** | **54.7%** | **72.2%** | **91.6%** | **50.1%** | **95.3%** |
| Front-End Bound | 27.2% | 23.2% | 28.2% | 13.6% | 36.9% | 11.3% |
| DSB switches | 4.3% | 3.1% | 6.6% | 1.7% | 6.5% | 1.0% |
| MITE bandwidth | 16.0% | 14.3% | 11.0% | 6.3% | 15.5% | 5.5% |
| ICache misses | 2.8% | 2.3% | 0.7% | 0.8% | 0.6% | 0.6% |

Reading:
- **The gain is the decoded ICache.** In step 4, layout alone lowered DSB coverage. With
  padding it rises on every target, to 95% on zopflipng, and front-end bound falls by 4–26
  points. The cycle savings follow the same order as the DSB gains and match the benchmarks.
- **Not fewer instructions.** zopfli and zopflipng execute 1.8–2.6% more instructions (the
  padding NOPs) and are still 8–16% faster: CPI falls from 0.53 to 0.48 and from 0.52 to 0.43.
- **Not the instruction cache.** ICache and ITLB misses barely change, except on speedtest1,
  the only target with a hot footprint larger than L1i.
- **Bad speculation and back-end bound rise in share.** These are fractions of pipeline slots:
  when the front end stops starving the machine, the remaining limits take a larger share of
  fewer cycles. It is not evidence of more mispredictions.

This closes the attribution question from step 4. WinBolt's gains on this CPU come from
keeping hot code DSB-resident, which on a JCC-erratum core means keeping branches off 32-byte
boundaries in a layout that has turned most taken branches into fall-throughs.

## Step 11: what trampolines cost, measured (Sep 2026)

A whole-binary rewrite (in-place, as BBT did for Windows) would keep block layout, splitting
and padding unchanged. It would add two things: no trampoline jumps, and no duplicate code.
The question was whether the first is worth a relinker.

**Estimate from the profiles.** Executed calls that still go through a trampoline in the best
layouts (`--blocks --jcc-erratum`):

| target | trampoline jumps | share of executed instructions |
|---|---|---|
| speedtest1 | 90,008 (82,700 from indirect calls) | 0.35% |
| zopfli | 43,780 | 0.15% |
| zopflipng | 17,453 | 0.04% |

The rest are calls from code that did not move.

**Measurement (throwaway, not a feature).** A speedtest1 variant of the best layout with every
pointer to a moved function aimed at its copy: 124 relocated data slots and 133 `lea` sites.
Together they cover all 82,700 profiled trampoline-bound indirect calls. This breaks the
one-value rule on purpose; the verify hash was unchanged, which decides nothing beyond this
binary. Redirecting the data slots alone covered only 7% of that traffic and measured nothing:
the hot targets (SQLite's record comparators) get their pointers from code.

| CPU cycles vs o2 (40 rounds) | run 1 | run 2 |
|---|---|---|
| best layout, trampolines | −4.07% [−4.26, −3.77] | −4.06% [−4.42, −3.69] |
| same, every pointer redirected | −4.26% [−4.47, −3.90] | −4.27% [−4.46, −4.13] |

**Conclusion.** The trampolines cost about 0.2% on speedtest1, the target with the most
indirect calls into moved code: less than the profile estimate, because a predicted
unconditional `jmp` is cheap. On zopfli and zopflipng it would be smaller still. A
whole-binary rewrite would not pay for itself in speed. It stays a later option for image size,
a single copy of each function and debuggability (OMAP), not performance.

## Step 12: WinBolt on top of MSVC PGO (Sep 2026)

BOLT is normally applied on top of compiler PGO. So far WinBolt was only compared against
PGO. This step applies it to the PGO builds of all three targets.

**What PGO builds needed:**
- **Split functions.** MSVC PGO moves each function's cold code into separate ranges.
  Functions with more than one range used to be refused: 712 functions (489 KB) in speedtest1.
  Now the entry (hot) range moves and the cold ranges stay (`Function.EntryBlocks`; every
  rewrite, layout, verifier and statistics path uses it). Cold code branches back into the
  original body, which stays intact past the trampoline. It keeps its chained unwind entries,
  whose parent is the original primary. `MovedFunction.Place` maps an address only if it moved.
- **Switch tables** whose cases PGO moved into a cold range: those entries keep their
  original addresses (writer, table check and oracle).
- **The oracle.** PGO builds have cold code the analysis does not discover: switch cases in
  leaf fragments, the known leaf jump table gap. That code jumps back into moved functions. Such
  references run the original body, which is correct: exactly the case §6.1's append strategy
  exists for. So the oracle now fails only for unknown references into a trampoline's 5 bytes.
  Deeper ones are counted as a warning (10 in PGO speedtest1).

No-op rewrite coverage of the PGO builds (share of all code bytes moved; split functions'
cold ranges stay by design):

| PGO build | before | now |
|---|---|---|
| speedtest1 | 32.6%, verification failed | 73.9%, verified |
| zopfli | 39.5% | 88.8% |
| zopflipng | 44.3%, verification failed | 76.9%, verified |

`Pgo_builds_move_their_split_functions_and_behave_identically` covers PGO zopfli and
speedtest1 in copy and rebuild mode.

**Profiles.** LBR traces of each PGO build: `artifacts/lbr-pgo-*.etl`, same workloads as
before. PGO already lays out blocks well, but it pays no attention to the JCC erratum:

| PGO build | fall-throughs (PGO → + our layout) | executed branches on 32-byte boundaries | padding NOPs (padding only) |
|---|---|---|---|
| speedtest1 | 80.6% → 83.5% | 21.0% | 0.82% |
| zopfli | 84.8% → 85.9% | 25.8% | 1.90% |
| zopflipng | 83.1% → 86.6% | 24.9% | 5.28% |

Variants:
- **PGO + padding:** `--profile --rebuild --jcc-erratum`: PGO's own block order, rebuilt with
  padding.
- **PGO + layout:** `--profile --blocks --jcc-erratum`: our block layout over PGO's.

All outputs are identical.

CPU cycles relative to o2, one session per target:

| candidate | speedtest1 (40 rounds) | zopfli (40) | zopflipng (20) |
|---|---|---|---|
| noise floor (copy) | −0.43% | +0.08% | +0.05% |
| MSVC PGO | −6.62% | −3.54% | −10.61% |
| **PGO + padding** | **−9.35%** [−9.62, −9.10] | **−12.05%** [−12.22, −11.67] | **−20.20%** [−20.46, −19.78] |
| PGO + our block layout + padding | −8.67% | −11.62% | −19.92% |
| o2 + WinBolt (`--blocks --jcc-erratum`) | −4.13% | −8.07% | −18.71% |

Reading:
- **The two compose.** On all three targets the best binary is PGO followed by WinBolt: 2.7
  to 9.6 points beyond PGO alone. On speedtest1, where PGO's inlining matters most, this is
  the first result better than PGO.
- **On a PGO build, keep PGO's block order.** Re-laying it out with our greedy chains is
  0.3–0.7 points worse than padding alone. What PGO misses is the erratum: 21–26% of its
  executed branches sit on 32-byte boundaries.
- **Recommended use:**
  - on a PGO build: `winbolt rewrite in out --profile etl --rebuild --jcc-erratum`;
  - on a build without PGO: `--profile etl --blocks --jcc-erratum`.

## Step 13: a third-party C++ binary, Factorio, and pointer redirection (Sep 2026)

**Target.** Factorio's `factorio.exe` (Steam, 43 MB, LTCG without PGO, static CRT, a matching
public-symbol PDB without linker fixups). Workload: its built-in benchmark
(`--benchmark <save> --benchmark-ticks 10000 --disable-audio`), timed by its own update time;
correctness by its game-state checksum. The LBR trace includes loading the save.

**What the binary needed first.** The statically linked CRT handlers (`__CxxFrameHandler4`,
`__C_specific_handler`) are named only by the PDB. Identifying them by exact PDB name (checked
at a .pdata start, tables still validated) took Frozen code from 63.8% to 0.7%. The no-op
rewrite then moves 98.9% of the code, verified. Fixes found on the way: stale in-copy jump
tables are int3-filled, thunk targets (`EntryJump`) bound leaf sweeps, and GS wrappers are
identified through jmp hops. The profile also gave no count to single-block functions (no
edges); straight-line runs now count the blocks they cross. Factorio's hottest indirect-call
targets are exactly such tiny virtual functions.

**Trampolines cost 5% here.** On speedtest1 they cost 0.2% (Step 11). Factorio makes most of
its indirect calls through vtables, and every one to a moved function went through a
trampoline: the no-op rewrite was +5.2% slower.

**Pointer redirection (`--redirect-pointers`).** §6.1's one-value rule is kept, not broken: a
function is redirected only if *every* way the image can form its address is known, and then
all of them are aimed at the copy, in copies and in original code alike
(`PointerRedirection.Plan`). Known forms are relocated 64-bit values (vtables, pointer tables,
`mov r64,imm64`) and RIP-relative `lea` in decoded code. Anything else excludes the function:
- a 32-bit RVA of it anywhere: data (except the exception table and chained unwind trailers,
  which only the unwinder reads), immediates and displacements;
- a possible RIP-relative operand in bytes nobody decoded (such an operand always has ModRM
  mod=00 rm=101 right before its disp32, so a byte scan finds every candidate);
- a RIP-relative operand other than `lea`, or a 32-bit absolute relocation;
- callers from outside the image: exports, the entry point, TLS callbacks, exception handlers
  and funclets.

The image must be DYNAMIC_BASE with relocations, so no absolute pointer can lack a relocation. A
CFG-enforced image redirects nothing, because its function table holds every target's RVA.

The verifier checks this independently of the writer: it enumerates, from the input, every
relocated value and `lea` that yields a redirected function and requires the copy's address
there (original sections and copies); after re-analysis, nothing in the output may still yield
a redirected original. Its oracle requires every linker reference to a redirected function to be
a redirected value, a redirected `lea` or a direct branch, and never an RVA. zopfli, speedtest1,
zopflipng, cxxehtest and the `/MT` builds pass that oracle, in copy and rebuild mode, and run
identically. Planning Factorio takes 0.7 s. The plan covers 96% of its profiled indirect calls
over the whole image, and 68% in the layout build: the rest go to functions the layout does not move.

**Results** (10000 ticks, 15 alternating rounds, one session, identical checksums):

| Factorio | vs original |
|---|---|
| no-op | +5.2% [+4.6, +5.6] |
| no-op + redirect | +1.5% [+0.6, +2.0] |
| `--profile .. --blocks --jcc-erratum` | −1.4% [−2.0, −1.0] |
| **same + `--redirect-pointers`** | **−5.0%** [−5.6, −4.5] |

Reading: on virtual-call-heavy C++ the trampolines ate most of the layout's gain;
redirection recovers it. It stays opt-in until more binaries have run with it. Still open
for Factorio: block layout inside FH4 functions (about 63% of its code is `cxx-eh-table`),
and a trace without the save load.

## Step 14: block layout inside C++ EH functions, Factorio (Sep 2026)

On Factorio, 32% of executed instructions are in `__CxxFrameHandler4` functions, which until now
kept their original block order (they moved only as byte copies, Step 7). `--layout-eh` reorders
the blocks of plain **unwind-only** FH4 functions (no try blocks, not separated, not a catch
funclet) and regenerates their tables (`Fh4Writer`):
- a new **IP-to-state map**: every instruction's original EH state at its new address, in ascending
  new RVA, one entry per transition. A dropped `jmp` (its target placed next) occupies no bytes and
  contributes no map point (`Fh4Writer.DroppedJump`).
- a new **FuncInfo4** pointing at it; the unwind map (destructor and unwind-funclet RVAs) is the
  original's, since those funclets do not move.
- a copy of the **UNWIND_INFO** naming the new FuncInfo4. A plain `__CxxFrameHandler4`'s handler data
  is exactly the FuncInfo4 RVA; a GS wrapper (`__GSHandlerCheck_EH4`) appends stack-cookie data,
  preserved verbatim (it is frame-relative).

A split function's FuncInfo4 is **separated**: one code piece for the hot copy (keyed at the copy
start) and one per cold segment (keyed at the cold start), because the CRT keys a separated
function's map by the code piece's own start (`FunctionEntry->BeginAddress`, which for a cold PC is
the cold chained entry's begin). Each piece's map is delta-encoded from its own start. The existing
empty chained cold entry is kept; the unwinder follows it to the primary for the handler but reports
the cold entry as the function entry, so the cold piece is selected.

The verifier re-parses the output's FuncInfo4, picks the piece for each instruction by its new
address, and requires the same state the original map gave it, plus the header (separated flag
matching the split), codes, handler and GS data copied verbatim. It caught, in development: a
dropped-jmp map point, dropped GS cookie data (a runtime `__fastfail`), and — via the runtime test —
that a single map is wrong for a split function (a cold-part throw missed destructors until the
separated map was added, keyed to the cold start).

cxxehtest reorders and splits its FH4 `Thrower` (a Tracker destructor runs while unwinding, through a
cold-keyed segment) and runs identically in copy and static-CRT (`/MT`) builds, with a negative
control (a stale map is rejected). Factorio: 4,366 functions laid out (was 2,703), 3,506 of them
split; 90% footprint 167 pages / 3,101 lines (reorder-only 189 / 3,095, previous best 176 / 3,291).
Across three same-session A/Bs (10000 ticks, 15-25 alternating rounds, identical checksums),
`--layout-eh` is consistently ~1.4 points faster than `--blocks --jcc-erratum --redirect-pointers`
(e.g. −5.7% vs −4.3%, −7.1% vs −5.9%). Splitting cuts the footprint further than reordering alone
(167 vs 189 pages), but any extra wall-clock gain over reorder-only is within this machine's noise;
kept because it is the correct separated form and helps footprint. Opt-in.

## Step 15: re-benchmark of the first three targets (Sep 2026)

Pointer redirection (Step 13) needed a profiler fix: straight-line runs now count the blocks they
cross, so a function that is a single basic block (a tiny virtual, invisible to the edge counts) gets
an execution count and C3 places it. That reordered which functions the layout moves, so the three
original targets were re-measured to confirm no regression. `winbolt bench` against the o2 build
(30 rounds, noise floor within ±0.4%, CPU cycles):

| target | `--blocks --jcc-erratum` | + `--redirect-pointers` | + `--layout-eh` | recorded (Step 8) |
|---|---|---|---|---|
| zopfli | −8.2% | −8.4% | — | −8.07% |
| speedtest1 | −3.9% | −4.4% | — | −4.13% |
| zopflipng | −18.5% | −18.6% | −18.6% | −18.71% |

The canonical `--blocks --jcc-erratum` numbers land on their Step 8 values: the profiler fix does not
regress these targets. It barely moves their layouts because they have few single-block hot functions,
unlike Factorio, where those tiny virtuals were a large share of the indirect-call traffic. The new
options confirm the same story: `--redirect-pointers` adds ~0.5 points on speedtest1 (it has real
indirect calls) and nothing on the plain-C zopfli or on zopflipng; `--layout-eh` is a wash on zopflipng
(its hot code is the zopfli C library, not the C++ EH paths). The trampoline and EH-layout costs these
options remove only bite virtual-call- and EH-heavy code such as Factorio.

## Step 16: Factorio profile window, trampoline-less moves, two jump table gaps (Sep 2026)

Three weaknesses showed in the Step 14 build's report.

**The profile measured the wrong phase.** The Factorio trace covers loading the save as well as
the 10000 timed ticks. Its hottest functions were save migration (`getFullMigrationResult`),
`inflate_fast`, `crc32_16bytes`, `Tile::load` and the stream reader. None of them runs in the
timed phase. `--profile-during <function>` (`EtwLbrProfile.Apply(during:)`) keeps, per process,
only the samples between the first and the last sample that touches the named function. It makes
two passes over the trace. With `?update@Surface@@QEAAXXZ` as the marker, the window is 4.3–9.9 s
and keeps 60.5% of the LBR samples. The loading functions leave the hot list, and the layout moves
1,848 functions instead of 4,481. The 90% footprint falls from 167 to 99 pages, now under the
assumed 128-entry I-TLB. The output is 2.3 MB smaller.

**Hot address-taken functions too short for a trampoline.** Factorio's hottest indirect-call
targets include identical-code-folded one-liners such as `asRemoteController` (3 bytes) and
`_Voidify_iter` (4 bytes). The gate freezes them (`trampoline-window`). A trampoline only serves
callers that hold the original address. When `--redirect-pointers` aims every pointer at the copy,
only direct branches from unmoved code still reach the original, and its body is intact. Such a
function now moves without a trampoline (`MovedFunction.HasTrampoline = false`). This applies when
the entry is too short or a branch target lies in the window, and the gate reason is the only one.
Otherwise it stays, with its exclusion reason. The verifier requires every such function to be a
redirected target, and never an export, the entry point, a TLS callback or an exception handler.
Its original entry must be unchanged. Moved this way: 11 functions in Factorio, 3–8 in each test
target. Profiled indirect calls that skip a trampoline rose from 68.9% to 95.9%.

**Jump tables after a noreturn call whose first byte does not decode.** In
`CraftingMachine::update`, `AlertCenter::update` and `GraphicsSettingsPresets::str`, the table
follows a call to a noreturn function. The first exploration decodes past the call and stops at
the table's first byte, which is not a valid instruction. Nothing overlapped the table, so the
second exploration with barriers (Stage 4) never ran, and the `undecodable` downgrade stayed. An
invalid instruction inside a recovered table's extent now triggers the second exploration too.

**Rounded-size index (the CRT's memmove).** memmove dispatches its tail copy on
`((n + 31) & ~31) >> 5`, with `n < 256` from the loop exit. Recovery now tracks an index of the
form `((x + c) & mask) >> k`, met backward as shifts, then masks, then an add. The bound on x
bounds the index arithmetically, since each step is monotone. All four memmove tables are
recovered (9 entries each, matching the data layout), and memmove is `FullyTransformable`.

Together these take Factorio's Frozen functions from 276 to 104. The layout now places 99.8% of
executed instructions (was 98.3%).

**Still open.** `luaV_execute` keeps `__ImageBase` in r9 across calls to a callee that LTCG knows
does not write r9 (MSVC's link-time register allocation). Proving the table needs an
interprocedural clobber analysis. It is 0.2% of executed instructions. Jumps through memory
(`attachInternal`, `WaitCondition::isFulfilled`) are unmodelled absolute-pointer tables.

**Results** (10000 ticks, 15 alternating rounds, one session, identical checksums; median of
per-round ratios, bootstrap 95% CI):

| Factorio | vs original |
|---|---|
| Step 14 best (`--blocks --jcc-erratum --redirect-pointers --layout-eh`, whole-trace profile) | −7.1% [−8.2, −4.3] |
| same, `--profile-during ?update@Surface@@QEAAXXZ` | −6.6% [−8.6, −5.9] |
| same + trampoline-less moves + both table fixes | **−7.2%** [−8.7, −6.6] |

Reading: all three are about 7% faster, and the differences between them are within this machine's
noise. The last build has the best median (5,070 ms vs 5,174 ms) and the tightest interval,
against the Step 14 build −1.8% [−3.1, +1.6]. The windowed profile gets the same speed from less
than half the moved code and 40% fewer hot pages. But it holds only ~54k LBR samples for 1,863
executed functions. A longer capture of the tick phase is the next step before reading more into
layout differences.

**Longer trace.** `artifacts/lbr-factorio-ticks.etl` holds 50000 ticks. Its window is 4.9–34.9 s,
keeping 89% of 658k LBR events. It profiles 2,286 executed functions, and 2,266 are placed (99.8%
of executed instructions). The 90% footprint is 108 pages. A second session with 15 alternating
rounds and identical checksums, against the original:

| Factorio | vs original |
|---|---|
| Step 14 best (whole-trace profile) | −6.5% [−7.8, −5.4] |
| short window + Step 16 fixes | −7.3% [−8.7, −5.7] |
| **long tick trace + Step 16 fixes** | **−8.2%** [−9.1, −6.5] |

Against the Step 14 build, the long-trace build is −0.7% [−2.6, −0.3], and the short-window build
with the fixes −1.6% [−1.9, −0.3]. Both are now outside the noise. The two tick-window builds do
not differ measurably from each other (−0.2% [−1.1, +1.7]). Recommended Factorio command:
`--profile lbr-factorio-ticks.etl --profile-during ?update@Surface@@QEAAXXZ --blocks --jcc-erratum
--redirect-pointers --layout-eh`.

## Step 17: a non-MSVC target, ripgrep: LLVM switch tables and default-less switches (Sep 2026)

The coverage survey (R2) showed LLVM and Rust builds freezing 13-53% of their code. ripgrep 15.0.0
(Rust, LLVM, static CRT, no PDB: the shape of most third-party software) became the first non-MSVC
rewrite target, in append mode (no PDB, so no fixup oracle: verification is the instruction-level checks
and re-analysis).

What had to change, in the order it blocked the result:

1. **Table-relative switch tables.** LLVM emits `lea b,[rip+T]; movsxd r,[b+i*4+d]; add r,b; jmp r`: signed
   entries relative to a base register, not MSVC's image-relative dwords. `JumpTableRecovery` proves the
   base (every base register's nearest write is the same `lea`), the signed load and the add, and
   (`BoundCheck`) skips the flag-neutral instructions a scheduler puts between the `cmp` and its `jcc`.
   The writers rebuild such a table in `.wbdata` with entries relative to itself and re-point every base
   `lea`. LLVM hoists one base into a register and reaches several tables by displacement, so the tables of
   one base move as one region (`TableUnit`), and a table is only moved when its base is addressed by no
   other instruction.
2. **Default-less switches.** Rust tells LLVM that the default of a `match` is unreachable, so the dispatch
   has no compare anywhere: the index comes from memory and is adjusted (`dec edx`, `add eax,-2`). No code
   analysis can bound it (an interval analysis was scoped and dropped after disassembling the failures).
   Since every real entry of a table is a valid in-function target, the extent can be read off the data
   instead: entries while they target the function, stopping at the next address any code references
   (`JumpTable.ExtentInferred`). That is sound for the target set (it can only over-approximate) and is
   accepted for the signed table-relative form only: MSVC always bounds its tables, so an unproven bound
   there is a gap in the analysis (allowing it broke the /MT fixup-oracle tests). ripgrep's hottest
   functions, the regex VM's opcode dispatch, were exactly this: 43% of its executed instructions.
3. **Thunk discovery.** A forward `jmp` whose skipped bytes are all padding is a thunk, not a rotated loop;
   otherwise re-analysis of the output swallowed a thunk's copy into the sweep of its neighbour.

Frozen share of code after these (and Step 18): ripgrep 53% -> 2.4%, lld-link 25% -> 1.8%, clang 25% ->
2.1%.

**Benchmark.** The first workload searched thousands of files: VTune showed the kernel's file system took
two thirds of the cycles (`rg.exe` was 31%), inside which the padded layout was already -9.7% cycles
(DSB coverage 26% -> 33.5%) but which the whole-process bench could not resolve (+/- 1.3%). A single
290 MB file with a regex-heavy pattern (0.65 s, noise floor 0.03-0.2%) resolves it; the trace was
recaptured on it. 20 rounds against the original:

| build | cycles |
|---|---|
| C3 function order only | -0.2% (noise) |
| `--blocks --jcc-erratum` | -3.0% |
| `--blocks --jcc-erratum --align-loops` | -4.05% |

Output is identical (hash) on both workloads and a third regex; 88.7% (99.1% after Step 18) of the executed
instructions are in rewritten functions. The gain is smaller than on zopfli/zopflipng (front-end bound
throughout) because ripgrep is largely data-bound in its SIMD search loops, and its whole-process front-end
bound (43-48%) is mostly the kernel's.

## Step 18: exception handlers without a PDB (Sep 2026)

A statically linked C++ runtime leaves `__CxxFrameHandler3/4` and `__C_specific_handler` unnamed, so every
function using them was frozen (`handler-data`). A handler that is still unidentified after export, import,
instruction-sequence and PDB-name identification is now classified by the handler data of **all** its users
(at least two): FH3 (`ParseFh3`: FuncInfo magic, tables parse), `__C_specific_handler` (a strict SCOPE_TABLE:
begin < end, jump target 0 or in a .pdata range, handler 1 or executable, a `__finally` has a funclet), FH4
(`ParseFh4` parses); every code address must lie in some .pdata range (a split function's cold fragments
are separate entries) and funclets in executable sections. One user that does not fit leaves the handler
unknown for everybody. msvcrt.dll's `__CxxFrameHandler` import is the FH3 handler under its old name.
The gate still validates the parsed tables against the discovered functions. Result: ripgrep 53% -> 11.5%
frozen (before Step 17), 7z.dll 47.5% -> 0%, IL2CPP GameAssembly 16-18% -> 1.2%.

## Step 19: FH3 functions move; block layout inside them (Sep 2026)

FH3 (`__CxxFrameHandler3`, emitted by MSVC before VS 2019 and by Rust) keys its IP-to-state map by
absolute RVAs, so a byte copy needs its own map. The survey: FH3 is 47.5% of 7z.dll, 45% of ripgrep,
11.9% of ELDEN RING, 8.6% of MGS V; modern MSVC emits FH4 instead.

* **Copies** (`FunctionRewriter.Fh3UnwindCopy`): a new UNWIND_INFO (verbatim to the handler data, GS cookie
  data kept) naming a 40-byte copy of the FuncInfo whose only change is the pointer to a new IP-to-state map:
  the same states, entries inside the function moved to the copy, entries elsewhere (the catch funclets that
  share the map) first, so the array stays sorted (copies sit above the original code). Unwind and try block
  maps and the unwind funclets are shared. A catch funclet returns a continuation address inside the original
  body, which stays intact past the trampoline, so execution continues there.
* **Catch funclets cannot move.** The runtime identifies a running catch funclet by its entry's BeginAddress
  being a `HandlerType.dispOfHandler`; a copy is not recognized and `FindHandler` aborts (found by the runtime
  test, exit 0xC0000409, not by the verifier). They are refused (`CxxEhParser.Fh3CatchHandlers`).
* **Block layout** (`Fh3Writer`, opt-in `--layout-eh`): a reordered and split function gets one map over the
  hot copy and every cold segment, one entry per state change along the new layout, each instruction (but a
  dropped `jmp`) keeping the state it had. Unlike FH4, catch continuations need no regeneration (they are
  absolute addresses in the funclet, into the original body), so functions with try blocks are laid out too.
* **Verification.** `CheckFh3Copy` / `CheckFh3Layout` re-parse the output: unwind info equal up to the
  FuncInfo pointer, FuncInfo equal but for the map, map sorted, states equal at every instruction.
  `Fh3Tests` and `Fh3LayoutTests` run cxxehtest built with `/d2FH4-` (`fh3`: imported handler, `fh3mt`: static)
  in copy, rebuild, shuffled and split modes and compare its output, with a negative control.
* **ripgrep**: a no-op rewrite now moves 97.5% of the code (was 48%), 99.1% of executed instructions are in
  rewritten functions; with `--layout-eh` 144 functions are laid out, 123 split, output identical. The speed
  does not change (-3.6% with either, noise floor 0.17%): the FH3 functions carry only about 10% of ripgrep's
  executed instructions. The value is coverage: 7z.dll, MGS V and ELDEN RING code that was refused now moves.

## Step 20: 7-Zip, an FH3 target with a real gain (Sep 2026)

7-Zip 26.01 (`7z.exe` + `7z.dll`, MSVC, FH3 handlers: 47.5% of the DLL's code, no PDB) is the target where
Step 19 matters. Workload: `7z.exe a -mx=5 -mmt=1` of 4 MB of text (1.03 s, deterministic archive); trace
`artifacts/lbr-7z.etl` (`tools/profile/Capture-7z.ps1`); only `7z.dll` is rewritten, the exe is a copy.
99.9% of the executed instructions are in rewritten functions (76 of 77); the archives are byte-identical
for every build. 20 rounds against the original (noise floor 0.04%, CI +/-0.25%):

| build (7z.dll) | cycles |
|---|---|
| C3 function order | -1.43% |
| `--blocks --jcc-erratum` | -5.85% |
| `+ --align-loops` | -6.00% |
| `+ --layout-eh` | -6.09% |

So a binary built by an older compiler, without a PDB, in append mode, gains about as much as the first
MSVC targets (-5% speedtest1, -8% zopfli). `--layout-eh` adds only 0.1 point here (10 more functions laid out).

## Step 21: a PDB for append-mode output (Sep 2026)

Only whole-program mode wrote a PDB (W4). An append-mode output kept naming the original PDB, whose
addresses describe the original code: the trampolines and stale bodies were named correctly, the copies
(where the program actually runs) were not, so stack traces and crash dumps of a rewritten binary showed
`sub_...` or nothing for every moved function. The same OMAP mechanism fixes it (`AppendPdb`,
`PdbWriter.WithOmap`, run by `rewrite` whenever the input has a PDB; `--no-pdb` skips it):

* OMAP_TO_SRC (rewritten -> original): identity over the original image (headers excepted: a record
  targeting RVA 0 means "no counterpart"), and each copy back to its original range: one record for a byte
  copy, one per instruction for a rebuilt function, hot and cold parts alike; a dropped `jmp` has no
  address of its own. Padding, rebuilt tables and the appended sections have no counterpart.
* OMAP_FROM_SRC (original -> rewritten): identity except the moved ranges, which map to their copies; a
  symbol at an original entry lands at its copy, so a breakpoint by name hits the code that runs.
* The CodeView record is retired after verification (a new GUID derived from the original's and the output's
  bytes, age 1, the new PDB's path or file name; the checksum is recomputed): the verifier compares the
  original sections with the input, and only that record and the checksum differ afterwards (tested).

Checked with WinBolt's loader (every function symbol at its copy or its original address: 126 of 126 on zopfli),
with dbghelp (`AppendPdbTests`: `SymFromName` gives the copy; `SymFromAddr` inside a copy, in shuffled and
split rebuilt functions too, gives the function and the original offset; the original entry keeps its name),
and by hand with cdb: `bp zopfli_a!ZopfliDeflatePart` hits, the stack reads `ZopfliDeflate+0xb7`,
`ZopfliGzipCompress+0x30c`, and the source line `deflate.c(814)` resolves for the copy.

## Step 22: profiles without branch records (Sep 2026)

Every result so far came from an LBR trace: an elevated ETW session on an Intel CPU with LBR, which rules
out AMD machines, most VMs and anyone who cannot run such a session. What a trace without branch records is
worth was measured on the existing traces: the LBR events carry the same periodic instruction-pointer
sample every ETW profile session takes (about 8 kHz), so `--ip-only` ignores the branch records and builds
the profile from those samples alone (`IpProfileBuilder`, fidelity `SamplingOnly`; opt-in and labelled in the
profile report: "block, edge and call counts are estimates, not measurements").

**The estimate.** A block's count is its most-sampled instruction's samples (`--ip-estimator max`, the
default; `mean` divides the block's samples by its instruction count), made consistent along straight-line
code (a block whose only way in or out is an edge to or from a block with no other way out or in runs as
often as it). Edge counts balance the block counts: each block's outgoing edges are scaled to its count and
each block's incoming edges to its own, alternately (iterative proportional fitting), over the edges whose
ends ran. Direct call counts are the count of the block holding the call; indirect targets are unknown.
A block no sample hit is cold only if the code leading to it was itself sampled at least 500 times, else
it is *warm* (a fraction of its predecessor): with too few samples the estimate proves nothing, and moving
code that runs to the cold part costs more than leaving code that does not run in the hot one.

**How wrong it is** (against the branch-record counts of the same traces): 30-55% of the blocks that
ran are unsampled, but they carry only 0.2-2% of the executed weight.

**What it gives**, 15-20 rounds against the original, the same rewrite options, the branch-record build for reference:

| target | branch records | IP samples only |
|---|---|---|
| zopfli (`--blocks --jcc-erratum`) | -7.98% | -8.40% |
| ripgrep (`+ --align-loops`) | -4.06% | -4.05% |
| 7-Zip 7z.dll (`+ --align-loops`) | -6.01% | -5.58% |
| speedtest1 (`--blocks --jcc-erratum`) | -4.66% | -2.4% |

So three of four targets reach the gain of the branch-record profile, and speedtest1 half of it. Two
constants matter: the estimator (mean: ripgrep -1.7%, max -3.0..-3.5% at the then constant of 16 samples) and the
evidence threshold (speedtest1: 16 samples -0.3% (the estimate's cold part moved code that runs), 100: -1.9%,
500: -2.2%, 2000: -2.4%; without splitting -2.1%). The interpreter is the case where samples are scarcest:
800 hot functions, one giant dispatch function, a few thousand samples.

The layout of an estimated profile also exposed a bug in the block rebuilder: iced fixes a branch to code outside
the encoded blocks (a tail jump to another function's copy) once, short or near, and cannot widen it when the
distance to that fixed target grows because instructions before it shrank; it failed with "branch distance is too
far away" (speedtest1, one function). Such branches are now emitted as fixed-size near forms and their
displacement is filled in after encoding (`externalBranches`).

**Capture without LBR**: `tools/profile/Capture-Lbr.ps1 -SamplingOnly` (the same session without
`-LastBranch`); the workload scripts pass their arguments through the `Capture-Lbr.ps1` parameters. Not yet tried
on a CPU without LBR (no such machine here): the measurements above use the samples inside LBR traces, which are
the same events.

## Step 23: residency of the output, branch mispredictions, the inlining ceiling (Oct 2026)

Three follow-ups to §6.1's dual-residency hazard and to Stages 7-8.

**`winbolt residency <input> <output> --profile <trace of the output>`** (`ResidencyMap`,
`ResidencyAnalysis`, `EtwLbrProfile.ReadRaw`, tests `ResidencyTests`). The moves are read off the output: a
`jmp rel32` at an input function's entry into code past the input's SizeOfImage is a trampoline; an entry
the output's exception table no longer begins at moved without one. Every IP sample and LBR record of the
output's trace is placed: appended code, trampoline, original body of a moved function, unmoved function,
other. Reported: time per place; trampoline traffic by source (branch kind at the LBR source, decoded from the
output) and, for indirect sources, the pointer-redirection status of the target (`PointerRedirection.Plan`
on the input: redirectable, the exclusion reason, the image-wide refusal, or no pointer found); unmoved
functions calling through trampolines and the hottest unmoved functions, with their safety level; and every
entry into an original body, explained as a return, a C++ catch continuation, a direct branch from unmoved
code, or **unexplained: a reference the analysis did not find**. That last case turns the one blind spot of
append mode (an undiscovered reference, harmless for correctness, §6.1) into something a trace of the output
shows.

First trace, speedtest1 `--blocks --jcc-erratum` (no redirection), `--memdb --size 25`
(artifacts/lbr-residency-speedtest1.etl, report artifacts/residency/residency-speedtest1.txt; a short capture,
4,615 IP samples and 191,292 records in the image): 98.7% of samples in appended code, 1.1% on trampolines, 0.17%
in unmoved functions (all FullyTransformable, cold in the training profile), **none in an original body**: no
entry into a moved function's old code, so no undiscovered reference on this workload. 4.9% of the records are
jumps into trampolines, 99.6% of them indirect calls and jumps from appended code to 65 functions, **all
redirectable** by `--redirect-pointers`; the rest comes from unmoved code. Step 11 measured what removing that
traffic is worth (0.2%); samples on a trampoline's jmp (1.1%) need not be cycles it costs: the
measured gain is the reliable number.

Factorio, the Step 16 build (`factorio-ticks.exe`: `--blocks --jcc-erratum --redirect-pointers --layout-eh`, ticks
trace), benchmark run with the save load (artifacts/lbr-residency-factorio.etl; reports
artifacts/residency/residency-factorio*.txt). `residency --profile-during` takes the same window as the rewrite
(the function is found in the input and followed to its copy). Whole run: 36% of samples in unmoved functions, all
in loading the save and the final checksum (`Tile::load`, `inflate_fast`, `LuaValueSaver`, `crc32`), which the
training window left out on purpose. **Inside the tick window: 97.2% appended code, 0.13% trampolines, 2.6%
unmoved, no original body executed.** Trampoline records are 0.10% of the image's records: 58% indirect calls
from appended code, 42% direct calls from unmoved code, mostly from Frozen functions (`attachInternal`: a jump
through memory; `SegmentedUnitAI::update`: uncovered bytes). Unmoved time: `CraftingMachine::update` 0.65%
(undecodable instruction) and ~1.1% in 2-4-byte address-taken virtual functions (`return 0`-style, Frozen
trampoline-window: no room for a jmp, and not every pointer to them is redirectable).

**What it found: a planner false positive.** The indirect traffic was excluded from redirection as "RVA in
data", but the matching words were UNWIND_INFO headers and unwind codes (`10 54 25 00`, save rbp, reads as
0x00255410 = `AssemblingMachineControlBehavior::prepare`). `PointerRedirection.Plan` now skips each UNWIND_INFO's
header and code array (no addresses by format; handler RVA and handler data are still scanned; test
`Unwind_codes_that_look_like_an_rva_do_not_exclude_it`, with the no-codes negative control). Same layout as Step
16: 752 functions redirected (was 746), 8 left alone (was 14), profiled indirect calls skipping the trampoline
96.3% (was 95.9%); verification passes. Too small to benchmark. The remaining one, `AssemblingMachine::canInsert`,
collides inside FH4 FuncInfo4 streams; skipping those needs the parser's byte extents (their destructor actions
are real RVAs), not worth it for 0.02% of the records.

**Branch mispredictions are not in ETW's LBR records.** Each entry is (from, to, info), 24 bytes; the info
qword, where LBR_INFO's MISPRED bit would be, is zero in all 12.5 million entries of lbr-zopfli.etl
(i5-9600K, which has LBR_INFO). Mispredict-driven transformations (if-conversion to `cmov`, choosing indirect
call sites to promote) need VTune's precise `BR_MISP_RETIRED.*` events per address.

**Leaf inlining has no measurable ceiling here.** A function can be inlined at a direct call site without
compiler knowledge when it has no frame (no .pdata), is FullyTransformable and single-range, never touches
`rsp` (arguments on the stack would be off by 8), has no calls, tail jumps, indirect jumps or tables, and ends in
plain `ret`; its register and flag effects are then exactly the call's. Executed calls to such functions,
from the training profiles, as a share of executed instructions (<= 64 bytes):

| target | all direct calls | inlinable leaf calls | blocked: callee has a frame | indirect calls, dominant inlinable leaf target |
|---|---|---|---|---|
| speedtest1 | 1.14% | 0.00% | 0.65% | 0.00% |
| zopfli | 0.72% | 0.04% | 0.47% | 0.00% |
| zopflipng | 0.25% | 0.01% | 0.17% | 0.00% |
| Factorio (ticks window) | 1.28% | 0.03% | 0.98% | 0.07% |

Each inlined call saves a call and a ret, so the ceiling is about 0.1% of instructions, far below the
0.5-1.5 point layout noise: not built. /O2 and LTCG already inline what has no frame. The calls left are to
functions with frames, whose inlining needs unwind-info merging and register allocation (compiler work), and
PGO's -4.3% instructions (Step 4) comes from that plus the optimizations inlining enables. Calls through import
thunks (`call thunk` -> `jmp [IAT]`: memcpy, memcmp, strlen in speedtest1, 0.3% of instructions) could become
`call [rip+IAT]` in rebuilt code, saving one predicted jmp each: by Step 11's measure (0.35% trampoline jumps,
0.2% gain) worth ~0.1%, also not built.

**CPU-specific instructions have no measurable ceiling here either.** MSVC targets the x64 baseline (SSE2), so a
rewriter could in principle substitute newer instructions. Executed shares (training profiles; Factorio in its tick
window):

| | zopfli | zopflipng | speedtest1 | Factorio |
|---|---|---|---|---|
| packed SSE, all | 1.48% | | | 4.25% |
| ...packed arithmetic (what AVX2 width would double) | ~0 | ~0 | ~0 | ~0.1% |
| shift by `cl` (BMI2 `shlx`/`shrx`/`sarx`: 1 uop vs 3) | 0.05% | 0.06% | 0.02% | 0.07% |
| widening `mul` (`mulx`) | 0.01% | 0.00% | 0.06% | 0.03% |
| scalar/packed FP multiply (FMA candidates) | 0.00% | 0.00% | 0.00% | 1.21% |
| `xmm` register-register moves (3-operand AVX) | 0.28% | 0.08% | 0.02% | 1.00% |

The packed SSE is moves and shuffles (struct copies, spills, `xorps` zeroing; Factorio: 2.5% `movaps`, 1% `xorps`),
not vectorized loops; widening a real SSE2 loop to AVX2 would be re-vectorization (trip count, remainder, alignment,
reductions), which the roadmap excludes. Register moves are eliminated at rename on this CPU. FMA rounds once instead of
twice: not semantics-preserving (and would break Factorio's lockstep checksums). Shift-by-`cl` to `shlx` is a legal
peephole but needs flags liveness (`shlx` sets no flags) and runs at most 0.07%. Hot code that profits from new
instructions already dispatches at run time (CRT `memcpy`/`memset`, 7-Zip). And the output would fault on CPUs
without the feature. Not built; it would pay only on a binary with hot auto-vectorized SSE2 loops (image, audio,
physics kernels), none among the targets.

## Step 24: longjmp and EH-continuation targets move (Oct 2026)

`/guard:ehcont` (with `/CETCOMPAT`) gives the image a `GuardEHContinuationTable`: the OS accepts an exception
continuation only at a listed RVA when user-mode shadow stacks are enforced (CET hardware). Append mode used to
leave every function holding a listed target (or a `GuardLongJumpTargetTable` entry) in place, since a copy would
continue at an address the table does not list. On the new `ehcont` variant of cxxehtest that kept the 5
functions doing all the C++ EH, 20% of its code.

Now (`GuardTables`): when the guard flags declare plain 4-byte entries, such functions move, and the output gets
new tables in `.wbdata`: every original entry (the original body stays intact and may still be continued into:
FH3 catch funclets return original-body continuations) plus each moved target's new address (an FH4 or SEH copy
continues in the copy), sorted; the load config's table pointer and count are re-pointed (the pointer field keeps
its base relocation). With flag bytes in the entries the old exclusion stays. The verifier allows only those 16
bytes of the load config to change and requires the output's tables to equal original ∪ mapped exactly.

Tests `EhContinuationTests` (cxxehtest and unwindtest, copy and rebuild): every continuation target lies in a
moved function, both addresses are listed, the table lies in `.wbdata`, the programs run identically; negative
control: the original table pointer restored fails verification. This machine (i5-9600K) has no CET, so the OS
does not enforce the table here: the run checks behaviour, the verifier checks the table.
`Build-Targets.ps1 -Variants ehcont -Targets cxxehtest,unwindtest`.

## Step 25: epilogue tail calls, in-place switch index adjustment; jumps through memory measured (Oct 2026)

What is still frozen, classified by the shape of the unresolved jump (scratch tool over the survey binaries):
"jump through memory" (absolute-pointer tables and memory-indirect tail calls) is at most 0.2% of code anywhere,
so it was not built. Two other shapes were large:

**Indirect tail calls in functions with interior addresses.** The tail-call rule (Stage 1) accepts an unexplained
indirect jmp only when no address inside the function can exist as a value (no lea into it, no relocation into
it, no `__ImageBase` load). Big C++ functions fail that, so their virtual tail calls froze them: MGS V's
`add rsp,20h; pop rbx; jmp [rax+80h]`. The x64 ABI marks these jumps: the OS unwinder recognizes an epilogue
(`add rsp,N` or `lea rsp,[..]`, pops) only when it ends in `ret`, a direct jmp, or an indirect jmp with a REX.W
prefix (`48 FF /4`), and MSVC and LLVM emit that prefix for epilogue tail calls. After the epilogue the frame is
gone, so the target is not a block of the function. `CfgConstructionPass.EndsEpilogue` accepts, per site, a REX.W
`FF /4` directly after a frame teardown in its own block. Check: of ~60,000 recovered switch dispatches in the
survey, none has that shape. Tests: `Rex_w_indirect_jump_ending_an_epilogue_is_a_tail_call`, negative control
without the teardown.

**Index adjusted in place.** MSVC (IL2CPP code) compares a `lea` copy and adjusts the index itself:
`lea ecx,[rax-5]; cmp ecx,7; ja default; add eax,-5; movsxd rcx,eax; ...`. `FollowIndex` treats `add/sub idx,c`
and `inc/dec idx` like `lea idx,[x+c]` (x is the register's earlier value), so the existing link from the compared
`lea` proves the bound. Tests: `Index_adjusted_in_place_like_the_compared_lea_is_bounded`, negative control with a
different amount.

Frozen share of code (`analyze`, survey binaries):

| binary | before | after |
|---|---|---|
| Vampire Survivors GameAssembly (IL2CPP) | 6.5% (8.9 MB) | **2.9%** (3.5 MB) |
| Factorio | 0.5% (220 fns) | 0.4% (207 fns) |
| MGS V | 5.3% | 5.3% |

MGS V's rest is protection code (opaque arithmetic, `pushfq` / `cmovp` / `jmp rdi`): Frozen is right.

## Step 26: indirect call promotion (Oct 2026)

How much there is (training profiles; indirect calls whose top target takes >= 90% of the calls, as a share of all
taken branches): Factorio 2.78% (1,027 sites), 7-Zip 2.82%, zopfli 1.11%, speedtest1 0.56%, zopflipng 0.27%,
ripgrep 0.

`--promote-calls` (`CallPromotion.Plan`: >= 90% and >= 16 records to one function entry in the image) rewrites
such a call in a rebuilt function as

```
lea  r11,[rip+V]      ; V: the value a pointer to T holds (its copy when --redirect-pointers redirected it)
cmp  <operand>,r11    ; the call's own register or memory operand
je   fast
call <operand>        ; the original call, unchanged
jmp  after
fast: call T          ; direct, to T's copy when T moved
after:
```

The callee of an indirect call is unknown to the compiler, so the call follows the ABI: r10/r11 and the flags
are volatile and carry no argument (r10 when the operand uses r11), and the direct call sees the same inputs.
Both return addresses lie in the same unwind segment. Not promoted: RIP-relative calls (imports, CFG dispatch),
images with XFG (hash in r10), functions with EH tables (they map return addresses to states), noreturn calls,
targets inside the caller. The verifier checks each sequence: lea of the expected value into r10/r11 not used by
the operand, cmp of the same operand, je to a direct call of the target (or its copy), the original call
unchanged, jmp to where the call returned.

Tests `CallPromotionTests` (zopfli): all planned sites promoted, verified, identical output; a build promoting
every site to a **wrong** target still compresses identically (each guard falls back to the original call);
negative control: the compare value one off fails verification.

7-Zip (`--blocks --jcc-erratum`, each build at 4 layout shifts, 15 rounds): 10 sites promoted (99.9% of profiled
indirect calls now direct), archives identical. Cycles vs the original: layout -5.62%, **+ promotion -6.40%**;
promotion vs the same layout without it **-0.95%, 95% CI [-1.14, -0.51]** (that session's noise floor was wide,
±1.2%); repeated in a later session with 20 rounds: **-1.31%, CI [-2.16, -0.49], clears the noise floor**
(artifacts/bench-icp/bench-7z.txt). zopfli (5 sites, 1.1% of taken branches): -0.11%, CI [-0.34, +0.06], noise.
Opt-in: worth it where dominant indirect calls are a few percent of taken branches (7-Zip, Factorio).

## Step 27: startup order and a page model (Oct 2026)

Every layout so far serves a steady loop (cycles in a benchmark). A short run or a program's startup pays for
something else: the code pages it touches, each a page fault, a hard one on a cold file cache. C3 groups code
by heat, not by when it first runs, so startup code stays spread over the image.

* `rewrite --order first-use` (`EtwLbrProfile.FirstTouch`, `FunctionOrdering.FirstUse`): every function the first
  bound run touched, in the order it first ran (each its own cluster). With `--blocks`, cold blocks still go
  after all hot code.
* `rewrite --page-model` (`EtwLbrProfile.FirstTouches`, `PageModel.Curve`): the first run's distinct code touches,
  in time order, replayed through the original and the new layout (moved code at its new place; a branch from
  unmoved code into a moved entry also touches the trampoline's page). Prints distinct code pages touched by
  1/10/25/50% of the run's duration and in all. A model: it sees sampled code only.
* `bench` reports page faults per run (`GetProcessMemoryInfo`) and has `--copy-beside` (the noise-floor copy next
  to the baseline, for programs that find their data there).

Page model, code pages touched (4 KB):

| | 1% | 10% | 25% | 50% | all |
|---|---|---|---|---|---|
| speedtest1 original | 60 | 89 | 117 | 136 | 202 |
| speedtest1 `--blocks` C3 | 31 | 45 | 61 | 77 | 110 |
| speedtest1 `--blocks --order first-use` | **15** | **28** | **39** | **50** | **95** |
| Factorio original (whole trace: startup, save load, 10000 ticks) | 151 | 487 | 987 | 1,797 | 1,951 |
| Factorio `--blocks --jcc-erratum` C3 | 120 | 372 | 547 | 720 | 796 |
| Factorio `--blocks --jcc-erratum --order first-use` | **36** | **160** | **293** | **562** | **669** |

Measured: speedtest1's page faults do not separate the layouts (4,668 vs 4,669 per run, both +430 over the
original for the appended sections): the run touches all its hot code anyway, and Windows maps image pages in
clusters, so soft faults are not one per page. Factorio startup (`--benchmark SpaceAgeCleanGleba.zip --benchmark-ticks 1`: startup, save load, one tick;
~5 s; 12 rounds, warm file cache; candidates in bind, `bench --copy-beside`; artifacts/factorio/bench-startup.txt):
cycles C3 -1.29%, first-use -1.48%, **first-use vs C3 -0.06%, CI [-0.44, +0.61]**; page faults equal (~301,000 per
run, nearly all data). With a warm cache the 4x fewer early code pages are worth nothing measurable. Where it would
pay is a cold file cache (hard faults, ~0.1 ms each from SSD); measuring that needs the standby list flushed
(elevated) before every run: not done. `--order first-use` stays an option, C3 the default.

## Step 28: stale profiles (Oct 2026)

A trace binds only to the exact image it was recorded on (Stage 2: SizeOfImage, TimeDateStamp). Every rebuild
needed a new elevated capture. `rewrite new.exe out.exe --profile old.etl --profile-binary old.exe`
(`StaleProfile.Transfer`, Core) applies the trace to the binary it was recorded on and carries it over:
functions by unique PDB name (else a unique content hash), blocks by entry, then by strict content hash
(opcode forms, registers, non-address immediates and displacements), then loose (mnemonics), equal-sized hash
groups paired in address order; edge counts to the edge between matched blocks, block counts recomputed (at
least the source block's), call counts by position among the block's calls, indirect targets through the
function match. Nothing is guessed: unmatched counts are dropped.

| from o2 zopfli's trace to | functions matched | executed instructions carried | edge executions carried |
|---|---|---|---|
| the same build (self) | 62 / 62 | 100% | 100% (every count identical: test) |
| a build with a volatile counter added to `ZopfliFindLongestMatch` (the hottest function) | 59 / 62 | **99.6%** | **99.6%** |
| the `/guard:cf` build (every indirect call rewritten) | 57 / 62 | 89.1% | 91.9% |
| the LTCG build (other inlining) | 27 / 62 | 44.8% | 36.4% |

The modified build is `artifacts/targets-mod` (source copy `artifacts/zopfli-mod`, built with
`Build-Targets.ps1 -Zopfli <copy> -Output artifacts/targets-mod -Variants o2 -Targets zopfli`). Tests
`StaleProfileTests`: self transfer reproduces every block, edge and call count; the modified build's trace binding
is refused (`ProfileBindingException`), the stale transfer carries > 95%, the layout verifies and compresses
identically. 

Benchmark (`--i5` on zopfli-input.bin, each layout at 4 layout shifts, 15 rounds, cycles): the modified build laid out
with the stale profile **-10.88%** [-11.10, -10.31] against the modified build itself; for reference the fresh profile
on the original build gives -8.41% against the original (the modified baseline is slower: its volatile store is in the
hot loop, so the two percentages are not a ranking). A stale profile is as good as a fresh one here.

## Step 29: JCC padding on a CPU without the erratum (Oct 2026)

Step 4's open question ("revisit padding's cost on a CPU without the JCC erratum"), answered on the test box (Intel
N100, Gracemont: no uop cache, so nothing for the erratum to hurt). The builds are the dev-box ones, laid out from
the i5-9600K traces (`artifacts/lbr-zopfli.etl`, `lbr-zopflipng.etl`); only the benchmark ran on the N100
(`winbolt bench`, 20 rounds, cycles, noise floor -0.31% / -0.05%).

| target | `--blocks` vs o2 | `--blocks --jcc-erratum` vs o2 | jcc vs `--blocks` |
|---|---|---|---|
| zopfli (`--i5`, zopfli-text2.bin) | -3.23% [-3.73, -3.04] | -1.46% [-1.92, -1.17] | **+1.99%** [+1.60, +2.25] |
| zopflipng (256.png, 5 iterations) | -3.30% [-3.57, -2.93] | -1.46% [-2.08, -0.95] | **+1.74%** [+1.53, +2.18] |

Page faults unchanged. Results:

* The profile and the block layout transfer: `--blocks` alone still wins on the N100 (-3.3%, against -8 to -19% on
  the i5, where part of the gain was DSB coverage, Step 10).
* The padding is a net loss where the erratum does not apply, about the size of its executed-NOP overhead (zopfli
  1.74%). That explanation is a hypothesis: not tested (instruction counts, layout-shift averaging). Gracemont having no
  uop cache is from vendor documentation, not verified here.
* Same-input raw speed for reference: `zopfli-o2 --i5 zopfli-text2.bin` 0.703 s on the i5-9600K, 0.870 s on the N100
  (1.24x), identical output.

Consequence: `--jcc-erratum` stays opt-in, documented in the Manual as for affected cores only. Possible later: choose
it from CPUID at rewrite time. AMD and Ice Lake+ cores (uop cache, no erratum) are unmeasured.

---

# Stage 7 — Binary Specialization

Profile + hardware aware.

Possible optimizations:

* remove runtime CPU dispatch (the advisor reports candidates; the dispatching code is already hot-path
  CRT/library code and was not worth removing, Step 23)
* specialize for AVX2 machine (measured, not built: AVX2-width, BMI2 and FMA candidates are <= 0.1% of
  executed instructions on the targets except Factorio's FMA candidates at 1.2%, which change results; Step 23)
* remove unused compatibility paths
* direct-call specialization

Still avoid speculative optimizations.

---

# Stage 8 — Research Optimizations

Reserved for experimental work.

Examples:

* peephole optimizer
* instruction substitutions
* FMA generation (measured, not built: changes rounding, breaks Factorio's checksums; Step 23)
* BMI instruction replacement (measured, not built: <= 0.07% of executed instructions; Step 23)
* function cloning
* speculative devirtualization
* profile-guided indirect call promotion (built: `--promote-calls`, Step 26)

Automatic vectorization intentionally excluded from early roadmap.

---

# 9. Validation Framework

Validation is a first-class subsystem.

Every optimization pass must provide validation.

Validation layers:

## Structural

* valid PE
* valid headers
* valid relocations
* every structure in §5.4 re-derived from the emitted image and compared against what the
  transformation implies — `.pdata` sort invariant, `.xdata` chaining, CFGuard tables,
  TLS callbacks, delay-load descriptors, checksum

Structural and control-flow validation carry more weight than runtime testing here,
because they do not depend on test coverage (§R3).

## Control Flow

* identical CFG where expected
* reachable block verification
* jump table targets resolve to real block entries in the emitted image

## Runtime

Automated execution of test corpus.

Compare:

* output
* exit code
* exceptions

Comparison must normalize for legitimate run-to-run variation — ASLR-dependent addresses,
timestamps, thread interleaving, and any address printed by the program itself. A
comparison harness that flags these as differences will be disabled by its users within a
week, which is worse than not having one.

## Differential

Original binary

↓

Optimized binary

↓

Compare outputs

---

# 10. Test Corpus

Maintain growing collection, spanning both source language **and producing toolchain** —
the two vary independently, and §5.2 shows the toolchain is what determines code-address
table encoding:

* C and C++ via MSVC
* C and C++ via clang-cl and MinGW, which produce PE through a different backend
* Rust (LLVM)
* Go, which uses its own backend and its own switch lowering
* Delphi
* NativeAOT

Include:

* exceptions
* TLS and TLS callbacks
* CFGuard, XFG, and `/guard:ehcont`
* COM
* plugins
* DLLs
* dense and sparse `switch` dispatch, plus the many-cases-share-a-target shape that
  triggers MSVC's two-level table — the corpus must cover every encoding in §5.2, not
  merely "a switch"
* computed `goto`, where the toolchain supports it
* binaries built with `/LTCG:PGO`, which arrive with functions already hot/cold split
* functions whose address is taken and compared, to exercise §6.1 trampolines

First rewriting targets (Sep 2026), built from source by `tools/targets/Build-Targets.ps1`
in several variants (`/O2`, `/O2 /guard:cf`, later PGO). Source access gives a baseline:
compiler PGO is what WinBolt must be measured against (§1.1).

* **zopfli**, the correctness target: small C, fully deterministic output, so a rewritten
  binary must produce byte-identical files. Its hot code fits in L1i, so an honest
  performance result is zero.
* **SQLite's speedtest1**, the performance target: about 1.2 MB of code with a bytecode
  interpreter (a large switch, recovered), and SQLite's own deterministic benchmark.
* **zopflipng** (C++, same tree), later, for C++ exception tables.

Stress tests:

* tiny binaries
* very large binaries
* heavily optimized
* LTCG
* stripped binaries

---

# 11. Pass Registration

Modularity is a goal (§3.4). Dynamic assembly loading is one implementation of it, and
the wrong one to start with.

Stabilizing a pass API across `AssemblyLoadContext` boundaries costs versioning
discipline and debugging friction from the first commit, and buys isolation that nobody
needs while all passes ship in the same repository. The claim that "new passes require no
framework modifications" will not survive first contact regardless: pass ordering,
dependency declaration, and IR extension all force framework changes during Stages 1–5,
and a hardened plugin boundary makes each of those changes more expensive rather than
less.

**Stages 1–5: attribute-based registration within the main assembly.**

```
Passes/

Analysis/

Optimization/

Validation/

Reports/
```

The directory structure stays. Passes are discovered by attribute at startup, declare
their dependencies and required profile fidelity (§Stage 2), and are ordered by the
framework. This delivers the experimental modularity §3.4 asks for, with none of the
boundary cost.

**Later: dynamic loading**, once the pass API has stopped moving and there is a concrete
reason to run third-party passes out of tree. Designing the attribute contract with that
eventual move in mind is cheap; implementing it now is not.

---

# 12. Reporting

Reports should be readable by humans.

Example:

```
Top Hot Functions

Potential CPU Dispatch

Cold Branches

Instruction Mix

Layout Opportunities

Inlining Candidates

Dispatch Candidates
```

Reports should explain confidence.

Example:

```
Confidence:

High

Medium

Experimental
```

---

# 13. Relationship with WPA

WinBolt does not attempt to replace WPA.

| WPA              | WinBolt                |
| ---------------- | ---------------------- |
| Scheduling       | Binary layout          |
| Context switches | Function placement     |
| CPU utilization  | Branch optimization    |
| Wait analysis    | Devirtualization hints |
| Thread analysis  | CPU dispatch analysis  |
| Lock contention  | Binary specialization  |

Workflow:

```
ETW

↓

WPA

↓

WinBolt

↓

Optimization report

↓

(optional)

Optimized binary
```

---

# 14. Future Directions

Potential research modules:

* NativeAOT support
* ReadyToRun support
* PDB rewriting — **done**: append mode writes `<output>.pdb` with OMAP (Step 21), whole-program mode writes
  one from the fixups (W4)
* ARM64
* Intel PT — feasibility checked (2026-10-18), not built. Not as a profile source: sampled LBR (and even
  `--ip-only`, Step 22) already gives layouts within noise, while PT costs ~100+ MB/s per thread, slow decoding and
  is Intel-only. Proposed uses:
  * **Dynamic oracle for append-mode outputs without a PDB** (ripgrep, 7z.dll, IL2CPP), where the fixup oracle
    cannot run: every executed indirect target and return of a traced output must land on a mapped instruction
    boundary in moved code, never inside a moved function's original body. An exhaustive version of `residency`'s
    sampled check, for the traced windows only.
  * **Observed targets for analysis gaps**: TIP targets at `Frozen` `indirect-branch` sites and inferred-extent
    switch tables (`JumpTable.ExtentInferred`) show which shapes are missed. A lower bound only: guides work,
    never makes a function transformable.
  * Exact first-use order (Step 27), and per-block cycle cost (CYC packets) for layout-noise attribution.

  Probe results on the dev box (i5-9600K; no hypervisor, VBS off): CPUID has PT, ToPA, CR3 filtering and 2 IP filter
  ranges. The inbox `ipt.sys` (demand-start, `sc start ipt` elevated) answers WinIPT's IOCTLs (0x220004 request,
  0x220006 read trace, 0x30-byte input buffer; process trace started on a suspended process). A zopfli o2 trace
  parsed with 0 resyncs, and all 161,584 TIP/FUP IPs lay in loaded modules (154k in zopfli.exe). Limits: the driver
  returns a **snapshot of a per-thread ring buffer** (`TopaPagesPow2`, 2 MB = ~7.8M conditional branches, ~10-20 ms
  of zopfli; up to 128 MB), not a stream, so traces are windows. Overflow (OVF) packets occur under load and need
  resync. Next step if pursued: a decoder that walks WinBolt's own CFG with TNT bits / TIP targets (IP filter = target
  module, TIP.PGE/PGD at entry/exit), no libipt dependency (§3.3); first check that TNT bits match the CFG exactly.
* Intel LBR — **done**: the Stage 2 profile path (ETW with LBR stacks); `--ip-only` covers CPUs without it (Step 22)
* ML-assisted optimization ranking
* Binary diff visualization
* Source-level optimization recommendations
* Continuous integration regression analysis

---

# 15. Success Criteria

Stage 1 should report what fraction of hot code is transformable at all, so the value of
Stages 5–6 is known before they are built.

Stage 2 should demonstrate an edge-accurate profile capture path on a real binary. Failure
here changes the roadmap (§R1).

Stage 3 should already provide value without modifying binaries.

Stage 4 should produce a rewritten binary that is bit-for-bit justifiable — every changed
byte explained by a relocation, a RIP-relative fixup, or a structure listed in §5.4.

Stage 5 should demonstrate performance improvements on front-end-bound workloads that
clear a measured noise floor, and should honestly report no change on workloads that lack
front-end headroom.

Stage 6 should establish parity with the core capabilities expected from a BOLT-like optimizer on Windows.

The long-term objective is to provide a stable platform for binary optimization research rather than a fixed set of optimization passes, allowing new analyses and transformations to be added as independent modules while maintaining a strong validation story.

---

# 16. Risks and Open Questions

## R1. Profile fidelity — highest risk

Stages 5 and 6 need edge-accurate profiles. IP sampling cannot supply them (§Stage 2), and
hardware branch capture on Windows is materially harder to build than an ETW sampling
session. If that capture path proves impractical, Stage 6 does not happen in its current
form and Stage 5 degrades to coarse hot/cold partitioning.

Mitigation: prove the edge-accurate capture path early, in Stage 2, before Stages 3–4
build a roadmap on top of it. This is the one item worth prototyping ahead of its
scheduled slot.

## R2. Indirect branch coverage

The fraction of functions that survive the safety gate as `FullyTransformable` is unknown
until measured on real binaries. If jump table recovery and indirect target analysis leave
most hot functions `Frozen`, Stage 6's ceiling is low regardless of how well the
transformation itself works.

Open question: what is that fraction on a representative corpus? This is measurable at the
end of Stage 1 and should gate the decision to invest in Stage 6.

Measurements (Sep 2026), share of code bytes at each level. The last three columns are
the current state, with jump table recovery and code-pointer tracking:

| Binary | Fully, every handler frozen | Fully, handlers + SEH | Fully, + C++ EH | Fully, + jump tables | `RelocatableOnly` | `Frozen` |
| --- | --- | --- | --- | --- | --- | --- |
| `notepad.exe` | 37.6% | 94.9% | 94.9% | 94.9% | 2.1% | 0.0% |
| `ntdll.dll` | 59.9% | 81.0% | 81.0% | 81.0% | 14.6% | 0.7% |
| `kernel32.dll` | 47.3% | 76.8% | 76.8% | 80.0% | 12.0% | 1.8% |
| `edgehtml.dll` | 75.8% | 91.1% | 91.2% | 92.3% | 1.6% | 0.9% |
| `sqlncli11.dll` (BBT) | 24.2% | 33.8% | 34.3% | 41.0% | 28.8% | 8.2% |
| `ActivationManager.dll` | | | 62.0% | 62.0% | 31.4% | 0.0% |
| `nvcuvid.dll` (NVIDIA) | | | | 77.9% | 0.0% | 14.8% |

(Percentages are of all executable bytes; the rest of each row is padding, data, and
unattributed bytes.)

In the first column, handler data dominated. In the Windows binaries, most handler
functions use `__GSHandlerCheck`, whose data is a frame offset and holds no code addresses.
It is statically linked and unnamed without a PDB, so it is recognized by its exact
instruction sequence. The GS wrappers (`__GSHandlerCheck_SEH`, `_EH`, `_EH4`) are recognized
structurally: they call exactly the verified `__GSHandlerCheck` helper and one identified
inner handler, and nothing else, so their data starts with the inner handler's table. Every
identification was checked against Microsoft's public symbols for `ntdll.dll`,
`kernel32.dll`, `AADAuthHelper.dll` and `ActivationManager.dll`: 20 handlers, none
misidentified, one wrapper conservatively left unidentified.

C++ EH and SEH functions end up `RelocatableOnly`, not `FullyTransformable`: every code
address in their tables is known and checked, so they can move as a unit with the tables
rebased, but block reordering would have to regenerate IP-to-state maps and keep try
ranges contiguous. That is now the largest share not `FullyTransformable`, and making it
transformable is a Stage 6 cost (table regeneration), not an analysis gap.

`Frozen` code is under 2% except in `sqlncli11.dll` and `nvcuvid.dll`. On the Microsoft binaries, what remains frozen is mostly functions whose ranges hold bytes
disassembly never reached, plus register-indirect jumps whose table the recognizer could
not prove, for example because the image base was loaded in a different block (that
needs real dataflow, not a backward walk).

### Coverage survey across toolchains (Sep 2026)

Until now every rewrite target was built with MSVC. A survey ran `winbolt analyze` on 20
third-party x64 binaries: games on six engines, Chromium/Electron, LLVM tools, Rust, MinGW and
MSVC applications. Share of code by safety level:

| binary | toolchain | MB | PDB | Fully | Reloc. | Frozen (before) | main non-Fully reason |
|---|---|---|---|---|---|---|---|
| factorio.exe | MSVC LTCG | 42 | yes | 33.1% | 63.3% | 0.4% (0.5%) | C++ EH tables (FH4) |
| UnityPlayer.dll (2 games) | MSVC | 25-32 | no | 95-97% | 0.1-0.6% | 0.5-1.6% (0.6-2.2%) | - |
| GameAssembly.dll (Unity IL2CPP, 2 games) | MSVC | 62-174 | no | 80-82% | 11-15% | 1.2-2.9% (16-18%) | C++ EH tables (FH4) |
| Brotato.exe (Godot) | MSVC | 32 | no | 97.3% | 0.1% | 1.1% (1.1%) | - |
| SlayTheSpire2.exe (Godot) | lld | 853 | no | 97.0% | 0% | 1.4% (17.4%) | uncovered bytes |
| mgsvtpp.exe | non-Rich linker | 159 | no | 15.5% | 7.0% | 5.3% (5.3%) | C++ EH tables (FH3) |
| eldenring.exe | MSVC, protected | 83 | no | 45.7% | 12.6% | 15.7% (26.9%) | C++ EH (FH3), handler data |
| Code.exe (VS Code, Electron) | clang-cl + lld | 224 | no | 94.0% | 0.1% | 3.6% (14.6%) | falls off range, handler data |
| libGLESv2.dll (ANGLE) | clang-cl + lld | 8 | no | 95.4% | 0.9% | 1.6% (13.3%) | C++ EH tables |
| clang.exe | LLVM | 100 | no | 96.4% | 0.2% | 2.1% (25%) | uncovered bytes, falls off range |
| lld-link.exe | LLVM | 68 | no | 97.0% | 0.1% | 1.8% (25%) | uncovered bytes, falls off range |
| rg.exe (ripgrep) | Rust (LLVM), static CRT | 5 | no | 49.7% | 45.3% | 2.4% (53.2%) | C++ EH tables (FH3) |
| libvlccore.dll, git.exe, libcurl | MinGW GCC | 0.5-3 | no | 96-98% | 0% | 0-1.1% (7-24%) | - |
| 7z.dll | MSVC, msvcrt.dll CRT | 2 | no | 50.0% | 47.5% | 0% (47.5%) | C++ EH tables (FH3) |
| python38.dll | MSVC PGO | 4 | no | 97.1% | 0% | 1.3% (1.3%) | - |

The last column's parenthesis is the first survey (before the three fixes described below);
"Reloc." is `RelocatableOnly`, code that moves as a unit with its tables rebased. Re-run with
`tools/survey/Survey.ps1` (needs a Release CLI build).

The 32-bit `Loop Hero` was skipped. Of the 56 games in this Steam library, 23 ship 32-bit main
executables, mostly older or lighter titles.

**Update (Sep 2026): items 1 and 2 below are done.** LLVM switch tables (item 1) and handlers without a
PDB (item 2) are recognized (Steps 17 and 18); the Frozen column above is the result: 25% -> 2% for the
LLVM builds, 53% -> 2.4% for ripgrep, 47.5% -> 0% for 7z.dll, 16-18% -> 1-6% for IL2CPP. What is still
frozen is mostly code the disassembly does not reach (`uncovered-bytes`, `falls-off-range`), and the
protected ELDEN RING. FH3 C++ EH (7z.dll, ripgrep, MGS V, ELDEN RING: 9-48% of their code) now moves as
copies (Step 19).

**Update (Oct 2026, Step 25):** epilogue tail calls (REX.W indirect jmp after the frame teardown) and switch indexes
adjusted in place: Vampire Survivors' GameAssembly 6.5% -> 2.9%, Factorio 0.5% -> 0.4% (only these two rows
re-measured).

Findings, by how much code each would unlock:

1. **LLVM's switch encoding is not recognized.** Dispatch is `lea b,[table]; movsxd r,[b+idx*4];
   add r,b; jmp r`: signed offsets from the table's own address, where MSVC's are image-relative.
   The walk rejects the load ("does not load a dword..."). Where the function also has no
   `__ImageBase` load, the jump is taken as a tail call. Either way the case blocks stay
   unreached, and the function is frozen as `uncovered-bytes`: 11–22 MB of code in each large
   LLVM binary, about 15–25% of clang, lld, VS Code, ANGLE and a Godot build. This is a new
   encoding for `JumpTableRecovery`: table base from the `lea`, the `movsxd` load, and
   table-relative targets.
2. **Exception handlers without a PDB.** A statically linked C++ runtime (Rust with a static
   CRT, IL2CPP's GameAssembly, clang) leaves `__CxxFrameHandler3/4` and `__C_specific_handler`
   unnamed, so every function using them is frozen (`handler-data`). This is 53% of ripgrep and
   16–18% of the IL2CPP game code. Factorio got past this only because its PDB names them.
   Candidates:
   - identify handlers by their data: FH3's FuncInfo carries a magic number, and FH4's header
     either parses consistently across all users or not;
   - or by code signature, as `__GSHandlerCheck` already is.
   7-Zip's `__CxxFrameHandler`, imported from `msvcrt.dll`, is the older FH3-format handler
   under another name.
3. **No PDB for any third-party binary except Factorio.** Whole-program mode needs fixup
   records, so it stays a mode for builds you make yourself. Append mode is the path for
   everything else, and discovery without symbols has to carry the load.
4. **32-bit x86** is common among older games. It has no `.pdata`, and x86 SEH lives on the
   stack: a separate port, lower priority than 1 and 2.

The Fully/Frozen split is the analysis ceiling, not the speedup. Factorio is only 33%
FullyTransformable and still gained 8%, because its RelocatableOnly code moves as copies and
the hot code is what counts. But frozen code cannot move at all, and items 1 and 2 are most of
what freezes code outside MSVC builds.

## R3. Validation completeness

Differential testing proves only what the corpus exercises. A rewritten binary that passes
every test can still fail on an untested path — and binary-level bugs concentrate in rare
paths: exception unwinding, indirect dispatch, thread-local access on secondary threads.

The append-a-new-section strategy (§6.1) is the primary structural mitigation, since
undiscovered references still reach correct original code. Structural and control-flow
validation (§9) matter more than runtime testing precisely because they do not depend on
coverage.

Open question: is CFG-equivalence checking strong enough to serve as the primary gate,
with runtime testing as corroboration rather than the main evidence?

## R4. Measurement noise

Discussed in Stage 5. The risk is not that improvements fail to materialize but that noise
is mistaken for improvement, and the project builds on a result that is not real.

## R5. Managed and hybrid binaries

NativeAOT and ReadyToRun images appear in the corpus (§10) and in future directions (§14),
but their metadata and GC information impose constraints this document has not analysed.
Treat any NativeAOT result before that analysis exists as unvalidated.

### NativeAOT survey (Oct 2026)

**Population on this machine.** A scan of Program Files, AppData, the NuGet cache, the Steam library and
D:\aplikacje for the `DotNetRuntimeDebugHeader` export (every NativeAOT image since .NET 7 has it) found
only .NET 10 builds: `ilc.exe` itself (14.6 MB, Microsoft-built, no PDB) and the RgDotnet.Cli builds of
the sibling ripgrep-dotnet project. No older images with a `.managed` section were found: .NET 9+ merges
managed code into `.text`. A sample was added: `artifacts/aot/src/aotbench` (JSON source generation,
compiled regex, LINQ, virtual calls, try/catch/finally, SHA-256; ILCompiler 10.0.9 from the NuGet cache,
no download; publishing needs the VS Installer folder on PATH for `vswhere`).

| binary | MB | PDB | Fully | Reloc. | Frozen | frozen by the RyuJIT switch alone |
|---|---|---|---|---|---|---|
| aotbench.exe (sample) | 3.4 | yes | 84.5% | 1.1% | 9.8% | 97.5% of frozen bytes |
| ilc.exe (ILCompiler 10.0.9) | 14.6 | no | 82.1% | 3.6% | 10.4% | 98.7% |
| RgDotnet.Cli.exe | 3.0 | yes | 85.0% | 1.8% | 8.9% | 97.1% |

Analysis takes 1-3 s. Discovery works without symbols: .pdata covers managed methods and funclets, and
96% of executable bytes are claimed by functions.

**1. RyuJIT's switch encoding (all the Frozen share).** Dispatch is
`lea t,[rip+table]; mov e,[t+idx*4]; lea b,[rip+L]; add e,b; jmp e`, bounded by an ordinary
`cmp idx,n; ja default`. Entries are **unsigned** 32-bit offsets from a label `L` **inside the function**.
`L` is the entry in 151 of 391 sampled dispatches and the first instruction after the prologue in the rest.
This is a third encoding, beside MSVC's image-relative and LLVM's table-relative ones. It differs from
LLVM's in that the base is a second `lea`, not the table address, and the load zero-extends. It is
a small extension of `TableRelativeOffset32` (`JumpTable.BaseRva` already exists). The rewriters need
the base re-pointed to the moved label, or kept if the method moves as a unit. Once it exists, Frozen falls
to ~0.2% on all three binaries.
The interior `lea b` also causes most of the `interior-pointer` RelocatableOnly share.

**2. The gate does not see the GC info: a soundness gap.** Managed methods' UNWIND_INFO carries no
handler flag but is followed by runtime data: an UnwindBlockFlags byte (funclet kind, has-EH-info,
...), optional EH-info and associated-data RVAs, then the GC info. That trailing data is a median 16 bytes,
mean 33, against 0-12 bytes for native functions. 5,179 UNWIND_INFOs are shared by 8,154 managed .pdata
entries. GC info (safepoints, interruptible ranges, slot lifetimes) and EH clauses are keyed by
**offsets from the method start**. Byte copies keep them valid. `--rebuild`/`--blocks` would silently
invalidate them, and so would hot/cold splitting (a chained cold entry has no UnwindBlockFlags).

*Done (Oct 2026):* `NativeAotGate`, run first by `SafetyGatePass`, recognizes the
`DotNetRuntimeDebugHeader` export (`BinaryImage.NativeAot`). The managed range comes from
`__managedcode_a/z` in the PDB, else from the registration call: one block before a call with
`rdx = lea [rip+a]` and `r8 = lea [rip+z] - rdx` (`sub r8d,edx`), both code addresses, exactly one such
range in the image (aotbench: the same [0x1000, 0x16B360) as the PDB; ilc.exe: [0x1000, 0x60CFB0)). If neither
is found, every function is Frozen. Inside the range, managed methods are RelocatableOnly (`gc-info`), and
funclets (UnwindBlockFlags kind 1/2) and their parents (the preceding root .pdata entry, as the runtime walks back)
are Frozen. The UnwindBlockFlags byte follows the unwind codes **without** the even-count padding (the runtime's
`GetUnwindDataBlob` aligns only before a handler RVA). Read that way, every parent of a funclet has
`UBF_FUNC_HAS_EHINFO` and every root with EH info has funclets (aotbench: 7,753 roots, 382 handler and
19 filter funclets, 311 parents). The padded reading, used in the first survey, gives 233 impossible kind-3
entries and 920 parents without EH info. Its "~1,100 methods with funclets" in item 4 is wrong. Results:
aotbench 8,155 functions `gc-info`, Fully 84.5% -> 16.6% of code (the native runtime after the range), Frozen
15.4%; ilc.exe 31,057 functions, Fully 12.0%. Every rewriter (append, `--rebuild`, `--whole-program`)
refuses an image with `NativeAot` set (`FunctionRewriter.RefuseNativeAot`, exit 2), because of items 3-4. Tests:
`NativeAotGateTests` (synthetic: PDB range, registration call, unknown range, no export) and `NativeAotTests`
(aotbench, with and without the PDB, refusal in all modes).

**3. The registered managed-code range blocks append mode (verified at run time).** A no-op append
rewrite of aotbench verifies (9,606 of 10,240 functions, 89.7% of bytes), and the output fails fast
(0xC0000602) at the first GC. The stack is `StackFrameIterator::CalculateCurrentMethodState` under
`Thread::GcScanRoots`. Native startup code registers one range with
`RhRegisterOSModule(module, __managedcode_a, z - a, __unbox_a, unbox_z - unbox_a, ...)`, two
RIP-relative `lea`s (aotbench: [0x1000, 0x16B360), followed by ~300 KB of native runtime code in `.text`).
The runtime treats a return address outside the range as native code. In a throwaway experiment, the two
`lea`s (original and copy) were patched to end the range at `.wbtext`'s end. With that, the GC passes.
This is **not** a valid fix: native runtime code, `.rdata` and the rest then count as managed, which breaks
when a thread is suspended in a native helper.

**4. Funclets sit at fixed offsets from their parent (verified at run time).** With the range patched,
the first `throw` dispatches its catch funclet to `Main+0x9F2`, where Main is 0x9F2 bytes long: the
handler address is the parent's start plus the clause's handler offset. In the original image the funclet
follows Main; in `.wbtext` that address held int3 padding. A parent and its funclets (separate .pdata
entries, UnwindBlockFlags kind handler/filter) must move as **one unit with the same relative layout**.
The runtime's lookup also walks back from a funclet's .pdata entry to its root entry (per the runtime
source; not exercised here), so their .pdata entries must stay adjacent. aotbench: 311 of 7,753 managed
methods have funclets (401 funclets). The first survey's "~1,100 of 6,300" misread UnwindBlockFlags (see item 2).

**5. Whole-program mode is open but useless as is.** Linking with `/DEBUGTYPE:CV,FIXUP`
(`<LinkerArg Include="/DEBUGTYPE:CV,FIXUP" />`) passes the whole-program gate: 118,907 fixups, every
check ok, and the no-op whole-program rewrite verifies. But ILC emits all managed code as **one section
contribution** (1,483,569 bytes in aotbench), and references inside it carry no fixups: 63 of 19,038 direct
calls inside the range have one, and no fixup has both source and target inside it. Contribution-level reordering has
nothing to reorder. Function-level placement inside the range would need disassembly for intra-managed
references (as append mode does) and fixups for the incoming data references. That is a hybrid neither
mode implements. It is still the shape that fits item 3: optimized code stays inside the registered range.

**Not checked:** the stack-trace metadata (method RVA -> name, for `Exception.StackTrace`) after moves;
the unboxing-stub range (`__unbox_a/z`, registered the same way); CFG-enabled NativeAOT builds
(`<ControlFlowGuard>Guard</ControlFlowGuard>`); .NET 7/8 images (none here, and their packages are not cached).

**Verdict.** The analysis side is tractable now: item 1 is a small recovery rule, and discovery and
CFG work. The rewrite side is not. Append mode is blocked by the single registered range (item 3): it
would need every managed function that can appear on a stack (anything containing a call) to move into
one new range, with the registration re-pointed. A single function left behind breaks it. The
RyuJIT switch rule brings Frozen to ~0.2%, so this is conceivable, but it must reach 100% of calling
functions. Functions too short for a trampoline then need every reference redirected (`--redirect-pointers`). Parents and funclets must move as units (item 4), and
block layout needs a GC-info and EH-info encoder (item 2). The closest viable design is an in-range
rewrite of `[__managedcode_a, __managedcode_z)` (item 5), which is new work, not a variation of an
existing mode. Item 2's gate change has landed. The rewriters refuse NativeAOT images until such a design exists.

## R6. Image size growth

The append-a-new-section strategy trades size for safety. On very large binaries the
growth may itself be objectionable to users. Needs a measured budget and a policy for what
to do when it is exceeded.

## R7. Residual hazards of appending

§6.1 chooses appending and mitigates its known failure modes, but two remain open:

* **Trampoline overwrite.** Entry trampolines require that nothing jumps into the few
  bytes at a function entry that the trampoline replaces. Establishing this is far easier
  than full reference discovery, but it is not free, and functions where it cannot be
  established are downgraded rather than optimized. The rate at which that happens is
  unmeasured.
* **Widened CFGuard target set.** Keeping both the original and optimized entries valid
  slightly enlarges the indirect-call target set. Whether the original entry can be
  removed once a trampoline is installed — restoring the original set size — is an open
  question worth answering, since it would eliminate this regression entirely.

Neither is a reason to prefer in-place rewriting; both are enumerable, which is precisely
the property §6.1 selects for.

## Deliberately accepted

* **Authenticode invalidation** (§5.4) — unavoidable for any rewriter. Consumers re-sign.
* **Dead original code in the output image** (§6.1) — the price of the safety property.
* **No in-place rewriting without fixup records** — considered and rejected; see §6.1 for the
  reasoning. With complete fixup records it is allowed behind a gate (§6.2).
