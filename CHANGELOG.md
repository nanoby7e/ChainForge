# Changelog

All notable changes to ChainForge are documented in this file.

Versioning follows [Semantic Versioning](https://semver.org/): MAJOR.MINOR.PATCH.

---

## [1.0.0] - 2026-04-18

First full release. Terminal-based Windows x86 ROP chain development tool with six TUI tabs, comprehensive DLL capability analysis, and a validated test suite.

### Analysis Tab

- **Overview** — Loaded files, total gadget count, bad chars, clean gadget count.
- **Gadget Quality Distribution** — Score buckets (Clean / Moderate / Heavy / Complex) and grade distribution (GOOD / CAUTION / PROBLEMATIC) with ASCII bar charts.
- **Cross-Module Comparison** — Per-module capability matrix (MOV copy, Push/Pop, XCHG, Mem Write/Read, Pop Reg, Zero Reg, Add/Sub, Inc/Dec, Stack Pivot). Appears when 2+ files are loaded.
- **Module Address Analysis (ASLR / Rebase)** — Per-module address ranges, standard DLL/EXE range detection, null high byte flagging, and bad char impact breakdown per byte value.
- **API Chain Readiness (VirtualAlloc / WriteProcessMemory)** — 16-point prerequisite checklist with READY/MISS status and overall readiness verdict (EXCELLENT / GOOD / PARTIAL / LIMITED).
- **Gadget Reliability Summary** — Reliability flag distribution: plain ret, retn N, memory dereference, memory write, ESP modification, call, leave, string operations.
- **Capture ESP** — Per-register availability and best gadget.
- **Stack Pivot** — Per-register and leave-based pivots with counts and best gadget.
- **EAX Hub Map** — Routes to and from EAX across all registers with gadget counts and best examples.
- **Multi-Hop Path Analysis** — 2-hop relay paths for missing direct register copy routes, graded GOOD / CAUTION / PROBLEMATIC with alternatives shown for flagged legs.
- **Memory Write Map** — Per-pointer register, which source registers can write to memory, with grade and best gadget.
- **Memory Load Map** — Per-destination register, which pointer registers can load from memory.
- **Register copy matrices** — MOV, Push/Pop relay, and XCHG count grids for every register pair, with best gadget per row.
- **Memory read/write matrices** — `mov [PTR], SRC` and `mov DST, [PTR]` count grids.
- **Add / Sub matrices** — Separate grids for register-to-register ADD and SUB.
- **Inc / Dec / Neg** — Per-register counts for single-register arithmetic.
- **Zero Register** — Per-register availability including CDQ for EDX.
- **Key Single Instructions** — cld, cdq, pushad, popad, stosd, lodsd, leave, nop with counts and best gadget.
- **Progress bar** — Stage label, percentage, and gadget count shown during analysis.
- **Search cache** — Regex searches cached within a single analysis run for performance.

### Search Tab

- Plain text and regex search across all loaded files simultaneously.
- Results sorted: plain `ret` first, fewest instructions, then score.
- Each result shows bad char indicator, ret type, instruction count, address, ASM (with query highlighting), and source module.
- **Negative filters** — Exclude terms with `-` prefix (e.g. `mov eax -leave`).
- **Search history** — UP/DN in the input prompt cycles through previous queries.
- **Side effects line** — Selected gadget shows compact side effect summary above results (e.g. `+2 pop (esi, ebx) = 8B pad`).
- Address search by full (`0x10012f97`) or partial (`10012f`) hex.
- Regex quick-start guide on the intro screen.

### Suggest Tab

- Goal-based search: describe what you want in plain language.
- 25+ static goals and dynamic register-aware goals (e.g. `copy eax`, `copy esi to ebx`, `deref esi`, `write edi eax`, `zero edx`, `pop ecx`).
- Results grouped into strict, loose, and broad tiers with cross-category deduplication.
- Browsable goal catalogue with descriptions, usage examples, and ASM examples.
- Side effects line for selected gadget.

### Chain Tab

- Interactive chain builder with add by address, add padding, delete, reorder (K/J).
- Validate all entries for bad chars.
- Null-check selected entry inline.
- Regex search and pick result without leaving the tab.
- Export as Python `pack("<L", ...)` code.
- Save/load JSON with replace or append on import.
- Rename chain.
- Save prompt on quit if chain has unsaved entries.

### NullChk Tab

- Single and batch address checking against bad char constraints.
- Byte-position breakdown showing which positions are problematic.
- Null-free alternatives suggested for flagged values.
- Bad chars updatable mid-session.

### RegEx CheatSheet Tab

- Browsable reference of pre-built regex patterns from `data/cheatsheet.md`.
- Organized by operation category with strict/loose/broad tags.
- Filter by keyword or section name.
- Enter copies selected pattern to Search and runs it immediately.

### Core Engine

- **Bad char awareness** — All results, counts, and analysis sections automatically exclude gadgets at addresses containing configured bad bytes, including ASM immediate values embedded in instruction streams.
- **Gadget scoring** — Cleanliness scoring: plain ret preferred, fewer instructions better, penalties for side effects (pops, ESP changes, calls, memory writes).
- **Gadget deduplication** — Results deduplicated by ASM text to remove address-only duplicates.
- **Side effect detection** — 20+ patterns detected and summarised per gadget.
- **Grading system** — `_grade_asm()` classifies gadgets as GOOD, CAUTION (leave, retn N, mid-gadget memory derefs), or PROBLEMATIC (hlt, rep movsd, ESP corruption, segment register pops, privileged I/O).

### TUI

- Six tabs navigated by number keys (1-6).
- Help text at top of every tab, no bottom footers.
- Consistent layout: title bar, help lines, content area, status bar.
- Input buffer flush prevents scroll inertia when arrow keys are held.
- PgUp/PgDn on all scrollable tabs.
- Help popup (`?`) with full keyboard reference.
- Quit confirmation with optional save.
- Session log printed to terminal on close.

### CLI

- `python chainforge.py` launches the TUI with auto-loading from `gadgets/`.
- `-f FILE` for explicit files, `-b HEX` for custom bad chars.
- Subcommands: `search`, `nullcheck`, `suggest`, `chain`.

### Testing

- Five-layer test suite (`test_suite.py`):
  - Layer 1 — Random address sample: findability, cleanliness, dirty exclusion, ASM fragment search, deduplication.
  - Layer 2 — Matrix consistency: cell counts vs standalone search, clean first result, filtered <= unfiltered.
  - Layer 3 — Grading coverage: 50 known ASM strings across all grade branches, 10 immediate bad byte cases, determinism check.
  - Layer 4 — Suggest and NullChk: 15 goal searches with zero dirty results, 15 address classifications, bad byte position accuracy.
  - Layer 5 — Chain: entry consistency, validate catches injected bad address, JSON round-trip, Python export structure.
- Reproducible via `--seed` flag.
- Self-contained log output.

### Infrastructure

- Pure Python 3.6+, no dependencies (except `windows-curses` on Windows).
- Package-qualified imports (`from core.search import ...`).
- rp++ auto-loading from `gadgets/` directory.
