# ChainForge

A terminal-based Windows x86 ROP chain development tool. Originally built alongside the OffSec EXP-301 (OSED) course. Pure Python 3.6+, no dependencies.

Requires rp++ to generate gadget files from target binaries.

---

## Disclaimer

This tool is intended for authorized security research, penetration testing, and educational use only. Use on systems you do not own or have explicit written permission to test is illegal. The author is not responsible for any misuse or damages arising from use of this tool.

---

## Overview

ChainForge reduces the manual effort involved in Windows x86 ROP chain development. It processes rp++ gadget output and gives you a single terminal workspace to answer the questions that come up repeatedly during exploit development: what can this DLL actually do, can I copy this register into that one, what does this address point to, and does my chain have any bad bytes in it.

The TUI is split into six tabs navigated by number keys. Analysis runs a full capability report on your loaded gadgets. Search lets you query by plain text, regex, or address. Suggest translates plain-language goals into ranked gadget candidates. Chain is an interactive builder that validates, reorders, exports, and saves your work. NullChk verifies addresses against your bad char constraints. The RegEx CheatSheet gives you a browsable reference of pre-built search patterns.

Everything is bad-char aware throughout. Gadgets at addresses containing bad bytes are excluded from all results automatically based on your configured set. This applies equally to search results, analysis section counts, best-gadget examples, and the grading of multi-hop paths — including ASM immediate values that would embed bad bytes into the instruction stream.

---

## Setup

```bash
# Generate gadgets from a DLL using rp++
rp-win-x86.exe -f target.dll -r 5 > target_rop.txt
```

Drop any rp++ `.txt` output files into the `gadgets/` directory and they will be loaded automatically on startup. No flags required.

Only `.txt` files are loaded. Any other file types in `gadgets/` are ignored and flagged in the terminal output, with the exception of `.gitkeep` which is silently ignored. This helps catch accidental drops of wrong file types before a session.

```
[*] gadgets/ directory: 3 file(s) found
[+] (auto) Loaded 18,432 gadgets from module_a_rop.txt
[+] (auto) Loaded 11,205 gadgets from module_b_rop.txt
[+] (auto) Loaded 9,847 gadgets from module_c_rop.txt
[*] Bad chars: 0x0, 0xa, 0xd
[+] Total: 39,484 gadgets ready
```

With an additional `-f` file:

```
[*] gadgets/ directory: 3 file(s) found
[+] (auto) Loaded 18,432 gadgets from module_a_rop.txt
[+] (auto) Loaded 11,205 gadgets from module_b_rop.txt
[+] (auto) Loaded 9,847 gadgets from module_c_rop.txt
[+] (-f)   Loaded  7,612 gadgets from extra_rop.txt
[*] Bad chars: 0x0, 0xa, 0xd
[+] Total: 47,096 gadgets ready
```

After closing, any actions taken during the session are printed to the terminal:

```
[+] Analysis complete: 39,484 gadgets across 3 file(s)
[*] Bad chars changed: 0x0, 0xa, 0xb, 0xd
[+] Chain saved: my_chain.json  (12 entries)
[+] Chain imported (replaced): base_chain.json  —  8 entries
[+] Chain imported (appended): extra.json  —  4 entries  (16 total)
[!] Gadget file not found: missing_rop.txt
[!] Chain import failed — file not found: missing.json
[+] ChainForge closed.
```

```bash
# Launch (auto-loads from gadgets/)
python chainforge.py

# Additional files alongside gadgets/
python chainforge.py -f extra_rop.txt

# Custom bad chars
python chainforge.py -b 00,0a,0b,0c,0d,09,20

# Explicit files only
python chainforge.py -f module_a_rop.txt -f module_b_rop.txt -b 00,0a,0d

# CLI subcommands
python chainforge.py search -f target_rop.txt "mov eax"
python chainforge.py nullcheck 0x10021c89
python chainforge.py suggest "copy eax to ebx"
python chainforge.py chain
```

Press `?` inside the TUI to open the help menu.

---

## Tabs

### [1] Analysis

Full DLL capability scan. Run this first on a new target to understand what is and is not available before building a chain. All counts reflect only gadgets at clean addresses that pass your bad char filter. The overview lists every gadget file loaded, total gadget count, bad chars in use, and clean gadget count.

Sections are produced in order:

**EAX Hub Map** — maps every route to and from EAX across all loaded modules, with gadget counts and the best example for each direction. EAX is the primary relay register in most x86 ROP chains and this section gives you a quick picture of how reachable it is from any other register before you start planning.

**Multiple-Hop Path Analysis** — for every register pair that has no direct copy route, ChainForge finds the best 2-hop relay through an intermediate register and grades the path. Grades are GOOD (all legs have clean gadgets with no destructive side effects), CAUTION (side effects present — `leave`, `retn N`, mid-gadget memory dereferences), or PROBLEMATIC (likely access violation — `hlt`, `rep movsd`, ESP corruption via dereference, segment register pops, privileged I/O). When the best gadget for a leg is flagged, an alternative is shown. Paths where no viable relay exists are explicitly listed so you know what is simply not available.

**Memory Write Map** — for each pointer register, lists every source register that can be written to memory at that address, with grade and best gadget. Only GOOD and CAUTION gadgets are shown; PROBLEMATIC ones are excluded.

**Memory Load Map** — the reverse: for each destination register, which pointer registers can load a value from memory into it.

**Register copy matrices** — `mov`, push/pop relay, and `xchg` counts for every register pair, with the best available gadget shown per row.

**Memory read/write matrices** — `mov [PTR], SRC` and `mov DST, [PTR]` counts for every combination.

**Add / Sub matrices** — ADD and SUB shown as separate grids with counts per register pair.

**Inc / Dec / Neg** — per-register counts for single-register arithmetic.

**Capture ESP, Zero Register, Stack Pivot, Key Single Instructions** — availability and best examples for each.

### [2] Search

Plain text and regex gadget search across all loaded files simultaneously. Results are sorted: plain `ret` first, then fewest instructions, then score. Each result shows a bad char indicator, ret type, instruction count, address, ASM, and source module. A `>` marker in the left gutter shows the selected row.

- `/` — new plain text search
- `x` — new regex search
- `n` — refine — pre-fills the last query to edit and re-run
- `c` — clear results and return to the intro screen
- `Enter` — add selected gadget to chain
- `a` — add all current results to chain

You can search by address as well as ASM text — enter a full address like `0x10012f97` or a partial like `10012f` to find gadgets by location.

**Important:** rp++ always emits `dword` in memory operands. To search for a dereference use plain search with the exact text (`mov eax, dword [ecx]`) or regex with a literal space before the bracket (`mov\s+eax,\s*dword \[ecx\]`). The `[` must be escaped as `\[` in regex mode.

The intro screen includes a regex quick-start guide. The RegEx CheatSheet tab has pre-built patterns with strict/loose/broad tags.

### [3] Suggest

Goal-based search. Describe what you want in plain language and ChainForge searches all loaded modules, returning results grouped into strict, loose, and broad tiers so you can start with the cleanest gadgets and fall back as needed.

```
copy eax              copy eax to ecx       copy into esi from eax
deref esi             write esi             zero edx
push eax              pop ecx               capture esp
stack pivot           call virtualalloc
```

- `/` — new goal
- `n` — refine last goal
- `c` — return to goal browser
- `Enter` — add selected gadget to chain

### [4] Chain

Interactive chain builder. Gadgets added from Search or Suggest appear here. Every entry shows its address, ASM, comment, and bad char status.

- `a` add by address, `p` add padding, `d` delete, `K`/`J` reorder
- `v` validate all entries for bad chars
- `c` null-check selected entry
- `r` regex search and pick result without leaving the tab
- `e` export as Python `pack("<L", ...)` code
- `S` save to JSON, `O` import from JSON (replace or append)
- `N` rename chain

On quit, if the chain has unsaved entries, a save prompt appears before closing.

### [5] NullChk

Check any address or value against your bad char constraints. Shows which specific byte positions are problematic and supports batch checking of multiple values at once. Bad chars can be updated mid-session with `b`.

### [6] RegEx CheatSheet

Browsable reference of pre-built regex patterns from `data/cheatsheet.md`, organized by operation category. Each pattern is tagged `strict` (clean gadget, ret immediately follows), `loose` (side effects allowed), or `broad` (widest match). Press `Enter` on any pattern to copy it directly to the Search tab and run it immediately.

---

## Testing

ChainForge includes a test suite (`test_suite.py`) that validates the tool against your actual gadget files. It runs five layers of checks and writes a self-contained log that can be read in a new context to understand exactly what was tested.

```bash
python test_suite.py \
    --files module_a_rop.txt module_b_rop.txt module_c_rop.txt \
    --badchars 00,09,0a,0b,0c,0d,20 \
    --sample-pct 25 \
    --seed 42 \
    --log test_results.log
```

**Layer 1 — Random address sample** (default 25% of clean gadgets): verifies sampled gadgets are findable by address search, confirmed clean, not present when searched with dirty-only filtering, findable by ASM fragment, and that deduplication produces no duplicate ASM strings in results.

**Layer 2 — Matrix consistency**: for every cell in the MOV, Push/Pop, XCHG, Memory Write, Memory Read, ADD, and SUB matrices, confirms the count matches a direct standalone search using the same pattern. Also checks that the first result per cell is at a clean address and that filtered counts are always ≤ unfiltered counts.

**Layer 3 — Grading coverage**: runs 50 known ASM strings through `_grade_asm()` covering every branch of the destructive and caution pattern sets, verifies all 10 immediate bad byte detection cases, and confirms the grading function is deterministic.

**Layer 4 — Suggest and NullChk**: 15 goal-based searches verified to return zero dirty gadgets; 15 address classifications verified against expected clean/dirty status; bad byte position accuracy checked.

**Layer 5 — Chain**: entry bad char consistency, `validate()` correctly catches injected bad address, JSON round-trip preserves all entries and metadata, Python export contains all addresses and correct structure.

The `--seed` flag makes sampling reproducible. The log file includes all PASS/FAIL lines, sample counts, and a summary so it is fully self-contained.

---

## Directory Structure

```
chainforge/
├── chainforge.py          entry point
├── test_suite.py          validation test suite
├── gadgets/               drop rp++ .txt files here for auto-loading
├── core/
│   ├── search.py          gadget search engine
│   ├── suggest.py         goal-based suggestions
│   ├── chain.py           chain builder
│   └── nullcheck.py       bad char checker
├── analysis/
│   └── analysis.py        DLL capability analysis
├── ui/
│   └── tui.py             terminal UI
└── data/
    └── cheatsheet.md      regex pattern reference (required for tab 6)
```

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
