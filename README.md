# ChainForge

A terminal-based Windows x86 ROP chain development tool. Originally built alongside the OffSec EXP-301 (OSED) course. Pure Python 3.6+, no dependencies.

Requires rp++ to generate gadget files from target binaries.

---

## Disclaimer

This tool is intended for authorized security research, penetration testing, and educational use only. Use on systems you do not own or have explicit written permission to test is illegal. The author is not responsible for any misuse or damages arising from use of this tool.

---

## Overview

ChainForge reduces the manual effort involved in Windows x86 ROP chain development. It processes rp++ gadget output and provides a searchable, interactive workspace for finding gadgets, understanding what a target DLL can and cannot do, building and validating chains, and exporting them — all in one terminal interface.

All searches and analysis are bad-char aware. Gadgets at addresses containing bad bytes are excluded automatically based on your configured constraints.

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

Full DLL capability scan. Run this first on a new target to understand what is and is not available before building a chain. All counts reflect only gadgets at clean addresses that pass your bad char filter. The overview lists every gadget file loaded, total gadget count, bad chars, and clean gadget count.

- **EAX Hub Map** — all routes to and from EAX with gadget counts and best examples, since EAX is the primary relay register in most chains
- **Multiple-Hop Path Analysis** — automatically finds relay routes for missing direct register copies, with best gadget shown per leg
- **Register copy matrices** — `mov`, push/pop relay, and `xchg` counts for every register pair
- **Memory read/write matrices** — `mov [PTR], SRC` and `mov DST, [PTR]` for every combination
- **Add / Sub matrices** — register-to-register arithmetic counts (ADD and SUB shown separately)
- **Inc / Dec / Neg** — per-register counts for single-register arithmetic
- **Capture ESP** — which registers can receive the stack pointer
- **Zero register** — which registers can be zeroed cleanly
- **Stack pivot** — available pivot gadgets
- **Key single instructions** — `cld`, `cdq`, `pushad`, `popad`, `stosd`, `lodsd`, `nop`

### [2] Search

Plain text and regex gadget search across all loaded files simultaneously. Results are sorted: plain `ret` first, then fewest instructions, then score. Each result shows a bad char indicator, ret type, instruction count, address, ASM, and source module.

- `/` — new plain text search (starts empty)
- `x` — new regex search (starts empty)
- `n` — refine — pre-fills the last query to edit and re-run
- `c` — clear results and return to the intro screen
- `Enter` — add selected gadget to chain
- `a` — add all current results to chain

Search by address as well as ASM — enter a full address or a partial to find gadgets by location.

The intro screen includes a regex quick-start guide and points to the RegEx CheatSheet tab for pre-built patterns.

### [3] Suggest

Goal-based search. Describe what you want in plain language and ChainForge searches all loaded modules, returning results grouped by category and ranked by quality (strict/clean first).

```
copy eax              copy eax to ecx       copy into esi from eax
deref esi             write esi             zero edx
push eax              pop ecx               capture esp
stack pivot           call virtualalloc
```

- `/` — new goal (starts empty)
- `n` — refine last goal
- `c` — return to goal browser
- `Enter` — add selected gadget to chain

### [4] Chain

Interactive chain builder. Gadgets added from Search or Suggest appear here.

- `a` add by address, `p` add padding, `d` delete, `K`/`J` reorder
- `v` validate all entries for bad chars
- `c` null-check selected entry
- `r` regex search and pick result without leaving the tab
- `e` export as Python `pack("<L", ...)` code
- `S` save to JSON, `O` import from JSON (replace or append)
- `N` rename chain

On quit, if the chain has unsaved entries, a save prompt appears.

### [5] NullChk

Check any address or value against your bad char constraints. Shows which specific bytes are problematic and supports batch checking.

### [6] RegEx CheatSheet

Browsable reference of pre-built regex patterns from `data/cheatsheet.md`, organized by category. Each pattern is tagged `strict`, `loose`, or `broad`. Press `Enter` on any pattern to copy it to the Search tab and run it immediately.

---

## Directory Structure

```
chainforge/
├── chainforge.py          entry point
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
