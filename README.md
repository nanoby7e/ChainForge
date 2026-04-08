# ChainForge

A terminal-based Windows ROP chain development tool. Originally built alongside the OffSec EXP-301 (OSED) course. Pure Python 3.6+, no dependencies.

Requires rp++ to generate gadget files from target binaries.

---

## Disclaimer

This tool is intended for authorized security research, penetration testing, and educational use only. Use on systems you do not own or have explicit written permission to test is illegal. The author is not responsible for any misuse or damages arising from use of this tool.

---

## Overview

ChainForge is designed to reduce the manual effort involved in Windows x86 ROP chain development. It processes rp++ gadget output and gives you a searchable, interactive workspace for finding gadgets, understanding what a target DLL can and cannot do, building chains, and validating them against bad character constraints — all in one terminal interface.

All searches and analysis are bad-char aware. Gadgets at addresses containing bad bytes are excluded from results automatically based on your configured constraints.

---

## Setup

```bash
# Generate gadgets from a DLL using rp++
rp-win-x86.exe -f target.dll -r 5 > target_rop.txt
```

Drop any rp++ `.txt` output files into the `gadgets/` directory and they will be loaded automatically on startup. No flags required.

Example output on startup:

```
[*] gadgets/ directory: 3 file(s) found
[+] (auto) Loaded 22,482 gadgets from snfs_rop.txt
[+] (auto) Loaded 10,629 gadgets from csncdav6_rop.txt
[+] (auto) Loaded 12,632 gadgets from csmtpav6_rop.txt
[+] Total: 45,743 gadgets ready
```

With an additional `-f` file:

```
[*] gadgets/ directory: 3 file(s) found
[+] (auto) Loaded 22,482 gadgets from snfs_rop.txt
[+] (auto) Loaded 10,629 gadgets from csncdav6_rop.txt
[+] (auto) Loaded 12,632 gadgets from csmtpav6_rop.txt
[+] (-f)   Loaded  8,241 gadgets from extra_rop.txt
[+] Total: 53,984 gadgets ready
```

```bash
# Launch with auto-loaded gadgets from gadgets/
python chainforge.py

# Pass additional files alongside gadgets/ contents
python chainforge.py -f extra_rop.txt

# Override bad chars
python chainforge.py -b 00,0a,0d,09,20

# Explicit files only (skips gadgets/ if you prefer)
python chainforge.py -f target_rop.txt -f ntdll_rop.txt

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

Runs a full capability scan of all loaded gadgets and produces a structured report. Useful at the start of a new target to understand what is and is not available before building a chain.

- Register copy matrices — `mov`, push/pop relay, and `xchg` for every register pair
- Memory read and write matrices — `mov [PTR], SRC` and `mov DST, [PTR]` for every combination
- Capture ESP — which registers can receive the stack address
- Zero register — which registers can be zeroed cleanly
- Stack pivot options — `xchg eax, esp`, `leave`, and equivalents
- Key single instructions — `cld`, `cdq`, `pushad`, `popad`, `stosd`, `lodsd`, `nop`
- 2-hop path analysis — automatically finds relay routes for missing direct register copies, and explicitly lists pairs with no path at all

All counts in the matrices reflect only clean addresses that pass your bad char filter.

### [2] Search

Plain text and regex gadget search across all loaded files simultaneously.

- `/` — new plain text search
- `x` — new regex search
- `n` — refine last query (pre-fills the previous search to edit)
- `c` — clear and return to the intro screen
- Results are sorted: plain `ret` first, then fewest instructions, then score
- Each result shows a bad char indicator, ret type, instruction count, address, ASM, and module
- `Enter` adds the selected gadget to the chain. `a` adds all current results.

The Search tab includes a built-in regex quick-start guide when no search has been run, and a tip pointing to the RegEx CheatSheet tab for pre-built patterns.

### [3] Suggest

Goal-based search — describe what you want the gadget to do in plain language and ChainForge finds candidates across all loaded modules, grouped by category and ranked by quality.

Example goals:

```
copy eax
copy eax to ecx
copy into esi from eax
deref esi
write esi
zero edx
push eax
pop ecx
capture esp
stack pivot
call virtualalloc
```

Results are grouped into strict, loose, and broadest tiers so you can start with the cleanest gadgets and fall back as needed. Use `n` to refine a goal and `c` to return to the goal browser.

### [4] Chain

Interactive chain builder. Gadgets added from Search or Suggest land here.

- Add by address (`a`), add padding (`p`), delete (`d`), reorder (`K`/`J`)
- Validate all entries for bad chars (`v`)
- Null-check a specific entry (`c`)
- Regex search and pick result directly from the chain tab (`r`)
- Export as Python `pack("<L", ...)` code (`e`)
- Save to JSON (`S`) and import from JSON (`O`) — import supports replace or append
- Rename chain (`N`)

On quit, if the chain has unsaved entries, a prompt offers to save before exiting.

### [5] NullChk

Check any address or value against your bad char constraints. Supports single values and batch checking. Shows which specific bytes in the address are problematic.

### [6] RegEx CheatSheet

A browsable reference of pre-built regex patterns pulled from `data/cheatsheet.md`, organized by operation category (MOV, LEA, PUSH/POP, XCHG, arithmetic, logic, memory read/write, string ops, stack pivot, and more).

Each pattern is tagged with its tier — `strict` (clean gadget, ret immediately follows), `loose` (side effects allowed), or `broad` (widest match). Press `Enter` on any pattern to copy it directly into the Search tab and run it immediately.

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
