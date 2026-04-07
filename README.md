# ChainForge

A terminal-based Windows ROP chain development tool. Originally built alongside the OffSec EXP-301 (OSED) course. Pure Python 3.6+, no dependencies.

Requires rp++ to generate gadget files from target binaries.

---

## Disclaimer

This tool is intended for authorized security research, penetration testing, and educational use only. Use on systems you do not own or have explicit written permission to test is illegal. The author is not responsible for any misuse or damages arising from use of this tool.

---

## Setup

```bash
# Generate gadgets from a DLL using rp++
rp-win-x86.exe -f target.dll -r 5 > target_rop.txt

# Launch the TUI (default — no subcommand needed)
python chainforge.py -f target_rop.txt
python chainforge.py -f target_rop.txt -f ntdll_rop.txt
python chainforge.py -f target_rop.txt -b 00,0a,0d,09,20

# CLI subcommands
python chainforge.py search -f target_rop.txt "mov eax"
python chainforge.py nullcheck 0x10021c89
python chainforge.py suggest "copy eax to ebx"
python chainforge.py chain
```

Press `?` inside the TUI to open the help menu.

---

## Tabs

| Key | Tab | Description |
|-----|-----|-------------|
| 1 | Analysis | Full DLL capability report — register copy matrices, memory operations, stack pivot, path analysis |
| 2 | Search | Plain text and regex gadget search across all loaded files |
| 3 | Suggest | Goal-based search — describe what you need (copy eax, write memory, deref esi, zero edx, etc.) |
| 4 | Chain | Build, annotate, reorder, validate, and export ROP chains as Python pack() code |
| 5 | NullChk | Check addresses and values against bad char constraints |
| 6 | RegEx CheatSheet | Browse pre-built regex patterns by category with strict/loose/broad tiers |

---

## Directory Structure

```
chainforge/
├── chainforge.py          entry point
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
