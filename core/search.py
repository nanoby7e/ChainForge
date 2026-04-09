"""
search.py — ChainForge gadget search engine
Loads one or more rp++ output files, searches with regex,
filters bad chars, ranks by cleanliness.
"""

import re
import os
import sys
import struct
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

# ── Default bad character sets ────────────────────────────────────────────────
DEFAULT_BADCHARS = bytes([0x00, 0x0A, 0x0D])

# ── Side effect patterns — flag these in results ───────────────────────────────
SIDE_EFFECT_PATTERNS = [
    (r'pop\s+\w+', "pops stack value — account for padding"),
    (r'push\s+\w+', "pushes to stack — ESP moves"),
    (r'retn?\s+0x[0-9a-fA-F]+', "retn N — extra stack cleanup needed"),
    (r'xchg\s+esp', "modifies ESP — stack pivot"),
    (r'mov\s+esp', "modifies ESP — stack pivot"),
    (r'add\s+esp', "modifies ESP"),
    (r'sub\s+esp', "modifies ESP"),
    (r'call\s+', "call — pushes return address"),
    (r'add\s+byte\s*\[', "writes to memory via [reg] — check writability"),
    (r'mov\s+\w+,\s*\[', "reads from memory — ensure valid pointer"),
    (r'stosd|stosb|stosw', "string write — requires CLD first, EDI = dest"),
    (r'lodsd|lodsb|lodsw', "string read — ESI advances by 4 after"),
    (r'movsd|movsb|movsw', "string copy — both ESI and EDI advance"),
    (r'popad|popa\b', "restores all GPRs from stack — 32 bytes consumed"),
    (r'pushad|pusha\b', "saves all GPRs to stack — ESP moves 32 bytes"),
    (r'std\b', "sets DF — string ops will move BACKWARD"),
    (r'cld\b', "clears DF — string ops will move forward"),
    (r'cdq\b', "zeroes EDX if EAX positive — side effect on EDX"),
    (r'int\s+0x', "software interrupt — may terminate chain"),
    (r'sysenter|syscall', "syscall — transfers to kernel"),
]

# ── Cleanliness scoring ────────────────────────────────────────────────────────
def score_gadget(instructions: List[str]) -> int:
    """
    Lower score = cleaner/more useful gadget.
    Scoring priority:
      1. Gadgets ending in plain ret score best (no retn N cleanup needed)
      2. Fewer instructions = better
      3. Penalise side effects (extra pops, esp changes, calls)
    """
    full = " ; ".join(instructions).lower()
    last = instructions[-1].strip().lower() if instructions else ""

    # Base: instruction count * 10
    score = len(instructions) * 10

    # Prefer plain ret over retn N (retn needs stack padding)
    if re.match(r'retn\s+0x', last):
        score += 15   # retn N is less clean than plain ret
    elif re.match(r'ret', last):
        score -= 5    # plain ret gets a bonus

    # Penalise side effects
    penalties = {
        r'pop':          3,   # each pop costs a stack slot
        r'push':         3,
        r'xchg\s+esp':  20,   # stack pivot — dangerous side effect
        r'mov\s+esp':   20,
        r'add\s+esp':   10,
        r'call\s+':     15,   # pushes return address
        r'add\s+byte\s*\[': 25, # memory write — crash if read-only
        r'retn\s+0x':   10,   # extra cleanup bytes needed
        r'nop':         -2,   # nops are harmless, tiny bonus
    }
    for pat, penalty in penalties.items():
        if re.search(pat, full):
            score += penalty
    return score


@dataclass
class Gadget:
    address: int
    raw: str                          # full original line from rp++
    instructions: List[str]           # split on ;
    module: str = ""
    side_effects: List[str] = field(default_factory=list)
    score: int = 0

    @property
    def addr_str(self) -> str:
        return f"0x{self.address:08x}"

    @property
    def asm(self) -> str:
        return " ; ".join(self.instructions)

    def has_badchar(self, badchars: bytes) -> bool:
        addr_bytes = struct.pack("<I", self.address)
        return any(b in addr_bytes for b in badchars)

    def pack_line(self) -> str:
        return f'rop += pack("<L", ({self.addr_str}))  # {self.asm}'


def parse_rpp_file(path: str) -> List[Gadget]:
    """Parse an rp++ output file into Gadget objects."""
    gadgets = []
    module = os.path.basename(path)

    # rp++ format:  0x10023ace: mov eax, esi ; pop esi ; ret  ;  (1 found)
    pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s*:\s*(.+?)\s*;?\s*\(\d+\s+found\)',
        re.IGNORECASE
    )
    alt_pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s*:\s*(.+)',
        re.IGNORECASE
    )

    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                m = pattern.match(line) or alt_pattern.match(line)
                if not m:
                    continue

                addr_str, asm_str = m.group(1), m.group(2)
                # strip trailing (N found) if present
                asm_str = re.sub(r'\s*;?\s*\(\d+\s+found\)\s*$', '', asm_str).strip()

                try:
                    address = int(addr_str, 16)
                except ValueError:
                    continue

                # split instructions
                instructions = [i.strip() for i in asm_str.split(';') if i.strip()]
                if not instructions:
                    continue

                # detect side effects
                effects = []
                full_asm = asm_str.lower()
                for pat, desc in SIDE_EFFECT_PATTERNS:
                    if re.search(pat, full_asm):
                        effects.append(desc)

                g = Gadget(
                    address=address,
                    raw=line,
                    instructions=instructions,
                    module=module,
                    side_effects=effects,
                    score=score_gadget(instructions),
                )
                gadgets.append(g)

    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)

    return gadgets


def search_gadgets(
    gadgets: List[Gadget],
    query: str,
    badchars: bytes = DEFAULT_BADCHARS,
    include_badchars: bool = False,
    regex_mode: bool = False,
    max_results: int = 0,       # 0 = no limit
    highlight_query: str = "",  # term to highlight in asm (for TUI use)
) -> List[Gadget]:
    """
    Search gadgets by query string or regex. Returns ranked results.
    Sorted by: ret-ending first, then instruction count, then score.
    No result cap by default (max_results=0 means unlimited).
    """
    results = []
    compiled = None
    try:
        if regex_mode:
            compiled = re.compile(query, re.IGNORECASE)
            match_fn = lambda g: (bool(compiled.search(g.asm)) or
                                  bool(compiled.search(g.addr_str)))
        else:
            q = query.lower().lstrip('0x')
            match_fn = lambda g: (q in g.asm.lower() or
                                  q in g.addr_str.lower().lstrip('0x'))
    except re.error as e:
        print(f"[!] Invalid regex: {e}", file=sys.stderr)
        return []

    for g in gadgets:
        if not match_fn(g):
            continue
        if not include_badchars and g.has_badchar(badchars):
            continue
        results.append(g)

    # Sort: plain ret first, then fewest instructions, then score
    def sort_key(g: Gadget):
        last = g.instructions[-1].strip().lower() if g.instructions else ""
        has_ret   = 1 if re.match(r'ret$', last) else 0        # plain ret = best
        has_retn  = 1 if re.match(r'retn\s+', last) else 0    # retn = second
        has_other = 0 if (has_ret or has_retn) else 1           # no ret = last
        return (has_other, has_retn, len(g.instructions), g.score)

    results.sort(key=sort_key)

    # Deduplicate by ASM text — keep the first (best-scored) occurrence
    # of each unique instruction sequence. Different addresses with identical
    # instructions add no value and clutter results.
    seen_asm: set = set()
    deduped = []
    for g in results:
        key = g.asm.lower()
        if key not in seen_asm:
            seen_asm.add(key)
            deduped.append(g)

    if max_results and max_results > 0:
        return deduped[:max_results]
    return deduped


def format_gadget(g: Gadget, color: bool = True, show_module: bool = True) -> str:
    """Format a single gadget for terminal display."""
    RESET = "\033[0m" if color else ""
    CYAN  = "\033[96m" if color else ""
    GREEN = "\033[92m" if color else ""
    YELLOW= "\033[93m" if color else ""
    RED   = "\033[91m" if color else ""
    DIM   = "\033[2m"  if color else ""

    mod = f"{DIM}[{g.module}]{RESET} " if show_module and g.module else ""
    addr = f"{CYAN}{g.addr_str}{RESET}"
    asm  = f"{GREEN}{g.asm}{RESET}"
    score = f"{DIM}score:{g.score}{RESET}"

    line = f"  {addr}  {mod}{asm}  {score}"

    if g.side_effects:
        effects = f"\n    {YELLOW}⚠ {' | '.join(g.side_effects)}{RESET}"
        line += effects

    return line


def format_pack_line(g: Gadget, comment_override: str = "") -> str:
    comment = comment_override or g.asm
    return f'rop += pack("<L", ({g.addr_str}))  # {comment}'


# ── CLI entry point ────────────────────────────────────────────────────────────

def cli_search(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="chainforge.py search",
        description="Search rp++ gadget files"
    )
    parser.add_argument("-f", "--file", action="append", dest="files",
                        required=True, metavar="FILE",
                        help="rp++ output file (can specify multiple)")
    parser.add_argument("query", help="search query (string or regex)")
    parser.add_argument("-r", "--regex", action="store_true",
                        help="treat query as regex")
    parser.add_argument("-b", "--badchars", default="00,0a,0d",
                        help="bad chars as hex bytes, comma separated (default: 00,0a,0d)")
    parser.add_argument("--include-bad", action="store_true",
                        help="include gadgets with bad char addresses")
    parser.add_argument("-n", "--max", type=int, default=50,
                        help="max results (default: 50)")
    parser.add_argument("--pack", action="store_true",
                        help="output as Python pack() lines")
    parser.add_argument("--no-color", action="store_true",
                        help="disable color output")
    ns = parser.parse_args(args)

    # parse bad chars
    try:
        badchars = bytes(int(x.strip(), 16) for x in ns.badchars.split(","))
    except ValueError:
        print("[!] Invalid bad char format. Use hex bytes like: 00,0a,0d")
        sys.exit(1)

    # load all files
    all_gadgets = []
    for f in ns.files:
        g = parse_rpp_file(f)
        print(f"[+] Loaded {len(g):,} gadgets from {f}")
        all_gadgets.extend(g)

    print(f"[+] Total: {len(all_gadgets):,} gadgets | Bad chars: {ns.badchars}\n")

    results = search_gadgets(
        all_gadgets, ns.query,
        badchars=badchars,
        include_badchars=ns.include_bad,
        regex_mode=ns.regex,
        max_results=ns.max,
    )

    color = not ns.no_color and sys.stdout.isatty()

    if not results:
        print("  [!] No matching gadgets found.")
        return

    print(f"  Found {len(results)} gadget(s) matching '{ns.query}':\n")

    for g in results:
        if ns.pack:
            print("  " + format_pack_line(g))
        else:
            print(format_gadget(g, color=color))

    print()
