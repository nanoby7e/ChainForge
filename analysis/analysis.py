"""
analysis.py — ChainForge DLL capability analysis
Scans a loaded gadget list and produces a structured summary of what
register operations, memory operations, and special instructions exist.
Surfaces gaps and suggests multi-step paths for missing direct routes.
"""

import re
from typing import List, Dict, Tuple, Optional
from search import Gadget, search_gadgets

REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']


def _hit(gadgets, pattern, bad):
    return search_gadgets(gadgets, pattern, badchars=bad,
                          regex_mode=True, max_results=0)


def _best(results):
    return results[0].asm if results else None


def run_analysis(gadgets: List[Gadget], badchars: bytes) -> List[Tuple[str, str, List[str]]]:
    """
    Return a list of (section, status, [lines]) tuples.
    status: 'ok' | 'warn' | 'missing' | 'info'
    """
    sections = []

    # ── 1. Overview ──────────────────────────────────────────────────────────
    sections.append(("Overview", "info", [
        f"  Total gadgets loaded:  {len(gadgets):,}",
        f"  Bad chars:             {', '.join(hex(b) for b in badchars)}",
        f"  Clean gadgets:         {sum(1 for g in gadgets if not g.has_badchar(badchars)):,}",
    ]))

    # ── Shared matrix builder ────────────────────────────────────────────────
    GUTTER  = 14   # left margin for the row-axis label
    # Data row format: GUTTER + "  " + reg(5) + cells
    # Header format must match: same total prefix before first cell

    def make_matrix(row_label, col_label_str, count_fn, skip_same=True):
        """Build a labelled matrix — every row at identical column positions."""
        # Prefix before the first data cell on every row:
        # gutter (14) + "  " (2) + reg_name (5) = 21 chars total
        PREFIX = GUTTER + 2 + 5   # = 21

        out = []

        # Column axis label
        out.append(" " * PREFIX + "  " + col_label_str)

        # Register header — each column is "  " + 4-char name = 6 chars
        # Must start at PREFIX so first "  eax" aligns with first data cell
        hdr = " " * PREFIX
        for r in REGS:
            hdr += f"  {r:>4}"
        out.append(hdr)

        # Separator
        sep = " " * PREFIX
        for _ in REGS:
            sep += "  ----"
        out.append(sep)

        # Data rows
        mid = len(REGS) // 2
        for i, row_reg in enumerate(REGS):
            if i == mid:
                gutter = f"  {row_label:<{GUTTER - 2}}"
            else:
                gutter = " " * GUTTER

            cells = ""
            for col_reg in REGS:
                if skip_same and col_reg == row_reg:
                    cells += "  ----"
                    continue
                n = count_fn(row_reg, col_reg)
                cells += f"  {n:>4}"   # always 6 chars: "  " + 4-digit number

            # gutter(14) + "  "(2) + reg_name left-padded to 5 = PREFIX=21
            out.append(f"{gutter}  {row_reg:>5}{cells}")
        return out





    # ── 2. MOV copy matrix ───────────────────────────────────────────────────
    mov_missing = []
    def mov_count(dst, src):
        hits = _hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)
        if not hits: mov_missing.append((src, dst))
        return len(hits)

    mov_lines = make_matrix("DST (row)", "SRC (columns) ->", mov_count)
    mov_lines.insert(0, "  How to read:  row = destination register,  column = source register")
    mov_lines.insert(1, "  A value of 4 means 4 gadgets exist for  mov ROW, COL")
    mov_lines.insert(2, "")
    status = "ok" if len(mov_missing) < 30 else "warn"
    sections.append(("MOV Copy Matrix  (mov DST, SRC)", status, mov_lines))

    # ── 3. Push/pop relay matrix ─────────────────────────────────────────────
    pp_missing = []
    def pp_count(dst, src):
        hits = _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)
        if not hits: pp_missing.append((src, dst))
        return len(hits)

    pp_lines = make_matrix("DST (row)", "SRC (columns) ->", pp_count)
    pp_lines.insert(0, "  How to read:  row = destination,  column = source")
    pp_lines.insert(1, "  A value of 7 means 7 gadgets exist for  push COL ; ... ; pop ROW")
    pp_lines.insert(2, "")
    sections.append(("Push/Pop Relay Matrix  (push SRC ... pop DST)",
                     "ok" if len(pp_missing) < 30 else "warn", pp_lines))

    # ── 4. XCHG matrix ───────────────────────────────────────────────────────
    def xchg_count(r1, r2):
        if r2 >= r1: return 0
        hits = _hit(gadgets, rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1}).*ret', badchars)
        return len(hits)

    xchg_lines = make_matrix("REG (row)", "REG (columns) ->", xchg_count)
    xchg_lines.insert(0, "  How to read:  lower-left triangle only  (symmetric operation)")
    xchg_lines.insert(1, "  A value of 2 means 2 gadgets swap ROW and COL  (both registers change)")
    xchg_lines.insert(2, "")
    sections.append(("XCHG Matrix  (destructive swap)", "info", xchg_lines))

    # ── 5. Memory write matrix ───────────────────────────────────────────────
    def mw_count(ptr, src):
        hits = _hit(gadgets,
                    rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret', badchars)
        return len(hits)

    mw_lines = make_matrix("PTR (row)", "SRC (columns) ->", mw_count)
    mw_lines.insert(0, "  How to read:  row = pointer register holding dest address,  column = source value")
    mw_lines.insert(1, "  A value of 60 means 60 gadgets exist for  mov [ROW], COL")
    mw_lines.insert(2, "")
    sections.append(("Memory Write Matrix  (mov [PTR], SRC)", "info", mw_lines))

    # ── 6. Memory read matrix ────────────────────────────────────────────────
    def mr_count(dst, ptr):
        hits = _hit(gadgets,
                    rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret', badchars)
        return len(hits)

    mr_lines = make_matrix("DST (row)", "PTR (columns) ->", mr_count)
    mr_lines.insert(0, "  How to read:  row = destination register,  column = pointer register")
    mr_lines.insert(1, "  A value of 69 means 69 gadgets exist for  mov ROW, [COL]")
    mr_lines.insert(2, "")
    sections.append(("Memory Read Matrix  (mov DST, [PTR])", "info", mr_lines))

    # ── 7. Capture ESP ───────────────────────────────────────────────────────
    esp_lines = []
    esp_found = []
    for dst in REGS:
        hits = _hit(gadgets,
                    rf'(mov\s+{dst},\s*esp|lea\s+{dst},\s*\[esp|push\s+esp.*pop\s+{dst}).*ret',
                    badchars)
        if hits:
            esp_found.append(dst)
            esp_lines.append(f"    {dst:>5}  {len(hits):>4} gadgets   {hits[0].asm}")
    if not esp_lines:
        esp_lines.append("    NOT FOUND in any register")
    status = "ok" if esp_found else "missing"
    sections.append(("Capture ESP  (get stack address into register)", status, esp_lines))

    # ── 8. Zero register ─────────────────────────────────────────────────────
    zero_lines = []
    zero_missing = []
    for reg in REGS:
        hits = _hit(gadgets,
                    rf'(xor\s+{reg},\s*{reg}|sub\s+{reg},\s*{reg}).*ret', badchars)
        if hits:
            zero_lines.append(f"    {reg:>5}  {len(hits):>4} gadgets   {hits[0].asm}")
        else:
            zero_missing.append(reg)
            zero_lines.append(f"    {reg:>5}     0 gadgets   NOT FOUND")
    # cdq for EDX
    cdq = _hit(gadgets, r'^cdq\s*;?\s*ret', badchars)
    if cdq:
        zero_lines.append(f"    {'edx':>5}  {len(cdq):>4} via cdq   {cdq[0].asm}")
        if 'edx' in zero_missing:
            zero_missing.remove('edx')
    status = "ok" if not zero_missing else ("warn" if len(zero_missing) < 4 else "missing")
    sections.append(("Zero Register", status, zero_lines))

    # ── 9. Stack pivot ───────────────────────────────────────────────────────
    pivot_lines = []
    for reg in REGS:
        if reg == 'ebp':
            continue
        hits = _hit(gadgets,
                    rf'(xchg\s+({reg},\s*esp|esp,\s*{reg})|mov\s+esp,\s*{reg}).*ret',
                    badchars)
        if hits:
            pivot_lines.append(f"    via {reg:<5}  {len(hits):>4} gadgets   {hits[0].asm}")
    leave = _hit(gadgets, r'(leave|mov\s+esp,\s*ebp).*ret', badchars)
    if leave:
        pivot_lines.append(f"    via {'leave':<5}  {len(leave):>4} gadgets   {leave[0].asm}")
    if not pivot_lines:
        pivot_lines.append("    NOT FOUND")
    sections.append(("Stack Pivot", "ok" if pivot_lines else "missing", pivot_lines))

    # ── 10. Key single instructions ──────────────────────────────────────────
    singles = [
        ('cld',    r'^cld\s*;?\s*ret',    'REQUIRED before stosd/lodsd'),
        ('cdq',    r'^cdq\s*;?\s*ret',    'null-free EDX zero'),
        ('pushad', r'^pushad\s*;?\s*ret', 'save all regs'),
        ('popad',  r'^popad\s*;?\s*ret',  'restore all regs'),
        ('stosd',  r'^stosd\s*;?\s*ret',  'eax->[edi], edi+=4'),
        ('lodsd',  r'^lodsd\s*;?\s*ret',  '[esi]->eax, esi+=4'),
        ('leave',  r'^leave\s*;?\s*ret',  'mov esp,ebp; pop ebp'),
        ('nop',    r'^nop\s*;?\s*ret',    'padding/alignment'),
    ]
    single_lines = []
    single_missing = []
    for name, pat, desc in singles:
        hits = _hit(gadgets, pat, badchars)
        if hits:
            single_lines.append(f"    {name:<8}  {len(hits):>4} gadgets   {hits[0].asm}")
        else:
            single_lines.append(f"    {name:<8}     0 gadgets   NOT FOUND  ({desc})")
            single_missing.append(name)
    status = "ok" if not single_missing else "warn"
    sections.append(("Key Single Instructions", status, single_lines))

    # ── 11. Multi-step path analysis ─────────────────────────────────────────
    path_lines = []
    path_lines.append("    Checking all 2-hop register copy paths via relay...")
    path_lines.append("")

    # Find all direct mov copies available
    direct = {}
    for dst in REGS:
        for src in REGS:
            if src == dst: continue
            hits = _hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)
            pp   = _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)
            xchg = _hit(gadgets, rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret', badchars)
            if hits or pp or xchg:
                direct[(src, dst)] = len(hits) + len(pp) + len(xchg)

    # Find gaps and two-hop solutions
    gaps = []
    for dst in REGS:
        for src in REGS:
            if src == dst: continue
            if (src, dst) in direct: continue
            # Look for relay: src->relay->dst
            relays = []
            for relay in REGS:
                if relay in (src, dst): continue
                if (src, relay) in direct and (relay, dst) in direct:
                    relays.append(relay)
            gaps.append((src, dst, relays))

    no_path = [(s, d) for s, d, r in gaps if not r]
    has_path = [(s, d, r) for s, d, r in gaps if r]

    if has_path:
        path_lines.append("    2-hop paths available for missing direct routes:")
        for src, dst, relays in sorted(has_path):
            relay_str = ', '.join(relays)
            path_lines.append(f"      {src} -> {dst}   via  {relay_str}")
    path_lines.append("")
    if no_path:
        path_lines.append("    No path found (direct or 2-hop) for:")
        for src, dst in sorted(no_path):
            path_lines.append(f"      {src} -> {dst}   (consider memory write/read relay)")

    sections.append(("Register Copy Path Analysis", "info", path_lines))

    return sections
