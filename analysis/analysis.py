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


def run_analysis(gadgets: List[Gadget], badchars: bytes, files: list = None) -> List[Tuple[str, str, List[str]]]:
    """
    Return a list of (section, status, [lines]) tuples.
    status: 'ok' | 'warn' | 'missing' | 'info'
    """
    sections = []

    # ── 1. Overview ──────────────────────────────────────────────────────────
    import os as _os
    overview_lines = []
    if files:
        names = [_os.path.basename(f) for f in files]
        file_str = ', '.join(names)
        overview_lines.append(f"  Gadget files:          {file_str}")
    overview_lines.append(f"  Total gadgets loaded:  {len(gadgets):,}")
    overview_lines.append(f"  Bad chars:             {', '.join(hex(b) for b in badchars)}")
    overview_lines.append(f"  Clean gadgets:         {sum(1 for g in gadgets if not g.has_badchar(badchars)):,}")
    sections.append(("Overview", "info", overview_lines))

    # ── Shared matrix builder ────────────────────────────────────────────────
    GUTTER  = 14   # left margin for the row-axis label

    def _best_gadget(patterns):
        """Try patterns in order, return first hit's address + asm."""
        for pat in patterns:
            hits = _hit(gadgets, pat, badchars)
            if hits:
                g = hits[0]
                return f"{g.addr_str}  {g.asm}"
        return None

    def make_matrix(row_label, col_label_str, count_fn, best_fn=None,
                    skip_same=True, best_w=80):
        """Build a labelled matrix with count columns and optional best-gadget column."""
        PREFIX = GUTTER + 2 + 5   # = 21

        out = []

        # Column axis label
        out.append(" " * PREFIX + "  " + col_label_str)

        # Register header
        hdr = " " * PREFIX
        for r in REGS:
            hdr += f"  {r:>4}"
        if best_fn:
            hdr += "   Best gadget (strict/clean/with return first, may be trimmed)"
        out.append(hdr)

        # Separator
        sep = " " * PREFIX
        for _ in REGS:
            sep += "  ----"
        if best_fn:
            sep += "   " + "-" * min(best_w, 80)
        out.append(sep)

        # Data rows
        mid = len(REGS) // 2
        for i, row_reg in enumerate(REGS):
            if i == mid:
                gutter = f"  {row_label:<{GUTTER - 2}}"
            else:
                gutter = " " * GUTTER

            cells = ""
            best_cell = ""
            best_n = 0
            best_src = None

            for col_reg in REGS:
                if skip_same and col_reg == row_reg:
                    cells += "  ----"
                    continue
                n = count_fn(row_reg, col_reg)
                cells += f"  {n:>4}"
                # Track highest-count cell for best gadget lookup
                if best_fn and n > best_n:
                    best_n = n
                    best_src = col_reg

            if best_fn and best_src:
                ex = best_fn(row_reg, best_src)
                if ex:
                    best_cell = f"   [{best_src}] {ex[:75]}"

            out.append(f"{gutter}  {row_reg:>5}{cells}{best_cell}")
        return out







    # ── 7. EAX Hub Map ───────────────────────────────────────────────────────
    OTHER_REGS = [r for r in REGS if r != 'eax']
    eax_lines = []
    eax_lines.append("    EAX is the primary relay register in most ROP chains.")
    eax_lines.append("    Strict (clean ; ret) shown first where available.")
    eax_lines.append("")
    eax_lines.append(f"    {'Route':<18}  {'Gadgets':>7}   Best gadget (strict/clean/with return first, may be trimmed)")
    eax_lines.append(f"    {'-'*18}  {'-'*7}   {'-'*60}")

    def _eax_best(src, dst):
        for pat in [
            rf'^mov\s+{dst},\s*{src}\s*;\s*ret',
            rf'^push\s+{src}\s*;\s*pop\s+{dst}\s*;\s*ret',
            rf'mov\s+{dst},\s*{src}.*ret',
            rf'push\s+{src}.*pop\s+{dst}.*ret',
            rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret',
        ]:
            hits = _hit(gadgets, pat, badchars)
            if hits:
                g = hits[0]
                return f"{g.addr_str}  {g.asm[:75]}"
        return None

    for reg in OTHER_REGS:
        hits_to = (_hit(gadgets, rf'mov\s+eax,\s*{reg}.*ret', badchars) +
                   _hit(gadgets, rf'push\s+{reg}.*pop\s+eax.*ret', badchars) +
                   _hit(gadgets, rf'xchg\s+(eax,\s*{reg}|{reg},\s*eax).*ret', badchars))
        hits_fr = (_hit(gadgets, rf'mov\s+{reg},\s*eax.*ret', badchars) +
                   _hit(gadgets, rf'push\s+eax.*pop\s+{reg}.*ret', badchars) +
                   _hit(gadgets, rf'xchg\s+(eax,\s*{reg}|{reg},\s*eax).*ret', badchars))
        best_to = _eax_best(reg, 'eax')
        best_fr = _eax_best('eax', reg)
        route_to = f"{reg} -> eax"
        route_fr = f"eax -> {reg}"
        eax_lines.append(f"    {route_to:<18}  {len(hits_to):>7}   {best_to or 'NOT FOUND'}")
        eax_lines.append(f"    {route_fr:<18}  {len(hits_fr):>7}   {best_fr or 'NOT FOUND'}")
        eax_lines.append("")

    sections.append(("EAX Hub Map  (routes to and from EAX)", "info", eax_lines))
    # ── 8. Register Copy Path Analysis ───────────────────────────────────────
    path_lines = []
    path_lines.append("    Checking all 2-hop register copy paths via relay...")
    path_lines.append("")

    # Build direct route table
    direct = {}
    for dst in REGS:
        for src in REGS:
            if src == dst: continue
            mov  = _hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)
            pp   = _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)
            xchg = _hit(gadgets, rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret', badchars)
            if mov or pp or xchg:
                direct[(src, dst)] = len(mov) + len(pp) + len(xchg)

    # Find gaps and two-hop solutions
    gaps = []
    for dst in REGS:
        for src in REGS:
            if src == dst: continue
            if (src, dst) in direct: continue
            relays = [r for r in REGS if r not in (src, dst)
                      and (src, r) in direct and (r, dst) in direct]
            gaps.append((src, dst, relays))

    no_path  = [(s, d) for s, d, r in gaps if not r]
    has_path = [(s, d, r) for s, d, r in gaps if r]

    def _best_for_pair(src, dst):
        for pat in [
            rf'^mov\s+{dst},\s*{src}\s*;\s*ret',
            rf'^push\s+{src}\s*;\s*pop\s+{dst}\s*;\s*ret',
            rf'mov\s+{dst},\s*{src}.*ret',
            rf'push\s+{src}.*pop\s+{dst}.*ret',
            rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret',
        ]:
            hits = _hit(gadgets, pat, badchars)
            if hits:
                g = hits[0]
                return f"{g.addr_str}  {g.asm[:75]}"
        return None

    if has_path:
        path_lines.append("    Multiple-Hop paths available for missing direct routes:")
        path_lines.append("")
        for src, dst, relays in sorted(has_path):
            relay_str = ', '.join(relays)
            path_lines.append(f"      {src} -> {dst}   via  {relay_str}")
            for relay in relays:
                ex1 = _best_for_pair(src, relay)
                ex2 = _best_for_pair(relay, dst)
                path_lines.append(f"        [{src}->{relay}]  {ex1 or 'NOT FOUND'}")
                path_lines.append(f"        [{relay}->{dst}]  {ex2 or 'NOT FOUND'}")
            path_lines.append("")
    if no_path:
        path_lines.append("    No path found (direct or 2-hop) for:")
        for src, dst in sorted(no_path):
            path_lines.append(f"      {src} -> {dst}   (consider memory write/read relay)")

    sections.append(("Register Copy Path Analysis", "info", path_lines))

    # ── 2. MOV copy matrix ───────────────────────────────────────────────────
    mov_missing = []
    def mov_count(dst, src):
        hits = _hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)
        if not hits: mov_missing.append((src, dst))
        return len(hits)

    def mov_best(dst, src):
        return _best_gadget([
            rf'^mov\s+{dst},\s*{src}\s*;\s*ret',        # strict
            rf'mov\s+{dst},\s*{src}.*ret',               # loose
        ])
    mov_lines = make_matrix("DST (row)", "SRC (columns) ->", mov_count)
    mov_lines.insert(0, "  How to read:  row = destination register,  column = source register")
    mov_lines.insert(1, "  A value of 4 means 4 gadgets exist for  mov ROW, COL")
    mov_lines.insert(2, "")
    sections.append(("MOV Copy Matrix  (mov DST, SRC)", "info", mov_lines))
    # ── 3. Push/pop relay matrix ─────────────────────────────────────────────
    pp_missing = []
    def pp_count(dst, src):
        hits = _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)
        if not hits: pp_missing.append((src, dst))
        return len(hits)

    def pp_best(dst, src):
        return _best_gadget([
            rf'^push\s+{src}\s*;\s*pop\s+{dst}\s*;\s*ret',   # strict
            rf'push\s+{src}.*pop\s+{dst}.*ret',                 # loose
        ])
    pp_lines = make_matrix("DST (row)", "SRC (columns) ->", pp_count)
    pp_lines.insert(0, "  How to read:  row = destination,  column = source")
    pp_lines.insert(1, "  A value of 7 means 7 gadgets exist for  push COL ; ... ; pop ROW")
    pp_lines.insert(2, "")
    sections.append(("Push/Pop Relay Matrix  (push SRC ... pop DST)", "info", pp_lines))
    # ── 4. XCHG matrix ───────────────────────────────────────────────────────
    def xchg_count(r1, r2):
        if r2 >= r1: return 0
        hits = _hit(gadgets, rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1}).*ret', badchars)
        return len(hits)

    def xchg_best(r1, r2):
        if r2 >= r1: return None
        return _best_gadget([
            rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1})\s*;\s*ret',
            rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1}).*ret',
        ])
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

    def mw_best(ptr, src):
        return _best_gadget([
            rf'^mov\s+(dword\s*)?\[{ptr}\],\s*{src}\s*;\s*ret',
            rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret',
        ])
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

    def mr_best(dst, ptr):
        return _best_gadget([
            rf'^mov\s+{dst},\s*(dword\s*)?\[{ptr}\]\s*;\s*ret',
            rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret',
        ])
    mr_lines = make_matrix("DST (row)", "PTR (columns) ->", mr_count)
    mr_lines.insert(0, "  How to read:  row = destination register,  column = pointer register")
    mr_lines.insert(1, "  A value of 69 means 69 gadgets exist for  mov ROW, [COL]")
    mr_lines.insert(2, "")
    sections.append(("Memory Read Matrix  (mov DST, [PTR])", "info", mr_lines))

    # ── Add / Sub ─────────────────────────────────────────────────────────────
    def add_count(dst, src):
        return len(_hit(gadgets, rf'add\s+{dst},\s*{src}.*ret', badchars))

    def sub_count(dst, src):
        return len(_hit(gadgets, rf'sub\s+{dst},\s*{src}.*ret', badchars))

    add_lines = []
    add_lines.append("  How to read:  row = destination register,  column = source register")
    add_lines.append("  ADD and SUB shown as separate matrices below")
    add_lines.append("")
    add_lines.append("  ADD  (add DST, SRC)")
    add_lines.append("")
    for l in make_matrix("DST (row)", "SRC (columns) ->", add_count):
        add_lines.append(l)
    add_lines.append("")
    add_lines.append("  SUB  (sub DST, SRC)")
    add_lines.append("")
    for l in make_matrix("DST (row)", "SRC (columns) ->", sub_count):
        add_lines.append(l)

    sections.append(("Add / Sub Matrix  (register to register)", "info", add_lines))

    # ── Inc / Dec / Neg ──────────────────────────────────────────────────────
    incdec_lines = []
    incdec_lines.append("  How to read:  count of clean gadgets for each operation on that register")
    incdec_lines.append("")
    incdec_lines.append(f"    {'Reg':<6}  {'inc':>6}  {'dec':>6}  {'neg':>6}")
    incdec_lines.append(f"    {'-'*6}  {'------':>6}  {'------':>6}  {'------':>6}")
    for reg in REGS:
        inc_n = len(_hit(gadgets, rf'inc\s+{reg}.*ret', badchars))
        dec_n = len(_hit(gadgets, rf'dec\s+{reg}.*ret', badchars))
        neg_n = len(_hit(gadgets, rf'neg\s+{reg}.*ret', badchars))
        incdec_lines.append(f"    {reg:<6}  {inc_n:>6}  {dec_n:>6}  {neg_n:>6}")
    sections.append(("Inc / Dec / Neg  (per register counts)", "info", incdec_lines))

    # ── 9. Capture ESP ───────────────────────────────────────────────────────
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
    sections.append(("Capture ESP  (get stack address into register)", "info", esp_lines))

    # ── 10. Zero register ────────────────────────────────────────────────────
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
    cdq = _hit(gadgets, r'^cdq\s*;?\s*ret', badchars)
    if cdq:
        zero_lines.append(f"    {'edx':>5}  {len(cdq):>4} via cdq   {cdq[0].asm}")
        if 'edx' in zero_missing:
            zero_missing.remove('edx')
    sections.append(("Zero Register", "info", zero_lines))
    # ── 11. Stack pivot ───────────────────────────────────────────────────────
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
    sections.append(("Stack Pivot", "info", pivot_lines))
    # ── 12. Key single instructions ───────────────────────────────────────────
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
    sections.append(("Key Single Instructions", "info", single_lines))

    return sections
