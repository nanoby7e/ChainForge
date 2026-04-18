"""
analysis.py — ChainForge DLL capability analysis

Architecture:
  - Module-level constants: REGS, destructive/caution patterns
  - Module-level pure helpers: _grade_asm, _best_candidates, _path_grade
  - Per-section builder functions: each returns (title, status, lines)
  - run_analysis(): orchestrator — calls builders, returns section list
"""

import re
import struct
from typing import List, Dict, Tuple, Optional
from core.search import Gadget, search_gadgets

# ── Register set ──────────────────────────────────────────────────────────────
REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

# ── Destructive / AV-prone patterns ──────────────────────────────────────────
_DESTR = re.compile(
    r'(\bhlt\b'
    r'|\bud2\b'
    r'|\bint\s+3\b'
    r'|\bint\s+0x80\b'
    r'|\brep\s+(movsd|stosd|scasd|lodsd|cmpsb|stosb|movsb)\b'
    r'|\bpop\s+(ds|es|ss|fs|gs)\b'
    r'|\b(in|out)\s+'
    r'|\b(idiv|div)\s+'
    r'|\blgdt\b|\blidt\b|\blldt\b'
    r'|\b(or|add|sub|and|xor)\s+esp,\s*(dword\s*)?\['
    r'|\bmov\s+esp,\s*(dword\s*)?\[)',
    re.IGNORECASE
)

_CAUTION = re.compile(
    r'(\b(or|add|sub|and|xor)\s+e[a-z]{2},\s*(dword\s*)?\[(?!esp)'
    r'|\bretn\s+0x(?!0+\b)[0-9a-fA-F]+'
    r'|\bleave\b)',
    re.IGNORECASE
)

# Matches hex immediates in ASM (e.g. 0x10020E0B) for bad-byte checking
_re_imm = re.compile(r'\b0x[0-9a-fA-F]{4,8}\b')


# ── Pure helper functions ─────────────────────────────────────────────────────

_search_cache: Dict[Tuple[str, bytes], List[Gadget]] = {}

def _hit(gadgets: List[Gadget], pattern: str, badchars: bytes) -> List[Gadget]:
    """Search gadgets with regex, filtering bad chars. Cached per run_analysis() call."""
    key = (pattern, badchars)
    if key in _search_cache:
        return _search_cache[key]
    result = search_gadgets(gadgets, pattern, badchars=badchars,
                            regex_mode=True, max_results=0)
    _search_cache[key] = result
    return result


def _grade_asm(asm: str) -> Tuple[str, str]:
    """Return (grade, note): GOOD / CAUTION / PROBLEMATIC."""
    m = _DESTR.search(asm)
    if m:
        return 'PROBLEMATIC', m.group(0).strip()
    m = _CAUTION.search(asm)
    if m:
        return 'CAUTION', m.group(0).strip()
    return 'GOOD', ''


def _best_candidates(gadgets: List[Gadget], badchars: bytes,
                     patterns: List[str], n: int = 2) -> list:
    """
    Return up to n (gadget, grade, note) tuples across patterns.
    Sorted GOOD first, CAUTION second. PROBLEMATIC excluded.
    """
    ORDER = {'GOOD': 0, 'CAUTION': 1}
    seen = set()
    candidates = []
    for pat in patterns:
        for g in _hit(gadgets, pat, badchars):
            if g.addr_str in seen:
                continue
            seen.add(g.addr_str)
            grade, note = _grade_asm(g.asm)
            if grade != 'PROBLEMATIC':
                candidates.append((g, grade, note))
            if len(candidates) >= n * 2:
                break
    candidates.sort(key=lambda x: ORDER.get(x[1], 2))
    # Filter out gadgets whose ASM immediates contain bad bytes
    candidates = [c for c in candidates if not _imm_has_badchar(c[0].asm, badchars)]
    return candidates[:n]


def _copy_candidates(gadgets, badchars, src, dst, n=2):
    """Best candidates for a direct register copy src -> dst."""
    return _best_candidates(gadgets, badchars, [
        rf'^mov\s+{dst},\s*{src}\s*;\s*ret',
        rf'^push\s+{src}\s*;\s*pop\s+{dst}\s*;\s*ret',
        rf'mov\s+{dst},\s*{src}.*ret',
        rf'push\s+{src}.*pop\s+{dst}.*ret',
        rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret',
    ], n)


def _path_grade(leg_candidates: list) -> str:
    """Worst grade across all legs determines path grade."""
    grades = [c[1] for leg in leg_candidates for c in leg]
    if 'PROBLEMATIC' in grades: return 'PROBLEMATIC'
    if 'CAUTION' in grades:     return 'CAUTION'
    return 'GOOD'


def _render_candidates(cands, first_label, indent, lines, asm_w=70):
    """
    Append candidate lines to `lines`. Only shows second if first is flagged.
    """
    pad = ' ' * indent
    label_w = len(first_label)
    for i, (g, grade, note) in enumerate(cands):
        if i == 1 and cands[0][1] == 'GOOD':
            break
        lbl  = first_label if i == 0 else ' ' * (label_w + 2)
        flag = f'  !! {note}' if grade != 'GOOD' else ''
        lines.append(f'{pad}[{lbl}]  {g.addr_str}  {g.asm[:asm_w]}{flag}')
        if i == 0 and grade != 'GOOD' and len(cands) > 1:
            lines.append(f'{pad}{" " * (label_w + 2)}  (alt:)')


# ── Matrix builder ────────────────────────────────────────────────────────────

_GUTTER = 14


def _make_matrix(row_label, col_label_str, count_fn, best_fn=None,
                 skip_same=True, best_w=75):
    """Build a labelled matrix. Optionally appends a best-gadget column."""
    PREFIX = _GUTTER + 2 + 5  # 21

    out = []
    out.append(' ' * PREFIX + '  ' + col_label_str)

    hdr = ' ' * PREFIX
    for r in REGS:
        hdr += f'  {r:>4}'
    if best_fn:
        hdr += '   Best gadget (strict/clean/with return first, may be trimmed)'
    out.append(hdr)

    sep = ' ' * PREFIX + '  ----' * len(REGS)
    if best_fn:
        sep += '   ' + '-' * 80
    out.append(sep)

    mid = len(REGS) // 2
    for i, row_reg in enumerate(REGS):
        gutter = f'  {row_label:<{_GUTTER - 2}}' if i == mid else ' ' * _GUTTER
        cells = ''
        best_n, best_src = 0, None
        for col_reg in REGS:
            if skip_same and col_reg == row_reg:
                cells += '  ----'
                continue
            n = count_fn(row_reg, col_reg)
            cells += f'  {n:>4}'
            if best_fn and n > best_n:
                best_n, best_src = n, col_reg
        best_cell = ''
        if best_fn and best_src:
            ex = best_fn(row_reg, best_src)
            if ex:
                best_cell = f'   [{best_src}] {ex[:best_w]}'
        out.append(f'{gutter}  {row_reg:>5}{cells}{best_cell}')
    return out


def _imm_has_badchar(asm: str, badchars: bytes) -> bool:
    """Check if any immediate hex value embedded in ASM contains a bad byte."""
    for m in _re_imm.finditer(asm):
        val = int(m.group(0), 16)
        try:
            val_bytes = val.to_bytes(4, 'little')
        except OverflowError:
            continue
        if any(b in badchars for b in val_bytes):
            return True
    return False


def _best_str(gadgets, badchars, patterns, w=75):
    """Return 'addr  asm' string for first clean, non-destructive hit, or None."""
    for pat in patterns:
        hits = _hit(gadgets, pat, badchars)
        if hits:
            g = hits[0]
            grade, _ = _grade_asm(g.asm)
            if grade != 'PROBLEMATIC' and not _imm_has_badchar(g.asm, badchars):
                return f'{g.addr_str}  {g.asm}'
    return None


# ── Section builders ──────────────────────────────────────────────────────────

def _section_overview(gadgets, badchars, files):
    lines = []
    if files:
        import os
        names = ', '.join(os.path.basename(f) for f in files)
        lines.append(f'  Gadget files:          {names}')
    lines.append(f'  Total gadgets loaded:  {len(gadgets):,}')
    lines.append(f'  Bad chars:             {", ".join(hex(b) for b in badchars)}')
    lines.append(f'  Clean gadgets:         {sum(1 for g in gadgets if not g.has_badchar(badchars)):,}')
    return ('Overview', 'info', lines)


def _section_eax_hub(gadgets, badchars):
    other = [r for r in REGS if r != 'eax']
    lines = [
        '    EAX is the primary relay register in most ROP chains.',
        '    Strict (clean ; ret) shown first where available.',
        '',
        f"    {'Route':<18}  {'Gadgets':>7}   Best gadget (strict/clean/with return first, may be trimmed)",
        f"    {'-'*18}  {'-'*7}   {'-'*60}",
    ]
    for reg in other:
        def _count(src, dst):
            return (len(_hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)) +
                    len(_hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)) +
                    len(_hit(gadgets, rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret', badchars)))

        def _best(src, dst):
            cands = _copy_candidates(gadgets, badchars, src, dst, n=1)
            if cands:
                g = cands[0][0]
                return f'{g.addr_str}  {g.asm[:75]}'
            return None

        n_to = _count(reg, 'eax')
        n_fr = _count('eax', reg)
        b_to = _best(reg, 'eax') or 'NOT FOUND'
        b_fr = _best('eax', reg) or 'NOT FOUND'
        lines.append(f"    {f'{reg} -> eax':<18}  {n_to:>7}   {b_to}")
        lines.append(f"    {f'eax -> {reg}':<18}  {n_fr:>7}   {b_fr}")
        lines.append('')
    return ('EAX Hub Map  (routes to and from EAX)', 'info', lines)


def _section_path_analysis(gadgets, badchars):
    # Build direct route table
    direct = {}
    for dst in REGS:
        for src in REGS:
            if src == dst: continue
            if (_hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars) or
                    _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars) or
                    _hit(gadgets, rf'xchg\s+({dst},\s*{src}|{src},\s*{dst}).*ret', badchars)):
                direct[(src, dst)] = True

    # Find gaps
    gaps = []
    for dst in REGS:
        for src in REGS:
            if src == dst or (src, dst) in direct: continue
            relays = [r for r in REGS if r not in (src, dst)
                      and (src, r) in direct and (r, dst) in direct]
            gaps.append((src, dst, relays))

    no_path  = [(s, d) for s, d, r in gaps if not r]
    has_path = [(s, d, r) for s, d, r in gaps if r]

    lines = [
        '    Multiple-Hop paths available for missing direct routes:',
        '    Grade: [GOOD] all legs clean   [CAUTION] side effects   [PROBLEMATIC] likely AV',
        '',
    ]

    if has_path:
        ORDER = {'GOOD': 0, 'CAUTION': 1, 'PROBLEMATIC': 2}
        graded = []
        for src, dst, relays in sorted(has_path):
            for relay in relays:
                leg1 = _copy_candidates(gadgets, badchars, src, relay)
                leg2 = _copy_candidates(gadgets, badchars, relay, dst)
                if not leg1 or not leg2: continue
                pg = _path_grade([leg1, leg2])
                graded.append((pg, src, dst, relay, leg1, leg2))

        graded.sort(key=lambda x: (ORDER[x[0]], x[1], x[2]))

        # Keep best-graded relay per (src, dst) pair
        best_per_pair = {}
        for entry in graded:
            key = (entry[1], entry[2])
            if key not in best_per_pair or ORDER[entry[0]] < ORDER[best_per_pair[key][0]]:
                best_per_pair[key] = entry

        for key in sorted(best_per_pair):
            pg, src, dst, relay, leg1, leg2 = best_per_pair[key]
            lines.append(f'  [{pg:<11}]  {src} -> {dst}   via  {relay}')
            for label, cands in [(f'{src}->{relay}', leg1), (f'{relay}->{dst}', leg2)]:
                _render_candidates(cands, label, 6, lines, asm_w=70)
            lines.append('')

    if no_path:
        lines.append('    No path found (direct or 2-hop) for:')
        for src, dst in sorted(no_path):
            lines.append(f'      {src} -> {dst}   (consider memory write/read relay)')

    return ('Register Copy Path Analysis', 'info', lines)


def _section_memwrite_map(gadgets, badchars):
    lines = [
        '  How to read:  REG (ptr) = register holding destination address',
        '                SRC       = register whose value is written to memory',
        '  Only clean, non-destructive gadgets shown.',
        '',
    ]
    for ptr in REGS:
        ptr_entries = []
        for src in REGS:
            if src == ptr: continue
            cands = _best_candidates(gadgets, badchars, [
                rf'^mov\s+(dword\s*)?\[{ptr}\],\s*{src}\s*;\s*ret',
                rf'^mov\s+(dword\s*)?\[{ptr}[+-][^\]]+\],\s*{src}\s*;\s*ret',
                rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret',
            ])
            if cands:
                ptr_entries.append((src, cands))
        if not ptr_entries:
            continue
        lines.append(f'  [{ptr}] as pointer:')
        lines.append(f"    {'SRC':<6}  {'Grade':<11}  Best gadget")
        lines.append(f"    {'-'*6}  {'-'*11}  {'-'*60}")
        for src, cands in ptr_entries:
            for i, (g, grade, note) in enumerate(cands):
                if i == 1 and cands[0][1] == 'GOOD':
                    break
                src_lbl = src if i == 0 else ''
                flag = f'  !! {note}' if grade != 'GOOD' else ''
                lines.append(f'    {src_lbl:<6}  [{grade:<9}]  {g.addr_str}  {g.asm[:65]}{flag}')
        lines.append('')
    return ('Memory Write Map  (reg -> [ptr])', 'info', lines)


def _section_memload_map(gadgets, badchars):
    lines = [
        '  How to read:  DST = register receiving the loaded value',
        '                PTR = register holding the source memory address',
        '  Only clean, non-destructive gadgets shown.',
        '  Second candidate shown only if first is flagged.',
        '',
    ]
    for dst in REGS:
        dst_entries = []
        for ptr in REGS:
            if ptr == dst: continue
            cands = _best_candidates(gadgets, badchars, [
                rf'^mov\s+{dst},\s*(dword\s*)?\[{ptr}\]\s*;\s*ret',
                rf'^mov\s+{dst},\s*(dword\s*)?\[{ptr}[+-][^\]]+\]\s*;\s*ret',
                rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret',
            ])
            if cands:
                dst_entries.append((ptr, cands))
        if not dst_entries:
            continue
        lines.append(f'  [{dst}] as destination:')
        lines.append(f"    {'PTR':<6}  {'Grade':<11}  Best gadget")
        lines.append(f"    {'-'*6}  {'-'*11}  {'-'*60}")
        for ptr, cands in dst_entries:
            for i, (g, grade, note) in enumerate(cands):
                if i == 1 and cands[0][1] == 'GOOD':
                    break
                ptr_lbl = ptr if i == 0 else ''
                flag = f'  !! {note}' if grade != 'GOOD' else ''
                lines.append(f'    {ptr_lbl:<6}  [{grade:<9}]  {g.addr_str}  {g.asm[:65]}{flag}')
        lines.append('')
    return ('Memory Load Map  ([ptr] -> reg)', 'info', lines)


def _section_mov_matrix(gadgets, badchars):
    missing = []

    def count(dst, src):
        h = _hit(gadgets, rf'mov\s+{dst},\s*{src}.*ret', badchars)
        if not h: missing.append((src, dst))
        return len(h)

    def best(dst, src):
        return _best_str(gadgets, badchars, [
            rf'^mov\s+{dst},\s*{src}\s*;\s*ret',
            rf'mov\s+{dst},\s*{src}.*ret',
        ])

    mat = _make_matrix('DST (row)', 'SRC (columns) ->', count, best_fn=best)
    mat.insert(0, '  How to read:  row = destination register,  column = source register')
    mat.insert(1, '  A value of 4 means 4 gadgets exist for  mov ROW, COL')
    mat.insert(2, '')
    return ('MOV Copy Matrix  (mov DST, SRC)', 'info', mat)


def _section_pp_matrix(gadgets, badchars):
    missing = []

    def count(dst, src):
        h = _hit(gadgets, rf'push\s+{src}.*pop\s+{dst}.*ret', badchars)
        if not h: missing.append((src, dst))
        return len(h)

    def best(dst, src):
        return _best_str(gadgets, badchars, [
            rf'^push\s+{src}\s*;\s*pop\s+{dst}\s*;\s*ret',
            rf'push\s+{src}.*pop\s+{dst}.*ret',
        ])

    mat = _make_matrix('DST (row)', 'SRC (columns) ->', count, best_fn=best)
    mat.insert(0, '  How to read:  row = destination,  column = source')
    mat.insert(1, '  A value of 7 means 7 gadgets exist for  push COL ; ... ; pop ROW')
    mat.insert(2, '')
    return ('Push/Pop Relay Matrix  (push SRC ... pop DST)', 'info', mat)


def _section_xchg_matrix(gadgets, badchars):
    def count(r1, r2):
        if r2 >= r1: return 0
        return len(_hit(gadgets, rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1}).*ret', badchars))

    mat = _make_matrix('REG (row)', 'REG (columns) ->', count)
    mat.insert(0, '  How to read:  lower-left triangle only  (symmetric operation)')
    mat.insert(1, '  A value of 2 means 2 gadgets swap ROW and COL  (both registers change)')
    mat.insert(2, '')
    return ('XCHG Matrix  (destructive swap)', 'info', mat)


def _section_memwrite_matrix(gadgets, badchars):
    def count(ptr, src):
        return len(_hit(gadgets, rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret', badchars))

    def best(ptr, src):
        return _best_str(gadgets, badchars, [
            rf'^mov\s+(dword\s*)?\[{ptr}\],\s*{src}\s*;\s*ret',
            rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret',
        ])

    mat = _make_matrix('PTR (row)', 'SRC (columns) ->', count, best_fn=best)
    mat.insert(0, '  How to read:  row = pointer register holding dest address,  column = source value')
    mat.insert(1, '  A value of 60 means 60 gadgets exist for  mov [ROW], COL')
    mat.insert(2, '')
    return ('Memory Write Matrix  (mov [PTR], SRC)', 'info', mat)


def _section_memread_matrix(gadgets, badchars):
    def count(dst, ptr):
        return len(_hit(gadgets, rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret', badchars))

    def best(dst, ptr):
        return _best_str(gadgets, badchars, [
            rf'^mov\s+{dst},\s*(dword\s*)?\[{ptr}\]\s*;\s*ret',
            rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret',
        ])

    mat = _make_matrix('DST (row)', 'PTR (columns) ->', count, best_fn=best)
    mat.insert(0, '  How to read:  row = destination register,  column = pointer register')
    mat.insert(1, '  A value of 69 means 69 gadgets exist for  mov ROW, [COL]')
    mat.insert(2, '')
    return ('Memory Read Matrix  (mov DST, [PTR])', 'info', mat)


def _section_addsub_matrix(gadgets, badchars):
    def add_count(dst, src):
        return len(_hit(gadgets, rf'add\s+{dst},\s*{src}.*ret', badchars))

    def sub_count(dst, src):
        return len(_hit(gadgets, rf'sub\s+{dst},\s*{src}.*ret', badchars))

    lines = [
        '  How to read:  row = destination register,  column = source register',
        '  ADD and SUB shown as separate matrices below',
        '',
        '  ADD  (add DST, SRC)',
        '',
    ]
    for l in _make_matrix('DST (row)', 'SRC (columns) ->', add_count):
        lines.append(l)
    lines.append('')
    lines.append('  SUB  (sub DST, SRC)')
    lines.append('')
    for l in _make_matrix('DST (row)', 'SRC (columns) ->', sub_count):
        lines.append(l)
    return ('Add / Sub Matrix  (register to register)', 'info', lines)


def _section_incdecneg(gadgets, badchars):
    lines = [
        '  How to read:  count of clean gadgets for each operation on that register',
        '',
        f"    {'Reg':<6}  {'inc':>6}  {'dec':>6}  {'neg':>6}",
        f"    {'-'*6}  {'------':>6}  {'------':>6}  {'------':>6}",
    ]
    for reg in REGS:
        inc_n = len(_hit(gadgets, rf'inc\s+{reg}.*ret', badchars))
        dec_n = len(_hit(gadgets, rf'dec\s+{reg}.*ret', badchars))
        neg_n = len(_hit(gadgets, rf'neg\s+{reg}.*ret', badchars))
        lines.append(f'    {reg:<6}  {inc_n:>6}  {dec_n:>6}  {neg_n:>6}')
    return ('Inc / Dec / Neg  (per register counts)', 'info', lines)


def _section_capture_esp(gadgets, badchars):
    lines = []
    for dst in REGS:
        hits = _hit(gadgets,
                    rf'(mov\s+{dst},\s*esp|lea\s+{dst},\s*\[esp|push\s+esp.*pop\s+{dst}).*ret',
                    badchars)
        if hits:
            lines.append(f'    {dst:>5}  {len(hits):>4} gadgets   {hits[0].asm}')
    if not lines:
        lines.append('    NOT FOUND in any register')
    return ('Capture ESP  (get stack address into register)', 'info', lines)


def _section_zero_register(gadgets, badchars):
    lines = []
    missing = []
    for reg in REGS:
        hits = _hit(gadgets, rf'(xor\s+{reg},\s*{reg}|sub\s+{reg},\s*{reg}).*ret', badchars)
        if hits:
            lines.append(f'    {reg:>5}  {len(hits):>4} gadgets   {hits[0].asm}')
        else:
            missing.append(reg)
            lines.append(f'    {reg:>5}     0 gadgets   NOT FOUND')
    cdq = _hit(gadgets, r'^cdq\s*;?\s*ret', badchars)
    if cdq:
        lines.append(f"    {'edx':>5}  {len(cdq):>4} via cdq   {cdq[0].asm}")
        if 'edx' in missing:
            missing.remove('edx')
    return ('Zero Register', 'info', lines)


def _section_stack_pivot(gadgets, badchars):
    lines = []
    for reg in REGS:
        if reg == 'ebp': continue
        hits = _hit(gadgets,
                    rf'(xchg\s+({reg},\s*esp|esp,\s*{reg})|mov\s+esp,\s*{reg}).*ret',
                    badchars)
        if hits:
            lines.append(f'    via {reg:<5}  {len(hits):>4} gadgets   {hits[0].asm}')
    leave = _hit(gadgets, r'(leave|mov\s+esp,\s*ebp).*ret', badchars)
    if leave:
        lines.append(f"    via {'leave':<5}  {len(leave):>4} gadgets   {leave[0].asm}")
    if not lines:
        lines.append('    NOT FOUND')
    return ('Stack Pivot', 'info', lines)


def _section_key_singles(gadgets, badchars):
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
    lines = []
    for name, pat, desc in singles:
        hits = _hit(gadgets, pat, badchars)
        if hits:
            lines.append(f'    {name:<8}  {len(hits):>4} gadgets   {hits[0].asm}')
        else:
            lines.append(f'    {name:<8}     0 gadgets   NOT FOUND  ({desc})')
    return ('Key Single Instructions', 'info', lines)


# ── Phase 2 section builders ─────────────────────────────────────────────────

def _section_quality_distribution(gadgets, badchars):
    """Score and grade distribution across clean gadgets."""
    lines = []
    clean = [g for g in gadgets if not g.has_badchar(badchars)]
    total = len(clean)
    if not total:
        lines.append('  No clean gadgets to analyse.')
        return ('Gadget Quality Distribution', 'info', lines)

    buckets = [
        ('Clean (< 20)',     lambda s: s < 20),
        ('Moderate (20-39)', lambda s: 20 <= s < 40),
        ('Heavy (40-59)',    lambda s: 40 <= s < 60),
        ('Complex (60+)',    lambda s: s >= 60),
    ]
    bucket_counts = []
    for label, test in buckets:
        c = sum(1 for g in clean if test(g.score))
        bucket_counts.append((label, c))

    grade_counts = {'GOOD': 0, 'CAUTION': 0, 'PROBLEMATIC': 0}
    for g in clean:
        grade, _ = _grade_asm(g.asm)
        grade_counts[grade] += 1

    bar_w = 40
    lines.append(f'  Total clean gadgets: {total:,}')
    lines.append('')
    lines.append('  Score Distribution  (lower = cleaner gadget):')
    for label, count in bucket_counts:
        pct = count / total * 100
        filled = int(bar_w * count / total)
        bar = '#' * filled + '-' * (bar_w - filled)
        lines.append(f'    {label:<22}  [{bar}]  {count:>6}  ({pct:5.1f}%)')

    lines.append('')
    lines.append('  Grade Distribution  (destructive pattern analysis):')
    for grade in ('GOOD', 'CAUTION', 'PROBLEMATIC'):
        count = grade_counts[grade]
        pct = count / total * 100
        filled = int(bar_w * count / total)
        bar = '#' * filled + '-' * (bar_w - filled)
        lines.append(f'    {grade:<22}  [{bar}]  {count:>6}  ({pct:5.1f}%)')

    return ('Gadget Quality Distribution', 'info', lines)


def _section_cross_module(gadgets, badchars):
    """Per-module capability comparison."""
    from collections import defaultdict
    by_module = defaultdict(list)
    for g in gadgets:
        by_module[g.module].append(g)

    if len(by_module) < 2:
        return ('Cross-Module Comparison', 'info',
                ['  Single module loaded -- comparison requires 2+ files.'])

    lines = []
    _R = r'e[a-z]{2}'
    capabilities = [
        ('MOV copy',   rf'mov\s+{_R},\s*{_R}.*ret'),
        ('Push/Pop',   rf'push\s+{_R}.*pop\s+{_R}.*ret'),
        ('XCHG',       rf'xchg\s+({_R},\s*{_R}).*ret'),
        ('Mem Write',  rf'mov\s+(dword\s*)?\[{_R}[^\]]*\],\s*{_R}.*ret'),
        ('Mem Read',   rf'mov\s+{_R},\s*(dword\s*)?\[{_R}[^\]]*\].*ret'),
        ('Pop Reg',    rf'pop\s+{_R}.*ret'),
        ('Zero Reg',   rf'(xor|sub)\s+({_R}),\s*\2.*ret'),
        ('Add/Sub',    rf'(add|sub)\s+{_R},\s*(0x|{_R}).*ret'),
        ('Inc/Dec',    rf'(inc|dec)\s+{_R}.*ret'),
        ('Stk Pivot',  rf'(xchg|mov)\s+.*esp.*ret'),
    ]

    mod_names = sorted(by_module.keys())
    col_w = max(14, min(22, max(len(m) for m in mod_names) + 2))

    lines.append('  Unique clean gadgets per module (deduplicated by ASM):')
    lines.append('')
    hdr = f"    {'Capability':<14}"
    for m in mod_names:
        hdr += f"  {m[:col_w]:>{col_w}}"
    lines.append(hdr)
    sep = f"    {'-'*14}" + (f"  {'-'*col_w}" * len(mod_names))
    lines.append(sep)

    for cap_name, pattern in capabilities:
        row = f"    {cap_name:<14}"
        for m in mod_names:
            hits = search_gadgets(by_module[m], pattern, badchars=badchars,
                                  regex_mode=True, max_results=0)
            row += f"  {len(hits):>{col_w}}"
        lines.append(row)

    lines.append(sep)
    row = f"    {'Total Clean':<14}"
    for m in mod_names:
        clean = sum(1 for g in by_module[m] if not g.has_badchar(badchars))
        row += f"  {clean:>{col_w}}"
    lines.append(row)

    return ('Cross-Module Comparison', 'info', lines)


def _section_aslr_awareness(gadgets, badchars):
    """Module address ranges and bad char impact on the address space."""
    from collections import defaultdict
    lines = []
    by_module = defaultdict(list)
    for g in gadgets:
        by_module[g.module].append(g)

    lines.append('  Module address range analysis:')
    lines.append('')
    lines.append(f"    {'Module':<24}  {'Low Addr':>12}  {'High Addr':>12}  {'Gadgets':>8}  {'Clean':>6}  Notes")
    lines.append(f"    {'-'*24}  {'-'*12}  {'-'*12}  {'-'*8}  {'-'*6}  {'-'*30}")

    for mod in sorted(by_module.keys()):
        mod_g = by_module[mod]
        addrs = [g.address for g in mod_g]
        lo, hi = min(addrs), max(addrs)
        total_mod = len(mod_g)
        clean = sum(1 for g in mod_g if not g.has_badchar(badchars))
        notes = []
        if (lo & 0xFF000000) == 0:
            notes.append('null high byte')
        if 0x10000000 <= lo < 0x20000000:
            notes.append('standard DLL range')
        elif 0x00400000 <= lo < 0x01000000:
            notes.append('standard EXE range')
        clean_pct = clean / total_mod * 100 if total_mod else 0
        if clean_pct < 50:
            notes.append(f'{clean_pct:.0f}% clean')
        note_str = ', '.join(notes) if notes else 'OK'
        lines.append(f"    {mod[:24]:<24}  0x{lo:08x}  0x{hi:08x}  {total_mod:>8}  {clean:>6}  {note_str}")

    lines.append('')
    lines.append('  Bad char impact on address bytes:')
    lines.append(f"    {'Byte':>6}  {'Eliminated':>12}  {'% of Total':>10}  Note")
    lines.append(f"    {'-'*6}  {'-'*12}  {'-'*10}  {'-'*40}")
    bc_notes = {
        0x00: 'null byte', 0x0a: 'linefeed', 0x0d: 'carriage return',
        0x09: 'tab', 0x0b: 'vertical tab', 0x0c: 'form feed', 0x20: 'space',
    }
    for bc in sorted(badchars):
        affected = sum(1 for g in gadgets
                       if any(b == bc for b in struct.pack('<I', g.address)))
        pct = affected / len(gadgets) * 100 if gadgets else 0
        note = bc_notes.get(bc, '')
        lines.append(f"    0x{bc:02x}  {affected:>12,}  {pct:>9.1f}%  {note}")

    return ('Module Address Analysis  (ASLR / Rebase)', 'info', lines)


def _section_api_readiness(gadgets, badchars):
    """VirtualAlloc / WriteProcessMemory ROP chain prerequisites."""
    _R = r'e[a-z]{2}'
    checks = [
        ('pop eax',     rf'pop\s+eax.*ret',
         'Function pointer / return value'),
        ('pop ebx',     rf'pop\s+ebx.*ret',
         'dwSize / parameter setup'),
        ('pop ecx',     rf'pop\s+ecx.*ret',
         'lpAddress / lpBuffer'),
        ('pop edx',     rf'pop\s+edx.*ret',
         'flAllocationType / nSize'),
        ('pop esi',     rf'pop\s+esi.*ret',
         'flProtect / pointer register'),
        ('pop edi',     rf'pop\s+edi.*ret',
         'Return address / hProcess'),
        ('pop ebp',     rf'pop\s+ebp.*ret',
         'lpNumberOfBytesWritten / frame'),
        ('pushad',      rf'pushad.*ret',
         'Push all regs to build API call frame'),
        ('Zero EAX',    rf'(xor\s+eax,\s*eax|sub\s+eax,\s*eax).*ret',
         'Null-free zero for parameter setup'),
        ('Zero EDX',    rf'(xor\s+edx,\s*edx|sub\s+edx,\s*edx|cdq).*ret',
         'Zero EDX (cdq if EAX positive)'),
        ('Neg EAX',     rf'neg\s+eax.*ret',
         'Negate for null-free value encoding'),
        ('Capture ESP',
         rf'(mov\s+{_R},\s*esp|lea\s+{_R},\s*\[esp|push\s+esp.*pop\s+{_R}).*ret',
         'Get current stack address'),
        ('Mem Write',
         rf'mov\s+(dword\s*)?\[{_R}[^\]]*\],\s*{_R}.*ret',
         'Write register to controlled memory'),
        ('Stack Pivot',
         rf'(xchg\s+({_R},\s*esp|esp,\s*{_R})|mov\s+esp,\s*{_R}).*ret',
         'Redirect ESP to controlled buffer'),
        ('CLD',         rf'cld.*ret',
         'Direction flag for string operations'),
        ('STOSD',       rf'stosd.*ret',
         'Write eax to [edi], edi+=4'),
    ]

    lines = []
    lines.append('  VirtualAlloc / WriteProcessMemory ROP chain prerequisites:')
    lines.append('')
    lines.append(f"    {'Gadget':<16}  {'Count':>6}  {'Status':<6}  Purpose")
    lines.append(f"    {'-'*16}  {'-'*6}  {'-'*6}  {'-'*50}")

    ready = 0
    for name, pattern, purpose in checks:
        hits = _hit(gadgets, pattern, badchars)
        count = len(hits)
        status = 'READY' if count > 0 else 'MISS'
        if count > 0:
            ready += 1
        lines.append(f"    {name:<16}  {count:>6}  {status:<6}  {purpose}")

    total_checks = len(checks)
    pct = ready / total_checks * 100
    if pct >= 90:
        verdict = 'EXCELLENT -- all or nearly all prerequisites available'
    elif pct >= 70:
        verdict = 'GOOD -- most available, workarounds may be needed for gaps'
    elif pct >= 50:
        verdict = 'PARTIAL -- several missing, chain will require creativity'
    else:
        verdict = 'LIMITED -- many missing, consider loading additional modules'
    lines.append('')
    lines.append(f"  Readiness: {ready}/{total_checks} ({pct:.0f}%)  --  {verdict}")

    return ('API Chain Readiness  (VirtualAlloc / WriteProcessMemory)', 'info', lines)


def _section_reliability(gadgets, badchars):
    """Reliability flag distribution across clean gadgets."""
    lines = []
    clean = [g for g in gadgets if not g.has_badchar(badchars)]
    total = len(clean)
    if not total:
        lines.append('  No clean gadgets to analyse.')
        return ('Gadget Reliability Summary', 'info', lines)

    categories = [
        ('Plain ret ending',   r';\s*ret$',
         'Most reliable -- clean stack return'),
        ('retn N ending',      r'retn\s+0x',
         'Needs N bytes of stack padding'),
        ('Memory dereference', r'(mov|add|sub|or|xor|and)\s+\w+,\s*(dword\s*)?\[',
         'Requires valid pointer'),
        ('Memory write',       r'(mov|add|sub|or|xor|and)\s+(dword\s*)?\[',
         'Target must be writable'),
        ('ESP modification',   r'(add|sub|xchg|mov)\s+esp',
         'Changes stack pointer'),
        ('Call instruction',   r'\bcall\s+',
         'Pushes return address onto stack'),
        ('Leave instruction',  r'\bleave\b',
         'Overwrites ESP and pops EBP'),
        ('String operations',  r'\b(stosd|lodsd|movsd|stosb|movsb)\b',
         'Requires CLD + valid ESI/EDI'),
    ]

    lines.append('  Reliability flags across all clean gadgets:')
    lines.append('')
    lines.append(f"    {'Category':<24}  {'Count':>6}  {'% Clean':>8}  Note")
    lines.append(f"    {'-'*24}  {'-'*6}  {'-'*8}  {'-'*40}")

    for cat_name, pattern, note in categories:
        count = sum(1 for g in clean if re.search(pattern, g.asm, re.IGNORECASE))
        pct = count / total * 100
        lines.append(f"    {cat_name:<24}  {count:>6}  {pct:>7.1f}%  {note}")

    return ('Gadget Reliability Summary', 'info', lines)


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_analysis(gadgets: List[Gadget], badchars: bytes,
                 files: list = None,
                 progress=None) -> List[Tuple[str, str, List[str]]]:
    """
    Run all analysis sections and return a list of (title, status, lines).
    status is always 'info' — users differentiate pass/fail themselves.

    progress: optional callback(step: int, total: int, label: str)
              called before each section so the UI can show progress.
    """
    _search_cache.clear()
    g, b = gadgets, badchars

    steps = [
        ("Overview",              lambda: _section_overview(g, b, files)),
        ("Quality Distribution",  lambda: _section_quality_distribution(g, b)),
        ("Cross-Module Compare",  lambda: _section_cross_module(g, b)),
        ("Module Addresses",      lambda: _section_aslr_awareness(g, b)),
        ("API Chain Readiness",   lambda: _section_api_readiness(g, b)),
        ("Reliability Summary",   lambda: _section_reliability(g, b)),
        ("Capture ESP",           lambda: _section_capture_esp(g, b)),
        ("Stack Pivot",           lambda: _section_stack_pivot(g, b)),
        ("EAX Hub Map",           lambda: _section_eax_hub(g, b)),
        ("Multi-Hop Paths",       lambda: _section_path_analysis(g, b)),
        ("Memory Write Map",      lambda: _section_memwrite_map(g, b)),
        ("Memory Load Map",       lambda: _section_memload_map(g, b)),
        ("MOV Matrix",            lambda: _section_mov_matrix(g, b)),
        ("Push/Pop Matrix",       lambda: _section_pp_matrix(g, b)),
        ("XCHG Matrix",           lambda: _section_xchg_matrix(g, b)),
        ("Mem Write Matrix",      lambda: _section_memwrite_matrix(g, b)),
        ("Mem Read Matrix",       lambda: _section_memread_matrix(g, b)),
        ("Add/Sub Matrix",        lambda: _section_addsub_matrix(g, b)),
        ("Inc/Dec/Neg",           lambda: _section_incdecneg(g, b)),
        ("Zero Register",         lambda: _section_zero_register(g, b)),
        ("Key Instructions",      lambda: _section_key_singles(g, b)),
    ]

    results = []
    total = len(steps)
    for i, (label, fn) in enumerate(steps):
        if progress:
            progress(i, total, label)
        results.append(fn())
    return results
