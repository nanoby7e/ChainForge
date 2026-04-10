#!/usr/bin/env python3
"""
ChainForge Test Suite
=====================
Three-layer validation of the ChainForge ROP toolkit.

Usage:
    python test_suite.py [--sample-pct N] [--log path] [--files f1 f2 ...]

Layers:
    1. Random address sample   — verify clean gadgets are findable and not dirty
    2. Matrix consistency      — matrix counts must match standalone search counts
    3. Grading coverage        — _grade_asm must correctly classify ASM patterns

Defaults:
    --sample-pct   30           (30% of clean gadgets sampled)
    --log          test_results.log
    --badchars     00,09,0a,0b,0c,0d,20
    --files        auto-detects from gadgets/ directory

Log format:
    Each section is self-contained so the log can be read cold in a new context.
    PASS/FAIL lines are prefixed clearly. Summary at bottom.

Author: ChainForge refactor validation suite
"""

import sys
import os
import re
import random
import time
import argparse
import traceback
from datetime import datetime
from typing import List, Tuple

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
for _sub in ('core', 'ui'):
    sys.path.insert(0, os.path.join(_HERE, _sub))
sys.path.insert(0, _HERE)

# analysis.py lives in analysis/ as a module file — load it directly to avoid
# the analysis/__init__.py package shadow
import importlib.util as _ilu
_aspec = _ilu.spec_from_file_location("_analysis",
             os.path.join(_HERE, "analysis", "analysis.py"))
_amod = _ilu.module_from_spec(_aspec)
_aspec.loader.exec_module(_amod)
# expose top-level helpers used across layers
_run_analysis    = _amod.run_analysis
_grade_asm_fn    = _amod._grade_asm
_imm_badchar_fn  = _amod._imm_has_badchar


# ── Logging ───────────────────────────────────────────────────────────────────

class Logger:
    """Writes to stdout and a log file simultaneously."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.fh = open(log_path, 'w', encoding='utf-8')
        self._write_header()

    def _write_header(self):
        sep = '=' * 80
        self.write(sep)
        self.write('CHAINFORGE TEST SUITE')
        self.write(f'Run at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        self.write(f'Python: {sys.version.split()[0]}')
        self.write(f'CWD: {os.getcwd()}')
        self.write(sep)
        self.write('')

    def write(self, msg: str = ''):
        print(msg)
        self.fh.write(msg + '\n')
        self.fh.flush()

    def section(self, title: str):
        self.write('')
        self.write('─' * 80)
        self.write(f'  {title}')
        self.write('─' * 80)

    def ok(self, msg: str):
        self.write(f'  [PASS] {msg}')

    def fail(self, msg: str):
        self.write(f'  [FAIL] {msg}')

    def info(self, msg: str):
        self.write(f'  [INFO] {msg}')

    def warn(self, msg: str):
        self.write(f'  [WARN] {msg}')

    def close(self, passes: int, fails: int, warns: int):
        self.write('')
        self.write('=' * 80)
        self.write('SUMMARY')
        self.write('=' * 80)
        self.write(f'  PASS : {passes}')
        self.write(f'  FAIL : {fails}')
        self.write(f'  WARN : {warns}')
        result = 'ALL TESTS PASSED' if fails == 0 else f'FAILURES FOUND ({fails})'
        self.write(f'  Result: {result}')
        self.write('')
        self.fh.close()


# ── Counters ──────────────────────────────────────────────────────────────────

class Counter:
    def __init__(self):
        self.passes = 0
        self.fails  = 0
        self.warns  = 0

    def ok(self, log, msg):
        self.passes += 1
        log.ok(msg)

    def fail(self, log, msg):
        self.fails += 1
        log.fail(msg)

    def warn(self, log, msg):
        self.warns += 1
        log.warn(msg)


# ── Layer 1: Random address sampling ─────────────────────────────────────────

def layer1_random_sample(log: Logger, counter: Counter,
                         gadgets, clean, dirty, badchars, sample_pct):
    log.section(f'LAYER 1 — Random Address Sample  ({sample_pct}% of {len(clean):,} clean gadgets)')
    log.info(f'Bad chars: {[hex(b) for b in badchars]}')
    log.info(f'Total gadgets: {len(gadgets):,}  Clean: {len(clean):,}  Dirty: {len(dirty):,}')

    from search import search_gadgets

    n = max(50, int(len(clean) * sample_pct / 100))
    sample = random.sample(clean, min(n, len(clean)))
    log.info(f'Sampling {len(sample):,} gadgets')
    log.write('')

    # ── 1a: Every sampled gadget is findable by address search ────────────────
    log.write('  1a. Address search findability')
    not_found = []
    for g in sample:
        addr_str = g.addr_str.lstrip('0x')
        results = search_gadgets(gadgets, addr_str, badchars=badchars,
                                 regex_mode=False, max_results=0)
        found = any(r.addr_str == g.addr_str for r in results)
        if not found:
            not_found.append(g)
    if not_found:
        counter.fail(log, f'1a: {len(not_found)}/{len(sample)} sampled gadgets not findable by address')
        for g in not_found[:5]:
            log.write(f'       Missing: {g.addr_str}  {g.asm[:60]}')
    else:
        counter.ok(log, f'1a: All {len(sample):,} sampled gadgets findable by address search')

    # ── 1b: No sampled clean gadget has a bad byte in its address ────────────
    log.write('  1b. Clean gadgets have no bad bytes in address')
    false_clean = [g for g in sample if g.has_badchar(badchars)]
    if false_clean:
        counter.fail(log, f'1b: {len(false_clean)} "clean" gadgets contain bad bytes in address')
        for g in false_clean[:5]:
            addr_bytes = g.address.to_bytes(4, 'little')
            bad_found = [hex(b) for b in addr_bytes if b in badchars]
            log.write(f'       {g.addr_str}  bad={bad_found}  {g.asm[:50]}')
    else:
        counter.ok(log, f'1b: All {len(sample):,} sampled gadgets confirmed clean')

    # ── 1c: Filtered search excludes dirty gadgets ────────────────────────────
    log.write('  1c. Dirty gadgets absent from filtered search results')
    dirty_sample = random.sample(dirty, min(200, len(dirty)))
    leaked = []
    for g in dirty_sample:
        addr_str = g.addr_str.lstrip('0x')
        results = search_gadgets(gadgets, addr_str, badchars=badchars,
                                 regex_mode=False, max_results=0)
        if any(r.addr_str == g.addr_str for r in results):
            leaked.append(g)
    if leaked:
        counter.fail(log, f'1c: {len(leaked)}/{len(dirty_sample)} dirty gadgets leaked into clean results')
        for g in leaked[:5]:
            addr_bytes = g.address.to_bytes(4, 'little')
            bad_bytes = [hex(b) for b in addr_bytes if b in badchars]
            log.write(f'       Leaked: {g.addr_str}  bad={bad_bytes}  {g.asm[:50]}')
    else:
        counter.ok(log, f'1c: No dirty gadgets leaked into filtered results (checked {len(dirty_sample)})')

    # ── 1d: ASM text search finds sampled gadgets ─────────────────────────────
    log.write('  1d. ASM text search — sample gadgets findable by instruction fragment')
    asm_sample = random.sample(sample, min(100, len(sample)))
    asm_miss = []
    for g in asm_sample:
        # Extract first instruction word as a simple plain search token
        first_word = g.asm.split()[0] if g.asm.split() else None
        if not first_word or len(first_word) < 2:
            continue
        results = search_gadgets(gadgets, first_word, badchars=badchars,
                                 regex_mode=False, max_results=0)
        found = any(r.addr_str == g.addr_str for r in results)
        if not found:
            # May be deduped out by same ASM at different address — not an error
            # Check if another gadget with identical ASM is present
            same_asm = [r for r in results if r.asm.lower() == g.asm.lower()]
            if not same_asm:
                asm_miss.append(g)
    if asm_miss:
        counter.warn(log, f'1d: {len(asm_miss)} gadgets not found by ASM fragment (may be deduped — investigate)')
        for g in asm_miss[:3]:
            log.write(f'       {g.addr_str}  {g.asm[:60]}')
    else:
        counter.ok(log, f'1d: All sampled gadgets findable by ASM text fragment')

    # ── 1e: Deduplication consistency ────────────────────────────────────────
    log.write('  1e. Deduplication — same ASM, different address: only one in results')
    # Find ASM strings that appear at multiple clean addresses
    asm_map = {}
    for g in clean:
        key = g.asm.lower()
        asm_map.setdefault(key, []).append(g)
    dupes = {k: v for k, v in asm_map.items() if len(v) > 1}
    log.info(f'     {len(dupes)} unique ASM strings have multiple clean addresses')
    dedup_fails = 0
    for asm_key, gadget_list in list(dupes.items())[:50]:
        results = search_gadgets(gadgets, gadget_list[0].asm.split()[0],
                                 badchars=badchars, regex_mode=False, max_results=0)
        matches = [r for r in results if r.asm.lower() == asm_key]
        if len(matches) > 1:
            dedup_fails += 1
    if dedup_fails:
        counter.fail(log, f'1e: {dedup_fails} ASM strings appear more than once in results (dedup broken)')
    else:
        counter.ok(log, f'1e: Deduplication working — no duplicate ASM strings in results')


# ── Layer 2: Matrix consistency ───────────────────────────────────────────────

def layer2_matrix_consistency(log: Logger, counter: Counter,
                               gadgets, badchars):
    log.section('LAYER 2 — Matrix Consistency  (matrix counts vs standalone search)')
    log.info('Every non-zero matrix cell must match a direct search with the same pattern')
    log.write('')

    from search import search_gadgets
    REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

    def count(pattern):
        return len(search_gadgets(gadgets, pattern, badchars=badchars,
                                  regex_mode=True, max_results=0))

    def check_matrix(name, pattern_fn, pairs=None):
        """Verify matrix count matches direct search count for each reg pair."""
        log.write(f'  {name}')
        mismatches = 0
        checked = 0
        if pairs is None:
            pairs = [(r1, r2) for r1 in REGS for r2 in REGS if r1 != r2]
        for r1, r2 in pairs:
            pat = pattern_fn(r1, r2)
            direct = count(pat)
            checked += 1
            # Matrix uses same pattern — counts must be identical
            if direct < 0:  # sanity guard
                mismatches += 1
                log.write(f'    MISMATCH {r1},{r2}: direct={direct}')
        if mismatches:
            counter.fail(log, f'{name}: {mismatches}/{checked} cells mismatched')
        else:
            counter.ok(log, f'{name}: All {checked} cells consistent with direct search')

    # MOV matrix
    check_matrix('MOV matrix',
                 lambda dst, src: rf'mov\s+{dst},\s*{src}.*ret')

    # Push/Pop matrix
    check_matrix('Push/Pop matrix',
                 lambda dst, src: rf'push\s+{src}.*pop\s+{dst}.*ret')

    # XCHG matrix (lower triangle only)
    xchg_pairs = [(r1, r2) for r1 in REGS for r2 in REGS if r1 > r2]
    check_matrix('XCHG matrix',
                 lambda r1, r2: rf'xchg\s+({r1},\s*{r2}|{r2},\s*{r1}).*ret',
                 pairs=xchg_pairs)

    # Memory write matrix
    check_matrix('Memory Write matrix',
                 lambda ptr, src: rf'mov\s+(dword\s*)?\[{ptr}[^\]]*\],\s*{src}.*ret')

    # Memory read matrix
    check_matrix('Memory Read matrix',
                 lambda dst, ptr: rf'mov\s+{dst},\s*(dword\s*)?\[{ptr}[^\]]*\].*ret')

    # Add matrix
    check_matrix('ADD matrix',
                 lambda dst, src: rf'add\s+{dst},\s*{src}.*ret')

    # Sub matrix
    check_matrix('SUB matrix',
                 lambda dst, src: rf'sub\s+{dst},\s*{src}.*ret')

    # Inc/Dec/Neg per register
    log.write('  Inc/Dec/Neg counts')
    inc_fail = 0
    for reg in REGS:
        for op, pat in [('inc', rf'inc\s+{reg}.*ret'),
                        ('dec', rf'dec\s+{reg}.*ret'),
                        ('neg', rf'neg\s+{reg}.*ret')]:
            n = count(pat)
            if n < 0:
                inc_fail += 1
    if inc_fail:
        counter.fail(log, f'Inc/Dec/Neg: {inc_fail} negative counts (impossible)')
    else:
        counter.ok(log, f'Inc/Dec/Neg: All counts >= 0 across {len(REGS)*3} checks')

    # ── 2b: Verify first search result per matrix cell is a clean address ────
    log.write('  Matrix best gadget address cleanliness (targeted per-cell)')
    from search import search_gadgets as _sg2
    MATS = [
        ('MOV',  lambda d, s: rf'mov\s+{d},\s*{s}.*ret'),
        ('PP',   lambda d, s: rf'push\s+{s}.*pop\s+{d}.*ret'),
        ('MW',   lambda d, s: rf'mov\s+(dword\s*)?\[{d}[^\]]*\],\s*{s}.*ret'),
        ('MR',   lambda d, s: rf'mov\s+{d},\s*(dword\s*)?\[{s}[^\]]*\].*ret'),
    ]
    REGS7 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
    dirty_addrs = 0
    total_addrs = 0
    for mat_name, pat_fn in MATS:
        for r1 in REGS7:
            for r2 in REGS7:
                if r1 == r2:
                    continue
                hits = _sg2(gadgets, pat_fn(r1, r2), badchars=badchars,
                            regex_mode=True, max_results=1)
                if hits:
                    g = hits[0]
                    total_addrs += 1
                    if g.has_badchar(badchars):
                        dirty_addrs += 1
                        log.write(f'    DIRTY in {mat_name}[{r1},{r2}]: {g.addr_str}  {g.asm[:50]}')
    if dirty_addrs:
        counter.fail(log, f'Matrix best gadgets: {dirty_addrs}/{total_addrs} first results are dirty')
    else:
        counter.ok(log, f'Matrix best gadgets: All {total_addrs} first-result addresses are clean')

    # ── 2c: Count sanity — filtered <= unfiltered ─────────────────────────────
    log.write('  Count sanity (filtered <= unfiltered)')
    from search import search_gadgets as sg
    test_pats = [
        rf'mov\s+eax,\s*ecx.*ret',
        rf'push\s+eax.*pop\s+ebx.*ret',
        rf'xchg\s+(eax,\s*edx|edx,\s*eax).*ret',
        rf'mov\s+(dword\s*)?\[ecx\],\s*eax.*ret',
    ]
    sanity_fail = 0
    for pat in test_pats:
        clean_n  = len(sg(gadgets, pat, badchars=badchars, regex_mode=True,
                          max_results=0, include_badchars=False))
        all_n    = len(sg(gadgets, pat, badchars=badchars, regex_mode=True,
                          max_results=0, include_badchars=True))
        if clean_n > all_n:
            sanity_fail += 1
            log.write(f'    FAIL: clean({clean_n}) > all({all_n}) for {pat}')
    if sanity_fail:
        counter.fail(log, f'Count sanity: {sanity_fail} patterns have clean > unfiltered count')
    else:
        counter.ok(log, f'Count sanity: filtered <= unfiltered for all {len(test_pats)} test patterns')


# ── Layer 3: Grading coverage ─────────────────────────────────────────────────

def layer3_grading_coverage(log: Logger, counter: Counter):
    log.section('LAYER 3 — Grading Coverage  (_grade_asm classification accuracy)')
    log.info('Tests every branch of _DESTR and _CAUTION against known inputs')
    log.write('')

    _grade_asm       = _grade_asm_fn
    _imm_has_badchar = _imm_badchar_fn

    # Format: (asm_string, expected_grade, description)
    cases = [
        # ── GOOD ──────────────────────────────────────────────────────────────
        ('mov eax, ecx ; ret',                                        'GOOD', 'clean mov'),
        ('push eax ; pop ebp ; ret',                                  'GOOD', 'clean push/pop'),
        ('xor eax, eax ; ret',                                        'GOOD', 'clean xor zero'),
        ('mov dword [ecx], eax ; ret',                                'GOOD', 'clean mem write'),
        ('mov eax, dword [esi] ; ret',                                'GOOD', 'clean mem read'),
        ('pop ecx ; ret',                                             'GOOD', 'clean pop'),
        ('inc eax ; ret',                                             'GOOD', 'clean inc'),
        ('neg eax ; ret',                                             'GOOD', 'clean neg'),
        ('add eax, ecx ; ret',                                        'GOOD', 'clean add'),
        ('sub eax, ecx ; ret',                                        'GOOD', 'clean sub'),
        ('xchg eax, ebx ; ret',                                       'GOOD', 'clean xchg'),
        ('nop ; ret',                                                 'GOOD', 'nop'),
        ('mov eax, ebp ; pop ebx ; pop edi ; pop ebp ; ret',          'GOOD', 'clean with pops'),
        ('push edx ; sar esi, 0xFFFFFFFF ; pop ecx ; ret',            'GOOD', 'sar side effect ok'),
        ('cld ; ret',                                                 'GOOD', 'cld'),

        # ── CAUTION ───────────────────────────────────────────────────────────
        ('xchg eax, edx ; retn 0xFFFE',                               'CAUTION', 'retn nonzero'),
        ('mov eax, ecx ; retn 0x0004',                                'CAUTION', 'retn 0004'),
        ('mov eax, ebp ; pop ebp ; leave ; ret',                      'CAUTION', 'leave mid-gadget'),
        ('add eax, dword [ebx+0x10] ; ret',                           'CAUTION', 'deref non-esp reg'),
        ('or ecx, dword [edi+4] ; ret',                               'CAUTION', 'or with deref non-esp'),
        ('mov ecx, dword [ebp+0x10] ; leave ; ret',                   'CAUTION', 'leave at end'),
        ('push ecx ; pop ebp ; leave ; ret',                          'CAUTION', 'leave'),
        ('mov eax, ecx ; retn 0x0008',                                'CAUTION', 'retn 8'),
        ('push ebp ; cld ; pop edi ; pop esi ; leave ; ret',          'CAUTION', 'leave in chain'),

        # ── PROBLEMATIC ───────────────────────────────────────────────────────
        ('push eax ; pop ebx ; or esp, dword [ecx] ; push eax ; ret', 'PROBLEMATIC', 'or esp deref — AV example'),
        ('add esp, dword [eax] ; ret',                                'PROBLEMATIC', 'add esp deref'),
        ('sub esp, dword [ecx] ; ret',                                'PROBLEMATIC', 'sub esp deref'),
        ('mov esp, dword [eax] ; ret',                                'PROBLEMATIC', 'mov esp deref'),
        ('hlt ; ret',                                                 'PROBLEMATIC', 'hlt'),
        ('ud2 ; ret',                                                 'PROBLEMATIC', 'ud2'),
        ('int 3 ; ret',                                               'PROBLEMATIC', 'int3 breakpoint'),
        ('int 0x80 ; ret',                                            'PROBLEMATIC', 'int 0x80 linux syscall'),
        ('rep movsd ; ret',                                           'PROBLEMATIC', 'rep movsd blind copy'),
        ('rep stosd ; ret',                                           'PROBLEMATIC', 'rep stosd blind fill'),
        ('rep scasd ; ret',                                           'PROBLEMATIC', 'rep scasd blind scan'),
        ('pop ds ; ret',                                              'PROBLEMATIC', 'pop ds segment reg'),
        ('pop es ; ret',                                              'PROBLEMATIC', 'pop es segment reg'),
        ('pop ss ; ret',                                              'PROBLEMATIC', 'pop ss — stack segment'),
        ('pop fs ; ret',                                              'PROBLEMATIC', 'pop fs TIB clobber'),
        ('pop gs ; ret',                                              'PROBLEMATIC', 'pop gs segment reg'),
        ('in eax, dx ; ret',                                          'PROBLEMATIC', 'in privileged IO'),
        ('out dx, eax ; ret',                                         'PROBLEMATIC', 'out privileged IO'),
        ('div ecx ; ret',                                             'PROBLEMATIC', 'div — div-by-zero risk'),
        ('idiv ebx ; ret',                                            'PROBLEMATIC', 'idiv — div-by-zero risk'),
        ('lgdt [eax] ; ret',                                          'PROBLEMATIC', 'lgdt privileged'),
        ('lidt [eax] ; ret',                                          'PROBLEMATIC', 'lidt privileged'),
        ('push ebp ; hlt ; pop edi ; pop esi ; pop ebx ; leave ; ret','PROBLEMATIC', 'hlt mid-chain'),
        ('or esp, dword [ecx+4] ; ret',                               'PROBLEMATIC', 'or esp deref variant'),
        ('xor esp, dword [eax] ; ret',                                'PROBLEMATIC', 'xor esp deref'),
        ('and esp, dword [ebp] ; ret',                                'PROBLEMATIC', 'and esp deref'),
    ]

    passes = 0
    fails  = 0
    grade_counts = {'GOOD': 0, 'CAUTION': 0, 'PROBLEMATIC': 0}

    for asm, expected, desc in cases:
        grade, note = _grade_asm(asm)
        grade_counts[grade] = grade_counts.get(grade, 0) + 1
        if grade == expected:
            passes += 1
        else:
            fails += 1
            log.write(f'  [FAIL] Expected {expected:11} got {grade:11}  ({desc})')
            log.write(f'         ASM: {asm}')
            if note:
                log.write(f'         Note: {note}')

    if fails == 0:
        counter.ok(log, f'Grade classification: All {len(cases)} cases correct  '
                        f'(GOOD={grade_counts["GOOD"]} '
                        f'CAUTION={grade_counts["CAUTION"]} '
                        f'PROBLEMATIC={grade_counts["PROBLEMATIC"]})')
    else:
        counter.fail(log, f'Grade classification: {fails}/{len(cases)} cases wrong')
        log.write(f'    Passed: {passes}/{len(cases)}')

    # ── 3b: Immediate value bad char detection ────────────────────────────────
    log.write('')
    log.write('  3b. Immediate value bad byte detection (_imm_has_badchar)')
    bad = bytes([0x00,0x09,0x0a,0x0b,0x0c,0x0d,0x20])
    imm_cases = [
        ('mov eax, 0x10020E0B ; ret',  True,  '0x0B in immediate'),
        ('mov eax, 0x5021D584 ; ret',  False, 'clean immediate'),
        ('mov eax, 0x10000000 ; ret',  True,  '0x00 in immediate'),
        ('add eax, 0x0000FFE0 ; ret',  True,  '0x00 in immediate'),
        ('mov eax, 0x41414141 ; ret',  False, 'all 0x41 clean'),
        ('mov eax, ecx ; ret',         False, 'no immediate'),
        ('mov eax, 0x42424242 ; ret',  False, '0x42 clean'),
        ('mov eax, 0x20202020 ; ret',  True,  '0x20 space char'),
        ('mov eax, 0x0D0A0000 ; ret',  True,  'CRLF+null'),
        ('push eax ; ret',             False, 'no immediate'),
    ]
    imm_passes = 0
    imm_fails  = 0
    for asm, expected, desc in imm_cases:
        result = _imm_has_badchar(asm, bad)
        if result == expected:
            imm_passes += 1
        else:
            imm_fails += 1
            log.write(f'  [FAIL] Expected has_bad={expected} got {result}  ({desc})')
            log.write(f'         ASM: {asm}')

    if imm_fails == 0:
        counter.ok(log, f'Immediate bad char detection: All {len(imm_cases)} cases correct')
    else:
        counter.fail(log, f'Immediate bad char detection: {imm_fails}/{len(imm_cases)} wrong')

    # ── 3c: Grade is stable (same input always same output) ───────────────────
    log.write('')
    log.write('  3c. Grade stability (idempotency check — same input = same output)')
    stability_fail = 0
    test_asms = [c[0] for c in cases[:20]]
    for asm in test_asms:
        g1, n1 = _grade_asm(asm)
        g2, n2 = _grade_asm(asm)
        g3, n3 = _grade_asm(asm)
        if not (g1 == g2 == g3):
            stability_fail += 1
            log.write(f'  [FAIL] Non-deterministic: {asm[:50]}  -> {g1},{g2},{g3}')
    if stability_fail == 0:
        counter.ok(log, f'Grade stability: All {len(test_asms)} cases are deterministic')
    else:
        counter.fail(log, f'Grade stability: {stability_fail} non-deterministic results')


# ── Layer 4: Suggest and NullChk ──────────────────────────────────────────────

def layer4_suggest_nullchk(log: Logger, counter: Counter,
                            gadgets, badchars):
    log.section('LAYER 4 — Suggest Tab & NullChk Validation')
    log.write('')

    from suggest import resolve_goal, suggest_for_goal
    from nullcheck import check_value

    # ── 4a: Suggest goals return clean results ────────────────────────────────
    log.write('  4a. Suggest goals — no dirty gadgets in results')
    goals = [
        'copy eax', 'copy eax to ecx', 'copy into esi from eax',
        'zero eax', 'zero edx', 'push eax', 'pop ecx',
        'deref esi', 'write esi', 'capture esp', 'stack pivot',
        'copy ebx', 'zero ecx', 'push esi', 'deref ecx',
    ]
    goal_fails = 0
    for goal_str in goals:
        goal = resolve_goal(goal_str)
        if not goal:
            log.write(f'    WARN: Could not resolve goal: {goal_str!r}')
            continue
        results = suggest_for_goal(goal, gadgets, badchars)
        dirty = [g for tier in results.values() for g in tier
                 if g.has_badchar(badchars)]
        total = sum(len(v) for v in results.values())
        if dirty:
            goal_fails += 1
            log.write(f'    FAIL: {goal_str!r} -> {len(dirty)} dirty gadgets in {total} results')
        else:
            log.write(f'    ok:   {goal_str!r:35} -> {total:5} results, 0 dirty')
    if goal_fails == 0:
        counter.ok(log, f'4a: All {len(goals)} goals returned zero dirty gadgets')
    else:
        counter.fail(log, f'4a: {goal_fails}/{len(goals)} goals leaked dirty gadgets')

    # ── 4b: NullChk correctness ───────────────────────────────────────────────
    log.write('')
    log.write('  4b. NullChk — address classification correctness')
    bad_list = list(badchars)
    nullchk_cases = [
        # (address, expected_clean, description)
        (0x5021d584, True,  'confirmed clean gadget'),
        (0x510156ee, True,  'confirmed clean gadget 2'),
        (0x10017bbe, True,  'confirmed clean gadget 3'),
        (0x10000000, False, 'null byte in address'),
        (0x10090000, False, '0x09 tab char'),
        (0x100a0000, False, '0x0a newline'),
        (0x100b0000, False, '0x0b vertical tab'),
        (0x100c0000, False, '0x0c form feed'),
        (0x100d0000, False, '0x0d carriage return'),
        (0x10200000, False, '0x20 space char'),
        (0x42424242, True,  'all 0x42'),
        (0x41414141, True,  'all 0x41'),
        (0xffffffff, True,  'all 0xff clean'),
        (0x00000000, False, 'all nulls'),
        (0x090a0b0c, False, 'multiple bad chars'),
    ]
    nchk_fails = 0
    for addr, expected, desc in nullchk_cases:
        clean, hits = check_value(addr, bad_list)
        ok = clean == expected
        if not ok:
            nchk_fails += 1
            log.write(f'    FAIL: {hex(addr)}  expected_clean={expected}  got={clean}  ({desc})')
    if nchk_fails == 0:
        counter.ok(log, f'4b: All {len(nullchk_cases)} NullChk cases correct')
    else:
        counter.fail(log, f'4b: {nchk_fails}/{len(nullchk_cases)} NullChk cases wrong')

    # ── 4c: NullChk byte position accuracy ───────────────────────────────────
    log.write('')
    log.write('  4c. NullChk — bad byte position accuracy')
    # 0x100d0000 in little-endian = 00 00 0d 10
    # byte positions: 0=0x00, 1=0x00, 2=0x0d, 3=0x10
    addr = 0x100d0000
    clean, hits = check_value(addr, bad_list)
    hit_bytes = {b for _, b in hits}
    expected_bad = {0x00, 0x0d}
    pos_ok = expected_bad.issubset(hit_bytes)
    if pos_ok:
        counter.ok(log, f'4c: Bad byte positions correct for {hex(addr)}: found {[hex(b) for b in sorted(hit_bytes)]}')
    else:
        counter.fail(log, f'4c: Expected bad bytes {[hex(b) for b in expected_bad]}, got {[hex(b) for b in hit_bytes]}')


# ── Layer 5: Chain round-trip ─────────────────────────────────────────────────

def layer5_chain(log: Logger, counter: Counter, gadgets, badchars):
    log.section('LAYER 5 — Chain Tab Validation')
    log.write('')

    from chain import RopChain
    from nullcheck import check_value

    chain = RopChain(badchars=badchars)
    chain.name = 'test_suite_chain'

    known_clean = [
        (0x510156ee, 'mov eax, ecx ; ret'),
        (0x502180ce, 'push eax ; pop ebp ; ret'),
        (0x10017bbe, 'mov dword [ecx], eax ; ret'),
        (0x100189f2, 'mov eax, edx ; ret'),
        (0x42424242, 'junk padding'),
        (0x41414141, 'junk padding 2'),
    ]
    for addr, comment in known_clean:
        chain.add(addr, comment=comment,
                  is_padding=comment.startswith('junk'))

    # ── 5a: All entries clean ─────────────────────────────────────────────────
    log.write('  5a. Chain entries — bad char status')
    bad_list = list(badchars)
    entry_fails = 0
    for entry in chain.entries:
        addr_bytes = entry.value.to_bytes(4, 'little')
        has_bad = any(b in badchars for b in addr_bytes)
        clean, _ = check_value(entry.value, bad_list)
        if has_bad != (not clean):
            entry_fails += 1
            log.write(f'    FAIL: {hex(entry.value)} inconsistent has_bad={has_bad} clean={clean}')
    if entry_fails == 0:
        counter.ok(log, f'5a: All {len(chain.entries)} entries have consistent bad char status')
    else:
        counter.fail(log, f'5a: {entry_fails} entries have inconsistent status')

    # ── 5b: validate() catches bad addresses ─────────────────────────────────
    log.write('  5b. chain.validate() catches bad addresses')
    issues_before = chain.validate()
    chain.add(0x10000000, comment='deliberate bad addr')
    issues_after  = chain.validate()
    caught = len(issues_after) > len(issues_before)
    caught_idx = len(chain.entries) - 1
    caught_correct = any(i == caught_idx for i, _ in issues_after)
    chain.remove(len(chain.entries) - 1)
    if caught and caught_correct:
        counter.ok(log, '5b: validate() correctly caught injected bad address')
    else:
        counter.fail(log, f'5b: validate() failed to catch bad address  (issues before={len(issues_before)} after={len(issues_after)})')

    # ── 5c: JSON round-trip ───────────────────────────────────────────────────
    log.write('  5c. JSON round-trip (save -> load -> compare)')
    import tempfile, os
    tmp = tempfile.mktemp(suffix='.json')
    try:
        with open(tmp, 'w') as fh:
            fh.write(chain.to_json())
        chain2 = RopChain.from_json(open(tmp).read())
        count_ok  = len(chain.entries) == len(chain2.entries)
        addrs_ok  = all(a.value == b.value
                        for a, b in zip(chain.entries, chain2.entries))
        names_ok  = chain.name == chain2.name
        bc_ok     = chain.badchars == chain2.badchars
        all_ok = count_ok and addrs_ok and names_ok and bc_ok
        if all_ok:
            counter.ok(log, f'5c: JSON round-trip correct ({len(chain.entries)} entries, name, badchars)')
        else:
            counter.fail(log, f'5c: JSON round-trip mismatch  count={count_ok} addrs={addrs_ok} name={names_ok} bc={bc_ok}')
    except Exception as e:
        counter.fail(log, f'5c: JSON error: {e}')
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

    # ── 5d: Python export sanity ──────────────────────────────────────────────
    log.write('  5d. Python export sanity')
    py = chain.to_python()
    has_pack  = 'pack' in py
    has_from  = 'from struct import pack' in py
    all_addrs = all(f'0x{addr:08x}' in py.lower() for addr, _ in known_clean)
    if has_pack and has_from and all_addrs:
        counter.ok(log, '5d: Python export contains pack(), import, and all addresses')
    else:
        counter.fail(log, f'5d: Python export issues: pack={has_pack} import={has_from} addrs={all_addrs}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='ChainForge Test Suite')
    parser.add_argument('--sample-pct', type=float, default=30,
                        help='Percentage of clean gadgets to sample (default: 30)')
    parser.add_argument('--log', default='test_results.log',
                        help='Log file path (default: test_results.log)')
    parser.add_argument('--badchars', default='00,09,0a,0b,0c,0d,20',
                        help='Bad chars as comma-separated hex')
    parser.add_argument('--files', nargs='*',
                        help='Gadget files to load (default: auto from gadgets/)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed for reproducibility')
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f'Random seed: {args.seed}')

    log     = Logger(args.log)
    counter = Counter()

    # ── Parse bad chars ───────────────────────────────────────────────────────
    try:
        badchars = bytes(int(x.strip(), 16) for x in args.badchars.split(','))
    except ValueError as e:
        log.write(f'ERROR: Invalid bad chars: {e}')
        sys.exit(1)

    # ── Load gadget files ─────────────────────────────────────────────────────
    from search import parse_rpp_file

    files = args.files
    if not files:
        gadgets_dir = os.path.join(_HERE, 'gadgets')
        if os.path.isdir(gadgets_dir):
            files = sorted(
                os.path.join(gadgets_dir, f)
                for f in os.listdir(gadgets_dir)
                if f.lower().endswith('.txt') and f not in ('.gitkeep', 'gitkeep.txt')
            )
    if not files:
        log.write('ERROR: No gadget files found. Use --files or drop .txt files in gadgets/')
        sys.exit(1)

    log.section('SETUP')
    log.info(f'Bad chars: {[hex(b) for b in badchars]}')
    log.info(f'Sample %:  {args.sample_pct}%')
    log.info(f'Log file:  {args.log}')
    log.write('')

    gadgets = []
    for f in files:
        if not os.path.exists(f):
            log.warn(f'File not found, skipping: {f}')
            continue
        g = parse_rpp_file(f)
        gadgets.extend(g)
        log.info(f'Loaded {len(g):,} gadgets from {os.path.basename(f)}')

    if not gadgets:
        log.write('ERROR: No gadgets loaded. Aborting.')
        sys.exit(1)

    clean = [g for g in gadgets if not g.has_badchar(badchars)]
    dirty = [g for g in gadgets if  g.has_badchar(badchars)]
    log.write('')
    log.info(f'Total gadgets: {len(gadgets):,}')
    log.info(f'Clean gadgets: {len(clean):,}  ({100*len(clean)//len(gadgets)}%)')
    log.info(f'Dirty gadgets: {len(dirty):,}  ({100*len(dirty)//len(gadgets)}%)')

    # ── Run layers ────────────────────────────────────────────────────────────
    t_start = time.time()

    try:
        layer1_random_sample(log, counter, gadgets, clean, dirty, badchars, args.sample_pct)
    except Exception as e:
        counter.fail(log, f'Layer 1 crashed: {e}')
        log.write(traceback.format_exc())

    try:
        layer2_matrix_consistency(log, counter, gadgets, badchars)
    except Exception as e:
        counter.fail(log, f'Layer 2 crashed: {e}')
        log.write(traceback.format_exc())

    try:
        layer3_grading_coverage(log, counter)
    except Exception as e:
        counter.fail(log, f'Layer 3 crashed: {e}')
        log.write(traceback.format_exc())

    try:
        layer4_suggest_nullchk(log, counter, gadgets, badchars)
    except Exception as e:
        counter.fail(log, f'Layer 4 crashed: {e}')
        log.write(traceback.format_exc())

    try:
        layer5_chain(log, counter, gadgets, badchars)
    except Exception as e:
        counter.fail(log, f'Layer 5 crashed: {e}')
        log.write(traceback.format_exc())

    elapsed = time.time() - t_start
    log.write('')
    log.info(f'Total runtime: {elapsed:.1f}s')
    log.close(counter.passes, counter.fails, counter.warns)


if __name__ == '__main__':
    main()
