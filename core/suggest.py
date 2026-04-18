"""
suggest.py — ChainForge goal-based suggestions
Maps natural language goals to gadget search patterns,
ranked by cleanliness with side effect warnings.

Design:
- STATIC_GOALS dict contains generic patterns for non-register-specific goals
- Dynamic goals are generated on the fly from copy_patterns(), deref_patterns() etc.
- resolve_goal() parses the query for register names and verb, then routes to the
  right pattern generator — so "copy eax", "copy esi", "copy edx to ebx" all work
- Loose patterns (.*) are included alongside strict ones to catch gadgets with
  side effects (extra pops etc.) between key instructions
"""

import re
import sys
import argparse
from typing import List, Dict, Tuple, Optional
from core.search import Gadget, search_gadgets, format_gadget, format_pack_line

# ── Register sets ──────────────────────────────────────────────────────────────

ALL_REGS  = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
GPR       = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]
SAFE_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
REG       = r'e[a-z]{2}'


# ── Pattern generators (register-parameterised) ────────────────────────────────

def copy_patterns(src: str, dst: str = None) -> List[Tuple[str, str, int]]:
    """All ways to copy SRC into DST (or any register if dst=None)."""
    D = dst if dst else REG
    S = src
    no_self = f"(?!{S})"

    return [
        (f"mov {S} -> {dst or 'any'}  (strict — mov then immediately ret)",
         rf"^mov\s+{D},\s*{S}\s*;\s*ret",                                    1),
        (f"mov {S} -> {dst or 'any'}  (loose — pops/side effects ok)",
         rf"mov\s+{D},\s*{S}.*ret",                                            2),
        (f"lea [{S}] -> {dst or 'any'}  (strict — lea then immediately ret)",
         rf"^lea\s+{D},\s*\[{S}[^\]]*\]\s*;\s*ret",                        3),
        (f"lea [{S}] -> {dst or 'any'}  (loose)",
         rf"lea\s+{D},\s*\[{S}[^\]]*\].*ret",                                 4),
        (f"push {S} ; pop {dst or 'any'}  (strict — push pop then immediately ret)",
         rf"^push\s+{S}\s*;\s*pop\s+{D}\s*;\s*ret",                          5),
        (f"push {S} ; ... ; pop {dst or 'any'}  (loose — anything in between)",
         rf"push\s+{S}.*pop\s+{D}.*ret",                                      6),
        (f"xchg {S} <-> {dst or 'any'}  (destructive, strict)",
         rf"xchg\s+({S},\s*{no_self}{D}|{no_self}{D},\s*{S})\s*;.*ret",      7),
        (f"xchg {S} <-> {dst or 'any'}  (destructive, loose)",
         rf"xchg\s+({S},\s*{no_self}{D}|{no_self}{D},\s*{S}).*ret",          8),
        (f"xor-zero then or {S} -> {dst or 'any'}  (null-free copy)",
         rf"or\s+{D},\s*{S}.*ret",                                            9),
        (f"xor-zero then add {S} -> {dst or 'any'}",
         rf"add\s+{D},\s*{S}.*ret",                                           10),
        (f"broadest — any mov or lea {S} into {dst or 'any register'} not caught above",
         rf"(mov\s+{D},\s*{S}\b|lea\s+{D},\s*\[{S}[^\]]*\]).*ret",     11),
    ]


def copy_into_patterns(dst: str, src: str = None) -> List[Tuple[str, str, int]]:
    """
    All ways to copy ANYTHING (or specific SRC) INTO DST.
    This is the complement of copy_patterns() which treats the register as source.
    Use when you want to find gadgets that write into a specific register.
    """
    D = dst
    S = src if src else REG
    no_self = f"(?!{dst})"

    return [
        (f"mov {src or 'any'} -> {D}  (strict — mov then immediately ret)",
         rf"^mov\s+{D},\s*{S}\s*;\s*ret",                                    1),
        (f"mov {src or 'any'} -> {D}  (loose)",
         rf"mov\s+{D},\s*{S}.*ret",                                            2),
        (f"lea [{src or 'any'}] -> {D}  (strict — lea then immediately ret)",
         rf"^lea\s+{D},\s*\[{S}[^\]]*\]\s*;\s*ret",                        3),
        (f"lea [{src or 'any'}] -> {D}  (loose)",
         rf"lea\s+{D},\s*\[{S}[^\]]*\].*ret",                                 4),
        (f"push {src or 'any'} ; pop {D}  (strict — push pop then immediately ret)",
         rf"^push\s+{S}\s*;\s*pop\s+{D}\s*;\s*ret",                          5),
        (f"push {src or 'any'} ; ... ; pop {D}  (loose)",
         rf"push\s+{S}.*pop\s+{D}.*ret",                                      6),
        (f"xchg {D} <-> {src or 'any'}  (destructive, strict)",
         rf"xchg\s+({D},\s*{no_self}{S}|{no_self}{S},\s*{D})\s*;.*ret",      7),
        (f"xchg {D} <-> {src or 'any'}  (destructive, loose)",
         rf"xchg\s+({D},\s*{no_self}{S}|{no_self}{S},\s*{D}).*ret",          8),
        (f"pop {D}  (load from stack — immediate value)",
         rf"pop\s+{D}.*ret",                                                   9),
        (f"xor-zero then or -> {D}  (null-free load)",
         rf"xor\s+{D},\s*{D}.*or\s+{D},\s*{S}.*ret",                        10),
        (f"xor-zero then add -> {D}",
         rf"xor\s+{D},\s*{D}.*add\s+{D},\s*{S}.*ret",                       11),
        (f"broadest — any mov/lea/pop into {D} not caught above",
         rf"(mov\s+{D},\s*|lea\s+{D},\s*\[|pop\s+{D}\b).*ret",          12),
    ]


def copy_both_patterns(reg: str) -> List[Tuple[str, str, int]]:
    """
    Bidirectional copy — find ALL gadgets where REG appears as either
    source OR destination. Useful when you just want everything involving
    a register without caring about direction.
    """
    R = reg
    return [
        (f"{R} as source: mov {R} -> any  (strict)",
         rf"mov\s+{REG},\s*{R}\s*;.*ret",                                     1),
        (f"{R} as source: mov {R} -> any  (loose)",
         rf"mov\s+{REG},\s*{R}.*ret",                                          2),
        (f"{R} as dest:   mov any -> {R}  (strict)",
         rf"mov\s+{R},\s*{REG}\s*;.*ret",                                     3),
        (f"{R} as dest:   mov any -> {R}  (loose)",
         rf"mov\s+{R},\s*{REG}.*ret",                                          4),
        (f"{R} as source: push {R} ; pop any  (strict)",
         rf"push\s+{R}\s*;\s*pop\s+{REG}\s*;.*ret",                           5),
        (f"{R} as source: push {R} ; ... ; pop any  (loose)",
         rf"push\s+{R}.*pop\s+{REG}.*ret",                                    6),
        (f"{R} as dest:   push any ; pop {R}  (strict)",
         rf"push\s+{REG}\s*;\s*pop\s+{R}\s*;.*ret",                           7),
        (f"{R} as dest:   push any ; ... ; pop {R}  (loose)",
         rf"push\s+{REG}.*pop\s+{R}.*ret",                                    8),
        (f"lea [{R}] -> any  (source, strict)",
         rf"lea\s+{REG},\s*\[{R}[^\]]*\]\s*;.*ret",                           9),
        (f"lea [{R}] -> any  (source, loose)",
         rf"lea\s+{REG},\s*\[{R}[^\]]*\].*ret",                              10),
        (f"lea [any] -> {R}  (dest, strict)",
         rf"lea\s+{R},\s*\[{REG}[^\]]*\]\s*;.*ret",                          11),
        (f"lea [any] -> {R}  (dest, loose)",
         rf"lea\s+{R},\s*\[{REG}[^\]]*\].*ret",                              12),
        (f"xchg {R} <-> any  (both directions)",
         rf"xchg\s+({R},\s*{REG}|{REG},\s*{R}).*ret",                       13),
        (f"pop {R}  (stack into {R})",
         rf"pop\s+{R}.*ret",                                                  14),
        (f"or/add any -> {R}  (null-free copy into {R})",
         rf"(or|add)\s+{R},\s*{REG}.*ret",                                   15),
    ]


def deref_patterns(src: str, dst: str = None) -> List[Tuple[str, str, int]]:
    """All ways to read from memory at address in SRC into DST."""
    D = dst if dst else REG
    S = src
    patterns = [
        # Direct mov — strict
        (f"mov {dst or 'any'}, [{S}]  (strict — read is first instruction)",
         rf"mov\s+{D},\s*(dword\s*)?\[{S}[^\]]*\]\s*;.*ret",                1),
        # Direct mov — loose (read buried anywhere in gadget)
        (f"mov {dst or 'any'}, [{S}]  (loose — read anywhere in gadget)",
         rf"mov\s+{D},\s*(dword\s*)?\[{S}[^\]]*\].*ret",                     2),
        # Broadest: any instruction that reads from [S] into any register
        (f"ANY read from [{S}]  (broadest — add/sub/or/xchg with [{S}] as source)",
         rf"(mov|add|sub|or|xor|and|xchg|cmp)\s+{D},\s*(dword\s*|byte\s*|word\s*)?\[{S}[^\]]*\].*ret",
                                                                                 3),
        # Arithmetic reads
        (f"add {dst or 'any'}, [{S}]  (read + add — common buried in gadgets)",
         rf"add\s+{D},\s*(dword\s*)?\[{S}[^\]]*\].*ret",                     4),
        (f"or  {dst or 'any'}, [{S}]  (read + or)",
         rf"or\s+{D},\s*(dword\s*)?\[{S}[^\]]*\].*ret",                      5),
        (f"sub {dst or 'any'}, [{S}]  (read + subtract)",
         rf"sub\s+{D},\s*(dword\s*)?\[{S}[^\]]*\].*ret",                     6),
        # Read with offset
        (f"mov {dst or 'any'}, [{S}+offset]  (read with offset into {S})",
         rf"mov\s+{D},\s*(dword\s*)?\[{S}\s*[+\-][^\]]+\].*ret",           7),
        # Byte/word reads
        (f"movzx/movsx {dst or 'any'}, byte [{S}]  (zero/sign-extend byte read)",
         rf"(movzx|movsx)\s+{D},\s*(byte\s+|word\s+)?\[{S}[^\]]*\].*ret",   8),
    ]
    if src == "esi" or dst is None:
        patterns += [
            ("lodsd  [esi]->eax  (esi advances +4 side effect)",
             rf"lodsd.*ret",                                                       9),
            ("lodsb  [esi]->al  (byte read, esi advances +1)",
             rf"lodsb.*ret",                                                      10),
        ]
    if dst and dst != src:
        patterns.append(
            (f"relay: copy {S} to another reg, then deref",
             rf"mov\s+{REG},\s*{S}.*mov\s+{D},\s*(dword\s*)?\[{REG}\].*ret", 11)
        )
    return patterns


def write_patterns(dst_ptr: str, src: str = None) -> List[Tuple[str, str, int]]:
    """
    All ways to write SRC into memory at address in DST_PTR.
    Covers:
      - Direct writes: mov/or/add/sub/and/xor/xchg dword [ptr], src
      - Writes buried after other instructions in the gadget (loose .*) 
      - String instructions: stosd (eax->[edi])
      - Writes via [ptr+offset] or [ptr+reg]
    """
    S = src if src else REG
    D = dst_ptr

    patterns = [
        # ── Direct mov — strict (write is the first instruction) ─────────────
        (f"mov [{D}], {src or 'any'}  (strict — write is first)",
         rf"mov\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}\s*;.*ret",                1),

        # ── Direct mov — loose (write anywhere in gadget) ─────────────────────
        (f"mov [{D}], {src or 'any'}  (loose — write anywhere in gadget)",
         rf"mov\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                     2),

        # ── Arithmetic writes — if [D] is zero these are clean writes ─────────
        (f"or  [{D}], {src or 'any'}  (write if [{D}]==0, loose)",
         rf"or\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                      3),
        (f"add [{D}], {src or 'any'}  (write if [{D}]==0, loose)",
         rf"add\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                     4),
        (f"sub [{D}], {src or 'any'}  (subtract from memory, loose)",
         rf"sub\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                     5),
        (f"and [{D}], {src or 'any'}  (bitwise and into memory, loose)",
         rf"and\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                     6),
        (f"xor [{D}], {src or 'any'}  (xor into memory — zeroes if src==dst, loose)",
         rf"xor\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                     7),

        # ── Exchange — swaps register with memory value ────────────────────────
        (f"xchg [{D}], {src or 'any'}  (swaps, destructive, loose)",
         rf"xchg\s+(dword\s*)?\[{D}[^\]]*\],\s*{S}.*ret",                   8),

        # ── Byte/word writes ──────────────────────────────────────────────────
        (f"mov byte [{D}], {src or 'any'}  (byte write, loose)",
         rf"mov\s+byte\s*\[{D}[^\]]*\],\s*{S}.*ret",                         9),
        (f"mov word [{D}], {src or 'any'}  (word write, loose)",
         rf"mov\s+word\s*\[{D}[^\]]*\],\s*{S}.*ret",                        10),

        # ── Broadest: ANY write to [D] with any source ────────────────────────
        (f"any write to [{D}]  (broadest — catches all instruction forms)",
         rf"(mov|add|sub|or|xor|and|xchg)\s+(byte\s+|word\s+|dword\s+)?\[{D}[^\]]*\].*ret",
                                                                                   11),
    ]

    # ── String instruction stosd (eax -> [edi]) ───────────────────────────────
    if dst_ptr == "edi" or src == "eax" or src is None:
        patterns.append(
            ("stosd  eax->[edi], edi+=4  (cld required, edi must = dest address)",
             rf"stosd.*ret",                                                       12)
        )

    # ── Writes via [D+offset] or [D+reg] ─────────────────────────────────────
    patterns.append(
        (f"mov [{D}+offset], {src or 'any'}  (write with offset into {D})",
         rf"mov\s+(dword\s*)?\[{D}\s*[+\-][^\]]+\],\s*{S}.*ret",          13)
    )

    return patterns


def zero_patterns(reg: str = None) -> List[Tuple[str, str, int]]:
    """All ways to zero a register."""
    patterns = []
    if reg:
        R = reg
        patterns += [
            (f"xor {R}, {R}  (strict — cleanest, null-free, no immediate)",
             rf"xor\s+{R},\s*{R}\s*;.*ret",                                  1),
            (f"xor {R}, {R}  (loose — zero buried in gadget)",
             rf"xor\s+{R},\s*{R}.*ret",                                       2),
            (f"sub {R}, {R}  (strict)",
             rf"sub\s+{R},\s*{R}\s*;.*ret",                                  3),
            (f"sub {R}, {R}  (loose)",
             rf"sub\s+{R},\s*{R}.*ret",                                       4),
        ]
        if reg == "edx":
            patterns.insert(0, (
                "cdq  (zero EDX when EAX positive — null-free, no operands)",
                rf"cdq.*ret",                                                  1))
        patterns += [
            (f"and {R}, 0  (immediate — check for null bytes in address)",
             rf"and\s+{R},\s*0x0+\b.*ret",                                    4),
            (f"mov {R}, 0  (immediate — likely has null bytes)",
             rf"mov\s+{R},\s*0x0+\b.*ret",                                    5),
            (f"broadest — any zero/clear of {R}",
             rf"(xor\s+{R},\s*{R}|sub\s+{R},\s*{R}|cdq).*ret",              6),
        ]
    else:
        patterns = [
            ("xor reg, reg  (any register, cleanest)",
             rf"xor\s+({REG}),\s*\1.*ret",                                    1),
            ("sub reg, reg  (any register)",
             rf"sub\s+({REG}),\s*\1.*ret",                                    2),
            ("cdq  (zero EDX when EAX positive — null-free)",
             rf"cdq.*ret",                                                     3),
            ("and reg, 0  (immediate)",
             rf"and\s+{REG},\s*0x0+\b.*ret",                                  4),
        ]
    return patterns


def pop_patterns(reg: str = None) -> List[Tuple[str, str, int]]:
    """All ways to pop a value from the stack into a register."""
    R = reg if reg else REG
    return [
        (f"pop {reg or 'any'}  (strict — pop then immediately ret)",
         rf"pop\s+{R}\s*;.*ret",                                              1),
        (f"pop {reg or 'any'}  (loose — other instructions after ok)",
         rf"pop\s+{R}.*ret",                                                  2),
        (f"broadest — any pop of {reg or 'any register'}, no ret required",
         rf"pop\s+{R}",                                                        3),
    ]


def push_patterns(reg: str = None) -> List[Tuple[str, str, int]]:
    """All ways to push a register or value onto the stack."""
    R = reg if reg else REG
    return [
        (f"push {reg or 'any'}  (strict — push then immediately ret)",
         rf"push\s+{R}\s*;.*ret",                                              1),
        (f"push {reg or 'any'}  (loose — instructions after ok)",
         rf"push\s+{R}.*ret",                                                   2),
        (f"broadest — any push of {reg or 'any register or immediate'}",
         rf"push\s+{R}",                                                         3),
    ]


def add_offset_patterns(reg: str = None) -> List[Tuple[str, str, int]]:
    """All ways to add an offset to a register."""
    R = reg if reg else REG
    return [
        (f"add {reg or 'reg'}, imm  (strict)",
         rf"add\s+{R},\s*0x[0-9a-fA-F]+\s*;.*ret",                          1),
        (f"add {reg or 'reg'}, imm  (loose)",
         rf"add\s+{R},\s*0x[0-9a-fA-F]+.*ret",                              2),
        (f"sub {reg or 'reg'}, neg  (null-free — sub 0xFFFFFFxx == add small)",
         rf"sub\s+{R},\s*0x[fF]{{6}}[0-9a-fA-F]{{2}}.*ret",                3),
        (f"lea {reg or 'reg'}, [{reg or 'reg'}+N]  (add without touching src)",
         rf"lea\s+{R},\s*\[{R}[^\]]*\+[^\]]+\].*ret",                       4),
        (f"inc {reg or 'reg'}  (chain for small values)",
         rf"inc\s+{R}.*ret",                                                  5),
        (f"add {reg or 'reg'}, reg  (add two registers)",
         rf"add\s+{R},\s*{REG}.*ret",                                        6),
        (f"broadest — any addition or offset to {reg or 'reg'}",
         rf"(add|sub|inc|lea)\s+{R}.*ret",                                    7),
    ]


def sub_offset_patterns(reg: str = None) -> List[Tuple[str, str, int]]:
    """All ways to subtract an offset from a register."""
    R = reg if reg else REG
    return [
        (f"sub {reg or 'reg'}, imm  (strict)",
         rf"sub\s+{R},\s*0x[0-9a-fA-F]+\s*;.*ret",                          1),
        (f"sub {reg or 'reg'}, imm  (loose)",
         rf"sub\s+{R},\s*0x[0-9a-fA-F]+.*ret",                              2),
        (f"add {reg or 'reg'}, large  (sub via large positive)",
         rf"add\s+{R},\s*0x[fF]{{6}}[0-9a-fA-F]{{2}}.*ret",                3),
        (f"dec {reg or 'reg'}  (chain for small values)",
         rf"dec\s+{R}.*ret",                                                  4),
        (f"neg {reg or 'reg'}  (negate)",
         rf"neg\s+{R}.*ret",                                                  5),
        (f"sub {reg or 'reg'}, reg  (subtract two registers)",
         rf"sub\s+{R},\s*{REG}.*ret",                                        6),
        (f"broadest — any subtraction or decrement of {reg or 'reg'}",
         rf"(sub|dec|neg)\s+{R}.*ret",                                        7),
    ]


# ── Static goals (not register-parameterised) ──────────────────────────────────

STATIC_GOALS: Dict[str, List[Tuple[str, str, int]]] = {

    "copy": [
        ("mov reg, reg  (strict — mov immediately followed by ret, nothing between)",
         rf"^mov\s+{REG},\s*{REG}\s*;\s*ret",                                1),
        ("mov reg, reg  (loose — side effects between ok)",
         rf"mov\s+{REG},\s*{REG}.*ret",                                        2),
        ("lea [reg]  (strict — lea immediately followed by ret)",
         rf"^lea\s+{REG},\s*\[{REG}[^\]]*\]\s*;\s*ret",                    3),
        ("lea [reg]  (loose)",
         rf"lea\s+{REG},\s*\[{REG}\].*ret",                                    4),
        ("push/pop  (strict — push then pop then immediately ret)",
         rf"^push\s+{REG}\s*;\s*pop\s+{REG}\s*;\s*ret",                      5),
        ("push ... pop  (loose — instructions in between)",
         rf"push\s+{REG}.*pop\s+{REG}.*ret",                                   6),
        ("xchg  (destructive — both registers change, excludes esp)",
         rf"xchg\s+(?!.*\besp\b){REG},\s*(?!esp){REG}.*ret",                  7),
        ("xor-zero then or  (null-free copy — single gadget)",
         rf"xor\s+({REG}),\s*\1\s*;\s*or\s+{REG},\s*{REG}.*ret",             8),
        ("xor-zero then or  (null-free copy — loose, buried in gadget)",
         rf"xor\s+{REG},\s*{REG}.*or\s+{REG},\s*{REG}.*ret",                  9),
        # Broadest: any mov or lea not caught by strict/loose above
        # Does NOT include xchg (has its own category) or add/or (need zero-dest)
        ("broadest — any mov or lea register copy not caught above",
         rf"(mov\s+{REG},\s*{REG}|lea\s+{REG},\s*\[{REG}[^\]]*\]).*ret",  10),
    ],

    "capture esp": [
        ("mov reg, esp  (strict — cleanest)",
         rf"mov\s+{REG},\s*esp\s*;.*ret",                                      1),
        ("mov reg, esp  (loose — side effects ok)",
         rf"mov\s+{REG},\s*esp.*ret",                                           2),
        ("lea reg, [esp]  (strict)",
         rf"lea\s+{REG},\s*\[esp[^\]]*\]\s*;.*ret",                           3),
        ("lea reg, [esp+offset]  (loose)",
         rf"lea\s+{REG},\s*\[esp[^\]]*\].*ret",                                4),
        ("push esp ; pop any  (strict)",
         rf"push\s+esp\s*;\s*pop\s+{REG}\s*;.*ret",                           5),
        ("push esp ; ... ; pop any  (loose — pops in between)",
         rf"push\s+esp.*pop\s+{REG}.*ret",                                     6),
        ("xchg reg, esp  (modifies ESP — pivot side effect)",
         rf"xchg\s+(esp,\s*{REG}|{REG},\s*esp).*ret",                         7),
        ("broadest — any instruction reading ESP value",
         rf"(mov|lea|push|xchg)\s+.*esp.*ret",                                  8),
    ],

    "dereference": [
        # Direct mov — strict
        ("mov reg, [reg]  (strict — read is first instruction)",
         rf"mov\s+{REG},\s*(dword\s*)?\[{REG}[^\]]*\]\s*;.*ret",              1),
        # Direct mov — loose (read buried anywhere in gadget)
        ("mov reg, [reg]  (loose — read anywhere in gadget)",
         rf"mov\s+{REG},\s*(dword\s*)?\[{REG}[^\]]*\].*ret",                  2),
        # Broadest: any instruction that reads from memory into a register
        ("ANY read from [reg]  (broadest — catches all instruction forms)",
         rf"(mov|add|sub|or|xor|and|xchg|cmp|test)\s+{REG},\s*(dword\s*|byte\s*|word\s*)?\[{REG}[^\]]*\].*ret",
                                                                                 3),
        # Arithmetic reads (add/sub/or etc with memory source)
        ("add reg, [reg]  (read from memory and add — common in gadgets)",
         rf"add\s+{REG},\s*(dword\s*)?\[{REG}[^\]]*\].*ret",                  4),
        ("or  reg, [reg]  (read from memory and or)",
         rf"or\s+{REG},\s*(dword\s*)?\[{REG}[^\]]*\].*ret",                   5),
        ("sub reg, [reg]  (read from memory and subtract)",
         rf"sub\s+{REG},\s*(dword\s*)?\[{REG}[^\]]*\].*ret",                  6),
        # Reads with offset
        ("mov reg, [reg+offset]  (read with offset)",
         rf"mov\s+{REG},\s*(dword\s*)?\[{REG}\s*[+\-][^\]]+\].*ret",        7),
        # Byte/word reads
        ("movzx/movsx reg, byte [reg]  (zero/sign extend byte read)",
         rf"(movzx|movsx)\s+{REG},\s*(byte\s+|word\s+)?\[{REG}[^\]]*\].*ret", 8),
        # String instruction
        ("lodsd  [esi]->eax  (esi advances +4 side effect)",
         rf"lodsd.*ret",                                                           9),
        ("lodsb  [esi]->al   (byte read, esi advances +1)",
         rf"lodsb.*ret",                                                          10),
    ],

    "write memory": [
        # Direct mov — strict (write is first instruction)
        ("mov [reg], reg  (strict — write is first instruction)",
         rf"mov\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}\s*;.*ret",              1),
        # Direct mov — loose (write buried anywhere in gadget like the example gadget)
        ("mov [reg], reg  (loose — write anywhere in gadget)",
         rf"mov\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                  2),
        # Broadest: any write instruction to any memory address
        ("ANY write to [reg]  (broadest — catches all instruction forms)",
         rf"(mov|add|sub|or|xor|and|xchg)\s+(byte\s+|word\s+|dword\s+)?\[{REG}[^\]]*\],\s*{REG}.*ret",
                                                                                 3),
        # Arithmetic writes (clean if destination memory is zero)
        ("add [reg], reg  (write if dest mem is zero, loose)",
         rf"add\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                  4),
        ("sub [reg], reg  (subtract from memory)",
         rf"sub\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                  5),
        ("or  [reg], reg  (write if dest mem is zero, loose)",
         rf"or\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                   6),
        ("xor [reg], reg  (xor into memory)",
         rf"xor\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                  7),
        ("and [reg], reg  (bitwise and into memory)",
         rf"and\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                  8),
        # Exchange
        ("xchg [reg], reg  (swaps register with memory — destructive)",
         rf"xchg\s+(dword\s*)?\[{REG}[^\]]*\],\s*{REG}.*ret",                 9),
        # Byte/word writes
        ("mov byte [reg], reg  (byte write)",
         rf"mov\s+byte\s*\[{REG}[^\]]*\],\s*{REG}.*ret",                     10),
        # String instruction
        ("stosd  eax->[edi], edi+=4  (cld required first)",
         rf"stosd.*ret",                                                           11),
        # Writes with offset
        ("mov [reg+offset], reg  (write with offset)",
         rf"mov\s+(dword\s*)?\[{REG}\s*[+\-][^\]]+\],\s*{REG}.*ret",       12),
    ],

    "zero register": [
        ("xor reg, reg  (strict — cleanest, null-free, no immediate needed)",
         rf"xor\s+({REG}),\s*\1\s*;.*ret",                                    1),
        ("xor reg, reg  (loose — buried in gadget)",
         rf"xor\s+({REG}),\s*\1.*ret",                                         2),
        ("sub reg, reg  (strict)",
         rf"sub\s+({REG}),\s*\1\s*;.*ret",                                    3),
        ("sub reg, reg  (loose)",
         rf"sub\s+({REG}),\s*\1.*ret",                                         4),
        ("cdq  (zeroes EDX when EAX positive — null-free, no operands)",
         rf"cdq.*ret",                                                            5),
        ("and reg, 0  (immediate — check for null bytes in gadget address)",
         rf"and\s+{REG},\s*0x0+\b.*ret",                                       6),
        ("mov reg, 0  (immediate — likely has null bytes in instruction)",
         rf"mov\s+{REG},\s*0x0+\b.*ret",                                       7),
        ("broadest — any zero/clear of any register",
         rf"(xor\s+{REG},\s*{REG}|sub\s+{REG},\s*{REG}|cdq|and\s+{REG},\s*0).*ret",
                                                                                  8),
    ],

    "add offset": add_offset_patterns(),
    "subtract offset": sub_offset_patterns(),

    "inc dec": [
        ("inc any reg  (loose)",
         rf"inc\s+{REG}.*ret",                                                  1),
        ("dec any reg  (loose)",
         rf"dec\s+{REG}.*ret",                                                  2),
    ],

    "neg": [
        ("neg reg  (two's complement negate, any register)",
         rf"neg\s+{REG}.*ret",                                                  1),
    ],

    "stack pivot": [
        ("xchg reg, esp  (classic — strict)",
         rf"xchg\s+(esp,\s*{REG}|{REG},\s*esp)\s*;.*ret",                     1),
        ("xchg reg, esp  (loose)",
         rf"xchg\s+(esp,\s*{REG}|{REG},\s*esp).*ret",                         2),
        ("mov esp, reg  (strict)",
         rf"mov\s+esp,\s*{REG}\s*;.*ret",                                      3),
        ("mov esp, reg  (loose)",
         rf"mov\s+esp,\s*{REG}.*ret",                                           4),
        ("mov esp, ebp  (epilogue fragment)",
         rf"mov\s+esp,\s*ebp.*ret",                                             5),
        ("leave  (mov esp,ebp ; pop ebp)",
         rf"leave.*ret",                                                         6),
        ("add esp, N  (skip over stack data)",
         rf"add\s+esp,\s*0x[0-9a-fA-F]+.*ret",                                 7),
        ("sub esp, N  (back into controlled buffer)",
         rf"sub\s+esp,\s*0x[0-9a-fA-F]+.*ret",                                 8),
        ("broadest — any instruction that modifies ESP to controlled value",
         rf"(xchg|mov|add|sub)\s+.*(esp).*ret",                                 9),
    ],

    "call function": [
        ("call eax  (strict — most common, register holds function address)",
         rf"call\s+eax\s*;?\s*$",                                              1),
        ("call reg  (strict — any register)",
         rf"call\s+{REG}\s*;?\s*$",                                             2),
        ("call reg  (loose — call buried in gadget)",
         rf"call\s+{REG}.*ret",                                                  3),
        ("jmp eax  (strict)",
         rf"jmp\s+eax",                                                          4),
        ("jmp reg  (strict — any)",
         rf"jmp\s+{REG}",                                                        5),
        ("call [reg]  (indirect through pointer)",
         rf"call\s+\[{REG}\]",                                                  6),
        ("push reg ; ret  (trampoline — ret acts as jmp to register)",
         rf"push\s+{REG}\s*;.*ret",                                             7),
        ("push eax ; ret  (trampoline — most common)",
         rf"push\s+eax\s*;.*ret",                                               8),
        ("broadest — any call/jmp to a register",
         rf"(call|jmp)\s+(\[)?{REG}(\])?",                                     9),
    ],

    "pop": [
        ("pop eax  (strict — pop then immediately ret)",
         rf"pop\s+eax\s*;.*ret",                                                1),
        ("pop ebx  (strict)",  rf"pop\s+ebx\s*;.*ret",                         1),
        ("pop ecx  (strict)",  rf"pop\s+ecx\s*;.*ret",                         1),
        ("pop edx  (strict)",  rf"pop\s+edx\s*;.*ret",                         1),
        ("pop esi  (strict)",  rf"pop\s+esi\s*;.*ret",                         1),
        ("pop edi  (strict)",  rf"pop\s+edi\s*;.*ret",                         1),
        ("pop ebp  (strict)",  rf"pop\s+ebp\s*;.*ret",                         1),
        ("pop any  (loose — other pops/instructions after ok)",
         rf"pop\s+{REG}.*ret",                                                   2),
        ("broadest — any pop of any register",
         rf"pop\s+{REG}",                                                        3),
    ],

    "push": [
        ("push eax  (strict — push then immediately ret)",
         rf"push\s+eax\s*;.*ret",                                               1),
        ("push ebx  (strict)",  rf"push\s+ebx\s*;.*ret",                       1),
        ("push ecx  (strict)",  rf"push\s+ecx\s*;.*ret",                       1),
        ("push edx  (strict)",  rf"push\s+edx\s*;.*ret",                       1),
        ("push esi  (strict)",  rf"push\s+esi\s*;.*ret",                       1),
        ("push edi  (strict)",  rf"push\s+edi\s*;.*ret",                       1),
        ("push ebp  (strict)",  rf"push\s+ebp\s*;.*ret",                       1),
        ("push esp  (strict — captures stack address)",
         rf"push\s+esp\s*;.*ret",                                               1),
        ("push imm  (push immediate value onto stack)",
         rf"push\s+0x[0-9a-fA-F]+.*ret",                                        2),
        ("push any  (loose — instructions after ok)",
         rf"push\s+{REG}.*ret",                                                  3),
        ("broadest — any push of any register or immediate",
         rf"push\s+({REG}|0x[0-9a-fA-F]+)",                                     4),
    ],

    "logic": [
        ("xor reg, reg  (strict — zero same register, null-free)",
         rf"xor\s+({REG}),\s*\1\s*;.*ret",                                    1),
        ("xor reg, reg  (loose — zero buried in gadget)",
         rf"xor\s+({REG}),\s*\1.*ret",                                         2),
        ("xor reg, reg  (strict — two different regs, flip bits)",
         rf"xor\s+{REG},\s*{REG}\s*;.*ret",                                    3),
        ("xor reg, reg  (loose — two different regs)",
         rf"xor\s+{REG},\s*{REG}.*ret",                                        4),
        ("or  reg, reg  (strict — combine bits, copy if dest=0)",
         rf"or\s+{REG},\s*{REG}\s*;.*ret",                                     5),
        ("or  reg, reg  (loose)",
         rf"or\s+{REG},\s*{REG}.*ret",                                         6),
        ("and reg, reg  (strict — mask bits)",
         rf"and\s+{REG},\s*{REG}\s*;.*ret",                                    7),
        ("and reg, reg  (loose)",
         rf"and\s+{REG},\s*{REG}.*ret",                                        8),
        ("not reg  (bitwise NOT — flips all bits)",
         rf"not\s+{REG}.*ret",                                                  9),
        ("neg reg  (arithmetic negate — two's complement)",
         rf"neg\s+{REG}.*ret",                                                 10),
        ("broadest — any bitwise/logic operation between registers",
         rf"(xor|or|and|not|neg)\s+{REG}.*ret",                               11),
    ],

    "flags": [
        ("cld  (clear DF — REQUIRED before string ops stosd/lodsd/movsd)",
         rf"cld.*ret",                                                           1),
        ("std  (set DF — string ops move backward)",
         rf"std.*ret",                                                           2),
        ("clc  (clear carry flag)",
         rf"clc.*ret",                                                           3),
        ("stc  (set carry flag)",
         rf"stc.*ret",                                                           4),
        ("cmc  (complement carry)",
         rf"cmc.*ret",                                                           5),
        ("pushfd  (push EFLAGS onto stack)",
         rf"pushfd.*ret",                                                        6),
        ("popfd  (pop EFLAGS from stack)",
         rf"popfd.*ret",                                                         7),
        ("lahf  (EFLAGS low byte -> AH)",
         rf"lahf.*ret",                                                          8),
        ("sahf  (AH -> EFLAGS low byte)",
         rf"sahf.*ret",                                                          9),
    ],

    "clear direction flag": [
        ("cld  (REQUIRED before stosd/lodsd/movsd — clears DF)",
         rf"cld.*ret",                                                           1),
        ("cld bare  (no ret — check if usable)",
         rf"cld$",                                                               2),
    ],

    "string ops": [
        ("cld  (always run this first)",
         rf"cld.*ret",                                                           1),
        ("stosd  eax->[edi], edi+=4  (write eax to memory)",
         rf"stosd.*ret",                                                         2),
        ("lodsd  [esi]->eax, esi+=4  (read memory into eax)",
         rf"lodsd.*ret",                                                         3),
        ("movsd  [esi]->[edi], both+=4  (memory copy)",
         rf"movsd.*ret",                                                         4),
        ("stosb  al->[edi], edi+=1  (byte write)",
         rf"stosb.*ret",                                                         5),
        ("lodsb  [esi]->al, esi+=1  (byte read)",
         rf"lodsb.*ret",                                                         6),
        ("stosw  ax->[edi], edi+=2  (word write)",
         rf"stosw.*ret",                                                         7),
    ],

    "save registers": [
        ("pushad  (push all GPRs — 32 bytes on stack)",
         rf"pushad.*ret",                                                        1),
        ("pusha  (same as pushad in 32-bit)",
         rf"pusha.*ret",                                                         2),
        ("pushfd  (save EFLAGS)",
         rf"pushfd.*ret",                                                        3),
    ],

    "restore registers": [
        ("popad  (pop all GPRs — EDI ESI EBP skip EBX EDX ECX EAX)",
         rf"popad.*ret",                                                         1),
        ("popa  (same as popad in 32-bit)",
         rf"popa.*ret",                                                          2),
        ("popfd  (restore EFLAGS)",
         rf"popfd.*ret",                                                         3),
    ],

    "syscall": [
        ("int 0x80  (Linux 32-bit — eax=syscall number)",
         rf"int\s+0x80.*ret",                                                   1),
        ("int 0x2e  (Windows native syscall)",
         rf"int\s+0x2e.*ret",                                                   2),
        ("sysenter  (fast 32-bit syscall entry)",
         rf"sysenter",                                                           3),
        ("syscall  (64-bit only)",
         rf"syscall",                                                            4),
    ],

    "nop": [
        ("nop  (0x90 — single byte)",
         rf"nop.*ret",                                                           1),
        ("fnop  (FPU nop — 0xD9D0)",
         rf"fnop.*ret",                                                          2),
        ("xchg eax, eax  (same encoding as nop — 0x90)",
         rf"xchg\s+eax,\s*eax.*ret",                                            3),
    ],

    "shift": [
        ("shl reg, N  (left shift — multiply by 2^N, null-free encoding)",
         rf"shl\s+{REG},\s*(cl|\d+).*ret",                                      1),
        ("shr reg, N  (right shift unsigned)",
         rf"shr\s+{REG},\s*(cl|\d+).*ret",                                      2),
        ("sar reg, N  (arithmetic right shift — sign preserving)",
         rf"sar\s+{REG},\s*(cl|\d+).*ret",                                      3),
        ("rol reg, N  (rotate left)",
         rf"rol\s+{REG},\s*(cl|\d+).*ret",                                      4),
        ("ror reg, N  (rotate right)",
         rf"ror\s+{REG},\s*(cl|\d+).*ret",                                      5),
    ],

    "byte manipulation": [
        ("bswap reg  (reverse byte order — endian swap)",
         rf"bswap\s+{REG}.*ret",                                                 1),
        ("xlatb  (AL = [EBX+AL] — table lookup)",
         rf"xlatb.*ret",                                                         2),
        ("movsx reg, r/m8  (sign-extend byte to dword)",
         rf"movsx\s+{REG}.*ret",                                                  3),
        ("movzx reg, r/m8  (zero-extend byte to dword)",
         rf"movzx\s+{REG}.*ret",                                                  4),
        ("cdq  (sign-extend EAX into EDX:EAX — zeroes EDX if EAX positive)",
         rf"cdq.*ret",                                                            5),
        ("cwde  (sign-extend AX into EAX)",
         rf"cwde.*ret",                                                           6),
    ],

    "all shorthands": [
        ("cld",      rf"cld.*ret",                                               1),
        ("std",      rf"std.*ret",                                               2),
        ("cdq",      rf"cdq.*ret",                                               3),
        ("pushad",   rf"pushad.*ret",                                            4),
        ("popad",    rf"popad.*ret",                                             5),
        ("pusha",    rf"pusha.*ret",                                             6),
        ("popa",     rf"popa.*ret",                                              7),
        ("lahf",     rf"lahf.*ret",                                              8),
        ("sahf",     rf"sahf.*ret",                                              9),
        ("pushfd",   rf"pushfd.*ret",                                           10),
        ("popfd",    rf"popfd.*ret",                                            11),
        ("clc",      rf"clc.*ret",                                              12),
        ("stc",      rf"stc.*ret",                                              13),
        ("cmc",      rf"cmc.*ret",                                              14),
        ("fnop",     rf"fnop.*ret",                                             15),
        ("bswap",    rf"bswap\s+{REG}.*ret",                                   16),
        ("xlatb",    rf"xlatb.*ret",                                            17),
        ("sysenter", rf"sysenter",                                              18),
        ("int 0x80", rf"int\s+0x80.*ret",                                      19),
        ("int 0x2e", rf"int\s+0x2e.*ret",                                      20),
        ("stosd",    rf"stosd.*ret",                                            21),
        ("lodsd",    rf"lodsd.*ret",                                            22),
        ("leave",    rf"leave.*ret",                                            23),
    ],

    "retn": [
        ("retn N  (any stdcall stack cleanup value)",
         rf"retn?\s+0x[0-9a-fA-F]+",                                            1),
        ("retn 0x0002",  rf"retn\s+0x0*2\b",                                    2),
        ("retn 0x0004",  rf"retn\s+0x0*4\b",                                    3),
        ("retn 0x0008",  rf"retn\s+0x0*8\b",                                    4),
        ("retn 0x000C",  rf"retn\s+0x0*c\b",                                    5),
    ],

    "leave": [
        ("leave  (mov esp,ebp ; pop ebp — classic epilogue)",
         rf"leave.*ret",                                                         1),
        ("mov esp, ebp ; pop ebp ; ret  (manual epilogue)",
         rf"mov\s+esp,\s*ebp.*pop\s+ebp.*ret",                                  2),
        ("mov esp, ebp  (partial epilogue)",
         rf"mov\s+esp,\s*ebp.*ret",                                              3),
    ],
}

# Expose as GOALS for TUI compatibility
GOALS = STATIC_GOALS


# ── Register synonym table ─────────────────────────────────────────────────────

REG_SYNONYMS = {
    "eax": "eax", "ax": "eax", "al": "eax", "ah": "eax",
    "ebx": "ebx", "bx": "ebx", "bl": "ebx", "bh": "ebx",
    "ecx": "ecx", "cx": "ecx", "cl": "ecx", "ch": "ecx",
    "edx": "edx", "dx": "edx", "dl": "edx", "dh": "edx",
    "esi": "esi", "si": "esi",
    "edi": "edi", "di": "edi",
    "ebp": "ebp", "bp": "ebp",
    "esp": "esp", "sp": "esp",
}

VERB_COPY      = {"copy", "mov", "move", "transfer", "put", "save",
               "preserve", "get", "load into", "store into"}
VERB_COPY_INTO = {"into", "load into", "put into", "store into", "write into",
                  "copy into", "move into", "set", "receive"}
VERB_COPY_FROM = {"from", "out of", "copy from", "move from", "copy out",
                  "move out", "source"}
VERB_COPY_BOTH = {"involving", "using", "with", "any direction", "both",
                  "bidirectional", "either"}
VERB_DEREF = {"deref", "dereference", "read", "load from", "indirect",
              "read memory", "pointer", "from memory"}
VERB_WRITE = {"write", "store", "set", "patch", "put into",
              "write to", "store to", "save to"}
VERB_ZERO  = {"zero", "null", "clear", "zeroise", "zeroize", "blank"}
VERB_POP   = {"pop", "load from stack", "stack load"}
VERB_PUSH  = {"push onto stack", "push value onto", "push reg onto"}
# Note: bare "push" is NOT in VERB_PUSH because "push eax" would conflict
# with copy_patterns. "push eax" is handled via __push__ dynamic goal below.
VERB_ADD   = {"add", "increase", "offset", "adjust up", "increment by", "plus"}
VERB_SUB   = {"subtract", "sub", "decrease", "adjust down", "decrement by", "minus"}
VERB_CALL  = {"call", "jump", "jmp", "invoke", "execute", "run",
              "virtualalloc", "virtualprotect"}

ALIASES: Dict[str, str] = {
    # copy
    "copy":             "copy",
    "mov":              "copy",
    "move":             "copy",
    "transfer":         "copy",
    # capture esp
    "capture esp":      "capture esp",
    "get esp":          "capture esp",
    "save esp":         "capture esp",
    "esp":              "capture esp",
    "stack address":    "capture esp",
    # deref
    "deref":            "dereference",
    "dereference":      "dereference",
    "read memory":      "dereference",
    "indirect":         "dereference",
    "pointer":          "dereference",
    # write
    "write":            "write memory",
    "store":            "write memory",
    "write memory":     "write memory",
    "patch":            "write memory",
    # zero
    # "zero" is NOT an alias here — if a register is present (e.g. "zero edx"),
    # the dynamic resolver handles it. Only exact "zero register" maps statically.
    "zero register":    "zero register",
    "null register":    "zero register",
    "clear reg":        "zero register",
    # arithmetic
    "add":              "add offset",
    "add offset":       "add offset",
    "offset":           "add offset",
    "increase":         "add offset",
    "subtract":         "subtract offset",
    "sub":              "subtract offset",
    "decrease":         "subtract offset",
    "inc dec":          "inc dec",
    "increment":        "inc dec",
    "decrement":        "inc dec",
    "neg":              "neg",
    "negate":           "neg",
    # logic
    "logic":            "logic",
    "xor":              "logic",
    "bitwise":          "logic",
    # pivot
    "pivot":            "stack pivot",
    "stack pivot":      "stack pivot",
    "pivot stack":      "stack pivot",
    # call
    "call":             "call function",
    "call function":    "call function",
    "jmp":              "call function",
    "jump":             "call function",
    "invoke":           "call function",
    "virtualalloc":     "call function",
    "virtualprotect":   "call function",
    "execute":          "call function",
    "trampoline":       "call function",
    # pop
    "pop":              "pop",
    "stack load":       "pop",
    # flags
    "flags":            "flags",
    "flag":             "flags",
    "eflags":           "flags",
    "cld":              "clear direction flag",
    "clear direction":  "clear direction flag",
    "direction flag":   "clear direction flag",
    "df":               "clear direction flag",
    "string ops":       "string ops",
    "stosd":            "string ops",
    "lodsd":            "string ops",
    "strings":          "string ops",
    # context
    "pushad":           "save registers",
    "pusha":            "save registers",
    "save regs":        "save registers",
    "push all":         "save registers",
    "push":             "push",
    "push reg":         "push",
    "push register":    "push",
    "push value":       "push",
    "push onto stack":  "push",
    "popad":            "restore registers",
    "popa":             "restore registers",
    "restore regs":     "restore registers",
    "pop all":          "restore registers",
    # cdq
    "cdq":              "zero register",
    # "zero edx" removed — handled dynamically by __zero__edx
    # syscall
    "syscall":          "syscall",
    "int 0x80":         "syscall",
    "sysenter":         "syscall",
    "interrupt":        "syscall",
    "int80":            "syscall",
    # misc
    "nop":              "nop",
    "padding":          "nop",
    "shift":            "shift",
    "rotate":           "shift",
    "shl":              "shift",
    "shr":              "shift",
    "rol":              "shift",
    "ror":              "shift",
    "sar":              "shift",
    "byte manipulation":"byte manipulation",
    "bswap":            "byte manipulation",
    "endian":           "byte manipulation",
    "movsx":            "byte manipulation",
    "movzx":            "byte manipulation",
    "shorthands":       "all shorthands",
    "shortcuts":        "all shorthands",
    "all shorthands":   "all shorthands",
    "all":              "all shorthands",
    "retn":             "retn",
    "stdcall":          "retn",
    "cleanup":          "retn",
    "leave":            "leave",
    "epilogue":         "leave",
    # directional copy hints — these get parsed dynamically but
    # add aliases so partial match fallback also works
    "copy into":        "copy",
    "load into":        "copy",
    "into":             "copy",
    "copy from":        "copy",
    "out of":           "copy",
    "both directions":  "copy",
    "bidirectional":    "copy",
}


# ── Resolution engine ──────────────────────────────────────────────────────────

def _extract_registers(query: str) -> List[str]:
    """Extract registers in order of first appearance in the query string."""
    q = query.lower()
    # Find all matches with their position so we can sort by appearance order
    hits = []
    for synonym, canonical in REG_SYNONYMS.items():
        m = re.search(r'\b' + re.escape(synonym) + r'\b', q)
        if m:
            hits.append((m.start(), canonical))
    # Sort by position, deduplicate preserving order
    seen = set()
    found = []
    for pos, canonical in sorted(hits):
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)
    return found


def _extract_verb(query: str) -> Optional[str]:
    q = query.lower()
    for v in VERB_COPY:
        if v in q: return "copy"
    for v in VERB_DEREF:
        if v in q: return "deref"
    for v in VERB_WRITE:
        if v in q: return "write"
    for v in VERB_ZERO:
        if v in q: return "zero"
    for v in VERB_POP:
        if v in q: return "pop"
    for v in VERB_ADD:
        if v in q: return "add"
    for v in VERB_SUB:
        if v in q: return "sub"
    for v in VERB_CALL:
        if v in q: return "call"
    return None


def resolve_goal(query: str) -> Optional[str]:
    """
    Parse a query into a goal key.
    Resolution order:
      1. Exact match in STATIC_GOALS
      2. Exact alias match
      3. Dynamic register+verb resolution (BEFORE partial matches so
         'copy eax' -> __copy__eax__any not generic 'copy')
      4. Partial match against static goal keys and aliases (fallback)
    """
    q = query.lower().strip()

    # 1. Exact static match
    if q in STATIC_GOALS:   return q
    if q in ALIASES:        return ALIASES[q]

    # 2. Dynamic register-aware resolution — checked BEFORE partial string matches
    regs = _extract_registers(q)
    verb = _extract_verb(q)

    # Check for explicit push goal before copy — "push eax" should mean
    # find gadgets that push eax, not copy eax
    if regs:
        q_lower_check = q
        push_kws = {"push", "push reg", "push onto", "push value"}
        if any(k in q_lower_check for k in push_kws) and not any(
                k in q_lower_check for k in {"push all", "pushad", "pusha"}):
            return f"__push__{regs[0]}"

    if verb == "copy" and regs:
        q_lower = q
        into_kws = VERB_COPY_INTO | {"into", "load into", "put into",
                                     "copy into", "move into"}
        from_kws = VERB_COPY_FROM | {"from", "out of", "out", "copy from"}
        both_kws = VERB_COPY_BOTH | {"both", "involving", "any direction",
                                     "bidirectional", "either way"}
        # "to" in a two-register query means "copy X to Y" — Y is destination
        to_kws   = {" to ", " -> ", " into "}

        is_into = any(k in q_lower for k in into_kws)
        is_from = any(k in q_lower for k in from_kws)
        is_both = any(k in q_lower for k in both_kws)
        has_to  = any(k in q_lower for k in to_kws)

        if is_both:
            # "copy eax both" / "eax bidirectional"
            return f"__copyboth__{regs[0]}"

        elif is_into:
            # "copy into ecx" — ecx is DESTINATION, search any source
            # "copy into ecx from eax" — ecx is DEST, eax is specific SOURCE
            dst = regs[0]
            if is_from and len(regs) >= 2:
                # Both "into" and "from" present — specific pair, dst=regs[0] src=regs[1]
                src = regs[1]
                return f"__copyinto__{dst}__{src}"
            return f"__copyinto__{dst}__any"

        elif is_from:
            # "copy from eax" — eax is SOURCE, search any destination
            # "copy eax into ecx" handled by has_to branch below
            src = regs[0]
            if is_into and len(regs) >= 2:
                dst = regs[1]
                return f"__copyinto__{dst}__{src}"
            return f"__copy__{src}__any"

        elif has_to and len(regs) >= 2:
            # "copy ecx to ebx" / "copy X -> Y"
            # The SECOND register is the destination — search ALL sources into it.
            # This gives a broad search: who can write into ebx?
            dst = regs[1]
            return f"__copyinto__{dst}__any"

        elif len(regs) == 1:
            # Single register, no directional hint — default to copy OUT of it
            return f"__copy__{regs[0]}__any"

        else:
            # Two registers, no directional keyword at all (e.g. "copy eax ebx")
            # Treat first as source, second as destination — specific pair search
            src = regs[0]
            dst = regs[1]
            return f"__copy__{src}__{dst}"

    if verb == "deref" and regs:
        src = regs[0]
        dst = regs[1] if len(regs) > 1 else None
        return f"__deref__{src}__{dst or 'any'}"

    if verb == "write" and regs:
        dst_ptr = regs[0]
        src = regs[1] if len(regs) > 1 else None
        return f"__write__{dst_ptr}__{src or 'any'}"

    if verb == "zero" and regs:
        return f"__zero__{regs[0]}"

    if verb == "pop" and regs:
        return f"__pop__{regs[0]}"

    if verb == "add" and regs:
        return f"__add__{regs[0]}"

    if verb == "sub" and regs:
        return f"__sub__{regs[0]}"

    if verb == "call":
        return "call function"

    # Register(s) mentioned with no clear verb
    if regs:
        q_lower = q
        into_kws = {"into", "load into", "put into", "copy into", "move into", "receive"}
        both_kws = {"both", "involving", "any direction", "bidirectional", "either"}
        to_kws   = {" to ", " -> ", " into "}

        if any(k in q_lower for k in both_kws):
            return f"__copyboth__{regs[0]}"
        elif any(k in q_lower for k in into_kws):
            return f"__copyinto__{regs[0]}__any"
        elif any(k in q_lower for k in to_kws) and len(regs) >= 2:
            # "eax to ebx" with no verb — second register is destination
            dst = regs[1]
            return f"__copyinto__{dst}__any"
        else:
            return f"__copy__{regs[0]}__any"

    # 3. Partial match fallback (generic queries with no register)
    for key in STATIC_GOALS:
        if q in key or key in q:
            return key
    for alias, goal in ALIASES.items():
        if q in alias or alias in q:
            return goal

    return None


def get_patterns(goal_key: str) -> List[Tuple[str, str, int]]:
    """Return patterns for any goal key, static or dynamic."""
    if goal_key in STATIC_GOALS:
        return STATIC_GOALS[goal_key]

    if goal_key.startswith("__copyinto__"):
        parts = goal_key.split("__")   # ['', 'copyinto', dst, src]
        dst = parts[2]
        src = None if parts[3] == "any" else parts[3]
        return copy_into_patterns(dst, src)

    if goal_key.startswith("__copyboth__"):
        reg = goal_key.split("__")[2]
        return copy_both_patterns(reg)

    if goal_key.startswith("__copy__"):
        parts = goal_key.split("__")   # ['', 'copy', src, dst]
        src = parts[2]
        dst = None if parts[3] == "any" else parts[3]
        return copy_patterns(src, dst)

    if goal_key.startswith("__deref__"):
        parts = goal_key.split("__")
        src = parts[2]
        dst = None if parts[3] == "any" else parts[3]
        return deref_patterns(src, dst)

    if goal_key.startswith("__write__"):
        parts = goal_key.split("__")
        dst_ptr = parts[2]
        src = None if parts[3] == "any" else parts[3]
        return write_patterns(dst_ptr, src)

    if goal_key.startswith("__zero__"):
        reg = goal_key.split("__")[2]
        return zero_patterns(reg)

    if goal_key.startswith("__pop__"):
        reg = goal_key.split("__")[2]
        return pop_patterns(reg)

    if goal_key.startswith("__push__"):
        reg = goal_key.split("__")[2]
        return push_patterns(reg)

    if goal_key.startswith("__add__"):
        reg = goal_key.split("__")[2]
        return add_offset_patterns(reg)

    if goal_key.startswith("__sub__"):
        reg = goal_key.split("__")[2]
        return sub_offset_patterns(reg)

    return []


def goal_display_name(goal_key: str) -> str:
    if not goal_key.startswith("__"):
        return goal_key
    parts = goal_key.split("__")
    verb    = parts[1] if len(parts) > 1 else ""
    src     = parts[2] if len(parts) > 2 else ""
    dst     = parts[3] if len(parts) > 3 else ""
    if verb == "copy":
        # parts: ['', 'copy', src, dst]
        reg_src = parts[2] if len(parts) > 2 else ""
        reg_dst = parts[3] if len(parts) > 3 else "any"
        if reg_dst and reg_dst != "any":
            return f"copy {reg_src} -> {reg_dst}  (specific pair)"
        return f"copy {reg_src} -> any  ({reg_src} is source)"
    if verb == "copyinto":
        # parts: ['', 'copyinto', dst, src]
        reg_dst = parts[2] if len(parts) > 2 else ""
        reg_src = parts[3] if len(parts) > 3 else "any"
        if reg_src and reg_src != "any":
            return f"copy {reg_src} -> {reg_dst}  (specific pair)"
        return f"copy any -> {reg_dst}  (any source into {reg_dst})"
    if verb == "copyboth":
        # parts: ['', 'copyboth', reg]
        reg = parts[2] if len(parts) > 2 else src
        return f"copy {reg} <-> any  (all gadgets involving {reg})"
    if verb == "deref":  return f"dereference [{src}] -> {dst}"
    if verb == "write":  return f"write [{src}] = {dst}"
    if verb == "zero":   return f"zero {src}"
    if verb == "pop":    return f"pop {src}"
    if verb == "push":   return f"push {src} onto stack"
    if verb == "add":    return f"add offset to {src}"
    if verb == "sub":    return f"subtract offset from {src}"
    return goal_key


# ── Search runner ──────────────────────────────────────────────────────────────

def suggest_for_goal(
    goal_key: str,
    gadgets: List[Gadget],
    badchars: bytes,
    max_per_pattern: int = 0,   # 0 = unlimited
) -> Dict[str, List[Gadget]]:
    """
    Search all patterns for a goal.
    - No result limits — returns everything that matches.
    - Deduplicates across categories: a gadget shown in "strict" will NOT
      appear again in "loose" or "broadest", keeping categories distinct.
    - Patterns run in priority order so strict appears before loose before broadest.
    """
    patterns = get_patterns(goal_key)
    results = {}
    seen_addresses: set = set()   # track addresses already shown in earlier categories

    for desc, pattern, priority in sorted(patterns, key=lambda x: x[2]):
        try:
            matches = search_gadgets(
                gadgets, pattern,
                badchars=badchars,
                regex_mode=True,
                max_results=0,   # no limit
            )
        except re.error:
            continue

        # Only include gadgets not already shown in a higher-priority category
        new_matches = [g for g in matches if g.address not in seen_addresses]

        if new_matches:
            results[desc] = new_matches
            seen_addresses.update(g.address for g in new_matches)

    return results


def print_suggestions(goal_key, results, color=True):
    RESET = "\033[0m"  if color else ""
    BOLD  = "\033[1m"  if color else ""
    CYAN  = "\033[96m" if color else ""
    YELLOW= "\033[93m" if color else ""

    name = goal_display_name(goal_key)
    print(f"\n  {BOLD}Goal: {name}{RESET}\n")

    if not results:
        print(f"  {YELLOW}No gadgets found.{RESET}")
        print(f"  Try loading more DLL files or broadening your bad char set.\n")
        return

    for desc, gadgets in results.items():
        print(f"  {CYAN}-- {desc} --{RESET}")
        for g in gadgets:
            print(format_gadget(g, color=color, show_module=True))
        print()


# ── CLI entry point ────────────────────────────────────────────────────────────

def cli_suggest(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="chainforge.py suggest",
        description="Goal-based gadget suggestions"
    )
    parser.add_argument("goal", nargs="+",
                        help="e.g. 'copy eax', 'copy esi to ebx', 'deref esi', "
                             "'write esi eax', 'zero edx', 'pop ecx', 'stack pivot'")
    parser.add_argument("-f", "--file", action="append", dest="files", metavar="FILE")
    parser.add_argument("-b", "--badchars", default="00,0a,0d")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--list-goals", action="store_true")
    ns = parser.parse_args(args)

    color = not ns.no_color and sys.stdout.isatty()
    CYAN  = "\033[96m" if color else ""
    RESET = "\033[0m"  if color else ""

    if ns.list_goals:
        print("\n  Static goals:\n")
        for g in sorted(STATIC_GOALS.keys()):
            print(f"    {CYAN}{g}{RESET}")
        print("\n  Dynamic goal examples (register-aware):\n")
        examples = [
            "copy eax", "copy ebx", "copy ecx", "copy edx",
            "copy esi", "copy edi", "copy ebp",
            "copy eax to ebx", "copy esi to eax", "copy ecx to edx",
            "deref eax", "deref esi", "deref ecx", "deref ebp",
            "deref esi to eax", "deref ecx to ebx",
            "write esi", "write edi", "write esi eax", "write edi ecx",
            "zero eax", "zero ebx", "zero ecx", "zero edx",
            "pop eax", "pop ecx", "pop esi", "pop edi",
            "add eax", "add ebx", "add ecx",
            "subtract eax", "subtract ecx",
        ]
        for ex in examples:
            resolved = resolve_goal(ex)
            print(f"    {CYAN}{ex:38}{RESET} -> {goal_display_name(resolved)}")
        print()
        return

    query    = " ".join(ns.goal)
    goal_key = resolve_goal(query)

    if not goal_key:
        print(f"\n  [!] Unknown goal: '{query}'")
        print(f"  Run with --list-goals to see available goals.\n")
        return

    if not ns.files:
        print(f"\n  No gadget files loaded. Showing patterns for: "
              f"{goal_display_name(goal_key)}\n")
        for desc, pattern, _ in get_patterns(goal_key):
            print(f"  {CYAN}{desc}{RESET}")
            print(f"    {pattern}\n")
        return

    from core.search import parse_rpp_file
    try:
        badchars = bytes(int(x.strip(), 16) for x in ns.badchars.split(","))
    except ValueError:
        print("[!] Invalid bad char format.")
        sys.exit(1)

    all_gadgets = []
    for f in ns.files:
        all_gadgets.extend(parse_rpp_file(f))

    results = suggest_for_goal(goal_key, all_gadgets, badchars)
    print_suggestions(goal_key, results, color=color)
