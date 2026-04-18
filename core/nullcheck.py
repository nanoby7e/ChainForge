"""
nullcheck.py — ChainForge null byte and bad char checker
Validates addresses and immediate values, suggests null-free alternatives.
"""

import struct
import sys
import argparse
from typing import List, Tuple, Optional


DEFAULT_BADCHARS = bytes([0x00, 0x0A, 0x0D])

# ── Core functions ─────────────────────────────────────────────────────────────

def check_value(value: int, badchars: List[int]) -> Tuple[bool, List[Tuple[int, int]]]:
    """
    Check a 32-bit value for bad chars.
    Returns (is_clean, [(byte_position, byte_value), ...])
    """
    try:
        packed = struct.pack("<I", value & 0xFFFFFFFF)
    except struct.error:
        return False, []

    hits = []
    for i, b in enumerate(packed):
        if b in badchars:
            hits.append((i, b))

    return len(hits) == 0, hits


def negate_offset(offset: int) -> int:
    """Return two's complement negation for 32-bit value."""
    return (0x100000000 - (offset & 0xFFFFFFFF)) & 0xFFFFFFFF


def suggest_alternatives(offset: int) -> List[dict]:
    """
    Given a desired offset that contains null bytes,
    suggest null-free ways to achieve the same result.
    """
    suggestions = []
    neg = negate_offset(offset)

    # Check if negated value is clean
    neg_packed = struct.pack("<I", neg)
    if 0x00 not in neg_packed and 0x0A not in neg_packed and 0x0D not in neg_packed:
        suggestions.append({
            "type": "sub_negate",
            "description": f"sub reg, {hex(neg)}  (== add reg, {hex(offset)})",
            "value": neg,
            "clean": True,
        })

    # Split into two clean parts
    splits = find_clean_splits(offset)
    for a, b in splits[:3]:
        suggestions.append({
            "type": "split_add",
            "description": f"add reg, {hex(a)}  then  add reg, {hex(b)}  (== add reg, {hex(offset)})",
            "value": (a, b),
            "clean": True,
        })

    # INC chain for small values
    if offset <= 32:
        suggestions.append({
            "type": "inc_chain",
            "description": f"inc reg  x{offset}  (chain {offset} inc gadgets)",
            "value": offset,
            "clean": True,
        })

    # DEC chain for small negative values
    neg_small = (0x100000000 - offset) & 0xFFFFFFFF
    if neg_small <= 32:
        suggestions.append({
            "type": "dec_chain",
            "description": f"dec reg  x{neg_small}  (chain {neg_small} dec gadgets, equivalent to sub {hex(offset)})",
            "value": neg_small,
            "clean": True,
        })

    return suggestions


def find_clean_splits(target: int, badchars: List[int] = None) -> List[Tuple[int, int]]:
    """Find pairs of clean values that add to target."""
    if badchars is None:
        badchars = DEFAULT_BADCHARS

    splits = []
    candidates = [
        0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0C, 0x0E, 0x0F,
        0x11, 0x12, 0x14, 0x18, 0x1E, 0x20, 0x21, 0x22, 0x24, 0x28,
        0x30, 0x40, 0x41, 0x44, 0x48, 0x50, 0x60, 0x70, 0x80,
    ]

    for a in candidates:
        b = (target - a) & 0xFFFFFFFF
        if b == 0:
            continue
        a_packed = struct.pack("<I", a)
        b_packed = struct.pack("<I", b)
        a_clean = not any(x in a_packed for x in badchars)
        b_clean = not any(x in b_packed for x in badchars)
        if a_clean and b_clean and (a, b) not in splits and (b, a) not in splits:
            splits.append((a, b))

    return splits


def format_bytes(value: int) -> str:
    """Format a 32-bit value as little-endian hex bytes."""
    packed = struct.pack("<I", value & 0xFFFFFFFF)
    return " ".join(f"{b:02x}" for b in packed)


def analyze_value(value: int, badchars: List[int], color: bool = True) -> str:
    """Full analysis of a value — returns formatted string."""
    RESET  = "\033[0m"  if color else ""
    GREEN  = "\033[92m" if color else ""
    RED    = "\033[91m" if color else ""
    YELLOW = "\033[93m" if color else ""
    CYAN   = "\033[96m" if color else ""
    DIM    = "\033[2m"  if color else ""

    lines = []
    is_clean, hits = check_value(value, badchars)

    packed = struct.pack("<I", value & 0xFFFFFFFF)
    byte_display = []
    for i, b in enumerate(packed):
        bstr = f"{b:02x}"
        if b in badchars:
            byte_display.append(f"{RED}{bstr}{RESET}")
        else:
            byte_display.append(f"{GREEN}{bstr}{RESET}")

    lines.append(f"\n  Value:    {CYAN}{hex(value)}{RESET}  ({value})")
    lines.append(f"  LE bytes: {' '.join(byte_display)}  (little-endian)")
    lines.append(f"  Bad chars checked: {', '.join(hex(b) for b in badchars)}")

    if is_clean:
        lines.append(f"  Status:   {GREEN}CLEAN — no bad characters{RESET}")
    else:
        bad_desc = ", ".join(f"byte[{i}]={hex(b)}" for i, b in hits)
        lines.append(f"  Status:   {RED}BAD — contains: {bad_desc}{RESET}")
        lines.append(f"\n  {YELLOW}Null-free alternatives:{RESET}")
        alts = suggest_alternatives(value)
        if alts:
            for alt in alts:
                lines.append(f"    {DIM}→{RESET}  {alt['description']}")
        else:
            lines.append(f"    {RED}No clean alternatives found automatically.{RESET}")

    return "\n".join(lines)


def check_chain(addresses: List[int], badchars: List[int], color: bool = True) -> str:
    """Check a list of addresses and report which ones have bad chars."""
    RESET  = "\033[0m"  if color else ""
    GREEN  = "\033[92m" if color else ""
    RED    = "\033[91m" if color else ""
    CYAN   = "\033[96m" if color else ""

    lines = [f"\n  Checking {len(addresses)} address(es) for bad chars: "
             f"{', '.join(hex(b) for b in badchars)}\n"]

    clean_count = 0
    for addr in addresses:
        is_clean, hits = check_value(addr, badchars)
        packed = struct.pack("<I", addr & 0xFFFFFFFF)
        byte_str = " ".join(f"{b:02x}" for b in packed)
        status = f"{GREEN}OK{RESET}" if is_clean else f"{RED}BAD{RESET}"
        if is_clean:
            clean_count += 1
        bad_info = ""
        if hits:
            bad_info = f"  ← {RED}byte[{hits[0][0]}]={hex(hits[0][1])}{RESET}"
        lines.append(f"  {CYAN}{hex(addr):12}{RESET}  [{byte_str}]  {status}{bad_info}")

    lines.append(f"\n  {clean_count}/{len(addresses)} addresses are clean.")
    return "\n".join(lines)


# ── CLI entry point ────────────────────────────────────────────────────────────

def cli_nullcheck(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="chainforge.py nullcheck",
        description="Check values/addresses for bad characters"
    )
    parser.add_argument("values", nargs="+",
                        help="hex values to check (e.g. 0x10021c89 0x1C)")
    parser.add_argument("-b", "--badchars", default="00,0a,0d",
                        help="bad chars as hex bytes, comma separated (default: 00,0a,0d)")
    parser.add_argument("--no-color", action="store_true")
    ns = parser.parse_args(args)

    try:
        badchars = [int(x.strip(), 16) for x in ns.badchars.split(",")]
    except ValueError:
        print("[!] Invalid bad char format.")
        sys.exit(1)

    color = not ns.no_color and sys.stdout.isatty()

    for val_str in ns.values:
        try:
            value = int(val_str, 16)
        except ValueError:
            print(f"[!] Cannot parse value: {val_str}")
            continue
        print(analyze_value(value, badchars, color=color))

    print()
