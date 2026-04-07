"""
chain.py — ChainForge chain builder
Build, annotate, validate, and export Python pack() chains.
"""

import sys
import struct
import argparse
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict
from nullcheck import check_value, analyze_value, DEFAULT_BADCHARS
from search import Gadget, parse_rpp_file, search_gadgets, format_gadget


@dataclass
class ChainEntry:
    value: int
    comment: str = ""
    is_padding: bool = False
    is_gadget: bool = False

    @property
    def addr_str(self) -> str:
        return f"0x{self.value:08x}"

    def pack_line(self, var: str = "rop") -> str:
        if self.is_padding:
            return f'{var} += pack("<L", ({self.addr_str}))  # {self.comment or "padding"}'
        return f'{var} += pack("<L", ({self.addr_str}))  # {self.comment}'


class RopChain:
    def __init__(self, badchars: bytes = DEFAULT_BADCHARS):
        self.entries: List[ChainEntry] = []
        self.badchars = badchars
        self.name = "chainforge_chain"
        self.notes = ""

    def add(self, value: int, comment: str = "", is_padding: bool = False):
        self.entries.append(ChainEntry(
            value=value,
            comment=comment,
            is_padding=is_padding,
            is_gadget=not is_padding,
        ))

    def remove(self, index: int):
        if 0 <= index < len(self.entries):
            self.entries.pop(index)

    def validate(self) -> List[Tuple[int, str]]:
        """Return list of (index, issue) for problems found."""
        issues = []
        for i, entry in enumerate(self.entries):
            clean, hits = check_value(entry.value, list(self.badchars))
            if not clean:
                bad = ", ".join(f"byte[{p}]={hex(b)}" for p, b in hits)
                issues.append((i, f"BAD CHARS: {bad}"))
        return issues

    def to_python(self, var_name: str = "rop", eip_entry: Optional[int] = None) -> str:
        lines = [
            f'from struct import pack',
            f'',
            f'# {self.name}',
        ]
        if self.notes:
            for note_line in self.notes.splitlines():
                lines.append(f'# {note_line}')
        lines.append(f'')

        if eip_entry is not None and self.entries:
            first = self.entries[0]
            lines.append(f'eip  = pack("<L", ({first.addr_str}))  # {first.comment}')
            rest = self.entries[1:]
        else:
            rest = self.entries

        first_rop = True
        for entry in rest:
            prefix = f'{var_name} +=' if not first_rop else f'{var_name}  ='
            first_rop = False
            lines.append(f'{prefix} pack("<L", ({entry.addr_str}))  # {entry.comment}')

        return "\n".join(lines)

    def to_json(self) -> str:
        data = {
            "name": self.name,
            "notes": self.notes,
            "badchars": list(self.badchars),
            "entries": [asdict(e) for e in self.entries],
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, data: str) -> "RopChain":
        obj = json.loads(data)
        chain = cls(badchars=bytes(obj.get("badchars", DEFAULT_BADCHARS)))
        chain.name = obj.get("name", "chainforge_chain")
        chain.notes = obj.get("notes", "")
        for e in obj.get("entries", []):
            chain.entries.append(ChainEntry(**e))
        return chain

    def display(self, color: bool = True) -> str:
        RESET  = "\033[0m"  if color else ""
        CYAN   = "\033[96m" if color else ""
        GREEN  = "\033[92m" if color else ""
        RED    = "\033[91m" if color else ""
        YELLOW = "\033[93m" if color else ""
        DIM    = "\033[2m"  if color else ""

        issues = dict(self.validate())
        lines = [f"\n  {CYAN}Chain: {self.name}{RESET}  ({len(self.entries)} entries)\n"]

        for i, entry in enumerate(self.entries):
            issue = issues.get(i, "")
            status = f"{RED}[BAD]{RESET} " if issue else f"{GREEN}[ OK]{RESET} "
            addr = f"{CYAN}{entry.addr_str}{RESET}"
            comment = f"{DIM}{entry.comment}{RESET}"
            pad = f"{YELLOW}[PAD]{RESET} " if entry.is_padding else "      "
            lines.append(f"  {i:2}  {status}{pad}{addr}  {comment}")
            if issue:
                lines.append(f"        {RED}→ {issue}{RESET}")

        if not self.entries:
            lines.append(f"  {DIM}(empty){RESET}")

        return "\n".join(lines)


# ── Interactive chain wizard ───────────────────────────────────────────────────

def cli_chain(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="chainforge.py chain",
        description="Interactive ROP chain builder"
    )
    parser.add_argument("-f", "--file", action="append", dest="files",
                        metavar="FILE", help="rp++ output file(s) to load")
    parser.add_argument("-l", "--load", metavar="JSON",
                        help="load existing chain from JSON file")
    parser.add_argument("-b", "--badchars", default="00,0a,0d")
    parser.add_argument("--no-color", action="store_true")
    ns = parser.parse_args(args)

    color = not ns.no_color and sys.stdout.isatty()

    try:
        badchars = bytes(int(x.strip(), 16) for x in ns.badchars.split(","))
    except ValueError:
        print("[!] Invalid bad char format.")
        sys.exit(1)

    # Load gadgets if files provided
    all_gadgets: List[Gadget] = []
    if ns.files:
        for f in ns.files:
            g = parse_rpp_file(f)
            all_gadgets.extend(g)
        print(f"[+] Loaded {len(all_gadgets):,} gadgets.")

    # Load or create chain
    chain = RopChain(badchars=badchars)
    if ns.load:
        try:
            with open(ns.load) as f:
                chain = RopChain.from_json(f.read())
            print(f"[+] Loaded chain '{chain.name}' ({len(chain.entries)} entries)")
        except Exception as e:
            print(f"[!] Could not load chain: {e}")

    _chain_repl(chain, all_gadgets, badchars, color)


def _chain_repl(chain: RopChain, gadgets: List[Gadget], badchars: bytes, color: bool):
    RESET  = "\033[0m"  if color else ""
    CYAN   = "\033[96m" if color else ""
    GREEN  = "\033[92m" if color else ""
    YELLOW = "\033[93m" if color else ""
    DIM    = "\033[2m"  if color else ""

    HELP = f"""
  {CYAN}Chain Builder Commands:{RESET}
    add <addr> <comment>     Add gadget address with comment
    pad <addr>               Add padding value (junk)
    pad                      Add 0x42424242 as junk padding
    remove <index>           Remove entry by index
    show                     Display current chain
    validate                 Check for bad characters
    search <query>           Search loaded gadgets
    nullcheck <value>        Check value for bad chars
    export                   Print Python pack() chain
    save <file.json>         Save chain to JSON
    load <file.json>         Load chain from JSON
    name <name>              Set chain name
    note <text>              Add/replace chain notes
    clear                    Clear all entries
    help                     Show this help
    quit / exit              Exit chain builder
"""
    print(HELP)

    while True:
        try:
            prompt = f"{CYAN}chain>{RESET} " if color else "chain> "
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting chain builder.")
            break

        if not line:
            continue

        parts = line.split(None, 2)
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help":
            print(HELP)

        elif cmd == "show":
            print(chain.display(color=color))

        elif cmd == "add":
            if len(parts) < 2:
                print("  Usage: add <addr> [comment]")
                continue
            try:
                addr = int(parts[1], 16)
            except ValueError:
                print(f"  [!] Invalid address: {parts[1]}")
                continue
            comment = parts[2] if len(parts) > 2 else ""
            is_clean, hits = check_value(addr, list(badchars))
            if not is_clean:
                bad = ", ".join(f"byte[{p}]={hex(b)}" for p, b in hits)
                print(f"  {YELLOW}⚠ Warning: bad chars in address — {bad}{RESET}")
            chain.add(addr, comment)
            print(f"  {GREEN}Added [{len(chain.entries)-1}] {hex(addr)}  {comment}{RESET}")

        elif cmd == "pad":
            if len(parts) >= 2:
                try:
                    val = int(parts[1], 16)
                except ValueError:
                    print(f"  [!] Invalid value: {parts[1]}")
                    continue
            else:
                val = 0x42424242
            comment = parts[2] if len(parts) > 2 else "padding / junk"
            chain.add(val, comment, is_padding=True)
            print(f"  {GREEN}Added padding [{len(chain.entries)-1}] {hex(val)}{RESET}")

        elif cmd == "remove":
            if len(parts) < 2:
                print("  Usage: remove <index>")
                continue
            try:
                idx = int(parts[1])
            except ValueError:
                print(f"  [!] Invalid index: {parts[1]}")
                continue
            if 0 <= idx < len(chain.entries):
                removed = chain.entries[idx]
                chain.remove(idx)
                print(f"  {GREEN}Removed [{idx}] {removed.addr_str} {removed.comment}{RESET}")
            else:
                print(f"  [!] Index out of range (0-{len(chain.entries)-1})")

        elif cmd == "validate":
            issues = chain.validate()
            if not issues:
                print(f"  {GREEN}All {len(chain.entries)} entries are clean.{RESET}")
            else:
                print(f"  {YELLOW}Found {len(issues)} issue(s):{RESET}")
                for idx, issue in issues:
                    e = chain.entries[idx]
                    print(f"    [{idx}] {e.addr_str}  {e.comment}")
                    print(f"         → {issue}")

        elif cmd == "search":
            if not gadgets:
                print("  [!] No gadget files loaded. Restart with -f file.txt")
                continue
            if len(parts) < 2:
                print("  Usage: search <query>")
                continue
            query = " ".join(parts[1:])
            results = search_gadgets(gadgets, query, badchars=badchars, max_results=20)
            if not results:
                print(f"  [!] No results for '{query}'")
            else:
                print(f"\n  Results for '{query}':\n")
                for g in results:
                    print(format_gadget(g, color=color))
                print()

        elif cmd == "nullcheck":
            if len(parts) < 2:
                print("  Usage: nullcheck <hex_value>")
                continue
            try:
                val = int(parts[1], 16)
            except ValueError:
                print(f"  [!] Invalid value: {parts[1]}")
                continue
            print(analyze_value(val, list(badchars), color=color))

        elif cmd == "export":
            print(f"\n{chain.to_python()}\n")

        elif cmd == "save":
            if len(parts) < 2:
                print("  Usage: save <filename.json>")
                continue
            path = parts[1]
            try:
                with open(path, "w") as f:
                    f.write(chain.to_json())
                print(f"  {GREEN}Saved to {path}{RESET}")
            except Exception as e:
                print(f"  [!] Save failed: {e}")

        elif cmd == "load":
            if len(parts) < 2:
                print("  Usage: load <filename.json>")
                continue
            path = parts[1]
            try:
                with open(path) as f:
                    chain = RopChain.from_json(f.read())
                print(f"  {GREEN}Loaded '{chain.name}' ({len(chain.entries)} entries){RESET}")
            except Exception as e:
                print(f"  [!] Load failed: {e}")

        elif cmd == "name":
            if len(parts) < 2:
                print("  Usage: name <chain_name>")
                continue
            chain.name = " ".join(parts[1:])
            print(f"  {GREEN}Chain name set to: {chain.name}{RESET}")

        elif cmd == "note":
            if len(parts) < 2:
                print("  Usage: note <text>")
                continue
            chain.notes = " ".join(parts[1:])
            print(f"  {GREEN}Note set.{RESET}")

        elif cmd == "clear":
            confirm = input("  Clear all entries? (y/N): ").strip().lower()
            if confirm == "y":
                chain.entries.clear()
                print(f"  {GREEN}Chain cleared.{RESET}")

        else:
            print(f"  [!] Unknown command: {cmd}. Type 'help' for commands.")
