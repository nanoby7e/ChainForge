#!/usr/bin/env python3
"""
ChainForge — Windows ROP chain development toolkit
Pure stdlib. No dependencies. Python 3.6+

Usage:
    python chainforge.py -f rop.txt                   # launch TUI (default)
    python chainforge.py -f rop.txt -b 00,0a,0d       # with bad chars
    python chainforge.py search -f rop.txt "mov eax"  # CLI search
    python chainforge.py nullcheck 0x10021c89         # check address
    python chainforge.py suggest "copy eax to ebx"    # goal-based suggestions
    python chainforge.py chain                        # chain builder
"""

import sys
import os

# Add subdirectories to sys.path so modules can import each other by bare name
_here = os.path.dirname(os.path.abspath(__file__))
for _sub in ('core', 'analysis', 'ui'):
    sys.path.insert(0, os.path.join(_here, _sub))
sys.path.insert(0, _here)

def main():
    args = sys.argv[1:]

    # No args — launch TUI with empty args (will auto-load from gadgets/)
    if not args:
        from ui.tui import launch_tui
        launch_tui([])
        return

    # Explicit help
    if args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    # If first arg is a flag or not a known subcommand, pass everything to TUI
    known_cmds = {"tui", "search", "nullcheck", "suggest", "chain"}
    if args[0].startswith("-") or args[0].lower() not in known_cmds:
        from ui.tui import launch_tui
        launch_tui(args)
        return

    cmd = args[0].lower()

    if cmd == "tui":
        from ui.tui import launch_tui
        launch_tui(args[1:])
    elif cmd == "search":
        from core.search import cli_search
        cli_search(args[1:])
    elif cmd == "nullcheck":
        from core.nullcheck import cli_nullcheck
        cli_nullcheck(args[1:])
    elif cmd == "suggest":
        from core.suggest import cli_suggest
        cli_suggest(args[1:])
    elif cmd == "chain":
        from core.chain import cli_chain
        cli_chain(args[1:])
    else:
        print(f"Unknown command: {args[0]}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()
