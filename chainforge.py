#!/usr/bin/env python3
"""
ChainForge — Windows ROP chain development toolkit
Pure stdlib. No dependencies. Python 3.6+

Usage:
    python chainforge.py tui                          # interactive TUI
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
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "tui":
        from ui.tui import launch_tui
        launch_tui(sys.argv[2:])
    elif cmd == "search":
        from core.search import cli_search
        cli_search(sys.argv[2:])
    elif cmd == "nullcheck":
        from core.nullcheck import cli_nullcheck
        cli_nullcheck(sys.argv[2:])
    elif cmd == "suggest":
        from core.suggest import cli_suggest
        cli_suggest(sys.argv[2:])
    elif cmd == "chain":
        from core.chain import cli_chain
        cli_chain(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()
