"""
tui.py — ChainForge terminal UI
Combines gadget search, null-byte checker, chain builder, and goal suggester
into a single curses-based interface.

Fixes vs original:
- Removed stdscr.timeout(100) — was causing constant redraws that wiped popups
- input_prompt replaced with read_line() — blocking char-by-char input,
  main loop cannot redraw underneath it
- draw_help blocks with its own getch() — popup stays until keypress
- All popups use timeout(-1) while active
- dirty flag — screen only redraws when something changed
"""

import curses
import sys
import os
import re
import struct
from typing import List, Optional
from search import Gadget, parse_rpp_file, search_gadgets
from nullcheck import check_value, analyze_value, suggest_alternatives, DEFAULT_BADCHARS
from suggest import GOALS, resolve_goal, suggest_for_goal
from chain import RopChain


# ── Color pair IDs ─────────────────────────────────────────────────────────────
C_TITLE     = 1
C_HIGHLIGHT = 2
C_GOOD      = 3
C_WARN      = 4
C_BAD       = 5
C_DIM       = 6
C_CYAN      = 7
C_INPUT     = 8


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE,     curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_HIGHLIGHT, curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(C_GOOD,      curses.COLOR_GREEN,  -1)
    curses.init_pair(C_WARN,      curses.COLOR_YELLOW, -1)
    curses.init_pair(C_BAD,       curses.COLOR_RED,    -1)
    curses.init_pair(C_DIM,       curses.COLOR_WHITE,  -1)
    curses.init_pair(C_CYAN,      curses.COLOR_CYAN,   -1)
    curses.init_pair(C_INPUT,     curses.COLOR_BLACK,  curses.COLOR_WHITE)


# ── App state ──────────────────────────────────────────────────────────────────

class AppState:
    def __init__(self):
        self.gadgets: List[Gadget] = []
        self.files: List[str] = []
        self.badchars: bytes = DEFAULT_BADCHARS
        self.search_results: List[Gadget] = []
        self.search_query: str = ""
        self.selected_idx: int = 0
        self.chain = RopChain()
        self.active_tab: int = 5
        self.status_msg: str = "ChainForge ready  |  ? help  |  1-4 switch tabs  |  q quit"
        self.scroll_offset: int = 0
        self.suggest_goal: str = ""
        self.suggest_results: dict = {}
        self.nullcheck_value: str = ""
        self.nullcheck_output: List[str] = []
        self.dirty: bool = True
        self.highlight_query: str = ""   # term to highlight in search results
        self.regex_mode: bool = False     # True when last search was regex
        self.suggest_sel: int = 0         # selected gadget row index in suggest
        self.cheat_scroll: int = 0        # scroll offset for cheatsheet tab
        self.session_log: list = []        # actions buffered during curses session
        self.cheat_filter: str = ""       # filter string for cheatsheet tab
        self.cheat_sel: int = 0           # selected entry in cheatsheet
        self.analysis_rows: list = []     # flat display rows from last analysis
        self.analysis_scroll: int = 0     # scroll offset for analysis tab
        self.analysis_done: bool = False  # whether analysis has been run


# ── Safe draw helper ───────────────────────────────────────────────────────────

def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    available = w - x - 1
    if available <= 0:
        return
    try:
        win.addstr(y, x, str(text)[:available], attr)
    except curses.error:
        pass


# ── Blocking line input ────────────────────────────────────────────────────────

def read_line(win, y, x, prompt: str, initial: str = "") -> Optional[str]:
    """
    Blocking single-line input drawn at (y, x).
    Returns the string entered, or None if user pressed Escape.
    Uses character-by-character getch() with timeout(-1) so the
    main loop cannot race and redraw over this.
    """
    h, w = win.getmaxyx()
    px = x
    ix = x + len(prompt)
    max_len = max(1, w - ix - 2)

    win.timeout(-1)
    curses.curs_set(1)

    buf = list(initial)
    cur = len(buf)

    def redraw():
        safe_addstr(win, y, px, prompt, curses.color_pair(C_CYAN) | curses.A_BOLD)
        win.hline(y, ix, ' ', max_len)
        display = "".join(buf)
        safe_addstr(win, y, ix, display[:max_len], curses.color_pair(C_INPUT))
        cx = min(ix + cur, ix + max_len - 1)
        try:
            win.move(y, cx)
        except curses.error:
            pass
        win.refresh()

    redraw()
    result = None

    while True:
        try:
            ch = win.getch()
        except KeyboardInterrupt:
            break

        if ch in (curses.KEY_ENTER, 10, 13):
            result = "".join(buf)
            break
        elif ch == 27:          # Escape
            result = None
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif ch == curses.KEY_DC:
            if cur < len(buf):
                buf.pop(cur)
        elif ch == curses.KEY_LEFT:
            cur = max(0, cur - 1)
        elif ch == curses.KEY_RIGHT:
            cur = min(len(buf), cur + 1)
        elif ch == curses.KEY_HOME:
            cur = 0
        elif ch == curses.KEY_END:
            cur = len(buf)
        elif 32 <= ch <= 126 and len(buf) < max_len:
            buf.insert(cur, chr(ch))
            cur += 1

        redraw()

    curses.curs_set(0)
    win.timeout(-1)
    return result


# ── Chrome ─────────────────────────────────────────────────────────────────────

def draw_title_bar(win, state: AppState):
    h, w = win.getmaxyx()
    tabs = ["[1] Analysis", "[2] Search", "[3] Suggest", "[4] Chain", "[5] NullChk", "[6] RegEx CheatSheet"]
    # Map display position (0-5) to the internal active_tab index
    # Key 1=Analysis(5), 2=Search(0), 3=Suggest(1), 4=Chain(2), 5=NullChk(3), 6=CheatSheet(4)
    tab_display_to_internal = [5, 0, 1, 2, 3, 4]
    title = " ChainForge "
    win.hline(0, 0, ' ', w)
    safe_addstr(win, 0, 1, title,
                curses.color_pair(C_TITLE) | curses.A_BOLD)
    x = len(title) + 2
    for i, tab in enumerate(tabs):
        is_active = tab_display_to_internal[i] == state.active_tab
        attr = curses.color_pair(C_HIGHLIGHT) if is_active \
               else curses.color_pair(C_TITLE)
        safe_addstr(win, 0, x, f" {tab} ", attr)
        x += len(tab) + 3
    info = f" {len(state.gadgets):,} gadgets | bad: {','.join(hex(b) for b in state.badchars)} "
    safe_addstr(win, 0, w - len(info) - 1, info, curses.color_pair(C_TITLE))


def draw_status_bar(win, state: AppState):
    h, w = win.getmaxyx()
    win.hline(h - 1, 0, ' ', w)
    safe_addstr(win, h - 1, 1, state.status_msg[:w - 2],
                curses.color_pair(C_TITLE))


# ── Tab 1: Search ──────────────────────────────────────────────────────────────

def _highlight_asm(win, row, col, asm: str, query: str, is_sel: bool, max_w: int):
    """
    Draw asm text with the query term highlighted in yellow/bold.
    - Selected row:     base=green/bold,  highlight=yellow/bold
    - Normal row:       base=white/dim,   highlight=yellow/bold
    Using C_DIM (white) as base ensures the yellow highlight is always visible.
    Using attr=0 (default) made text invisible on some terminals.
    """
    if not query or len(asm) == 0:
        safe_addstr(win, row, col, asm[:max_w],
                    curses.color_pair(C_GOOD) | curses.A_BOLD if is_sel
                    else curses.color_pair(C_DIM))
        return

    base_attr  = curses.color_pair(C_GOOD) | curses.A_BOLD if is_sel else curses.color_pair(C_DIM)
    hi_attr    = curses.color_pair(C_WARN) | curses.A_BOLD

    q = query.lower()
    text = asm[:max_w]
    x = col
    remaining = max_w
    i = 0
    while i < len(text) and remaining > 0:
        pos = text.lower().find(q, i)
        if pos == -1 or pos >= len(text):
            safe_addstr(win, row, x, text[i:][:remaining], base_attr)
            break
        # draw text before match
        before = text[i:pos]
        if before:
            safe_addstr(win, row, x, before[:remaining], base_attr)
            x += len(before)
            remaining -= len(before)
        # draw highlighted match
        match = text[pos:pos + len(q)]
        safe_addstr(win, row, x, match[:remaining], hi_attr)
        x += len(match)
        remaining -= len(match)
        i = pos + len(q)


def draw_search_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2

    # ── Header: line 1 — mode + query ──────────────────────────────────────────
    # Mode badge
    if state.regex_mode:
        mode_label = "[REGEX]"
        mode_attr  = curses.color_pair(C_WARN) | curses.A_BOLD
    else:
        mode_label = "[plain]"
        mode_attr  = curses.color_pair(C_DIM)
    safe_addstr(win, y, 2, mode_label, mode_attr)

    # "Query:" label
    safe_addstr(win, y, 11, "Query:", curses.color_pair(C_CYAN))

    # Query value or hint — keep well clear of right edge
    if state.search_query:
        q_text = state.search_query[:w - 18]
        safe_addstr(win, y, 18, q_text, curses.color_pair(C_GOOD))
    else:
        hint = "/=plain search  |  addr: 0x10012f97 or partial 10012f"
        safe_addstr(win, y, 18, hint[:w - 18], curses.color_pair(C_DIM))
    y += 1

    # ── Header: line 2 — result count + sort info ────────────────────────────
    if state.search_results:
        count_str = f"{len(state.search_results):,} results"
        safe_addstr(win, y, 2, count_str, curses.color_pair(C_CYAN))
        sort_info = "  sorted: plain ret  ->  fewest instructions  ->  score"
        safe_addstr(win, y, 2 + len(count_str), sort_info[:w - 4 - len(count_str)],
                    curses.color_pair(C_DIM))
    else:
        safe_addstr(win, y, 2,
                    "No results" if state.search_query else
                    "Load a file with L, then press / to search",
                    curses.color_pair(C_DIM))
    y += 1
    win.hline(y, 0, curses.ACS_HLINE, w)
    y += 1

    visible_h = h - y - 3
    start = state.scroll_offset
    hl = state.highlight_query

    for i, g in enumerate(state.search_results[start:start + visible_h]):
        row = y + i
        idx = start + i
        is_sel = idx == state.selected_idx
        if is_sel:
            safe_addstr(win, row, 0, '>', curses.color_pair(C_GOOD) | curses.A_BOLD)

        clean, _ = check_value(g.address, list(state.badchars))
        sc = curses.color_pair(C_GOOD) if clean else curses.color_pair(C_BAD)

        # ret indicator
        last = g.instructions[-1].strip().lower() if g.instructions else ""
        if re.match(r'ret$', last):
            ret_ind = "R"
            ret_attr = curses.color_pair(C_GOOD) | curses.A_BOLD
        elif re.match(r'retn', last):
            ret_ind = "r"
            ret_attr = curses.color_pair(C_WARN)
        else:
            ret_ind = "-"
            ret_attr = curses.color_pair(C_DIM)

        safe_addstr(win, row, 2, "[+]" if clean else "[!]", sc)
        safe_addstr(win, row, 6, ret_ind, ret_attr)

        # ── instruction count (green<=2, yellow<=4, dim>=5) ───────────────────
        n_instrs = len(g.instructions)
        cnt_str  = f"{n_instrs:2}"
        cnt_attr = (curses.color_pair(C_GOOD) if n_instrs <= 2 else
                    curses.color_pair(C_WARN) if n_instrs <= 4 else
                    curses.color_pair(C_DIM))
        safe_addstr(win, row, 8, cnt_str, cnt_attr)

        safe_addstr(win, row, 11, g.addr_str,
                    curses.color_pair(C_CYAN) | (curses.A_BOLD if is_sel else 0))
        _highlight_asm(win, row, 22, g.asm, hl, is_sel, w - 36)
        mod = f"[{g.module}]"
        safe_addstr(win, row, w - len(mod) - 2, mod, curses.color_pair(C_DIM))

    if not state.search_results:
        if state.search_query:
            safe_addstr(win, y + 1, 4,
                        f"No gadgets matched '{state.search_query[:w-20]}' -- try broadening or use x for regex",
                        curses.color_pair(C_DIM))
        else:
            # ── Regex quick-start guide ───────────────────────────────────────
            CY  = curses.color_pair(C_CYAN)
            WN  = curses.color_pair(C_WARN)
            DIM = curses.color_pair(C_DIM)
            GD  = curses.color_pair(C_GOOD)
            row = y + 1

            def sh(r, c, text, attr=DIM):
                safe_addstr(win, r, c, text[:w - c - 1], attr)

            sh(row, 2, "Plain search  (/  or  n to refine)", CY)
            sh(row, 42, "Matches ASM text or gadget address.", DIM)
            row += 1
            sh(row, 4, "mov eax",     GD)
            sh(row, 18, "->  any gadget containing 'mov eax' in the ASM", DIM)
            row += 1
            sh(row, 4, "0x10012f97",  GD)
            sh(row, 18, "->  look up a gadget by full address", DIM)
            row += 1
            sh(row, 4, "10012f",      GD)
            sh(row, 18, "->  partial address — returns all gadgets in that range", DIM)
            row += 2

            sh(row, 2, "Regex search  (x)", CY)
            sh(row, 20, "Pattern language — build precise matches:", DIM)
            row += 1

            entries = [
                (r"\s+",        "one or more spaces     e.g.  mov\\s+eax matches 'mov eax'"),
                (r"\s*",        "zero or more spaces    e.g.  [eax\\s*+\\s*4]"),
                (r".*",          "anything in between    e.g.  push.*pop  matches push then pop"),
                (r"e[a-z]{2}",   "any register           e.g.  mov\\s+e[a-z]{2},\\s*eax"),
                (r"[^]]+",       "anything except ]      e.g.  [eax[^]]*]  matches [eax+offset]"),
                (r"(a|b)",       "either a or b          e.g.  (mov|lea)\\s+eax"),
                (r"^mov",        "must start with mov    e.g.  ^mov\\s+eax  (strict = clean)"),
                (r";.*ret",      "ends with ret          e.g.  ^mov\\s+eax,\\s*esi\\s*;.*ret"),
                (r"\b",         "word boundary          e.g.  \\beax\\b  won't match 'eaxh'"),
            ]
            for pat, desc in entries:
                if row >= h - 4:
                    break
                sh(row, 4,  pat,  WN)
                sh(row, 18, desc, DIM)
                row += 1

            row += 1
            if row < h - 4:
                sh(row, 2, "Tip:", CY)
                sh(row, 8, "Use the [5] RegEx CheatSheet tab to browse pre-built patterns with strict/loose tags.", DIM)


    safe_addstr(win, h - 2, 2,
                "/=search (ASM or address)  x=regex  n=refine  c=clear  UP/DN=scroll  Enter=add to chain  L=load",
                curses.color_pair(C_DIM))


def handle_search_key(win, key, state: AppState):
    h, w = win.getmaxyx()

    if key in (ord('/'), ord('s')):
        q = read_line(win, 2, 2, "/ Search: ", "")   # empty — new search
        if q is not None:
            state.search_query = q
            state.highlight_query = q
            state.regex_mode = False
            state.search_results = search_gadgets(
                state.gadgets, q,
                badchars=state.badchars,
                regex_mode=False,
                max_results=0,
            )
            state.selected_idx = 0
            state.scroll_offset = 0
            n = len(state.search_results)
            state.status_msg = f"Plain search: {n} results for '{q}'"

    elif key in (ord('x'), ord('X'), ord('R'), ord('r')):
        q = read_line(win, 2, 2, "x Regex: ", "")   # empty — new search
        if q is not None:
            # Validate regex before running — show error in status bar
            try:
                re.compile(q, re.IGNORECASE)
            except re.error as e:
                state.status_msg = f"Invalid regex: {e}"
                state.regex_mode = False
                return
            state.search_query = q
            state.highlight_query = ""
            state.regex_mode = True
            state.search_results = search_gadgets(
                state.gadgets, q,
                badchars=state.badchars,
                regex_mode=True,
                max_results=0,
            )
            state.selected_idx = 0
            state.scroll_offset = 0
            n = len(state.search_results)
            state.status_msg = f"Regex: {n} results for '{q}'"

    elif key == ord('n'):
        # Refine — pre-fills last query so you can edit and re-run
        if state.search_query:
            q = read_line(win, 2, 2, "n Refine: ", state.search_query)
            if q is not None:
                state.search_query = q
                state.highlight_query = q if not state.regex_mode else ""
                state.search_results = search_gadgets(
                    state.gadgets, q,
                    badchars=state.badchars,
                    regex_mode=state.regex_mode,
                    max_results=0,
                )
                state.selected_idx = 0
                state.scroll_offset = 0
                n = len(state.search_results)
                mode = "Regex" if state.regex_mode else "Plain"
                state.status_msg = f"{mode} refine: {n} results for '{q}'"

    elif key == curses.KEY_DOWN:
        if state.selected_idx < len(state.search_results) - 1:
            state.selected_idx += 1
            if state.selected_idx >= state.scroll_offset + (h - 8):
                state.scroll_offset += 1

    elif key == curses.KEY_UP:
        if state.selected_idx > 0:
            state.selected_idx -= 1
            if state.selected_idx < state.scroll_offset:
                state.scroll_offset -= 1

    elif key in (10, 13, curses.KEY_ENTER):
        if state.search_results and state.selected_idx < len(state.search_results):
            g = state.search_results[state.selected_idx]
            comment = read_line(win, h - 3, 2, "Comment: ", g.asm)
            if comment is not None:
                state.chain.add(g.address, comment or g.asm)
                state.status_msg = f"Added {g.addr_str}  ({len(state.chain.entries)} in chain)"

    elif key == ord('a'):
        for g in state.search_results:
            state.chain.add(g.address, g.asm)
        state.status_msg = f"Added all {len(state.search_results)} gadgets to chain"

    elif key == ord('c'):
        state.search_query   = ""
        state.highlight_query = ""
        state.search_results = []
        state.selected_idx   = 0
        state.scroll_offset  = 0
        state.regex_mode     = False
        state.status_msg     = "Search cleared"

    elif key == ord('L'):
        path = read_line(win, h - 3, 2, "Load rp++ file: ")
        if path:
            path = path.strip()
            if os.path.exists(path):
                new_g = parse_rpp_file(path)
                state.gadgets.extend(new_g)
                state.files.append(path)
                state.session_log.append(f"[+] Gadgets loaded: {path}  ({len(new_g):,} gadgets)")
                state.status_msg = (f"Loaded {len(new_g):,} gadgets from "
                                    f"{os.path.basename(path)} "
                                    f"(total: {len(state.gadgets):,})")
            else:
                state.status_msg = f"File not found: {path}"
                state.session_log.append(f"[!] Gadget file not found: {path}")


# ── Tab 2: Suggest ─────────────────────────────────────────────────────────────

# ── Goal descriptions for the suggest tab ─────────────────────────────────────
# ── Goal catalogue: (description, [usage examples], [asm examples]) ──────────
GOAL_CATALOGUE = {
    "copy": (
        "copy any register into any other register",
        ["copy eax", "copy esi", "copy ecx to edx", "move esi"],
        ["mov eax, esi ; ret", "push ebx ; pop eax ; ret", "lea ecx, [edx] ; ret"],
    ),
    "copy (into reg)": (
        "copy ANY source register INTO a specific destination register",
        ["copy into eax", "load into ebx", "copy into esi from ecx"],
        ["mov eax, esi ; ret", "push ecx ; pop eax ; ret", "xchg eax, ebx ; ret"],
    ),
    "copy (both directions)": (
        "find ALL gadgets where a register appears as source OR destination",
        ["copy eax both", "eax bidirectional", "copy esi involving"],
        ["mov eax, esi ; ret", "mov ecx, eax ; ret", "push eax ; pop ebx ; ret"],
    ),
    "capture esp": (
        "read current ESP value into a register — captures the stack address",
        ["capture esp", "get esp", "esp"],
        ["mov eax, esp ; ret", "push esp ; pop eax ; ret", "lea eax, [esp] ; ret"],
    ),
    "dereference": (
        "read value FROM memory: dst = [ptr]  —  follow a pointer",
        ["deref esi", "deref eax", "dereference ecx to ebx"],
        ["mov eax, dword [esi] ; ret", "mov ebx, dword [eax] ; ret", "lodsd ; ret"],
    ),
    "write memory": (
        "write a register INTO memory: [ptr] = src  —  patch a value in place",
        ["write esi", "write edi eax", "write ecx"],
        ["mov dword [esi], eax ; ret", "stosd ; ret  (eax->[edi])", "or dword [esi], eax ; ret"],
    ),
    "zero register": (
        "zero out a register — use xor (cleanest, null-free) or cdq to zero EDX",
        ["zero eax", "zero edx", "null ebx", "cdq"],
        ["xor eax, eax ; ret", "sub ecx, ecx ; ret", "cdq ; ret  (EDX=0 when EAX positive)"],
    ),
    "add offset": (
        "add an offset to a register — includes null-free negation trick",
        ["add eax", "add offset", "add ebx"],
        ["add eax, 0x1C ; ret", "sub eax, 0xFFFFFFE4 ; ret  (== +0x1C)", "inc eax ; ret"],
    ),
    "subtract offset": (
        "subtract from a register — null-free alternatives included",
        ["subtract eax", "sub ecx", "decrease ebx"],
        ["sub eax, 0x10 ; ret", "dec ebx ; ret", "neg eax ; ret"],
    ),
    "inc dec": (
        "single-step inc/dec — chain multiples for small null-free adjustments",
        ["inc dec", "increment", "decrement"],
        ["inc eax ; ret", "dec ebx ; ret", "inc esi ; pop edi ; ret"],
    ),
    "neg": (
        "negate a register — two's complement, useful for null-free sign inversion",
        ["neg", "negate eax"],
        ["neg eax ; ret", "neg ecx ; pop esi ; ret"],
    ),
    "stack pivot": (
        "redirect ESP to a controlled buffer — foundation of ROP exploitation",
        ["stack pivot", "pivot", "esp control"],
        ["xchg eax, esp ; ret", "mov esp, eax ; ret", "mov esp, ebp ; pop ebp ; ret"],
    ),
    "call function": (
        "call or jump to address in a register — used to invoke VirtualAlloc, shellcode etc",
        ["call function", "virtualalloc", "call eax", "jmp eax"],
        ["call eax", "jmp eax", "push eax ; ret  (trampoline)", "call [esi]"],
    ),
    "pop": (
        "pop next stack value into a register — loads value from your ROP chain",
        ["pop eax", "pop ecx", "pop esi"],
        ["pop eax ; ret", "pop ecx ; pop esi ; ret", "pop edi ; pop esi ; pop ebx ; ret"],
    ),
    "push": (
        "push a register or immediate value onto the stack",
        ["push eax", "push esi", "push ecx"],
        ["push eax ; ret", "push esi ; pop ebx ; ret", "push esp ; ret  (captures stack addr)"],
    ),
    "logic": (
        "bitwise ops — xor to zero, or to combine, and to mask, not to flip",
        ["logic", "xor", "or", "bitwise"],
        ["xor eax, eax ; ret", "or ebx, eax ; ret", "and ecx, edx ; ret", "not eax ; ret"],
    ),
    "flags": (
        "CPU flag manipulation — cld/std control direction, clc/stc carry, pushfd/popfd save/restore",
        ["flags", "eflags", "cld"],
        ["cld ; ret", "std ; ret", "clc ; ret", "pushfd ; ret", "popfd ; ret"],
    ),
    "clear direction flag": (
        "cld — clears DF flag, MUST run before stosd/lodsd/movsd so they move forward",
        ["cld", "clear direction flag", "df"],
        ["cld ; ret", "cld ; pop esi ; ret"],
    ),
    "string ops": (
        "stosd/lodsd/movsd — fast memory ops using ESI/EDI, always needs cld first",
        ["string ops", "stosd", "lodsd"],
        ["cld ; ret  (run first!)", "stosd ; ret  (eax->[edi], edi+=4)",
         "lodsd ; ret  ([esi]->eax, esi+=4)", "movsd ; ret  ([esi]->[edi])"],
    ),
    "save registers": (
        "pushad — pushes all 8 GPRs to stack (32 bytes): EAX ECX EDX EBX ESP EBP ESI EDI",
        ["save registers", "pushad", "push all"],
        ["pushad ; ret", "pusha ; ret"],
    ),
    "restore registers": (
        "popad — pops all 8 GPRs from stack, restores state after function call",
        ["restore registers", "popad", "pop all"],
        ["popad ; ret  (restores EDI ESI EBP EBX EDX ECX EAX)", "popa ; ret"],
    ),
    "syscall": (
        "trigger OS syscall — int 0x80 Linux 32-bit, int 0x2e Windows native, sysenter fast path",
        ["syscall", "int 0x80", "sysenter"],
        ["int 0x80 ; ret  (Linux, eax=syscall#)", "int 0x2e ; ret  (Windows)", "sysenter"],
    ),
    "nop": (
        "no-op gadgets — alignment padding, NOP sled building, or timing fillers",
        ["nop", "padding"],
        ["nop ; ret", "fnop ; ret  (FPU nop)", "xchg eax, eax ; ret  (encodes as 0x90)"],
    ),
    "shift": (
        "bit shift/rotate — shl/shr for multiply/divide by 2, rol/ror for encoding tricks",
        ["shift", "shl", "rotate"],
        ["shl eax, 1 ; ret  (*2)", "shr ecx, 4 ; ret  (/16)", "rol eax, 8 ; ret"],
    ),
    "byte manipulation": (
        "byte-level ops — bswap reverses endian, movzx/movsx extend bytes, xlatb table lookup",
        ["byte manipulation", "bswap", "endian", "movsx"],
        ["bswap eax ; ret  (12345678->78563412)", "movzx eax, al ; ret", "cdq ; ret"],
    ),
    "all shorthands": (
        "sweep for ALL single-instruction shorthands in one search across your dump",
        ["all shorthands", "all", "shorthands"],
        ["cld ; ret", "cdq ; ret", "pushad ; ret", "popad ; ret", "stosd ; ret", "lodsd ; ret"],
    ),
    "retn": (
        "retn N gadgets — stdcall cleanup, each N bytes needs matching padding in your chain",
        ["retn", "stdcall", "cleanup"],
        ["retn 0x0002  (2 bytes pad)", "retn 0x0004  (4 bytes)", "retn 0x000C  (12 bytes)"],
    ),
    "leave": (
        "leave = mov esp,ebp ; pop ebp — epilogue fragment useful for stack pivot setup",
        ["leave", "epilogue"],
        ["leave ; ret", "mov esp, ebp ; pop ebp ; ret"],
    ),
}

GOAL_DESCRIPTIONS = {k: v[0] for k, v in GOAL_CATALOGUE.items()}


def _goal_desc(goal_key: str) -> str:
    """Get human-readable description for a goal, including dynamic ones."""
    from suggest import goal_display_name
    if goal_key in GOAL_DESCRIPTIONS:
        return GOAL_DESCRIPTIONS[goal_key]
    # Dynamic goals — generate description from key
    if goal_key.startswith("__copyinto__"):
        parts = goal_key.split("__")
        dst, src = parts[2], parts[3]
        return f"copy {src if src != 'any' else 'any register'} INTO {dst} — {dst} is the destination"
    if goal_key.startswith("__copyboth__"):
        reg = goal_key.split("__")[2]
        return f"all gadgets where {reg} appears as source OR destination (bidirectional)"
    if goal_key.startswith("__copy__"):
        parts = goal_key.split("__")
        src, dst = parts[2], parts[3]
        return f"copy {src} OUT to {dst if dst != 'any' else 'any register'} — {src} is the source"
    if goal_key.startswith("__deref__"):
        parts = goal_key.split("__")
        src, dst = parts[2], parts[3]
        return f"read [{src}] into {dst if dst != 'any' else 'any register'}: dst = dword [{src}]"
    if goal_key.startswith("__write__"):
        parts = goal_key.split("__")
        ptr, src = parts[2], parts[3]
        return f"write {src if src != 'any' else 'a register'} into memory at [{ptr}]: [{ptr}] = src"
    if goal_key.startswith("__zero__"):
        reg = goal_key.split("__")[2]
        return f"zero out {reg} without null bytes (xor {reg},{reg} or cdq)"
    if goal_key.startswith("__pop__"):
        reg = goal_key.split("__")[2]
        return f"pop next stack value into {reg}"
    if goal_key.startswith("__push__"):
        reg = goal_key.split("__")[2]
        return f"push {reg} onto the stack — used for stack relay or preserving value"
    if goal_key.startswith("__add__"):
        reg = goal_key.split("__")[2]
        return f"add immediate or register to {reg} (null-free options included)"
    if goal_key.startswith("__sub__"):
        reg = goal_key.split("__")[2]
        return f"subtract from {reg}: sub, dec, neg"
    return goal_display_name(goal_key)


def draw_suggest_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2

    # Goal line + description
    safe_addstr(win, y, 2, "Goal: ", curses.color_pair(C_CYAN))
    goal_disp = state.suggest_goal or "(press / to set goal)"
    safe_addstr(win, y, 8, goal_disp[:w - 10], curses.color_pair(C_DIM))
    y += 1

    if state.suggest_goal:
        desc = _goal_desc(state.suggest_goal)
        safe_addstr(win, y, 4, desc[:w - 6], curses.color_pair(C_WARN))
    y += 1
    win.hline(y, 0, curses.ACS_HLINE, w)
    y += 1

    if not state.suggest_results:
        if not state.suggest_goal:
            # ── Goal catalogue browser ────────────────────────────────────────
            # Shows scrollable list: goal name + description + query examples
            cat_keys = list(GOAL_CATALOGUE.keys())
            # prepend dynamic examples
            dynamic_entries = [
                ("copy eax  (out)",       "copy eax OUT to any register — eax is the source",
                 ["copy eax", "move esi", "copy ecx to edx"]),
                ("copy into eax",         "copy any register INTO eax — eax is the destination",
                 ["copy into eax", "load into ebx", "copy into esi from ecx"]),
                ("copy eax both",         "all gadgets involving eax as source OR destination",
                 ["copy eax both", "eax bidirectional", "copy esi involving"]),
                ("deref esi",             "dereference: eax = [esi]  —  follow a pointer in esi",
                 ["deref esi", "deref eax", "dereference ecx to ebx"]),
                ("write esi eax",         "write eax into memory: [esi] = eax",
                 ["write esi", "write edi eax", "write ecx"]),
                ("zero eax",              "zero out eax: xor eax,eax  (null-free)",
                 ["zero eax", "zero edx", "null ebx"]),
                ("pop ecx",               "pop next chain value into ecx",
                 ["pop ecx", "pop eax", "pop esi"]),
                ("add eax",               "add offset to eax, null-free options included",
                 ["add eax", "add ebx", "subtract ecx"]),
            ]

            safe_addstr(win, y, 2,
                        "/  to search a goal  |  UP/DN to scroll  |  1 to return to Search",
                        curses.color_pair(C_DIM))
            y += 1
            win.hline(y, 0, curses.ACS_HLINE, w)
            y += 1

            # Build flat list of display rows
            # Each entry: (indent, text, attr)
            all_rows = []

            # Static goals from catalogue
            all_rows.append((0, "  STATIC GOALS", curses.color_pair(C_CYAN) | curses.A_BOLD))
            all_rows.append((0, "", 0))
            for key, (desc, examples, asm_examples) in GOAL_CATALOGUE.items():
                all_rows.append((0, f"  {key}", curses.color_pair(C_CYAN)))
                all_rows.append((2, desc[:w-6], curses.color_pair(C_WARN)))
                ex_str = "  query: " + "  /  ".join(examples[:3])
                all_rows.append((2, ex_str[:w-6], curses.color_pair(C_DIM)))
                asm_str = "  e.g.:  " + "   ".join(asm_examples[:2])
                all_rows.append((2, asm_str[:w-6], curses.color_pair(C_GOOD)))
                all_rows.append((0, "", 0))

            # Dynamic examples
            all_rows.append((0, "  DYNAMIC GOALS  (register-aware)", curses.color_pair(C_CYAN) | curses.A_BOLD))
            all_rows.append((0, "", 0))
            for name, desc, examples in dynamic_entries:
                all_rows.append((0, f"  {name}", curses.color_pair(C_CYAN)))
                all_rows.append((2, desc[:w-6], curses.color_pair(C_WARN)))
                ex_str = "  query: " + "  /  ".join(examples[:3])
                all_rows.append((2, ex_str[:w-6], curses.color_pair(C_DIM)))
                all_rows.append((0, "", 0))

            visible_h = h - y - 3
            scroll = state.scroll_offset
            total = len(all_rows)
            for row_data in all_rows[scroll:scroll + visible_h]:
                if y >= h - 3:
                    break
                indent, text, attr = row_data
                if text:
                    safe_addstr(win, y, indent, text, attr)
                y += 1

            if total > visible_h:
                safe_addstr(win, h - 3, w - 20,
                            f"[{scroll+1}-{min(scroll+visible_h, total)}/{total}]",
                            curses.color_pair(C_DIM))
        else:
            safe_addstr(win, y + 2, 4,
                        "No gadgets found. Load a gadget file with L, or try a different goal.",
                        curses.color_pair(C_DIM))
        safe_addstr(win, h - 2, 2,
                    "/=search goal  c=clear  L=load file  UP/DN=scroll",
                    curses.color_pair(C_DIM))
        return

    # ── Results — scrollable, sorted, highlighted ────────────────────────────
    visible_h = h - y - 3
    flat_rows = []  # (is_header, content, attr)
    #   is_header=True  -> content is a string label
    #   is_header=False -> content is a Gadget object

    # Build highlight term from the actual pattern being searched, not the goal name
    # Use the search query stored from last plain search, or fall back to nothing
    # For suggest, we derive a plain-text highlight from the goal key
    def _suggest_hl(goal_key: str) -> str:
        """Extract a plain-text highlight term from a goal key."""
        if not goal_key or goal_key.startswith('__'):
            parts = goal_key.split('__') if goal_key else []
            if len(parts) > 2:
                verb = parts[1]
                reg  = parts[2]
                if verb in ('copy', 'copyinto', 'copyboth'):
                    return reg
                if verb == 'deref':
                    return f'[{reg}]'
                if verb == 'write':
                    return f'[{reg}]'
                if verb in ('zero', 'pop', 'push', 'add', 'sub'):
                    return reg
            return ""
        # Static goals — use key words as highlight
        hl_map = {
            'write memory': '[', 'dereference': '[',
            'capture esp': 'esp', 'stack pivot': 'esp',
            'zero register': 'xor', 'add offset': 'add',
            'subtract offset': 'sub', 'call function': 'call',
            'pop': 'pop', 'logic': 'xor',
        }
        return hl_map.get(goal_key, "")

    hl_term = _suggest_hl(state.suggest_goal)

    for desc, gs in state.suggest_results.items():
        # Category header — show gadget count
        flat_rows.append((True, f"-- {desc}  ({len(gs)})", curses.color_pair(C_CYAN)))
        # Gadgets already sorted by suggest_for_goal (ret-first, fewest instructions)
        for g in gs:
            flat_rows.append((False, g, 0))
        flat_rows.append((True, "", 0))   # blank separator

    start = state.scroll_offset
    row = y
    # Build a flat list of visible gadget indices for selection tracking
    gadget_flat = []   # list of Gadget objects in display order (no headers)
    for item in flat_rows:
        if not item[0]:   # not a header
            gadget_flat.append(item[1])

    # Clamp suggest_sel to valid range
    if gadget_flat:
        state.suggest_sel = max(0, min(state.suggest_sel, len(gadget_flat) - 1))

    gadget_display_idx = 0  # tracks which gadget we're on across flat_rows

    for item in flat_rows[start:start + visible_h]:
        if row >= h - 3:
            break
        is_header = item[0]
        content   = item[1]

        if is_header:
            if content:
                safe_addstr(win, row, 2, str(content)[:w - 4],
                            curses.color_pair(C_CYAN))
        else:
            g = content

            # Work out the absolute gadget index for this row
            # gadget_flat has all gadgets; we need to find which one this is
            try:
                abs_idx = gadget_flat.index(g)
            except ValueError:
                abs_idx = -1
            is_sel = (abs_idx == state.suggest_sel)
            if is_sel:
                safe_addstr(win, row, 0, '>', curses.color_pair(C_GOOD) | curses.A_BOLD)

            # ── Bad char indicator ────────────────────────────────────────────
            clean, _ = check_value(g.address, list(state.badchars))
            bc_attr  = curses.color_pair(C_GOOD) if clean else curses.color_pair(C_BAD)
            bc_ind   = "[+]" if clean else "[!]"
            safe_addstr(win, row, 2, bc_ind, bc_attr)

            # ── ret indicator ─────────────────────────────────────────────────
            last = g.instructions[-1].strip().lower() if g.instructions else ""
            if re.match(r'ret$', last):
                ret_ind  = "R"
                ret_attr = curses.color_pair(C_GOOD) | curses.A_BOLD
            elif re.match(r'retn', last):
                ret_ind  = "r"
                ret_attr = curses.color_pair(C_WARN)
            else:
                ret_ind  = "-"
                ret_attr = curses.color_pair(C_DIM)
            safe_addstr(win, row, 6, ret_ind, ret_attr)

            # ── instruction count (green=2, yellow=3-4, dim=5+) ───────────────
            n_instrs = len(g.instructions)
            cnt_str  = f"{n_instrs:2}"
            cnt_attr = (curses.color_pair(C_GOOD) if n_instrs <= 2 else
                        curses.color_pair(C_WARN) if n_instrs <= 4 else
                        curses.color_pair(C_DIM))
            safe_addstr(win, row, 8, cnt_str, cnt_attr)

            # ── address ───────────────────────────────────────────────────────
            safe_addstr(win, row, 11, g.addr_str,
                        curses.color_pair(C_CYAN) | (curses.A_BOLD if is_sel else 0))

            # ── asm with highlight ────────────────────────────────────────────
            _highlight_asm(win, row, 22, g.asm, hl_term, is_sel, w - 36)

            # ── module ────────────────────────────────────────────────────────
            mod = f"[{g.module}]"
            safe_addstr(win, row, w - len(mod) - 2, mod, curses.color_pair(C_DIM))

        row += 1

    # scroll indicator
    total = len(flat_rows)
    shown = min(visible_h, total - start)
    if total > visible_h:
        safe_addstr(win, h - 3, w - 22,
                    f"[{start+1}-{start+shown}/{total}]",
                    curses.color_pair(C_DIM))

    safe_addstr(win, h - 2, 2,
                "/=new goal  n=refine goal  UP/DN=navigate  Enter=add to chain  c=clear  L=load",
                curses.color_pair(C_DIM))


def handle_suggest_key(win, key, state: AppState):
    h, w = win.getmaxyx()

    if key in (ord('/'), ord('g')):
        q = read_line(win, 2, 2, "/ Goal: ", "")   # empty — new goal
        if q:
            from suggest import goal_display_name
            goal = resolve_goal(q.strip())
            if goal:
                state.suggest_goal = goal
                state.suggest_results = suggest_for_goal(
                    goal, state.gadgets, state.badchars)
                state.scroll_offset = 0
                total = sum(len(v) for v in state.suggest_results.values())
                state.status_msg = (f"Goal: {goal_display_name(goal)}  --  "
                                    f"{total} gadgets found")
            else:
                state.status_msg = (f"Unknown goal: '{q}'  --  "
                                    "try: copy eax, copy esi to ebx, deref esi, write esi, zero edx")

    elif key == ord('n'):
        # Refine — pre-fills last goal so you can edit it
        if state.suggest_goal:
            from suggest import goal_display_name
            prev = goal_display_name(state.suggest_goal)
            q = read_line(win, 2, 2, "n Refine goal: ", prev)
            if q:
                goal = resolve_goal(q.strip())
                if goal:
                    state.suggest_goal = goal
                    state.suggest_results = suggest_for_goal(
                        goal, state.gadgets, state.badchars)
                    state.scroll_offset = 0
                    state.suggest_sel = 0
                    total = sum(len(v) for v in state.suggest_results.values())
                    state.status_msg = (f"Goal: {goal_display_name(goal)}  --  "
                                        f"{total} gadgets found")
                else:
                    state.status_msg = f"Unknown goal: '{q}'"

    elif key == ord('c'):
        state.suggest_goal = ""
        state.suggest_results = {}
        state.scroll_offset = 0
        state.status_msg = "Goal cleared"

    elif key == curses.KEY_DOWN:
        # Navigate to next gadget, scroll if needed
        if state.suggest_results:
            all_gadgets = [g for gs in state.suggest_results.values() for g in gs]
            if state.suggest_sel < len(all_gadgets) - 1:
                state.suggest_sel += 1
                # Scroll down if selected gadget is off screen
                state.scroll_offset += 1
        else:
            state.scroll_offset += 1

    elif key == curses.KEY_UP:
        # Navigate to previous gadget, scroll if needed
        if state.suggest_results:
            if state.suggest_sel > 0:
                state.suggest_sel -= 1
                state.scroll_offset = max(0, state.scroll_offset - 1)
        else:
            state.scroll_offset = max(0, state.scroll_offset - 1)

    elif key in (10, 13, curses.KEY_ENTER):
        # Add currently selected gadget to chain
        if state.suggest_results:
            all_gadgets = [g for gs in state.suggest_results.values() for g in gs]
            if all_gadgets:
                g = all_gadgets[state.suggest_sel]
                comment = read_line(win, h - 3, 2, "Comment: ", g.asm)
                if comment is not None:
                    state.chain.add(g.address, comment or g.asm)
                    state.status_msg = (f"Added {g.addr_str} to chain "
                                        f"({len(state.chain.entries)} entries)")

    elif key == ord('L'):
        path = read_line(win, h - 3, 2, "Load rp++ file: ")
        if path:
            path = path.strip()
            if os.path.exists(path):
                new_g = parse_rpp_file(path)
                state.gadgets.extend(new_g)
                state.session_log.append(f"[+] Gadgets loaded: {path}  ({len(new_g):,} gadgets)")
                state.status_msg = (f"Loaded {len(new_g):,} gadgets from "
                                    f"{os.path.basename(path)}")
            else:
                state.status_msg = f"File not found: {path}"
                state.session_log.append(f"[!] Gadget file not found: {path}")


# ── Tab 3: Chain ───────────────────────────────────────────────────────────────

def draw_chain_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2
    chain = state.chain
    issues = dict(chain.validate())

    safe_addstr(win, y, 2,
                f"Chain: {chain.name}   {len(chain.entries)} entries   "
                f"bad: {','.join(hex(b) for b in chain.badchars)}",
                curses.color_pair(C_CYAN))
    y += 1
    win.hline(y, 0, curses.ACS_HLINE, w)
    y += 1

    visible_h = h - y - 4
    start = state.scroll_offset

    for i, entry in enumerate(chain.entries[start:start + visible_h]):
        row = y + i
        idx = start + i
        is_sel = idx == state.selected_idx
        if is_sel:
            safe_addstr(win, row, 0, '>', curses.color_pair(C_GOOD) | curses.A_BOLD)

        issue = issues.get(idx)
        s_attr = curses.color_pair(C_BAD) if issue else curses.color_pair(C_GOOD)
        safe_addstr(win, row, 2, f"{idx:3}", curses.color_pair(C_DIM))
        safe_addstr(win, row, 6, "[!]" if issue else "[+]", s_attr)
        pad = "[PAD]" if entry.is_padding else "     "
        safe_addstr(win, row, 10, pad,
                    curses.color_pair(C_WARN) if entry.is_padding
                    else curses.color_pair(C_DIM))
        safe_addstr(win, row, 16, entry.addr_str,
                    curses.color_pair(C_CYAN) | (curses.A_BOLD if is_sel else 0))
        safe_addstr(win, row, 28, entry.comment[:w - 32],
                    curses.color_pair(C_GOOD) if is_sel else 0)

    if not chain.entries:
        safe_addstr(win, y + 2, 4,
                    "Chain is empty  --  search a gadget and press Enter to add it",
                    curses.color_pair(C_DIM))

    safe_addstr(win, h - 3, 2,
                "a=add  p=pad  d=del  K=move up  J=move down  e=export  v=validate  S=save  O=import",
                curses.color_pair(C_DIM))
    safe_addstr(win, h - 2, 2,
                "UP/DN=navigate  c=nullcheck  r=regex pick  N=rename",
                curses.color_pair(C_DIM))


def handle_chain_key(win, key, state: AppState):
    h, w = win.getmaxyx()
    chain = state.chain

    if key == curses.KEY_DOWN:
        if state.selected_idx < len(chain.entries) - 1:
            state.selected_idx += 1
            if state.selected_idx >= state.scroll_offset + (h - 9):
                state.scroll_offset += 1

    elif key == curses.KEY_UP:
        if state.selected_idx > 0:
            state.selected_idx -= 1
            if state.selected_idx < state.scroll_offset:
                state.scroll_offset -= 1

    elif key == ord('a'):
        addr_str = read_line(win, h - 5, 2, "Address (hex): ")
        if addr_str:
            try:
                addr = int(addr_str.strip(), 16)
                comment = read_line(win, h - 4, 2, "Comment: ") or ""
                chain.add(addr, comment)
                state.status_msg = f"Added {hex(addr)}"
            except ValueError:
                state.status_msg = f"Invalid address: {addr_str}"

    elif key == ord('p'):
        comment = read_line(win, h - 5, 2, "Padding comment: ") or "junk / padding"
        chain.add(0x42424242, comment, is_padding=True)
        state.status_msg = "Added padding 0x42424242"

    elif key == ord('d'):
        if chain.entries:
            idx = state.selected_idx
            removed = chain.entries[idx]
            chain.remove(idx)
            if state.selected_idx >= len(chain.entries) and state.selected_idx > 0:
                state.selected_idx -= 1
            state.status_msg = f"Removed [{idx}] {removed.addr_str}"

    elif key == ord('K'):
        # Move selected entry UP one position
        idx = state.selected_idx
        if chain.entries and idx > 0:
            chain.entries[idx], chain.entries[idx - 1] =                 chain.entries[idx - 1], chain.entries[idx]
            state.selected_idx -= 1
            if state.selected_idx < state.scroll_offset:
                state.scroll_offset -= 1
            state.status_msg = f"Moved [{idx}] up  ->  [{idx - 1}]"

    elif key == ord('J'):
        # Move selected entry DOWN one position
        idx = state.selected_idx
        if chain.entries and idx < len(chain.entries) - 1:
            chain.entries[idx], chain.entries[idx + 1] =                 chain.entries[idx + 1], chain.entries[idx]
            state.selected_idx += 1
            if state.selected_idx >= state.scroll_offset + (h - 9):
                state.scroll_offset += 1
            state.status_msg = f"Moved [{idx}] down  ->  [{idx + 1}]"

    elif key == ord('e'):
        state.session_log.append(f"[+] Chain exported to terminal  ({len(chain.entries)} entries)")
        _popup_export(win, state)

    elif key == ord('v'):
        issues = chain.validate()
        if not issues:
            state.status_msg = f"All {len(chain.entries)} entries clean"
        else:
            state.status_msg = f"{len(issues)} bad char issue(s) found"

    elif key == ord('S'):
        path = read_line(win, h - 5, 2, "Save to JSON: ")
        if path:
            try:
                with open(path.strip(), "w") as f:
                    f.write(chain.to_json())
                state.status_msg = f"Saved to {path.strip()}"
                state.session_log.append(f"[+] Chain saved: {path.strip()}  ({len(chain.entries)} entries)")
            except Exception as e:
                state.status_msg = f"Save failed: {e}"
                state.session_log.append(f"[!] Chain save failed: {e}")

    elif key == ord('O'):
        path = read_line(win, h - 5, 2, "Import chain JSON: ")
        if path:
            path = path.strip()
            if not os.path.exists(path):
                state.status_msg = f"File not found: {path}"
                state.session_log.append(f"[!] Chain import failed — file not found: {path}")
            else:
                try:
                    from chain import RopChain
                    with open(path) as f:
                        loaded = RopChain.from_json(f.read())
                    n = len(loaded.entries)
                    # Ask whether to replace or append
                    choice = read_line(win, h - 4, 2,
                                       f"  r=replace current chain  a=append  ({n} entries): ")
                    if choice and choice.strip().lower() == 'r':
                        state.chain = loaded
                        state.chain.badchars = state.badchars
                        state.selected_idx = 0
                        state.scroll_offset = 0
                        state.status_msg = (f"Imported '{loaded.name}' — "
                                            f"{n} entries (replaced)")
                        state.session_log.append(f"[+] Chain imported (replaced): {path}  —  {n} entries")
                    elif choice and choice.strip().lower() == 'a':
                        for entry in loaded.entries:
                            state.chain.entries.append(entry)
                        state.status_msg = (f"Imported '{loaded.name}' — "
                                            f"{n} entries appended "
                                            f"({len(state.chain.entries)} total)")
                        state.session_log.append(f"[+] Chain imported (appended): {path}  —  {n} entries  ({len(state.chain.entries)} total)")
                    else:
                        state.status_msg = "Import cancelled"
                except Exception as e:
                    state.status_msg = f"Import failed: {e}"
                    state.session_log.append(f"[!] Chain import failed: {e}")

    elif key == ord('N'):
        name = read_line(win, h - 5, 2, "Chain name: ")
        if name:
            chain.name = name.strip()
            state.status_msg = f"Renamed: {chain.name}"

    elif key == ord('c'):
        if chain.entries and state.selected_idx < len(chain.entries):
            entry = chain.entries[state.selected_idx]
            out = analyze_value(entry.value, list(state.badchars), color=False)
            state.status_msg = " | ".join(
                l.strip() for l in out.splitlines() if l.strip())

    elif key == ord('r'):
        if not state.gadgets:
            state.status_msg = "No gadgets loaded — press L in Search tab first"
            return
        q = read_line(win, h - 5, 2, "Regex: ")
        if q:
            results = search_gadgets(
                state.gadgets, q,
                badchars=state.badchars,
                regex_mode=True,
                max_results=30,
            )
            if results:
                _popup_picker(win, state, results, q)
            else:
                state.status_msg = f"No results for: {q}"


def _popup_picker(win, state: AppState, results: List[Gadget], query: str):
    h, w = win.getmaxyx()
    box_h = min(len(results) + 6, h - 4)
    box_w = min(w - 6, 110)
    sy = (h - box_h) // 2
    sx = (w - box_w) // 2
    sel = 0

    while True:
        try:
            popup = win.subwin(box_h, box_w, sy, sx)
        except curses.error:
            return
        popup.clear()
        popup.box()
        safe_addstr(popup, 0, 2, f" Regex: {query} ", curses.color_pair(C_TITLE))
        safe_addstr(popup, box_h - 2, 2,
                    "UP/DN select   Enter add to chain   Esc cancel",
                    curses.color_pair(C_DIM))

        visible = box_h - 4
        for i, g in enumerate(results[:visible]):
            row = i + 2
            is_sel = i == sel
            if is_sel:
                popup.hline(row, 1, ' ', box_w - 2)
            clean, _ = check_value(g.address, list(state.badchars))
            color = curses.color_pair(C_GOOD) if clean else curses.color_pair(C_BAD)
            safe_addstr(popup, row, 2, g.addr_str,
                        curses.color_pair(C_CYAN) | (curses.A_BOLD if is_sel else 0))
            safe_addstr(popup, row, 14, g.asm[:box_w - 18], color)

        popup.refresh()
        key = win.getch()

        if key == curses.KEY_DOWN and sel < min(len(results), visible) - 1:
            sel += 1
        elif key == curses.KEY_UP and sel > 0:
            sel -= 1
        elif key in (10, 13, curses.KEY_ENTER):
            g = results[sel]
            popup.clear()
            popup.refresh()
            comment = read_line(win, h - 3, 2, "Comment: ", g.asm)
            state.chain.add(g.address, comment or g.asm)
            state.status_msg = (f"Added {g.addr_str}  "
                                f"({len(state.chain.entries)} in chain)")
            return
        elif key == 27:
            popup.clear()
            popup.refresh()
            return


def _popup_export(win, state: AppState):
    h, w = win.getmaxyx()
    code = state.chain.to_python()
    lines = code.splitlines()
    max_line = max((len(l) for l in lines), default=40)
    box_h = min(len(lines) + 6, h - 2)
    box_w = min(max_line + 6, w - 4)
    sy = max(0, (h - box_h) // 2)
    sx = max(0, (w - box_w) // 2)
    scroll = 0
    visible = box_h - 4

    while True:
        try:
            popup = win.subwin(box_h, box_w, sy, sx)
        except curses.error:
            return
        popup.clear()
        popup.box()
        safe_addstr(popup, 0, 2, " Python Export ", curses.color_pair(C_TITLE))
        safe_addstr(popup, box_h - 2, 2,
                    "UP/DN scroll   any other key to close",
                    curses.color_pair(C_DIM))
        for i, line in enumerate(lines[scroll:scroll + visible]):
            safe_addstr(popup, i + 2, 2, line[:box_w - 4],
                        curses.color_pair(C_GOOD))
        popup.refresh()

        key = win.getch()
        if key == curses.KEY_DOWN and scroll < len(lines) - visible:
            scroll += 1
        elif key == curses.KEY_UP and scroll > 0:
            scroll -= 1
        else:
            popup.clear()
            popup.refresh()
            return


# ── Tab 4: Null Check ──────────────────────────────────────────────────────────

def draw_nullcheck_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2
    safe_addstr(win, y, 2, "Value: ", curses.color_pair(C_CYAN))
    safe_addstr(win, y, 9,
                state.nullcheck_value or "(press n to check a value)",
                curses.color_pair(C_DIM))
    y += 2

    for line in state.nullcheck_output:
        if y >= h - 3:
            break
        line = line.strip()
        if not line:
            y += 1
            continue
        if "CLEAN" in line:
            attr = curses.color_pair(C_GOOD)
        elif "BAD" in line:
            attr = curses.color_pair(C_BAD)
        elif "->" in line or "alternative" in line.lower():
            attr = curses.color_pair(C_WARN)
        else:
            attr = curses.color_pair(C_DIM)
        safe_addstr(win, y, 2, line[:w - 4], attr)
        y += 1

    safe_addstr(win, h - 2, 2,
                "n=check value  m=check multiple  b=set bad chars",
                curses.color_pair(C_DIM))


def handle_nullcheck_key(win, key, state: AppState):
    h, w = win.getmaxyx()

    if key == ord('n'):
        val_str = read_line(win, 2, 2, "Value (hex): ")
        if val_str:
            try:
                val = int(val_str.strip(), 16)
                state.nullcheck_value = hex(val)
                output = analyze_value(val, list(state.badchars), color=False)
                alts = suggest_alternatives(val)
                lines = output.splitlines()
                if alts:
                    lines += ["", "  Null-free alternatives:"]
                    for a in alts:
                        lines.append(f"  -> {a['description']}")
                state.nullcheck_output = lines
                state.status_msg = f"Checked {hex(val)}"
            except ValueError:
                state.status_msg = f"Invalid hex: {val_str}"

    elif key == ord('m'):
        val_str = read_line(win, 2, 2, "Addresses (space-separated hex): ")
        if val_str:
            lines = []
            for v in val_str.strip().split():
                try:
                    val = int(v, 16)
                    clean, hits = check_value(val, list(state.badchars))
                    packed = struct.pack('<I', val & 0xFFFFFFFF)
                    byte_str = ' '.join(f'{b:02x}' for b in packed)
                    if clean:
                        status = "CLEAN"
                    else:
                        status = f"BAD  byte[{hits[0][0]}]={hex(hits[0][1])}"
                    lines.append(f"  {hex(val):14}  [{byte_str}]  {status}")
                except ValueError:
                    lines.append(f"  {v}  INVALID")
            state.nullcheck_output = lines
            state.nullcheck_value = "batch"
            state.status_msg = f"Checked {len(lines)} values"

    elif key == ord('b'):
        bc_str = read_line(win, h - 3, 2, "Bad chars (comma hex, e.g. 00,0a,0d): ")
        if bc_str:
            try:
                state.badchars = bytes(int(x.strip(), 16)
                                       for x in bc_str.split(","))
                state.chain.badchars = state.badchars
                bc_display = ','.join(hex(b) for b in state.badchars)
                state.status_msg = f"Bad chars: {bc_display}"
                state.session_log.append(f"[*] Bad chars changed: {bc_display}")
            except ValueError:
                state.status_msg = "Invalid format — use: 00,0a,0d"


# ── Tab 5: RegEx Cheatsheet ─────────────────────────────────────────────────────

def _parse_cheatsheet():
    """Parse data/cheatsheet.md into a list of (section, subsection, [patterns]) tuples."""
    import os, re as _re
    # Look for the cheatsheet alongside this file
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, '..', 'data', 'cheatsheet.md'),
        os.path.join(here, 'data', 'cheatsheet.md'),
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if not path:
        return []

    def _tag_from_sub(sub: str) -> str:
        """Extract a short type tag from the subsection name."""
        s = sub.lower()
        if "strict" in s:    return "strict"
        if "loose" in s:     return "loose"
        if "broadest" in s:  return "broad"
        if "bare" in s:      return "bare"
        if "both" in s:      return "both"
        if "specific" in s:  return "specific"
        return ""

    sections = []
    cur_section = ""
    cur_sub = ""
    in_code = False
    cur_patterns = []
    cur_comment = ""   # inline comment from the line before (e.g. "; without ret")

    with open(path, errors='replace') as f:
        for line in f:
            line = line.rstrip()
            if line.startswith('## ') and 'Table' not in line:
                if cur_sub and cur_patterns:
                    sections.append((cur_section, cur_sub, cur_patterns[:]))
                cur_section = line[3:].strip()
                cur_sub = ""
                cur_patterns = []
                in_code = False
            elif line.startswith('### '):
                if cur_sub and cur_patterns:
                    sections.append((cur_section, cur_sub, cur_patterns[:]))
                cur_sub = line[4:].strip()
                cur_patterns = []
                cur_comment = ""
                in_code = False
            elif line.strip() in ('```', '```bash', '```python', '```asm', '```regex'):
                in_code = not in_code
            elif in_code:
                stripped = line.strip()
                # "; Strict" / "; Loose" comments set the tag for the next pattern
                if stripped.startswith(';'):
                    comment = stripped[1:].strip().lower()
                    if "strict" in comment:
                        cur_comment = "strict"
                    elif "loose" in comment:
                        cur_comment = "loose"
                    elif "broad" in comment:
                        cur_comment = "broad"
                    elif "bare" in comment:
                        cur_comment = "bare"
                    elif "both" in comment:
                        cur_comment = "both"
                    elif "specific" in comment:
                        cur_comment = "specific"
                    # else keep previous tag
                elif stripped and not stripped.startswith('#'):
                    if any(c in stripped for c in [r'\s', r'\+', r'\*', '[', '.*',
                                                    r'\b', '(?', r'\d', r'\w']):
                        tag = cur_comment or _tag_from_sub(cur_sub)
                        cur_patterns.append((stripped, tag))

    if cur_sub and cur_patterns:
        sections.append((cur_section, cur_sub, cur_patterns[:]))
    return sections


# Load cheatsheet once at module level
_CHEATSHEET = None

def _get_cheatsheet():
    global _CHEATSHEET
    if _CHEATSHEET is None:
        _CHEATSHEET = _parse_cheatsheet()
    return _CHEATSHEET


def draw_cheatsheet_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2

    # Filter input row
    safe_addstr(win, y, 2, "Filter: ", curses.color_pair(C_CYAN))
    filt = state.cheat_filter or "(/ to filter by section or keyword)"
    safe_addstr(win, y, 10, filt[:w - 12], curses.color_pair(C_DIM))
    y += 1
    win.hline(y, 0, curses.ACS_HLINE, w)
    y += 1

    cheat = _get_cheatsheet()

    if not cheat:
        safe_addstr(win, y + 2, 4,
                    "data/cheatsheet.md not found — place the data/ folder alongside chainforge.py",
                    curses.color_pair(C_BAD))
        return

    # Build flat display list filtered by state.cheat_filter
    flt = state.cheat_filter.lower()
    flat = []   # (type, content, attr)
    #   type "section"    -> section heading string
    #   type "sub"        -> subsection heading string
    #   type "pattern"    -> regex pattern string
    #   type "blank"      -> empty spacer

    cur_sec = None
    for section, sub, patterns in cheat:
        # Filter: show entry if filter matches section, sub, or any pattern
        if flt:
            match = (flt in section.lower() or flt in sub.lower() or
                     any(flt in p.lower() for p, _ in patterns))
            if not match:
                continue

        if section != cur_sec:
            if cur_sec is not None:
                flat.append(("blank", "", 0))
            flat.append(("section", f"  {section}", curses.color_pair(C_CYAN) | curses.A_BOLD))
            cur_sec = section

        flat.append(("sub", f"    {sub}", curses.color_pair(C_WARN)))
        for item in patterns:
            # item is (pattern_str, tag_str)
            p, tag = item if isinstance(item, tuple) else (item, "")
            flat.append(("pattern", p, tag))
        flat.append(("blank", "", 0))

    if not flat:
        safe_addstr(win, y + 2, 4,
                    f"No entries match: {state.cheat_filter!r}",
                    curses.color_pair(C_DIM))
        safe_addstr(win, h - 2, 2,
                    "/=filter  c=clear  UP/DN=nav  Enter=run in Search  1=Search tab",
                    curses.color_pair(C_DIM))
        return

    # Clamp selection and scroll
    pattern_indices = [i for i, (t, _, _) in enumerate(flat) if t == "pattern"]
    if pattern_indices:
        state.cheat_sel = max(0, min(state.cheat_sel, len(pattern_indices) - 1))
        sel_flat_idx = pattern_indices[state.cheat_sel]
        # Auto-scroll to keep selection visible
        visible_h = h - y - 3
        if sel_flat_idx < state.cheat_scroll:
            state.cheat_scroll = sel_flat_idx
        elif sel_flat_idx >= state.cheat_scroll + visible_h:
            state.cheat_scroll = sel_flat_idx - visible_h + 1

    # Draw visible rows
    visible_h = h - y - 3
    pat_counter = 0
    for i, (typ, content, attr) in enumerate(flat[state.cheat_scroll:
                                                    state.cheat_scroll + visible_h]):
        abs_i = state.cheat_scroll + i
        if y >= h - 3:
            break

        if typ == "blank":
            y += 1
            continue

        is_sel = (typ == "pattern" and
                  pattern_indices and
                  abs_i == pattern_indices[state.cheat_sel])

        if typ == "pattern":
            # attr is the tag string for patterns
            tag = attr   # repurposed field
            if is_sel:
                safe_addstr(win, y, 0, '>', curses.color_pair(C_GOOD) | curses.A_BOLD)

            # Tag badge — colored by type
            TAG_COLORS = {
                "strict":   curses.color_pair(C_GOOD),
                "loose":    curses.color_pair(C_WARN),
                "broad":    curses.color_pair(C_CYAN),
                "bare":     curses.color_pair(C_DIM),
                "both":     curses.color_pair(C_CYAN),
                "specific": curses.color_pair(C_WARN),
            }
            tag_str   = f"[{tag:<8}]" if tag else "[        ]"
            tag_color = TAG_COLORS.get(tag, curses.color_pair(C_DIM))
            safe_addstr(win, y, 2, tag_str, tag_color)

            # Pattern text
            pat_x    = 13
            pat_text = content[:w - pat_x - 1]
            pat_attr = (curses.color_pair(C_GOOD) | curses.A_BOLD if is_sel
                        else curses.color_pair(C_DIM))
            safe_addstr(win, y, pat_x, pat_text, pat_attr)
        else:
            safe_addstr(win, y, 0, content[:w - 1], attr)
        y += 1

    # Scroll indicator
    total = len(flat)
    shown = min(visible_h, total - state.cheat_scroll)
    if total > visible_h:
        safe_addstr(win, h - 3, w - 20,
                    f"[{state.cheat_scroll+1}-{state.cheat_scroll+shown}/{total}]",
                    curses.color_pair(C_DIM))

    safe_addstr(win, h - 2, 2,
                "/=filter  c=clear  UP/DN=scroll  Enter=copy to search  1=Search",
                curses.color_pair(C_DIM))


def handle_cheatsheet_key(win, key, state: AppState):
    h, w = win.getmaxyx()
    cheat = _get_cheatsheet()
    flat = []
    flt = state.cheat_filter.lower()
    cur_sec = None
    for section, sub, patterns in cheat:
        if flt:
            match = (flt in section.lower() or flt in sub.lower() or
                     any(flt in p.lower() for p, _ in patterns))
            if not match:
                continue
        if section != cur_sec:
            if cur_sec is not None:
                flat.append(("blank", "", 0))
            flat.append(("section", section, 0))
            cur_sec = section
        flat.append(("sub", sub, 0))
        for item in patterns:
            p, tag = item if isinstance(item, tuple) else (item, "")
            flat.append(("pattern", p, tag))
        flat.append(("blank", "", 0))

    pattern_indices = [i for i, (t, _, _) in enumerate(flat) if t == "pattern"]
    pattern_items  = [flat[i][1] for i in pattern_indices]

    if key == ord('/'):
        q = read_line(win, 2, 2, "/ Filter: ", state.cheat_filter)
        if q is not None:
            state.cheat_filter = q
            state.cheat_scroll = 0
            state.cheat_sel = 0

    elif key == ord('c'):
        state.cheat_filter = ""
        state.cheat_scroll = 0
        state.cheat_sel = 0

    elif key == curses.KEY_DOWN:
        if state.cheat_sel < len(pattern_indices) - 1:
            state.cheat_sel += 1
        else:
            state.cheat_scroll = min(state.cheat_scroll + 1,
                                     max(0, len(flat) - (h - 5)))

    elif key == curses.KEY_UP:
        if state.cheat_sel > 0:
            state.cheat_sel -= 1
        else:
            state.cheat_scroll = max(0, state.cheat_scroll - 1)

    elif key in (10, 13, curses.KEY_ENTER):
        # Copy selected pattern to search tab and switch to it
        if pattern_items and state.cheat_sel < len(pattern_items):
            pattern = pattern_items[state.cheat_sel].strip()
            # Clean up comment suffixes like "# strict" etc
            pattern = pattern.split('  #')[0].split(' ;')[0].strip()
            state.search_query = pattern
            state.highlight_query = ""
            state.regex_mode = True
            state.search_results = search_gadgets(
                state.gadgets, pattern,
                badchars=state.badchars,
                regex_mode=True,
                max_results=0,
            )
            state.selected_idx = 0
            state.scroll_offset = 0
            state.active_tab = 0
            state.dirty = True
            n = len(state.search_results)
            state.status_msg = (f"Cheatsheet regex: {n} results  |  "
                                f"pattern: {pattern[:50]}")


# ── Tab 6: Analysis ───────────────────────────────────────────────────────────

def _build_analysis_flat(sections, w):
    """Flatten analysis sections into display rows: (text, attr_key)"""
    from ui.tui import C_CYAN, C_GOOD, C_WARN, C_BAD, C_DIM
    rows = []
    STATUS_ATTR = {
        'ok':      C_GOOD,
        'warn':    C_WARN,
        'missing': C_BAD,
        'info':    C_CYAN,
    }
    for title, status, lines in sections:
        attr = STATUS_ATTR.get(status, C_DIM)
        rows.append((f"  {title}", attr, True))   # section header
        for line in lines:
            rows.append((line, C_DIM, False))
        rows.append(("", C_DIM, False))
    return rows


def draw_analysis_tab(win, state: AppState):
    h, w = win.getmaxyx()
    y = 2

    safe_addstr(win, y, 2, "DLL Capability Analysis", curses.color_pair(C_CYAN) | curses.A_BOLD)
    if state.gadgets:
        g_str = f"  ({len(state.gadgets):,} gadgets from {len(state.files)} file(s))"
        safe_addstr(win, y, 26, g_str, curses.color_pair(C_DIM))
    y += 1

    win.hline(y, 0, curses.ACS_HLINE, w)
    y += 1

    if not state.gadgets:
        safe_addstr(win, y + 2, 4,
                    "No gadgets loaded — load a file with L in the Search tab first",
                    curses.color_pair(C_DIM))
        safe_addstr(win, h - 2, 2,
                    "a=run analysis  L=load file",
                    curses.color_pair(C_DIM))
        return

    if not state.analysis_done:
        safe_addstr(win, y + 2, 4,
                    "Press a to run analysis  (may take a few seconds)",
                    curses.color_pair(C_WARN))
        safe_addstr(win, h - 2, 2,
                    "a=run analysis  UP/DN=scroll  c=clear",
                    curses.color_pair(C_DIM))
        return

    # Draw flat rows
    STATUS_COLORS = {
        C_CYAN:  curses.color_pair(C_CYAN)  | curses.A_BOLD,
        C_GOOD:  curses.color_pair(C_GOOD)  | curses.A_BOLD,
        C_WARN:  curses.color_pair(C_WARN)  | curses.A_BOLD,
        C_BAD:   curses.color_pair(C_BAD)   | curses.A_BOLD,
        C_DIM:   curses.color_pair(C_DIM),
    }

    visible_h = h - y - 3
    rows = state.analysis_rows
    start = state.analysis_scroll
    total = len(rows)

    for text, attr_key, is_header in rows[start:start + visible_h]:
        if y >= h - 3:
            break
        if is_header and text:
            safe_addstr(win, y, 0, text[:w - 1],
                        STATUS_COLORS.get(attr_key, curses.color_pair(C_CYAN)) )
        elif text:
            safe_addstr(win, y, 0, text[:w - 1], curses.color_pair(C_DIM))
        y += 1

    if total > visible_h:
        shown = min(visible_h, total - start)
        safe_addstr(win, h - 3, w - 22,
                    f"[{start+1}-{start+shown}/{total}]",
                    curses.color_pair(C_DIM))

    safe_addstr(win, h - 2, 2,
                "a=re-run  UP/DN=scroll  c=clear  (sections: OK=green  warn=yellow  missing=red)",
                curses.color_pair(C_DIM))


def handle_analysis_key(win, key, state: AppState):
    h, w = win.getmaxyx()

    if key == ord('a'):
        if not state.gadgets:
            state.status_msg = "No gadgets loaded — use L in Search tab first"
            return
        state.status_msg = "Running analysis... (this may take a moment)"
        state.dirty = True
        win.clear()
        draw_title_bar(win, state)
        draw_status_bar(win, state)
        safe_addstr(win, 5, 4,
                    "Analysing gadgets — scanning all register combinations...",
                    curses.color_pair(C_WARN))
        win.refresh()

        from analysis import run_analysis
        sections = run_analysis(state.gadgets, state.badchars, files=state.files)

        # Flatten for display
        rows = []
        STATUS_MAP = {'ok': C_GOOD, 'warn': C_WARN, 'missing': C_BAD, 'info': C_CYAN}
        for title, status, lines in sections:
            attr = STATUS_MAP.get(status, C_CYAN)
            rows.append((f"  {title}", attr, True))
            for line in lines:
                rows.append((line, C_DIM, False))
            rows.append(("", C_DIM, False))

        state.analysis_rows = rows
        state.analysis_scroll = 0
        state.analysis_done = True
        state.status_msg = f"Analysis complete — {len(rows)} lines  |  UP/DN to scroll"
        state.session_log.append(f"[+] Analysis complete: {len(state.gadgets):,} gadgets across {len(state.files)} file(s)")

    elif key == ord('c'):
        state.analysis_done = False
        state.analysis_rows = []
        state.analysis_scroll = 0
        state.status_msg = "Analysis cleared"

    elif key == curses.KEY_DOWN:
        if state.analysis_rows:
            state.analysis_scroll = min(
                state.analysis_scroll + 1,
                max(0, len(state.analysis_rows) - (h - 8)))

    elif key == curses.KEY_UP:
        state.analysis_scroll = max(0, state.analysis_scroll - 1)

    elif key == ord('L'):
        path = read_line(win, h - 3, 2, "Load rp++ file: ")
        if path:
            path = path.strip()
            if os.path.exists(path):
                new_g = parse_rpp_file(path)
                state.gadgets.extend(new_g)
                state.files.append(path)
                state.analysis_done = False  # invalidate old analysis
                state.status_msg = (f"Loaded {len(new_g):,} gadgets — press a to re-run analysis")
            else:
                state.status_msg = f"File not found: {path}"
                state.session_log.append(f"[!] Gadget file not found: {path}")


# ── Help popup ─────────────────────────────────────────────────────────────────

def draw_help(win):
    h, w = win.getmaxyx()
    lines = [
        "",
        "  ChainForge  --  Keyboard Reference",
        "",
        "  Global",
        "    1-6               switch tabs",
        "    ?                 this help screen",
        "    q                 quit  (asks for confirmation)",
        "",
        "  Analysis tab  [1]",
        "    a     run full capability analysis  (takes a few seconds)",
        "    c     clear results",
        "    UP/DN scroll the report",
        "",
        "  Search tab  [2]",
        "    /     new plain text search  (starts empty)",
        "    x     new regex search  (starts empty, r/R also work)",
        "    n     refine  (pre-fills last query to edit and re-run)",
        "    UP/DN  navigate results",
        "    Enter  add selected gadget to chain",
        "    a      add all current results to chain",
        "    L      load rp++ output file",
        "",
        "  Suggest tab  [3]",
        "    /     new goal  (g also works, starts empty)",
        "          e.g.: copy eax  /  copy esi to ebx  /  deref esi  /  zero edx",
        "    n     refine goal  (pre-fills last goal to edit)",
        "    c     clear goal and return to goal browser",
        "    UP/DN navigate results",
        "    Enter add selected result to chain",
        "    L     load rp++ output file",
        "",
        "  Chain tab  [4]",
        "    a     add gadget by address",
        "    p     add padding (0x42424242)",
        "    d     delete selected entry",
        "    r     regex search then pick result",
        "    e     export as Python pack() code",
        "    v     validate all addresses for bad chars",
        "    S     save chain to JSON",
        "    O     import chain from JSON  (replace or append)",
        "    N     rename chain",
        "    c     null-check selected entry",
        "    UP/DN navigate entries",
        "    K     move selected entry up",
        "    J     move selected entry down",
        "",
        "  Null Check tab  [5]",
        "    n     check single value",
        "    m     check multiple (space separated)",
        "    b     set bad characters",
        "",
        "  RegEx CheatSheet tab  [6]",
        "    /     filter by keyword or section name",
        "    c     clear filter",
        "    UP/DN navigate patterns",
        "    Enter copy selected pattern to Search and run it",
        "",
        "  All input fields",
        "    Enter confirm  |  Esc cancel  |  Left/Right move cursor",
        "    Backspace delete left  |  Del delete right",
        "",
        "  Press any key to close this help",
    ]

    box_h = min(len(lines) + 2, h - 2)
    box_w = min(80, w - 4)
    sy = max(0, (h - box_h) // 2)
    sx = max(0, (w - box_w) // 2)

    win.timeout(-1)

    try:
        popup = win.subwin(box_h, box_w, sy, sx)
    except curses.error:
        win.getch()
        return

    popup.clear()
    popup.box()
    safe_addstr(popup, 0, 2, " Help ", curses.color_pair(C_TITLE))

    section_keywords = {
        "Global", "Analysis tab", "Search tab", "Suggest tab", "Chain tab",
        "Null Check tab", "RegEx CheatSheet tab", "All input fields",
    }

    for i, line in enumerate(lines[:box_h - 2]):
        stripped = line.strip()
        if any(kw in stripped for kw in section_keywords):
            attr = curses.color_pair(C_CYAN) | curses.A_BOLD
        elif stripped and stripped[0].isalpha() and len(stripped) > 2 and stripped[1] == " ":
            attr = curses.color_pair(C_WARN)
        else:
            attr = curses.color_pair(C_DIM)
        safe_addstr(popup, i + 1, 1, line[:box_w - 2], attr)

    popup.refresh()
    win.getch()          # blocks — popup stays until a key is pressed
    popup.clear()
    popup.refresh()


# ── Main loop ──────────────────────────────────────────────────────────────────

def tui_main(stdscr, preloaded_gadgets=None, preloaded_files=None, badchars=None):
    init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)

    # No timeout — getch() blocks until a real keypress.
    # This is the core fix: previously timeout(100) caused the loop to spin
    # every 100ms, wiping popups and input prompts before the user could interact.
    stdscr.timeout(-1)

    state = AppState()
    tui_main._last_state = state   # expose for post-session log flush

    # Apply preloaded gadgets and settings from CLI args
    if preloaded_gadgets:
        state.gadgets = preloaded_gadgets
        state.files   = list(preloaded_files or [])
        files_str = ", ".join(os.path.basename(f) for f in state.files)
        state.status_msg = (f"Loaded {len(state.gadgets):,} gadgets from {files_str}  "
                            f"|  ? help  |  1-4 tabs  |  q quit")
    if badchars is not None:
        state.badchars = badchars
        state.chain.badchars = badchars

    while True:
        if state.dirty:
            stdscr.clear()
            draw_title_bar(stdscr, state)
            draw_status_bar(stdscr, state)

            if state.active_tab == 0:
                draw_search_tab(stdscr, state)
            elif state.active_tab == 1:
                draw_suggest_tab(stdscr, state)
            elif state.active_tab == 2:
                draw_chain_tab(stdscr, state)
            elif state.active_tab == 3:
                draw_nullcheck_tab(stdscr, state)
            elif state.active_tab == 4:
                draw_cheatsheet_tab(stdscr, state)
            elif state.active_tab == 5:
                draw_analysis_tab(stdscr, state)

            stdscr.refresh()
            state.dirty = False

        try:
            key = stdscr.getch()
        except KeyboardInterrupt:
            break

        if key == -1:
            continue

        state.dirty = True

        if key == ord('q'):
            # Confirm before quitting — if chain has entries, offer save option
            h, w = stdscr.getmaxyx()
            has_chain = bool(state.chain.entries)

            if has_chain:
                lines = [
                    "",
                    "  Confirm Quit",
                    "",
                    f"  Chain has {len(state.chain.entries)} unsaved entries.",
                    "",
                    "  y    quit  (chain will be lost)",
                    "  s    save chain to JSON then quit",
                    "  n    go back",
                    "",
                    "  Press any key to cancel",
                ]
            else:
                lines = [
                    "",
                    "  Confirm Quit",
                    "",
                    "  Any unsaved chain work will be lost.",
                    "",
                    "  y    quit",
                    "  n    go back",
                    "",
                    "  Press any key to cancel",
                ]

            box_w = 44
            box_h = len(lines) + 2
            sy = max(0, (h - box_h) // 2)
            sx = max(0, (w - box_w) // 2)
            try:
                popup = stdscr.subwin(box_h, box_w, sy, sx)
            except curses.error:
                break
            popup.clear()
            popup.box()
            safe_addstr(popup, 0, 2, " Quit? ", curses.color_pair(C_TITLE))
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped in ("Confirm Quit",):
                    attr = curses.color_pair(C_CYAN) | curses.A_BOLD
                elif stripped.startswith('y '):
                    attr = curses.color_pair(C_GOOD) | curses.A_BOLD
                elif stripped.startswith('s '):
                    attr = curses.color_pair(C_WARN) | curses.A_BOLD
                elif stripped.startswith('n '):
                    attr = curses.color_pair(C_BAD) | curses.A_BOLD
                else:
                    attr = curses.color_pair(C_DIM)
                safe_addstr(popup, i + 1, 1, line[:box_w - 2], attr)
            popup.refresh()
            stdscr.timeout(-1)
            confirm = stdscr.getch()
            popup.clear()
            popup.refresh()

            if confirm in (ord('y'), ord('Y')):
                break
            elif confirm in (ord('s'), ord('S')) and has_chain:
                # Save chain then quit — show a bordered filename prompt
                popup.clear()
                popup.refresh()

                save_lines = [
                    "",
                    "  Save Chain to JSON",
                    "",
                    "  Enter filename below.",
                    "  Esc to cancel.",
                    "",
                ]
                sp_w = 44
                sp_h = len(save_lines) + 4
                sp_y = max(0, (h - sp_h) // 2)
                sp_x = max(0, (w - sp_w) // 2)
                try:
                    save_popup = stdscr.subwin(sp_h, sp_w, sp_y, sp_x)
                except curses.error:
                    save_popup = None

                if save_popup:
                    save_popup.clear()
                    save_popup.box()
                    safe_addstr(save_popup, 0, 2, " Save Chain ", curses.color_pair(C_TITLE))
                    for i, line in enumerate(save_lines):
                        stripped = line.strip()
                        if "Save Chain to JSON" in stripped:
                            attr = curses.color_pair(C_CYAN) | curses.A_BOLD
                        else:
                            attr = curses.color_pair(C_DIM)
                        safe_addstr(save_popup, i + 1, 1, line[:sp_w - 2], attr)
                    save_popup.refresh()

                path = read_line(stdscr, sp_y + sp_h - 2,
                                 sp_x + 2, "File: ")

                if save_popup:
                    save_popup.clear()
                    save_popup.refresh()

                if path and path.strip():
                    try:
                        with open(path.strip(), "w") as f:
                            f.write(state.chain.to_json())
                        state.status_msg = f"Saved to {path.strip()}"
                        state.session_log.append(f"[+] Chain saved on quit: {path.strip()}  ({len(state.chain.entries)} entries)")
                        break   # saved — now quit
                    except Exception as e:
                        state.status_msg = f"Save failed: {e}"
                        state.dirty = True
                        continue
                # Empty path or Esc — cancelled, go back
            state.dirty = True
            continue
        elif key == ord('?'):
            draw_help(stdscr)
        elif key == ord('1'):
            state.active_tab = 5
            state.scroll_offset = 0
        elif key == ord('2'):
            state.active_tab = 0
            state.scroll_offset = 0
            state.selected_idx = 0
        elif key == ord('3'):
            state.active_tab = 1
            state.scroll_offset = 0
        elif key == ord('4'):
            state.active_tab = 2
            state.scroll_offset = 0
            state.selected_idx = 0
        elif key == ord('5'):
            state.active_tab = 3
            state.scroll_offset = 0
        elif key == ord('6'):
            state.active_tab = 4
            state.scroll_offset = 0
            state.cheat_scroll = 0
        elif state.active_tab == 0:
            handle_search_key(stdscr, key, state)
        elif state.active_tab == 1:
            handle_suggest_key(stdscr, key, state)
        elif state.active_tab == 2:
            handle_chain_key(stdscr, key, state)
        elif state.active_tab == 3:
            handle_nullcheck_key(stdscr, key, state)
        elif state.active_tab == 4:
            handle_cheatsheet_key(stdscr, key, state)
        elif state.active_tab == 5:
            handle_analysis_key(stdscr, key, state)


def launch_tui(args=None):
    """
    Launch the interactive TUI.
    args: list of CLI args (e.g. ['-f', 'rop.txt', '-f', 'rop2.txt'])
          If None, sys.argv[2:] is used automatically by the dispatcher.
    """
    import argparse
    parser = argparse.ArgumentParser(prog="chainforge.py tui", add_help=False)
    parser.add_argument("-f", "--file", action="append", dest="files",
                        metavar="FILE", default=[],
                        help="rp++ output file to load on startup (repeat for multiple)")
    parser.add_argument("-b", "--badchars", default="00,0a,0d",
                        metavar="HEX",
                        help="bad chars as comma-separated hex (default: 00,0a,0d)")
    parser.add_argument("-h", "--help", action="store_true")
    ns, _ = parser.parse_known_args(args if args is not None else [])

    if ns.help:
        print()
        print("  chainforge.py tui  [-f FILE ...] [-b HEX]")
        print()
        print("  -f FILE   rp++ output file to load (repeat for multiple DLLs)")
        print("  -b HEX    bad chars, comma-separated hex  (default: 00,0a,0d)")
        print()
        print("  Examples:")
        print("    python chainforge.py tui -f snfs_rop.txt")
        print("    python chainforge.py tui -f snfs_rop.txt -f ntdll_rop.txt")
        print("    python chainforge.py tui -f snfs_rop.txt -b 00,0a,0d,20")
        print()
        return

    # Parse bad chars
    try:
        badchars = bytes(int(x.strip(), 16) for x in ns.badchars.split(","))
    except ValueError:
        print(f"[!] Invalid bad chars: {ns.badchars}  (expected format: 00,0a,0d)")
        return

    # Auto-detect gadget files in the gadgets/ directory
    here = os.path.dirname(os.path.abspath(__file__))
    gadgets_dir = os.path.join(here, '..', 'gadgets')
    auto_files = []
    IGNORED = {'.gitkeep', 'gitkeep.txt'}
    if os.path.isdir(gadgets_dir):
        all_dir = os.listdir(gadgets_dir)
        auto_files = sorted(
            os.path.join(gadgets_dir, f)
            for f in all_dir
            if f.lower().endswith('.txt') and f not in IGNORED
        )
        # Warn about any files that are not .txt and not intentionally ignored
        skipped = [f for f in all_dir if not f.lower().endswith('.txt') and f not in IGNORED]
        for f in sorted(skipped):
            print(f"[*] gadgets/ skipped (not a .txt file): {f}")

    # Merge auto-detected and explicitly passed files, preserving order, no duplicates
    seen = set()
    all_files = []
    for path in auto_files + list(ns.files):
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            all_files.append(path)

    if auto_files:
        print(f"[*] gadgets/ directory: {len(auto_files)} file(s) found")

    # Pre-load gadget files before entering curses
    preloaded = []
    loaded_paths = []
    for path in all_files:
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            continue
        g = parse_rpp_file(path)
        preloaded.extend(g)
        loaded_paths.append(path)
        source = "(auto)" if os.path.realpath(path) in {os.path.realpath(f) for f in auto_files} else "(-f)"
        print(f"[+] {source} Loaded {len(g):,} gadgets from {os.path.basename(path)}")

    bc_str = ', '.join(hex(b) for b in badchars)
    print(f"[*] Bad chars: {bc_str}")
    if preloaded:
        print(f"[+] Total: {len(preloaded):,} gadgets ready")
    elif not all_files:
        print(f"[*] No gadget files loaded — drop .txt files in gadgets/ or pass -f")

    try:
        curses.wrapper(tui_main, preloaded, loaded_paths, badchars)
    except KeyboardInterrupt:
        pass
    # Flush any actions that happened inside curses (where print is suppressed)
    if hasattr(tui_main, '_last_state') and tui_main._last_state:
        log = tui_main._last_state.session_log
        if log:
            print()
            for entry in log:
                print(entry)
    print("[+] ChainForge closed.")
