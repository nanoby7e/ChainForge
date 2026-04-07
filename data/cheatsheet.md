# ROP Gadget Cheatsheet

> **Usage**: Copy regex patterns into VS Code search (`Ctrl+F` → enable `.*` regex mode).
>
> **Two pattern tiers provided for every operation:**
> - **Strict** — instructions must be adjacent (no instructions in between)
> - **Loose** — allows any instructions between key operations — catches gadgets with side effects in between
>
> Always search loose first to see everything available, then evaluate side effects manually.

---

## Table of Contents

- [Registers Quick Reference](#registers-quick-reference)
- [Pattern Tier Explained](#pattern-tier-explained)
- [MOV — Direct Copy](#mov--direct-copy)
- [LEA — Address Arithmetic](#lea--address-arithmetic)
- [PUSH / POP — Stack Relay](#push--pop--stack-relay)
- [XCHG — Exchange](#xchg--exchange)
- [Arithmetic — ADD / SUB / INC / DEC / NEG](#arithmetic--add--sub--inc--dec--neg)
- [Logic — XOR / OR / AND](#logic--xor--or--and)
- [Memory Read — Dereference](#memory-read--dereference)
- [Memory Write — Store](#memory-write--store)
- [String Instructions — STOSD / LODSD](#string-instructions--stosd--lodsd)
- [Stack Pivot](#stack-pivot)
- [Null-Byte Avoidance](#null-byte-avoidance)
- [Multi-Step / Second Order Operations](#multi-step--second-order-operations)
- [Shorthand / Single-Instruction Gadgets](#shorthand--single-instruction-gadgets)
- [retn Cleanup Values](#retn-cleanup-values)
- [Raw Byte Search](#raw-byte-search-misaligned-gadgets)

---

## Registers Quick Reference

| Register | Common Role in ROP |
|---|---|
| `eax` | Return value, general arithmetic, dereference target |
| `ebx` | Argument register (int 0x80), general storage |
| `ecx` | Counter, argument register, general storage |
| `edx` | Data register, argument register |
| `esi` | Source index, IAT pointer storage |
| `edi` | Destination index, stosd target |
| `ebp` | Base pointer, relay register, stack reference |
| `esp` | Stack pointer — modify with extreme caution |
| `eip` | Instruction pointer — only controlled via ret/jmp/call |

---

## Pattern Tier Explained

rp++ gadgets commonly include extra instructions between the ones you care about. For example:

```
0x10023ace: mov eax, esi ; pop esi ; ret
0x10017b63: mov dword [esi], ecx ; pop esi ; ret
0x1001b9bd: mov eax, ebx ; pop edi ; pop ebx ; ret
```

If you only search `push\s+eax\s*;\s*pop\s+ebx` you miss gadgets like:
```
push eax ; pop ecx ; pop esi ; pop edi ; pop ebx ; ret
```

**Loose pattern** uses `.*` to allow anything in between:
```
push\s+eax.*pop\s+ebx.*ret
```

This catches gadgets with pops, nops, or other instructions between your key operations. Always check what those extra instructions do — each `pop` consumes a stack slot requiring a padding DWORD in your chain.

---

## MOV — Direct Copy

Copies value of one register directly into another. Never accesses memory.

### Any register to any register
```
; Strict
mov\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### EAX to any register
```
; Strict
mov\s+e[a-z]{2},\s*eax\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*eax.*ret
```

### Any register to EAX
```
; Strict
mov\s+eax,\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+eax,\s*e[a-z]{2}.*ret
```

### ESI to any register
```
; Strict
mov\s+e[a-z]{2},\s*esi\s*;.*ret

; Loose — catches: mov eax, esi ; pop esi ; ret
mov\s+e[a-z]{2},\s*esi.*ret
```

### ECX to any register
```
; Strict
mov\s+e[a-z]{2},\s*ecx\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*ecx.*ret
```

### EBP to any register
```
; Strict
mov\s+e[a-z]{2},\s*ebp\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*ebp.*ret
```

### Any register to EBP
```
; Strict
mov\s+ebp,\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+ebp,\s*e[a-z]{2}.*ret
```

**Notes:**
- Cleanest gadget type — no side effects on the move itself
- Extra `pop` instructions in loose results consume stack slots — add one padding DWORD per extra pop
- `eip` is never a valid MOV destination — control EIP only via `ret`/`jmp`/`call`

---

## LEA — Address Arithmetic

Computes an address and stores result in a register. **Never accesses memory** — brackets are misleading.

### Simple register copy
```
; Strict
lea\s+e[a-z]{2},\s*\[e[a-z]{2}\]\s*;.*ret

; Loose
lea\s+e[a-z]{2},\s*\[e[a-z]{2}\].*ret
```

### With numeric offset
```
; Strict
lea\s+e[a-z]{2},\s*\[e[a-z]{2}[\s\+\-\dx]*\]\s*;.*ret

; Loose
lea\s+e[a-z]{2},\s*\[e[a-z]{2}[\s\+\-\dx]*\].*ret
```
Matches: `lea eax, [ebx+4]` / `lea eax, [ebx+0x1C]` / `lea eax, [ebx-8]`

### Two register addition
```
; Strict
lea\s+e[a-z]{2},\s*\[e[a-z]{2}\+e[a-z]{2}\]\s*;.*ret

; Loose
lea\s+e[a-z]{2},\s*\[e[a-z]{2}\+e[a-z]{2}\].*ret
```

### Specifically from EAX
```
; Strict
lea\s+e[a-z]{2},\s*\[eax[^\]]*\]\s*;.*ret

; Loose
lea\s+e[a-z]{2},\s*\[eax[^\]]*\].*ret
```

### From ESP (capture stack pointer)
```
; Strict
lea\s+e[a-z]{2},\s*\[esp[^\]]*\]\s*;.*ret

; Loose
lea\s+e[a-z]{2},\s*\[esp[^\]]*\].*ret
```

**Key difference from MOV:**

| Instruction | Memory access? | Effect |
|---|---|---|
| `mov eax, [esi]` | YES — reads from RAM | `eax = value at address esi` |
| `lea eax, [esi]` | NO | `eax = esi` (just copies the address) |
| `lea eax, [esi+4]` | NO | `eax = esi + 4` |

---

## PUSH / POP — Stack Relay

Copies via the stack. **Push must always come before pop** in the same gadget.

> Loose patterns are especially important here — rp++ very commonly produces gadgets with multiple pops between the push and the destination pop. Each extra `pop` consumes one stack slot requiring a padding DWORD.

### Any source to any destination
```
; Strict — adjacent only
push\s+e[a-z]{2}\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose — anything in between
push\s+e[a-z]{2}.*pop\s+e[a-z]{2}.*ret
```

### EAX to any register
```
; Strict
push\s+eax\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose
push\s+eax.*pop\s+e[a-z]{2}.*ret
```

### ESI to any register
```
; Strict
push\s+esi\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose
push\s+esi.*pop\s+e[a-z]{2}.*ret
```

### ECX to any register
```
; Strict
push\s+ecx\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose
push\s+ecx.*pop\s+e[a-z]{2}.*ret
```

### EBX to any register
```
; Strict
push\s+ebx\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose
push\s+ebx.*pop\s+e[a-z]{2}.*ret
```

### ESP to any register (capture stack pointer)
```
; Strict
push\s+esp\s*;\s*pop\s+e[a-z]{2}\s*;.*ret

; Loose
push\s+esp.*pop\s+e[a-z]{2}.*ret
```

### Specific source to specific destination — loose only
```
push\s+eax.*pop\s+ebx.*ret
push\s+eax.*pop\s+ecx.*ret
push\s+eax.*pop\s+edx.*ret
push\s+eax.*pop\s+esi.*ret
push\s+eax.*pop\s+edi.*ret

push\s+esi.*pop\s+eax.*ret
push\s+esi.*pop\s+ebx.*ret
push\s+esi.*pop\s+edi.*ret

push\s+esp.*pop\s+eax.*ret
push\s+esp.*pop\s+ebx.*ret
push\s+esp.*pop\s+ecx.*ret
```

**Critical rule:**
```
CORRECT:   push eax ; pop ebx ; ret        -> ebx = eax
WRONG:     pop ebx ; push eax ; ret        -> ret jumps to eax value (crash)
```

**Counting stack slots consumed by loose gadgets:**
```
push eax ; pop ecx ; pop esi ; pop edi ; pop ebx ; ret

Copies EAX into ECX, but also pops 3 more values from the stack:
  pop esi  -> 1 DWORD padding required
  pop edi  -> 1 DWORD padding required
  pop ebx  -> 1 DWORD padding required (or an intentional value)

Chain layout:
  pack("<L", gadget_addr)
  pack("<L", 0x42424242)   # consumed by pop esi
  pack("<L", 0x42424242)   # consumed by pop edi
  pack("<L", 0x42424242)   # consumed by pop ebx
  pack("<L", next_gadget)
```

---

## XCHG — Exchange

Swaps two register values atomically. Destructive to both registers.

### EAX with any register — both directions
```
; Strict
xchg\s+(eax,\s*e[a-z]{2}|e[a-z]{2},\s*eax)\s*;.*ret

; Loose
xchg\s+(eax,\s*e[a-z]{2}|e[a-z]{2},\s*eax).*ret
```

### Any two registers
```
; Strict
xchg\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
xchg\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### ESP — stack pivot
```
; Strict
xchg\s+(esp,\s*e[a-z]{2}|e[a-z]{2},\s*esp)\s*;.*ret

; Loose
xchg\s+(esp,\s*e[a-z]{2}|e[a-z]{2},\s*esp).*ret
```

**Notes:**
- Both registers change — not a pure copy
- `xchg eax, esp` is the classic stack pivot
- Use when you can afford to lose the original value, or restore it afterwards

---

## Arithmetic — ADD / SUB / INC / DEC / NEG

### ADD — register to register
```
; Strict
add\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
add\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### ADD — immediate value
```
; Strict
add\s+e[a-z]{2},\s*0x[0-9a-fA-F]+\s*;.*ret

; Loose
add\s+e[a-z]{2},\s*0x[0-9a-fA-F]+.*ret
```

### ADD to EAX from any register
```
; Strict
add\s+eax,\s*e[a-z]{2}\s*;.*ret

; Loose
add\s+eax,\s*e[a-z]{2}.*ret
```

### ADD EAX and ECX in either direction
```
; Strict
add\s+e(ax|cx),\s*e(cx|ax)\s*;.*ret

; Loose
add\s+e(ax|cx),\s*e(cx|ax).*ret
```

### SUB — register to register
```
; Strict
sub\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
sub\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### SUB — immediate value
```
; Strict
sub\s+e[a-z]{2},\s*0x[0-9a-fA-F]+\s*;.*ret

; Loose
sub\s+e[a-z]{2},\s*0x[0-9a-fA-F]+.*ret
```

### SUB — null-free negative immediate (high byte = FF)
```
; Strict
sub\s+e[a-z]{2},\s*0x[fF][fF][fF][fF][0-9a-fA-F]{2}\s*;.*ret

; Loose
sub\s+e[a-z]{2},\s*0x[fF][fF][fF][fF][0-9a-fA-F]{2}.*ret
```

### INC / DEC
```
; Strict
(inc|dec)\s+e[a-z]{2}\s*;.*ret

; Loose
(inc|dec)\s+e[a-z]{2}.*ret
```

### NEG
```
; Strict
neg\s+e[a-z]{2}\s*;.*ret

; Loose
neg\s+e[a-z]{2}.*ret
```

---

## Logic — XOR / OR / AND

### XOR — zero a register (same reg both sides)
```
; Strict
xor\s+(e[a-z]{2}),\s*\1\s*;.*ret

; Loose
xor\s+(e[a-z]{2}),\s*\1.*ret
```
Example: `xor eax, eax` → `eax = 0`. No null bytes. Essential setup for OR copy.

### XOR — two different registers
```
; Strict
xor\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
xor\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### OR — any register from EAX (excluding eax,eax)
```
; Strict
or\s+(?!eax,\s*eax)e[a-z]{2},\s*eax\s*;.*ret

; Loose
or\s+(?!eax,\s*eax)e[a-z]{2},\s*eax.*ret
```

### OR — any two registers both directions
```
; Strict
or\s+(eax,\s*e[a-z]{2}|e[a-z]{2},\s*eax)\s*;.*ret

; Loose
or\s+(eax,\s*e[a-z]{2}|e[a-z]{2},\s*eax).*ret
```

### AND — any two registers
```
; Strict
and\s+e[a-z]{2},\s*e[a-z]{2}\s*;.*ret

; Loose
and\s+e[a-z]{2},\s*e[a-z]{2}.*ret
```

### Zero then OR copy — single gadget
```
; Strict — xor and or must be adjacent
xor\s+(e[a-z]{2}),\s*\1\s*;\s*or\s+e[a-z]{2},\s*eax\s*;.*ret

; Loose — allows instructions between xor and or
xor\s+(e[a-z]{2}),\s*\1.*or\s+e[a-z]{2},\s*eax.*ret
```

**OR copy pattern:**
```asm
xor ebx, ebx    ; ebx = 0
or  ebx, eax    ; ebx = 0 | eax = eax   (clean copy, no null bytes)
```
Only works cleanly when destination is zero first — otherwise bits merge.

---

## Memory Read — Dereference

Reads value stored at a memory address into a register.

### Dereference any register into any register
```
; Strict
mov\s+e[a-z]{2},\s*(dword\s*)?\[e[a-z]{2}[^\]]*\]\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*(dword\s*)?\[e[a-z]{2}[^\]]*\].*ret
```

### Dereference into EAX specifically
```
; Strict
mov\s+eax,\s*(dword\s*)?\[e[a-z]{2}[^\]]*\]\s*;.*ret

; Loose
mov\s+eax,\s*(dword\s*)?\[e[a-z]{2}[^\]]*\].*ret
```

### Dereference EAX into EAX (double dereference)
```
; Strict
mov\s+eax,\s*(dword\s*)?\[eax\]\s*;.*ret

; Loose
mov\s+eax,\s*(dword\s*)?\[eax\].*ret
```

### Dereference ESI
```
; Strict
mov\s+e[a-z]{2},\s*(dword\s*)?\[esi[^\]]*\]\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*(dword\s*)?\[esi[^\]]*\].*ret
```

### Dereference EBP
```
; Strict
mov\s+e[a-z]{2},\s*(dword\s*)?\[ebp[^\]]*\]\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*(dword\s*)?\[ebp[^\]]*\].*ret
```

### Dereference ECX
```
; Strict
mov\s+e[a-z]{2},\s*(dword\s*)?\[ecx[^\]]*\]\s*;.*ret

; Loose
mov\s+e[a-z]{2},\s*(dword\s*)?\[ecx[^\]]*\].*ret
```

### Broadest — everything that reads from memory
```
; Loose
mov\s+e[a-z]{2},\s*(dword\s*)?\[e[a-z]{2}[^\]]*\].*ret
```

---

## Memory Write — Store

Writes register value to a memory address. Destination must be writable.

### Write any register to any memory location
```
; Strict
mov\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*e[a-z]{2}.*ret
```

### Write EAX to any memory location
```
; Strict
mov\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*eax\s*;.*ret

; Loose
mov\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*eax.*ret
```

### Write to [ESI]
```
; Strict
mov\s+(dword\s*)?\[esi[^\]]*\],\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+(dword\s*)?\[esi[^\]]*\],\s*e[a-z]{2}.*ret
```

### Write EAX to [ESI]
```
; Strict
mov\s+(dword\s*)?\[esi[^\]]*\],\s*eax\s*;.*ret

; Loose
mov\s+(dword\s*)?\[esi[^\]]*\],\s*eax.*ret
```

### Write ECX to [ESI]
```
; Strict
mov\s+(dword\s*)?\[esi[^\]]*\],\s*ecx\s*;.*ret

; Loose
mov\s+(dword\s*)?\[esi[^\]]*\],\s*ecx.*ret
```

### Write to [EDI]
```
; Strict
mov\s+(dword\s*)?\[edi[^\]]*\],\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+(dword\s*)?\[edi[^\]]*\],\s*e[a-z]{2}.*ret
```

### Arithmetic write — add/or/xor to memory
```
; Strict
(add|sub|or|xor|and)\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*e[a-z]{2}\s*;.*ret

; Loose
(add|sub|or|xor|and)\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*e[a-z]{2}.*ret
```
> Only clean if destination memory is zero first — otherwise bits merge.

### Broadest — everything that writes to memory
```
; Loose
(mov|add|sub|or|xor|and)\s+(dword\s*)?\[e[a-z]{2}[^\]]*\],\s*e[a-z]{2}.*ret
```

---

## String Instructions — STOSD / LODSD

### STOSD — write EAX to [EDI]
```
; Strict
stosd\s*;.*ret

; Loose — allows instructions after stosd before ret
stosd.*ret
```
- Writes EAX to `[EDI]`, EDI advances by 4
- Requires EDI = destination address (not ESI)
- **Always use CLD before this**

### LODSD — read [ESI] into EAX
```
; Strict
lodsd\s*;.*ret

; Loose
lodsd.*ret
```
- Reads `[ESI]` into EAX, ESI advances by 4 (side effect)

### MOVSD — copy [ESI] to [EDI]
```
; Strict
movsd\s*;.*ret

; Loose
movsd.*ret
```
- Both ESI and EDI advance by 4

> **Always find a `cld` gadget before any string instruction.** If DF=1 they walk backward through memory.

---

## Stack Pivot

### xchg esp with any register
```
; Strict
xchg\s+(esp,\s*e[a-z]{2}|e[a-z]{2},\s*esp)\s*;.*ret

; Loose
xchg\s+(esp,\s*e[a-z]{2}|e[a-z]{2},\s*esp).*ret
```

### mov esp from any register
```
; Strict
mov\s+esp,\s*e[a-z]{2}\s*;.*ret

; Loose
mov\s+esp,\s*e[a-z]{2}.*ret
```

### mov esp, ebp (epilogue pivot)
```
; Strict
mov\s+esp,\s*ebp\s*;.*ret

; Loose
mov\s+esp,\s*ebp.*ret
```

### Stack adjustment — skip bytes
```
; Strict
(add|sub)\s+esp,\s*0x[0-9a-fA-F]+\s*;.*ret

; Loose
(add|sub)\s+esp,\s*0x[0-9a-fA-F]+.*ret
```

**Golden rule:** If you touch ESP, you must know exactly what is at the new ESP before the next `ret` executes.

---

## Null-Byte Avoidance

When an immediate value contains null bytes (`\x00`), subtract the negated value instead of adding.

### Conversion table

| Desired operation | Null-free equivalent |
|---|---|
| `add eax, 0x1C` | `sub eax, 0xFFFFFFE4` |
| `add eax, 0x10` | `sub eax, 0xFFFFFFF0` |
| `add eax, 0x08` | `sub eax, 0xFFFFFFF8` |
| `add eax, 0x04` | `sub eax, 0xFFFFFFFC` |
| `add eax, 0x01` | `inc eax` |

### Formula
```
null-free value = 0x100000000 - desired_offset
```

### Verify in Python
```python
import struct
struct.pack('<I', 0xFFFFFFE4).hex()   # e4ffffff — no null bytes
struct.pack('<I', 0x1C).hex()         # 1c000000 — has null bytes
```

### Null-free splits for 0x1C
```
0x0E + 0x0E = 0x1C
0x0F + 0x0D = 0x1C
0x10 + 0x0C = 0x1C
```

---

## Multi-Step / Second Order Operations

For all two-gadget combinations, search each gadget separately using loose patterns to avoid missing gadgets with side effects between key instructions.

---

### Copy EAX to target register — via zero + OR

```asm
xor ebx, ebx    ; ebx = 0
or  ebx, eax    ; ebx = eax
```
```
; Step 1 — find zero gadget
xor\s+(e[a-z]{2}),\s*\1.*ret

; Step 2 — find or gadget
or\s+e[a-z]{2},\s*eax.*ret
```

### Copy EAX to target register — via zero + ADD

```asm
xor ebx, ebx    ; ebx = 0
add ebx, eax    ; ebx = eax
```
```
; Step 1
xor\s+(e[a-z]{2}),\s*\1.*ret

; Step 2
add\s+e[a-z]{2},\s*eax.*ret
```

---

### Copy ESI to EAX with ESI preserved

```asm
mov eax, esi ; pop esi ; ret    ; eax = esi, pop restores esi from stack
; stack: [original ESI value]   <- consumed by pop esi
```
```
; Strict
mov\s+eax,\s*esi\s*;\s*pop\s+esi\s*;.*ret

; Loose — allows instructions between mov and pop esi
mov\s+eax,\s*esi.*pop\s+esi.*ret
```

---

### Dereference ESI when no [esi] gadget exists

```asm
mov eax, esi ; pop esi ; ret    ; copy esi to eax, restore esi from stack
; stack: [original ESI value]
mov eax, dword [eax] ; ret      ; dereference — eax = value at original esi
```
```
; Step 1
mov\s+eax,\s*esi.*pop\s+esi.*ret

; Step 2
mov\s+eax,\s*(dword\s*)?\[eax\].*ret
```

---

### Copy via EBP relay

```asm
mov ebp, eax ; ret
mov ebx, ebp ; ret
```
```
; Step 1
mov\s+ebp,\s*e[a-z]{2}.*ret

; Step 2
mov\s+e[a-z]{2},\s*ebp.*ret
```

---

### Copy via memory relay (last resort)

```asm
mov dword [esi], eax    ; write to writable address
mov ebx, dword [esi]    ; read back into different register
```
```
; Step 1
mov\s+(dword\s*)?\[e[a-z]{2}\],\s*eax.*ret

; Step 2
mov\s+e[a-z]{2},\s*(dword\s*)?\[e[a-z]{2}\].*ret
```

---

### Write EAX to [ESI] via STOSD

```asm
; Step 1 — copy ESI into EDI (any of these)
mov edi, esi
push esi ; pop edi
xchg edi, esi
lea edi, [esi]

; Step 2
stosd           ; eax -> [edi] (= original esi), edi += 4
```
```
; Step 1 — find any ESI to EDI copy (loose)
mov\s+edi,\s*esi.*ret
push\s+esi.*pop\s+edi.*ret
xchg\s+(edi,\s*esi|esi,\s*edi).*ret
lea\s+edi,\s*\[esi\].*ret

; Step 2
stosd.*ret
```

---

### Write EAX to [ESI] via OR (if [esi] is zero)

```asm
or dword [esi], eax    ; [esi] = 0 | eax = eax  (only if [esi] == 0)
```
```
; Strict
or\s+(dword\s*)?\[esi\],\s*eax\s*;.*ret

; Loose
or\s+(dword\s*)?\[esi\],\s*eax.*ret
```

---

### Capture ESP — no direct gadget

```
; In order of preference — all loose
mov\s+e[a-z]{2},\s*esp.*ret
lea\s+e[a-z]{2},\s*\[esp[^\]]*\].*ret
push\s+esp.*pop\s+e[a-z]{2}.*ret
xchg\s+(esp,\s*e[a-z]{2}|e[a-z]{2},\s*esp).*ret
```

---

### Copy ESI to EDI — STOSD setup

```
; Strict
mov\s+edi,\s*esi\s*;.*ret
push\s+esi\s*;\s*pop\s+edi\s*;.*ret
xchg\s+(edi,\s*esi|esi,\s*edi)\s*;.*ret
lea\s+edi,\s*\[esi\]\s*;.*ret

; Loose
mov\s+edi,\s*esi.*ret
push\s+esi.*pop\s+edi.*ret
xchg\s+(edi,\s*esi|esi,\s*edi).*ret
lea\s+edi,\s*\[esi\].*ret
```

---

## Shorthand / Single-Instruction Gadgets

These single-instruction gadgets are easy to overlook but frequently appear in rp++ output.

---

### Flag Instructions

| Mnemonic | Full Name | Effect | ROP Use |
|---|---|---|---|
| `CLD` | Clear Direction Flag | DF = 0 | Required before stosd/lodsd/movsd |
| `STD` | Set Direction Flag | DF = 1 | String ops move backward |
| `CLC` | Clear Carry Flag | CF = 0 | Setup for ADC gadgets |
| `STC` | Set Carry Flag | CF = 1 | Setup for ADC gadgets |
| `CMC` | Complement Carry | CF = !CF | Flip carry |
| `CLI` | Clear Interrupt Flag | IF = 0 | Kernel mode only |
| `STI` | Set Interrupt Flag | IF = 1 | Kernel mode only |
| `LAHF` | Load AH from Flags | AH = low 8 of EFLAGS | Capture flags state |
| `SAHF` | Store AH into Flags | EFLAGS = AH | Restore flags state |
| `PUSHFD` | Push EFLAGS | pushes flags onto stack | Save flags |
| `POPFD` | Pop EFLAGS | pops stack into flags | Restore flags |

> **CLD is critical** — always use a `cld` gadget before any string instruction. If DF=1 they walk backward through memory.

```
; Strict
(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd)\s*;.*ret

; Loose
(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd).*ret

; Bare — no ret
^(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd)
```

---

### Context Save / Restore

| Mnemonic | Full Name | Effect |
|---|---|---|
| `PUSHAD` | Push All Dwords | Pushes EAX ECX EDX EBX ESP EBP ESI EDI — 32 bytes |
| `POPAD` | Pop All Dwords | Pops into EDI ESI EBP (skip) EBX EDX ECX EAX |
| `PUSHA` | Push All | Same as PUSHAD in 32-bit mode |
| `POPA` | Pop All | Same as POPAD in 32-bit mode |

**PUSHAD stack layout** (top to bottom after push):
```
ESP+00  EDI
ESP+04  ESI
ESP+08  EBP
ESP+0C  ESP (original — ignored on POPAD)
ESP+10  EBX
ESP+14  EDX
ESP+18  ECX
ESP+1C  EAX
```

**POPAD is powerful** — set up 32 bytes on the stack with all register values, execute POPAD, and all 8 registers are loaded in one gadget.

```
; Strict
(pushad|popad|pusha|popa)\s*;.*ret

; Loose
(pushad|popad|pusha|popa).*ret

; Bare
^(pushad|popad|pusha|popa)
```

---

### Zero Registers Without Null Bytes

| Mnemonic | Effect | Why Useful |
|---|---|---|
| `CDQ` | Sign-extends EAX into EDX:EAX | Zeroes EDX if EAX positive — null-free |
| `CWDE` | Sign-extends AX into EAX | 16-bit to 32-bit extend |
| `CBW` | Sign-extends AL into AX | 8-bit to 16-bit extend |

**CDQ null-free zero:**
```asm
cdq     ; EDX = 0  (when EAX is positive — no immediate, no null bytes)
ret
```

```
; Strict
(cdq|cwde|cbw)\s*;.*ret

; Loose
(cdq|cwde|cbw).*ret

; Bare
^(cdq|cwde|cbw)
```

---

### Syscall / Interrupt

| Mnemonic | Effect | Context |
|---|---|---|
| `INT 0x80` | Linux 32-bit syscall | EAX = syscall number |
| `INT 0x2E` | Windows native syscall | EAX = syscall number |
| `SYSENTER` | Fast syscall entry | 32-bit |
| `SYSCALL` | 64-bit syscall | 64-bit only |

```
; Strict
int\s+0x(80|2e)\s*;.*ret
(sysenter|syscall)\s*;.*ret

; Loose
int\s+0x(80|2e).*ret
(sysenter|syscall).*ret
```

---

### NOP Variants — Padding and Alignment

| Mnemonic | Bytes | Notes |
|---|---|---|
| `NOP` | `\x90` | Single byte |
| `XCHG EAX, EAX` | `\x90` | Same encoding as NOP |
| `FNOP` | `\xD9\xD0` | FPU no-op — 2 bytes |
| `NOP DWORD [EAX]` | `\x0F\x1F\x00` | Multi-byte NOP |

```
; Strict
nop\s*;.*ret
(fnop|nop\s+dword)\s*;.*ret

; Loose
nop.*ret
fnop.*ret
```

---

### Shift and Rotate

| Mnemonic | Effect |
|---|---|
| `SHL reg, N` | reg << N (multiply by 2^N) |
| `SHR reg, N` | reg >> N unsigned |
| `SAR reg, N` | reg >> N sign-preserving |
| `ROL reg, N` | rotate left N bits |
| `ROR reg, N` | rotate right N bits |

**Null-byte encoding via shift:**
```asm
mov eax, 0x0E    ; clean value
shl eax, 1       ; eax = 0x1C  (no null bytes in either instruction)
```

```
; Strict
(shl|shr|sar|rol|ror)\s+e[a-z]{2},\s*(cl|\d+)\s*;.*ret

; Loose
(shl|shr|sar|rol|ror)\s+e[a-z]{2},\s*(cl|\d+).*ret
```

---

### Byte Manipulation

| Mnemonic | Effect |
|---|---|
| `BSWAP reg` | Reverse byte order — endian swap |
| `XLATB` | AL = [EBX + AL] — table lookup |
| `MOVSX reg, r/m8` | Sign-extend byte to dword |
| `MOVZX reg, r/m8` | Zero-extend byte to dword |

```
; Strict
bswap\s+e[a-z]{2}\s*;.*ret
(bswap|xlatb)\s*;.*ret
(movsx|movzx)\s+e[a-z]{2}.*;\s*ret

; Loose
bswap\s+e[a-z]{2}.*ret
(bswap|xlatb).*ret
(movsx|movzx)\s+e[a-z]{2}.*ret
```

---

### All Shorthands Combined

```
; Strict
(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd|pushad|popad|pusha|popa|cdq|cwde|cbw|sysenter|syscall|fnop|bswap|xlatb)\s*;.*ret

; Loose
(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd|pushad|popad|pusha|popa|cdq|cwde|cbw|sysenter|syscall|fnop|bswap|xlatb).*ret

; Bare — no ret required
^(cld|std|clc|stc|cmc|lahf|sahf|pushfd|popfd|pushad|popad|pusha|popa|cdq|cwde|cbw|sysenter|syscall|fnop|bswap|xlatb)
```

---

## retn Cleanup Values

`retn 0xN` pops extra N bytes from stack after the return address. Account for this with padding.

### Stack layout for retn 0x0002
```
ESP+00  -> gadget address        (consumed by ret — EIP jumps here)
ESP+04  -> next gadget address   (EIP jumps to this after retn)
ESP+08  -> 2 bytes padding       (consumed by retn 0x0002 cleanup)
ESP+0A  -> following gadget
```

### In Python
```python
rop += pack("<L", gadget_addr)      # gadget with retn 0x0002
rop += pack("<H", 0x9090)           # 2 bytes padding for cleanup
rop += pack("<L", next_gadget)      # resumes here
```

### Common retn values

| Instruction | Extra bytes consumed | Python padding |
|---|---|---|
| `ret` | 0 | none |
| `retn 0x0002` | 2 | `pack("<H", 0x9090)` |
| `retn 0x0004` | 4 | `pack("<L", 0x42424242)` |
| `retn 0x0008` | 8 | two `pack("<L", ...)` |
| `retn 0x000C` | 12 | three `pack("<L", ...)` |

### Find all retn gadgets
```
; Any gadget ending in retn with immediate
.*retn\s+0x[0-9a-fA-F]+

; Specific value
.*retn\s+0x0002
.*retn\s+0x0004
```

---

## Raw Byte Search (Misaligned Gadgets)

Search binary directly for byte sequences when disassemblers miss misaligned gadgets.

### Python / pwntools
```python
from pwn import *
elf = ELF('./target')

sequences = {
    'mov eax, esp ; ret':       b'\x89\xe0\xc3',
    'mov ebx, esp ; ret':       b'\x89\xe3\xc3',
    'mov ecx, esp ; ret':       b'\x89\xe1\xc3',
    'mov edx, esp ; ret':       b'\x89\xe2\xc3',
    'mov esi, esp ; ret':       b'\x89\xf4\xc3',
    'mov edi, esp ; ret':       b'\x89\xfc\xc3',
    'mov ebp, esp ; ret':       b'\x89\xe5\xc3',
    'push esp ; pop eax ; ret': b'\x54\x58\xc3',
    'push esp ; pop ebx ; ret': b'\x54\x5b\xc3',
    'push esp ; pop ecx ; ret': b'\x54\x59\xc3',
    'push esp ; pop edx ; ret': b'\x54\x5a\xc3',
    'push esp ; pop esi ; ret': b'\x54\x5e\xc3',
    'push esp ; pop edi ; ret': b'\x54\x5f\xc3',
    'push esp ; pop ebp ; ret': b'\x54\x5d\xc3',
    'xchg eax, esp ; ret':      b'\x94\xc3',
    'lea eax, [esp] ; ret':     b'\x8d\x04\x24\xc3',
    'lea eax, [esp+4] ; ret':   b'\x8d\x44\x24\x04\xc3',
    'mov eax, [eax] ; ret':     b'\x8b\x00\xc3',
    'mov eax, [esi] ; ret':     b'\x8b\x06\xc3',
    'stosd ; ret':              b'\xab\xc3',
    'lodsd ; ret':              b'\xad\xc3',
    'cld ; ret':                b'\xfc\xc3',
    'cdq ; ret':                b'\x99\xc3',
    'popad ; ret':              b'\x61\xc3',
    'pushad ; ret':             b'\x60\xc3',
}

for name, seq in sequences.items():
    for offset in elf.search(seq):
        print(f'{name}: {hex(offset)}')
```

### rp++ flags
```bash
rp-win-x86.exe -f target.dll -r 1 > rop_r1.txt  # single instruction gadgets only
rp-win-x86.exe -f target.dll -r 5 > rop_r5.txt  # up to 5 instructions (default)
rp-win-x86.exe -f target.dll -r 8 > rop_r8.txt  # deeper — more side effects to review
```

### Filter bad characters from results
```bash
grep -i "mov eax, esp" rop.txt | grep -v " 00" | grep -v " 0a" | grep -v " 0d"
```

### Grep for loose patterns at command line
```bash
# Push/pop with anything in between
grep -i "push eax" rop.txt | grep -i "pop ebx"

# Any write to [esi]
grep -i "\[esi\]," rop.txt

; Any dereference of esi
grep -i ", \[esi\]" rop.txt

# All shorthands
grep -iE "^\s*(cld|std|cdq|popad|pushad|pusha|popa|lodsd|stosd)" rop.txt

# All gadgets with side effect pops after a useful instruction
grep -i "mov eax" rop.txt | grep -i "pop"
```

---

*Reference built during x86 Windows ROP chain development targeting VirtualAlloc shellcode execution.*
