# F3SecuromPAless

Fable III SecuROM PA Emulator.

Run Fable III without talking to SecuROM PA activation servers. Pair it with a GFWL emulator and a Steamworks emulator if you want a self contained copy of a title that is no longer supported. Works on the Steam build and the retail DVD build at **v1.1.1.3**.

This project does **not** generate licenses, patch `paul.dll`, or spoof `iphlpapi.dll`. It reproduces the runtime channel the game already uses, a named file mapping plus `SendMessage` IPC to a helper window.

Do not run this next to a real SecuROM helper. They will fight over the mapping name WWE (the rock) style.

---

## Why launching `Fable3.exe` alone fails

Direct start hits “use the launcher.” The exe expects a named file mapping created by the official DRM process. If `OpenFileMapping` fails, it takes the fail path.

Creating an empty mapping is enough to *boot*. It is not enough to *play*:

- Graphics get forced to low and the menu claims a pirated copy.
- Later world loads hang when a periodic check fails.

The mapping is not a boolean “DRM was here.” It holds the HWND, message id, vendor/version fields, and the path/PID of the process that owns the window. The game then `SendMessage`s that HWND for the rest of the session and hashes a buffer the helper writes back.

---

## What this tool does

1. Creates a hidden IPC window.
2. Creates the mapping `-=[SMS_Fable3.exe_SMS]=-` (`0x6C4` bytes) and fills HWND, message id, vendor string, **this process’s image path**, and this process’s PID.
3. Starts `Fable3.exe` (suspended), publishes the block, resumes it.
4. Answers `SendMessage` on `WM_APP + 0x51`. `lParam` pointers live in the **game**; the helper uses `ReadProcessMemory` / `WriteProcessMemory`.

Keep this process alive for the whole session or you'll run into SecuROM check failures.

---

## Mapping (`0x6C4`)

Unused gaps are zero.

| Offset | Field | Value | Why |
|--------|--------|--------|-----|
| `+0x00` | magic | `0x00080309` | block looks live |
| `+0x04` | HWND | helper window (low 32 bits) | `SendMessage` target |
| `+0x0C` | flag | `1` | session live |
| `+0x10` | 20 `WORD`s | `0xB100 + i` | session stamps |
| `+0x44` | `Msg` | `WM_APP + 0x51` (`0x4051`) | IPC message id |
| `+0x60` | extra | `0x008659D0`, `0x711EC211`, `0x00090308` | version-like constants |
| `+0x6C` | version | `0x0001000B` | compared on some paths |
| `+0xA8` | vendor | `"Sony DADC Austria AG"` as LE dwords | string / XOR checks |
| `+0x2A8` | wchar path | **full path of this emulator** | parent exe name check (Gypsy Camp) |
| `+0x4B4` | wchar name | `Fable3.exe` | consistency |
| `+0x6C0` | cookie | helper PID | must match parent PID |

`+0x2A8` must be the emulator path, not `Fable3.exe`. The game compares the filename there to the parent process image. If you launched the game, the parent is this tool.

---

## IPC (`SendMessageA`)

`wParam` is the request. Unknown ids return `0`.

### 2 — process id

- `lParam` unused.
- Return the PID of `Fable3.exe`.
- Pass: return value equals the game’s own PID.
- On `Albion\MistPeak_GypsyCamp` (and similar): parent PID must equal `+0x6C0`, and the parent exe name must match the filename at `+0x2A8`. Failure can load the world and then freeze follow scripts (`dword_1C86C20` tamper).

### 4 — open

- Return token `0x2000` (any non zero is enough).
- Later `7` / `9` / `10` structs carry this token.

### 9 — size

Game struct at `lParam`:

```text
+0  token
+4  zero
+8  outSize     ← write size here
```

Return `1`. Official helper used `56957` (`0xDE7D`). This tool may report the full `fableaudioex.ini` size. The next `7` uses `outSize` as `length`.

### 10 — span / lock

```text
+0  token
+4  a
+8  span
+C  b
+10 out         ← write 0
```

Return `span`. Rare (`addr % 12 == 1` or `% 10 == 1`) together with a 256 byte `7`.

### 7 — read

```text
+0  token
+4  length      // 256 on the rare call; else value from 9
+8  dest        // game malloc; already holds ReadFile(ini)
+C  outBytes    ← bytes stored
```

WPM `length` bytes to `dest`, set `outBytes`, return `1`.

- On entry, first 256 bytes of `dest` are raw `fableaudioex.ini` → hash **T1**.
- On return, first 256 bytes must hash to **T2**. This tool writes the ini, then overlays a generated 256 byte prefix.
- Return `0` → retry loop, then T2 fails.

Two call sites: the `% 12` / `% 10` one is usually skipped. The hashed `7` always follows `9`.

### 6 — close

Return `1`. The game then zeros and frees `dest`.

---

## Where checks run

World names are exact.

| World | Function | Messages | Extra |
|-------|----------|----------|--------|
| Most loads | `sub_9F4B50` | 4, 9, 7, 6 | T1 + T2 |
| `Albion\Mangroves` | `sub_6488A0` | 4, 9, (10), 7, 6 | T1 + T2 |
| `Albion\MistPeak_RenegadeCamp` | `sub_9F38A0` | same | T1 + T2 |
| `Albion\MistPeak_GypsyCamp` | `sub_9F2770` | **2** | parent path + PID cookie |
| `Albion\OldRepository` | `sub_9F31F0` | **2** | PID |
| `DemonDoors\RoadToRule`, `Albion\TheHole` | later `sub_9F4B50` | **2** | window text / parent PID |

---

## Hash (T1 and T2)

Same 256 byte function, two buffers.

```text
IV = 0x7A30DCF3
K  = 0x9A0F1C24

h ← buf[0] XOR IV
for i ← 1 to 255:
    h ← ROL32(h, 3) XOR buf[i] XOR K
```

`ROL32` is a 32-bit rotate left.

| Name | Buffer | Digest |
|------|--------|--------|
| T1 | first 256 bytes of `fableaudioex.ini` after the game’s `ReadFile` | `0xDE551B5C` |
| T2 | first 256 bytes at `dest` after `wParam` 7 | `0x68C4203A` |

Those numbers are **digests**, not IPC arguments. You cannot send `0x68C4203A`; you put bytes in `dest` that hash to it.

This is not CRC/MD5/SHA. It is a homemade 32-bit rotate XOR checksum. Each input byte only hits the low 8 bits of state; `ROL 3` lifts 3 bits. Invertible (`Unmix` = XOR then `ROR32` 3). Many 256 byte blocks share a digest.

### T2 prefix

Official SecuROM rewrites `dest` (at least the first 256 bytes; `SDFA 04 00 00 00` stays). This tool does not need a capture.

Reachable states from a fixed prefix:

```text
1 extra byte     256
2              2 048
3             16 384
4            131 072
9             ~2^32   (any digest)
```

Four free bytes are not enough. Keep ini bytes `0..246`, solve `247..255`:

1. Hash forward through byte 246.
2. BFS 5 bytes forward (`Mix`) — about 1 048 576 states.
3. BFS 4 bytes backward from `0x68C4203A` (`Unmix`) — about 131 072 states.
4. Unpack a shared state into `out[247..255]`.
5. Check `Hash256(out) == 0x68C4203A`.

On `7`: write the full ini, overlay those 256 bytes. The game’s own `ReadFile` still sees T1; after `7` it sees T2. Bytes past 256 stay the ini tail.

---

## Limits

- Official `7` wrote `56957` bytes. Only the first 256 were shown to change for the hash. If a later path consumes transformed bytes after that, overlaying 256 is not enough — the title so far only hashes 256.
- Tamper dwords in the exe can leave a world loaded and freeze scripts. A failed `wParam` 2 looks like a stuck NPC, not a DRM dialog.
- Console `[Map]` / `[IPC]` / `T1` / `T2` lines are the live log that each step ran and both digests matched.
