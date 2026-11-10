# Detection Engineering — Xeno Executor (v1.3.65)

How to detect Xeno at every layer it touches, built from the static analysis in
`docs/FINDINGS.md` / `docs/TECHNICAL_DEEP_DIVE.md` and the decrypted payloads (`payloads/xeno_client.lua`,
`payloads/xeno_payload2.lua`). Ships with two ready tools (in `tools/`):

- **`tools/xeno_executor.yar`** — YARA pack (file + memory scanning). Validated against the sample.
- **`tools/xeno_detector.py`** — standalone score-based PE scanner (no YARA needed).
  `python tools/xeno_detector.py <file-or-dir> [-v]` → score ≥ 60 = likely Xeno, 30–59 = executor-family. Thresholds are heuristic and untested against a large benign corpus.

---

## 1. File / static layer

| Indicator | Value | Strength |
|---|---|---|
| Credit string | `Xeno is only maintained by Rizve ... rizve@xeno.onl` | Unique |
| PDB path | `C:\Users\rizve\OneDrive\Desktop\Projects\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb` | Unique |
| Export contract | `Attach, Execute, GetClients, Initialize, SetSetting, Version` (all six) | High (shared by forks) |
| Attach strings | `Intercepted translation module @{:#x}`, `Attaching in-game using translation module.` | Unique |
| XOR key (raw) | `3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB` | Unique |
| XOR key (code) | dword-store pattern `C7 00 3EFD5045 C7 40 04 ED61BFCA` (initializer @ `.text:0x3B10`) | Unique |
| Encrypted resources | PE resource type `8194`, IDs `8192`/`8196`, headers `16 48 7F B8 4D 0D 89 C8` / `16 48 7F B8 4D 95 9C CF` | Unique |
| Payload marker | `DO NOT DELETE: BELONGS TO XENO` | Unique |
| Env vars | `%XENO_CLIENT_PID%`, `%XENO_SERVER_PORT%`, `%XENO_VERSION%` | High |
| Remote URLs | `x3no.pages.dev/ep.zst.enc`, `/version.txt`, `/code.lua`; `xeno.now`; `xeno.onl` | High |
| PE anomalies | unsigned; `TimeDateStamp` later than the scan date (flagged only when actually in the future) | Weak (context only) |
| Bundled libs | Luau FFlag strings + zstd error strings + cpp-httplib/IXWebSocket RTTI in one binary | Medium |

`tools/xeno_detector.py` weights these; a fork that strips the "Xeno" branding still trips
`export_contract`, `resource_type_8194`, `xor_key`, and `luau_fflags`.

## 2. Memory layer (scanning a live process)

Load `tools/xeno_executor.yar` against process memory of the loader or any injected region:

- `Xeno_ClientLua_Payload` fires on the **decrypted** client script — the DLL must
  decrypt it in memory to use it, so the plaintext is always present in the loader
  process after `Initialize`.
- `Xeno_Server_Protocol` catches the resident strings (`/f?e=`, `/rq?c=`, `localhost:3110`).
- Watch for a process hosting a `localhost` HTTP server while also holding open
  handles to a Roblox process (`NtSuspendProcess`/`NtWriteVirtualMemory` call targets).

## 3. Behavioral layer (EDR / Sysmon)

| Behavior | Why it's suspicious |
|---|---|
| Non-Roblox process calls `NtSuspendProcess` / `NtWriteVirtualMemory` on `RobloxPlayerBeta.exe` | Core attach primitive (resolved manually from `ntdll.dll` at `Initialize`) |
| A process creates `%LOCALAPPDATA%/`-adjacent dir `Xeno/` containing `workspace`, `autoexec`, `Cache` | Fixed on-disk layout |
| Environment variables `XENO_CLIENT_PID`, `XENO_SERVER_PORT`, `XENO_VERSION` set before child start | Loader handshake |
| HTTP listener bound to `127.0.0.1` (esp. port **3110**) from an unsigned binary, serving `POST /f?e=<int>` and `POST /rq?c=..&h=..&u=..` | Xeno control plane |
| Outbound HTTPS to `x3no.pages.dev`, `xeno.now`, `xeno.onl`, or `pastebin.com/raw/A7n0vJtR` | Offsets / RCE-push / config channels |
| Roblox window manipulated by a foreign process (`SetWindowPos`, `RedrawWindow`, `DwmSetWindowAttribute` right after a suspend) | `RefreshRBXWindowV2` fallback |
| Process terminates other instances of itself (`Terminated same existing Xeno process`) | Self-mutex behavior |
| Clipboard write + `keybd_event`/`mouse_event` bursts from the loader process | Input synthesis |

## 4. In-game layer (for Roblox-side / anti-cheat detection)

The decrypted `CLIENT.LUA` exposes exactly what Xeno looks like from *inside* the game:

1. **`CoreGui` folder named after the client PID** (`%XENO_CLIENT_PID%`), with:
   - child folders `Pointer` and `Loadstring`,
   - a `Message` instance named **`DO NOT DELETE: BELONGS TO XENO`**,
   - randomly-named `ModuleScript` children (names are `math.random(1, 9999999)`), swapped frequently (the `ExecutionListener` regenerates them in a tight loop).
2. **Global pollution:** `shared.__Xeno` table; `getfenv().Xeno` on the hijacked thread.
3. **Hijacked `en-us` module:** the locale translation ModuleScript under
   `RobloxGui.Modules` has non-original bytecode. Server-side, compare the module's
   bytecode hash against the known-good en-us table (Xeno keeps a pristine copy in
   resource `8196` precisely so it *looks* right — hash comparison defeats this).
4. **Loopback HTTP from the DataModel:** `HttpService:RequestInternal` calls to
   `http://localhost:<port>/f?e=` at a steady cadence (the execute loop polls with
   `task.wait(0.001)`) — an unmistakable traffic signature. Also watch for
   `POST /ls?c=loadstring:<number>`, `/qt?p=`, `/cb`.
5. **Bytecode churn:** repeated `require()` of brand-new ModuleScripts returning
   functions — legitimate code virtually never does this in a 1 ms loop.
6. **Patched bytecode is transient (v1.3.65+):** the *BytecodePatchWatcher* thread
   auto-restores original module bytecode if a patch isn't consumed quickly, and
   originals are checksummed. Memory-scanning for foreign bytecode must catch the
   narrow patch→run/restore window; prefer the persistent signals above.
7. **Self-identifying calls:** `identifyexecutor()` returns Xeno branding; scripts that
   call it reveal the environment (honeypot opportunity).
8. **Update/RCE callbacks:** outbound fetches to `x3no.pages.dev/version.txt` and
   `code.lua` via the proxy endpoint.

## 5. Network layer

- **Loopback:** `POST /f?e=<0-21>` with JSON body `{"c":..., "p":...}`; `POST /rq?c=<methodId>&h=<b64>&u=<b64>`; `POST /ls?c=<moduleName>&p=<pid>` (compile); `POST /qt?p=<pid>` (teleport queue); `POST /cb` (clipboard). All are path-shaped enough for a localhost-inspecting proxy/EDR rule.
- **Outbound:** `GET https://x3no.pages.dev/{version.txt,code.lua,ep.zst.enc}` — the `ep.zst.enc` blob is XOR-encrypted with the same 32-byte key pattern (`.zst.enc` naming) and can be scanned after download with the `Xeno_ResourceXorKey` logic.
- **Headers added by the proxy:** `roblox-place-id`, `roblox-game-id`, `roblox-session-id` on non-Roblox HTTP traffic.

## 6. YARA rule map

| Rule | Layer | Fires on |
|---|---|---|
| `Xeno_Executor_DLL_HighConf` | file/memory | unique Xeno strings + PDB path |
| `Xeno_ResourceXorKey` | file/memory | key bytes or the initializer code pattern |
| `Xeno_EncryptedResource` | file | the two encrypted resource headers |
| `Xeno_ClientLua_Payload` | memory/disk | decrypted CLIENT.LUA artifacts |
| `Xeno_Server_Protocol` | memory/pcap | loopback protocol strings, port 3110 |
| `Executor_API_Generic` | file | the six-export executor contract (catches forks) |

Validated results on this sample: `sample/TEST.dll` → 4 rules fire; `payloads/xeno_client.lua` → 2 rules fire.
