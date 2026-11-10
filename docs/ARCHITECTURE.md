# Architecture — Xeno v1.3.65

How Xeno's components fit together, reconstructed from static analysis of the DLL and the decrypted client script. Finding IDs (`F-xx`) refer to `FINDINGS.md`, which holds the evidence and confidence for each claim. RVAs are relative to image base `0x180000000`. Disassembly excerpts are as observed; C++ blocks marked *reconstruction* are readable approximations, not recovered source.

---

## 1. Components

```
┌──────────────┐  exports / named pipe (F-55)  ┌───────────────────────────────┐
│  Xeno UI     │ ─────────────────────────────► │ Xeno.dll (native core)        │
│  (Electron)  │                                │  • offsets fetch (curl)       │
└──────────────┘                                │  • Luau compiler              │
                                                │  • localhost HTTP/WS server   │
                                                │  • cross-process memory I/O   │
                                                └──────┬──────────────▲─────────┘
                                   bytecode writes     │              │ POST /f /ls /rq /qt /cb
                                   (Nt*VirtualMemory)  ▼              │ (HttpService:RequestInternal)
                                                ┌───────────────────────────────┐
                                                │ RobloxPlayerBeta.exe          │
                                                │  en-us module → CLIENT.LUA    │
                                                │  CoreGui/<pid>/... container  │
                                                └───────────────────────────────┘
                                                               │ HTTPS
                                                               ▼
                                         x3no.pages.dev: ep.zst.enc, code.lua, version.txt
```

The DLL never runs Luau inside Roblox by itself. It writes compiled bytecode into ModuleScripts that the Roblox client already executes or that the Xeno client `require()`s, and serves everything else over loopback HTTP.

## 2. Binary layout

```
.text   VA=0x1000    VS=0x1A948B   code
.rdata  VA=0x1AB000  VS=0x69004    strings, vtables, imports, Lua wrapper text
.data   VA=0x215000  VS=0x3F124    globals (client vector, server state, key pointers)
.pdata  VA=0x255000  VS=0xCE94     unwind info
.rsrc   VA=0x262000  VS=0x16440    manifest + two encrypted resources
.reloc  VA=0x279000  VS=0x15EC     relocations
```

Entry point `0x199A60` is the standard MSVC CRT DLL startup. No packing (F-03).

## 3. Exported interface

### 3.1 `Version` — 0x18D3E0

```asm
cmp   qword [rip+0x8AD70], 0xF     ; std::string capacity > 15 ?
lea   rax, [rip+0x8AD51]           ; inline buffer ("v1.3.65")
cmova rax, [rip+0x8AD49]           ; else heap pointer
ret
```

Returns `g_version.c_str()` (F-11).

### 3.2 `Attach` — 0x18D3D0

```asm
xor ecx, ecx
jmp 0x18018C040                    ; internal attach routine, argument false
```

### 3.3 `Execute` — 0x18D400

```asm
mov  r14, r8                       ; count
mov  r15, rdx                      ; PID array
mov  r12, rcx                      ; script
...
mov  esi, dword [r15 + rbp*4]      ; pid = pids[i]
lea  rcx, [rip+0x893C2]
call qword [rip+0x1E194]           ; imported helper, purpose not established
test eax, eax
jne  <skip>
mov  eax, dword [rip+0x893FA]
cmp  eax, 0x7FFFFFFF               ; sentinel check on a global
je   <abort>
mov  rbx, qword [rip+0xC4EF4]      ; client vector begin
mov  rdi, qword [rip+0xC4EF5]      ; client vector end
cmp  dword [rcx + 0x2D0], esi      ; client->pid == pid ?
...
call qword [rip+0x1DE2F]           ; virtual call with std::string(script)
```

*Reconstruction* (return value and helper semantics are inferred, F-14):

```cpp
int Execute(const char* script, const int* pids, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (helper(pids[i]) != 0) continue;
        if (g_state == INT_MAX) return /* not ready */;
        for (auto& client : g_clients)
            if (client->pid == pids[i])          // +0x2D0
                client->QueueScript(std::string(script));
    }
}
```

### 3.4 `GetClients` — 0x18D610

Acquires a lazily initialized SRW lock, walks the client vector, and skips objects whose `+0x2C0` field is null (F-15). The output format was not traced.

### 3.5 `SetSetting` — 0x18D950

`switch (id)`: `1` toggles Discord Rich Presence and logs `"RPC is Enabled"` / `"RPC was disabled"`; `0` jumps to a separate handler at `0x18DD10` that was not analyzed (F-17).

### 3.6 `Initialize` — 0x18CA80

```asm
lea  rcx, [rip+0x4F17F]   ; "ntdll.dll"
call [rip+0x1E801]        ; LoadLibraryA
...
lea  rdx, "NtUnlockVirtualMemory"  -> GetProcAddress -> global
lea  rdx, "NtLockVirtualMemory"    -> ...
lea  rdx, "NtSuspendProcess"       -> ...
lea  rdx, "NtResumeProcess"        -> ...
lea  rdx, "NtReadVirtualMemory"    -> ...
lea  rdx, "NtWriteVirtualMemory"   -> ...
```

These are ordinary calls through `ntdll` exports, not direct system calls. `NtSuspendProcess`, `NtResumeProcess` and the lock/unlock pair have no documented Win32 wrapper, which is a sufficient reason to resolve them this way. The remainder of `Initialize` (directory setup, cache load, offsets fetch, server start) is inferred from log strings, not traced.

## 4. Attach

Ordered from log strings and client code. Steps marked † are inferred.

1. Enumerate processes and create an `RBXClient` per Roblox PID (`"Creating new RBXClient: {}"`); reuse cached PIDs (`"Reattaching to cached client PID: {}"`).
2. Refuse elevated targets when not elevated (F-32).
3. Wait for the client window and the DataModel.
4. Locate `RobloxGui → Modules → en-us` (`"Could not find RobloxGui->Modules..."`). Offsets for the running Roblox version come from the downloaded RBXClient data (§7).
5. Replace the module's bytecode with compiled `CLIENT.LUA` (`"Intercepted translation module @{:#x}"`). † The write uses the resolved `NtWriteVirtualMemory`; † suspension around the write is plausible but not traced.
6. Roblox runs the module. `CLIENT.LUA` recognises the en-us context (`P:396`), builds its container, and calls `Activate` (op 0) until the DLL answers. The DLL logs `"Attach ping received..."`.
7. If no ping arrives, retry, then `"Still did not receive the success ping from client. Treating this as failed."` Whether a window-refresh step remains in v1.3.65 is unverified (F-36).
8. On `PlayerRemoving` for the local player, the client sends op 19 and the DLL reattaches after the next place loads.

**Why this target.** A ModuleScript under `RobloxGui` is loaded by Roblox's own Lua as part of normal startup, so replacing its bytecode gives Xeno a Luau thread without creating a native thread or loading a DLL into the process. Xeno also bundles Roblox's original en-us table (resource `8196`), most plausibly so that translation lookups keep working after the module is replaced; how the two are combined was not traced. *This rationale is the analyst's interpretation; the mechanism is F-30.*

## 5. Execution and protocol

### 5.1 Path A — `Execute` export

```
UI ──Execute(script, pids)──► DLL: queue per client
                              DLL: compile with embedded Luau + wrapper (F-41, F-43)
                              DLL: locate current execution module in CoreGui/<pid>
                              DLL: write bytecode, read back to verify
Roblox (CLIENT.LUA, P:4826-4872):
    loop every ~1 ms:
        ok, f = pcall(require, ExecutionModule)
        if f is a function:
            ExecutionModule:Destroy()
            setfenv(f, {getfenv, setfenv, setmetatable, error, Xeno})
            task.spawn(f)
            POST /f?e=21   (LockCustomBytecode)
            create new random-named module
```

The client sends nothing until a script has run. How the DLL identifies the current execution module (its name is random) was not traced.

### 5.2 Path B — `loadstring`

```
CLIENT.LUA (P:1994-2080):
    module = ModuleScript "loadstring:<rand>[:chunkName]" in CoreGui/<pid>/Loadstring
    POST /ls?c=<module name>&p=<pid>  body = source     -- 400 = compile error, 500 = server error
    repeat every 50 ms, up to 3 s:
        POST /f?e=20   (UnlockCustomBytecode)
        res = require(module)
        POST /f?e=21   (LockCustomBytecode)
        if res[XENO_PID] is a function: return it
```

Returning a table keyed by PID means a module compiled for one client cannot be consumed as another client's result.

### 5.3 Opcode table (`P:193-227`)

| Op | Name | Op | Name |
|---|---|---|---|
| 0 | `Activate` (returns HWID) | 11 | `LockModule` |
| 1 | `ReadFile` | 12 | `UnlockModule` |
| 2 | `GetFileType` | 13 | `GetProperties` |
| 3 | `ListFiles` | 14 | `GetInstanceRBXSignals` |
| 4 | `MakeFolder` | 15 | `GetInstanceFunctions` |
| 5 | `DelFolder` | 16 | `HookInstance` |
| 6 | `DelFile` | 17 | `SetScriptable` |
| 7 | `GetCustomAsset` | 18 | `GetInstanceAddress` |
| 8 | `GetScriptBytecode` | 19 | `PlayerRemoving` |
| 9 | `SetScriptBytecode` | 20 | `UnlockCustomBytecode` |
| 10 | `RestoreScriptBytecode` | 21 | `LockCustomBytecode` |

`WriteFile = -1` is client-side only. Commented-out code references `CBlockFunctions`, `GetQueueOnTeleport` and `GetAutoExecuteContents`, which are not in the table (version drift).

### 5.4 Other endpoints

| Endpoint | Purpose |
|---|---|
| `POST /rq?c=<method>&h=<b64 headers>&u=<b64 url>` | HTTP proxy for script `request()`, executed by libcurl in the DLL; the client adds Xeno user-agent, HWID (`exploit-guid`, `xeno-fingerprint`) and game-server headers (F-54) |
| `POST /qt?p=<pid>` | Store a `queue_on_teleport` script |
| `POST /cb` | Set the OS clipboard |

Requests from user scripts to loopback port 3110 are refused by the client (F-53).

### 5.5 Bytecode Patch Watcher (v1.3.65)

A watchdog restores a patched module's original bytecode if the client does not consume the patch in time (F-45). The log text says the purpose is preventing crashes. A side effect relevant to defenders is that foreign bytecode is only present for a short window.

## 6. Resource encryption

`LoadResource`/`SizeofResource`/`LockResource` at `0x18CD06–0x18CD7F` copy the blob into a `std::string` and call `0x1906B0`:

```asm
0x190737: mov   r8,  [rip+0xC25DA]   ; key.begin   (.data 0x252D18)
0x19073e: mov   rcx, [rip+0xC25DB]   ; key.end     (.data 0x252D20)
0x190745: sub   rcx, r8              ; key length (32)
0x19074a: mov   rax, r9
0x19074d: div   rcx                  ; rdx = i % 32
0x190750: movzx ecx, byte [r10+r9]
0x190755: xor   cl, byte [rdx+r8]
0x19075d: mov   [rax+r9], cl
```

The key pointers are zero in the file and filled by a CRT dynamic initializer at `0x3B10`, which allocates 32 bytes and stores eight immediates:

```
0x4550FD3E 0xCABF61ED 0x92A1EF57 0x966607D0 0x21F7C5FD 0x3649BD12 0x19B33F7A 0xBBF52AA9
→ 3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB
```

After XOR the routine checks for the zstd magic (`0x1908DD: cmp ecx, 0xFD2FB528`), calls `ZSTD_getFrameContentSize` and `ZSTD_decompress`, and logs `"Could not decompress a Xeno resource: {}"` on failure.

*Reconstruction:*

```cpp
std::string LoadXenoResource(int id) {
    HRSRC   h    = FindResourceW(g_module, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(8194));
    HGLOBAL g    = LoadResource(g_module, h);
    DWORD   size = SizeofResource(g_module, h);
    std::string buf(static_cast<const char*>(LockResource(g)), size);
    for (size_t i = 0; i < buf.size(); ++i)
        buf[i] ^= g_key[i % g_key.size()];
    if (memcmp(buf.data(), "\x28\xB5\x2F\xFD", 4) != 0) return {};
    std::string out(ZSTD_getFrameContentSize(buf.data(), buf.size()), '\0');
    if (ZSTD_isError(ZSTD_decompress(out.data(), out.size(), buf.data(), buf.size()))) return {};
    return out;
}
```

| Resource | Encrypted | Decrypted | Content |
|---|---|---|---|
| `8194/8192` | 27,985 B | 145,004 B | `CLIENT.LUA` |
| `8194/8196` | 62,613 B | 336,884 B | Roblox en-us translation table |

## 7. Offsets and remote content

Roblox ships frequently, so Xeno does not hard-code internal offsets. At startup the DLL downloads zstd-compressed RBXClient data, falling back to `https://x3no.pages.dev/ep.zst.enc` if the primary source fails. Entries are keyed by Roblox version; one version can alias another's offsets, and unknown versions fall back to a default with a warning (F-33). The primary source is unknown (F-34).

The client separately fetches `version.txt` (update notice) and `code.lua`, which it runs with the full Xeno environment on every attach (F-63).

## 8. Script environment

The client builds a `Xeno` table of roughly 160 functions in the common "UNC" style (`getgenv`, `hookfunction`, `getscriptbytecode`, `request`, file I/O, `Drawing`, input synthesis, and so on). Not all are functional: the header says some are fake (F-48), and identity functions only store a number (F-47). Before exposing any of this, the client wraps a list of Roblox services so that selected methods raise `"Attempt to call a blocked function"` (F-90; `P:441-577`).

## 9. Cache

One binary file in the Xeno directory holds client PIDs, compiled bytecode, flags and client info, plus queued teleport scripts. A bad header is non-fatal (`"No valid cache found (Starting new fresh cache)"`).

## 10. Technique mapping

Mapped conservatively; Xeno is software the user installs and runs on purpose, so these describe mechanisms, not an intrusion.

| ATT&CK technique | Mechanism |
|---|---|
| T1055 Process Injection | Writing compiled Luau bytecode into the Roblox process's memory |
| T1106 Native API | `Nt*` functions resolved from `ntdll` |
| T1027 / T1140 Obfuscated files; Deobfuscate/Decode | XOR+zstd resources; `ep.zst.enc` |
| T1105 Ingress Tool Transfer | Runtime download of offsets and `code.lua` |
| T1057 Process Discovery | Process and window enumeration to find Roblox clients |
| T1082 System Information Discovery | Hardware identifier returned to the client |
