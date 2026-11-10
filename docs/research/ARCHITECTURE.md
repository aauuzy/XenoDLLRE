# Architecture — Xeno v1.3.65

How Xeno's components fit together, reconstructed from static analysis of the DLL and the decrypted client script. Finding IDs (`F-xx`) refer to [`FINDINGS.md`](FINDINGS.md), which holds the evidence and confidence for each claim. RVAs are relative to image base `0x180000000`. Disassembly excerpts are as observed; C++ blocks marked *reconstruction* are readable approximations, not recovered source.

---

## 1. Components

```
┌──────────────┐  exports (F-10, F-55)          ┌───────────────────────────────┐
│  Xeno UI     │ ─────────────────────────────► │ Xeno.dll (native core)        │
│  (Electron)  │                                │  • offsets fetch (curl)       │
└──────────────┘                                │  • Luau compiler              │
                                                │  • localhost HTTP/WS server   │
                                                │  • cross-process memory I/O   │
                                                │  • Discord RPC (discord-ipc)  │
                                                └──────┬──────────────▲─────────┘
                                   bytecode writes     │              │ POST /f /ls /rq /qt /cb
                     (VirtualAllocEx +                 ▼              │ (HttpService:RequestInternal)
                      WriteProcessMemory, F-31)
                                                ┌───────────────────────────────┐
                                                │ RobloxPlayerBeta.exe          │
                                                │  en-us module → CLIENT.LUA    │
                                                │  CoreGui/<pid>/... container  │
                                                └───────────────────────────────┘
                                                               │ HTTPS
                                                               ▼
                 pastebin (primary offsets); x3no.pages.dev: ep.zst.enc, code.lua, version.txt
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

Entry point `0x199A60` is the standard MSVC CRT DLL startup. No packing (F-03). The file is signed with a self-signed certificate and timestamped (F-04).

The disassembly excerpts below were re-checked against the sample on 2026-11-10 and match at every stated address.

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
lea  rcx, [rip+0x893C2]            ; g_clientsMutex (0x216810)
call qword [rip+0x1E194]           ; MSVCP140!_Mtx_lock
test eax, eax
jne  <throw>
mov  eax, dword [rip+0x893FA]      ; mutex count field (0x21685C)
cmp  eax, 0x7FFFFFFF               ; std::mutex::lock's recursion check
je   <throw>
mov  rbx, qword [rip+0xC4EF4]      ; client vector begin (shared_ptr, stride 0x10)
mov  rdi, qword [rip+0xC4EF5]      ; client vector end
mov  rcx, qword [rbx]              ; client
cmp  dword [rcx + 0x2D0], esi      ; client->pid == pid ?
jne  <next>
mov  rcx, qword [rcx]              ; client->hProcess (+0x00)
lea  rdx, [rsp+0x50]
call qword [rip+0x1DE2F]           ; KERNEL32!GetExitCodeProcess
cmp  dword [rsp+0x50], 0x103       ; STILL_ACTIVE ?
...
lea  r8, [rip+0xFD0]               ; thread procedure 0x18E540
call qword [rip+0x1E63E]           ; _beginthreadex({client, ctrl, script})
call qword [rip+0x1E040]           ; _Thrd_detach
```

*Reconstruction* (F-13, F-14):

```cpp
void Execute(const char* script, const int* pids, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        std::shared_ptr<RBXClient> target;
        {
            std::lock_guard lock(g_clientsMutex);
            for (auto& c : g_clients)
                if (c->pid == pids[i] && IsAlive(c->hProcess))   // +0x2D0, +0x00
                    { target = c; break; }
        }
        if (target)
            std::thread([target, script] { CompileWriteVerify(target, script); }).detach();
            // thread procedure 0x18E540 -> 0x117980 (F-41)
    }
}
```

### 3.4 `GetClients` — 0x18D610

Acquires a lazily initialized SRW lock, walks the client vector, and skips objects whose `+0x2C0` field is null (F-15). The output format was not traced.

### 3.5 `SetSetting` — 0x18D950

`switch (id)`: `1` toggles Discord Rich Presence and logs `"RPC is Enabled"` / `"RPC was disabled"`; `0` jumps to `0x18DD10`, which only stores `value != 0` in a byte flag:

```asm
0x18DD10: test  edx, edx
          setne byte [rip+0xC4290]   ; g_setting0 (0x251FA9)
          jmp   <epilogue>
```

The flag's only reader is the background loop at `0x18C910`, which terminates other Xeno processes and then calls the internal attach routine every 200 ms with `!g_setting0` (F-17, F-84):

```asm
0x18CA50: cmp  byte [rip+0xC5552], 0  ; g_setting0
          je   0x18CA75               ; -> mov cl, 1
          xor  ecx, ecx               ; cl = 0
0x18CA5B: call 0x18C040               ; internal attach routine (same target as the Attach export)
          ...                         ; sleep 200 ms (0xC8)
          jmp  0x18CA50
```

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

These are ordinary calls through `ntdll` exports, not direct system calls. In v1.3.65 none of the six stored pointers (`.data` `0x251FC0`–`0x251FE8`) is referenced outside `Initialize`; all cross-process memory access uses the imported Win32 functions (F-31, F-86). v1.3.40 called `NtSuspendProcess` and `NtResumeProcess` from its attach function (F-99), so the resolution looks like a leftover. The remainder of `Initialize` (directory setup, cache load, server start) is inferred from log strings, not traced.

## 4. Attach

The main attach routine is `0x1124B0`; `0x14D360` is a reduced copy used to reattach after `PlayerRemoving`. Steps are ordered by the routine's log strings and cross-references (F-30–F-36). Steps marked † are inferred.

1. A background loop (`0x18C910`) terminates other Xeno instances, then calls the client-scan routine `0x18C040` (the `Attach` export's target) every 200 ms (F-17, F-84). It enumerates processes (`CreateToolhelp32Snapshot`, via `0x18B380`) and, for a new Roblox PID, starts `0x18B850` (`"Creating new RBXClient: {}"`), reusing cached PIDs.
2. `0x111C30` opens the process with `PROCESS_ALL_ACCESS`, inheritable, and refuses elevated targets when not elevated (F-32). It then starts a thread (`0x11D7A0`) that runs the per-client attach routine `0x1124B0`.
3. Fetch the RBXClient (offsets) data: pastebin first, `ep.zst.enc` second (F-33, F-34).
4. Wait for the client window and the DataModel, then `LocalPlayer` and `CoreGui`. The log strings show a cached or scanned render-view address, a string-address lookup and an instruction-candidate search. Start the Bytecode Patch Watcher thread (F-45).
5. Locate `RobloxGui → Modules → … → Locales → en-us` (`"Could not find RobloxGui->Modules..."`, `"Could not find en-us locale module..."`).
6. Write into the Roblox process: allocate with `VirtualAllocEx` and write with `WriteProcessMemory` (helper `0x10D6B0`), write again, log `"Intercepted translation module @{:#x}"`, write once more (F-31). The process is not suspended. † What each write contains (compiled `CLIENT.LUA`, the module's bytecode pointer) is inferred from the client side, not traced.
7. Roblox runs the module. `CLIENT.LUA` recognises the en-us context (`P:396`), builds its container, and calls `Activate` (op 0) until the DLL answers. The DLL logs `"Attach ping received..."` (`0x14CF80`).
8. If no ping arrives, call the window-refresh routine `0x111490` (`"...Using RefreshRBXWindowV2..."`), then `"...Attempting to restart current thread..."` (F-35, F-36).
9. On `PlayerRemoving` for the local player, the client sends op 19 and `0x14D360` reattaches after the next place loads; if its ping also fails it logs `"...Treating this as failed."`.

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

The key pointers are zero in the file and filled by a CRT dynamic initializer at `0x3B10`, which allocates 32 bytes and stores eight immediates (the `mov dword [rax], imm32` sequence begins at `0x3B30`):

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

Roblox ships frequently, so Xeno does not hard-code internal offsets. At the start of each attach the DLL downloads zstd-compressed RBXClient data from `https://pastebin.com/raw/A7n0vJtR` (primary; the request is made with timeouts of 2 s and 8 s and needs HTTP 2xx), falling back to `https://x3no.pages.dev/ep.zst.enc` if that request fails or the data does not decompress. Entries are keyed by Roblox version; one version can alias another's offsets, and unknown versions fall back to a default with a warning (F-33, F-34). Neither URL was fetched for this research.

The client separately fetches `version.txt` (update notice) and `code.lua`, which it runs with the full Xeno environment on every attach (F-63).

## 8. Script environment

The client builds a `Xeno` table of roughly 160 functions in the common "UNC" style (`getgenv`, `hookfunction`, `getscriptbytecode`, `request`, file I/O, `Drawing`, input synthesis, and so on). Not all are functional: the header says some are fake (F-48), and identity functions only store a number (F-47). Before exposing any of this, the client wraps a list of Roblox services so that selected methods raise `"Attempt to call a blocked function"` (F-90; `P:441-577`).

## 9. Cache

One binary file in the Xeno directory holds client PIDs, compiled bytecode, flags and client info, plus queued teleport scripts. A bad header is non-fatal (`"No valid cache found (Starting new fresh cache)"`).

## 10. Technique mapping

Mapped conservatively; Xeno is software the user installs and runs on purpose, so these describe mechanisms, not an intrusion.

| ATT&CK technique | Mechanism |
|---|---|
| T1055 Process Injection | `VirtualAllocEx` + `WriteProcessMemory` of compiled Luau bytecode into the Roblox process; no remote thread |
| T1106 Native API | `Nt*` functions resolved from `ntdll`; only v1.3.40 calls any of them (`NtSuspendProcess`/`NtResumeProcess`) |
| T1027 / T1140 Obfuscated files; Deobfuscate/Decode | XOR+zstd resources; `ep.zst.enc` |
| T1105 Ingress Tool Transfer | Runtime download of offsets and `code.lua` |
| T1057 Process Discovery | Process and window enumeration to find Roblox clients |
| T1082 System Information Discovery | Hardware identifier returned to the client |
