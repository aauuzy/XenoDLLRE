# Findings — TEST.dll (Xeno v1.3.65)

Everything discovered during static analysis of `TEST.dll`. Statements are based on direct evidence in the binary (strings, imports, disassembly); inferred items are marked *(inferred)*.

---

## 1. Identification

| Attribute | Value | Evidence |
|---|---|---|
| Product | **Xeno** (Roblox script executor) | `"Xeno Version: "`, `"https://xeno.now"`, `"Using Xeno "` |
| Version | **v1.3.65** | String returned by `Version()` export |
| Maintainer | "Rizve" — `rizve@xeno.onl`, Discord `.rizve` | Embedded credit string |
| File type | PE32+ DLL, x86-64, ~2.3 MB, 6 sections | `file`, PE headers |
| Toolchain | MSVC C++ (MSVCP140 / VCRUNTIME140), console subsystem | Import table, subsystem field |
| Packed/obfuscated | **No** — plain sections, plain strings | Section layout, readable strings |
| Code-signed | **No** (`UnknownError`, no signer) | `Get-AuthenticodeSignature` |
| Compile timestamp | **Forged** — 2026-10-20 (future) | PE `TimeDateStamp` |
| PDB path leaked | `C:\Users\rizve\OneDrive\Desktop\Projects\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb` | String |
| Manifest | `asInvoker`, `uiAccess=false` | Resource 24 |

## 2. Exported API

The DLL exposes the classic executor contract consumed by its loader/UI:

| Export | RVA | Reconstructed signature | Behavior |
|---|---|---|---|
| `Initialize` | `0x18CA80` | `bool Initialize(bool showConsole)` | Sets up console/logging, loads `ntdll.dll`, resolves six `Nt*` natives |
| `Attach` | `0x18D3D0` | `void Attach()` | Tail-call thunk → `internal_attach(false)` |
| `Execute` | `0x18D400` | `int Execute(const char* script, const int* pids, size_t count)` | Queues a script to each attached client matching the PID list |
| `GetClients` | `0x18D610` | `... GetClients()` | Walks the global client vector under a shared lock, returns attached clients |
| `SetSetting` | `0x18D950` | `void SetSetting(int id, bool value)` | `id==1` toggles Discord RPC (`"RPC is Enabled"`/`"RPC was disabled"`) |
| `Version` | `0x18D3E0` | `const char* Version()` | Returns `"v1.3.65"` |

## 3. Bundled components

Statically embedded, identified by unique strings/symbols:

- **Luau compiler & runtime glue** — dozens of `Luau*` FFlag strings (`LuauSolverV2`, `LuauCompileInlineThreshold`, `DebugLuauNoInline`, ...). The DLL compiles Luau itself rather than relying on the client.
- **zstd** — unique error-string set (`ERROR_frameType_unknown`, `ERROR_blockChecksum_invalid`, ...); used for resources and remote data.
- **cpp-httplib** — RTTI symbols `httplib::Request` / `httplib::Response`; powers the local HTTP server.
- **IXWebSocket** — `ixwebsocket::heartbeat`, Sec-WebSocket handshake strings; powers the WebSocket channels.
- **libcurl + OpenSSL 3** (`libcurl.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll`) — HTTPS downloads; Sectigo strings are curl's bundled CA store, not a signature.
- **DiscordRPC** — `"DiscordRPC"`, `"{}" requested to join`, `"SET_ACTIVITY"`.
- **fmt-style logging** — all log strings use `{}` placeholders.

## 4. Runtime architecture

- **Localhost control plane:** hosts an HTTP server on `127.0.0.1:<port>` — `"Xeno Server is Live on http://localhost:{}"`, `"Visit http://localhost:{} to view any additional information"`. The hijacked in-game module polls this server for work (scripts to run).
- **WebSockets:** client-facing WebSocket library for user scripts (`WebSocket` env function) and internal messaging; dedicated "WebSockets Cleaner" thread.
- **Threads (named in logs):** Xeno Server, WebSockets Cleaner, Xeno Caching, Client Checker.
- **Configuration via environment variables:** `%XENO_CLIENT_PID%`, `%XENO_SERVER_PORT%`, `%XENO_VERSION%` *(inferred: set by the loader before calling `Initialize`)*.
- **On-disk layout:** a "Xeno" directory containing a **workspace** folder, an **autoexec** folder, and a **cache** file; log lines: `"Workspace Directory: "`, `"Auto Execute Directory: "`, `"Directory: "`, `"Waiting for Xeno directory to be created..."`.
- **Script file recognition by suffix:** `.arscript`, `.script`, `.vbscript`, `.applescript` — any extension ending in `script` is treated as executable script content *(inferred from extension list)*.
- **Named-pipe IPC:** `WaitNamedPipeW`/`PeekNamedPipe` used for communication with the loader/UI process *(inferred)*.

## 5. Attach mechanism (core finding)

Xeno does **not** do classic DLL/shellcode injection. It hijacks Roblox's own Luau module system:

1. Enumerates processes (`CreateToolhelp32Snapshot`) and finds Roblox clients; creates an `RBXClient` object per PID (`"Creating new RBXClient: {}"`).
2. Refuses to attach if Roblox runs elevated and Xeno doesn't (`"Failed to open the Roblox client process because it is running with administrator privileges..."`).
3. Waits for the Roblox window (`"Waiting for Client Window"`, `"Timeout ({}s) exceeded while waiting for window"`).
4. Locates `RobloxGui -> Modules`, specifically the **en-us locale translation ModuleScript** (`"Could not find en-us locale translation module. Going back to in-game check..."`).
5. **Intercepts/replaces that module's bytecode** (`"Intercepted translation module @{:#x}"`, `UnlockModule`/`LockModule`, `SetBytecode`/`SetScriptBytecode`) using cross-process memory access — including direct `NtSuspendProcess`/`NtReadVirtualMemory`/`NtWriteVirtualMemory` on the Roblox process.
6. The injected module runs inside the game's Luau VM, phones home to the localhost server, and confirms with `"Attach ping received from client "{}""`.
7. Fallbacks: if the menu-stage attach fails or is slow, it attaches **in-game** (`"Attaching in-game using translation module."`, `"Attach is taking longer than expected... (I hate you {})"`); if the success ping never arrives it forces a window refresh (`"Did not receive the success ping from client. Using RefreshRBXWindowV2..."` — hence all the `USER32` window-manipulation imports), then restarts the thread, then gives up.
8. **Re-attach on teleport:** `"[::PlayerRemoving]: Player leaving ping recieved. We have to reattach."` plus `QueueOnTeleport` script restoration.

### Version resilience — remote offsets

Roblox updates break hardcoded offsets, so Xeno downloads them:

- `"Attempting to retrieve RBXClient data..."` → primary endpoint (embedded) → fallback **secondary endpoint: `https://x3no.pages.dev/ep.zst.enc`**.
- Data is **zstd-compressed** (`"RBXClient data resource decompression failed... Using secondary endpoint"`), parsed, and applied per Roblox version: `"Offsets for version "{}" not found. Using offsets from default version: {}"`, with alias chaining (`"Offsets for version "{}" points to "{}""`).

## 6. Script environment

- `Loadstring` wraps every user script in the `Xeno` environment; the wrapper source is embedded **verbatim**:

```lua
return function(...)
    for i,v in getfenv().Xeno do getfenv(0)[i]=v end
    local e={}
    setmetatable(e, {__index = getfenv().Xeno})
    setfenv(1,e)
    local s=Instance.new('LocalScript')
    getfenv(1).script=s
    setfenv(0, getfenv(1));
    -- <user script pasted here>
```

  This promotes all `Xeno.*` functions to globals, sandboxes the script with a metatable fallback, and fabricates a `script` global (a dummy `LocalScript`). A second wrapper (`return function(...)error([[ ... `) is the error-reporting path.
- Exposed function names found in the binary: `Loadstring`, `Request`, `WebSocket`, `ReadFile`, `WriteFile`, `RConsole`, `Console`, `OpenUrl`, `Base64`, `Crypt`, `zstd`, `QueueOnTeleport`, `SetScriptable`, `GetBytecode`, `SetBytecode`, `SetScriptBytecode`, `HookInstance`, `GetService`, `GetRBXSignals`, `GetFunctions`, `GetProperties`, `GetInstanceFromObjectValue`, `SaveScriptProfilingData`, `ExecuteJavaScript`.
- **autoexec**: scripts in the autoexec folder run after every attach (`"[::HandleAutoExecute]: Executed {} script(s) from autoexec directory"`).
- **queue_on_teleport**: persisted to cache and re-loaded (`"Loaded {} Cached queued scripts for QueueOnTeleport"`).

## 7. Persistence & caching

- Cache file stores: RBXClient PIDs, `RBXBytecode`, `RBXMFlags`, `RBXClientInfos` — `"Loaded existing cache: {} RBXClients, {} RBXBytecode, {} RBXMFlags, {} RBXClientInfos"`.
- On startup it re-attaches to previously seen clients: `"Reattaching to cached client PID: {}"`.
- Caches a `RenderView` pointer (`"Invalid Cached RenderView. Fetching Automatically..."`, `"RenderView retrieved from Cache: {:#x}"`) — a Roblox internal used for Drawing/render functions.
- Terminates duplicate Xeno processes: `"Terminated same existing Xeno process: {}"`.

## 8. Security-relevant observations (red flags)

- **Unsigned** binary with a **future-forged timestamp**.
- **HWID fingerprinting:** imports `GetCurrentHwProfileW`.
- **Runtime-downloaded executable content:** `https://x3no.pages.dev/ep.zst.enc` (encrypted, zstd-compressed) — behavior can change without a DLL update.
- Contacts a **pastebin** (`https://pastebin.com/raw/A7n0vJtR`) — purpose not determinable statically (likely a config/announcement/version channel).
- Reads the **Steam registry key** (`"Error opening Steam key"`, `"Error reading SteamExe key"`) — no legitimate Roblox need; repurposed or borrowed code *(inferred)*.
- **Encrypted embedded payloads (SOLVED):** resources `8194/8192` (27,985 B) and `8194/8196` (62,613 B), shared magic `16 48 7F B8`, entropy ≈ 7.99 bits/byte. The encryption is a **repeating 32-byte XOR key** built at runtime by an initializer at `.text:0x3B10`: `3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB`. XOR then zstd-decompress yields:
  - `8192` → **`CLIENT.LUA` (145,004 B)** — the entire Xeno client init script injected into Roblox (extracted as `payloads/xeno_client.lua`).
  - `8196` → **336,884 B** — Roblox's own en-us locale translation table, bundled so the hijacked `en-us` module still works normally after replacement (extracted as `payloads/xeno_payload2.lua`).
- Uses **`Nt*` syscalls directly** instead of Win32 wrappers — bypasses user-mode API hooks on `kernel32` (anti-monitoring/anti-AV-evasion trait).
- **Process tampering:** suspends the Roblox process and writes to its memory (`NtSuspendProcess`, `NtWriteVirtualMemory`, `VirtualAllocEx`, `WriteProcessMemory`).
- **Clipboard & input synthesis:** `SetClipboardData`, `keybd_event`, `mouse_event`.
- Discord social-engineering hook: `"Inviting you to our Official Discord server :D {}"`, join-request handling.

## 9. Indicators of compromise (IOCs)

| Type | Value |
|---|---|
| Mutex/behavior | Terminates existing "Xeno" processes; `Xeno/` working directory with `workspace`, `autoexec`, `Cache` |
| Env vars | `XENO_CLIENT_PID`, `XENO_SERVER_PORT`, `XENO_VERSION` |
| URLs | `https://xeno.now`, `https://xeno.onl`, `https://x3no.pages.dev/ep.zst.enc`, `https://x3no.pages.dev/version.txt`, `https://x3no.pages.dev/code.lua`, `https://pastebin.com/raw/A7n0vJtR`, `https://discord.gg/xe-no` |
| Network | HTTP server bound to `localhost:<port>` (fixed/dev port **3110**); endpoints `/f?e=<opcode>`, `/rq?c=..&h=..&u=..`; outbound HTTPS to the above |
| Resource blobs | Type `8194`, IDs `8192`/`8196`, magic `16 48 7F B8`; XOR key `3EFD5045ED61BFCA57EFA192D0076696FDC5F72112BD49367A3FB319A92AF5BB` |
| In-game artifacts | `CoreGui\<pid>` folder; `Message` instance `"DO NOT DELETE: BELONGS TO XENO"`; `shared.__Xeno`; random-named ModuleScripts |
| Strings | `"Xeno is only maintained by Rizve..."`, PDB path `...\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb` |
| Registry | Reads Steam key (`Software\...\Steam`, `SteamExe`) *(inferred)* |
| Email/Discord | `rizve@xeno.onl`, Discord user `.rizve` |

## 9b. Round-2 findings — decrypted payload contents

Recovered by XOR-decrypting both resources (see §8) — confirmed 100% of the earlier inferences and added:

- **Attach target confirmed in the payload itself:** `CLIENT.LUA` checks `if script.Name == "en-us"` — the hijacked module is the **en-us locale translation ModuleScript**, and resource `8196` is the original translation table kept so the game keeps working after the swap.
- **In-game artifacts (excellent detection surface):** the client creates a folder in `CoreGui` **named after `%XENO_CLIENT_PID%`** containing a `Message` instance named **`DO NOT DELETE: BELONGS TO XENO`**, plus randomly-named `ModuleScript` children. It also sets the global **`shared.__Xeno`**.
- **Execute pipeline at the Lua level:** an `ExecutionListener` loop creates a random-named `ModuleScript`; the DLL overwrites its bytecode (opcodes `LockCustomBytecode`/`UnlockCustomBytecode`); the client `require()`s it — when the bytecode is a compiled user script, `require` returns a function which is run with the Xeno environment, then the module is regenerated.
- **Full client↔server protocol:** `POST http://localhost:<port>/f?e=<opcode>` with JSON body `{c=<arg>, p=<pid>}`. Opcode table (`XFS`): `Activate=0, ReadFile=1, GetFileType=2, ListFiles=3, MakeFolder=4, DelFolder=5, DelFile=6, GetCustomAsset=7, GetScriptBytecode=8, SetScriptBytecode=9, RestoreScriptBytecode=10, LockModule=11, UnlockModule=12, GetProperties=13, GetInstanceRBXSignals=14, GetInstanceFunctions=15, HookInstance=16, SetScriptable=17, GetInstanceAddress=18, PlayerRemoving=19, UnlockCustomBytecode=20, LockCustomBytecode=21` (`WriteFile=-1` is client-side only). User-script HTTP goes through a DLL proxy: `POST /rq?c=<methodId>&h=<b64 headers>&u=<b64 url>`.
- **Execution endpoints (round 3):** compile service `POST /ls?c=<moduleName>&p=<pid>` (400 = Luau compile error, 500 = server error; patched module returns a **PID-keyed table** `{[pid]=function}`), teleport queue `POST /qt?p=<pid>`, clipboard `POST /cb`. UI execution rides opcodes 20/21: the client creates a random-named ModuleScript and polls `require()` every 1 ms; the DLL compiles the queued source (embedded Luau + env wrapper), overwrites the module's bytecode via `NtWriteVirtualMemory`, and **read-back verifies the write** before the client's next `require()` picks it up.
- **BytecodePatchWatcher (v1.3.65+):** a watchdog thread that auto-restores original module bytecode if a patch isn't consumed in time — foreign bytecode in game memory is deliberately transient.
- **Disabled in v1.3.65's client:** teleport-queue replay and autoexec blocks are commented out in `CLIENT.LUA` (DLL-side storage/logging still active).
- **Version evolution (v1.3.40 → v1.3.65, from `COMPARE_REPORT.md`):** attach reworked from home-page/menu bytecode-set + `RefreshQueueOnTeleport` to the translation-module + `PlayerRemoving` model; offset system renamed ("ecs patterns" → "inp data"); `dwmapi.dll` import and the BytecodePatchWatcher added; cpp-httplib/IXWebSocket upgraded; same XOR key across both builds.
- **Server self-protection:** the client refuses to send requests to `localhost:3110` / `127.0.0.1:3110` (`"Not allowed to send request to Xeno server"`) — **3110 is Xeno's fixed/dev server port**.
- **Server hands out the HWID:** the `Activate` call "returns hwid" per the code comment — confirming HWID fingerprinting happens in the DLL.
- **Remote code execution channel:** every attach fetches **`https://x3no.pages.dev/code.lua`** and runs it via `loadstring` with the full Xeno environment (named `XenoNotification`) — the author can push arbitrary code into every live session without updating the DLL. Update checks poll **`https://x3no.pages.dev/version.txt`**.
- **Third-party code pulled at runtime:** `saveinstance` is downloaded from `https://raw.githubusercontent.com/luau/SynSaveInstance/main/saveinstance.luau`.
- **Credits in the payload:** `Quivings (https://getsolara.dev/)` (ProxyService; mock-service "vulnerabilities mitigation") and `razzoni`. The header admits **"I apologize for UNC functions that are fake / not working as I would like more scripts being able to run"** — several advertised API functions are stubs.
- **Full UNC/environment function list recovered** (~160 functions): `getgenv, getrenv, getsenv, getgc, getconnections, getcallingscript, getscriptbytecode, setscriptbytecode, restorescriptbytecode, getscriptclosure, getscripthash, getloadedmodules, getrunningscripts, getnilinstances, getinstances, gethui, gethiddenproperty(ies), sethiddenproperty, getproperties, getinstancefunctions, getrbxsignals, getinstanceaddress, hookfunction, hookinstance, newcclosure, newlclosure, clonefunction, replaceclosure, cloneref, compareinstances, checkcaller, checkclosure, iscclosure, islclosure, isourclosure, isexecutorclosure, getidentity/setidentity, getthreadidentity/setthreadidentity, getthreadcontext/setthreadcontext, loadstring, loadfile, dofile, require, decompile, disassemble, dumpstring, saveinstance/savegame, identifyexecutor, getexecutorname/version, whatexecutor, request/http_request, HttpGet/HttpPost, WebSocket, readfile/writefile/appendfile/delfile/makefolder/delfolder/isfile/isfolder/listfiles, getcustomasset, setclipboard/toclipboard/setrbxclipboard, getfpscap/setfpscap, getfflag/setfflag, isnetworkowner, getsimulationradius/setsimulationradius, fireclickdetector/firetouchinterest/fireproximityprompt, queue_on_teleport, keypress/keyrelease, mousemoveabs/mousemoverel/mousescroll, isrbxactive/isgameactive/iswindowactive, gethwid/get_hwid, crypt, lz, base64, Drawing, console*/rconsole* family, isreadonly/setreadonly, isscriptable/setscriptable, getrenderproperty/setrenderproperty, isrenderobj, cleardrawcache`.
- **Roblox-identifying headers** are attached to proxied requests: `roblox-place-id`, `roblox-game-id`, `roblox-session-id`.
- **New IOC URLs:** `https://x3no.pages.dev/version.txt`, `https://x3no.pages.dev/code.lua`, `https://xeno.onl`, `https://discord.gg/xe-no`, `https://getsolara.dev`, `https://raw.githubusercontent.com/luau/SynSaveInstance/main/saveinstance.luau`.

## 10. Assessment

`TEST.dll` is the genuine native core of the **Xeno Roblox executor v1.3.65**. It is a cheat tool whose entire purpose is unauthorized code execution inside Roblox — it tampers with another process's memory, hijacks in-game modules, fingerprints the machine (HWID), and pulls encrypted executable payloads from the internet at runtime. From a defender's perspective it behaves like a grayware/malware-adjacent tool: unsigned, timestamp-forged, with remote payload delivery and anti-hooking syscall usage. It should not be run on a machine you care about outside of an isolated analysis environment.
