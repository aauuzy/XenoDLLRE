# Findings

Every finding about Xeno v1.3.65 (`Xeno.dll`, SHA-256 `50318bc8d60477a2402440c4989611ba9640cf6a709b5ec9d4c44e3860e99049`), with its evidence and a confidence level.

DLL-level evidence (addresses, imports, strings, signature) was re-verified on 2026-11-10 against a copy extracted from the public v1.3.65 installer, which is byte-identical to the analyzed build (F-08). A second pass the same day cross-referenced the internal functions behind the attach, execution, offsets and Discord code paths (evidence code `X`), which settled most open questions and corrected several earlier inferences (see the corrections log). [`ARCHITECTURE.md`](ARCHITECTURE.md) explains how the pieces fit together; this document is the authoritative list of what is claimed.

## Confidence levels

All analysis is static. Nothing here has been observed running. "Confirmed" therefore means the artifact itself states it unambiguously, not that the behavior was watched happening.

| Level | Meaning |
|---|---|
| **Confirmed** | Directly present in the binary or the decrypted client source, with no interpretation needed beyond reading it. |
| **Strongly supported** | Two or more independent static sources agree (for example a log string, an import, and client code), but the behavior was not executed. |
| **Inferred** | A reasoned interpretation of one source, or a reconstruction. Plausible, not demonstrated. |
| **Unverified** | Stated in earlier revisions or reasonable to expect, but not checked against evidence available to this revision. |

## Evidence codes

| Code | Source | Reproducible from this repository? |
|---|---|---|
| `S` | ASCII string in the DLL | Needs the sample |
| `I` | Import table entry | Needs the sample; counts in [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) |
| `D` | Disassembly at the given RVA (capstone 5.0.7, image base `0x180000000`) | Needs the sample |
| `R` | Resource directory, sizes, entropy | Needs the sample; values in [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) |
| `P:<line>` | Line in the decrypted `CLIENT.LUA` | Needs the sample; line index in [`payloads/README.md`](../../payloads/README.md) |
| `C` | [`COMPARE_REPORT.md`](../../reports/COMPARE_REPORT.md) (v1.3.40 to v1.3.65 diff) | Needs both samples |
| `X` | Cross-reference from [`tools/xrefs.py`](../../tools/xrefs.py): which `.pdata` function references a string, import or global, and which functions call it. Pinned by [`tests/test_samples.py`](../../tests/test_samples.py) | Needs the sample |

`X` evidence shows that code is present and how it is connected, not that a given path runs. "No reference" means no direct RIP-relative reference or direct call; access through a register-held pointer or copied struct is not ruled out.

---

## 1. Identification

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-01 | The sample is the native core of the Xeno Roblox executor, version `v1.3.65`. | Confirmed | `S`: `"Xeno Version: "`, `https://xeno.now`; `D`: `Version` export returns `"v1.3.65"`; `P:1` header `v1.3.65 CLIENT.LUA` |
| F-02 | PE32+ DLL, x86-64, 2,362,704 bytes, six standard sections, PE timestamp 2026-10-20 20:43:17 UTC. | Confirmed | [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) |
| F-03 | Not packed: standard section names and sizes, readable strings, intact `.pdata`, no writable+executable section. | Confirmed | Section table in [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) |
| F-04 | Authenticode-signed with a **self-signed** certificate, subject and issuer `CN=Rizve A`, serial `3FDA0D2C31C5C2A84790E6E2F20D1306`, valid 2026-05-10 to 2027-05-10, SHA-256 fingerprint `AEE2FA8D…C2B30A21`. The signed SHA-256 file digest matches the file, so it has not been modified since signing. The signature carries a Sectigo RFC 3161 timestamp of 2026-10-20 20:44:16 UTC, about one minute after the PE timestamp. Windows reports `UnknownError` because the chain does not lead to a trusted root. v1.3.40 is signed by a different self-signed `CN=Rizve A` certificate (serial `34598A72A3AEEAB84AC8BD75D471BC9C`, valid 2025-09-03 to 2026-09-03, SHA-256 `15EB8533…F1BBACED`): the subject is kept across yearly renewals, the serial is not. | Confirmed | 8,016-byte certificate table at file offset `0x23EE00`; digest recomputed and compared; both builds' certificates parsed with OpenSSL |
| F-05 | Built with MSVC (MSVCP140, VCRUNTIME140, UCRT imports). | Confirmed | `I` |
| F-06 | Embedded PDB path `C:\Users\rizve\OneDrive\Desktop\Projects\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb`. The `net9.0-windows8.0` component is a .NET target-framework folder name, which is unusual for a native DLL shipped in an Electron installer; the build arrangement behind it is unknown. | Confirmed (path) / Unresolved (meaning) | `S` |
| F-08 | Distributed as an NSIS installer wrapping an Electron app (`app-64.7z`). `Xeno.dll` ships at `resources/public/Xeno.dll` alongside `libcurl.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll` and the MSVC runtime. The public installer `Xeno-v1.3.65.exe` (88,851,592 bytes, SHA-256 `829c1e8861cadb5835fe968b98d06254254e6a4120250d9f5cf612d3f152c7a1`) contains a DLL identical to the analyzed one. | Confirmed | Installer extracted with 7-Zip; DLL SHA-256 compared |
| F-07 | Maintainer attribution "Rizve", contact `rizve@xeno.onl`, Discord `.rizve`. These are self-published by the developer in the binary and client header. | Confirmed | `S`; `P:1-12` |

## 2. Exported interface

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-10 | Six exports: `Attach` (0x18D3D0), `Execute` (0x18D400), `GetClients` (0x18D610), `Initialize` (0x18CA80), `SetSetting` (0x18D950), `Version` (0x18D3E0). | Confirmed | Export table |
| F-11 | `Version` returns `c_str()` of a global `std::string` holding `"v1.3.65"` (MSVC small-string pattern). | Confirmed | `D` 0x18D3E0 |
| F-12 | `Attach` is a two-instruction thunk: `xor ecx, ecx; jmp` to the client-scan routine `0x18C040` with a `false` argument. That routine enumerates processes and starts `0x18B850` (creates an `RBXClient`), which calls `0x111C30` (opens the process, F-32); `0x111C30` starts a thread `0x11D7A0` that runs the per-client attach routine `0x1124B0` (F-30). | Confirmed | `D` 0x18D3D0; `X` |
| F-13 | `Execute` takes a script pointer in `rcx`, a 32-bit PID array in `rdx`, and a count in `r8`. For each PID it locks a global `std::mutex`, scans a vector of `shared_ptr` clients for one whose `+0x2D0` field equals the PID, and checks that client's process is alive (`GetExitCodeProcess(*(HANDLE*)client, …) == STILL_ACTIVE`). For a live match it unlocks, packs the client, its control block and the script pointer into a heap block, and starts a detached thread (`_beginthreadex` with procedure `0x18E540`, then `_Thrd_detach`). That procedure calls the compile/write/verify function `0x117980` (F-41). | Confirmed | `D` 0x18D400–0x18D5BA; `X` 0x18E540 → 0x117980 |
| F-14 | The imported call at `rip+0x1E194` is `MSVCP140!_Mtx_lock`, and the `0x7FFFFFFF` comparison that follows reads the mutex's own count field at `0x21685C` (inside the mutex at `0x216810`); together they are the inlined `std::mutex::lock`, not PID validation or a readiness flag. No return value is computed: `rax` is not set before the normal return, so the export is effectively `void`. | Confirmed | `D` 0x18D447–0x18D467 |
| F-15 | `GetClients` walks the client vector under a lazily initialized SRW lock and skips objects whose `+0x2C0` field is null. | Confirmed (control flow) | `D` 0x18D610 |
| F-16 | The client object's process handle is its first field (`+0x00`), the argument `Execute` passes to `GetExitCodeProcess`; `+0x2D0` is the PID. The meaning of `+0x2C0` (tested non-null by `GetClients`) is not established; the `+0x318` read in `GetClients` is on an object returned by a helper call and is not established as a client field. | Confirmed (`+0x00`, `+0x2D0`) / Unverified (`+0x2C0`, `+0x318`) | `D` 0x18D480–0x18D493, 0x18D6A7, 0x18D718 |
| F-17 | `SetSetting(1, value)` toggles Discord Rich Presence (application ID `1393297926209405000`). `SetSetting(0, value)` stores `value != 0` in a byte flag at `0x251FA9`. The only reader is a background loop at `0x18C910` (no direct callers; a thread procedure) that first terminates other Xeno processes (F-84) and then calls the client-scan routine `0x18C040` every 200 ms with argument `!flag`. The `Attach` export calls the same routine with `false` (F-12), so setting 0 makes the background loop behave like repeated manual `Attach` calls. What the routine does differently for `true` was not traced; an auto-attach toggle is the likely meaning. | Confirmed (control flow) / Inferred (meaning) | `D` 0x18D96C, 0x18DD10, 0x18CA50–0x18CA77; `X` refs to 0x251FA9 |
| F-18 | `Initialize` loads `ntdll.dll` and resolves `NtLockVirtualMemory`, `NtUnlockVirtualMemory`, `NtSuspendProcess`, `NtResumeProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory` with `GetProcAddress`, storing them at `.data` `0x251FC0`–`0x251FE8` and failing if any is null. In v1.3.65 nothing outside `Initialize` references those six globals (F-31). | Confirmed | `D` 0x18CA80–0x18CBCE; `X`; `S`: `"Failed to load ntdll.dll"`, `"A symbol was unable to be loaded from ntdll.dll"` |

## 3. Bundled components

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-20 | Luau compiler compiled in (many `Luau*` feature-flag strings, compiler error text such as `"Exceeded constant limit"`). | Strongly supported | `S` |
| F-21 | zstd compiled in. | Confirmed | `S` (zstd error-name strings); `D` calls to `ZSTD_getFrameContentSize` 0x1800E0830 and `ZSTD_decompress` 0x1800E0CD0 |
| F-22 | cpp-httplib (HTTP server) and IXWebSocket (WebSocket) compiled in. | Strongly supported | RTTI names `httplib::Request`/`Response`, `ixwebsocket::heartbeat`; WebSocket handshake error strings |
| F-23 | libcurl and OpenSSL 3 loaded as separate DLLs. | Confirmed | `I`: `libcurl.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll` |
| F-24 | Discord RPC integration. | Strongly supported | `S`: `"DiscordRPC"`, `"SET_ACTIVITY"`, join-request strings |

## 4. Attach mechanism

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-30 | Xeno attaches by replacing the bytecode of the **en-us locale translation ModuleScript** (found via `RobloxGui` → `Modules` → … → `Locales`), so its client runs when the Roblox client loads that module. Two functions do this: the main attach routine `0x1124B0` and the `PlayerRemoving` reattach routine `0x14D360`. In `0x1124B0` the log strings run `"Attaching in-game using translation module."` → `RobloxGui` → `Modules` → `Locales` → `"Intercepted translation module @{:#x}"`, and the cross-process allocation and writes (F-31) sit between the `Locales` lookup and the interception log. | Strongly supported (DLL code path confirmed; that the written data is the compiled client is inferred from the client side) | `X` 0x1124B0, 0x14D360; `S`; `P:396` checks `script.Name == "en-us"`; resource `8196` is the en-us table (F-62) |
| F-31 | Cross-process writes in v1.3.65 go through the **imported Win32 `WriteProcessMemory`**, not the resolved `NtWriteVirtualMemory`. In the attach routine the sequence around the interception log is: a helper (`0x10D6B0`) that calls `VirtualAllocEx` then `WriteProcessMemory` (at `0x116019`), a `WriteProcessMemory` at `0x116060`, the `"Intercepted translation module"` log at `0x11606A`, then a `WriteProcessMemory` at `0x116160`. The six resolved `Nt*` pointers are never referenced after `Initialize`, so the process is **not suspended** around the write in v1.3.65. v1.3.40 differs: its attach function calls the resolved `NtSuspendProcess` and `NtResumeProcess` (and, like v1.3.65, never calls `NtWriteVirtualMemory`). | Confirmed (call sites, both builds) / Strongly supported (`Nt*` unused in v1.3.65: no direct reference) | `X`; `D` 0x10D6B0, 0x115F90–0x116160; [`tests/test_samples.py`](../../tests/test_samples.py) |
| F-32 | Attach opens the Roblox process with `OpenProcess(PROCESS_ALL_ACCESS (0x1FFFFF), bInheritHandle = TRUE, pid)` and refuses an elevated Roblox process when Xeno itself is not elevated. | Confirmed | `D` 0x111C30; `S`: `"Failed to open the Roblox client process because it is running with administrator privileges..."` (same function) |
| F-33 | Per-Roblox-version memory offsets ("RBXClient data") are downloaded at runtime and zstd-compressed, with alias and default-version fallbacks. The fetch is in the main attach routine `0x1124B0`: the primary request (`0x117450`, timeouts 2 s and 8 s, success on HTTP 2xx) goes to the pastebin URL (F-34); on failure or bad data the routine falls back to the secondary `https://x3no.pages.dev/ep.zst.enc`. | Confirmed (control flow) | `D` 0x112564–0x11262C; `S`: `"Successfully retrieved RBXClient data (Primary)"`, `"Primary endpoint failed..."`, `"...Using secondary endpoint"`, `"Offsets for version "{}" points to "{}""` |
| F-34 | The primary offsets endpoint is `https://pastebin.com/raw/A7n0vJtR`: it is the URL passed to the first fetch. Its content was not retrieved (see [`DISCLOSURE.md`](../DISCLOSURE.md)), so whether it holds the data itself or a pointer to it is not established. | Confirmed (role in code) / Unverified (content) | `D` 0x11259A–0x112605 |
| F-35 | The injected client signals success through the localhost server (handled in `0x14CF80`). If no ping arrives, the main attach routine forces a window refresh (F-36) and then `"Attempting to restart current thread..."`; the `PlayerRemoving` reattach routine instead gives up with `"...Treating this as failed."` | Confirmed (code paths) | `X`: `"Attach ping received..."` in 0x14CF80; `"...Attempting to restart current thread..."` in 0x1124B0; `"...Treating this as failed."` in 0x14D360 |
| F-36 | v1.3.65 still has the forced window-refresh fallback (`RefreshRBXWindowV2`) when the success ping is late. The routine is `0x111490`, called only from the two attach routines (which hold the fallback log string). It is the only user of `SetWindowPos`, `RedrawWindow`, `LockWindowUpdate` and `DwmSetWindowAttribute`, and also uses `Get/SetWindowPlacement`, `SetWindowLongPtrW`, `IsZoomed`, `MonitorFromWindow` and `Sleep`. v1.3.40 instead imported focus-manipulation APIs (`AttachThreadInput`, `SetFocus`, `SetActiveWindow`, `BringWindowToTop`, `ShowWindow`, `SendMessageTimeoutW`) that v1.3.65 dropped. | Confirmed | `X` 0x111490; `C` |
| F-37 | After the player leaves a place, Xeno reattaches (`PlayerRemoving`, op 19). | Strongly supported | `S`: `"[::PlayerRemoving]: Player leaving ping recieved. We have to reattach."`; `P:4803-4811` |

## 5. Execution

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-40 | **Path A (`Execute` export):** the client keeps a random-named ModuleScript in its container and calls `require()` on it every ~1 ms. When the DLL has overwritten its bytecode with a compiled user script, `require` returns a function, which the client runs with the Xeno environment, then sends op 21 (`LockCustomBytecode`) and creates a new module. The client never sends op 20 on this path. | Confirmed (client side) | `P:4826-4872` |
| F-41 | The DLL compiles the queued source with its embedded Luau compiler, writes the bytecode into the execution module, and reads it back to verify. All three are in one function, `0x117980`, reached from `Execute`'s thread procedure (F-13): it holds the compile-error and verify-failure strings, locates the module under `CoreGui`, calls the `VirtualAllocEx`+`WriteProcessMemory` helper `0x10D6B0` and a `WriteProcessMemory` wrapper, and calls `ReadProcessMemory` wrappers. | Confirmed (code path) | `X` 0x117980; `S`: `"Could not verify that the execution module has changed..."`, `"[{}]: Failed to compile (this is a problem with your script): {}"` |
| F-42 | **Path B (`loadstring`):** the client creates `loadstring:<random>` under its `Loadstring` folder, posts the source to `/ls?c=<name>&p=<pid>`, then polls op 20, `require`, op 21 until the module returns a table keyed by PID whose value is a function, with a 3 s timeout. HTTP 400 means a compile error. | Confirmed (client side) | `P:1994-2080` |
| F-43 | User source is wrapped in a prologue that copies the `Xeno` table into the thread environment, gives the script a metatable-backed environment, and fabricates a `script` global. | Confirmed | Wrapper text in `.rdata` (`S`); a variant at `P:1643` |
| F-44 | Compiled bytecode is cached in the Xeno cache file alongside client PIDs, flags and client info. | Strongly supported | `S`: `"Loaded existing cache: {} RBXClients, {} RBXBytecode, {} RBXMFlags, {} RBXClientInfos"` |
| F-45 | New in v1.3.65: a "Bytecode Patch Watcher" thread (`0x11D550`, started from the attach routine, which logs its thread address) restores original module bytecode with `WriteProcessMemory` if a patch is not consumed within a threshold measured with `QueryPerformanceCounter`. The log text gives crash prevention as the reason. | Confirmed | `X` 0x11D550; `S`: `"[::BytecodePatchWatcherT]: Threshold reached. Workers failed to call restore (Automatically restoring to prevent crash)"`, `"Bytecode Patch Watcher thread: {:#x}"`; `C` |
| F-46 | Original bytecode is checksummed so restores can be verified. | Strongly supported | `S`: `"Restored data doesn't match checksum"` |
| F-47 | The client's identity functions are stubs: `getthreadidentity` returns a stored number (default 3) and `setthreadidentity` only changes that number. The actual identity the hijacked module runs at was not determined. | Confirmed (stubs) / Unverified (real identity) | `P:3503-3516` |
| F-48 | Some advertised environment functions are non-functional by the author's own statement. | Confirmed | `P:14` |

## 6. Localhost control plane

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-50 | The DLL runs an HTTP server on `localhost`. Its port reaches the client by text substitution: `CLIENT.LUA` holds the literal `%XENO_SERVER_PORT%`, and `Initialize` references that placeholder (and `%XENO_VERSION%`) next to the resource loader. `%XENO_CLIENT_PID%` and `%ROBLOX_CLIENT_VERSION%` are substituted per client in the attach routines. None of these are environment variables. | Strongly supported | `S`: `"Xeno Server is Live on http://localhost:{}"`; `P:65`; `X` 0x18CA80, 0x1124B0, 0x14D360 |
| F-51 | Opcode endpoint `POST /f?e=<op>` with JSON body `{"c": <arg>, "p": <pid>}`; ops 0–21 as listed in [`ARCHITECTURE.md`](ARCHITECTURE.md) §5; a missing status is treated as 410 ("Xeno was closed"). | Confirmed (client side) | `P:137-175`, `P:193-227` |
| F-52 | Additional endpoints: `/ls` (compile), `/rq?c=<method>&h=<b64 headers>&u=<b64 url>` (HTTP proxy for user scripts), `/qt?p=<pid>` (teleport queue), `/cb` (clipboard). | Confirmed (client side) | `P:2007`, `P:2174`, `P:2839-2847`, `/cb` call site |
| F-53 | The client refuses user requests to port 3110 on loopback. The reason (a fixed or development port) is not established. | Confirmed (behavior) / Inferred (reason) | `P:2168-2169` |
| F-54 | Every request made through the script HTTP API carries `User-Agent: Xeno/<version>` (unless the script overrides it), `exploit-guid` and `xeno-fingerprint` headers set to the user's hardware identifier, and `roblox-place-id`, `roblox-game-id` (the server JobId) and `roblox-session-id` headers. Any third-party server a Xeno script contacts therefore receives a stable machine identifier and the user's current game server. | Confirmed | `P:2157-2165`; identifier source `P:420-435` |
| F-55 | The named-pipe imports belong to the bundled Discord RPC client, not to a UI channel: `WaitNamedPipeW` and `CreateFileW` are used by `0x193D80`, which references the wide string `\\?\pipe\discord-ipc-0`, and `PeekNamedPipe`/`ReadFile` by its companion reader `0x193EB0`. No other pipe code was found, so the UI most likely drives the DLL only through its exports; how the Electron process loads and calls them was not traced. | Confirmed (pipes are Discord IPC) / Unverified (UI mechanism) | `X` 0x193D80, 0x193EB0 |

## 7. Resources and remote content

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-60 | Resources `8194/8192` (27,985 B) and `8194/8196` (62,613 B) are a repeating 32-byte XOR over a zstd frame. Key `3EFD5045ED61BFCA57EFA192D0076696FDC5F72112BD49367A3FB319A92AF5BB`. | Confirmed | `D` decrypt loop 0x190737–0x19075D, key initializer 0x3B10; independent known-plaintext derivation of the first 4 key bytes; both resources decrypt and decompress |
| F-61 | The key is unchanged between v1.3.40 and v1.3.65. | Confirmed | `C` |
| F-62 | `8192` is `CLIENT.LUA` (145,004 B); `8196` is Roblox's en-us translation table (336,884 B), returned through a metatable so missing keys yield an empty string. | Confirmed | Decrypted output; hashes in [`payloads/README.md`](../../payloads/README.md) |
| F-63 | On every attach, the client downloads `https://x3no.pages.dev/code.lua` and, if it is longer than 3 bytes, runs it with the full Xeno environment. The developer can therefore run arbitrary code in every attached client without shipping a new DLL. | Confirmed (client code) | `P:4813-4824` |
| F-64 | The client checks `https://x3no.pages.dev/version.txt` for update notifications. | Confirmed | `P:62`, `P:372` |
| F-65 | `saveinstance` is fetched at call time from `raw.githubusercontent.com/luau/SynSaveInstance`. | Confirmed | Call site in `CLIENT.LUA` (`Xeno.saveinstance`) |
| F-66 | `https://pastebin.com/raw/A7n0vJtR` is the primary offsets source (F-34). It is referenced only in the attach routine `0x1124B0`, alongside `ep.zst.enc`. v1.3.40 references both URLs in its attach function too. | Confirmed | `X`; `D` 0x11259A |

## 8. In-game footprint

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-70 | A `Folder` under `CoreGui` named after the Roblox client PID, containing `Pointer` and `Loadstring` folders and a `Message` named `DO NOT DELETE: BELONGS TO XENO`. | Confirmed | `P:28-44` |
| F-71 | `shared.__Xeno` is set to the Xeno environment table. | Confirmed | `P:59` |
| F-72 | Random-numeric-named ModuleScripts are created and destroyed continuously in the container during execution (F-40). | Confirmed | `P:4826-4872` |
| F-73 | The en-us translation module's bytecode differs from Roblox's original while Xeno is attached. | Strongly supported | Follows from F-30; not measured |

## 9. Host behavior

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-80 | A `Xeno` directory with `workspace` and `autoexec` folders and a cache file. | Strongly supported | `S`: directory log lines |
| F-81 | Autoexec and teleport-queue replay are disabled in this client build (code commented out), though the DLL still logs both. | Confirmed (client) | `P:4774-4802` |
| F-82 | The `Activate` call returns a hardware identifier (braces stripped; a random GUID is used if it fails). On the DLL side, `GetCurrentHwProfileW`'s only user is the localhost request dispatcher `0x150E10` (the function holding the opcode handlers' `"Missing 'p' field: PID"` errors). The client attaches the value to outgoing script HTTP requests (F-54) and exposes it as `gethwid()`. What the developer otherwise uses it for is not established. | Confirmed (HWID source and use) / Unverified (other use) | `P:420-435`, `P:2112-2113`, `P:2158-2159`; `X` 0x150E10 |
| F-83 | The Steam registry reads are part of the bundled Discord RPC library's game-registration code, not Xeno-specific: `0x193B50` opens `HKCU\Software\Valve\Steam`, reads `SteamExe`, and builds a `steam://rungameid/%s` command. It is reached from `SetSetting` through `0x192DB0`. | Confirmed | `X` 0x193B50; wide strings `Software\Valve\Steam`, `SteamExe`, `"%s" steam://rungameid/%s`; root key `0x80000001` |
| F-84 | Terminates other running Xeno instances: the background loop `0x18C910` opens each with `PROCESS_TERMINATE` and calls `TerminateProcess` before starting its attach loop (F-17). | Confirmed | `X` 0x18C910; `S`: `"Terminated same existing Xeno process: {}"` |
| F-85 | Imports for clipboard writes and synthesized input (`SetClipboardData`, `keybd_event`, `mouse_event`), used to back the script API (`setclipboard`, `keypress`, `mouse*`). | Strongly supported | `I`; corresponding client functions |
| F-86 | `OpenProcess`, `VirtualAllocEx`, `ReadProcessMemory`, `WriteProcessMemory` and `VirtualQueryEx` are imported in v1.3.65; `CreateRemoteThread` and `VirtualProtectEx` are not. The Win32 functions do all the cross-process work: `WriteProcessMemory` is used in 13 functions (including both attach routines, the patch watcher and the execution path), `ReadProcessMemory` in 17, `VirtualAllocEx` only in the helper `0x10D6B0`. The resolved `Nt*` functions are not used (F-31). | Confirmed | `I`; `X` |
| F-87 | The bundled Discord RPC library also contains its URL-protocol registration code (`0x193640`): it creates `HKCU\Software\Classes\discord-<application id>` with `URL Protocol`, `DefaultIcon` and `shell\open\command` values pointing at the host executable. It is reachable from `SetSetting(1, …)` through `0x192DB0`. Whether Xeno's initialization asks the library to register (and so whether the key appears on a user's machine) was not traced. | Confirmed (code present and reachable) / Unverified (runs) | `X` 0x193640; wide strings `Software\Classes\%s`, `discord-%s`, `URL:Run game %s protocol`; root key `0x80000001` |

## 10. Security-relevant observations

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-90 | Xeno ships a deny-list (`BlockedServiceFuncs`) covering purchase, authentication-cookie, analytics, web-browser, capture and messaging APIs (for example `MarketplaceService:PerformPurchase`, `BrowserService:CopyAuthCookieFromBrowserToEngine`, `HttpRbxApiService:*`) and stubs `GetDeviceAccessToken` / `GetDeviceIntegrityToken`. The credits call this "vulnerabilities mitigation". This implies the developers believe these APIs are reachable from the context their scripts run in. | Confirmed (list exists) / Unverified (reachability) | `P:10`, `P:441-549`, `P:575-577` |
| F-91 | Consequently, the risks of this design fall mainly on Xeno's own users: scripts they run, and the `code.lua` channel (F-63), execute in a context the developer felt needed these protections. | Inferred | F-63, F-90 |
| F-92 | Script HTTP requests disclose a stable hardware identifier and the current game server to whatever host a script contacts (F-54). Script authors can use this to track Xeno users across sessions and accounts. | Confirmed (headers) | F-54 |

See [`DISCLOSURE.md`](../DISCLOSURE.md) for how these map to Roblox's security boundaries.

## 11. Changes v1.3.40 to v1.3.65

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-95 | Attach reworked: menu/home-page bytecode set and `RefreshQueueOnTeleport` strings removed; translation-module and `PlayerRemoving` strings added. | Confirmed (strings) | `C` |
| F-96 | Offset data terminology changed from "ecs pattern data" to "inp data". | Confirmed (strings) | `C` |
| F-97 | `dwmapi.dll` import added; BytecodePatchWatcher added; HTTP/WebSocket server strings expanded. | Confirmed | `C` |
| F-98 | `AttachThreadInput` was imported by v1.3.40 and dropped in v1.3.65, along with the other focus-manipulation imports listed in F-36. The regenerated function-level import diff shows 6 imports added and 13 removed. | Confirmed | `I` (both builds); `C` (regenerated 2026-11-10) |
| F-99 | v1.3.40 called `NtSuspendProcess` and `NtResumeProcess` from its attach function; v1.3.65 calls no resolved `Nt*` function (F-31). | Confirmed | `X` on both builds |
---

## Corrections to earlier revisions

Earlier revisions of this repository contained the following errors. They are recorded so reviewers can see what changed and why.

| Earlier claim | Correction |
|---|---|
| Resolving `Nt*` functions makes Xeno use "direct syscalls" that bypass user-mode hooks. | Calling `ntdll` exports via `GetProcAddress` is not a direct syscall; ntdll stubs are where most user-mode hooks sit. Several of the resolved functions (`NtSuspendProcess`, `NtLock/UnlockVirtualMemory`) have no kernel32 equivalent, so no evasion intent can be inferred. |
| Execution path A: the client posts op 20 before the DLL writes bytecode. | The client never sends op 20 on path A; it only polls `require()` and sends op 21 after a function is returned (F-40). Op 20 is used by `loadstring` (F-42). |
| Detection: steady 1 ms loopback HTTP traffic from the execution loop. | The 1 ms loop is a local `require()`; HTTP happens only after a script runs. |
| ~7.99 bits/byte entropy rules out compression and indicates encryption. | zstd output is also near 8 bits/byte. The evidence for encryption was the absent zstd magic plus the XOR differential test. |
| `FindResourceW(..., RT_RCDATA /*8194*/)` | `RT_RCDATA` is 10; 8194 is a custom resource type. |
| Detection: compare the en-us module's bytecode hash server-side. | Servers cannot read client memory; this is a client-integrity check. |
| Hijacked module runs with CoreGui-level (high) privileges. | Not established. The client's identity functions are stubs (F-47). |
| `RefreshRBXWindowV2` reconstruction with specific call sequence. | Reconstructed from imports only; removed. The fallback exists in v1.3.65 (F-36), but its body has not been disassembled. |
| The binary is unsigned; the Sectigo strings are curl's CA bundle. | The file is signed with a self-signed `Rizve A` certificate and timestamped by Sectigo; the Sectigo strings belong to the timestamp chain (F-04). |
| (Raised during the November review) `RefreshRBXWindowV2` was removed in v1.3.65. | Incorrect. Only two of its strings were removed; the fallback string and its window imports are present in v1.3.65 (F-36). The original documentation was right. |
| `decrypt_resources.py` works on any Xeno sample. | Verified on v1.3.40 and v1.3.65 only. |
| Unsigned binary / no PDB as anti-forensics; cache file as persistence. | Removed from the technique mapping; neither meets the ATT&CK definitions. |
| (Before the November cross-reference pass) The attach write goes through the resolved `NtWriteVirtualMemory`, possibly with the process suspended (F-31). | The writes use imported `WriteProcessMemory`, with `VirtualAllocEx` in a helper; the resolved `Nt*` pointers are never referenced after `Initialize` in v1.3.65. Suspension via `NtSuspendProcess`/`NtResumeProcess` happened in v1.3.40 only (F-99). |
| The UI talks to the DLL over named pipes (F-55). | The pipe imports are the Discord RPC client's `discord-ipc-0` connection. |
| `Execute` validates PIDs through an imported helper and checks a "not ready" sentinel; it makes a virtual call with the script (F-13, F-14). | The import is `_Mtx_lock`, the sentinel is `std::mutex`'s internal count, and the call annotated as virtual was `GetExitCodeProcess`. Delivery happens on a detached thread. |
| `+0x2C0` is the client's process handle (F-16). | The handle is at `+0x00`; `+0x2C0` is unidentified. |
| The primary offsets endpoint is unknown; the pastebin's purpose is unknown (F-34, F-66). | The pastebin URL is the primary endpoint. |
| The Steam registry reads are unexplained (F-83). | They are Discord RPC library code. |
| "UTF-16 strings contained nothing of interest" ([`METHODOLOGY.md`](METHODOLOGY.md)). | The wide strings identify the Discord pipe and the Steam and URL-protocol registry paths (F-55, F-83, F-87). |
| `Xeno_Signer_Certificate` matched one serial and lived in the main YARA file. | v1.3.40 uses a different serial, and `pe.signatures` needs YARA built with OpenSSL; without it the whole rule file failed to compile. The rule now matches the self-signed subject and is in its own file. |

## Open questions

1. What identity does the hijacked en-us module run at, and are the APIs in F-90 actually callable from it? Static analysis cannot answer this; it needs an instrumented client, which is outside this project's method.
2. Why v1.3.65 still resolves six `Nt*` functions it never calls (F-18, F-31): leftover code from v1.3.40, or use through a path the cross-reference index cannot see.
3. Meaning of the .NET-style PDB path (F-06).
4. What the internal attach routine does differently when called with `true` (F-17).
5. Meaning of client field `+0x2C0` (F-16), and whether the Discord protocol key is actually written (F-87).

Resolved on 2026-11-10: the primary offsets endpoint and the pastebin's role (F-34, F-66); where the Win32 memory APIs are used versus the `Nt*` functions (F-31, F-86); whether v1.3.40 imported `AttachThreadInput` (F-98); `SetSetting` id 0 (F-17).
