# Findings

Every finding about Xeno v1.3.65 (`Xeno.dll`, SHA-256 `50318bc8d60477a2402440c4989611ba9640cf6a709b5ec9d4c44e3860e99049`), with its evidence and a confidence level. `ARCHITECTURE.md` explains how the pieces fit together; this document is the authoritative list of what is claimed.

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
| `I` | Import table entry | Needs the sample; counts in `SAMPLE_REPORT.md` |
| `D` | Disassembly at the given RVA (capstone 5.0.7, image base `0x180000000`) | Needs the sample |
| `R` | Resource directory, sizes, entropy | Needs the sample; values in `SAMPLE_REPORT.md` |
| `P:<line>` | Line in the decrypted `CLIENT.LUA` | Needs the sample; line index in `payloads/README.md` |
| `C` | `COMPARE_REPORT.md` (v1.3.40 to v1.3.65 diff) | Needs both samples |

---

## 1. Identification

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-01 | The sample is the native core of the Xeno Roblox executor, version `v1.3.65`. | Confirmed | `S`: `"Xeno Version: "`, `https://xeno.now`; `D`: `Version` export returns `"v1.3.65"`; `P:1` header `v1.3.65 CLIENT.LUA` |
| F-02 | PE32+ DLL, x86-64, 2,362,704 bytes, six standard sections, PE timestamp 2026-10-20 20:43:17 UTC. | Confirmed | `SAMPLE_REPORT.md` |
| F-03 | Not packed: standard section names and sizes, readable strings, intact `.pdata`, no writable+executable section. | Confirmed | Section table in `SAMPLE_REPORT.md` |
| F-04 | Signature status. `Get-AuthenticodeSignature` returned `UnknownError`, which is not the `NotSigned` status an unsigned file produces; it usually means a signature blob exists but could not be validated. The Sectigo time-stamping CA URLs in the binary appear inside DER certificate fragments, which a PEM CA bundle would not contain. Whether the file carries an (invalid or unverifiable) signature is unresolved; `SAMPLE_REPORT.md` now records the certificate-table size. | Unverified | `S`; signature check output |
| F-05 | Built with MSVC (MSVCP140, VCRUNTIME140, UCRT imports). | Confirmed | `I` |
| F-06 | Embedded PDB path `C:\Users\rizve\OneDrive\Desktop\Projects\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb`. The `net9.0-windows8.0` component is a .NET target-framework folder name, which is unusual for a native DLL shipped in an Electron installer; the build arrangement behind it is unknown. | Confirmed (path) / Unresolved (meaning) | `S` |
| F-07 | Maintainer attribution "Rizve", contact `rizve@xeno.onl`, Discord `.rizve`. These are self-published by the developer in the binary and client header. | Confirmed | `S`; `P:1-12` |

## 2. Exported interface

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-10 | Six exports: `Attach` (0x18D3D0), `Execute` (0x18D400), `GetClients` (0x18D610), `Initialize` (0x18CA80), `SetSetting` (0x18D950), `Version` (0x18D3E0). | Confirmed | Export table |
| F-11 | `Version` returns `c_str()` of a global `std::string` holding `"v1.3.65"` (MSVC small-string pattern). | Confirmed | `D` 0x18D3E0 |
| F-12 | `Attach` is a two-instruction thunk: `xor ecx, ecx; jmp` to an internal attach routine with a `false` argument. | Confirmed | `D` 0x18D3D0 |
| F-13 | `Execute` takes a script pointer in `rcx`, a 32-bit PID array in `rdx`, and a count in `r8`; for each PID it scans a global client vector, compares the PID at object offset `+0x2D0`, and makes a virtual call with the script as a `std::string`. | Confirmed (control flow) | `D` 0x18D400 |
| F-14 | `Execute` returns a delivered count and validates PIDs through a helper before scanning. | Inferred | Return type and the purpose of the imported call at `rip+0x1E194` were not established |
| F-15 | `GetClients` walks the client vector under a lazily initialized SRW lock and skips objects whose `+0x2C0` field is null. | Confirmed (control flow) | `D` 0x18D610 |
| F-16 | Field `+0x2C0` is the process handle and `+0x318 == 1` means "attached". | Inferred | Field names are interpretations of how the values are tested |
| F-17 | `SetSetting(1, value)` toggles Discord Rich Presence. Setting 0 has a separate handler (0x18DD10) whose purpose is unknown. | Confirmed (id 1) / Unverified (id 0) | `D` 0x18D950; `S`: `"RPC is Enabled"`, `"RPC was disabled"` |
| F-18 | `Initialize` loads `ntdll.dll` and resolves `NtLockVirtualMemory`, `NtUnlockVirtualMemory`, `NtSuspendProcess`, `NtResumeProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory` with `GetProcAddress`. | Confirmed | `D` 0x18CA80; `S`: `"Failed to load ntdll.dll"`, `"A symbol was unable to be loaded from ntdll.dll"` |

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
| F-30 | Xeno attaches by replacing the bytecode of the **en-us locale translation ModuleScript** under `RobloxGui.Modules`, so its client runs when the Roblox client loads that module. | Strongly supported | `S`: `"Intercepted translation module @{:#x}"`, `"Could not find en-us locale translation module..."`, `"Attaching in-game using translation module."`; `P:396` checks `script.Name == "en-us"`; resource `8196` is the en-us table (F-62) |
| F-31 | The bytecode write goes through the resolved `NtWriteVirtualMemory`, and the target process may be suspended around the write. | Inferred | F-18 resolves the functions; the call sites inside the attach routine were not disassembled |
| F-32 | Attach refuses to open an elevated Roblox process when Xeno itself is not elevated. | Confirmed | `S`: `"Failed to open the Roblox client process because it is running with administrator privileges..."` |
| F-33 | Per-Roblox-version memory offsets are downloaded at runtime and zstd-compressed; there is a primary endpoint and a secondary `https://x3no.pages.dev/ep.zst.enc`, with alias and default-version fallbacks. | Strongly supported | `S`: `"RBXClient data resource decompression failed... Using secondary endpoint"`, `"Offsets for version "{}" points to "{}""`, `"...Using offsets from default version"` |
| F-34 | The primary offsets endpoint URL. | Unverified | Not present as a plain string. Possibly built at runtime or fetched via the pastebin URL (F-55) |
| F-35 | The injected client signals success through the localhost server; if no ping arrives, Xeno escalates through further attempts and then gives up. | Strongly supported | `S`: `"Attach ping received from client..."`, `"Still did not receive the success ping from client. Treating this as failed."` |
| F-36 | In v1.3.65 the fallback includes a forced window refresh (`RefreshRBXWindowV2`). | Unverified | Two `RefreshRBXWindowV2` strings were removed in v1.3.65 (`C`); whether the routine survives in v1.3.65 has not been checked |
| F-37 | After the player leaves a place, Xeno reattaches (`PlayerRemoving`, op 19). | Strongly supported | `S`: `"[::PlayerRemoving]: Player leaving ping recieved. We have to reattach."`; `P:4805-4811` |

## 5. Execution

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-40 | **Path A (`Execute` export):** the client keeps a random-named ModuleScript in its container and calls `require()` on it every ~1 ms. When the DLL has overwritten its bytecode with a compiled user script, `require` returns a function, which the client runs with the Xeno environment, then sends op 21 (`LockCustomBytecode`) and creates a new module. The client never sends op 20 on this path. | Confirmed (client side) | `P:4826-4872` |
| F-41 | The DLL compiles the queued source with its embedded Luau compiler, writes the bytecode into the execution module, and reads it back to verify. | Strongly supported | `S`: `"Could not verify that the execution module has changed..."`, `"[{}]: Failed to compile (this is a problem with your script): {}"` |
| F-42 | **Path B (`loadstring`):** the client creates `loadstring:<random>` under its `Loadstring` folder, posts the source to `/ls?c=<name>&p=<pid>`, then polls op 20, `require`, op 21 until the module returns a table keyed by PID whose value is a function, with a 3 s timeout. HTTP 400 means a compile error. | Confirmed (client side) | `P:1994-2080` |
| F-43 | User source is wrapped in a prologue that copies the `Xeno` table into the thread environment, gives the script a metatable-backed environment, and fabricates a `script` global. | Confirmed | Wrapper text in `.rdata` (`S`); a variant at `P:1643` |
| F-44 | Compiled bytecode is cached in the Xeno cache file alongside client PIDs, flags and client info. | Strongly supported | `S`: `"Loaded existing cache: {} RBXClients, {} RBXBytecode, {} RBXMFlags, {} RBXClientInfos"` |
| F-45 | New in v1.3.65: a "Bytecode Patch Watcher" thread restores original module bytecode if a patch is not consumed within a threshold. The log text gives crash prevention as the reason. | Confirmed (existence and stated purpose) | `S`: `"[::BytecodePatchWatcherT]: Threshold reached. Workers failed to call restore (Automatically restoring to prevent crash)"`; `C` |
| F-46 | Original bytecode is checksummed so restores can be verified. | Strongly supported | `S`: `"Restored data doesn't match checksum"` |
| F-47 | The client's identity functions are stubs: `getthreadidentity` returns a stored number (default 3) and `setthreadidentity` only changes that number. The actual identity the hijacked module runs at was not determined. | Confirmed (stubs) / Unverified (real identity) | `P:3503-3516` |
| F-48 | Some advertised environment functions are non-functional by the author's own statement. | Confirmed | `P:14` |

## 6. Localhost control plane

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-50 | The DLL runs an HTTP server on `localhost`, port supplied to the client via `%XENO_SERVER_PORT%`. | Strongly supported | `S`: `"Xeno Server is Live on http://localhost:{}"`; `P:65` |
| F-51 | Opcode endpoint `POST /f?e=<op>` with JSON body `{"c": <arg>, "p": <pid>}`; ops 0–21 as listed in `ARCHITECTURE.md` §5; a missing status is treated as 410 ("Xeno was closed"). | Confirmed (client side) | `P:137-175`, `P:193-227` |
| F-52 | Additional endpoints: `/ls` (compile), `/rq?c=<method>&h=<b64 headers>&u=<b64 url>` (HTTP proxy for user scripts), `/qt?p=<pid>` (teleport queue), `/cb` (clipboard). | Confirmed (client side) | `P:2007`, `P:2174`, `P:2839-2847`, `/cb` call site |
| F-53 | The client refuses user requests to port 3110 on loopback. The reason (a fixed or development port) is not established. | Confirmed (behavior) / Inferred (reason) | `P:2168-2169` |
| F-54 | Proxied requests carry `roblox-place-id`, `roblox-game-id`, `roblox-session-id` headers. | Confirmed | `P:2162` |
| F-55 | The UI process communicates with the DLL over named pipes. | Inferred | Only `WaitNamedPipeW`/`PeekNamedPipe` imports |

## 7. Resources and remote content

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-60 | Resources `8194/8192` (27,985 B) and `8194/8196` (62,613 B) are a repeating 32-byte XOR over a zstd frame. Key `3EFD5045ED61BFCA57EFA192D0076696FDC5F72112BD49367A3FB319A92AF5BB`. | Confirmed | `D` decrypt loop 0x190737–0x19075D, key initializer 0x3B10; independent known-plaintext derivation of the first 4 key bytes; both resources decrypt and decompress |
| F-61 | The key is unchanged between v1.3.40 and v1.3.65. | Confirmed | `C` |
| F-62 | `8192` is `CLIENT.LUA` (145,004 B); `8196` is Roblox's en-us translation table (336,884 B), returned through a metatable so missing keys yield an empty string. | Confirmed | Decrypted output; hashes in `payloads/README.md` |
| F-63 | On every attach, the client downloads `https://x3no.pages.dev/code.lua` and, if it is longer than 3 bytes, runs it with the full Xeno environment. The developer can therefore run arbitrary code in every attached client without shipping a new DLL. | Confirmed (client code) | `P:4813-4824` |
| F-64 | The client checks `https://x3no.pages.dev/version.txt` for update notifications. | Confirmed | `P:62`, `P:372` |
| F-65 | `saveinstance` is fetched at call time from `raw.githubusercontent.com/luau/SynSaveInstance`. | Confirmed | Call site in `CLIENT.LUA` (`Xeno.saveinstance`) |
| F-66 | The DLL references `https://pastebin.com/raw/A7n0vJtR`. Purpose unknown. | Confirmed (reference) / Unverified (purpose) | `S` |

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
| F-81 | Autoexec and teleport-queue replay are disabled in this client build (code commented out), though the DLL still logs both. | Confirmed (client) | `P:4773-4801` |
| F-82 | The `Activate` call returns a hardware identifier; `GetCurrentHwProfileW` is imported. What the HWID is used for (licensing, telemetry, bans) is not established. | Confirmed (HWID returned) / Unverified (use) | `P:420`; `I` |
| F-83 | Reads Steam registry values. Purpose unknown. | Confirmed (strings) / Unverified (purpose) | `S`: `"Error opening Steam key"`, `"Error reading SteamExe key"` |
| F-84 | Terminates other running Xeno instances on start. | Strongly supported | `S`: `"Terminated same existing Xeno process: {}"` |
| F-85 | Imports for clipboard writes and synthesized input (`SetClipboardData`, `keybd_event`, `mouse_event`), used to back the script API (`setclipboard`, `keypress`, `mouse*`). | Strongly supported | `I`; corresponding client functions |
| F-86 | `VirtualAllocEx`/`WriteProcessMemory` are imported in v1.3.65. | Unverified | Listed in the original import analysis; `"Failed to allocate to Client"` was removed in v1.3.65 (`C`); re-check the v1.3.65 import table |

## 10. Security-relevant observations

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-90 | Xeno ships a deny-list (`BlockedServiceFuncs`) covering purchase, authentication-cookie, analytics, web-browser, capture and messaging APIs (for example `MarketplaceService:PerformPurchase`, `BrowserService:CopyAuthCookieFromBrowserToEngine`, `HttpRbxApiService:*`) and stubs `GetDeviceAccessToken` / `GetDeviceIntegrityToken`. The credits call this "vulnerabilities mitigation". This implies the developers believe these APIs are reachable from the context their scripts run in. | Confirmed (list exists) / Unverified (reachability) | `P:10`, `P:441-549`, `P:575-577` |
| F-91 | Consequently, the risks of this design fall mainly on Xeno's own users: scripts they run, and the `code.lua` channel (F-63), execute in a context the developer felt needed these protections. | Inferred | F-63, F-90 |

See `DISCLOSURE.md` for how these map to Roblox's security boundaries.

## 11. Changes v1.3.40 to v1.3.65

| ID | Finding | Confidence | Evidence |
|---|---|---|---|
| F-95 | Attach reworked: menu/home-page bytecode set and `RefreshQueueOnTeleport` strings removed; translation-module and `PlayerRemoving` strings added. | Confirmed (strings) | `C` |
| F-96 | Offset data terminology changed from "ecs pattern data" to "inp data". | Confirmed (strings) | `C` |
| F-97 | `dwmapi.dll` import added; BytecodePatchWatcher added; HTTP/WebSocket server strings expanded. | Confirmed | `C` |
| F-98 | `AttachThreadInput` appears in the removed-strings list, suggesting a USER32 import was dropped. | Inferred | `C`. The function-level import diff in the committed `COMPARE_REPORT.md` was produced by a version of `compare_samples.py` that compared only the first DLL; regenerate it to confirm |

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
| `RefreshRBXWindowV2` reconstruction with specific call sequence. | Reconstructed from imports only; removed. Its status in v1.3.65 is unverified (F-36). |
| The binary is unsigned; the Sectigo strings are curl's CA bundle. | `UnknownError` does not mean unsigned, and DER certificate fragments do not come from a PEM bundle. Status unresolved (F-04). |
| `decrypt_resources.py` works on any Xeno sample. | Verified on v1.3.40 and v1.3.65 only. |
| Unsigned binary / no PDB as anti-forensics; cache file as persistence. | Removed from the technique mapping; neither meets the ATT&CK definitions. |

## Open questions

1. What identity does the hijacked en-us module run at, and are the APIs in F-90 actually callable from it?
2. Primary offsets endpoint (F-34) and the role of the pastebin (F-66).
3. Whether `RefreshRBXWindowV2` and `VirtualAllocEx` usage remain in v1.3.65 (F-36, F-86).
4. Meaning of the .NET-style PDB path (F-06), and whether the file carries a certificate table (F-04).
5. `SetSetting` id 0 (F-17).
