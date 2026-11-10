# Reverse Engineering Process — TEST.dll (Xeno v1.3.65)

This document describes **how** the analysis was performed: the tooling, the order of operations, and why each step was taken. For the raw results see `docs/FINDINGS.md`; for reconstructed code and internals see `docs/TECHNICAL_DEEP_DIVE.md`.

---

## 1. Triage — identify the file

**Goal:** confirm what kind of binary we have before investing time.

- `file TEST.dll` → `PE32+ executable for MS Windows (DLL), x86-64, 6 sections` — a native 64-bit Windows DLL, ~2.3 MB.
- Section layout (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`) with normal names and sizes is the first indicator the binary is **not packed**. Packed binaries usually show few sections, high-entropy `.text`, and tiny import tables.
- The PE timestamp decoded to **October 2026** — a forged/future timestamp, a common anti-attribution trick.

**Tool:** `file` (Git Bash), then Python + `pefile` for everything after.

## 2. Static header & section analysis (pefile)

A Python script using `pefile` dumped:

- `Machine = 0x8664` (x86-64), `Subsystem = 3` (console), `ImageBase = 0x180000000` (default for MSVC x64 DLLs — confirms a standard MSVC build).
- Section characteristics: `.text` is `0x60000020` (execute/read, contains code), `.rdata` read-only data, `.data` read/write — all standard, no executable+writable section (no self-modifying packer stub).
- `.pdata` present → preserved unwind info → the binary was compiled with standard C++ exception handling, again consistent with an unprotected build.

**Decision:** since nothing is packed, skip dynamic unpacking entirely and go straight to static analysis.

## 3. Export table — find the public contract

`pefile`'s `DIRECTORY_ENTRY_EXPORT` gave six exports:

```
Attach, Execute, GetClients, Initialize, SetSetting, Version
```

This naming pattern is the well-known **Roblox executor DLL contract** (the loader/UI calls `Initialize` → `Attach` → `Execute`). This single table identified the *class* of software immediately.

## 4. Import table — capability mapping

Walking `DIRECTORY_ENTRY_IMPORT` and grouping by DLL tells you what the program *can do* without reading a single instruction:

| Import source | Capability inferred |
|---|---|
| `libcurl.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll` | HTTPS client (downloads, remote config) |
| `WS2_32.dll` + `httplib`/`IXWebSocket` symbols | HTTP + WebSocket server/client |
| `KERNEL32` (`CreateToolhelp32Snapshot`, `OpenProcess`, `VirtualAllocEx`, `Read/WriteProcessMemory`) | Process enumeration + cross-process memory access (injection toolkit) |
| `KERNEL32` (`WaitNamedPipeW`, `PeekNamedPipe`) | IPC with a UI/loader process |
| `USER32` (`EnumWindows`, `SetWindowPos`, `RedrawWindow`, `DwmSetWindowAttribute`...) | Roblox window discovery/manipulation |
| `ADVAPI32` registry + `GetCurrentHwProfileW` | Registry reads, HWID fingerprinting |
| `MSVCP140` / `VCRUNTIME140` | MSVC C++ toolchain, C++ exceptions |

## 5. String analysis — the highest-yield step

Because the binary is unobfuscated, strings *are* the documentation. Two passes with regex over raw bytes:

1. **ASCII strings** (`[\x20-\x7e]{4,}` → 10,366 strings), filtered by keyword families: `http`, `xeno`, `attach`, `offset`, `module`, `pipe`, `version`, `roblox`, `autoexec`, `cache`, `error`, etc.
2. **UTF-16 wide strings** (`(?:[\x20-\x7e]\x00){5,}`) — nothing interesting (all logic strings are narrow, consistent with fmt/std::string logging).

Key discoveries from strings alone:

- Product identity: `"Xeno Version: "`, `"https://xeno.now"`, maintainer credit `"Rizve"`, `rizve@xeno.onl`, and a **PDB path** `C:\Users\rizve\OneDrive\Desktop\Projects\Xeno\build\Release\net9.0-windows8.0\Xeno.pdb`.
- Embedded **Luau compiler**: dozens of `Luau*` feature-flag strings (`LuauSolverV2`, `LuauCompileInlineThreshold`, ...).
- Embedded **zstd** (unique `ERROR_frameType_unknown`-style error strings), **cpp-httplib** (`httplib::Request/Response` RTTI symbols), **IXWebSocket** (`ixwebsocket::heartbeat`), **DiscordRPC**.
- The **entire attach narrative** in log lines: `"Intercepted translation module @{:#x}"`, `"Attaching in-game using translation module."`, `"Offsets for version "{}" not found..."`, `"Attach ping received from client..."`.
- **Runtime config channels**: `%XENO_CLIENT_PID%`, `%XENO_SERVER_PORT%`, `%XENO_VERSION%`, `localhost` HTTP server, remote payload URL `https://x3no.pages.dev/ep.zst.enc`, a pastebin URL.
- The **verbatim Lua wrapper** used for `Loadstring`.

Technique note: log strings use fmt-style `{}` placeholders — grepping for `[{}` and `{}]:` recovers the internal logging taxonomy and the names of internal components (`RBXClient`, `XenoServer`, `::Loadstring`, `::CRefresh`, `::HandleAutoExecute`, `::PlayerRemoving`, `::UnlockModule`, `::LockModule`).

## 6. Resource section analysis

Walking `DIRECTORY_ENTRY_RESOURCE`:

- `24/2/1033` — a standard application manifest (`asInvoker`, no auto-elevation).
- `8194/8192/1033` (27,985 bytes) and `8194/8196/1033` (62,613 bytes) — **custom resource type 8194**, both starting with the same 4-byte magic `16 48 7F B8`.

**Entropy test** (Shannon entropy over the byte distribution): both ≈ **7.99 bits/byte** — the theoretical maximum — which rules out plain compression (zstd/lz4 output sits lower with visible structure) and indicates **encryption** (or encrypted-then-compressed). Combined with the log string `"Could not decompress a Xeno resource: {}"`, the pipeline is: `resource → decrypt → zstd decompress → client payload`. The identical magic prefix on both blobs suggests a shared container format/header.

## 7. Signature & authenticity check

`Get-AuthenticodeSignature` via PowerShell → `Status: UnknownError`, no signer certificate. The Sectigo certificate strings found in the binary were traced to **curl's bundled CA store** (the `http://crt.sectigo.com/...` URLs are CA-bundle artifacts), *not* an Authenticode signature. Conclusion: **unsigned binary**.

## 8. Targeted disassembly (capstone)

With the "what" established by strings, disassembly was used only to answer specific questions. Python + `capstone 5.0.7`, disassembling at export RVAs with RIP-relative string resolution:

- **`Version`** — 4 instructions: MSVC `std::string::c_str()` SSO pattern (`cmp [str+16], 0xF; lea/cmov`) returning `"v1.3.65"`.
- **`Attach`** — 2 instructions: `xor ecx,ecx; jmp internal_attach` → a tail-call thunk passing `false`.
- **`Execute`** — full prologue disassembly revealed the calling convention: `rcx` = script, `rdx` = PID array pointer, `r8` = count; loops `dword [r15 + rbp*4]` over PIDs, scans a global vector of client objects comparing `[client+0x2D0]` (PID), then virtual-calls a send routine with the script as `std::string`.
- **`GetClients`** — global client-vector walk with a `std::shared_mutex` (SRWLock via TLS `InitOnce`), skipping clients whose field `+0x2C0` is null.
- **`SetSetting`** — `switch(ecx)`: case 1 toggles a global byte and logs `"RPC is Enabled"` / `"RPC was disabled"` (Discord RPC).
- **`Initialize`** — resolves `NtLockVirtualMemory`, `NtUnlockVirtualMemory`, `NtSuspendProcess`, `NtResumeProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory` from `ntdll.dll` via `GetProcAddress` into globals, failing with `"Failed to load ntdll.dll"` otherwise. Using `Nt*` instead of the documented Win32 wrappers is a mild anti-monitoring choice (bypasses userland hooks placed on `kernel32` exports).

## 9. Correlation & reconstruction

The final step was cross-referencing everything into a coherent model:

- Export disassembly + strings → API contract and client-object field map (`+0x2C0` attached/handle, `+0x2D0` PID, `+0x318` state).
- Ordered log strings → the attach state machine (window wait → module interception → ping handshake → refresh fallbacks → autoexec → teleport-reattach).
- Imports + server strings → the localhost HTTP/WebSocket control plane.
- Resource entropy + decompress strings → the encrypted payload pipeline.

No dynamic analysis (no execution, no debugger) was used — everything in these reports comes from static analysis of the single file. Where a conclusion is inferred rather than proven, it is marked as such in the other two documents.

## 10. Round 2 — breaking the resource encryption and recovering the payloads

The open question after round 1 was the two encrypted resources. Steps, in order:

1. **Differential test (cheap, high information).** XORing the two blobs against each other: `A^B` starts with `00 00 00 00` then diverges into ~7.96-bit entropy. Reading: the shared prefix means *same keystream + same plaintext prefix* (both are zstd frames), and the divergence means the cipher is a **keystream cipher** (XOR-family), not a block cipher — with CBC/ECB the cancellation pattern would look different.
2. **Known-plaintext attack.** Assuming the plaintexts start with the zstd magic `28 B5 2F FD` (the string `"Could not decompress a Xeno resource"` says decompression happens right after decryption), XORing the first 4 ciphertext bytes `16 48 7F B8` gives keystream `3E FD 50 45`. Held for later verification.
3. **Code xref hunting.** Located the error strings in the image, then brute-scanned `.text` for `lea reg, [rip+disp]` (opcode `48 8D /r`, modrm `xx000101`) whose RIP-relative target equals a string's RVA. This found the single log site per string (`0x190A97` for the decompress error, `0x18CD14`/`0x18CDC1` for the load errors).
4. **Read the surrounding functions.** At `0x18CD06-0x18CD7F`: the classic `LoadResource → SizeofResource → LockResource` sequence building a `std::string(ptr, size)`, then a call into `0x1906B0`. Inside `0x1906B0`, before the log site, sat the cipher itself — a tight loop: `div` by key length, `xor cl, byte [rdx+r8]` at `0x190755` — **repeating-key XOR**, key range stored as a begin/end pointer pair in `.data` (`0x252D18/0x252D20`).
5. **Chase the key.** The `.data` slots are zero in the file ⇒ runtime-initialized. Full-.text capstone scan for `mov [rip+disp], reg` targeting those two addresses found exactly one writer at `0x3B1E/0x3B67` — a CRT dynamic initializer that `malloc(32)`s and stores eight immediate dwords. Those immediates *are* the key; its first four bytes `3E FD 50 45` matched the known-plaintext guess exactly — two independent methods agreeing.
6. **Decrypt + decompress.** 20 lines of Python (`tools/decrypt_resources.py`): XOR with the 32-byte key, verify the `28 B5 2F FD` magic, zstd-decompress (`zstandard` module). Both resources opened on the first try: a 145 KB `CLIENT.LUA` and a 337 KB Roblox en-us translation table.
7. **Mine the payload.** The decrypted client script is uncommented source: it handed over the attach target (`script.Name == "en-us"`), the execute loop (`ExecutionListener` + `require`), the full client↔server protocol (`/f?e=` opcodes 0-21, `/rq?` proxy), the fixed port `3110`, the remote code-push channel (`code.lua`), ~160 UNC function names, and the author's own note that some UNC functions are stubs. Every round-1 inference about the attach mechanism was confirmed by the payload.

Lesson embedded in the flow: for keystream-cipher resources, **don't start with the cipher — start with the log strings**, xref them, and read backwards. The error strings named every stage of the pipeline (`retrieve → decompress → invalid`) before a single instruction was read.

## Tooling summary

| Tool | Purpose |
|---|---|
| `file` | Format triage |
| Python 3.14 + `pefile 2024.8.26` | PE headers, sections, imports, exports, resources |
| Python `re` | ASCII/UTF-16 string extraction & keyword mining |
| Python `math`/`collections` | Shannon entropy of resources |
| `capstone 5.0.7` | x86-64 disassembly of exported & internal functions |
| PowerShell `Get-AuthenticodeSignature` | Signature verification |
| Python + `zstandard 0.25.0` | Decompression of decrypted resources |
| Custom scripts | `tools/decrypt_resources.py` (XOR+zstd pipeline), `tools/xeno_detector.py` (PE scanner) |
