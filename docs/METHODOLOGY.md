# Methodology

How the analysis was performed, in the order it happened, and why each step was chosen. Results are in `FINDINGS.md`; the reconstructed design is in `ARCHITECTURE.md`.

## Environment and constraints

- **Static only.** No Xeno binary was executed and no debugger was attached. Every behavioral statement is derived from code, strings, imports or the decrypted client script.
- **Samples.** Two builds extracted from the official installers: v1.3.65 (SHA-256 `50318bc8…99049`, the subject of this report) and v1.3.40 (SHA-256 prefix `37e78bb4944ed703`, used for comparison). Samples are not redistributed.
- **No interaction with Roblox or Xeno infrastructure** is part of the documented method: none of the steps below requires a request to Roblox services, `x3no.pages.dev`, `xeno.now` or the pastebin URL.

| Tool | Version | Use |
|---|---|---|
| Python | 3.14 | Scripting |
| pefile | 2024.8.26 | Headers, sections, imports, exports, resources |
| capstone | 5.0.7 | x86-64 disassembly |
| zstandard | 0.25.0 | Decompression |
| PowerShell `Get-AuthenticodeSignature` | Windows built-in | Signature check |
| 7-Zip | — | Installer extraction (`tools/update_sample.py`) |

## Phase 1 — Triage and capability mapping

**1. Format.** `file` and pefile: PE32+ DLL, x86-64, six sections with standard names, `.pdata` intact, no section both writable and executable. This indicated an unpacked MSVC build, so the analysis went straight to static work without an unpacking step.

**2. Exports.** Six exports: `Attach`, `Execute`, `GetClients`, `Initialize`, `SetSetting`, `Version`. The names describe an injector/executor interface driven by a separate UI.

**3. Imports.** Grouped by DLL to map capabilities before reading code: libcurl/OpenSSL (HTTPS client), WS2_32 (sockets), process and memory APIs (cross-process access), USER32 window APIs (window discovery and manipulation), named-pipe APIs (IPC), `GetCurrentHwProfileW` (hardware identifier). Imports show what the program *can* do, not what it does; each was later tied to strings or code where possible.

**4. Strings.** ASCII (`[\x20-\x7e]{4,}`, 10,366 strings) and UTF-16 extraction, filtered by keyword. Because the binary is not obfuscated and logs with fmt-style `{}` placeholders, searching for `[{}` and `{}]:` recovered component names (`RBXClient`, `XenoServer`, `::Loadstring`, `::PlayerRemoving`, `::UnlockModule`, …) and most of the attach sequence. UTF-16 strings contained nothing of interest.

**5. Resources.** Besides the manifest, two resources of custom type `8194` (IDs `8192`, `8196`) with the same first five bytes and near-maximal entropy (≈7.99 bits/byte). Entropy alone cannot separate compression from encryption, since zstd output is also close to 8 bits/byte. What pointed to encryption was that neither blob began with the zstd magic even though the string `"Could not decompress a Xeno resource"` showed zstd was involved.

**6. Signature.** `Get-AuthenticodeSignature` returned `UnknownError`. That was originally read as "unsigned", but an unsigned file returns `NotSigned`; `UnknownError` typically means a signature is present and could not be validated. Sectigo time-stamping CA URLs also appear in the binary inside what look like DER certificate fragments. The question is open (F-04); the certificate-table size reported by `tools/sample_report.py` settles whether a signature blob exists.

**7. Targeted disassembly.** capstone at each export RVA, resolving RIP-relative operands to strings. This established calling conventions and object-field offsets for `Execute` and `GetClients`, the `Version` small-string pattern, the `Attach` thunk, and the `ntdll` resolution in `Initialize`.

**8. Timestamp.** The PE timestamp (2026-10-20) was first misread as forged. It precedes the analysis date and is a plausible build date.

## Phase 2 — Breaking the resource encryption

**1. Differential test.** XORing the two blobs against each other gave zeros for the shared prefix and high entropy afterwards. Identical ciphertext over an identical plaintext prefix (both are zstd frames) is what a fixed keystream produces; a block cipher in CBC mode with distinct IVs would not.

**2. Known plaintext.** Assuming the plaintext starts with the zstd magic `28 B5 2F FD`, XOR with the ciphertext prefix `16 48 7F B8` gives keystream bytes `3E FD 50 45`.

**3. Cross-references from strings.** For each resource error string, `.text` was scanned for `lea reg, [rip+disp]` (REX.W `8D`, ModRM mod=00 r/m=101) whose target is the string's RVA. This located the log sites (`0x190A97`, `0x18CD14`, `0x18CDC1`).

**4. The cipher.** Reading back from the log sites found the resource load sequence at `0x18CD06` and the transform at `0x1906B0`: a byte loop indexing a key by `i mod len`, with the key held as a begin/end pointer pair in `.data` (`0x252D18`/`0x252D20`).

**5. The key.** Those `.data` slots are zero in the file, so they are filled at runtime. A full-`.text` scan for stores to those addresses found one writer, a CRT dynamic initializer at `0x3B10` that allocates 32 bytes and writes eight immediate dwords. The first four bytes matched the known-plaintext result.

**6. Decryption.** XOR, check the magic, zstd-decompress (`tools/decrypt_resources.py`). Both resources decompressed to text: `CLIENT.LUA` (145,004 B) and Roblox's en-us table (336,884 B). Successful decompression of both is the decisive confirmation of the key.

**7. Client analysis.** `CLIENT.LUA` is unobfuscated Luau. It provided the attach target check, the container layout, the protocol, the execution loops, the remote channels and the service deny-list. Its line numbers are indexed in `payloads/README.md`.

**Lesson.** For an unobfuscated binary, the fastest path to a cipher is through its error messages: cross-reference them and read backwards.

## Phase 3 — Version comparison

`tools/update_sample.py` extracts `Xeno.dll` from each installer; `tools/compare_samples.py` diffs exports, imports, URLs, environment variables, resources, filtered strings and section sizes between two builds. Comparing v1.3.40 with v1.3.65 dated the attach rework, the Bytecode Patch Watcher and the `dwmapi.dll` import, and showed the resource key did not change.

## Phase 4 — Review and correction (November 2026)

A full review of the repository against the client source and the generated reports found claims that went further than the evidence, several technical errors, and a bug in `compare_samples.py` that limited the function-level import diff to one DLL. Corrections are listed at the end of `FINDINGS.md`. Each finding now carries a confidence level and an evidence reference, the tools gained a test suite (`tests/`) built on synthetic DLLs, and the redistributed payloads were replaced by hashes and a line index.

## Reproducing

With a legitimately obtained v1.3.65 installer in `app/`:

```bash
python tools/update_sample.py app/Xeno-v1.3.65.exe      # → sample/TEST.dll, SAMPLE_REPORT.md
python tools/decrypt_resources.py sample/TEST.dll payloads/
sha256sum payloads/xeno_resource_*.bin                  # compare with payloads/README.md
```

Disassembly listings in `ARCHITECTURE.md` can be checked at the stated RVAs in any disassembler.
