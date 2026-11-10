# Detection

Indicators and detection approaches for Xeno, derived from [`FINDINGS.md`](../research/FINDINGS.md). Each section states which layer a defender needs access to, how specific the indicator is, and how it can fail.

**Validation status.** The tools have been checked against two real Xeno builds (v1.3.40 and v1.3.65, both re-run on 2026-11-10 with the current tools and pinned by [`tests/test_samples.py`](../../tests/test_samples.py), which runs whenever the samples are present), against synthetic DLLs that reproduce Xeno's export set and resource layout (`tests/`), and against the text files in this repository. They have **not** been run against a large benign corpus or against other executors. No accuracy figures are claimed.

## Tools

| Tool | Input | Output |
|---|---|---|
| [`detection/xeno_detector.py`](../../detection/xeno_detector.py) | File or directory | Score and verdict per file |
| [`detection/xeno_executor.yar`](../../detection/xeno_executor.yar) | File, process memory, or capture | Matching rules; compiles on any YARA build |
| [`detection/xeno_signer.yar`](../../detection/xeno_signer.yar) | File | Signer certificate rule; needs YARA built with OpenSSL |

The signer rule is kept in its own file because `pe.signatures` exists only when YARA is built with OpenSSL, and the Windows `yara-python` wheels are not. When it shared a file with the other rules, such a build rejected the whole file and no rule loaded. Compile the two files separately, or catch the signer file's `SyntaxError` and continue without it.

### Detector scoring

PE files are scored on product-unique strings and three structural checks: a certificate table naming the `Rizve A` signer (+35), the full six-export interface (+25), and a type-8194 resource whose first four bytes decrypt to the zstd magic under the known key (+35 each). Verdicts: ≥60 `xeno (heuristic)`, 30–59 `executor-family (suspicious)`.

Non-PE files (memory dumps, scripts, reports) get `xeno strings (non-PE)` if any string indicator is present. They never receive a DLL verdict; a document that quotes Xeno strings, including this one, would otherwise score as Xeno.

The `env_vars` indicator name is historical: `%XENO_CLIENT_PID%`, `%XENO_SERVER_PORT%` and `%ROBLOX_CLIENT_VERSION%` are placeholders the DLL substitutes into the client source before compiling it, not environment variables (see Layer 2).

Expected behavior, covered by tests (real-sample rows by [`tests/test_samples.py`](../../tests/test_samples.py), the rest by [`tests/test_tools.py`](../../tests/test_tools.py)):

| Input | Verdict |
|---|---|
| Xeno v1.3.65 DLL | `xeno (heuristic)`, score 370; YARA HighConf, ResourceKey_Initializer, EncryptedResource and API_Generic fire, plus Signer_Certificate where YARA has OpenSSL |
| Xeno v1.3.40 DLL | `xeno (heuristic)`, score 325; YARA HighConf, ResourceKey_Initializer, EncryptedResource and API_Generic fire, plus Signer_Certificate where YARA has OpenSSL. The detector's `xor_key_init` does not fire because v1.3.40 builds the same key on the stack rather than through a heap pointer (the YARA rule covers both forms, the detector's literal pattern only the v1.3.65 one); `zstd_errors` does not fire because v1.3.40's zstd build lacks the `ERROR_*` name strings |
| DLL with the six exports and a resource encrypted with the known key | `xeno (heuristic)` |
| Same, but the resource key differs (simulates a key rotation) | `executor-family (suspicious)` |
| DLL with only the six exports | `no match` |
| Unrelated DLL | `no match` |
| Repository text files | `no match` or `xeno strings (non-PE)` |

### YARA rules

| Rule | Scope | What it matches | False-positive considerations |
|---|---|---|---|
| `Xeno_Executor_DLL_HighConf` | File | MZ header and 2 of 10 product strings / PDB path | Requires a PE; low risk |
| `Xeno_Signer_Certificate` ([`xeno_signer.yar`](../../detection/xeno_signer.yar)) | File | Authenticode signature by a self-signed `CN=Rizve A` certificate (subject and issuer). Known serials for v1.3.40 and v1.3.65 are in the rule's metadata | Survives the yearly certificate renewals seen so far (the subject stayed the same, the serial changed). Matches any other file self-signed with that name. Requires YARA built with OpenSSL |
| `Xeno_ResourceKey_Initializer` | File | Key immediates as stored by the initializer: through a heap pointer (v1.3.65) or on the stack (v1.3.40) | Breaks on key rotation or a new code-generation pattern |
| `Xeno_ResourceKey_Memory` | Memory | The 32-byte key as contiguous bytes | Any file or report containing the raw key bytes |
| `Xeno_EncryptedResource` | File | Type-8194 resource beginning `16 48 7F B8` | Independent of payload size and version while the key is unchanged; tested on synthetic DLLs, v1.3.40 and v1.3.65 |
| `Xeno_ClientLua_Payload` | Memory, file | 3 of 8 distinctive `CLIENT.LUA` strings | Matches documents that quote them |
| `Xeno_Server_Protocol` | Memory, capture | 4 of 7 protocol strings | Matches documents that quote them, including this repository |
| `Executor_API_Generic` | File | All six export names | Names are generic; triage only |

An earlier revision matched 16 bytes of each encrypted resource. Bytes 5 onward include the zstd frame header, which encodes the content size and so changes with every build. The current rule matches only the 4-byte encrypted magic within a type-8194 resource.

## Layer 1 — Files on disk

Product strings, the PDB path, the signing certificate, the key initializer, and the encrypted resources together identify Xeno builds with high specificity. The export set alone does not. Forks that strip branding would still match the structural checks while the key is unchanged. A key rotation would defeat the key-based checks; [`tools/sample_report.py`](../../tools/sample_report.py) attempts automatic recovery from the initializer pattern.

## Layer 2 — Host behavior (EDR, Sysmon)

| Observable | Specificity | Notes |
|---|---|---|
| A non-Roblox process opens `RobloxPlayerBeta.exe` with `PROCESS_ALL_ACCESS` (`0x1FFFFF`) and an inheritable handle, then calls `VirtualAllocEx` and `WriteProcessMemory` on it, with no `CreateRemoteThread`, `NtSuspendProcess` or `VirtualProtectEx` (F-31, F-32) | Medium | Remote allocation plus writes without a remote thread is less common than the full injection pattern, but other external executors and some overlays share it. Telemetry needs handle-open events with access masks (Sysmon event 10) or allocation/write events (ETW threat-intelligence provider). v1.3.40 additionally suspended and resumed the process around the attach |
| Same process opens other processes with `PROCESS_TERMINATE` and kills earlier copies of itself on start (F-84) | Low | Common single-instance behavior; useful only in combination |
| `Xeno` directory with `workspace`, `autoexec` and a cache file | High | Location not established |
| `HKCU\Software\Classes\discord-1393297926209405000` URL-protocol key (F-87) | High if present | Discord RPC registration code is present and reachable; whether Xeno triggers it is not established |
| Loopback HTTP listener in the same process, receiving `POST /f?e=<int>`, `/ls?c=`, `/rq?c=` | High | Requires loopback capture or a host-based proxy |
| Outbound HTTPS to `x3no.pages.dev`, `xeno.now`, `xeno.onl`; `pastebin.com/raw/A7n0vJtR` at each attach (primary offsets source, F-34) | High (domains) | Domains can change without a DLL update. The pastebin fetch happens before the Roblox process is written, so it marks an attach attempt |
| Named-pipe client connection to `\\.\pipe\discord-ipc-0` from the same process (F-55) | Low | Any Discord Rich Presence integration does this |

`%XENO_SERVER_PORT%`, `%XENO_VERSION%`, `%XENO_CLIENT_PID%` and `%ROBLOX_CLIENT_VERSION%` are not environment variables. They appear as Lua string literals in `CLIENT.LUA` (for example `local XENO_PID = "%XENO_CLIENT_PID%"`), so they can only take effect through text substitution before compiling. `Initialize` references the first two next to the resource loader (once per run), and the two attach routines reference the last two (per client). There is nothing to observe in the process environment.

## Layer 3 — Inside the Roblox client

These require code or checks running in the client, which is the domain of Roblox's client integrity and anti-cheat systems. A game server cannot observe client memory or CoreGui directly, and an experience's own scripts cannot read CoreGui.

| Observable | Specificity | Notes |
|---|---|---|
| `CoreGui` folder named with the client's own PID, containing `Pointer`, `Loadstring`, and `Message` "DO NOT DELETE: BELONGS TO XENO" | Very high | Trivial for the developer to rename in a future build |
| `shared.__Xeno` present | Very high | Same caveat |
| en-us translation module's bytecode differs from the shipped original | High | Persistent for the session; does not depend on branding |
| ModuleScripts created and destroyed at high frequency under one CoreGui folder, each `require()`d repeatedly | High | The polling loop runs every ~1 ms; it is local and produces no network traffic |
| `HttpService:RequestInternal` calls to `http://localhost:<port>/f?e=`, `/ls?c=loadstring:`, `/qt?p=`, `/cb` | High | Only after an execution (op 21), on each `loadstring` (ops 20/21), and on file and API calls; not a constant stream |
| Foreign bytecode in a module | High | Transient by design in v1.3.65 (Bytecode Patch Watcher); prefer the persistent signals above |

## Layer 4 — Network

Loopback traffic is described above. Outbound, the client requests `version.txt` and `code.lua` from `x3no.pages.dev` on attach, and the DLL requests `pastebin.com/raw/A7n0vJtR` at the start of each attach, then `ep.zst.enc` only if that fails. Proxied script requests carry `User-Agent: Xeno/<version>` by default, `exploit-guid` and `xeno-fingerprint` (the user's hardware identifier), and `roblox-place-id`, `roblox-game-id`, `roblox-session-id`, on traffic that is not going to Roblox. Any web service that Xeno scripts call can see these headers, which makes them the simplest server-side signal available outside Roblox (for example to operators of script-hosting or webhook endpoints).

## Running the tests

```bash
pip install pefile zstandard yara-python capstone
python -m unittest discover -s tests -v
```

[`tests/test_tools.py`](../../tests/test_tools.py) builds harmless DLLs with `clang`, `lld-link` and `llvm-rc` and skips those tests if the tools are missing. [`tests/test_samples.py`](../../tests/test_samples.py) runs against `sample/TEST.dll` and `sample/TEST-v1.3.40.dll` when their SHA-256 matches the analyzed builds, and skips otherwise. The signer-rule tests skip when YARA lacks OpenSSL.

## Next steps for validation

1. Scan a benign corpus (a Windows `System32` copy, common game and overlay DLLs) and record any hits.
2. Scan other executor builds that are legitimately available, to measure family-level overlap.
3. Run the signer rule on a YARA build with OpenSSL; it has only been checked by parsing both certificates with OpenSSL directly.
