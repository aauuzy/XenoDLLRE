# Detection

Indicators and detection approaches for Xeno, derived from `FINDINGS.md`. Each section states which layer a defender needs access to, how specific the indicator is, and how it can fail.

**Validation status.** The tools have been checked against two Xeno builds (v1.3.40 by the author; v1.3.65 by the author and again on 2026-11-10 with the current tools), against synthetic DLLs that reproduce Xeno's export set and resource layout (`tests/`), and against the text files in this repository. They have **not** been run against a large benign corpus or against other executors. No accuracy figures are claimed.

## Tools

| Tool | Input | Output |
|---|---|---|
| `tools/xeno_detector.py` | File or directory | Score and verdict per file |
| `tools/xeno_executor.yar` | File, process memory, or capture | Matching rules |

### Detector scoring

PE files are scored on product-unique strings and three structural checks: a certificate table naming the `Rizve A` signer (+35), the full six-export interface (+25), and a type-8194 resource whose first four bytes decrypt to the zstd magic under the known key (+35 each). Verdicts: ≥60 `xeno (heuristic)`, 30–59 `executor-family (suspicious)`.

Non-PE files (memory dumps, scripts, reports) get `xeno strings (non-PE)` if any string indicator is present. They never receive a DLL verdict; a document that quotes Xeno strings, including this one, would otherwise score as Xeno.

Expected behavior, covered by tests:

| Input | Verdict |
|---|---|
| Xeno v1.3.65 DLL | `xeno (heuristic)`, score 370; YARA file rules HighConf, Signer_Certificate, ResourceKey_Initializer, EncryptedResource and API_Generic fire |
| DLL with the six exports and a resource encrypted with the known key | `xeno (heuristic)` |
| Same, but the resource key differs (simulates a key rotation) | `executor-family (suspicious)` |
| DLL with only the six exports | `no match` |
| Unrelated DLL | `no match` |
| Repository text files | `no match` or `xeno strings (non-PE)` |

### YARA rules

| Rule | Scope | What it matches | False-positive considerations |
|---|---|---|---|
| `Xeno_Executor_DLL_HighConf` | File | MZ header and 2 of 10 product strings / PDB path | Requires a PE; low risk |
| `Xeno_Signer_Certificate` | File | Authenticode signature by the self-signed `Rizve A` certificate (subject and serial) | Very specific; stops matching when the certificate is renewed or replaced (expires 2027-05-10). Requires YARA built with OpenSSL |
| `Xeno_ResourceKey_Initializer` | File | Key immediates as emitted by the initializer | Specific to this compiler output; breaks on key rotation or code-generation changes |
| `Xeno_ResourceKey_Memory` | Memory | The 32-byte key as contiguous bytes | Any file or report containing the raw key bytes |
| `Xeno_EncryptedResource` | File | Type-8194 resource beginning `16 48 7F B8` | Independent of payload size and version while the key is unchanged; tested on synthetic DLLs and v1.3.65 |
| `Xeno_ClientLua_Payload` | Memory, file | 3 of 8 distinctive `CLIENT.LUA` strings | Matches documents that quote them |
| `Xeno_Server_Protocol` | Memory, capture | 4 of 7 protocol strings | Matches documents that quote them, including this repository |
| `Executor_API_Generic` | File | All six export names | Names are generic; triage only |

An earlier revision matched 16 bytes of each encrypted resource. Bytes 5 onward include the zstd frame header, which encodes the content size and so changes with every build. The current rule matches only the 4-byte encrypted magic within a type-8194 resource.

## Layer 1 — Files on disk

Product strings, the PDB path, the signing certificate, the key initializer, and the encrypted resources together identify Xeno builds with high specificity. The export set alone does not. Forks that strip branding would still match the structural checks while the key is unchanged. A key rotation would defeat the key-based checks; `tools/sample_report.py` attempts automatic recovery from the initializer pattern.

## Layer 2 — Host behavior (EDR, Sysmon)

| Observable | Specificity | Notes |
|---|---|---|
| A non-Roblox process opens `RobloxPlayerBeta.exe` with memory-write access and writes to it | Medium | Shared by all external executors and some overlays; telemetry needs handle or `WriteProcessMemory`-class events |
| Process sets `XENO_CLIENT_PID`, `XENO_SERVER_PORT`, `XENO_VERSION` | High | Inferred from the `%…%` placeholders; how they are set is not traced |
| `Xeno` directory with `workspace`, `autoexec` and a cache file | High | Location not established |
| Loopback HTTP listener in the same process, receiving `POST /f?e=<int>`, `/ls?c=`, `/rq?c=` | High | Requires loopback capture or a host-based proxy |
| Outbound HTTPS to `x3no.pages.dev`, `xeno.now`, `xeno.onl`, `pastebin.com/raw/A7n0vJtR` | High (domains) | Domains can change without a DLL update |

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

Loopback traffic is described above. Outbound, the client requests `version.txt` and `code.lua` from `x3no.pages.dev` on attach, and the DLL requests `ep.zst.enc` on startup if the primary offsets source fails. Proxied script requests carry `User-Agent: Xeno/<version>` by default, `exploit-guid` and `xeno-fingerprint` (the user's hardware identifier), and `roblox-place-id`, `roblox-game-id`, `roblox-session-id`, on traffic that is not going to Roblox. Any web service that Xeno scripts call can see these headers, which makes them the simplest server-side signal available outside Roblox (for example to operators of script-hosting or webhook endpoints).

## Running the tests

```bash
pip install pefile zstandard yara-python
python -m unittest discover -s tests -v
```

The PE tests build harmless DLLs with `clang`, `lld-link` and `llvm-rc`; they are skipped if those tools are missing.

## Next steps for validation

1. Scan a benign corpus (a Windows `System32` copy, common game and overlay DLLs) and record any hits.
2. Scan other executor builds that are legitimately available, to measure family-level overlap.
3. Regenerate `COMPARE_REPORT.md` with the current tools once the v1.3.40 sample is available.
