# Xeno (TEST.dll) Reverse Engineering & Detection Pack

Static-analysis project on `sample/TEST.dll` = **Xeno Roblox executor v1.3.65** (unsigned x86-64 DLL, "Rizve" / xeno.now). Defensive purpose: document the threat and detect it.

## Layout

```
├── README.md                        ← you are here
├── SAMPLE_REPORT.md                 ← AUTO-GENERATED snapshot of the current sample (do not edit)
├── docs/
│   ├── REVERSE_ENGINEERING_PROCESS.md   how the analysis was done (methodology)
│   ├── FINDINGS.md                      every fact recovered + IOC list
│   ├── TECHNICAL_DEEP_DIVE.md           disassembly, structs, crypto, protocol
│   └── DETECTION.md                     detection engineering guide (5 layers)
├── tools/
│   ├── decrypt_resources.py         XOR+zstd resource decryptor (works on any Xeno sample)
│   ├── xeno_detector.py             score-based PE scanner (≥60 = likely Xeno, heuristic)
│   ├── xeno_executor.yar            6-rule YARA pack (validated on this sample)
│   ├── update_sample.py             extracts Xeno.dll from a new installer → sample/TEST.dll
│   ├── sample_report.py             rewrites SAMPLE_REPORT.md for the current sample (auto-run by update_sample.py)
│   └── compare_samples.py           diffs two DLL versions → COMPARE_REPORT.md
├── payloads/
│   ├── xeno_client.lua              decrypted CLIENT.LUA — Xeno's in-game client (145 KB)
│   └── xeno_payload2.lua            decrypted resource 8196 — Roblox en-us translations (337 KB)
└── sample/                          ← local only, gitignored
    ├── TEST.dll                     current sample = Xeno v1.3.65 (handle as live malware)
    └── TEST-v1.3.40.dll             archived older build for comparison

Local-only (gitignored, not in the repo): `app/` — the Xeno installers the samples were extracted from;
and `COMPARE_REPORT.md` — auto-generated diff of v1.3.40 → v1.3.65.
```

## Samples and installers are NOT included

`sample/` and `app/` are listed in `.gitignore` on purpose: they hold live malware-adjacent binaries (Xeno DLLs and installers) and are not redistributed here. Every command below that mentions `sample/TEST.dll` or `app/Xeno-*.exe` needs you to supply those files yourself:

1. Create `sample/` and `app/` in the repo root.
2. Obtain a Xeno installer legitimately for analysis and put it in `app/`, e.g. `app/Xeno-v1.3.65.exe`.
3. Run `python tools/update_sample.py app/Xeno-v1.3.65.exe` to extract it to `sample/TEST.dll`.
4. Analyze only inside an isolated VM. Never run the DLL or installer on a machine you care about.

Without the samples you can still read the docs, use `tools/xeno_executor.yar` and `tools/xeno_detector.py` against your own files, and inspect the recovered scripts in `payloads/`.

## Licensing

Original code and documentation: MIT, see `LICENSE`. The files in `payloads/` are decrypted third-party content recovered from Xeno (`xeno_client.lua`) and Roblox (`xeno_payload2.lua`, locale strings). They are **not** covered by the MIT license, remain the property of their respective owners, and are included only for research and detection purposes.

## Detection caveat

The detector's score thresholds (≥60 likely Xeno, 30-59 executor-family) are heuristics. They are validated only against the two samples analyzed here, not a large benign corpus. Treat hits as leads, not verdicts.
## Version-tracking workflow

```bash
python tools/update_sample.py app/Xeno-v1.3.40.exe   # install a version as sample/TEST.dll
cp sample/TEST.dll sample/TEST-v1.3.40.dll           # archive it under a versioned name
python tools/update_sample.py app/Xeno-v1.3.65.exe   # install the newer one
python tools/compare_samples.py sample/TEST-v1.3.40.dll sample/TEST.dll
# → COMPARE_REPORT.md: exports/imports/URLs/key/resources/string diffs
```

## Quick start

```bash
python tools/xeno_detector.py sample/TEST.dll -v     # scan the sample (scores 365)
python tools/decrypt_resources.py sample/TEST.dll .  # re-derive the payloads yourself
yara tools/xeno_executor.yar sample/TEST.dll         # 4 rules fire
```

Reading order for the docs: `REVERSE_ENGINEERING_PROCESS.md` → `FINDINGS.md` → `TECHNICAL_DEEP_DIVE.md` → `DETECTION.md`.

## Key results in one paragraph

Xeno attaches to Roblox by **replacing the bytecode of the en-us locale translation ModuleScript** in `RobloxGui.Modules` (no foreign threads/DLLs), using per-version offsets downloaded at runtime. The DLL hosts a **localhost HTTP server** (`/f?e=<opcode>`, `/rq?` proxy) that the injected script polls. Resources are protected with a **32-byte repeating XOR key** (`3EFD5045…`, recovered) + zstd. Every attach also fetches and runs `https://x3no.pages.dev/code.lua` — a live remote-code-push channel. In-game, it leaves a `CoreGui` folder named after the client PID containing a `Message` named `DO NOT DELETE: BELONGS TO XENO` — the easiest detection point of all.
