# Briefing: Xeno executor (v1.3.65)

**For:** Roblox security and anti-cheat teams
**From:** Gavin Hatcher ([github.com/aauuzy](https://github.com/aauuzy))
**Date:** November 2026
**Status:** Defensive research. Not a vulnerability report: everything described requires the user to run Xeno on their own machine.

## What Xeno is

A free Windows Roblox script executor in wide use. Its scale cannot be established from public data (`docs/THREAT_ASSESSMENT.md` §2). The current public installer contains exactly the DLL analyzed here (`Xeno.dll` v1.3.65, SHA-256 `50318bc8…99049`).

## How it works

Xeno never loads a DLL or creates a thread in Roblox. It overwrites the bytecode of the built-in **en-us locale translation CoreScript module**, so Roblox runs Xeno's client as part of its own startup. That client talks to a **localhost HTTP server** in Xeno's DLL through `HttpService:RequestInternal`. User scripts run by having the DLL compile them and write the bytecode into a ModuleScript the client keeps `require()`ing. Memory offsets for each Roblox release are downloaded at runtime, which is why Xeno survives updates within hours.

## Key observations

1. Replaced CoreScript bytecode executes without an integrity check (G-1).
2. CoreScript context can reach arbitrary loopback ports over HTTP. This is Xeno's entire control plane (G-2).
3. Bytecode written into a `require()`d module from outside the process is executed (G-3).
4. Xeno's own deny-list suggests purchase, auth-cookie and messaging APIs may be reachable from its context (G-5, unverified).
5. Xeno harms its own users: every attached client runs code the developer publishes (`code.lua`), every script HTTP request leaks the user's hardware ID and game server, and fake "undetected" Xeno installers have spread an infostealer.

## Recommended actions

| Priority | Action | Effect on Xeno |
|---|---|---|
| 1 | Block loopback HTTP from client script contexts (C-2) | Removes its control plane |
| 1 | Record the en-us bytecode mismatch and CoreGui artifacts as telemetry (C-6, C-7) | Measures prevalence |
| 2 | Verify all CoreScript bytecode against the shipped build (C-1) | Removes its attach method |
| 2 | Reject out-of-band bytecode in `require()` (C-3) | Removes its execution method |
| 3 | Audit privileged APIs reachable from CoreScript context (C-5) | Protects executor users |

Details, risks and quick detection indicators: `docs/COUNTERMEASURES.md`.

## Evidence

Static analysis only; nothing was executed and no Roblox or Xeno infrastructure was contacted. Every claim in `docs/FINDINGS.md` carries an evidence reference and a confidence level. Disassembly, imports and signature were re-verified against the sample on 2026-11-10. Samples and the decrypted client are not redistributed; hashes are in `SAMPLE_REPORT.md` and `payloads/README.md`. Samples can be shared privately on request.

## Documents

| Document | Contents |
|---|---|
| `docs/THREAT_ASSESSMENT.md` | Prevalence, who is harmed, client observations G-1 to G-5, Xeno's dependencies |
| `docs/COUNTERMEASURES.md` | Ranked proposals and detection indicators |
| `docs/ARCHITECTURE.md` | Full technical design with disassembly |
| `docs/FINDINGS.md` | Every claim with evidence and confidence |
| `docs/DETECTION.md` | File, host, in-client and network indicators; YARA and scanner |
| `docs/LIMITATIONS.md` | What is not established |
