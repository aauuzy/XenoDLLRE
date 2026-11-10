# Threat assessment

What Xeno is used for, how widespread it appears to be, who it harms, and what its design reveals about where the Roblox client can be hardened. Finding IDs (`F-xx`) refer to `FINDINGS.md`. Countermeasures are in `COUNTERMEASURES.md`.

## 1. Summary

Xeno is a free, keyless script executor for the Windows Roblox client. It lets a user run arbitrary Luau inside their own client with an environment of roughly 160 functions aimed at cheating and game manipulation. It works without loading a DLL or creating a thread in Roblox: it replaces the bytecode of a built-in CoreScript module, then drives that code over a localhost HTTP server (F-30, F-40, F-50).

The main harm falls on other players and experience developers through cheating. Xeno's own users carry real risk too: the developer can push code into every attached client (F-63), every script HTTP request discloses the user's hardware ID (F-54), and the "undetected" branding is being used by malware campaigns. Xeno does not exploit a vulnerability in Roblox as the term is used in security: it requires the user to run it on their own machine. Its design does show specific places where the client trusts its own memory and network behaviour more than it needs to (§5).

## 2. Prevalence

There is no reliable public measurement of how many people use Xeno. What can be said, and how strong each piece is:

| Indicator | What it shows | Reliability |
|---|---|---|
| The author encounters Xeno users in most Roblox experiences he joins | Broad use across experiences | Anecdotal; one observer |
| The official Xeno Discord server has about 600,000 members (author's observation) | A large audience | Membership is not usage: it includes inactive and duplicate accounts and people who joined once |
| Third-party download pages claim figures such as "838,000+ users" or "183,415 users online" | Nothing verifiable | These pages are unofficial and often clones or SEO sites; figures are unsourced |
| A malware campaign has impersonated Xeno since early 2026 (§3.4) | Enough demand that criminals find Xeno worth impersonating | Strong as an indication of popularity; says nothing about the real user count |
| Xeno's update model (offsets downloaded at runtime, F-33) lets it keep working across Roblox releases without a new build | Sustained availability | Confirmed design |

**Conclusion.** Xeno is clearly widely used, but its scale cannot be established from public data, and this repository does not claim a number. Roblox can measure it directly: the in-client indicators in `COUNTERMEASURES.md` §2 (a modified en-us module, the `CoreGui/<pid>` container, `shared.__Xeno`) can count Xeno-attached sessions in telemetry without banning anyone.

## 3. Who is harmed

### 3.1 Other players

Xeno exposes input synthesis, property and signal access, metatable and function hooking (partly stubbed, F-48), HTTP, and file I/O to scripts shared through script hubs. In practice this enables movement cheats (flying, speed, teleport), automation, and abuse of each experience's remote events. Players in affected servers lose fair play; the harm is the same in kind as any executor's.

### 3.2 Experience developers

Most gameplay damage happens because an experience trusts what the client sends. Developers bear the cost: economy abuse, lost players, and time spent on anti-exploit work. Server-side validation is their main defense whatever the executor (`COUNTERMEASURES.md` §4).

### 3.3 Xeno's own users

- **Remote code channel.** Every attached client downloads `code.lua` from the developer's host and runs it with the full Xeno environment (F-63). Whoever controls that host, the developer or anyone who compromises the account, can run code in every attached session at once.
- **Identifier leakage.** Every script HTTP request sends the user's hardware ID as `exploit-guid` and `xeno-fingerprint`, plus their current server's JobId and PlaceId, to whatever host the script contacts (F-54). Script and webhook operators can track users across sessions and accounts.
- **Privileged APIs.** Xeno blocks its own scripts from purchase, authentication-cookie and messaging APIs (F-90). That implies the developers believe these APIs are reachable from the context Xeno's scripts run in; if so, a malicious shared script that got around the block, or the remote code channel, could act on the user's account. Reachability is unverified.
- **Account action.** Use violates Roblox's Terms of Use and risks moderation.

### 3.4 Impersonation malware

Bitdefender reported a campaign distributing a fake "undetected" Xeno through gaming forums and Discord communities. It installs a Java-based remote access trojan and infostealer that takes browser passwords and cookies, Discord and Roblox tokens, and cryptocurrency wallet data, and allows keylogging, screen and webcam capture, and remote command execution. The campaign began in early 2026, peaked in March 2026, and remained active as of August 2026 ([TechRadar, 4 August 2026](https://techradar.com/pro/security/new-malware-disguised-as-popular-roblox-cheat-tool-could-give-hackers-full-control-of-your-pc-including-the-webcam)).

### 3.5 Roblox

Trust in fair play, moderation and support load, and the ongoing engineering cost of the anti-cheat arms race.

## 4. How Xeno works, in brief

1. The Electron UI loads `Xeno.dll`, which downloads per-Roblox-version memory offsets (F-33) and starts a localhost HTTP server (F-50).
2. The DLL finds each Roblox client, locates the en-us locale translation ModuleScript under `RobloxGui.Modules`, and overwrites its bytecode with Xeno's client script (F-30).
3. Roblox loads that module as part of its own startup, so Xeno's client runs as a CoreScript. It builds a container in `CoreGui`, sets `shared.__Xeno`, fetches `code.lua`, and calls the DLL over loopback HTTP (F-70, F-71, F-63).
4. To run a user script, the DLL compiles it with an embedded Luau compiler and writes the bytecode into a ModuleScript the client is repeatedly `require()`ing; `require` returns the compiled function and the client runs it (F-40, F-41).
5. Everything else (file access, HTTP, clipboard, teleport queue) goes through `/f?e=<op>` and related endpoints on the localhost server (F-51, F-52).

Full detail: `ARCHITECTURE.md`.

## 5. What Xeno's design shows about the client

Each item below is inferred from the fact that Xeno works as documented. None is a vulnerability in the bounty sense, because all of them require the user to run Xeno on their own machine. They are the places where hardening would cost Xeno the most.

| ID | Observation | Basis | Confidence |
|---|---|---|---|
| G-1 | A built-in CoreScript module whose bytecode has been replaced in memory still loads and runs. Nothing checks the module's bytecode against what Roblox shipped before executing it. | F-30, F-73 | Inferred |
| G-2 | Code running as that CoreScript can send HTTP requests to arbitrary loopback ports through `HttpService:RequestInternal`. Xeno's entire control plane depends on this. | F-50, F-51; `P:122` uses `RequestInternal` | Strongly supported |
| G-3 | A ModuleScript created at runtime in `CoreGui` and then given bytecode written from outside the process is executed by `require()` without any provenance check. | F-40, F-42 | Inferred |
| G-4 | Roblox's internal object layout changes little enough between releases that Xeno can reuse ("alias") offsets across versions and update them remotely within hours. | F-33 | Inferred |
| G-5 | The context Xeno's scripts run in may reach purchase, authentication-cookie and messaging APIs, judging by Xeno's own deny-list. | F-90 | Unverified |

## 6. Xeno's structural dependencies

Each is something Xeno currently cannot work without. The cost column estimates how much engineering it would take Xeno to replace the dependency if Roblox removed it; these are the analyst's estimates.

| Dependency | Evidence | If broken | Estimated cost to Xeno |
|---|---|---|---|
| A built-in CoreScript module it can overwrite and that Roblox will load (en-us) | F-30 | No attach | High if all CoreScripts are integrity-checked; low if only en-us is (Xeno moves to another module) |
| Loopback HTTP from CoreScript context | G-2 | No control plane: no execution, files or HTTP proxy | High; Luau inside the client has no other channel to an outside process |
| Out-of-band bytecode in `require()`d modules | F-40, F-42 | No script execution | High |
| Runtime offsets from its own host | F-33 | No attach after each Roblox update until restored | Medium; hosting moves easily, but stable layouts are what make aliasing cheap |
| Fixed artifacts (`CoreGui/<pid>`, `Message`, `shared.__Xeno`) | F-70, F-71 | Detection only | Low; renaming takes minutes |
| Fixed signing certificate | F-04 | Detection only | Low; a new self-signed certificate takes minutes |
| Unchanged resource key | F-61 | Detection only | Low |

The pattern matters for prioritizing: the identifiers are cheap for Xeno to change and best used for measurement and ban waves; the execution primitives (G-1 to G-3) are expensive to replace and are where hardening has lasting effect.
