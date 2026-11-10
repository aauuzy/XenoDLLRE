# Security assessment and disclosure

How the findings relate to Roblox's security boundaries, why nothing here has been reported as a vulnerability, and what this repository deliberately does not publish.

## Threat model

Roblox treats the game client as untrusted. Xeno runs only because a user installs it and lets it write into their own Roblox process. Anything that depends on that starting point is a person modifying software on their own device, which is a Terms of Use matter rather than a breach of a Roblox security boundary. Three categories need to be kept apart:

| Category | Who owns the problem | Examples in this research |
|---|---|---|
| Client-side manipulation by the device owner | Roblox anti-cheat and client integrity (detection, not vulnerability) | Bytecode replacement in the en-us module (F-30), execution loop (F-40), in-game artifacts (F-70–F-72) |
| Experiences accepting what a modified client sends | The experience developer (server-side validation) | Any gameplay advantage scripts gain; not analyzed here |
| A Roblox-controlled boundary crossed without the attacker already controlling the victim's machine | Roblox security (bounty-eligible) | **None established** |

## Classification of notable findings

**Attach and execution (F-30, F-40–F-46).** Detection intelligence. Valuable to anti-cheat work because it describes how the bytecode is replaced and which artifacts persist, but it requires native code with write access to the user's own Roblox process.

**Remote code channel (F-63).** Every attached client fetches and runs `code.lua` from the developer's host with the full Xeno environment. This is a risk to Xeno's users (whoever controls that host controls every attached session), not a Roblox vulnerability.

**Identifier leakage (F-54, F-92).** Script HTTP requests send the user's hardware identifier and current game server to any host a script contacts. This is a privacy risk to Xeno's users created by Xeno, not a Roblox issue.

**Service deny-list (F-90).** Xeno blocks its own scripts from purchase, authentication-cookie, analytics and messaging APIs and calls this "vulnerabilities mitigation". This suggests those APIs are reachable from the context Xeno's scripts run in, which would mean malicious scripts shared among Xeno users (or the `code.lua` channel) could act on the user's account. Reachability has not been tested. Even if confirmed, the precondition is still the user running Xeno, so it is user-safety information rather than a platform vulnerability.

## HackerOne position

Based on Roblox's HackerOne policy (version dated 2026-03-04, read 2026-11-10; always check the live policy before testing or submitting):

- Engine and client security work such as memory corruption, sandbox escapes and RCE chains is in scope, and minimal proofs of concept are accepted. Data-model bugs that let exploiters crash game servers are explicitly encouraged.
- The policy prohibits distributing executors, cheats or bypass frameworks; building telemetry-bypass frameworks; automating exploit deployment; developing reliable arbitrary-code chains against production clients without authorization; and testing against Roblox's server, control-plane or management infrastructure.

**Current status: no report submitted.** Nothing in this repository demonstrates a Roblox-controlled boundary being crossed. Submitting executor architecture or detection notes as a vulnerability would most likely be closed as not applicable.

**What would qualify.** A reproducible issue where content Roblox delivers or the engine processes (place files, replicated instances, network messages, assets) causes harm on a client or server that its owner did not consent to, without the attacker first running native code on that machine. For example, game-server-controlled data reaching a privileged script identity on clients, a server crash triggerable through the data model, or memory corruption in the engine reachable from game content. This research may suggest where to look; it does not show any such issue.

## What this repository does not publish

- The full decrypted `CLIENT.LUA` or the Roblox locale table (hashes and a line index only; `payloads/README.md`).
- Downloaded offsets, the contents of `ep.zst.enc`, or any Roblox memory layout.
- Any code that improves, repairs or hides an executor, or bypasses anti-cheat or telemetry.

## Research conduct

- Static analysis of locally held samples only.
- No requests to Roblox services, Xeno infrastructure or the referenced pastebin as part of the documented method.
- No other users' data accessed; personal information is limited to the attribution the Xeno developer publishes in the binary itself.

## Contact

Corrections to the analysis: open an issue in this repository. Suspected Roblox vulnerabilities must go to Roblox's HackerOne program, not to public issues.

## References

- Roblox HackerOne program: https://hackerone.com/roblox
- Policy version history: https://hackerone.com/roblox/policy_versions
- Roblox, "How to Report Security Exploits": https://en.help.roblox.com/hc/en-us/articles/360038516512-How-to-Report-Security-Exploits
