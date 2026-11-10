# Countermeasures

Ways to detect, measure and disrupt Xeno, ranked by how much each would cost Xeno to work around. Observations `G-x` and dependencies come from [`THREAT_ASSESSMENT.md`](THREAT_ASSESSMENT.md); finding IDs from [`FINDINGS.md`](../research/FINDINGS.md).

These are proposals from outside analysis. The author has no visibility into Roblox's existing detections, and some of these may already be in place. Each proposal states its assumptions and risks so it can be evaluated quickly by people who do.

## 1. Platform hardening (durable)

### C-1 Verify CoreScript bytecode before it runs

**Breaks:** attach (G-1).
Compare each built-in CoreScript module's bytecode with the hash of what the release shipped, when it is loaded and periodically while the client runs. Cover every module under `RobloxGui` and `CorePackages`, not just en-us: checking one module only moves Xeno to the next.
**Cost to Xeno:** high. It would need a different way to get code into a privileged Luau context.
**Risks:** the check itself becomes a target, so it should live where Xeno cannot simply overwrite it. Performance cost depends on frequency.

### C-2 Restrict CoreScript HTTP to loopback

**Breaks:** the control plane (G-2), and with it execution, file access and the HTTP proxy.
Deny `HttpService:RequestInternal` (and equivalents) to `localhost`, `127.0.0.0/8` and `::1` from the client's script contexts, or limit CoreScript requests to an allowlist of Roblox hosts.
**Cost to Xeno:** high. Luau inside the client has no other channel to an outside process; Xeno would have to invent one through memory alone.
**Risks:** legitimate CoreScript or developer-tool traffic to loopback, if any exists, would break. That needs checking against Roblox's own usage. This is also the simplest change on this list.

### C-3 Reject externally written bytecode in `require()`

**Breaks:** script execution (G-3).
Track bytecode provenance: a ModuleScript created at runtime should only run bytecode produced by Roblox's own compile path. A module whose bytecode changed without going through that path should fail to load and be reported.
**Cost to Xeno:** high.
**Risks:** design work in the engine; must not affect legitimate dynamic modules.

### C-4 Make offset reuse harder

**Breaks:** Xeno's cheap cross-version updates (G-4).
Vary the layout of the structures Xeno reads between releases (field order, padding, encrypted pointers) so offsets cannot be aliased from one version to the next.
**Cost to Xeno:** medium per release, recurring. Does not stop Xeno, but turns "update within hours" into "re-reverse every build".
**Risks:** engineering and debugging cost for Roblox.

### C-5 Audit what CoreScript context can reach

**Addresses:** G-5.
Confirm whether purchase, authentication-cookie and messaging APIs are callable from the context Xeno's client runs in. If they are, gate them by caller as well as identity.
**Value:** protects Xeno's users (and any future executor's users) from malicious shared scripts and from the developer's remote code channel.

## 2. Detection and measurement (fast, brittle)

These rely on identifiers Xeno can change quickly. Their best use is counting how many sessions run Xeno and supporting ban waves, not lasting prevention.

| ID | Indicator | Layer | Evidence |
|---|---|---|---|
| C-6 | en-us translation module bytecode differs from the shipped original | Client integrity | F-30 |
| C-7 | `CoreGui` folder named with the client's own PID, containing `Pointer`, `Loadstring` and a `Message` named `DO NOT DELETE: BELONGS TO XENO`; `shared.__Xeno` set | Client integrity | F-70, F-71 |
| C-8 | ModuleScripts created and destroyed at high rate under one CoreGui folder, each `require()`d repeatedly | Client integrity | F-72 |
| C-9 | Loopback `RequestInternal` calls to `/f?e=`, `/ls?c=loadstring:`, `/qt?p=`, `/cb` | Client integrity | F-51, F-52 |
| C-10 | A process loading a module signed by the self-signed `CN=Rizve A` certificate (serial `3FDA0D2C31C5C2A84790E6E2F20D1306`) while holding a write handle to `RobloxPlayerBeta.exe` | Host (anti-cheat) | F-04 |
| C-11 | A process with a loopback HTTP listener that also holds memory-write access to the Roblox process | Host (anti-cheat) | F-50, F-86 |
| C-12 | Outbound requests carrying `exploit-guid` or `xeno-fingerprint` headers, or `User-Agent: Xeno/` | Any web service scripts contact | F-54 |

C-6 and C-8 are the hardest for Xeno to remove without changing how it works. C-7, C-10 and C-12 take minutes to change but are very specific while they last. File-level signatures for the DLL are in [`DETECTION.md`](DETECTION.md) and the [`detection/`](../../detection) folder.

**Prevalence.** C-6 or C-7 recorded as telemetry, without enforcement, would give Roblox the user count this repository cannot ([`THREAT_ASSESSMENT.md`](THREAT_ASSESSMENT.md) §2).

## 3. Infrastructure

Xeno depends on `x3no.pages.dev` for offsets (`ep.zst.enc`), the remote code channel (`code.lua`) and update checks, and on `xeno.now` / `xeno.onl` for distribution. Whether to pursue hosting-provider abuse reports or legal action is a decision for Roblox's legal and trust teams, not a technical measure. Expect it to delay Xeno rather than stop it, since hosting is easy to move.

## 4. Experience developers

Most of the visible damage depends on experiences trusting the client. Regardless of executor:

- Validate movement on the server: maximum speed, vertical travel without support, teleport distance between updates.
- Treat every RemoteEvent and RemoteFunction argument as attacker-controlled; check the caller, ranges, rate and game state.
- Keep currency, inventory and progression changes server-authoritative.
- Do not rely on client-side anti-exploit scripts as a boundary; Xeno runs with more privilege than any experience script and can read or disable them.

## 5. User safety

- **Impersonation malware.** Fake "undetected" Xeno installers have been used to spread a remote-access trojan and infostealer targeting Roblox and Discord tokens and browser credentials ([`THREAT_ASSESSMENT.md`](THREAT_ASSESSMENT.md) §3.4). Safety messaging aimed at players searching for executors could point this out.
- **Identifier leakage and remote code.** Xeno users are tracked by any script host (F-54) and run whatever the developer publishes as `code.lua` (F-63).

## 6. Suggested order

1. **C-2** first: one restriction, large effect, cheap to evaluate.
2. **C-6/C-7 as telemetry** at the same time, to measure prevalence before and after.
3. **C-1** and **C-3** as the durable fixes.
4. **C-5** as a user-protection audit.
5. **C-4** if the update arms race continues.
