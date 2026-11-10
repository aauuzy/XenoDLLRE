# Recovered payloads

Xeno v1.3.65 embeds two encrypted resources (type `8194`, IDs `8192` and `8196`). Both decrypt with the repeating 32-byte XOR key and decompress with zstd (see `docs/ARCHITECTURE.md` §6). The decrypted files are **not redistributed** in this repository:

- `8192` is Xeno's working in-game client. Publishing it in full would amount to distributing an executor component, which Roblox's HackerOne policy prohibits and which adds nothing a reviewer cannot reproduce from a legitimately obtained sample.
- `8196` is Roblox's own en-us locale table. It is third-party content with no research value beyond its hash.

Earlier revisions of this repository (up to commit `0e2c4a1`) contained both files. They remain in git history.

## Reproducing

```bash
python tools/decrypt_resources.py sample/TEST.dll payloads/
```

This writes `xeno_resource_8192.bin` and `xeno_resource_8196.bin`. The `.gitignore` excludes them. Compare against the hashes below to confirm you have the same build.

| Resource | Encrypted size | Decrypted size | Lines | SHA-256 of decrypted file |
|---|---|---|---|---|
| `8194/8192` (CLIENT.LUA) | 27,985 | 145,004 | 4,874 | `5fc6c57bd7f770f5a0da214b81b0594b26a921a759eb64f76b33dc12fadca3a6` |
| `8194/8196` (en-us table) | 62,613 | 336,884 | 1 | `14c9b23e99fafb330e271c283e9c498dbdc0c9a8dd1bf88c34211e190c7ba001` |

## Line index for `CLIENT.LUA` (v1.3.65)

The documentation cites these line numbers as evidence. Each row describes the code briefly; read the file you decrypted yourself for full context.

| Lines | Content | Cited for |
|---|---|---|
| 1–12 | Header: `v1.3.65 CLIENT.LUA -- POST OPEN SOURCE`, maintainer and credits | Identification |
| 14 | Author note that some advertised functions are non-functional | Environment completeness |
| 16 | `local XENO_PID = "%XENO_CLIENT_PID%"` | Loader templating |
| 28–44 | `CoreGui` folder named after the PID, `Pointer` and `Loadstring` subfolders, `Message` named `DO NOT DELETE: BELONGS TO XENO` | In-game artifacts |
| 59 | `shared.__Xeno = Xeno` | In-game artifacts |
| 61–65 | `Urls` table: `version.txt`, `code.lua`, `http://localhost:%XENO_SERVER_PORT%` | Remote channels, control plane |
| 122 | `HttpService:RequestInternal(options):Start(...)`: the transport for all calls to the localhost server | Control plane (G-2) |
| 137–175 | `RServer`: `POST /f?e=<op>` with JSON `{c, p}`; custom endpoints send raw `text/plain`; a missing status is treated as 410 | Protocol |
| 193–227 | `XFS` opcode table, 0–21, plus client-only `WriteFile = -1` | Protocol |
| 309 | `RawHttpGet` | Remote channels |
| 396 | `if xRenv.script.Name == "en-us" then` | Attach target |
| 420–435 | `RServer({XFS.Activate, ''}, true)`; comment says it returns the HWID; random GUID fallback | HWID |
| 441–549 | `BlockedServiceFuncs`: services and methods Xeno denies to user scripts | Security significance |
| 575–577 | `GetDeviceAccessToken`, `GetDeviceIntegrityToken(Yield)` replaced with `Blocked` | Security significance |
| 1643 | Environment wrapper variant used for module identity checks | Execution wrapper |
| 1994–2080 | `Xeno.loadstring`: module named `loadstring:<random>[chunkName]`, source posted to `/ls?c=<name>&p=<pid>`, then op 20 / `require` / op 21 polling (2038–2040) with a 3 s timeout | Execution path B |
| 2157–2165 | Proxied request headers: `user-agent: Xeno/<version>`, `exploit-guid` and `xeno-fingerprint` (HWID), `roblox-place-id`, `roblox-game-id`, `roblox-session-id` | Protocol, identifier leakage |
| 2168–2169 | Requests to port 3110 refused | Protocol |
| 2174 | `/rq?c=` HTTP proxy | Protocol |
| 2839–2847 | `queue_on_teleport` posts to `/qt?p=` | Teleport queue |
| 2933 | `saveinstance` fetched from `luau/SynSaveInstance` on GitHub | Remote content |
| 3503–3516 | `getthreadidentity` returns a stored number (default 3); `setthreadidentity` only updates that number | Environment completeness |
| 4766 | Commented-out call to `XFS.CBlockFunctions`, an opcode absent from the table | Version drift |
| 4774–4802 | Teleport-queue replay and autoexec blocks, both commented out; they reference `XFS.GetQueueOnTeleport` and `XFS.GetAutoExecuteContents`, which are not in the table | Disabled features |
| 4813–4824 | Fetches `code.lua`; if longer than 3 bytes, runs it via `Xeno.loadstring(..., "XenoNotification")` with the Xeno environment | Remote code-push channel |
| 4826–4872 | `ExecutionListener`: local `require()` loop on a random-named ModuleScript; sends only op 21, after a function is returned | Execution path A |
