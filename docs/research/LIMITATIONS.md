# Limitations

What this research does not establish, and why it matters for reading the other documents.

**Static analysis only.** No Xeno binary was executed. Behavior is reconstructed from code, strings, imports and the decrypted client script. Findings marked "Confirmed" are confirmed as present in the artifacts, not observed at runtime. Timing, ordering and error paths described in [`ARCHITECTURE.md`](ARCHITECTURE.md) may differ in practice.

**Two builds.** Only v1.3.40 and v1.3.65 were examined. Xeno updates frequently and its offsets and some code arrive at runtime (`ep.zst.enc`, `code.lua`), so the behavior of any given session can differ from what is described here without a DLL change.

**Partial disassembly.** The exported functions, the resource loader, the decrypt routine and the key initializer were disassembled. The attach routines, the execution path, the patch watcher, the offsets fetch and the Discord code were mapped by cross-reference ([`tools/xrefs.py`](../../tools/xrefs.py)): which strings, imports and globals each function uses, and which functions call it. Cross-references show where `WriteProcessMemory` is called and in what order relative to the log strings. They do not show what bytes are written or to which Roblox structure; those parts of the descriptions still rest on the client code. The index sees only RIP-relative references and direct calls in functions with `.pdata` entries, so "not referenced" means "not referenced directly". The server's request handlers were not traced beyond the dispatcher.

**Evidence availability.** Samples are not redistributed, so DLL-level evidence (RVAs, strings, imports) can only be checked by someone who obtains the same build. Hashes are given so they can confirm they have it. As of 2026-11-10 the public v1.3.65 installer still contains the analyzed DLL (F-08); that will change when Xeno updates.

**Detection validation.** The detector and YARA rules are tested on two real builds (pinned by [`tests/test_samples.py`](../../tests/test_samples.py)), synthetic fixtures and this repository's text. There is no benign-corpus result and no measurement against other executors. Thresholds are heuristics. The signer YARA rule has not been run on a YARA build with OpenSSL; the certificates it targets were checked with OpenSSL directly.

**Generated reports.** [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) and [`COMPARE_REPORT.md`](../../reports/COMPARE_REPORT.md) were both regenerated with the current tools on 2026-11-10, the latter from the real v1.3.40 and v1.3.65 samples.

**Unresolved questions.** Listed at the end of [`FINDINGS.md`](FINDINGS.md). The most consequential are the actual script identity of the hijacked module and whether the APIs Xeno blocks for its users are reachable from it (F-47, F-90).

**Prevalence.** No public data establishes how many people use Xeno. Discord membership and third-party download figures are not usage counts ([`THREAT_ASSESSMENT.md`](../defense/THREAT_ASSESSMENT.md) §2).

**Countermeasures are proposals.** [`COUNTERMEASURES.md`](../defense/COUNTERMEASURES.md) is written without knowledge of Roblox's existing detections or internal constraints; some measures may already exist or be impractical.

**Scope.** This is research on one third-party executor. It says nothing about other executors, including Potassium, and does not by itself establish any vulnerability in Roblox (see [`DISCLOSURE.md`](../DISCLOSURE.md)).
