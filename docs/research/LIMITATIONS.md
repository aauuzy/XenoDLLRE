# Limitations

What this research does not establish, and why it matters for reading the other documents.

**Static analysis only.** No Xeno binary was executed. Behavior is reconstructed from code, strings, imports and the decrypted client script. Findings marked "Confirmed" are confirmed as present in the artifacts, not observed at runtime. Timing, ordering and error paths described in [`ARCHITECTURE.md`](ARCHITECTURE.md) may differ in practice.

**Two builds.** Only v1.3.40 and v1.3.65 were examined. Xeno updates frequently and its offsets and some code arrive at runtime (`ep.zst.enc`, `code.lua`), so the behavior of any given session can differ from what is described here without a DLL change.

**Partial disassembly.** The exported functions, the resource loader, the decrypt routine and the key initializer were disassembled. The internal attach routine, the server handlers, the write path into Roblox memory and the Bytecode Patch Watcher were not; their descriptions rest on log strings and client code. Field names (`hProcess`, `state`) are interpretations of how values are tested.

**Evidence availability.** Samples are not redistributed, so DLL-level evidence (RVAs, strings, imports) can only be checked by someone who obtains the same build. Hashes are given so they can confirm they have it. As of 2026-11-10 the public v1.3.65 installer still contains the analyzed DLL (F-08); that will change when Xeno updates.

**Detection validation.** The detector and YARA rules have been tested on two real builds, synthetic fixtures and this repository's text. There is no benign-corpus result and no measurement against other executors. Thresholds are heuristics.

**Generated reports.** [`SAMPLE_REPORT.md`](../../reports/SAMPLE_REPORT.md) was regenerated with the current tools on 2026-11-10. The committed [`COMPARE_REPORT.md`](../../reports/COMPARE_REPORT.md) was produced by a version of `compare_samples.py` whose function-level import diff covered only the first DLL, so its "Imported functions: No changes" line is not reliable; it needs regenerating with the v1.3.40 sample.

**Unresolved questions.** Listed at the end of [`FINDINGS.md`](FINDINGS.md). The most consequential are the actual script identity of the hijacked module and whether the APIs Xeno blocks for its users are reachable from it (F-47, F-90).

**Prevalence.** No public data establishes how many people use Xeno. Discord membership and third-party download figures are not usage counts ([`THREAT_ASSESSMENT.md`](../defense/THREAT_ASSESSMENT.md) §2).

**Countermeasures are proposals.** [`COUNTERMEASURES.md`](../defense/COUNTERMEASURES.md) is written without knowledge of Roblox's existing detections or internal constraints; some measures may already exist or be impractical.

**Scope.** This is research on one third-party executor. It says nothing about other executors, including Potassium, and does not by itself establish any vulnerability in Roblox (see [`DISCLOSURE.md`](../DISCLOSURE.md)).
