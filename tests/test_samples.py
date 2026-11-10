"""Regression tests against the real Xeno samples.

Run from the repository root:  python -m unittest discover -s tests -v

These tests pin the findings that the documentation cites from the binaries (detector scores,
YARA matches, resource hashes, export addresses, and the cross-references behind F-17, F-31,
F-34, F-36, F-55, F-83, F-86 and F-98). They read the samples as data only; nothing is loaded or
executed.

Samples are not redistributed. Each test class is skipped unless the exact build is present at
sample/TEST.dll (v1.3.65) or sample/TEST-v1.3.40.dll, identified by SHA-256.
"""
import hashlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "detection"))

import pefile  # noqa: E402

import decrypt_resources  # noqa: E402
import xeno_detector  # noqa: E402

try:
    import yara
except ImportError:
    yara = None

try:
    import xrefs
except ImportError:  # capstone missing
    xrefs = None

V65 = os.path.join(ROOT, "sample", "TEST.dll")
V40 = os.path.join(ROOT, "sample", "TEST-v1.3.40.dll")
V65_SHA = "50318bc8d60477a2402440c4989611ba9640cf6a709b5ec9d4c44e3860e99049"
V40_SHA = "37e78bb4944ed7038c2fc5932e6631d244652d0c58431a8b4470800f3e462aaf"
MAIN_RULES = os.path.join(ROOT, "detection", "xeno_executor.yar")
SIGNER_RULES = os.path.join(ROOT, "detection", "xeno_signer.yar")


def sha256_file(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


HAVE_V65 = sha256_file(V65) == V65_SHA
HAVE_V40 = sha256_file(V40) == V40_SHA


def signer_rules():
    """Compiled signer rules, or None when YARA lacks OpenSSL (pe.signatures)."""
    try:
        return yara.compile(SIGNER_RULES)
    except yara.SyntaxError:
        return None


@unittest.skipIf(yara is None, "yara-python not installed")
class YaraCompileTests(unittest.TestCase):
    def test_main_rules_compile_without_openssl(self):
        # The main rule file must not depend on pe.signatures; if it did, a YARA build without
        # OpenSSL would reject the whole file and silently lose every rule.
        yara.compile(MAIN_RULES)
        with open(MAIN_RULES) as f:
            self.assertNotRegex(f.read(), r"\bin\s+pe\.signatures\b")


@unittest.skipUnless(HAVE_V65, "sample/TEST.dll (v1.3.65) not present")
class V65DetectionTests(unittest.TestCase):
    def test_detector(self):
        score, verdict, hits = xeno_detector.scan_file(V65)
        self.assertEqual((score, verdict), (370, "xeno (heuristic)"))
        self.assertEqual(set(hits), {
            "credit_rizve", "pdb_path", "attach_module", "xeno_resource", "xeno_server",
            "offsets_endpoint", "env_vars", "xor_key_init", "luau_fflags", "zstd_errors",
            "signer_rizve_cert", "export_contract_full",
            "resource_8194_decrypts(id=8192)", "resource_8194_decrypts(id=8196)"})

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_yara_main(self):
        fired = sorted(m.rule for m in yara.compile(MAIN_RULES).match(V65))
        self.assertEqual(fired, ["Executor_API_Generic", "Xeno_EncryptedResource",
                                 "Xeno_Executor_DLL_HighConf", "Xeno_ResourceKey_Initializer"])

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_yara_signer(self):
        rules = signer_rules()
        if rules is None:
            self.skipTest("YARA built without OpenSSL; pe.signatures unavailable")
        self.assertEqual([m.rule for m in rules.match(V65)], ["Xeno_Signer_Certificate"])

    def test_resources_decrypt_to_documented_hashes(self):
        blobs = decrypt_resources.get_resources(pefile.PE(V65))
        expected = {  # payloads/README.md
            "8192": (27985, 145004, "5fc6c57bd7f770f5a0da214b81b0594b26a921a759eb64f76b33dc12fadca3a6"),
            "8196": (62613, 336884, "14c9b23e99fafb330e271c283e9c498dbdc0c9a8dd1bf88c34211e190c7ba001"),
        }
        self.assertEqual(sorted(blobs), sorted(expected))
        for name, (enc, dec, digest) in expected.items():
            out = decrypt_resources.decrypt_blob(blobs[name])
            self.assertEqual(len(blobs[name]), enc, name)
            self.assertEqual(len(out), dec, name)
            self.assertEqual(hashlib.sha256(out).hexdigest(), digest, name)

    def test_exports(self):  # F-10
        pe = pefile.PE(V65)
        exports = {e.name.decode(): e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        self.assertEqual(exports, {
            "Attach": 0x18D3D0, "Execute": 0x18D400, "GetClients": 0x18D610,
            "Initialize": 0x18CA80, "SetSetting": 0x18D950, "Version": 0x18D3E0})

    def test_key_initializer(self):  # F-60
        pe = pefile.PE(V65)
        code = pe.get_memory_mapped_image()[0x3B30:0x3B30 + 13]
        self.assertEqual(code, bytes.fromhex("C7003EFD5045C74004ED61BFCA"))


@unittest.skipUnless(HAVE_V65 and xrefs is not None, "v1.3.65 sample or capstone missing")
class V65CrossReferenceTests(unittest.TestCase):
    """Cross-references behind the findings revised in the November 2026 verification pass."""

    @classmethod
    def setUpClass(cls):
        cls.ix = xrefs.Index(V65)

    def users(self, slot):
        return {f for f, _, _, _ in self.ix.refs.get(slot, [])}

    def import_users(self, name):
        return {f for s in self.ix.import_slot(name) for f in self.users(s)}

    def string_users(self, text):
        return {f for _, s, uses in self.ix.strings_matching(text) for f, _, _, _ in uses}

    def test_nt_pointers_only_touched_by_initialize(self):  # F-18, F-31
        slots = {
            "NtUnlockVirtualMemory": 0x251FD0, "NtLockVirtualMemory": 0x251FE0,
            "NtSuspendProcess": 0x251FC0, "NtResumeProcess": 0x251FE8,
            "NtReadVirtualMemory": 0x251FD8, "NtWriteVirtualMemory": 0x251FC8}
        for name, slot in slots.items():
            self.assertEqual(self.ix.resolved_slot(name), [slot], name)
            self.assertEqual(self.users(slot), {0x18CA80}, name)

    def test_attach_writes_use_win32_apis(self):  # F-30, F-31, F-86
        attach = self.string_users("Intercepted translation module")
        self.assertEqual(attach, {0x1124B0, 0x14D360})
        self.assertTrue(attach <= self.import_users("WriteProcessMemory"))
        self.assertTrue(attach <= self.import_users("ReadProcessMemory"))
        self.assertEqual(self.import_users("VirtualAllocEx"), {0x10D6B0})
        self.assertTrue({0x1124B0, 0x14D360} <= {c for _, c in self.ix.callers(0x10D6B0, 1)})
        self.assertEqual(self.ix.import_slot("CreateRemoteThread"), [])

    def test_attach_open_process_all_access(self):  # F-32
        self.assertIn(0x111C30, self.string_users("running with administrator privileges"))
        self.assertIn(0x111C30, self.import_users("OpenProcess"))

    def test_execute_path(self):  # F-13, F-41
        # Execute's thread procedure reaches the compile/write/verify function.
        self.assertIn(0x18E540, {c for _, c in self.ix.callers(0x117980, 1)})
        self.assertEqual(self.string_users("Failed to compile (this is a problem"), {0x117980})
        self.assertEqual(self.string_users("Could not verify that the execution module"), {0x117980})
        self.assertIn(0x117980, {c for _, c in self.ix.callers(0x10D6B0, 1)})

    def test_window_refresh_routine(self):  # F-36
        users = {self.ix.import_slot(n) and frozenset(self.import_users(n)) for n in
                 ("SetWindowPos", "RedrawWindow", "LockWindowUpdate", "DwmSetWindowAttribute")}
        self.assertEqual(users, {frozenset({0x111490})})
        self.assertEqual({c for d, c in self.ix.callers(0x111490, 1)}, {0x1124B0, 0x14D360})
        self.assertEqual(self.string_users("Using RefreshRBXWindowV2"), {0x1124B0, 0x14D360})

    def test_offsets_endpoints(self):  # F-33, F-34, F-66
        fetch = self.string_users("Successfully retrieved RBXClient data (Primary)")
        self.assertEqual(fetch, {0x1124B0})
        self.assertEqual(self.string_users("pastebin.com/raw/A7n0vJtR"), fetch)
        self.assertEqual(self.string_users("x3no.pages.dev/ep.zst.enc"), fetch)

    def test_named_pipes_are_discord_ipc(self):  # F-55
        self.assertEqual(self.import_users("WaitNamedPipeW"), {0x193D80})
        self.assertIn("\\\\?\\pipe\\discord-ipc-0", self.ix.wstrings_of(0x193D80))
        self.assertEqual(self.import_users("PeekNamedPipe"), {0x193EB0})

    def test_steam_registry_is_discord_rpc(self):  # F-83
        self.assertEqual(self.string_users("Error opening Steam key"), {0x193B50})
        self.assertIn("Software\\Valve\\Steam", self.ix.wstrings_of(0x193B50))
        self.assertIn("steam://rungameid/%s", " ".join(self.ix.wstrings_of(0x193B50)))
        self.assertIn(0x18D950, {c for _, c in self.ix.callers(0x193B50, 2)})

    def test_setting_zero_flag(self):  # F-17
        self.assertEqual(self.users(0x251FA9), {0x18D950, 0x18C910})
        self.assertEqual(self.string_users("Terminated same existing Xeno process"), {0x18C910})

    def test_hwid_in_request_dispatcher(self):  # F-82
        self.assertEqual(self.import_users("GetCurrentHwProfileW"), {0x150E10})


@unittest.skipUnless(HAVE_V40, "sample/TEST-v1.3.40.dll not present")
class V40Tests(unittest.TestCase):
    def test_detector(self):
        score, verdict, hits = xeno_detector.scan_file(V40)
        self.assertEqual((score, verdict), (325, "xeno (heuristic)"))
        self.assertNotIn("xor_key_init", hits)
        self.assertNotIn("zstd_errors", hits)

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_yara_main(self):
        fired = sorted(m.rule for m in yara.compile(MAIN_RULES).match(V40))
        self.assertEqual(fired, ["Executor_API_Generic", "Xeno_EncryptedResource",
                                 "Xeno_Executor_DLL_HighConf", "Xeno_ResourceKey_Initializer"])

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_yara_signer(self):
        rules = signer_rules()
        if rules is None:
            self.skipTest("YARA built without OpenSSL; pe.signatures unavailable")
        self.assertEqual([m.rule for m in rules.match(V40)], ["Xeno_Signer_Certificate"])

    def test_resources_same_key(self):  # F-61
        blobs = decrypt_resources.get_resources(pefile.PE(V40))
        expected = {
            "8192": (27793, 143847, "f9e9f59dd62b6328e119acde36d048e7468e2802b860233cf7bdfc4e32c06958"),
            "8196": (60487, 327903, "88dd355a194a3eea432c283f641e9d87fba1f730631d67fa349b835e10f0c4c7"),
        }
        for name, (enc, dec, digest) in expected.items():
            out = decrypt_resources.decrypt_blob(blobs[name])
            self.assertEqual((len(blobs[name]), len(out)), (enc, dec), name)
            self.assertEqual(hashlib.sha256(out).hexdigest(), digest, name)

    @unittest.skipIf(xrefs is None, "capstone not installed")
    def test_suspend_resume_called_and_attach_thread_input(self):  # F-31, F-98
        ix = xrefs.Index(V40)
        self.assertTrue(ix.import_slot("AttachThreadInput"))
        url_fn = {f for _, s, u in ix.strings_matching("pastebin.com/raw/A7n0vJtR") for f, _, _, _ in u}
        for name in ("NtSuspendProcess", "NtResumeProcess"):
            (slot,) = ix.resolved_slot(name)
            calls = {f for f, _, mn, _ in ix.refs[slot] if mn == "call"}
            self.assertEqual(calls, url_fn, name)
        (slot,) = ix.resolved_slot("NtWriteVirtualMemory")
        self.assertFalse([1 for _, _, mn, _ in ix.refs[slot] if mn == "call"])


if __name__ == "__main__":
    unittest.main()
