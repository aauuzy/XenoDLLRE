"""Tests for the analysis and detection tools.

Run from the repository root:  python -m unittest discover -s tests -v

The PE tests build small, harmless DLLs at test time (clang + lld-link + llvm-rc). They mimic
Xeno's structure (export names, an XOR+zstd type-8194 resource) without containing any Xeno
code. If the toolchain is missing, those tests are skipped rather than failed.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import zstandard  # noqa: E402

import compare_samples  # noqa: E402
import decrypt_resources  # noqa: E402
import xeno_detector  # noqa: E402

try:
    import yara
except ImportError:
    yara = None

KEY = xeno_detector.XOR_KEY
EXPORTS = ["Attach", "Execute", "GetClients", "Initialize", "SetSetting", "Version"]
TOOLCHAIN = all(shutil.which(t) for t in ("clang", "lld-link", "llvm-rc"))


def encrypt(payload, key=KEY):
    frame = zstandard.ZstdCompressor().compress(payload)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(frame))


def build_dll(workdir, name, exports, resource=None):
    """Build a minimal x64 DLL with the given exports and an optional type-8194 resource."""
    src = os.path.join(workdir, f"{name}.c")
    with open(src, "w") as f:
        for e in exports:
            f.write(f"__declspec(dllexport) int {e}(void) {{ return 0; }}\n")
        f.write("int unused_symbol(void) { return 0; }\n")
    obj = os.path.join(workdir, f"{name}.obj")
    subprocess.run(["clang", "--target=x86_64-pc-windows-msvc", "-c", src, "-o", obj], check=True)
    inputs = [obj]
    if resource is not None:
        blob = os.path.join(workdir, f"{name}.bin")
        with open(blob, "wb") as f:
            f.write(resource)
        rc = os.path.join(workdir, f"{name}.rc")
        with open(rc, "w") as f:
            f.write(f'8192 8194 "{os.path.basename(blob)}"\n')
        res = os.path.join(workdir, f"{name}.res")
        subprocess.run(["llvm-rc", "/fo", res, rc], check=True, cwd=workdir)
        inputs.append(res)
    out = os.path.join(workdir, f"{name}.dll")
    subprocess.run(["lld-link", "/dll", "/noentry", "/nodefaultlib", f"/out:{out}", *inputs],
                   check=True, capture_output=True)
    return out


class ResourceCryptoTests(unittest.TestCase):
    def test_round_trip(self):
        payload = b"print('benign')\n" * 100
        self.assertEqual(decrypt_resources.decrypt_blob(encrypt(payload)), payload)

    def test_wrong_key_returns_none(self):
        wrong = bytes(32)
        self.assertIsNone(decrypt_resources.decrypt_blob(encrypt(b"x" * 64, wrong)))

    def test_resource_decrypts_prefix_check(self):
        self.assertTrue(xeno_detector.resource_decrypts(encrypt(b"abc")))
        self.assertFalse(xeno_detector.resource_decrypts(b"\x00" * 16))
        self.assertFalse(xeno_detector.resource_decrypts(b"\x16\x48"))


class CertificateTableTests(unittest.TestCase):
    def test_unsigned_pe_has_empty_table(self):
        class Entry:
            VirtualAddress = 0
            Size = 0

        class Header:
            DATA_DIRECTORY = [Entry()] * 16

        class FakePE:
            OPTIONAL_HEADER = Header()

        self.assertEqual(xeno_detector.certificate_table(FakePE(), b"MZ" + b"\0" * 64), b"")


class DetectorTextTests(unittest.TestCase):
    def scan_bytes(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        try:
            return xeno_detector.scan_file(f.name)
        finally:
            os.unlink(f.name)

    def test_quoted_indicators_are_not_a_dll_verdict(self):
        text = b"Report: the DLL contains 'Xeno is only maintained by Rizve' and localhost:3110"
        score, verdict, hits = self.scan_bytes(text)
        self.assertEqual(verdict, "xeno strings (non-PE)")
        self.assertIn("credit_rizve", hits)

    def test_plain_text_is_no_match(self):
        self.assertEqual(self.scan_bytes(b"hello world")[1], "no match")

    def test_repository_files_never_get_a_pe_verdict(self):
        local_only = tuple(os.path.join(ROOT, d) + os.sep for d in ("sample", "app"))
        for path in xeno_detector.iter_paths(ROOT):
            if path.startswith(local_only) or "__pycache__" in path:
                continue
            verdict = xeno_detector.scan_file(path)[1]
            self.assertIn(verdict, ("no match", "xeno strings (non-PE)"), path)


class CompareTests(unittest.TestCase):
    def test_import_diff_covers_every_dll(self):
        old = {"A.dll": ["f1"], "B.dll": ["g1", "g2"], "C.dll": ["h1"]}
        new = {"A.dll": ["f1"], "B.dll": ["g1", "g3"], "D.dll": ["k1"]}
        added, removed = compare_samples.diff_imports(old, new)
        self.assertEqual(added, ["B.dll!g3", "D.dll!k1"])
        self.assertEqual(removed, ["B.dll!g2", "C.dll!h1"])


@unittest.skipUnless(TOOLCHAIN, "clang, lld-link and llvm-rc are required to build test DLLs")
class DetectorPETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="xenodllre_test_")
        cls.structural = build_dll(cls.tmp, "structural", EXPORTS, encrypt(b"benign\n" * 50))
        cls.exports_only = build_dll(cls.tmp, "exports_only", EXPORTS)
        cls.wrong_key = build_dll(cls.tmp, "wrong_key", EXPORTS, encrypt(b"benign\n" * 50, bytes(32)))
        cls.benign = build_dll(cls.tmp, "benign", ["DoWork"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_structural_match(self):
        score, verdict, hits = xeno_detector.scan_file(self.structural)
        self.assertEqual(verdict, "xeno (heuristic)")
        self.assertIn("export_contract_full", hits)
        self.assertIn("resource_8194_decrypts(id=8192)", hits)

    def test_exports_alone_stay_below_family_threshold(self):
        self.assertEqual(xeno_detector.scan_file(self.exports_only)[1], "no match")

    def test_rotated_key_build_is_family_not_xeno(self):
        score, verdict, hits = xeno_detector.scan_file(self.wrong_key)
        self.assertIn("resource_8194(id=8192)", hits)
        self.assertEqual(verdict, "executor-family (suspicious)")

    def test_benign_dll(self):
        self.assertEqual(xeno_detector.scan_file(self.benign)[:2], (0, "no match"))

    def test_decryptor_extracts_fixture(self):
        import pefile
        blobs = decrypt_resources.get_resources(pefile.PE(self.structural))
        self.assertEqual(decrypt_resources.decrypt_blob(blobs["8192"]), b"benign\n" * 50)

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_yara_rules(self):
        rules = yara.compile(os.path.join(ROOT, "tools", "xeno_executor.yar"))
        fired = lambda p: sorted(m.rule for m in rules.match(p))  # noqa: E731
        self.assertEqual(fired(self.structural), ["Executor_API_Generic", "Xeno_EncryptedResource"])
        self.assertEqual(fired(self.wrong_key), ["Executor_API_Generic"])
        self.assertEqual(fired(self.benign), [])


if __name__ == "__main__":
    unittest.main()
