#!/usr/bin/env python3
"""update_sample.py
Extracts Xeno.dll from the Xeno Electron NSIS installer and installs it
as the workspace analysis sample at sample/TEST.dll (backing up the old one).

Usage:
    python tools/update_sample.py [path-to-installer.exe]

If no installer path is given, the workspace root and sample/ are searched
for a *.exe installer. After replacement the detector is run automatically
to confirm the new sample is identified.

Requires 7-Zip (auto-detected in common install locations, or set SEVEN_ZIP).
"""

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time

WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE    = os.path.join(WORKSPACE, "sample", "TEST.dll")
DETECTOR  = os.path.join(WORKSPACE, "detection", "xeno_detector.py")
REPORTER  = os.path.join(WORKSPACE, "tools", "sample_report.py")

SEVEN_ZIP_CANDIDATES = [
    os.environ.get("SEVEN_ZIP", ""),
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
    shutil.which("7z") or "",
]


def find_7z():
    for c in SEVEN_ZIP_CANDIDATES:
        if c and os.path.exists(c):
            return c
    sys.exit("ERROR: 7-Zip not found. Install it or set the SEVEN_ZIP env var.")


def find_installer():
    if len(sys.argv) > 1:
        exe = os.path.abspath(sys.argv[1])
        if not os.path.exists(exe):
            sys.exit(f"ERROR: installer not found: {exe}")
        return exe
    candidates = [p for p in glob.glob(os.path.join(WORKSPACE, "*.exe"))
                  + glob.glob(os.path.join(WORKSPACE, "sample", "*.exe"))]
    if not candidates:
        sys.exit("ERROR: no installer .exe found. Drop it in the workspace root "
                 "or pass its path: python tools/update_sample.py <installer.exe>")
    candidates.sort(key=os.path.getsize, reverse=True)
    return candidates[0]


def run_7z(args, cwd=None):
    cmd = [find_7z()] + args
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if result.returncode not in (0, 1):  # 7z returns 1 for warnings
        print(f"  STDERR: {result.stderr[:500]}")
        raise RuntimeError(f"7z exited with code {result.returncode}")
    return result.stdout


def find_files(root, name):
    return [os.path.join(dp, f)
            for dp, _, fs in os.walk(root)
            for f in fs if f.lower() == name.lower()]


def main():
    installer = find_installer()
    print(f"Installer: {installer} ({os.path.getsize(installer):,} bytes)")

    # ── Stage 1: extract the NSIS .exe ──────────────────────────
    stage1 = tempfile.mkdtemp(prefix="xeno_stage1_")
    print(f"[1/4] Extracting NSIS installer -> {stage1}")
    run_7z(["x", installer, f"-o{stage1}", "-y"])
    print(f"      Top-level items: {os.listdir(stage1)}")

    # ── Stage 2: extract inner electron archive if present ──────
    inner = (glob.glob(os.path.join(stage1, "**", "app-64.7z"), recursive=True)
             + glob.glob(os.path.join(stage1, "**", "app.7z"), recursive=True)
             + glob.glob(os.path.join(stage1, "**", "*.7z"), recursive=True))
    stage2 = tempfile.mkdtemp(prefix="xeno_stage2_")
    if inner:
        inner.sort(key=os.path.getsize, reverse=True)
        print(f"[2/4] Extracting inner archive: {inner[0]} -> {stage2}")
        run_7z(["x", inner[0], f"-o{stage2}", "-y"])
        search_root = stage2
    else:
        print("[2/4] No inner 7z found - searching stage1 directly")
        search_root = stage1
    print(f"      Search root contents: {os.listdir(search_root)[:20]}")

    # ── Stage 3: locate Xeno.dll ────────────────────────────────
    print(f"[3/4] Searching for Xeno.dll ...")
    matches = find_files(search_root, "Xeno.dll") or find_files(stage1, "Xeno.dll")
    if not matches:
        print("\nERROR: Xeno.dll not found in extracted content. Files seen:")
        for r, _, fs in os.walk(stage1):
            for f in fs:
                print(f"  {os.path.join(r, f)}")
        sys.exit(1)
    matches.sort(key=os.path.getsize, reverse=True)  # largest = real DLL, not a stub
    source_dll = matches[0]
    print(f"  Found: {source_dll} ({os.path.getsize(source_dll):,} bytes)")

    # ── Stage 4: install as sample/TEST.dll ─────────────────────
    if os.path.exists(SAMPLE):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        backup = SAMPLE + f".{stamp}.bak"
        shutil.copy2(SAMPLE, backup)
        print(f"[4/4] Backed up old sample ({os.path.getsize(SAMPLE):,} bytes) -> {backup}")
        os.chmod(SAMPLE, 0o777)  # clear read-only before overwrite
    else:
        print("[4/4] No existing sample - fresh install")
    shutil.copy2(source_dll, SAMPLE)
    print(f"  Installed new sample -> {SAMPLE} ({os.path.getsize(SAMPLE):,} bytes)")

    shutil.rmtree(stage1, ignore_errors=True)
    shutil.rmtree(stage2, ignore_errors=True)

    # ── Verify with the detector ────────────────────────────────
    print("\nRunning detector on the new sample...")
    subprocess.run([sys.executable, DETECTOR, SAMPLE, "-v"])

    # ── Regenerate the auto report ──────────────────────────────
    print("\nRegenerating reports/SAMPLE_REPORT.md ...")
    subprocess.run([sys.executable, REPORTER])

    print("\n[OK] Sample updated.")


if __name__ == "__main__":
    main()
