#!/usr/bin/env python3
"""Score-based scanner for Xeno-family executor DLLs (built from TEST.dll v1.3.65 analysis).

Usage: python xeno_detector.py <file-or-directory> [-v]

Scoring: every indicator has a weight; >= 60 = likely Xeno, 30-59 = executor-family
(suspicious), < 30 = no match. These thresholds are HEURISTICS: they have not been validated
against a large benign sample set, so expect possible false positives/negatives.
"""
import argparse
import io
import math
import os
import re
import struct
import sys
from collections import Counter

try:
    import pefile
except ImportError:
    sys.exit("pip install pefile")

XOR_KEY = bytes.fromhex(
    "3EFD5045ED61BFCA57EFA192D0076696"
    "FDC5F72112BD49367A3FB319A92AF5BB"
)

EXPORT_SET = {"Attach", "Execute", "GetClients", "Initialize", "SetSetting", "Version"}

INDICATORS = [
    # (id, weight, kind, needle(s))
    ("credit_rizve",        35, "str", [b"Xeno is only maintained by Rizve", b"rizve@xeno.onl"]),
    ("pdb_path",            35, "str", [b"Projects\\Xeno\\build\\Release\\net9.0-windows8.0\\Xeno.pdb"]),
    ("attach_module",       30, "str", [b"Intercepted translation module @",
                                        b"Attaching in-game using translation module."]),
    ("xeno_resource",       30, "str", [b"Could not decompress a Xeno resource"]),
    ("xeno_server",         20, "str", [b"Xeno Server is Live on http://localhost:"]),
    ("offsets_endpoint",    20, "str", [b"https://x3no.pages.dev/ep.zst.enc"]),
    ("env_vars",            15, "str", [b"%XENO_CLIENT_PID%", b"%XENO_SERVER_PORT%"]),
    ("port3110",            10, "str", [b"localhost:3110"]),
    ("xor_key",             35, "str", [XOR_KEY]),
    ("xor_key_init",        35, "str", [bytes.fromhex("C7003EFD5045C74004ED61BFCA")]),
    ("resource_hdr_8192",   30, "str", [bytes.fromhex("16487FB84D0D89C857FB8F914A912FDD")]),
    ("resource_hdr_8196",   30, "str", [bytes.fromhex("16487FB84D959CCF575B0C931A29EBA4")]),
    ("client_lua",          35, "str", [b"DO NOT DELETE: BELONGS TO XENO",
                                        b"v1.3.65 CLIENT.LUA"]),
    ("code_push_url",       20, "str", [b"https://x3no.pages.dev/code.lua"]),
    ("luau_fflags",         10, "str", [b"LuauSolverV2", b"LuauCompileInlineThreshold"]),
    ("zstd_errors",         10, "str", [b"ERROR_frameType_unknown", b"ERROR_blockChecksum_invalid"]),
]


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def scan_file(path, verbose=False):
    raw = open(path, "rb").read()
    hits, score = [], 0

    def add(ind):
        nonlocal score
        hits.append(ind[0])
        score += ind[1]

    for ind in INDICATORS:
        _, _, _, needles = ind
        if any(n in raw for n in needles):
            add(ind)

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            names = {s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
            matched = EXPORT_SET & names
            if len(matched) == len(EXPORT_SET):
                hits.append("export_contract_full")
                score += 25
            elif len(matched) >= 4:
                hits.append(f"export_contract_partial({len(matched)}/6)")
                score += 10
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            def walk(d, path_=()):
                for e in d.entries:
                    nm = e.name.string.decode() if e.name else str(e.id)
                    p = path_ + (nm,)
                    if hasattr(e, "directory"):
                        walk(e.directory, p)
                    elif p[0] == "8194":
                        hits.append(f"resource_type_8194(id={p[1]})")
                        nonlocal_score[0] += 20
            nonlocal_score = [0]
            walk(pe.DIRECTORY_ENTRY_RESOURCE)
            score += nonlocal_score[0]
        ts = pe.FILE_HEADER.TimeDateStamp
        import datetime
        if ts > datetime.datetime.now(datetime.UTC).timestamp():
            hits.append("future_timestamp")
            score += 5
    except pefile.PEFormatError:
        pass  # not a PE - string indicators still count (memory dumps, lua files)

    verdict = ("XENO (heuristic match)" if score >= 60
               else "executor-family (suspicious)" if score >= 30
               else "no match")
    return score, verdict, hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    paths = []
    if os.path.isdir(a.target):
        for root, _, files in os.walk(a.target):
            paths += [os.path.join(root, f) for f in files]
    else:
        paths = [a.target]

    for p in paths:
        score, verdict, hits = scan_file(p, a.verbose)
        if score >= 30 or a.verbose:
            print(f"{p}\n  score={score}  verdict={verdict}")
            for h in hits:
                print(f"    + {h}")


if __name__ == "__main__":
    main()
