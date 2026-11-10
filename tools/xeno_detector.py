#!/usr/bin/env python3
"""Score-based scanner for Xeno-family executor DLLs.

Built from static analysis of Xeno v1.3.40 and v1.3.65. See docs/DETECTION.md.

Usage: python xeno_detector.py <file-or-directory> [-v]

Verdicts:
  PE files     score >= 60  -> "xeno (heuristic)"
               score 30-59  -> "executor-family (suspicious)"
  non-PE files any hit      -> "xeno strings (non-PE)"  (memory dumps, scripts, reports)

Thresholds are heuristics validated only against two Xeno builds and the benign set described
in docs/DETECTION.md. Treat results as leads, not verdicts.
"""
import argparse
import datetime
import os
import sys

try:
    import pefile
except ImportError:
    sys.exit("pip install pefile")

XOR_KEY = bytes.fromhex(
    "3EFD5045ED61BFCA57EFA192D0076696"
    "FDC5F72112BD49367A3FB319A92AF5BB"
)
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
RESOURCE_TYPE = 8194
SIGNER_SUBJECT = b"Rizve A"
EXPORT_SET = {"Attach", "Execute", "GetClients", "Initialize", "SetSetting", "Version"}
PE_THRESHOLD_XENO = 60
PE_THRESHOLD_FAMILY = 30

STRING_INDICATORS = [
    ("credit_rizve",     35, [b"Xeno is only maintained by Rizve", b"rizve@xeno.onl"]),
    ("pdb_path",         35, [b"Projects\\Xeno\\build\\Release\\net9.0-windows8.0\\Xeno.pdb"]),
    ("attach_module",    30, [b"Intercepted translation module @",
                              b"Attaching in-game using translation module."]),
    ("xeno_resource",    30, [b"Could not decompress a Xeno resource"]),
    ("xeno_server",      20, [b"Xeno Server is Live on http://localhost:"]),
    ("offsets_endpoint", 20, [b"https://x3no.pages.dev/ep.zst.enc"]),
    ("env_vars",         15, [b"%XENO_CLIENT_PID%", b"%XENO_SERVER_PORT%"]),
    ("port3110",         10, [b"localhost:3110"]),
    ("xor_key_raw",      35, [XOR_KEY]),
    ("xor_key_init",     35, [bytes.fromhex("C7003EFD5045C74004ED61BFCA")]),
    ("client_lua",       35, [b"DO NOT DELETE: BELONGS TO XENO", b"CLIENT.LUA -- POST OPEN SOURCE"]),
    ("code_push_url",    20, [b"https://x3no.pages.dev/code.lua"]),
    ("luau_fflags",      10, [b"LuauSolverV2", b"LuauCompileInlineThreshold"]),
    ("zstd_errors",      10, [b"ERROR_frameType_unknown", b"ERROR_blockChecksum_invalid"]),
]


def resource_decrypts(blob, key=XOR_KEY):
    """True if the blob's first 4 bytes XOR the key prefix to the zstd frame magic."""
    return len(blob) >= 4 and bytes(b ^ k for b, k in zip(blob[:4], key)) == ZSTD_MAGIC


def iter_resources(pe):
    """Yield (type_id, name_id, data) for every leaf in the resource directory."""
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    image = pe.get_memory_mapped_image()
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(rtype, "directory"):
            continue
        for rname in rtype.directory.entries:
            if not hasattr(rname, "directory"):
                continue
            for lang in rname.directory.entries:
                off, size = lang.data.struct.OffsetToData, lang.data.struct.Size
                yield rtype.id, rname.id, image[off:off + size]


def certificate_table(pe, raw):
    """Bytes of the Authenticode certificate table (empty if the file is not signed)."""
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    return raw[entry.VirtualAddress:entry.VirtualAddress + entry.Size] if entry.Size else b""


def scan_pe(pe, raw):
    hits, score = [], 0
    if SIGNER_SUBJECT in certificate_table(pe, raw):
        hits.append("signer_rizve_cert")
        score += 35
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        names = {s.name.decode(errors="replace")
                 for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
        matched = EXPORT_SET & names
        if matched == EXPORT_SET:
            hits.append("export_contract_full")
            score += 25
        elif len(matched) >= 4:
            hits.append(f"export_contract_partial({len(matched)}/6)")
            score += 10
    for rtype, rname, blob in iter_resources(pe):
        if rtype != RESOURCE_TYPE:
            continue
        if resource_decrypts(blob):
            hits.append(f"resource_{RESOURCE_TYPE}_decrypts(id={rname})")
            score += 35
        else:
            hits.append(f"resource_{RESOURCE_TYPE}(id={rname})")
            score += 5
    return score, hits


def scan_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    hits, score = [], 0
    for name, weight, needles in STRING_INDICATORS:
        if any(n in raw for n in needles):
            hits.append(name)
            score += weight

    try:
        pe = pefile.PE(data=raw, fast_load=True)
    except pefile.PEFormatError:
        return score, ("xeno strings (non-PE)" if hits else "no match"), hits

    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
    ])
    pe_score, pe_hits = scan_pe(pe, raw)
    score += pe_score
    hits += pe_hits
    if pe.FILE_HEADER.TimeDateStamp > datetime.datetime.now(datetime.UTC).timestamp():
        hits.append("note:future_timestamp")

    if score >= PE_THRESHOLD_XENO:
        verdict = "xeno (heuristic)"
    elif score >= PE_THRESHOLD_FAMILY:
        verdict = "executor-family (suspicious)"
    else:
        verdict = "no match"
    return score, verdict, hits


def iter_paths(target):
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                yield os.path.join(root, f)
    else:
        yield target


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="file or directory to scan")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every file and all hits")
    a = ap.parse_args()

    for p in iter_paths(a.target):
        try:
            score, verdict, hits = scan_file(p)
        except OSError as e:
            print(f"{p}\n  error: {e}", file=sys.stderr)
            continue
        if verdict != "no match" or a.verbose:
            print(f"{p}\n  score={score}  verdict={verdict}")
            for h in hits:
                print(f"    + {h}")


if __name__ == "__main__":
    main()
