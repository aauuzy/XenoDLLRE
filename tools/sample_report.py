#!/usr/bin/env python3
"""sample_report.py
Analyzes a Xeno DLL (default: sample/TEST.dll) and (re)writes reports/SAMPLE_REPORT.md.
The analysis is factored into analyze() so tools/compare_samples.py can reuse it.

Usage:  python tools/sample_report.py [dll-path] [-o report-path]
"""

import argparse
import datetime
import hashlib
import io
import os
import re
import sys

import pefile

WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(WORKSPACE, "detection"))
from xeno_detector import scan_file  # noqa: E402

SAMPLE    = os.path.join(WORKSPACE, "sample", "TEST.dll")
REPORT    = os.path.join(WORKSPACE, "reports", "SAMPLE_REPORT.md")

KNOWN_KEY = bytes.fromhex(
    "3EFD5045ED61BFCA57EFA192D0076696"
    "FDC5F72112BD49367A3FB319A92AF5BB"
)
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    from collections import Counter
    import math
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def display_path(path):
    """Workspace-relative path for files in the repo, bare file name otherwise."""
    rel = os.path.relpath(os.path.abspath(path), WORKSPACE)
    return os.path.basename(path) if rel.startswith("..") else rel


def get_resources(pe):
    img = pe.get_memory_mapped_image()
    blobs = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return blobs

    def walk(d, path=()):
        for e in d.entries:
            name = e.name.string.decode() if e.name else str(e.id)
            p = path + (name,)
            if hasattr(e, "directory"):
                walk(e.directory, p)
            else:
                off, sz = e.data.struct.OffsetToData, e.data.struct.Size
                blobs["/".join(p)] = img[off:off + sz]
    walk(pe.DIRECTORY_ENTRY_RESOURCE)
    return blobs


def recover_xor_key(text_bytes):
    """Yield 32-byte key candidates from `mov dword [reg], imm32` x8 stores
    (the CRT initializer pattern Xeno uses)."""
    pat = re.compile(
        rb"\xC7\x00(....)"
        rb"\xC7\x40\x04(....)\xC7\x40\x08(....)\xC7\x40\x0C(....)"
        rb"\xC7\x40\x10(....)\xC7\x40\x14(....)\xC7\x40\x18(....)\xC7\x40\x1C(....)",
        re.DOTALL)
    for m in pat.finditer(text_bytes):
        yield b"".join(m.groups())


def try_decrypt(blobs, key):
    out = {}
    for name, blob in blobs.items():
        if not name.startswith("8194/"):
            continue
        dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
        out[name] = dec if dec[:4] == ZSTD_MAGIC else None
    return out


def payload_info(dec):
    try:
        import zstandard as zstd
        raw = zstd.ZstdDecompressor().stream_reader(io.BytesIO(dec)).read()
        first = raw.split(b"\n", 1)[0][:80].decode(errors="replace")
        return len(raw), first
    except Exception as e:
        return None, f"decompress failed: {e}"


def analyze(path):
    """Full static profile of a Xeno-family DLL. Returns a plain dict."""
    raw = open(path, "rb").read()
    pe = pefile.PE(path)
    now = datetime.datetime.now(datetime.UTC).timestamp()

    data = {
        "path": path,
        "size": len(raw),
        "sha256": sha256(path),
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "timestamp_str": datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp_future": pe.FILE_HEADER.TimeDateStamp > now,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "cert_table_size": pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size,
        "imagebase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "sections": [{
            "name": s.Name.decode(errors="replace").rstrip("\x00"),
            "va": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
            "raw": s.SizeOfRawData, "chars": s.Characteristics,
        } for s in pe.sections],
        "exports": {},
        "imports": {},
        "versions": [],
        "urls": [],
        "env_vars": [],
        "resources": {},          # name -> {size, magic, entropy}
        "xor_key": None,          # hex str, "UNCHANGED", or None
        "xor_key_status": "none", # unchanged | rotated | failed | none
        "payloads": {},           # name -> {size, head}
        "detector": {},
    }

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                data["exports"][e.name.decode()] = hex(e.address)

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        data["imports"][entry.dll.decode()] = sorted(
            i.name.decode() for i in entry.imports if i.name)

    from collections import Counter
    vers = Counter(v.decode() for v in re.findall(rb"v\d+\.\d+\.\d+", raw))
    data["versions"] = [v for v, _ in vers.most_common(5)]

    strs = set(s.decode() for s in re.findall(rb"[\x20-\x7e]{6,}", raw))
    data["urls"] = sorted(s for s in strs if re.match(r"https?://", s)
                          and "sectigo" not in s and "usertrust" not in s)
    data["env_vars"] = sorted(s for s in strs if re.match(r"%XENO_", s))
    data["strings"] = strs  # used by compare_samples; trimmed there

    blobs = get_resources(pe)
    enc = {k: v for k, v in blobs.items() if k.startswith("8194/")}
    for k, v in enc.items():
        data["resources"][k] = {
            "size": len(v), "magic": v[:4].hex(), "entropy": round(entropy(v), 3)}

    if enc:
        dec_map = try_decrypt(blobs, KNOWN_KEY)
        if all(dec_map.get(k) for k in enc):
            data["xor_key"] = KNOWN_KEY.hex().upper()
            data["xor_key_status"] = "unchanged"
        else:
            text = pe.sections[0].get_data()
            for cand in recover_xor_key(text):
                dm = try_decrypt(blobs, cand)
                if all(dm.get(k) for k in enc):
                    dec_map = dm
                    data["xor_key"] = cand.hex().upper()
                    data["xor_key_status"] = "rotated"
                    break
            else:
                data["xor_key_status"] = "failed"
        if data["xor_key"]:
            for k, dec in dec_map.items():
                size, head = payload_info(dec)
                data["payloads"][k] = {"size": size, "head": head}

    score, verdict, hits = scan_file(path)
    data["detector"] = {"score": score, "verdict": verdict, "hits": hits}
    return data


# ── rendering ───────────────────────────────────────────────────

def render(d):
    L = []
    add = L.append
    add("# SAMPLE_REPORT.md — AUTO-GENERATED")
    add("")
    add("> **Do not edit.** Regenerated by `tools/sample_report.py` on every sample update.")
    add(f"> Generated: {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    add("")

    forged = " **(later than report time)**" if d["timestamp_future"] else ""
    add("## File identity")
    add("")
    add("| Attribute | Value |")
    add("|---|---|")
    add(f"| Path | `{display_path(d['path'])}` |")
    add(f"| Size | {d['size']:,} bytes |")
    add(f"| SHA-256 | `{d['sha256']}` |")
    add(f"| Machine | {d['machine']}{' (x86-64)' if d['machine'] == '0x8664' else ''} |")
    add(f"| PE timestamp | {d['timestamp_str']} UTC{forged} |")
    add(f"| Subsystem | {d['subsystem']} |")
    cert = (f"present ({d['cert_table_size']:,} bytes)" if d["cert_table_size"]
            else "absent (no Authenticode signature)")
    add(f"| Certificate table | {cert} |")
    add(f"| ImageBase | {d['imagebase']} |")
    add(f"| EntryPoint | {d['entrypoint']} |")
    add("")

    add("## Sections")
    add("")
    add("| Name | VA | VSize | Raw | Characteristics |")
    add("|---|---|---|---|---|")
    for s in d["sections"]:
        add(f"| `{s['name']}` | {hex(s['va'])} | {hex(s['vsize'])} | "
            f"{hex(s['raw'])} | {hex(s['chars'])} |")
    add("")

    add("## Exports")
    add("")
    if d["exports"]:
        add("| Name | RVA |")
        add("|---|---|")
        for n, r in sorted(d["exports"].items()):
            add(f"| `{n}` | {r} |")
    else:
        add("(none)")
    add("")

    if d["versions"]:
        add("## Version strings found")
        add("")
        for v in d["versions"]:
            add(f"- `{v}`")
        add("")

    add("## Imports (summary)")
    add("")
    add("| DLL | # functions |")
    add("|---|---|")
    for dll, names in sorted(d["imports"].items()):
        add(f"| `{dll}` | {len(names)} |")
    add("")

    add("## Encrypted resources")
    add("")
    if not d["resources"]:
        add("No type-8194 resources found (container format changed?).")
        add("")
    else:
        add("| Resource | Size | Magic | Entropy |")
        add("|---|---|---|---|")
        for k, r in sorted(d["resources"].items()):
            add(f"| `{k}` | {r['size']:,} | `{r['magic']}` | {r['entropy']:.3f} |")
        add("")
        status = d["xor_key_status"]
        if status == "unchanged":
            add(f"XOR key: **unchanged** (`{d['xor_key']}`)")
        elif status == "rotated":
            add(f"XOR key: **ROTATED - auto-recovered:** `{d['xor_key']}`")
        else:
            add("XOR key: **changed and not auto-recoverable** (manual recovery per "
                "`docs/research/METHODOLOGY.md`, Phase 2).")
        add("")
        if d["payloads"]:
            add("| Resource | Decrypted size | Payload head |")
            add("|---|---|---|")
            for k, p in sorted(d["payloads"].items()):
                size = f"{p['size']:,}" if p["size"] else "?"
                add(f"| `{k}` | {size} | `{p['head']}` |")
            add("")

    if d["urls"] or d["env_vars"]:
        add("## Network / config indicators")
        add("")
        for u in d["urls"]:
            add(f"- `{u}`")
        for e in d["env_vars"]:
            add(f"- `{e}`")
        add("")

    add("## Detector verdict")
    add("")
    add("```")
    add(display_path(d['path']))
    add(f"  score={d['detector']['score']}  verdict={d['detector']['verdict']}")
    for h in d["detector"]["hits"]:
        add(f"    + {h}")
    add("```")
    add("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Write SAMPLE_REPORT.md for a Xeno DLL.")
    ap.add_argument("dll", nargs="?", default=SAMPLE)
    ap.add_argument("-o", "--output", default=REPORT)
    a = ap.parse_args()
    dll, out = a.dll, a.output
    if not os.path.exists(dll):
        sys.exit(f"ERROR: not found: {dll}")
    d = analyze(dll)
    open(out, "w", encoding="utf-8").write(render(d))
    print(f"[OK] report written -> {out}")


if __name__ == "__main__":
    main()
