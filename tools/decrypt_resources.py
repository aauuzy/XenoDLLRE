#!/usr/bin/env python3
"""Decryptor for Xeno embedded resources (PE resource type 8194).

Pipeline recovered from the v1.3.65 DLL (.text:0x1906B0):
    resource bytes --XOR(32-byte repeating key)--> zstd frame --zstd--> payload

Key recovered from the CRT dynamic initializer at .text:0x3B10. Verified against v1.3.40 and
v1.3.65; other builds may use a different key (sample_report.py attempts automatic recovery).

Usage: python decrypt_resources.py <dll> [out_dir]
"""
import argparse
import io
import os
import sys

import pefile
import zstandard as zstd

KEY = bytes.fromhex(
    "3EFD5045ED61BFCA57EFA192D0076696"
    "FDC5F72112BD49367A3FB319A92AF5BB"
)
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
RESOURCE_TYPE = "8194"


def xor(data, key=KEY):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_blob(blob, key=KEY):
    """Return the decompressed payload, or None if the key does not produce a zstd frame."""
    dec = xor(blob, key)
    if dec[:4] != ZSTD_MAGIC:
        return None
    return zstd.ZstdDecompressor().stream_reader(io.BytesIO(dec)).read()


def get_resources(pe):
    img = pe.get_memory_mapped_image()
    blobs = {}

    def walk(d, path=()):
        for e in d.entries:
            name = e.name.string.decode() if e.name else str(e.id)
            p = path + (name,)
            if hasattr(e, "directory"):
                walk(e.directory, p)
            elif p[0] == RESOURCE_TYPE:
                off, sz = e.data.struct.OffsetToData, e.data.struct.Size
                blobs[p[1]] = img[off:off + sz]

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        walk(pe.DIRECTORY_ENTRY_RESOURCE)
    return blobs


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dll")
    ap.add_argument("out_dir", nargs="?", default=".")
    a = ap.parse_args()

    blobs = get_resources(pefile.PE(a.dll))
    if not blobs:
        sys.exit(f"no type-{RESOURCE_TYPE} resources in {a.dll}")
    os.makedirs(a.out_dir, exist_ok=True)
    for name, blob in blobs.items():
        out = decrypt_blob(blob)
        if out is None:
            print(f"resource {name}: no zstd magic after XOR - key differs in this build")
            continue
        path = os.path.join(a.out_dir, f"xeno_resource_{name}.bin")
        with open(path, "wb") as f:
            f.write(out)
        print(f"resource {name}: {len(blob)} -> {len(out)} bytes -> {path}")


if __name__ == "__main__":
    main()
