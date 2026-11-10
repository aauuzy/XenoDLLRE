#!/usr/bin/env python3
"""Standalone decryptor for Xeno v1.3.65 embedded resources (type 8194).

Pipeline recovered from TEST.dll @ .text:0x1906B0:
    resource bytes  --XOR(32-byte repeating key)-->  zstd frame  --zstd-->  payload

Key recovered from the CRT dynamic initializer @ .text:0x3B10.

Usage: python decrypt_resources.py <dll> [out_dir]
"""
import io
import struct
import sys

import pefile
import zstandard as zstd

KEY = bytes.fromhex(
    "3EFD5045ED61BFCA57EFA192D0076696"
    "FDC5F72112BD49367A3FB319A92AF5BB"
)
RESOURCE_TYPE = "8194"


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

    walk(pe.DIRECTORY_ENTRY_RESOURCE)
    return blobs


def main():
    dll = sys.argv[1] if len(sys.argv) > 1 else "TEST.dll"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    pe = pefile.PE(dll)
    for name, blob in get_resources(pe).items():
        dec = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(blob))
        if dec[:4] != b"\x28\xb5\x2f\xfd":
            print(f"resource {name}: bad magic after XOR ({dec[:4].hex()}) - key mismatch?")
            continue
        out = zstd.ZstdDecompressor().stream_reader(io.BytesIO(dec)).read()
        path = f"{out_dir}/xeno_resource_{name}.bin"
        with open(path, "wb") as f:
            f.write(out)
        print(f"resource {name}: {len(blob)} -> {len(out)} bytes -> {path}")


if __name__ == "__main__":
    main()
