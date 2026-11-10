#!/usr/bin/env python3
"""xrefs.py
Static cross-reference index for an x64 PE built with MSVC. Used to tie log strings, imports and
runtime-resolved function pointers to the functions that use them.

Functions are taken from .pdata (chained unwind fragments are folded into their root function).
Each function is disassembled linearly with capstone; every RIP-relative operand and every
direct call/jmp target is recorded. Nothing is executed.

Usage:
    python tools/xrefs.py <dll> --string "<substring>"     functions referencing matching strings
    python tools/xrefs.py <dll> --import <name>             functions using an imported function
    python tools/xrefs.py <dll> --global 0x<rva>            functions reading or writing a global
    python tools/xrefs.py <dll> --func 0x<rva>              summary of one function
    python tools/xrefs.py <dll> --resolved <name>           functions calling a GetProcAddress-
                                                            resolved pointer (e.g. NtWriteVirtualMemory)
Add --callers N to also list callers up to N levels.

Limits: only functions with .pdata entries are indexed (leaf functions without unwind data are
missed); only RIP-relative operands and direct call/jmp targets are recorded, so pointers loaded
through a register, a vtable or a copied struct are invisible. "No reference found" therefore means
no direct reference, not proof that a value is never used.
"""

import argparse
import bisect
import collections
import re
import sys

import capstone
import pefile
from capstone import x86

STR_RE = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")


class Index:
    def __init__(self, path):
        self.pe = pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
        ])
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.img = pe.get_memory_mapped_image()
        self.sections = {s.Name.rstrip(b"\0").decode(): s for s in pe.sections}

        # imports: IAT slot RVA -> "dll!name"
        self.iat = {}
        for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in d.imports:
                name = imp.name.decode() if imp.name else f"#{imp.ordinal}"
                self.iat[imp.address - self.base] = f"{d.dll.decode()}!{name}"

        # functions from .pdata, folding chained fragments into their root
        frags = []
        for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
            root, ui, hops = e.struct.BeginAddress, e.unwindinfo, 0
            while ui is not None and ui.Flags & 0x4 and hops < 32:   # UNW_FLAG_CHAININFO
                parent = ui.get_chained_function_entry()
                if parent is None:
                    break
                root = parent.struct.BeginAddress
                ui = parent.unwindinfo
                hops += 1
            frags.append((e.struct.BeginAddress, e.struct.EndAddress, root))
        frags.sort()
        self.frags = frags
        self.frag_starts = [f[0] for f in frags]

        self.refs = collections.defaultdict(list)      # target rva -> [(func, insn_rva, mnemonic, op_str)]
        self.calls = collections.defaultdict(set)      # callee rva -> {caller func}
        self.func_refs = collections.defaultdict(list)  # func -> [(insn_rva, target, mnemonic, op_str)]
        self.func_calls = collections.defaultdict(set)  # func -> {callee}
        self._disassemble()

    def func_of(self, rva):
        i = bisect.bisect_right(self.frag_starts, rva) - 1
        if i >= 0 and self.frags[i][0] <= rva < self.frags[i][1]:
            return self.frags[i][2]
        return None

    def _disassemble(self):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for begin, end, root in self.frags:
            code = self.img[begin:end]
            for ins in md.disasm(code, begin):
                nxt = ins.address + ins.size
                for op in ins.operands:
                    if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                        tgt = nxt + op.mem.disp
                        self.refs[tgt].append((root, ins.address, ins.mnemonic, ins.op_str))
                        self.func_refs[root].append((ins.address, tgt, ins.mnemonic, ins.op_str))
                if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == x86.X86_OP_IMM:
                    tgt = ins.operands[0].imm
                    callee = self.func_of(tgt)
                    if callee is not None and callee != root:
                        self.calls[callee].add(root)
                        self.func_calls[root].add(callee)

    # ---- helpers -------------------------------------------------------------------------
    def string_at(self, rva, limit=200):
        sec = self.sections.get(".rdata")
        if sec is None or not (sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize):
            return None
        raw = self.img[rva:rva + limit]
        m = STR_RE.match(raw)
        if not m:
            return None
        end = m.end()
        if end < len(raw) and raw[end] != 0:
            return None
        return m.group().decode("ascii", "replace")

    def wstring_at(self, rva, limit=400):
        """UTF-16LE string at rva (MSVC wide literals), or None."""
        sec = self.sections.get(".rdata")
        if sec is None or not (sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize):
            return None
        m = re.match(rb"((?:[\x20-\x7e]\x00){4,})\x00\x00", self.img[rva:rva + limit])
        return m.group(1).decode("utf-16le") if m else None

    def wstrings_of(self, func):
        return [w for _, tgt, _, _ in self.func_refs.get(func, []) if (w := self.wstring_at(tgt))]

    def strings_matching(self, needle):
        out = []
        for tgt, uses in self.refs.items():
            s = self.string_at(tgt)
            if s and needle.lower() in s.lower():
                out.append((tgt, s, uses))
        return sorted(out)

    def import_slot(self, name):
        return [rva for rva, n in self.iat.items() if n.split("!")[1].lower() == name.lower()]

    def resolved_slot(self, name):
        """Global(s) that receive GetProcAddress(…, name): after the lea of the name string, find the
        next call through the GetProcAddress IAT slot, then the first `mov qword ptr [rip+X], rax`
        after that call. MSVC often schedules the store after the following lea, so the store
        immediately after the lea belongs to the previous lookup."""
        gpa = set(self.import_slot("GetProcAddress"))
        slots = set()
        for tgt, s, uses in self.strings_matching(name):
            if s != name:
                continue
            for func, ins_rva, mn, ops in uses:
                after = sorted(r for r in self.func_refs[func] if r[0] > ins_rva)
                called = False
                for r in after[:12]:
                    if not called:
                        called = r[2] == "call" and r[1] in gpa
                    elif r[2] == "mov" and r[3].startswith("qword ptr [rip") and r[3].endswith("rax"):
                        slots.add(r[1])
                        break
        return sorted(slots)

    def callers(self, func, depth):
        level, seen, out = {func}, {func}, []
        for d in range(1, depth + 1):
            nxt = set()
            for f in level:
                for c in self.calls.get(f, ()):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
                        out.append((d, c))
            level = nxt
        return out

    def summary(self, func):
        strs, imps, globs = [], [], []
        for ins_rva, tgt, mn, ops in self.func_refs.get(func, []):
            if tgt in self.iat:
                imps.append(self.iat[tgt])
            else:
                s = self.string_at(tgt)
                if s:
                    strs.append(s)
                elif ".data" in self.sections and self._in(".data", tgt):
                    globs.append(tgt)
        return strs, sorted(set(imps)), sorted(set(globs)), sorted(self.func_calls.get(func, ()))

    def _in(self, name, rva):
        s = self.sections[name]
        return s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize


def h(x):
    return f"0x{x:X}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--string")
    g.add_argument("--import", dest="imp")
    g.add_argument("--global", dest="glob")
    g.add_argument("--func")
    g.add_argument("--resolved")
    ap.add_argument("--callers", type=int, default=0)
    a = ap.parse_args()

    ix = Index(a.dll)
    funcs = set()
    if a.string:
        for tgt, s, uses in ix.strings_matching(a.string):
            print(f"string {h(tgt)} {s[:100]!r}")
            for func, ins, mn, ops in uses:
                print(f"    ref {h(ins)} in func {h(func)}")
                funcs.add(func)
    elif a.imp:
        for slot in ix.import_slot(a.imp):
            print(f"import {ix.iat[slot]} slot {h(slot)}")
            for func, ins, mn, ops in ix.refs.get(slot, []):
                print(f"    {mn:5} {h(ins)} in func {h(func)}")
                funcs.add(func)
    elif a.resolved:
        for slot in ix.resolved_slot(a.resolved):
            print(f"resolved {a.resolved} stored at global {h(slot)}")
            for func, ins, mn, ops in ix.refs.get(slot, []):
                print(f"    {mn:5} {h(ins)} in func {h(func)}  {ops}")
                funcs.add(func)
    elif a.glob:
        slot = int(a.glob, 16)
        for func, ins, mn, ops in ix.refs.get(slot, []):
            print(f"    {mn:5} {h(ins)} in func {h(func)}  {ops}")
            funcs.add(func)
    elif a.func:
        f = ix.func_of(int(a.func, 16))
        strs, imps, globs, callees = ix.summary(f)
        print(f"func {h(f)}  callers={len(ix.calls.get(f, ()))}  callees={len(callees)}")
        for s in strs:
            print(f"    str  {s[:110]!r}")
        for i in imps:
            print(f"    imp  {i}")
        funcs.add(f)
    if a.callers:
        for f in sorted(funcs):
            for d, c in ix.callers(f, a.callers):
                print(f"  {'  ' * d}caller L{d} {h(c)} (of {h(f)})")


if __name__ == "__main__":
    sys.exit(main())
