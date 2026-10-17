#!/usr/bin/env python3
"""Disassemble a VA range from IDMan.exe, annotating string/IAT-ish operands."""
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BIN = r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.exe.orig"
pe = pefile.PE(BIN, fast_load=True); pe.parse_data_directories()
IB = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, "rb").read()
SECS = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"), "va": s.VirtualAddress,
         "vsize": s.Misc_VirtualSize, "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData}
        for s in pe.sections]

def rva_to_off(rva):
    for s in SECS:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None

def va_to_off(va): return rva_to_off(va - IB)

def secname(rva):
    for s in SECS:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["name"]
    return "?"

def peek(va, n=64):
    o = va_to_off(va)
    if o is None: return None
    return blob[o:o+n]

def cstr(va, n=120):
    o = va_to_off(va)
    if o is None: return None
    e = blob.find(b"\x00", o, o+n)
    if e < 0: return None
    b = blob[o:e]
    if not b or any(c < 9 or (13 < c < 32) or c > 126 for c in b):
        return None
    return b.decode("latin-1")

md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(start_va, length=400):
    o = va_to_off(start_va)
    if o is None:
        print(f"0x{start_va:08X} unmapped"); return
    code = blob[o:o+length]
    for ins in md.disasm(code, start_va):
        ann = ""
        ops = ins.op_str
        # annotate absolute memory refs  [0xNNNNNNNN]
        import re
        for m in re.finditer(r"0x([0-9a-f]{6,8})", ops):
            t = int(m.group(1), 16)
            if t >= IB and va_to_off(t) is not None:
                s = cstr(t)
                if s: ann += f"  ; \"{s}\""
        print(f"0x{ins.address:08X}  {ins.mnemonic:<9} {ops}{ann}")

if __name__ == "__main__":
    a = int(sys.argv[1], 16)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    dis(a, n)
