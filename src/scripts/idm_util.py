#!/usr/bin/env python3
"""IDM helpers: resolve IAT entries, read strings, find direct callers (E8 rel32),
find function start by scanning back over int3 padding."""
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BIN = r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.exe.orig"
pe = pefile.PE(BIN, fast_load=True)
pe.parse_data_directories()
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, "rb").read()
SECS = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"), "va": s.VirtualAddress,
         "vsize": s.Misc_VirtualSize, "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData}
        for s in pe.sections]
TEXT = next(s for s in SECS if s["name"] == ".text")

def off_to_rva(off):
    for s in SECS:
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return s["va"] + (off - s["raw"])
    return None

def rva_to_off(rva):
    for s in SECS:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None

def va_to_off(va):
    return rva_to_off(va - IMAGE_BASE)

def cstr(va, n=400):
    off = va_to_off(va)
    if off is None:
        return "<unmapped>"
    e = blob.find(b"\x00", off, off + n)
    return blob[off:off + (e - off if e > 0 else n)].decode("latin-1")

# ---- IAT map ----
IAT = {}
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll = entry.dll.decode(errors="replace")
    for imp in entry.imports:
        if imp.address:
            IAT[imp.address] = f"{dll}!{imp.name.decode(errors='replace') if imp.name else 'ord'+str(imp.ordinal)}"

def iat_name(va):
    return IAT.get(va, "<not an import>")

md = Cs(CS_ARCH_X86, CS_MODE_32)

def callers_of(target_va, maxn=40):
    """Find E8 rel32 call sites whose target == target_va."""
    out = []
    start, end = TEXT["raw"], TEXT["raw"] + TEXT["rawsize"]
    pos = start
    while pos < end - 5:
        if blob[pos] == 0xE8:
            rel = struct.unpack("<i", blob[pos + 1:pos + 5])[0]
            src_rva = off_to_rva(pos)
            if src_rva is not None:
                tgt = IMAGE_BASE + src_rva + 5 + rel
                if tgt == target_va:
                    out.append(pos)
        pos += 1
    return out

def func_start(va):
    """Scan back from va over int3 padding to find the previous function start."""
    off = va_to_off(va)
    p = off - 1
    while p > 0 and blob[p] == 0xCC:
        p -= 1
    # p is last byte of previous function; walk back a bit to find its prologue
    return off_to_rva(p + 1) + IMAGE_BASE if p + 1 <= off else va

def show(va, before=48, after=80):
    off = va_to_off(va)
    rva = va - IMAGE_BASE
    base_rva = rva - before
    fo = rva_to_off(base_rva)
    if fo is None:
        fo, base_rva = off, rva
    code = blob[fo:off + after]
    for ins in md.disasm(code, IMAGE_BASE + base_rva):
        mark = "  <== HERE" if ins.address == va else ""
        print(f"    0x{ins.address:08X}  {ins.mnemonic:<9} {ins.op_str}{mark}")

if __name__ == "__main__":
    for a in sys.argv[1:]:
        va = int(a, 16)
        print("=" * 100)
        print(f"### VA 0x{va:08X}")
        print(f"  string: {cstr(va, 200)!r}" if va_to_off(va) is not None else "")
        print(f"  IAT: {iat_name(va)}")
        cs = callers_of(va)
        print(f"  direct callers (E8): {len(cs)}")
        for c in cs[:20]:
            print(f"    call @ VA 0x{IMAGE_BASE + off_to_rva(c):08X}")
