#!/usr/bin/env python3
"""IDM xref hunter v2 - scan .text for absolute immediates pointing at given VAs
(or auto-resolve string VAs from patterns), and disassemble the reference sites.

Usage:
  xref2.py va 0x788904 0x787fb0 ...
  xref2.py str "This is 30 day" "%s Full." ...
"""
import pefile, re, sys, struct
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

def cstr(off, n=300):
    e = blob.find(b"\x00", off, off + n)
    return blob[off:off + (e - off if e > 0 else n)].decode("latin-1")

def str_start(off):
    s = off
    while s > 0 and blob[s - 1] != 0:
        s -= 1
    return s

md = Cs(CS_ARCH_X86, CS_MODE_32)

def refs_to_va(va):
    needle = struct.pack("<I", va)
    out, pos = [], TEXT["raw"]
    end = TEXT["raw"] + TEXT["rawsize"]
    while True:
        i = blob.find(needle, pos, end)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out

def show(file_off, before=32, after=64, label=""):
    rva = off_to_rva(file_off)
    base_rva = rva - before
    fo = rva_to_off(base_rva)
    if fo is None:
        fo, base_rva = file_off, rva
    code = blob[fo:file_off + after]
    print(f"    --- disasm @ VA 0x{IMAGE_BASE+rva:08X} {label}")
    for ins in md.disasm(code, IMAGE_BASE + base_rva):
        mark = "  <== HERE" if ins.address == IMAGE_BASE + rva else ""
        print(f"      0x{ins.address:08X}  {ins.mnemonic:<9} {ins.op_str}{mark}")

def hunt_va(va, maxrefs=30):
    print("=" * 100)
    print(f"### VA 0x{va:08X}")
    r = refs_to_va(va)
    if not r:
        print("    no code refs")
    for i, f in enumerate(r[:maxrefs]):
        show(f)
    if len(r) > maxrefs:
        print(f"    ... {len(r)-maxrefs} more")

def hunt_str(pat):
    for m in re.finditer(re.escape(pat.encode()), blob):
        off = m.start()
        rva = off_to_rva(off)
        if rva is None:
            continue
        s = str_start(off)
        srva = off_to_rva(s)
        print(f"\n[STR] {pat!r} -> start VA 0x{IMAGE_BASE+srva:08X} : {cstr(s,200)!r}")

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "va":
        for a in sys.argv[2:]:
            hunt_va(int(a, 16))
    elif mode == "str":
        for p in sys.argv[2:]:
            hunt_str(p)
