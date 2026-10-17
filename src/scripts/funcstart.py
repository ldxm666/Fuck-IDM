#!/usr/bin/env python3
"""Find candidate function starts by scanning back for int3 padding."""
import pefile, sys

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

def off_to_rva(off):
    for s in SECS:
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return s["va"] + (off - s["raw"])
    return None

def find_start(va):
    off = rva_to_off(va - IB)
    if off is None:
        return None
    p = off - 1
    run = 0
    while p > 0 and blob[p] == 0xCC:
        run += 1
        p -= 1
    if run >= 2:
        return IB + off_to_rva(p + 1)
    return None

if __name__ == "__main__":
    for a in sys.argv[1:]:
        va = int(a, 16)
        s = find_start(va)
        print(f"0x{va:08X} -> start 0x{s:08X}" if s else f"0x{va:08X} -> (no padding boundary found)")
