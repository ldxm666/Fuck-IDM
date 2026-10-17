#!/usr/bin/env python3
"""Dump every null-terminated printable string intersecting a VA range."""
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

def off_to_va(off):
    for s in SECS:
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return IB + s["va"] + (off - s["raw"])
    return None

def dump(va_start, va_end):
    o = rva_to_off(va_start - IB)
    e = rva_to_off(va_end - IB)
    if o is None or e is None:
        print("unmapped"); return
    i = o
    while i < e:
        if 32 <= blob[i] < 127:
            j = i
            while j < e and 32 <= blob[j] < 127:
                j += 1
            if blob[j] == 0 and (j - i) >= 2:
                print(f"0x{off_to_va(i):08X}  {blob[i:j].decode('latin-1')!r}")
            i = j + 1
        else:
            i += 1

if __name__ == "__main__":
    a = int(sys.argv[1], 16)
    b = int(sys.argv[2], 16)
    dump(a, b)
