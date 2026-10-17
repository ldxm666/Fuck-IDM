#!/usr/bin/env python3
"""Resolve a global that holds a pointer to a string (or read raw values)."""
import pefile, sys, struct

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

def rd32(va):
    o = va_to_off(va)
    if o is None: return None
    return struct.unpack("<I", blob[o:o+4])[0]

def cstr(va, n=300):
    o = va_to_off(va)
    if o is None: return None
    e = blob.find(b"\x00", o, o+n)
    if e < 0: e = o+n
    return blob[o:e].decode("latin-1")

def wstr(va, n=300):
    o = va_to_off(va)
    if o is None: return None
    e = blob.find(b"\x00\x00", o, o+n)
    if e < 0: e = o+n
    return blob[o:e].decode("utf-16-le", errors="replace")

if __name__ == "__main__":
    for a in sys.argv[1:]:
        va = int(a, 16)
        v = rd32(va)
        print(f"### global 0x{va:08X} = 0x{v:08X}" if v is not None else f"### 0x{va:08X} unmapped")
        if v is None: continue
        if v and IB <= v < IB + 0x600000:
            s = cstr(v)
            if s and s.isprintable():
                print(f"    -> CSTR: {s!r}")
            else:
                print(f"    -> raw bytes at target: {blob[va_to_off(v):va_to_off(v)+32].hex(' ')}")
        else:
            print(f"    (not a pointer into image; raw={v})")
