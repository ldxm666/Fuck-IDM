#!/usr/bin/env python3
"""MData-writer static probe for IDM 6.43 Build 15 (PE32 x86).

READ-ONLY on the target. Targets the b15 original, NOT the b8 build that
scripts/idm_util.py points at (b8: .rdata VA 0x294000 / b15: 0x295000).

Usage:
  python mdata_probe.py secs
  python mdata_probe.py refs  0x29D1E4 0x29D1E4 ...
  python mdata_probe.py range 0x29D000 0x29E000 [--all]
  python mdata_probe.py reloc [0x29D000 0x29E000]
  python mdata_probe.py str   0x29D1E4
  python mdata_probe.py hex   0x29B7E4 96
"""
import sys, struct

BIN = r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe.bak-original"
try:
    import pefile
except ImportError:
    sys.exit("pefile missing")

pe = pefile.PE(BIN, fast_load=True)
pe.parse_data_directories()
IB = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, "rb").read()
SECS = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"),
         "va": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
         "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData}
        for s in pe.sections]


def rva_to_off(rva):
    for s in SECS:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def va_to_off(va):
    return rva_to_off(va - IB)


def off_to_va(off):
    for s in SECS:
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return IB + s["va"] + (off - s["raw"])
    return None


def secname(va):
    o = va_to_off(va)
    if o is None:
        return "<unmapped>"
    for s in SECS:
        if s["raw"] <= o < s["raw"] + s["rawsize"]:
            return s["name"]
    return "?"


def cstr(va, n=200):
    o = va_to_off(va)
    if o is None:
        return "<unmapped>"
    e = blob.find(b"\x00", o, o + n)
    return blob[o:o + (e - o if e >= 0 else n)].decode("latin-1", "replace")


def cmd_secs():
    for s in SECS:
        print("%-8s VA=0x%06X RAW=0x%06X vsize=0x%06X rawsize=0x%06X" %
              (s["name"], s["va"], s["raw"], s["vsize"], s["rawsize"]))
    print("ImageBase=0x%X  SizeOfImage=0x%X  file=%d" %
          (IB, pe.OPTIONAL_HEADER.SizeOfImage, len(blob)))
    print("DllCharacteristics=0x%X  (DYNAMICBASE=%s)" %
          (pe.OPTIONAL_HEADER.DllCharacteristics,
           bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)))
    print("reloc dir RVA=0x%X size=0x%X" %
          (pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress,
           pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size))


def cmd_refs(*vas):
    """Full-file scan for the 4-byte little-endian value of each VA, and of its RVA."""
    for h in vas:
        va = int(h, 16)
        for label, val in (("VA ", va), ("RVA", va - IB)):
            if not (0 <= val <= 0xFFFFFFFF):
                print("%s 0x%08X : n/a (negative)" % (label, val))
                continue
            pat = struct.pack("<I", val)
            hits = []
            p = blob.find(pat)
            while p >= 0 and len(hits) < 40:
                hits.append(p)
                p = blob.find(pat, p + 1)
            print("%s 0x%08X : %d hit(s)%s" %
                  (label, val, len(hits),
                   "".join("  0x%06X(%s)" % (h2, secname(off_to_va(h2) or 0))
                           for h2 in hits[:12])))


def cmd_range(lo, hi, scope=".text"):
    """Scan for any 4-byte LE value inside [lo,hi) and report distinct targets."""
    lo, hi = int(lo, 16), int(hi, 16)
    seen = {}
    if scope == "--all":
        spans = [(0, len(blob), "FILE")]
    else:
        s = next(s for s in SECS if s["name"] == scope)
        spans = [(s["raw"], s["raw"] + s["rawsize"], scope)]
    for a, b, nm in spans:
        for p in range(a, b - 3):
            v = struct.unpack_from("<I", blob, p)[0]
            if lo <= v < hi:
                seen.setdefault(v, []).append(p)
    print("dwords in [0x%X,0x%X) found in %s: %d distinct" %
          (lo, hi, scope, len(seen)))
    for v in sorted(seen):
        srcs = seen[v]
        print("  0x%08X x%-3d  %s" %
              (v, len(srcs),
               " ".join("0x%06X" % (off_to_va(o) or 0) for o in srcs[:8])))


def cmd_reloc(lo=None, hi=None):
    lo = int(lo, 16) if lo else 0
    hi = int(hi, 16) if hi else 0xFFFFFFFF
    ents = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None)
    if not ents:
        print("NO .reloc entries parsed")
        return
    total = 0
    inrange = []
    types = {}
    for blk in ents:
        for e in blk.entries:
            total += 1
            types[e.type] = types.get(e.type, 0) + 1
            if lo <= e.rva + IB < hi:
                inrange.append((e.rva + IB, e.type))
    print("total relocs=%d  types=%s" % (total, types))
    print("relocs in [0x%X,0x%X): %d" % (lo, hi, len(inrange)))
    for va, t in inrange[:60]:
        print("  0x%08X type=%d" % (va, t))


def cmd_str(va):
    va = int(va, 16)
    print("VA 0x%08X file 0x%06X sec %s -> %r" %
          (va, va_to_off(va) or 0, secname(va), cstr(va)))


def cmd_hex(va, n=96):
    va = int(va, 16)
    n = int(n)
    o = va_to_off(va)
    b = blob[o:o + n]
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        print("%08X  %-47s  %s" %
              (va + i, " ".join("%02x" % c for c in chunk),
               "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))


def cmd_diff(other):
    """Byte-diff this (original) file against another copy; print changed ranges."""
    b2 = open(other, "rb").read()
    if len(b2) != len(blob):
        print("size differs: %d vs %d" % (len(blob), len(b2)))
    n = min(len(blob), len(b2))
    runs = []
    i = 0
    while i < n:
        if blob[i] != b2[i]:
            s = i
            while i < n and blob[i] != b2[i]:
                i += 1
            runs.append((s, i))
        i += 1
    print("%d differing byte-run(s)" % len(runs))
    for s, e in runs:
        va = off_to_va(s)
        print("file 0x%06X..0x%06X (len %d)  VA 0x%s" %
              (s, e, e - s, ("%08X" % va) if va else "unmapped"))
        print("   orig: %s" % " ".join("%02x" % c for c in blob[s:e][:24]))
        print("   live: %s" % " ".join("%02x" % c for c in b2[s:e][:24]))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    c = sys.argv[1]
    a = sys.argv[2:]
    {"secs": cmd_secs, "refs": cmd_refs, "range": cmd_range,
     "reloc": cmd_reloc, "str": cmd_str, "hex": cmd_hex, "diff": cmd_diff}[c](*a)
