#!/usr/bin/env python3
"""Classify every static reference site of the MData / MACHINE / CURRENT_USER /
CLSID string literals in IDM 6.43 b15 (PE32 x86, ImageBase 0x400000).

READ-ONLY on the target binary.

Usage:
  python mdata_sites.py classify [--str MData] [--fwd 96]
  python mdata_sites.py callers 0x44DEAB [--depth 2]
  python mdata_sites.py func    0x44DE52
  python mdata_sites.py dis     0x44DE30 128
"""
import sys, struct

BIN = r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe.bak-original"
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(BIN, fast_load=True)
pe.parse_data_directories()
IB = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, "rb").read()
SECS = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"),
         "va": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
         "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData}
        for s in pe.sections]
TEXT = next(s for s in SECS if s["name"] == ".text")

# ---- IAT ----
IAT = {}
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll = entry.dll.decode(errors="replace")
    for imp in entry.imports:
        if imp.address:
            nm = imp.name.decode(errors="replace") if imp.name else "ord%d" % imp.ordinal
            IAT[imp.address] = "%s!%s" % (dll, nm)


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


def cstr(va, n=160):
    o = va_to_off(va)
    if o is None:
        return "<unmapped>"
    e = blob.find(b"\x00", o, o + n)
    return blob[o:o + (e - o if e >= 0 else n)].decode("latin-1", "replace")


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

STRINGS = {
    "MData": 0x69D1E4, "MACHINE": 0x69D1EC, "CURRENT_USER": 0x69D1F4,
    "OnTimer": 0x69D184, "CLSID_E6871B76": 0x69D1A4,
}


def sites_for(va):
    """Every file offset holding the 4-byte LE absolute VA."""
    pat = struct.pack("<I", va)
    out, p = [], blob.find(pat)
    while p >= 0:
        out.append(p)
        p = blob.find(pat, p + 1)
    return out


def func_start(va):
    """MSVC x86: functions are separated by >=2 0xCC padding bytes (or by a
    preceding ret).  Walk back to the last such boundary."""
    o = va_to_off(va)
    p = o - 1
    while p > TEXT["raw"] and blob[p] == 0xCC:
        p -= 1
    if blob[p] == 0xCC:
        pass
    # scan back for a CC run (>=2) whose end is followed by a plausible prologue
    best = None
    q = p
    limit = max(TEXT["raw"], o - 0x1200)
    while q > limit:
        if blob[q] == 0xCC and blob[q - 1] == 0xCC:
            e = q
            while e + 1 < o and blob[e + 1] == 0xCC:
                e += 1
            cand = e + 1
            b0 = blob[cand:cand + 3]
            if b0[:2] in (b"\x55\x8b", b"\x55\x8d", b"\x55\x53", b"\x55\x56",
                          b"\x55\x57", b"\x83\xec", b"\x6a\xff", b"\x53\x56",
                          b"\x56\x57", b"\x8b\xff", b"\x64\xa1", b"\x55\x8b") or \
               b0[0] == 0x55 or b0[:2] == b"\x83\xec" or b0[0] == 0x6A:
                return off_to_va(cand)
            best = cand
            q = q - 1
            continue
        q -= 1
    return off_to_va(best) if best else None


def dis_range(start_va, length, annotate=True):
    o = va_to_off(start_va)
    if o is None:
        return []
    out = []
    for ins in md.disasm(blob[o:o + length], start_va):
        ann = ""
        if annotate:
            if ins.mnemonic == "call" and ins.op_str.startswith("dword ptr [0x"):
                t = int(ins.op_str.split("[")[1].rstrip("]"), 16)
                if t in IAT:
                    ann = IAT[t]
                else:
                    s = cstr(t, 80)
                    ann = '-> 0x%08X "%s"' % (t, s)
            else:
                for tok in ins.op_str.replace("[", " ").replace("]", " ").split(","):
                    tok = tok.strip()
                    if tok.startswith("0x"):
                        try:
                            t = int(tok, 16)
                        except ValueError:
                            continue
                        if IB <= t < IB + 0x600000:
                            s = cstr(t, 60)
                            if s and all(32 <= ord(ch) < 127 for ch in s) and len(s) > 2:
                                ann = '; "%s"' % s
        out.append((ins.address, ins.mnemonic, ins.op_str, ann, ins.size))
    return out


def first_api(site_va, fwd=96):
    for a, m, ops, ann, sz in dis_range(site_va, fwd):
        if m == "call" and ann and "!" in ann:
            return a, ann
        if m == "call":
            return a, ann
    return None, None


def reloc_set():
    """All base-relocation RVAs (absolute VAs) in the image."""
    s = set()
    for blk in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        for e in blk.entries:
            s.add(IB + e.rva)
    return s


RELOCS = reloc_set()


def cmd_classify(strname="MData", fwd=96):
    va = STRINGS[strname]
    offs = sites_for(va)
    print("# %s  VA 0x%08X  value %r  -> %d static sites" %
          (strname, va, cstr(va), len(offs)))
    print("%-12s %-12s %-12s %-6s %s" % ("push@VA", "funcStart", "call@VA", "reloc", "API"))
    for o in offs:
        push_va = off_to_va(o) - 1
        fs = func_start(push_va)
        ca, api = first_api(push_va, fwd)
        # the 4-byte immediate field sits at push_va+1 and must be relocated
        rl = "YES" if (push_va + 1) in RELOCS else "no"
        print("0x%08X   0x%08X   0x%08X   %-6s %s" %
              (push_va, fs or 0, ca or 0, rl, api))


def cmd_dis(va, n=128):
    va = int(va, 16)
    for a, m, ops, ann, sz in dis_range(va, int(n)):
        print("0x%08X  %-9s %-38s %s" % (a, m, ops, ann))


def callers_of(target_va, maxn=60):
    out = []
    a, b = TEXT["raw"], TEXT["raw"] + TEXT["rawsize"]
    for p in range(a, b - 5):
        if blob[p] == 0xE8:
            rel = struct.unpack_from("<i", blob, p + 1)[0]
            src = off_to_va(p)
            if src and src + 5 + rel == target_va:
                out.append(src)
                if len(out) >= maxn:
                    break
    return out


def cmd_callers(va, depth="1"):
    va = int(va, 16)
    depth = int(depth)
    cur = [va]
    seen = set()
    for d in range(depth + 1):
        nxt = []
        print("--- depth %d: %d target(s)" % (d, len(cur)))
        for t in cur:
            if t in seen:
                continue
            seen.add(t)
            cs = callers_of(t)
            print("  target 0x%08X  <- %d caller(s)" % (t, len(cs)))
            for c in cs[:20]:
                fs = func_start(c)
                ca, api = first_api(c, 24)
                print("     0x%08X (func 0x%08X)  next: 0x%08X %s" %
                      (c, fs or 0, ca or 0, api))
            nxt.extend(cs[:20])
        cur = nxt
        if not cur:
            break


def cmd_func(va):
    va = int(va, 16)
    fs = func_start(va)
    print("containing function start: 0x%08X (site 0x%08X, +0x%X)" %
          (fs or 0, va, va - (fs or va)))


def cmd_msgmap(fva):
    """Locate AFX_MSGMAP_ENTRY (24 bytes) whose pfn == fva, decode the message id."""
    fva = int(fva, 16)
    pat = struct.pack("<I", fva)
    hits = []
    p = blob.find(pat)
    while p >= 0:
        hits.append(p)
        p = blob.find(pat, p + 1)
    WM = {0x0113: "WM_TIMER", 0x0111: "WM_COMMAND", 0x0110: "WM_INITDIALOG",
          0x0112: "WM_SYSCOMMAND", 0x0001: "WM_CREATE", 0x0002: "WM_DESTROY",
          0x0010: "WM_CLOSE", 0x0114: "WM_HSCROLL", 0x0115: "WM_VSCROLL",
          0x0100: "WM_KEYDOWN", 0x000F: "WM_PAINT", 0x0014: "WM_ERASEBKGND",
          0x0210: "WM_ACTIVATEAPP", 0x0118: "WM_CTLCOLOR", 0x007E: "WM_DISPLAYCHANGE",
          0x0219: "WM_DEVICECHANGE", 0x0400: "WM_USER", 0x8000: "AFX_MSG_MAP_END"}
    print("# func 0x%08X : %d dword occurrence(s)" % (fva, len(hits)))
    for h in hits:
        base = h - 20                     # pfn is the last field of the 24-byte entry
        va = off_to_va(base)
        if va is None or base < 0:
            print("  file 0x%06X  (no entry base)" % h); continue
        e = blob[base:base + 24]
        nm, nc, nid, nlast, nsig, pfn = struct.unpack("<IIIIII", e)
        aligned = (base % 24 == 0)
        print("  file 0x%06X  VA 0x%08X  24-aligned=%s" % (h, va, aligned))
        print("     nMessage=0x%04X (%s) nCode=0x%X nID=0x%X nLastID=0x%X nSig=0x%X pfn=0x%08X"
              % (nm, WM.get(nm, "?"), nc, nid, nlast, nsig, pfn))
        for k in (-2, -1, 1, 2):
            b2 = base + k * 24
            if b2 < 0 or b2 + 24 > len(blob):
                continue
            m2, c2, i2, l2, s2, p2 = struct.unpack("<IIIIII", blob[b2:b2 + 24])
            v2 = off_to_va(b2)
            print("        [%+d] 0x%08X msg=0x%04X (%s) nSig=0x%X pfn=0x%08X"
                  % (k, v2 or 0, m2, WM.get(m2, "?"), s2, p2))


def cmd_apiscan(lo, hi):
    """List every `call dword ptr [IAT]` inside a VA range."""
    lo, hi = int(lo, 16), int(hi, 16)
    for a, m, ops, ann, sz in dis_range(lo, hi - lo):
        if m == "call" and ann and "!" in ann:
            print("0x%08X  %s" % (a, ann))


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    c = args[0]
    kw = {}
    pos = []
    i = 1
    while i < len(args):
        if args[i].startswith("--"):
            kw[args[i][2:]] = args[i + 1]
            i += 2
        else:
            pos.append(args[i])
            i += 1
    if c == "classify":
        cmd_classify(kw.get("str", "MData"), int(kw.get("fwd", 96)))
    elif c == "dis":
        cmd_dis(pos[0], kw.get("n", 128))
    elif c == "callers":
        cmd_callers(pos[0], kw.get("depth", 1))
    elif c == "func":
        cmd_func(pos[0])
    elif c == "msgmap":
        cmd_msgmap(pos[0])
    elif c == "apiscan":
        cmd_apiscan(pos[0], pos[1])
