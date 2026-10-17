#!/usr/bin/env python3
"""IDM xref hunter.

Finds null-terminated strings in IDMan.exe and locates code references to them
by scanning .text for absolute 32-bit immediates (ImageBase + RVA), which is how
MSVC x86 emits `push offset str` / `mov reg, offset str`.
"""
import pefile, re, sys, struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BIN = r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.exe.orig"

pe = pefile.PE(BIN, fast_load=True)
pe.parse_data_directories()
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, "rb").read()

SECS = []
for s in pe.sections:
    SECS.append({
        "name": s.Name.rstrip(b"\x00").decode(errors="replace"),
        "va": s.VirtualAddress,
        "vsize": s.Misc_VirtualSize,
        "raw": s.PointerToRawData,
        "rawsize": s.SizeOfRawData,
    })

def sec_by_name(n):
    for s in SECS:
        if s["name"] == n:
            return s
    raise KeyError(n)

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

def find_string_start(off):
    """Walk back to the previous NUL to get the real string start."""
    start = off
    while start > 0 and blob[start - 1] != 0:
        start -= 1
    return start

def read_cstr(off, maxlen=400):
    end = blob.find(b"\x00", off, off + maxlen)
    if end < 0:
        end = off + maxlen
    return blob[off:end].decode("latin-1")

md = Cs(CS_ARCH_X86, CS_MODE_32)
text = sec_by_name(".text")

def find_code_refs(va, extra=0):
    """Scan .text for little-endian VA immediates."""
    needle = struct.pack("<I", va + extra)
    hits = []
    start = text["raw"]
    end = start + text["rawsize"]
    pos = start
    while True:
        i = blob.find(needle, pos, end)
        if i < 0:
            break
        hits.append(i)
        pos = i + 1
    return hits

def disasm_at(file_off, before=24, after=48):
    rva = off_to_rva(file_off)
    if rva is None:
        return []
    fo = rva_to_off(rva - before)
    if fo is None:
        fo = file_off
    code = blob[fo:file_off + after]
    out = []
    for ins in md.disasm(code, IMAGE_BASE + rva - before):
        out.append(f"0x{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}")
    return out

def hunt(pattern, label=None, maxrefs=25):
    label = label or pattern
    print("=" * 110)
    print(f"### {label}")
    print(f"    pattern: {pattern!r}")
    for m in re.finditer(re.escape(pattern.encode()), blob):
        off = m.start()
        rva = off_to_rva(off)
        if rva is None:
            continue
        sstart = find_string_start(off)
        srva = off_to_rva(sstart)
        sva = IMAGE_BASE + srva
        sec = next((s["name"] for s in SECS if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"])), "?")
        print(f"\n  string @ file 0x{off:08X} rva 0x{rva:08X}  start_rva 0x{srva:08X} VA 0x{sva:08X} sec={sec}")
        print(f"    full text: {read_cstr(sstart, 200)!r}")
        refs = find_code_refs(sva)
        # also allow refs to the interior occurrence (compiler may fold to substring)
        if sva != IMAGE_BASE + rva:
            refs += find_code_refs(IMAGE_BASE + rva)
        refs = sorted(set(refs))
        if not refs:
            print("    (no absolute-immediate code refs found)")
        for r in refs[:maxrefs]:
            rrva = off_to_rva(r)
            print(f"    -> ref @ file 0x{r:08X} rva 0x{rrva:08X} VA 0x{IMAGE_BASE+rrva:08X}")
            for line in disasm_at(r, before=16, after=40):
                print(f"         {line}")
        if len(refs) > maxrefs:
            print(f"    ... {len(refs)-maxrefs} more refs")

if __name__ == "__main__":
    pats = sys.argv[1:]
    if not pats:
        pats = [
            "This is 30 day trial version",
            "has not been registered for 30 days",
            "free trial period has expired",
            "Your license for Internet Download Manager has expired",
            "counterfeit Serial Number",
        ]
    for p in pats:
        hunt(p)
