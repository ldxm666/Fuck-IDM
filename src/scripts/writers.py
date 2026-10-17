#!/usr/bin/env python3
"""Classify every reference to a global as READ or WRITE by finding the exact
instruction that contains the disp32 immediate."""
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BIN = r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.exe.orig"
pe = pefile.PE(BIN, fast_load=True); pe.parse_data_directories()
IB = pe.OPTIONAL_HEADER.ImageBase
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

md = Cs(CS_ARCH_X86, CS_MODE_32)

def find_insn_covering(ref_off):
    """Try decoding from ref_off-k so an instruction ends exactly at ref_off+4."""
    end_rva = off_to_rva(ref_off) + 4
    for k in range(1, 17):
        start_off = ref_off - k
        srva = off_to_rva(start_off)
        if srva is None:
            continue
        code = blob[start_off:start_off + k + 16]
        for ins in md.disasm(code, IB + srva):
            if ins.address + ins.size == IB + end_rva:
                return ins, start_off
            if ins.address + ins.size > IB + end_rva:
                break
    return None, None

def classify(va):
    needle = struct.pack("<I", va)
    hits, pos = [], TEXT["raw"]
    end = TEXT["raw"] + TEXT["rawsize"]
    while True:
        i = blob.find(needle, pos, end)
        if i < 0:
            break
        hits.append(i)
        pos = i + 1
    print(f"### VA 0x{va:08X}: {len(hits)} raw occurrences in .text")
    reads, writes, unknown = [], [], []
    for h in hits:
        ins, so = find_insn_covering(h)
        if ins is None:
            unknown.append(h); continue
        # a write has the memory operand as the DESTINATION (first operand in intel syntax)
        ops = ins.op_str
        is_write = False
        if ins.mnemonic in ("mov", "movzx", "movsx", "and", "or", "xor", "add", "sub", "inc", "dec", "not", "neg"):
            # destination is before the comma
            dst = ops.split(",")[0]
            if "0x779cdc" in dst.lower() or f"{va:x}" in dst.lower():
                is_write = True
        if ins.mnemonic == "inc" or ins.mnemonic == "dec":
            is_write = "0x779cdc" in ops.lower()
        rec = (IB + off_to_rva(so), ins.mnemonic, ops, ins.size)
        (writes if is_write else reads).append(rec)
    print(f"  WRITES ({len(writes)}):")
    for r in writes:
        print(f"    0x{r[0]:08X}  {r[1]:<7} {r[2]}")
    print(f"  READS ({len(reads)}):")
    for r in reads:
        print(f"    0x{r[0]:08X}  {r[1]:<7} {r[2]}")
    if unknown:
        print(f"  UNDECODED: {[hex(IB+off_to_rva(u)) for u in unknown]}")

if __name__ == "__main__":
    for a in sys.argv[1:]:
        classify(int(a, 16))
