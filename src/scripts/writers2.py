#!/usr/bin/env python3
"""Classify refs to a global by the opcode bytes that precede the disp32.
Handles the x86 encodings MSVC actually emits for absolute [disp32] operands."""
import pefile, sys, struct

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

# opcode patterns ending right before disp32 -> (mnemonic, is_write)
MODRM_MEM_ABS = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

def classify_site(p):
    """p = file offset of the disp32. Returns (desc, is_write)."""
    b1, b2 = blob[p-1], blob[p-2]
    b3 = blob[p-3]
    # mov dword ptr [addr], imm32
    if b1 == 0x05 and b2 == 0xC7:
        return f"mov dword [addr], 0x{struct.unpack('<I', blob[p+4:p+8])[0]:X}", True
    # mov byte ptr [addr], imm8
    if b1 == 0x05 and b2 == 0xC6:
        return f"mov byte [addr], 0x{blob[p+4]:02X}", True
    # mov [addr], eax  (A3)
    if b1 == 0xA3:
        return "mov [addr], eax", True
    # mov dword [addr], reg  (89 /r)
    if b2 == 0x89 and b1 in MODRM_MEM_ABS:
        return f"mov dword [addr], {REG32[(b1 >> 3) & 7]}", True
    # mov [addr], r8 (88 /r)
    if b2 == 0x88 and b1 in MODRM_MEM_ABS:
        return f"mov byte [addr], {REG32[(b1 >> 3) & 7]}b", True
    # inc/dec dword [addr]
    if b2 == 0xFF and b1 == 0x05:
        return "inc dword [addr]", True
    if b2 == 0xFF and b1 == 0x0D:
        return "dec dword [addr]", True
    # cmp dword [addr], imm32
    if b1 == 0x05 and b2 == 0x81:
        return f"cmp dword [addr], 0x{struct.unpack('<I', blob[p+4:p+8])[0]:X}", False
    if b1 == 0x05 and b2 == 0x83:
        v = struct.unpack('<b', blob[p+4:p+5])[0]
        return f"cmp dword [addr], {v}", False
    # cmp dword [addr], reg (39 /r)
    if b2 == 0x39 and b1 in MODRM_MEM_ABS:
        return f"cmp dword [addr], {REG32[(b1 >> 3) & 7]}", False
    # test dword [addr], imm32 (F7 /0)
    if b1 == 0x05 and b2 == 0xF7:
        return f"test dword [addr], 0x{struct.unpack('<I', blob[p+4:p+8])[0]:X}", False
    # test [addr], reg (85 /r)
    if b2 == 0x85 and b1 in MODRM_MEM_ABS:
        return f"test dword [addr], {REG32[(b1 >> 3) & 7]}", False
    # mov eax, [addr] (A1)
    if b1 == 0xA1:
        return "mov eax, [addr]", False
    # mov reg, [addr] (8B /r)
    if b2 == 0x8B and b1 in MODRM_MEM_ABS:
        return f"mov {REG32[(b1 >> 3) & 7]}, dword [addr]", False
    # movzx eax, byte [addr] (0F B6 05)
    if b1 == 0x05 and b2 == 0xB6 and b3 == 0x0F:
        return "movzx eax, byte [addr]", False
    # add/or/and/sub dword [addr], imm (81 /0../5) or reg (01/09/21/29 /r)
    for op, nm in ((0x01, "add"), (0x09, "or"), (0x21, "and"), (0x29, "sub"), (0x31, "xor")):
        if b2 == op and b1 in MODRM_MEM_ABS:
            return f"{nm} dword [addr], {REG32[(b1 >> 3) & 7]}", True
    if b2 == 0x81 and b1 in MODRM_MEM_ABS:
        nm = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][(b1 >> 3) & 7]
        return f"{nm} dword [addr], imm32", nm not in ("cmp",)
    return "UNKNOWN", None

def run(va):
    needle = struct.pack("<I", va)
    hits, pos = [], TEXT["raw"]
    end = TEXT["raw"] + TEXT["rawsize"]
    while True:
        i = blob.find(needle, pos, end)
        if i < 0:
            break
        hits.append(i); pos = i + 1
    writes, reads, unk = [], [], []
    for h in hits:
        desc, w = classify_site(h)
        rec = (IB + off_to_rva(h - 2 if blob[h-1] in MODRM_MEM_ABS and blob[h-2] in (0x89,0x88,0x39,0x85,0x01,0x09,0x21,0x29,0x31,0x8B) else h), desc)
        if w is True: writes.append(rec)
        elif w is False: reads.append(rec)
        else: unk.append((IB + off_to_rva(h), desc))
    print(f"### VA 0x{va:08X}: {len(hits)} occurrences  -> {len(writes)} writes, {len(reads)} reads, {len(unk)} unknown")
    print(f"\n  == WRITES ({len(writes)}) ==")
    for a, d in writes: print(f"    0x{a:08X}  {d}")
    print(f"\n  == UNKNOWN ({len(unk)}) ==")
    for a, d in unk: print(f"    0x{a:08X}  {d}")
    print(f"\n  == READS ({len(reads)}) ==")
    for a, d in reads: print(f"    0x{a:08X}  {d}")

if __name__ == "__main__":
    for a in sys.argv[1:]:
        run(int(a, 16))
