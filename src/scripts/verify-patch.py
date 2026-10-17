#!/usr/bin/env python3
"""Independent verification of a patched IDMan.exe.

Checks every patched byte, re-disassembles the patched code to confirm the new
control flow is what we intended, and confirms the .data initializer really reads 0.
"""
import sys, hashlib
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ORIG_SHA = "74f177c8a44a6feb95a88e1d8b385bc2683b4b87e7ef8bfe333a058c436cc9b8"
PATCH_SHA = "527e8edb30dd42038f1c985a135cea6a7258e6fa9beb6283e743f49b392be552"

EXPECT = {
    "registration_flag_init": (0x3782DC, bytes([0x00, 0x00, 0x00, 0x00])),
    "trial_nag_neutralized":  (0x7C6C0,  bytes([0xE9, 0x38, 0x00, 0x00, 0x00])),
}

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def main(path):
    pe = pefile.PE(path, fast_load=True); pe.parse_data_directories()
    IB = pe.OPTIONAL_HEADER.ImageBase
    data = open(path, "rb").read()
    digest = sha256(path)

    print(f"file   : {path}")
    print(f"sha256 : {digest}")
    if digest == PATCH_SHA:
        print("         -> matches the known PATCHED build")
    elif digest == ORIG_SHA:
        print("         -> this is the ORIGINAL, unpatched build")
    else:
        print("         -> UNKNOWN build (neither original nor expected patch)")

    ok = True
    print("\n--- patched bytes ---")
    for name, (off, want) in EXPECT.items():
        got = bytes(data[off:off + len(want)])
        good = got == want
        ok &= good
        print(f"  [{'OK ' if good else 'BAD'}] {name:24} @ 0x{off:08X}: want {want.hex(' ')}  got {got.hex(' ')}")

    # --- disassemble the neutralised nag function ---
    print("\n--- disassembly of FUN_0047d2c0 (VA 0x47D2C0) ---")
    secs = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"), "va": s.VirtualAddress,
             "vsize": s.Misc_VirtualSize, "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData}
            for s in pe.sections]
    def rva_to_off(rva):
        for s in secs:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["raw"] + (rva - s["va"])
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    o = rva_to_off(0x47D2C0 - IB)
    for ins in md.disasm(data[o:o + 24], 0x47D2C0):
        note = ""
        if ins.mnemonic == "jmp":
            note = "  <-- should be 0x47d2fd (the function's own `mov eax,1 ; ret`)"
        print(f"  0x{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}{note}")
    o2 = rva_to_off(0x47D2FD - IB)
    print(f"  target 0x47D2FD bytes: {data[o2:o2+6].hex(' ')}   (expect b8 01 00 00 00 c3 = mov eax,1 ; ret)")

    # --- confirm .data initializer ---
    print("\n--- g_registered (.data) ---")
    o3 = rva_to_off(0x779CDC - IB)
    val = int.from_bytes(data[o3:o3 + 4], "little")
    print(f"  file offset 0x{o3:08X}  dword = {val}   ({'Full / registered' if val == 0 else 'Trial / unregistered'})")

    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.patched.exe"))
