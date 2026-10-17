#!/usr/bin/env python3
"""IDM 6.43b8 patcher.

Applies a documented patch set to IDMan.exe. Every patch is a single
self-describing entry so the result is reproducible and auditable.

Usage:
  python patch_idm.py <input.exe> <output.exe> [--list]
"""
import sys, os, hashlib, shutil, struct

# (name, file_offset, original_bytes, patched_bytes, note)
PATCHES = [
    (
        "registration_flag_init",
        0x3782DC,
        bytes([0x01, 0x00, 0x00, 0x00]),
        bytes([0x00, 0x00, 0x00, 0x00]),
        "g_registered (VA 0x779CDC) .data initializer: 1=Trial -> 0=Registered",
    ),
    (
        "trial_nag_neutralized",
        0x7C6C0,
        bytes([0xA1, 0x04, 0x89, 0x78, 0x00]),          # mov eax, [0x788904]
        bytes([0xE9, 0x38, 0x00, 0x00, 0x00]),          # jmp 0x47D2FD
        "FUN_0047d2c0 ('This is 30 day trial version... register your copy?') "
        "-> jump straight to its own `mov eax,1 ; ret` epilogue",
    ),
]

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--list" in sys.argv:
        for n, off, o, p, note in PATCHES:
            print(f"{n:28} off=0x{off:08X} {o.hex(' ')} -> {p.hex(' ')}   # {note}")
        return
    if len(args) != 2:
        print(__doc__); sys.exit(1)
    src, dst = args
    data = bytearray(open(src, "rb").read())
    print(f"input : {src}")
    print(f"        sha256 {sha256(src)}  size {len(data)}")
    for n, off, orig, patched, note in PATCHES:
        cur = bytes(data[off:off + len(orig)])
        if cur == patched:
            print(f"  [skip] {n}: already patched")
            continue
        if cur != orig:
            print(f"  [FAIL] {n}: expected {orig.hex(' ')}, found {cur.hex(' ')} -- binary version mismatch")
            sys.exit(2)
        data[off:off + len(patched)] = patched
        print(f"  [ ok ] {n} @ 0x{off:08X}: {orig.hex(' ')} -> {patched.hex(' ')}   # {note}")
    open(dst, "wb").write(data)
    print(f"output: {dst}")
    print(f"        sha256 {sha256(dst)}  size {len(data)}")

if __name__ == "__main__":
    main()
