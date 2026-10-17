#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elf_probe.py -- 通用 ELF 结构/熵/锚点探针（纯标准库，无第三方依赖）

用途: 对已解包的原生 ELF 做"确定性事实"采集，为 Hook/逆向决策提供证据:
  1. ELF 头 / program header / section header 全量
  2. 符号表存在性 (.symtab / .dynsym) —— 判断是否被 strip
  3. 64KB 分块香农熵 —— 区分明文与密文区
  4. AArch64 指令指纹计数 (ret / nop) —— 客观区分"代码"与"密文"
  5. 明文锚点扫描 (保护器指纹 / 域名 / 卡密关键字)
  6. 嵌套归档 magic 扫描 (gzip/bzip2/xz/zip/7z)

用法:
  python elf_probe.py <path-to-elf> [--block 65536] [--top 40]

设计约束: 单次标准输出 < 150 行；不写任何文件；只读。
"""

import argparse
import math
import struct
import sys
from collections import Counter

# ---------- AArch64 指令指纹 ----------
A64_RET = b"\xc0\x03\x5f\xd6"   # ret
A64_NOP = b"\x1f\x20\x03\xd5"   # nop

# ---------- 明文锚点（保护器 / 授权平台） ----------
ANCHORS = [
    b"VT-Protector",
    b"jiami.t3yanzheng.com",
    b"t3yanzheng",
    b"T\xe5\x8a\xa0\xe5\xaf\x86",        # "T加密"
    b"__PAYLOAD__",
]

# ---------- 嵌套归档 magic ----------
MAGICS = {
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ\x00": "xz",
    b"PK\x03\x04": "zip",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x04\x22\x4d\x18": "lz4",
}

EM_NAMES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "aarch64",
    0x08: "mips", 0xF3: "riscv",
}
ET_NAMES = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN(PIE)", 4: "ET_CORE"}
PT_NAMES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
    5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME",
    0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
    0x6474e553: "GNU_PROPERTY",
}
SHT_NAMES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY",
}


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--block", type=int, default=65536)
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        data = fh.read()
    size = len(data)
    print(f"== file ==\n{args.path}\nsize = {size:,} B ({size/1048576:.2f} MiB)")

    # ---- ELF header ----
    if data[:4] != b"\x7fELF":
        print("!! not an ELF")
        return 1
    ei_class = data[4]
    ei_data = data[5]
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    print(f"class = {'ELF64' if is64 else 'ELF32'}  endian = {'little' if ei_data==1 else 'big'}")

    if is64:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff,
         _flags, _ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff,
         _flags, _ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)

    print(f"type = {ET_NAMES.get(e_type, hex(e_type))}  machine = {EM_NAMES.get(e_machine, hex(e_machine))} (0x{e_machine:x})")
    print(f"entry = 0x{e_entry:x}  phnum = {e_phnum}  shnum = {e_shnum}  shstrndx = {e_shstrndx}")

    # ---- program headers ----
    print("\n== program headers ==")
    loads = []
    interp = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > size:
            print(f"  [{i}] PHDR out of file bounds")
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from(endian + "IIQQQQQQ", data, off)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from(endian + "IIIIIIII", data, off)
        name = PT_NAMES.get(p_type, hex(p_type))
        fl = "".join([c for c, m in (("R", 4), ("W", 2), ("X", 1)) if p_flags & m])
        if p_type == 1:
            loads.append((p_offset, p_filesz, p_memsz, p_vaddr, fl))
            note = ""
            if p_filesz == 0 and p_memsz > 0:
                note = "  <== filesz=0 / memsz>0  FAKE LOAD (packer artifact)"
            if p_offset + p_filesz > size:
                note += "  <== extends past EOF"
            print(f"  [{i}] LOAD   off=0x{p_offset:08x} filesz=0x{p_filesz:08x} memsz=0x{p_memsz:08x} vaddr=0x{p_vaddr:08x} {fl}{note}")
        elif p_type == 3:
            interp = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode("utf-8", "replace")
            print(f"  [{i}] INTERP {interp}")
        else:
            print(f"  [{i}] {name:<12} off=0x{p_offset:08x} filesz=0x{p_filesz:08x} memsz=0x{p_memsz:08x} {fl}")

    # ---- section headers ----
    print("\n== section headers ==")
    shstr = b""
    if e_shnum and e_shoff:
        shstr_off, shstr_size = struct.unpack_from(endian + "IIQQ", data, e_shoff + e_shstrndx * e_shentsize)[2:4] \
            if False else (0, 0)
        # 简化: 先读所有 shdr, 再取 shstrtab
        shdrs = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > size:
                break
            if is64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align, sh_entsize = \
                    struct.unpack_from(endian + "IIQQQQIIQQ", data, off)
            else:
                sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align, sh_entsize = \
                    struct.unpack_from(endian + "IIIIIIIII", data, off)
                sh_flags = 0
            shdrs.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_flags))
        if e_shstrndx < len(shdrs):
            _n, _t, _a, o, s, _f = shdrs[e_shstrndx]
            shstr = data[o:o + s]
        for idx, (sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_flags) in enumerate(shdrs):
            nm = shstr[sh_name:].split(b"\x00")[0].decode("utf-8", "replace") if shstr else ""
            tn = SHT_NAMES.get(sh_type, str(sh_type))
            print(f"  [{idx:2d}] {nm:<16} {tn:<10} addr=0x{sh_addr:08x} off=0x{sh_offset:08x} size=0x{sh_size:08x}")
    else:
        print("  (no section header table)")

    symtab = any(shstr[s[0]:].split(b"\x00")[0] == b".symtab" for s in
                 [(0,)] ) if False else False
    # 直接按名字判断
    shnames = []
    if shstr and e_shnum and e_shoff:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > size:
                break
            nm_off = struct.unpack_from(endian + "I", data, off)[0]
            shnames.append(shstr[nm_off:].split(b"\x00")[0].decode("utf-8", "replace"))
    print(f"\n  .symtab present: {'.symtab' in shnames}")
    print(f"  .dynsym present: {'.dynsym' in shnames}")
    print(f"  section names   : {', '.join(shnames) if shnames else '(none)'}")

    # ---- 熵图 + 指令指纹 ----
    print(f"\n== entropy / instruction fingerprint (block={args.block}) ==")
    print(f"  {'offset':>12} {'size':>10} {'H':>6}  {'ret':>6} {'nop':>6}  class")
    rows = []
    for off in range(0, size, args.block):
        blk = data[off:off + args.block]
        h = entropy(blk)
        r = blk.count(A64_RET)
        n = blk.count(A64_NOP)
        if h >= 7.99:
            cls = "CIPHERTEXT"
        elif r or n:
            cls = "code"
        else:
            cls = "data/plain"
        rows.append((off, len(blk), h, r, n, cls))

    # 合并同类相邻块
    merged = []
    for row in rows:
        if merged and merged[-1][5] == row[5] and merged[-1][0] + merged[-1][1] == row[0]:
            m = merged[-1]
            merged[-1] = (m[0], m[1] + row[1], max(m[2], row[2]), m[3] + row[3], m[4] + row[4], m[5])
        else:
            merged.append(row)

    tot_plain = tot_cipher = 0
    for off, ln, h, r, n, cls in merged:
        if cls == "CIPHERTEXT":
            tot_cipher += ln
        else:
            tot_plain += ln
        print(f"  0x{off:010x} {ln:>10,} {h:>6.2f}  {r:>6} {n:>6}  {cls}")
    print(f"\n  plaintext/data = {tot_plain:,} B ({tot_plain/1048576:.2f} MiB)")
    print(f"  ciphertext     = {tot_cipher:,} B ({tot_cipher/1048576:.2f} MiB)")
    print(f"  ratio          = {100.0*tot_cipher/size:.1f}% encrypted")

    # ---- 锚点 ----
    print("\n== plaintext anchors ==")
    for a in ANCHORS:
        pos = data.find(a)
        if pos < 0:
            print(f"  {a!r:<32} NOT FOUND")
        else:
            ctx = data[pos:pos + 96].split(b"\x00")[0]
            print(f"  {a!r:<32} @0x{pos:x}  {ctx[:88]!r}")

    # ---- 归档 magic ----
    print("\n== nested archive magic ==")
    for magic, nm in MAGICS.items():
        positions = []
        start = 0
        while len(positions) < 4:
            p = data.find(magic, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1
        if positions:
            print(f"  {nm:<6} {len(positions)} hit(s) @ " + ", ".join(f"0x{p:x}" for p in positions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
