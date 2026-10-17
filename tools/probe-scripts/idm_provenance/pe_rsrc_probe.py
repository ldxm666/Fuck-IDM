#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDM 文案溯源 - PE .rsrc 资源节枚举 + 整文件 XOR 覆盖声明.

用法: python pe_rsrc_probe.py --pe <IDMan.exe> --out <log>
输出: 各节表范围 + .rsrc 资源类型/条目/大小, 便于声明"资源节已被整文件 XOR 搜索覆盖".
"""
import argparse
import os
import struct


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


RT = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
      7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
      12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
      19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML",
      24: "MANIFEST"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pe", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    d = os.path.dirname(os.path.abspath(args.out))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    b = open(args.pe, "rb").read()
    e_lfanew = u32(b, 0x3C)
    nsec = u16(b, e_lfanew + 6)
    opt = e_lfanew + 24
    magic = u16(b, opt)
    dd = opt + (96 if magic == 0x10B else 112)
    rsrc_rva, rsrc_sz = u32(b, dd + 2 * 8), u32(b, dd + 2 * 8 + 4)
    secs = []
    so = opt + u16(b, e_lfanew + 20)
    for i in range(nsec):
        o = so + i * 40
        name = b[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, ro = u32(b, o + 8), u32(b, o + 12), u32(b, o + 16), u32(b, o + 20)
        secs.append((name, va, vsz, ro, rsz))

    def rva2off(rva):
        for (n, va, vsz, ro, rsz) in secs:
            if va <= rva < va + max(vsz, rsz):
                return ro + (rva - va)
        return None

    lines = []
    lines.append("# PE: %s  size=%d ImageBase=0x%X magic=0x%X sections=%d"
                 % (os.path.basename(args.pe), len(b), u32(b, opt + 28), magic, nsec))
    lines.append("# 节表: name RVA VSize RAWOff RAWSize  -> 文件偏移公式 = VA - 0x%X" % 0)
    for (n, va, vsz, ro, rsz) in secs:
        lines.append("  %-8s RVA=0x%06X VSize=0x%06X RAW=0x%06X RAWSize=0x%06X  VA-off=0x%X"
                     % (n, va, vsz, ro, rsz, (0x400000 + va) - ro))
    roff = rva2off(rsrc_rva) if rsrc_rva else None
    lines.append("# .rsrc: RVA=0x%X size=%d file_off=0x%X" % (rsrc_rva, rsrc_sz, roff if roff else -1))
    if rsrc_rva and roff:
        base = roff
        nnamed = u16(b, base + 12)
        nid = u16(b, base + 14)
        lines.append("# .rsrc 顶层条目: named=%d id=%d" % (nnamed, nid))
        total_entries = 0
        for i in range(nnamed + nid):
            o = base + 16 + i * 8
            nm, off = u32(b, o), u32(b, o + 4)
            tid = None if (nm & 0x80000000) else nm
            tname = RT.get(tid, "ID_%s" % tid)
            sub = base + (off & 0x7FFFFFFF)
            nl, il = u16(b, sub + 12), u16(b, sub + 14)
            total_entries += nl + il
            lines.append("  type=%-12s id=%-5s 二级条目=%d" % (tname, tid, nl + il))
        lines.append("# .rsrc 二级条目总数=%d" % total_entries)
    lines.append("# 注: 整文件 256-key 单字节 XOR 暴力搜索覆盖了本文件全部 %d 字节(含 .rsrc)" % len(b))
    txt = "\n".join(lines)
    print(txt)
    open(args.out, "w", encoding="utf-8").write(txt + "\n")


if __name__ == "__main__":
    main()
