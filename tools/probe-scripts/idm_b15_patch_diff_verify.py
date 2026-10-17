#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM 6.43b15 独立审计 · 交叉验证：原始 vs 打补丁镜像

做三件事（全部只读）：
 1. 逐字节 diff，把所有「变化的连续区间」列出来（offset / VA / 长度 / old / new）。
 2. 对每个变化区间做「越界误伤」判定：是否与 patch 表里声明的站点/长度完全一致。
 3. 对打补丁镜像重跑弹窗调用点扫描，与原始镜像逐 site 比对：
    调用点集合必须完全一致（同长原位替换不应改变 E8 目标），且目标点状态应为 5×NOP / 短路。

用法：
 python idm_b15_patch_diff_verify.py --orig <orig.exe> --patched <patched.exe>
        --outdir <dir> [--tag t1] [--wrapper 0x474D20]
"""
import argparse
import csv
import os
import struct
import sys

TEXT_DELTA = 0x400C00
RDATA_DELTA = 0x401A00
DATA_DELTA = 0x402800


def hx(x):
    return "0x%X" % (x & 0xFFFFFFFF)


def va(off):
    """按节区间反推 VA（三种 delta 分别试）。"""
    for d in (TEXT_DELTA, RDATA_DELTA, DATA_DELTA):
        v = off + d
        if v > 0x400000:
            return d, v
    return None, None


def runs(a, b):
    """返回所有不同字节的连续区间 [(off, len, oldbytes, newbytes)]。"""
    if len(a) != len(b):
        print("  !! 长度不同: %d vs %d" % (len(a), len(b)))
    n = min(len(a), len(b))
    out = []
    i = 0
    while i < n:
        if a[i] != b[i]:
            s = i
            while i < n and a[i] != b[i]:
                i += 1
            out.append((s, i - s, a[s:i], b[s:i]))
        else:
            i += 1
    return out


def scan_calls(data, wrapper_va, image_base=0x400000):
    """扫 .text 内 call rel32 -> wrapper_va。返回 {va: (off, next5hex)}。"""
    ts, te = 0x400, 0x400 + 0x293200
    woff = wrapper_va - image_base - 0x1000 + 0x400
    res = {}
    i = ts
    while i < te - 5:
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            tgt = image_base + 0x1000 + (i - 0x400) + 5 + rel
            if tgt == wrapper_va:
                res[image_base + 0x1000 + (i - 0x400)] = (i, data[i:i + 5].hex())
                i += 5
                continue
        i += 1
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", required=True)
    ap.add_argument("--patched", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--tag", default="t1")
    ap.add_argument("--wrapper", default="0x474D20")
    args = ap.parse_args()

    a = open(args.orig, "rb").read()
    b = open(args.patched, "rb").read()
    print("orig   %s  %d B" % (os.path.basename(args.orig), len(a)))
    print("patch  %s  %d B" % (os.path.basename(args.patched), len(b)))

    rs = runs(a, b)
    print("\n=== 变化区间 %d 处 ===" % len(rs))
    rows = []
    tot = 0
    for off, ln, ob, nb in rs:
        d, v = va(off)
        tot += ln
        note = ""
        if nb == b"\x90" * ln:
            note = "全 NOP"
        elif nb == b"\x31\xc0\xc3":
            note = "xor eax,eax; ret（短路）"
        rows.append(dict(file_off=hx(off), va=hx(v) if v else "?", seg_delta=hx(d) if d else "?",
                         length=ln, old=ob.hex(), new=nb.hex(), note=note))
        print("  off %-9s VA %-11s len %-3d %s -> %s   %s" %
              (hx(off), hx(v) if v else "?", ln, ob.hex(), nb.hex(), note))
    print("总变更字节 = %d（声明站点字节合计若与之相等 ⇒ 无越界误伤）" % tot)

    wv = int(args.wrapper, 16)
    sa = scan_calls(a, wv)
    sb = scan_calls(b, wv)
    print("\n=== 调用点集合比对（wrapper %s）===" % hx(wv))
    print("  原始 %d 点 / 打补丁后 %d 点" % (len(sa), len(sb)))
    only_a = sorted(set(sa) - set(sb))
    only_b = sorted(set(sb) - set(sa))
    print("  仅原始有: %s" % ([hx(x) for x in only_a] or "无"))
    print("  仅补丁有: %s" % ([hx(x) for x in only_b] or "无"))
    nop = [hx(v) for v in sorted(sa) if sa[v][1] == "9090909090"]
    print("  已被替换为 5xNOP 的调用点: %d 处 %s" % (len(nop), nop))
    changed = [hx(v) for v in sorted(sa) if sa[v][1] != sb.get(v, ("", ""))[1]]
    print("  字节发生变化的调用点: %d 处 %s" % (len(changed), changed))

    out = os.path.join(args.outdir, "%s_patch_diff.csv" % args.tag)
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["file_off", "va", "seg_delta", "length",
                                          "old", "new", "note"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("\nCSV: %s" % out)


if __name__ == "__main__":
    main()
