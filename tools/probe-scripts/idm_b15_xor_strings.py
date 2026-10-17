#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM 6.43b15 独立审计 · 第四轮：全 256 key 单字节 XOR 硬编码文案枚举。

背景（Lead 提供的路径）：counterfeit 文案在 .data 里以 XOR 编码存放，运行期
`xor [eax+ecx], 0Fh` 就地解密后再 PostMessage 投递。本脚本做**穷举**：
  key ∈ [0,255] × 编码 ∈ {ASCII, UTF-16LE} × 一组 needle
输出所有命中（key / 编码 / 文件偏移 / 节名 / 解码后上下文），用于回答
「还有没有第 N 处」「是否存在无从句变体」。

用法：
  python idm_b15_xor_strings.py --exe <IDMan.exe> --outdir <dir> --tag b15
      [--needles "a|b|c"] [--ctx 64] [--keys 0-255]
"""
import argparse
import csv
import os
import struct
import sys

NEEDLES_DEFAULT = [
    "fake Serial Number",
    "Serial Number",
    "registered with a fake",
    "cracked product",
    "full-featured",
    "purchase the full",
    "has been blocked",
    "Be aware",
    "Internet Download Manager has been",
    "may work incorrectly",
    "download files with errors",
    "we advise you to",
    "Serial Number has been blocked",
    "or the Serial Number",
]


def hx(x):
    return "0x%X" % (x & 0xFFFFFFFF)


class PE(object):
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        e = struct.unpack_from("<I", d, 0x3C)[0]
        coff = e + 4
        optsz = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        so = opt + optsz
        self.sections = []
        for i in range(struct.unpack_from("<H", d, coff + 2)[0]):
            o = so + i * 40
            name = d[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vs, va, rs, raw = struct.unpack_from("<IIII", d, o + 8)
            self.sections.append((name, va, vs, raw, rs))

    def sec_of_off(self, off):
        for name, va, vs, raw, rs in self.sections:
            if raw <= off < raw + rs:
                return name
        return "?"

    def off2va(self, off):
        for name, va, vs, raw, rs in self.sections:
            if raw <= off < raw + rs:
                return self.image_base + va + (off - raw)
        return None

    def va2off(self, va):
        r = va - self.image_base
        for name, va0, vs, raw, rs in self.sections:
            if va0 <= r < va0 + max(vs, rs):
                dd = r - va0
                if dd < rs:
                    return raw + dd
        return None


def variants(needle, enc):
    """返回 [(pattern_bytes, decode_fn_label)]"""
    out = []
    if enc in ("ascii", "both"):
        out.append((needle.encode("latin-1"), "ascii"))
    if enc in ("utf16", "both"):
        out.append((needle.encode("utf-16-le"), "utf16le"))
    return out


def xor_search(data, pat, key):
    enc_pat = bytes(b ^ key for b in pat)
    res = []
    p = 0
    while True:
        i = data.find(enc_pat, p)
        if i < 0:
            return res
        res.append(i)
        p = i + 1


def decode_ctx(pe, off, length, key, enc):
    raw = pe.data[off:off + length]
    dec = bytes(b ^ key for b in raw)
    if enc == "utf16le":
        try:
            s = dec.decode("utf-16-le", "replace")
        except Exception:
            s = repr(dec)
    else:
        s = dec.decode("latin-1", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--tag", default="b15")
    ap.add_argument("--needles", default="")
    ap.add_argument("--enc", default="both", choices=["ascii", "utf16", "both"])
    ap.add_argument("--ctx", type=int, default=72)
    ap.add_argument("--exclude-key0", action="store_true", help="跳过 key=0（明文）")
    args = ap.parse_args()

    needles = [n for n in (args.needles.split("|") if args.needles else NEEDLES_DEFAULT) if n]
    pe = PE(args.exe)
    data = pe.data

    rows = []
    for nd in needles:
        for pat, enc in variants(nd, args.enc):
            for key in range(256):
                if args.exclude_key0 and key == 0:
                    continue
                for off in xor_search(data, pat, key):
                    rows.append(dict(
                        needle=nd, enc=enc, key="0x%02X" % key,
                        file_off=hx(off), va=hx(pe.off2va(off)) if pe.off2va(off) else "?",
                        section=pe.sec_of_off(off),
                        decoded=decode_ctx(pe, off, max(args.ctx, len(pat) + 16),
                                           key, enc)))

    os.makedirs(args.outdir, exist_ok=True)
    out = os.path.join(args.outdir, "%s_xor_hits.csv" % args.tag)
    if rows:
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)
    else:
        open(out, "w", encoding="utf-8").write("no hits\n")

    print("needles: %d, enc=%s, keys=256 -> hits=%d" % (len(needles), args.enc, len(rows)))
    by = {}
    for r in rows:
        by.setdefault((r["needle"], r["enc"]), []).append(r)
    print("\n%-34s %-8s %s" % ("needle", "enc", "hits / keys / sections"))
    for (nd, enc), rs in sorted(by.items()):
        keys = sorted(set(x["key"] for x in rs))
        secs = sorted(set(x["section"] for x in rs))
        print("%-34s %-8s %3d  keys=%s  sec=%s" %
              (nd[:34], enc, len(rs), ",".join(keys[:8]) + ("…" if len(keys) > 8 else ""),
               ",".join(secs)))
    print("\n---- 关键 hit 明细（每个 needle 取前 6 条）----")
    seen = {}
    for r in rows:
        k = (r["needle"], r["enc"])
        seen.setdefault(k, 0)
        if seen[k] < 6:
            print("  [%s/%s key=%s] %s %s %s" %
                  (r["needle"][:26], r["enc"], r["key"], r["file_off"], r["section"],
                   r["decoded"][:68]))
            seen[k] += 1
    print("\nCSV: %s" % out)


if __name__ == "__main__":
    main()
