#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDM 文案溯源 - 单字节 XOR 全键暴力 + 指定 key 搜索.

背景: IDM 用单字节 XOR 编码运行期字符串
  sub_51FFC0 @0x520141  xor [esp+ecx+...], 2Bh   -> "checkRes%ld_%d"
  sub_51FFC0 @0x5203A3  xor [esp+ecx+...], 0Fh   -> ".internetdownloadmanager.com"
所以磁盘上的静态资源也可能被同样手法编码。

用法:
  python xor_probe.py --mode brute    --files <glob...> --out <log>
  python xor_probe.py --mode knownkey --key 2B,0F --files <glob...> --out <log>
  python xor_probe.py --mode plain    --files <glob...> --out <log>

关键实现: 对每个 key 用 bytes.translate 一次性解码 (C 级速度),
再对 明文(ASCII) 与 UTF-16LE 两种 needle 各做一次 bytes.find。
UTF-16LE 也被同一 translate 覆盖: UTF16明文 XOR k 再 XOR k = UTF16明文。
"""
import argparse
import glob
import os
import sys
import time

NEEDLES_STRONG = [
    b"fake Serial Number",
    b"registered with a fake",
    b"Be aware that the cracked",
    b"full-featured product",
    b"purchase the full-featured",
    b"download files with errors",
    b"the cracked product may work",
    b"Serial Number. Be aware",
]
NEEDLES_WEAK = [b"Serial Number", b"full-featured", b"been registered with"]


def utf16le(s):
    return b"".join(bytes([c, 0]) for c in s)


def scan_buffer(buf, needles, keys, label, out, max_hits=100):
    hits = []
    t0 = time.time()
    for k in keys:
        tbl = bytes((b ^ k) & 0xFF for b in range(256))
        dec = buf.translate(tbl)
        for n in needles:
            start = 0
            while True:
                i = dec.find(n, start)
                if i < 0:
                    break
                hits.append((label, k, "ascii", n.decode("latin1"), i,
                             dec[max(0, i - 24):i + len(n) + 24]))
                start = i + 1
                if len(hits) >= max_hits:
                    break
            if len(hits) < max_hits:
                n16 = utf16le(n)
                start = 0
                while True:
                    i = dec.find(n16, start)
                    if i < 0:
                        break
                    hits.append((label, k, "utf16le", n.decode("latin1"), i,
                                 dec[max(0, i - 24):i + len(n16) + 24]))
                    start = i + 1
                    if len(hits) >= max_hits:
                        break
        if len(hits) >= max_hits:
            break
    line = "[%s] size=%d keys=%d needles=%d hits=%d elapsed=%.2fs" % (
        label, len(buf), len(keys), len(needles), len(hits), time.time() - t0)
    print(line, flush=True)
    out.write(line + "\n")
    for h in hits:
        s = "  HIT key=0x%02X form=%s needle=%r offset=0x%X (%d) ctx=%r" % (
            h[1], h[2], h[3], h[4], h[4], h[5])
        print(s, flush=True)
        out.write(s + "\n")
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["brute", "knownkey", "plain"], required=True)
    ap.add_argument("--key", default="2B,0F")
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-seconds", type=float, default=900.0)
    ap.add_argument("--weak", action="store_true")
    args = ap.parse_args()

    paths = []
    for spec in args.files:
        g = glob.glob(spec)
        if not g and os.path.isfile(spec):
            g = [spec]
        paths.extend(g)
    seen, ordered = set(), []
    for p in paths:
        rp = os.path.abspath(p)
        if rp in seen or not os.path.isfile(rp):
            continue
        seen.add(rp)
        ordered.append(rp)
    paths = sorted(ordered)

    needles = NEEDLES_STRONG + NEEDLES_WEAK if args.weak else NEEDLES_STRONG
    if args.mode == "brute":
        keys = list(range(256))
    elif args.mode == "knownkey":
        keys = [int(x, 16) for x in args.key.split(",")]
    else:
        keys = [0]

    d = os.path.dirname(os.path.abspath(args.out))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    grand = 0
    total_bytes = 0
    t0 = time.time()
    with open(args.out, "w", encoding="utf-8") as out:
        hdr = ("# IDM 文案溯源 xor_probe  mode=%s keys=%d(%s) needles=%d files=%d\n# 时间: %s\n"
               % (args.mode, len(keys), ",".join("%02X" % k for k in keys[:4]),
                  len(needles), len(paths), time.strftime("%Y-%m-%d %H:%M:%S")))
        out.write(hdr)
        print(hdr, flush=True)
        for p in paths:
            if time.time() - t0 > args.max_seconds:
                line = "# 达到 max-seconds 上限, 提前停止, 剩余文件未扫描"
                print(line, flush=True)
                out.write(line + "\n")
                break
            try:
                with open(p, "rb") as f:
                    buf = f.read()
            except OSError as e:
                print("[SKIP] %s: %s" % (p, e), flush=True)
                continue
            total_bytes += len(buf)
            label = os.path.basename(p)
            try:
                label = os.path.relpath(p).replace("\\", "/")
            except ValueError:  # 目标在别的盘符
                label = os.path.abspath(p).replace("\\", "/")
            grand += len(scan_buffer(buf, needles, keys, label, out))
        tail = ("# 汇总: 文件=%d 总字节=%d key数=%d needle数=%d 命中=%d 用时=%.1fs\n"
                % (len(paths), total_bytes, len(keys), len(needles), grand, time.time() - t0))
        out.write(tail)
        print(tail, flush=True)
    print("RESULT_HITS=%d" % grand)


if __name__ == "__main__":
    main()
