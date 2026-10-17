#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM 6.43b15 独立审计：全库枚举「弹窗包装」调用点（回答「有没有第 10 处」）

作者：auditor（T2）。不依赖 idm_engine 的补丁逻辑；只用其 PE/串定位做交叉校验（可选）。

原理
----
PE32, ImageBase 0x400000。`.text` 文件偏移 = VA - 0x400C00。
全 `.text` 扫描 `E8 rel32`，凡 rel32 目标 VA ∈ {包装函数集合} 即为一个弹窗调用点。
对每个调用点标注：
  * 宿主函数边界（自带 cc-padding 近似；与 idm_engine._func_bounds 一致）
  * call 之后是否紧跟 `83 C4 imm`（add esp,imm8）→ 能否安全原位 NOP
  * 前 N 字节内出现的所有 push 立即数；**cdecl 右到左压栈** ⇒ 倒数第 4 个 push = uType
  * 是否已处于「5x NOP」补丁态
  * 宿主函数体内是否含 `push <MData VA>`（MData 串 VA 由内容锚定 "MData" 得到）

用法
----
python idm_b15_popup_callpoints_audit.py --exe <IDMan.exe> --outdir <dir> [--tag b15]
    [--wrappers 0x474D20,0x474EB0,0x474FF0,0x475180] [--window 64]
    [--timeout 120] [--engine <path/to/idm_engine.py>] [--title-va 0x696DE8]

退出码：0 正常 / 2 参数或 PE 错误 / 3 超时
"""
import argparse
import csv
import json
import os
import re
import struct
import sys
import threading
import time

T0 = time.time()
DEADLINE = None


def watchdog():
    while True:
        time.sleep(0.5)
        if DEADLINE and time.time() > DEADLINE:
            sys.stderr.write("TIMEOUT: audit exceeded --timeout\n")
            os._exit(3)


def hx(x):
    return "0x%08X" % (x & 0xFFFFFFFF)


class PE(object):
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not MZ")
        e = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e:e + 4] != b"PE\x00\x00":
            raise ValueError("not PE")
        coff = e + 4
        self.machine, self.nsections = struct.unpack_from("<HH", d, coff)
        optsz = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic != 0x10B:
            raise ValueError("not PE32 (magic=0x%X)" % magic)
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        so = opt + optsz
        self.sections = []
        for i in range(self.nsections):
            o = so + i * 40
            name = d[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vs, va, rs, raw = struct.unpack_from("<IIII", d, o + 8)
            self.sections.append(dict(name=name, va=va, vsize=vs, raw=raw, rawsize=rs))

    def sec(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def va2off(self, va):
        r = va - self.image_base
        for s in self.sections:
            if s["va"] <= r < s["va"] + max(s["vsize"], s["rawsize"]):
                dd = r - s["va"]
                if dd < s["rawsize"]:
                    return s["raw"] + dd
        return None

    def off2va(self, off):
        for s in self.sections:
            if s["raw"] <= off < s["raw"] + s["rawsize"]:
                return self.image_base + s["va"] + (off - s["raw"])
        return None

    def text_span(self):
        s = self.sec(".text")
        return (s["raw"], s["raw"] + s["rawsize"]) if s else (0, 0)

    def find_all(self, needle, start=0, end=None):
        end = len(self.data) if end is None else end
        out = []
        p = start
        while True:
            i = self.data.find(needle, p, end)
            if i < 0:
                return out
            out.append(i)
            p = i + 1

    def find_string(self, literal):
        """在 .rdata 优先、再全节搜索字面量，返回 (VA, off) 或 (None, None)。"""
        order = [self.sec(".rdata")] + self.sections
        for s in order:
            if not s:
                continue
            i = self.data.find(literal, s["raw"], s["raw"] + s["rawsize"])
            if i >= 0:
                return self.off2va(i), i
        i = self.data.find(literal)
        return (self.off2va(i), i) if i >= 0 else (None, None)


def func_bounds(pe, off, span_limit=0x8000):
    """cc-padding 近似函数边界（与 idm_engine._func_bounds 同算法，独立实现）。"""
    ts, te = pe.text_span()
    lo = max(ts, off - span_limit)
    seg = pe.data[lo:off]
    ms = list(re.finditer(rb"\xcc{2,}", seg))
    start = lo + ms[-1].end() if ms else lo
    hi = min(te, off + span_limit)
    fwd = re.search(rb"\xcc{2,}", pe.data[off:hi])
    end = off + fwd.start() if fwd else hi
    return start, end


PUSH_IMM32 = 0x68
PUSH_IMM8 = 0x6A


def find_pushes(win, win_va):
    """在窗口内找 push imm32 / push imm8，返回 [(va, value, kind)]（按地址升序）。
    纯模式匹配 —— 可能被其它指令的立即数字节误命中，故同时输出原窗口 hex 供复核。"""
    out = []
    i = 0
    n = len(win)
    while i < n:
        if win[i] == PUSH_IMM32 and i + 4 < n:
            v = struct.unpack_from("<I", win, i + 1)[0]
            out.append((win_va + i, v, "imm32"))
            i += 5
            continue
        if win[i] == PUSH_IMM8 and i + 1 < n:
            out.append((win_va + i, win[i + 1], "imm8"))
            i += 2
            continue
        i += 1
    return out


def decode_cleanup(pe, off):
    """call 之后的栈清理：add esp,imm8 (83 C4 ib) / add esp,imm32 (81 C4 id) / 其它。"""
    b = pe.data[off:off + 8]
    if len(b) >= 3 and b[0] == 0x83 and b[1] == 0xC4:
        return ("add esp,0x%X" % b[2], True, 3)
    if len(b) >= 6 and b[0] == 0x81 and b[1] == 0xC4:
        v = struct.unpack_from("<I", b, 2)[0]
        return ("add esp,0x%X" % v, True, 6)
    return ("NONE", False, 0)


def main():
    global DEADLINE
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--tag", default="b15")
    ap.add_argument("--wrappers", default="0x474D20,0x474EB0,0x474FF0,0x475180",
                    help="逗号分隔的弹窗包装 VA 列表（默认含 4 个同族包装）")
    ap.add_argument("--window", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--title-va", default="0x696DE8")
    ap.add_argument("--mdata", default="MData")
    ap.add_argument("--engine", default="")
    ap.add_argument("--text-iat", default="0x695738,0x695740",
                    help="user32 MessageBoxA/W 的 IAT 槽 VA（直接调用 = 绕过包装）")
    args = ap.parse_args()

    DEADLINE = time.time() + args.timeout
    threading.Thread(target=watchdog, daemon=True).start()

    pe = PE(args.exe)
    wrappers = [(int(x, 16), None) for x in args.wrappers.split(",") if x.strip()]
    title_va = int(args.title_va, 16)
    text_iats = [int(x, 16) for x in args.text_iat.split(",") if x.strip()]

    # --- 交叉校验：地址数学 ---
    tstart, tend = pe.text_span()
    ts_sec = pe.sec(".text")
    math_notes = []
    math_notes.append("image_base=%s  .text RVA=%s RAW=%s size=0x%X" %
                      (hx(pe.image_base), hx(ts_sec["va"]), hx(ts_sec["raw"]), ts_sec["rawsize"]))
    for label, va, want_off in [("P4", 0x44DE52, 0x4D252), ("MData", 0x69D1E4, 0x29B7E4)]:
        got = pe.va2off(va)
        math_notes.append("check %-5s VA=%s -> off=%s (expect %s) %s" %
                          (label, hx(va), hx(got) if got is not None else "None",
                           hx(want_off), "OK" if got == want_off else "MISMATCH"))
    if args.engine and os.path.exists(args.engine):
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(args.engine)))
            import idm_engine  # noqa
            e_pe = idm_engine.PE(args.exe)
            same = (e_pe.image_base == pe.image_base and
                    e_pe.text_span() == pe.text_span())
            math_notes.append("idm_engine cross-check: %s" % ("OK" if same else "MISMATCH"))
        except Exception as ex:
            math_notes.append("idm_engine cross-check failed: %r" % (ex,))

    mdata_va, mdata_off = pe.find_string(args.mdata.encode())
    mdata_push = b"\x68" + struct.pack("<I", mdata_va) if mdata_va else None
    title_push = b"\x68" + struct.pack("<I", title_va)
    math_notes.append("MData 串 VA=%s off=%s ; 其 push 编码=%s" %
                      (hx(mdata_va) if mdata_va else "None",
                       hx(mdata_off) if mdata_off is not None else "None",
                       mdata_push.hex() if mdata_push else "-"))

    # --- 扫描 ---
    rows = []
    for wva, _lbl in wrappers:
        woff = pe.va2off(wva)
        if woff is None:
            math_notes.append("WARN: 包装 %s 不在任何节 -> 跳过" % hx(wva))
            continue
        i = tstart
        while i < tend - 5:
            if pe.data[i] == 0xE8:
                rel = struct.unpack_from("<i", pe.data, i + 1)[0]
                tgt = pe.off2va(i) + 5 + rel
                if tgt == wva:
                    rows.append(build_row(pe, i, wva, title_push, mdata_push, args.window))
                    i += 5
                    continue
            i += 1

    # --- 直接调用 user32 MessageBox：绕过包装的候选 ---
    direct = []
    msg_names = {0x695738: "USER32:MessageBoxA", 0x695740: "USER32:MessageBoxW"}
    for iat in text_iats:
        pat = b"\xff\x15" + struct.pack("<I", iat)
        for off in pe.find_all(pat, tstart, tend):
            tag = msg_names.get(iat, "USER32:%s" % hx(iat))
            row = build_row(pe, off, iat, title_push, mdata_push, args.window)
            row["wrapper"] = tag
            row["state"] = "raw-FF15"
            rows.append(row)
            direct.append(dict(iat_va=hx(iat), site_va=hx(pe.off2va(off)),
                               site_off=hx(off), host_va=row["host_va"]))
    # 也扫 call rel32 到 IAT thunk 的可能性：忽略（本文只报 ff15 绝对间接调用）

    rows.sort(key=lambda r: int(r["site_va"], 16))
    flagged = [r for r in rows if r["host_has_mdata_push"] == "Y" or r["pre_title_push"] == "Y"]
    patched = [r for r in rows if r["state"] == "already-5xNOP"]

    os.makedirs(args.outdir, exist_ok=True)
    csv_path = os.path.join(args.outdir, "%s_popup_callpoints.csv" % args.tag)
    json_path = os.path.join(args.outdir, "%s_popup_callpoints.json" % args.tag)
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["site_va"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dict(exe=args.exe, wrappers=[hx(w) for w, _ in wrappers],
                       math=math_notes, title_va=hx(title_va),
                       mdata_va=hx(mdata_va) if mdata_va else None,
                       rows=rows, direct_messagebox=direct), f, indent=1)

    # --- 报告 ---
    print("== IDM 弹窗调用点独立审计 ==")
    print("exe: %s" % args.exe)
    for n in math_notes:
        print("  " + n)
    print("包装函数: %s" % ", ".join(hx(w) for w, _ in wrappers))
    for wva, _ in wrappers:
        c = sum(1 for r in rows if r["wrapper"] == hx(wva))
        print("  %s 调用点 = %d" % (hx(wva), c))
    print("总计 call <包装> 调用点 = %d ; 已 5xNOP = %d ; 直接 user32 MessageBox = %d"
          % (len(rows), len(patched), len(direct)))
    print("[重点] host含MData push 或 前置含 push 0x696DE8 的点 = %d" % len(flagged))
    print("%-10s %-10s %-10s %-16s %-6s %-6s %-6s %-8s" %
          ("site_VA", "host", "wrappers", "cleanup", "title1", "MData", "uType", "hostname"))
    for r in flagged:
        print("%-10s %-10s %-10s %-16s %-6s %-6s %-6s %-8s" %
              (r["site_va"], r["host_va"], r["wrapper"], r["cleanup"],
               r["pre_title_push"], r["host_has_mdata_push"],
               r["utype_guess"], r["cleanup_ok"]))
    print("CSV : %s" % csv_path)
    print("JSON: %s" % json_path)
    print("elapsed %.2fs" % (time.time() - T0))


def build_row(pe, off, wva, title_push, mdata_push, window):
    va = pe.off2va(off)
    hs, he = func_bounds(pe, off)
    body = pe.data[hs:he]
    wstart = max(pe.text_span()[0], off - window)
    win = pe.data[wstart:off]
    pushes = find_pushes(win, pe.off2va(wstart))
    cleanup, clean_ok, clen = decode_cleanup(pe, off + 5)
    nxt = pe.data[off:off + 16]
    state = "already-5xNOP" if pe.data[off:off + 5] == b"\x90" * 5 else "raw-E8"
    utype = ""
    utype_conf = ""
    if len(pushes) >= 4:
        utype = hx(pushes[-4][1])
        utype_conf = "heuristic(%-2d imms)" % len(pushes)
    elif pushes:
        utype = hx(pushes[0][1])
        utype_conf = "weak(%d imm)" % len(pushes)
    pre40 = pe.data[max(pe.text_span()[0], off - 40):off]
    return {
        "wrapper": hx(wva),
        "site_va": hx(va),
        "site_off": hx(off),
        "host_va": hx(pe.off2va(hs)),
        "host_off": hx(hs),
        "host_end": hx(he),
        "host_size": "0x%X" % (he - hs),
        "host_has_mdata_push": "Y" if (mdata_push and mdata_push in body) else "-",
        "host_has_title_push": "Y" if title_push in body else "-",
        "pre_title_push": "Y" if title_push in pre40 else "-",
        "pre_win_title_push": "Y" if title_push in win else "-",
        "cleanup": cleanup,
        "cleanup_ok": "Y" if clean_ok else "N",
        "state": state,
        "utype_guess": utype,
        "utype_conf": utype_conf,
        "push_imm_window": ";".join("%s=%s(%s)" % (hx(a), hx(v), k) for a, v, k in pushes),
        "next16": nxt.hex(),
        "pre_win_hex": win.hex(),
    }


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write("FATAL: %r\n" % (e,))
        raise
