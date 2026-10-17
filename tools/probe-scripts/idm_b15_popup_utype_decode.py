#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM 6.43b15 独立审计 · 第二轮：用 Capstone 反汇编恢复每个弹窗调用点的真实 uType。

为什么需要它
------------
`call <弹窗包装>` 是 __cdecl 4 参：`f(hWnd, lpText, lpCaption, uType)`，
cdecl 右到左压栈 ⇒ 程序顺序里「第 1 个」push 就是 uType，最后一个 push 是 hWnd。
正则匹配 `68 imm32` 会被别的指令的立即数字节误命中（实测 0x522A93 被误判成 0x4B0，
真值是 0），所以必须真反汇编。

做法：对每个调用点，从 site-N (N<=80) 起做线性反汇编，保留「恰好平铺到 site」的
起点作为对齐锚点，再向前回溯取最后 4 个 push 作为参数组。可选 `--verify` 打印
回溯窗口的完整反汇编供人工核对。

用法
----
python idm_b15_popup_utype_decode.py --exe <IDMan.exe> --csv <.scratch/.../b15_popup_callpoints.csv>
        --outdir <dir> --tag b15 [--max-back 80] [--show 2400002] 
"""
import argparse
import csv
import json
import os
import struct
import sys

try:
    import capstone
except ImportError:
    sys.stderr.write("need capstone\n")
    sys.exit(2)


def hx(x):
    return "0x%08X" % (x & 0xFFFFFFFF)


class PESimple(object):
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

    def va2off(self, va):
        r = va - self.image_base
        for name, va0, vs, raw, rs in self.sections:
            if va0 <= r < va0 + max(vs, rs):
                dd = r - va0
                if dd < rs:
                    return raw + dd
        return None

    def off2va(self, off):
        for name, va0, vs, raw, rs in self.sections:
            if raw <= off < raw + rs:
                return self.image_base + va0 + (off - raw)
        return None


TERMINATORS = {"ret", "retn", "jmp", "int3", "ud2", "hlt"}


def recover_prev_insns(pe, md, site_off, want=10, max_back=80):
    """返回 (insns, align_start_off)。insns 为 site 之前且按序平铺到 site 的指令列表，
    不含 site 处的指令本身；insns[-1] 是紧邻 site 的上一条指令。"""
    site_va = pe.off2va(site_off)
    best = None
    for s in range(max(0, site_off - max_back), site_off):
        start_va = pe.off2va(s)
        if start_va is None:
            continue
        try:
            raw = list(md.disasm(bytes(pe.data[s:site_off + 6]), start_va))
        except Exception:
            continue
        if not raw or raw[0].address != start_va:
            continue
        cur = start_va
        prefix = []
        ok = True
        for i in raw:
            if i.address != cur:
                ok = False
                break
            if i.address == site_va:      # 平铺到达 site 处的 call 本身 -> 成功
                break
            prefix.append(i)
            cur += i.size
        if not ok or cur != site_va:
            continue
        if best is None or len(prefix) > len(best[0]):
            best = (prefix, s)
    return best if best else ([], None)


TRANSPARENT_CALLS = ()  # 占位：capstone 无符号名，改为「不因 call 截断」


def arg_group(insns, max_group=8):
    """收集 site 之前本次调用的实参 push。
    cdecl 右到左压栈：(hWnd, lpText, lpCaption, uType) ⇒ 组内第 1 个 push 是 uType。

    注意：**不因 `call` 截断**。实参布置中间常夹着透明调用（IDA 实测 0x521157 /
    0x523BD0 都在压栈之间插了 `call ds:GetDesktopWindow`），而且 capstone 不带符号名，
    无法按名字识别。因为「离 site 最近的 4 个 push」就是本次实参，跨过 call 也安全。
    只在真正的分支/返回处截断。"""
    grp = []
    for i in reversed(insns):
        m = i.mnemonic
        if m in ("ret", "retn", "int3", "jmp", "ud2", "hlt", "loop") or m.startswith("j"):
            break
        if m == "push":
            grp.append(i)
        if len(grp) >= max_group:
            break
    grp.reverse()
    return grp


def imm_hex(s):
    """把 capstone / IDA 两种立即数写法归一到 '0x..'；寄存器或内存表达式返回 ''。"""
    s = s.strip()
    if not s:
        return ""
    try:
        if s.lower().startswith("0x"):
            return "0x%X" % int(s, 16)
        if s.endswith("h") or s.endswith("H"):
            return "0x%X" % int(s[:-1], 16)
        if s.isdigit():
            return "0x%X" % int(s)
    except ValueError:
        return ""
    return ""


def op_text(i):
    return i.op_str.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--tag", default="b15")
    ap.add_argument("--max-back", type=int, default=80)
    ap.add_argument("--show", default="", help="逗号分隔的 site VA，打印其反汇编窗口")
    args = ap.parse_args()

    pe = PESimple(args.exe)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    rows = list(csv.DictReader(open(args.csv, encoding="utf-8-sig")))
    show = set(int(x, 16) for x in args.show.split(",") if x.strip())

    out = []
    for r in rows:
        site_va = int(r["site_va"], 16)
        site_off = int(r["site_off"], 16)
        insns, aoff = recover_prev_insns(pe, md, site_off, max_back=args.max_back)
        grp = arg_group(insns)
        uType = ""
        uType_src = "none"
        uType_hex = ""
        if len(grp) >= 4:
            p = grp[-4]                     # cdecl 右到左：(hWnd,text,caption,uType) -> 第1个 push 是 uType
            uType = op_text(p)
            uType_src = "push@%s" % hx(p.address)
            uType_hex = imm_hex(uType)
        elif grp:
            uType = op_text(grp[0])
            uType_src = "weak(%d push)@%s" % (len(grp), hx(grp[0].address))
            uType_hex = imm_hex(uType)
        # 参数组顺序（cdecl 右到左）：[uType, caption, text, hWnd]
        cap = grp[-3].op_str.strip() if len(grp) >= 3 else ""
        txt = grp[-2].op_str.strip() if len(grp) >= 2 else ""
        hwn = grp[-1].op_str.strip() if len(grp) >= 1 else ""
        host_va = "" if not r.get("host_va") else r["host_va"]
        out.append(dict(r, uType=uType, uType_hex=uType_hex, uType_src=uType_src,
                        caption_expr=cap, text_expr=txt, hwnd_expr=hwn,
                        arg_pushes=" | ".join(op_text(i) for i in grp),
                        n_args_push=len(grp)))

    csv2 = os.path.join(args.outdir, "%s_popup_utype.csv" % args.tag)
    if out:
        keys = list(out[0].keys())
        with open(csv2, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in out:
                w.writerow(r)

    from collections import Counter
    c = Counter(r["uType_hex"] for r in out)
    print("总调用点: %d" % len(out))
    print("uType 分布 (top 12):")
    for k, v in c.most_common(12):
        print("   %-12s %d" % (k or "(unknown)", v))
    mb_okcancel = [r for r in out if r["uType_hex"] == "0x1"]
    print("\n*** uType == 0x1 (MB_OKCANCEL，双按钮「确定/取消」) 的调用点: %d ***" % len(mb_okcancel))
    for r in mb_okcancel:
        print("   site=%s wrapper=%s host_off=%s cleanup=%s MData=%s caption=%s" %
              (r["site_va"], r["wrapper"], r.get("host_va"), r["cleanup"],
               r["host_has_mdata_push"], r["caption_expr"]))

    if show:
        print("\n=== 反汇编窗口 ===")
        for r in out:
            if int(r["site_va"], 16) in show:
                site_off = int(r["site_off"], 16)
                insns, aoff = recover_prev_insns(pe, md, site_off, max_back=args.max_back)
                print("--- %s (host_off=%s) ---" % (r["site_va"], r.get("host_va")))
                for i in insns[-16:]:
                    print("   %08X  %-22s %s" % (i.address, i.mnemonic, i.op_str))
                print("   %08X  CALL <wrapper %s>   ; uType=%s" %
                      (int(r["site_va"], 16), r["wrapper"], r["uType"]))
    print("\nCSV: %s" % csv2)


def q(x):
    return x


if __name__ == "__main__":
    main()
