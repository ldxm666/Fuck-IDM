#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flag-b15-snippet.py —— 新版版本无关「注册标志」定位器（P1 的替换实现）

背景
----
旧实现在 b15 上失效：IDM 6.43b15 把「关于」对话框里 `flag ? "Trial" : "Full"` 那段
判定整段删掉了（连 "Trial" 字符串都从镜像移除，"Full" 变成无条件 push），
所以旧签名 `39 1D <flag> 74 xx 68 <Trial> EB xx 68 <Full>` 在 b15 中根本不存在。

新实现不再依赖 UI 文案，改为从**注册逻辑本身**取三个互相独立的锚点并投票：

  A1 serial    83 F8 17 + >=3x (80 BD <disp32> 2D) + C7 05 <F> 00 00 00 00
               （序列号格式校验通过后把标志写 0）
  A2 naggate   83 3D <F> 00 74 ... 24 字节内出现 68 D8 14 00 00
               （试用弹窗门控；命令 ID 0x14D8 跨 b8/b15 不变）
  A3 threshold A1 <F> F7 D8 1B C0 83 E0 0F 83 C0 0F A3 <F+4>
               （无分支的 Trial?30:15 选择器；自带 F 与 F+4 的自校验，最独特）

投票规则：取票数最高者；票数并列或为 0 时返回 None（**失败即安全**，宁可跳过不猜）。

实测（本片段对两个文件实跑）
  b8  0x00779CDC  off 0x003782DC  init 1   votes=3/3
  b15 0x0077BD24  off 0x00379524  init 1   votes=3/3

接口：与 IDM-Unlock.py 的 PE / Site 类完全兼容，可直接整段替换原
      find_registration_flag(pe)。
"""

import struct

__all__ = ["find_registration_flag", "anchor_serial", "anchor_naggate",
           "anchor_threshold", "diagnose_registration_flag"]


# --------------------------------------------------------------------------- #
# 三个锚点：每个都返回 flag 的 VA（int）或 None
# --------------------------------------------------------------------------- #

def anchor_threshold(pe):
    """A3：mov eax,[F]; neg eax; sbb eax,eax; and eax,0xF; add eax,0xF; mov [F+4],eax

    这是 MSVC 为 `F ? 30 : 15` 生成的无分支选择器。序列极独特，
    且第二个操作数必须是 F+4，可用来做自校验。
    """
    pat = (b"\xA1" b"...."                       # mov eax, [F]
           b"\xF7\xD8"                           # neg eax
           b"\x1B\xC0"                           # sbb eax, eax
           b"\x83\xE0\x0F"                       # and eax, 0xF
           b"\x83\xC0\x0F"                       # add eax, 0xF
           b"\xA3" b"....")                      # mov [F+4], eax
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    hits = set()
    start = 0
    while True:
        i = data.find(b"\xA1", start)
        if i < 0:
            break
        start = i + 1
        if not (tstart <= i < tend - 22):
            continue
        chunk = data[i:i + 22]
        if len(chunk) < 22:
            continue
        if (chunk[5:7] == b"\xF7\xD8" and chunk[7:9] == b"\x1B\xC0"
                and chunk[9:12] == b"\x83\xE0\x0F" and chunk[12:15] == b"\x83\xC0\x0F"
                and chunk[15] == 0xA3):
            f = struct.unpack_from("<I", chunk, 1)[0]
            g = struct.unpack_from("<I", chunk, 16)[0]
            if g == f + 4:
                hits.add(f)
    return hits


def anchor_serial(pe):
    """A1：cmp eax,0x17 + >=3x `cmp byte ptr [ebp+disp32], 0x2d` + mov dword [F], 0

    序列号必须是 23 字符且第 5/11/17 位为 '-'，校验通过后把注册标志写 0。
    """
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    hits = set()
    start = 0
    while True:
        i = data.find(b"\x83\xF8\x17", start)          # cmp eax, 0x17
        if i < 0:
            break
        start = i + 1
        if not (tstart <= i < tend - 0x60):
            continue
        win = data[i:i + 0x60]
        dashes = 0
        j = 0
        while True:
            k = win.find(b"\x80\xBD", j)               # cmp byte ptr [ebp+disp32], imm8
            if k < 0:
                break
            if k + 6 < len(win) and win[k + 6] == 0x2D:  # '-' == 0x2d
                dashes += 1
            j = k + 1
        if dashes < 3:
            continue
        c = win.find(b"\xC7\x05")                      # mov dword ptr [F], imm32
        while c >= 0:
            if c + 10 <= len(win) and win[c + 6:c + 10] == b"\x00\x00\x00\x00":
                hits.add(struct.unpack_from("<I", win, c + 2)[0])
                break
            c = win.find(b"\xC7\x05", c + 1)
    return hits


def anchor_naggate(pe):
    """A2：cmp dword ptr [F], 0 / je ... 24 字节内出现 push 0x14D8

    这是试用弹窗触发链的总门控。命令 ID 0x14D8 在 b8 与 b15 中完全一致。
    """
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    hits = set()
    start = 0
    while True:
        i = data.find(b"\x83\x3D", start)              # cmp dword ptr [F], imm8
        if i < 0:
            break
        start = i + 1
        if not (tstart <= i < tend - 32):
            continue
        win = data[i:i + 32]
        if len(win) < 8 or win[6] != 0x00 or win[7] not in (0x74, 0x75):
            continue
        if b"\x68\xD8\x14\x00\x00" in win:             # push 0x14D8
            hits.add(struct.unpack_from("<I", win, 2)[0])
    return hits


# --------------------------------------------------------------------------- #
# 投票
# --------------------------------------------------------------------------- #

ANCHORS = (
    ("threshold", anchor_threshold),
    ("serial",    anchor_serial),
    ("naggate",   anchor_naggate),
)


def diagnose_registration_flag(pe):
    """返回 (flag_va_or_None, votes_dict, notes_list)，供 --scan 打印用。"""
    notes = []
    votes = {}
    for name, fn in ANCHORS:
        try:
            hits = fn(pe)
        except Exception as exc:
            notes.append("锚点 %s 异常：%s" % (name, exc))
            continue
        if not hits:
            notes.append("锚点 %-9s -> 无命中" % name)
        else:
            notes.append("锚点 %-9s -> %s" % (
                name, "、".join("0x%08X" % h for h in sorted(hits))))
        for h in hits:
            votes.setdefault(h, []).append(name)

    if not votes:
        notes.append("三个锚点全部无命中，无法定位注册标志")
        return None, votes, notes

    ranked = sorted(votes.items(), key=lambda kv: -len(kv[1]))
    best, names = ranked[0]
    if len(ranked) > 1 and len(ranked[1][1]) == len(names):
        notes.append("票数并列（0x%08X 与 0x%08X 各 %d 票），放弃"
                     % (best, ranked[1][0], len(names)))
        return None, votes, notes
    notes.append("选定 0x%08X（%d 票：%s）" % (best, len(names), "、".join(names)))
    return best, votes, notes


def find_registration_flag(pe):
    """drop-in 替换：返回 (Site, notes)。

    与 IDM-Unlock.py 中 Site 的构造方式保持一致：
        Site(key, title, offset, old, new, va=..., detail=..., confidence=...)
    """
    flag_va, votes, notes = diagnose_registration_flag(pe)
    if flag_va is None:
        return None, notes

    flag_off = pe.va_to_off(flag_va)
    if flag_off is None:
        notes.append("标志 VA 0x%08X 无法映射到文件偏移" % flag_va)
        return None, notes

    sec = pe.section_of_rva(flag_va - pe.image_base)
    if sec is None or not sec.writable:
        notes.append("标志 VA 0x%08X 不在可写数据段（在 %s）"
                     % (flag_va, sec.name if sec else "?"))
        return None, notes

    cur = pe.read_u32(flag_off)
    conf = "high" if len(votes.get(flag_va, [])) >= 2 else "medium"
    notes.append("标志 VA 0x%08X，段 %s，文件偏移 0x%08X，当前初值 0x%08X（%s），置信度 %s"
                 % (flag_va, sec.name, flag_off, cur,
                    "Trial" if cur else "Full", conf))

    old = struct.pack("<I", cur)
    new = b"\x00\x00\x00\x00"
    title = "注册状态全局 -> Full"
    if cur == 0:
        title = "注册状态全局"
        notes.append("已经是 Full（0），无需修改")
    return Site("registration_flag", title, flag_off, old, new,
                va=flag_va,
                detail="多锚点投票定位（%s）" % "、".join(votes.get(flag_va, [])),
                confidence=conf), notes


# --------------------------------------------------------------------------- #
# 自测：直接跑本文件即可对 b8 与 b15 两个文件验证
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import os
    import sys

    # IDM-Unlock.py 文件名带连字符，不能直接 import，用 importlib 从路径加载
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    unlock = os.path.join(os.path.dirname(here), "IDM-Unlock.py")
    if not os.path.isfile(unlock):
        unlock = os.path.join(here, "IDM-Unlock.py")
    spec = importlib.util.spec_from_file_location("idm_unlock", unlock)
    idm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(idm)

    targets = [
        ("b8 ", r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\IDMan.exe.orig"),
        ("b15", r"D:\pojie应用\jiesuo\work\idm-6.43b8\bin\b15\IDMan.exe.b15"),
    ]
    ok = True
    for tag, path in targets:
        if not os.path.isfile(path):
            print("%s  文件不存在：%s" % (tag, path))
            ok = False
            continue
        pe = idm.PE(path)
        print("=" * 74)
        print("%s  %s" % (tag, path))
        flag_va, votes, notes = diagnose_registration_flag(pe)
        for n in notes:
            print("   · " + n)
        if flag_va is None:
            print("   [FAIL] 未能定位")
            ok = False
            continue
        off = pe.va_to_off(flag_va)
        cur = pe.read_u32(off)
        print("   => flag VA 0x%08X  off 0x%08X  init 0x%08X" % (flag_va, off, cur))
    print("=" * 74)
    print("SELFTEST: %s" % ("PASS" if ok else "FAIL"))
