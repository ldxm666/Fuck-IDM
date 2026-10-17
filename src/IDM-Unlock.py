#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM-Unlock.py —— Internet Download Manager 一键解锁（去试用/付费弹窗 + 解锁 Full + 到期显示 9999）

设计目标
--------
1. 一次性：定位 → 备份 → 打补丁 → 部署 → 验证 → （可选）防回退，一条命令。
2. 版本无关：**不使用硬编码文件偏移**，全部靠特征码（signature）在目标二进制里现场定位。
   因此换 build / 换小版本通常仍然可用。
3. 失败即安全：任何一处特征码找不到或校验不通过，就**拒绝**打那一处补丁并明确报告，
   绝不"猜着改"。宁可少改，不可改错。

三种模式
--------
  --scan     只分析，不写任何东西（默认）。告诉你会改哪里、当前值是什么。
  --apply    备份 + 打补丁 + 部署到安装目录（必要时自动提权）。
  --restore  从备份还原成官方原版。

补丁内容
--------
  P1  registration_flag   : 把"注册状态"全局的 .data 初值改成 0（0=Full / 非0=Trial）
                            这是核心：它同时关掉试用弹窗触发链的唯一门控。
  P2  expiry_display_9999 : 把日期格式串 "%b/%d/%Y" 改成 "%b/%d/9999"
                            （IDM 的 nExpDt 是 32 位 time_t，硬上限 2038-01-19，
                             结构上到不了 9999；这里让界面显示 9999）
  P3  trial_nag_kill      : 【可选】把试用登记弹窗函数改成空操作（纵深防御）。
                            仅在能可靠验证函数形状时才应用。

用法示例
--------
  python IDM-Unlock.py --scan                 # 先看看会改什么
  python IDM-Unlock.py --apply                # 一键搞定（自动提权）
  python IDM-Unlock.py --apply --no-expiry    # 不改日期显示
  python IDM-Unlock.py --apply --no-nag-kill  # 不做 P3
  python IDM-Unlock.py --restore              # 还原
  python IDM-Unlock.py --scan --json          # 机器可读
"""

import os
import re
import sys
import json
import time
import shutil
import struct
import hashlib
import argparse
import subprocess
import ctypes
import tempfile
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

DEFAULT_INSTALL_DIRS = [
    r"C:\Program Files (x86)\Internet Download Manager",
    r"C:\Program Files\Internet Download Manager",
]
EXE_NAME = "IDMan.exe"
BACKUP_SUFFIX = ".bak-original"

# 特征码：试用登记弹窗的文案（用来找弹窗函数）
NAG_LITERAL = b"This is 30 day trial version of Internet Download Manager"
# 特征码：About 对话框用的日期格式串（全镜像唯一）
EXPIRY_FMT_OLD = b"%b/%d/%Y"
EXPIRY_FMT_NEW = b"%b/%d/9999"

# 到期时间显示用的时间戳：2037-12-31 12:00 UTC（中午，避开时区把日期挪走）
EXPIRY_TS = 2145916800 + 12 * 3600 - 19 * 86400  # 见下方自检，实际由 _expiry_ts() 计算


def _expiry_ts():
    """2037-12-31 12:00:00 UTC 的 Unix 秒。必须 <= 0x7FFFFFFF（IDM 只读 4 字节）。"""
    import calendar
    ts = calendar.timegm((2037, 12, 31, 12, 0, 0))
    assert ts <= 0x7FFFFFFF, "时间戳超过 IDM 能读取的 32 位上限"
    return ts


# --------------------------------------------------------------------------- #
# 极简 PE 解析（不依赖任何第三方库）
# --------------------------------------------------------------------------- #

class Section:
    __slots__ = ("name", "va", "vsize", "raw", "rawsize", "chars")

    def __init__(self, name, va, vsize, raw, rawsize, chars):
        self.name = name
        self.va = va
        self.vsize = vsize
        self.raw = raw
        self.rawsize = rawsize
        self.chars = chars

    @property
    def writable(self):
        return bool(self.chars & 0x80000000)

    def contains_rva(self, rva):
        return self.va <= rva < self.va + max(self.vsize, self.rawsize)


class PE:
    def __init__(self, path):
        self.path = path
        self.data = bytearray(open(path, "rb").read())
        if self.data[:2] != b"MZ":
            raise ValueError("不是有效的 PE 文件（缺少 MZ 头）")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("不是有效的 PE 文件（缺少 PE 签名）")
        coff = e_lfanew + 4
        self.machine, self.nsections = struct.unpack_from("<HH", self.data, coff)
        opt_size = struct.unpack_from("<H", self.data, coff + 16)[0]
        opt = coff + 20
        self.magic = struct.unpack_from("<H", self.data, opt)[0]
        if self.magic == 0x10B:      # PE32
            self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
        elif self.magic == 0x20B:    # PE32+
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
        else:
            raise ValueError("未知的可选头 magic: 0x%X" % self.magic)
        sec_off = opt + opt_size
        self.sections = []
        for i in range(self.nsections):
            o = sec_off + i * 40
            name = self.data[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", self.data, o + 8)
            chars = struct.unpack_from("<I", self.data, o + 36)[0]
            self.sections.append(Section(name, va, vsize, raw, rawsize, chars))
        self._text = self._pick(".text")
        self._rdata = self._pick(".rdata")

    def _pick(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    # --- 地址换算 ---
    def rva_to_off(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                d = rva - s.va
                if d < s.rawsize:
                    return s.raw + d
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s.raw <= off < s.raw + s.rawsize:
                return s.va + (off - s.raw)
        return None

    def va_to_off(self, va):
        return self.rva_to_off(va - self.image_base)

    def off_to_va(self, off):
        r = self.off_to_rva(off)
        return None if r is None else self.image_base + r

    def section_of_rva(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                return s
        return None

    def read_u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def text_span(self):
        s = self._text
        return (s.raw, s.raw + s.rawsize) if s else (0, 0)

    def find_all(self, needle, start=0, end=None):
        end = len(self.data) if end is None else end
        out, pos = [], start
        while True:
            i = self.data.find(needle, pos, end)
            if i < 0:
                return out
            out.append(i)
            pos = i + 1

    def cstr(self, off, maxlen=200):
        e = self.data.find(b"\x00", off, off + maxlen)
        if e < 0:
            e = off + maxlen
        return bytes(self.data[off:e])

    def find_string(self, literal):
        """在 .rdata（找不到就全文件）里定位一个字符串字面量，返回 (VA, 文件偏移)。

        注意：只要求是「字符串开头」，不要求后面紧跟 NUL —— 目标字面量可能只是
        某个更长字符串的前缀（例如弹窗文案后面还接着一句问句）。
        """
        for sec in ([self._rdata] if self._rdata else []) + self.sections:
            if sec is None:
                continue
            end = sec.raw + sec.rawsize
            pos = sec.raw
            while True:
                i = self.data.find(literal, pos, end)
                if i < 0:
                    break
                if i == 0 or self.data[i - 1] == 0:      # 确认是字符串起始
                    return self.off_to_va(i), i
                pos = i + 1
        return None, None

    def sha256(self):
        return hashlib.sha256(bytes(self.data)).hexdigest()


# --------------------------------------------------------------------------- #
# 补丁点模型
# --------------------------------------------------------------------------- #

class Site:
    def __init__(self, key, title, offset, old, new, va=None, detail="", confidence="high"):
        self.key = key
        self.title = title
        self.offset = offset
        self.old = bytes(old)
        self.new = bytes(new)
        self.va = va
        self.detail = detail
        self.confidence = confidence

    def check(self, pe):
        cur = bytes(pe.data[self.offset:self.offset + len(self.old)])
        if cur == self.new:
            return "already"
        if cur == self.old:
            return "ready"
        return "mismatch"

    def describe(self):
        loc = "file 0x%08X" % self.offset
        if self.va:
            loc += " / VA 0x%08X" % self.va
        return "%-22s %s  %s -> %s" % (
            self.key, loc, self.old.hex(" "), self.new.hex(" "))


# --------------------------------------------------------------------------- #
# 特征码引擎
# --------------------------------------------------------------------------- #

def _anchor_about_trial_full(pe):
    """锚点 A0（旧签名）—— About 对话框里的 `flag ? "Trial" : "Full"`。

    形状：
        39 1D <flag32>         cmp dword ptr [flag], ebx
        74 xx                  je  <push Full>
        68 <trialVA32>         push "Trial"
        EB xx                  jmp <after>
        68 <fullVA32>          push "Full"
    两个字符串地址相差 8 字节。

    注意：**IDM 6.43b15 把这段整段删掉了**（连 "Trial" 字符串都从镜像移除，"Full" 变成
    无条件 push），这是作者针对破解的改动。所以这个锚点在新版上会自然失效，
    由 A1/A2/A3 顶上；它保留下来是为了照顾 b8 及更早的版本。
    """
    hits = set()
    tstart, tend = pe.text_span()
    trial_vas = set()
    for m in pe.find_all(b"Trial\x00"):
        va = pe.off_to_va(m)
        if va:
            trial_vas.add(va)
    if not trial_vas:
        return hits
    for m in pe.find_all(b"\x68"):
        if not (tstart <= m < tend - 12):
            continue
        if pe.data[m + 5] != 0xEB or pe.data[m + 7] != 0x68:
            continue
        trial_va = pe.read_u32(m + 1)
        full_va = pe.read_u32(m + 8)
        if trial_va not in trial_vas or full_va != trial_va - 8:
            continue
        off_full = pe.va_to_off(full_va)
        if off_full is None or pe.cstr(off_full, 8) != b"Full":
            continue
        for back in range(4, 24):
            p = m - back
            if p < tstart:
                break
            if pe.data[p] == 0x39 and pe.data[p + 1] in (0x05, 0x0D, 0x15, 0x1D, 0x35, 0x3D):
                hits.add(pe.read_u32(p + 2))
                break
    return hits


def _anchor_threshold(pe):
    """锚点 A3（最强）—— MSVC 为 `flag ? 30 : 15` 生成的无分支选择器。

        A1 <F>                 mov  eax, [F]
        F7 D8                  neg  eax
        1B C0                  sbb  eax, eax
        83 E0 0F               and  eax, 0xF
        83 C0 0F               add  eax, 0xF
        A3 <F+4>               mov  [F+4], eax

    12 条固定指令，极独特；且第二个操作数必须是 F+4，**自带自校验**。
    这个锚点跨 b8/b15 逐字节相同，只在地址上有别。
    """
    hits = set()
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    pos = 0
    while True:
        i = data.find(b"\xA1", pos)
        if i < 0:
            break
        pos = i + 1
        if not (tstart <= i < tend - 22):
            continue
        c = data[i:i + 22]
        if len(c) < 22:
            continue
        if (c[5:7] == b"\xF7\xD8" and c[7:9] == b"\x1B\xC0"
                and c[9:12] == b"\x83\xE0\x0F" and c[12:15] == b"\x83\xC0\x0F"
                and c[15] == 0xA3):
            f = struct.unpack_from("<I", c, 1)[0]
            g = struct.unpack_from("<I", c, 16)[0]
            if g == f + 4:
                hits.add(f)
    return hits


def _anchor_serial(pe):
    """锚点 A1 —— 序列号格式校验通过后把注册标志写 0。

    形状：`cmp eax,0x17`（长度 23）+ ≥3 处 `cmp byte ptr [ebp+disp32], 0x2d`（三个 '-'）
          + `C7 05 <F> 00 00 00 00`（mov dword [F], 0）
    直接给出标志地址，不依赖相对布局。
    """
    hits = set()
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    pos = 0
    while True:
        i = data.find(b"\x83\xF8\x17", pos)
        if i < 0:
            break
        pos = i + 1
        if not (tstart <= i < tend - 0x60):
            continue
        win = data[i:i + 0x60]
        dashes, j = 0, 0
        while True:
            k = win.find(b"\x80\xBD", j)
            if k < 0:
                break
            if k + 6 < len(win) and win[k + 6] == 0x2D:
                dashes += 1
            j = k + 1
        if dashes < 3:
            continue
        c = win.find(b"\xC7\x05")
        while c >= 0:
            if c + 10 <= len(win) and win[c + 6:c + 10] == b"\x00\x00\x00\x00":
                hits.add(struct.unpack_from("<I", win, c + 2)[0])
                break
            c = win.find(b"\xC7\x05", c + 1)
    return hits


def _anchor_naggate(pe):
    """锚点 A2 —— 试用弹窗触发链的总门控。

    形状：`83 3D <F> 00 74`（cmp dword ptr [F], 0 / je）+ 32 字节内出现 `68 D8 14 00 00`
          （push 0x14D8）。
    命令 ID 0x14D8 在 b8 与 b15 中**完全一致**，是最稳的魔数之一。
    """
    hits = set()
    tstart, tend = pe.text_span()
    data = bytes(pe.data)
    pos = 0
    while True:
        i = data.find(b"\x83\x3D", pos)
        if i < 0:
            break
        pos = i + 1
        if not (tstart <= i < tend - 32):
            continue
        win = data[i:i + 32]
        if len(win) < 8 or win[6] != 0x00 or win[7] not in (0x74, 0x75):
            continue
        if b"\x68\xD8\x14\x00\x00" in win:
            hits.add(struct.unpack_from("<I", win, 2)[0])
    return hits


_FLAG_ANCHORS = (
    ("about",     _anchor_about_trial_full),
    ("threshold", _anchor_threshold),
    ("serial",    _anchor_serial),
    ("naggate",   _anchor_naggate),
)


def find_registration_flag(pe):
    """
    P1 —— 定位"注册状态"全局（0 = Full / 非 0 = Trial）。

    多锚点投票：四个互相独立的判据各自给出候选地址，取票数最高且唯一者。
    票数并列或全无命中就返回 None（**失败即安全**，宁可跳过也不猜着改）。

    为什么改成投票：旧实现只依赖 About 对话框的 UI 文案，而 IDM 6.43b15
    把这整段判定删掉了（反破解），单点判据直接失效。新判据锚在**注册逻辑本身**
    （序列号校验形状、试用弹窗门控的命令 ID、Trial?30:15 的无分支选择器），
    改这些等于改功能，成本高得多。
    """
    notes = []
    votes = {}
    for name, fn in _FLAG_ANCHORS:
        try:
            hits = fn(pe)
        except Exception as exc:
            notes.append("锚点 %-9s 异常：%s" % (name, exc))
            continue
        if not hits:
            notes.append("锚点 %-9s 无命中" % name)
        else:
            notes.append("锚点 %-9s 命中 %s"
                         % (name, "、".join("0x%08X" % h for h in sorted(hits))))
        for h in hits:
            votes.setdefault(h, []).append(name)

    if not votes:
        notes.append("四个锚点全部无命中，无法定位注册标志")
        return None, notes

    ranked = sorted(votes.items(), key=lambda kv: -len(kv[1]))
    best, names = ranked[0]
    if len(ranked) > 1 and len(ranked[1][1]) == len(names):
        notes.append("票数并列（0x%08X 与 0x%08X 各 %d 票），放弃"
                     % (best, ranked[1][0], len(names)))
        return None, notes

    flag_va = best
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
    conf = "high" if len(names) >= 2 else "medium"
    notes.append("选定标志 VA 0x%08X（%d 票：%s），段 %s，文件偏移 0x%08X，"
                 "当前初值 0x%08X（%s），置信度 %s"
                 % (flag_va, len(names), "、".join(names), sec.name, flag_off,
                    cur, "Trial" if cur else "Full", conf))
    detail = "多锚点投票定位（%s）" % "、".join(names)
    if cur == 0:
        notes.append("已经是 Full（0），无需修改")
        return Site("registration_flag", "注册状态全局", flag_off,
                    b"\x00\x00\x00\x00", b"\x00\x00\x00\x00",
                    va=flag_va, detail=detail, confidence=conf), notes
    return Site("registration_flag", "注册状态全局 -> Full",
                flag_off, struct.pack("<I", cur), b"\x00\x00\x00\x00",
                va=flag_va, detail=detail, confidence=conf), notes


def find_expiry_format(pe):
    """
    P2 —— 把日期格式串 "%b/%d/%Y" 改成 "%b/%d/9999"。

    IDM 的 nExpDt 是 __time64_t，但 RegQueryValueExA 的 lpcbData = 4，
    实际只读 32 位，硬上限 0x7FFFFFFF = 2038-01-19，结构上到不了 9999。
    所以这里改格式串，让界面直接显示 9999。
    该串全镜像唯一，且后面有足够 NUL 填充容纳更长的串。
    """
    notes = []
    hits = pe.find_all(EXPIRY_FMT_OLD)
    if not hits:
        if pe.find_all(EXPIRY_FMT_NEW):
            notes.append("格式串已经是 %s —— P2 之前打过了"
                         % EXPIRY_FMT_NEW.decode())
        else:
            notes.append("没找到格式串 %s" % EXPIRY_FMT_OLD.decode())
        return None, notes
    if len(hits) > 1:
        notes.append("格式串出现 %d 次，不唯一，放弃（避免改错）" % len(hits))
        return None, notes
    off = hits[0]
    # 需要放下更长的串：原串 9 字节 + NUL，新串 10 字节 + NUL
    room = 0
    p = off + len(EXPIRY_FMT_OLD)
    while p < len(pe.data) and pe.data[p] == 0 and room < 8:
        room += 1
        p += 1
    if room < 1:
        notes.append("格式串后面没有 NUL 填充，放不下 9999 变体")
        return None, notes
    notes.append("格式串 VA 0x%08X，后随 %d 字节 NUL 填充，可容纳 %s"
                 % (pe.image_base + pe.off_to_rva(off), room, EXPIRY_FMT_NEW.decode()))
    # 诚实披露：该字面量被多处共用，需要确认它们语义一致
    tstart, tend = pe.text_span()
    users = []
    pat = struct.pack("<I", pe.image_base + pe.off_to_rva(off))
    for m in pe.find_all(b"\x68" + pat):
        if tstart <= m < tend:
            users.append(pe.image_base + pe.off_to_rva(m))
    if users:
        notes.append("该格式串被 %d 处 push 引用（%s）。"
                     % (len(users), "、".join("VA 0x%08X" % u for u in users)))
        notes.append("已核实这几处都是「许可证到期时间」显示（前两处读注册表 nExpDt，"
                     "其余读由注册校验路径写入的全局），统一显示 9999 语义一致。")
    old = bytes(pe.data[off:off + len(EXPIRY_FMT_OLD) + 1])
    new = EXPIRY_FMT_NEW + b"\x00"
    if old == new:
        return Site("expiry_display_9999", "到期显示 9999", off, new, new,
                    va=pe.image_base + pe.off_to_rva(off), detail="已打过"), notes
    return Site("expiry_display_9999", "到期显示 9999",
                off, old, new, va=pe.image_base + pe.off_to_rva(off),
                detail='"%s" -> "%s"' % (EXPIRY_FMT_OLD.decode(), EXPIRY_FMT_NEW.decode())), notes


def find_nag_function(pe):
    """
    P3 —— 让试用登记弹窗函数变成空操作（纵深防御，可选）。

    链条：
      文案字面量 -> 找到 "push <字面量>; mov ecx,<CString全局>; call ..." 的初始化点
                -> 取出 CString 全局 VA
                -> 找 "mov eax,[该全局]"（A1 xx xx xx xx），即弹窗函数开头
                -> 向前扫 int3 填充确认函数边界
                -> 在函数体内找它自己的 "mov eax,1 ; ret" 收尾，把入口改成 jmp 过去
                   （保持返回值 1，且不改变调用约定 —— 比直接写 ret 安全）
    任何一步不满足就放弃，不改。
    """
    notes = []
    va_lit, off_lit = pe.find_string(NAG_LITERAL)
    if va_lit is None:
        notes.append("没找到试用弹窗文案字面量")
        return None, notes
    notes.append("弹窗文案 VA 0x%08X" % va_lit)

    lit_pat = struct.pack("<I", va_lit)
    tstart, tend = pe.text_span()
    cstring_va = None
    for m in pe.find_all(b"\x68" + lit_pat):
        if not (tstart <= m < tend):
            continue
        # 期望后面紧跟 B9 <global32>（mov ecx, imm32）
        if pe.data[m + 5] == 0xB9:
            cstring_va = pe.read_u32(m + 6)
            notes.append("CString 全局 VA 0x%08X（初始化点 VA 0x%08X）"
                         % (cstring_va, pe.image_base + pe.off_to_rva(m)))
            break
    if cstring_va is None:
        notes.append("没找到该文案的 CString 初始化点（形状不符）")
        return None, notes

    # 找 mov eax, [cstring]  —— A1 xx xx xx xx
    hits = pe.find_all(b"\xA1" + struct.pack("<I", cstring_va))
    hits = [h for h in hits if tstart <= h < tend]
    if len(hits) == 0:
        notes.append("没找到 mov eax,[该 CString] —— 该函数可能已经打过 P3"
                     "（锚点指令已被替换成 jmp），跳过")
        return None, notes
    if len(hits) > 1:
        notes.append("引用该 CString 的 mov eax,[..] 有 %d 处，不唯一，放弃" % len(hits))
        return None, notes
    func_off = hits[0]
    # 向前扫 int3 填充确认函数入口：填充结束后那一个字节才是函数起点
    p = func_off - 1
    run = 0
    while p > 0 and pe.data[p] == 0xCC:
        run += 1
        p -= 1
    if run < 2:
        notes.append("函数入口前没有 int3 填充，边界不可信，放弃")
        return None, notes
    func_off = p + 1 + run
    func_va = pe.image_base + pe.off_to_rva(func_off)
    notes.append("弹窗函数入口 VA 0x%08X（前面 %d 字节 int3 填充）" % (func_va, run))

    # 在函数体内找它自己的 mov eax,1 ; ret
    body = bytes(pe.data[func_off:func_off + 0x200])
    tail = body.find(b"\xB8\x01\x00\x00\x00\xC3")
    if tail < 0:
        notes.append("函数体内没找到 'mov eax,1 ; ret' 收尾，放弃")
        return None, notes
    if tail < 5:
        notes.append("收尾太靠近入口，放弃")
        return None, notes
    # 目标 = 函数内尾部；rel32 = 目标 - (入口+5)
    target = func_off + tail
    rel = target - (func_off + 5)
    if not (-0x80000000 <= rel <= 0x7FFFFFFF):
        notes.append("跳转距离超出 rel32，放弃")
        return None, notes
    new = b"\xE9" + struct.pack("<i", rel)
    notes.append("入口改为 jmp 0x%08X（该函数自己的 'mov eax,1; ret'）"
                 % (pe.image_base + pe.off_to_rva(target)))
    old = bytes(pe.data[func_off:func_off + len(new)])
    if old == new:
        return Site("trial_nag_kill", "试用弹窗函数置空", func_off, new, new,
                    va=func_va, detail="已打过"), notes
    return Site("trial_nag_kill", "试用弹窗函数置空",
                func_off, old, new, va=func_va,
                detail="jmp 到自身 'mov eax,1 ; ret' 收尾",
                confidence="medium"), notes


UPDATE_ANCHOR = b"update.cgi"


def find_update_gate(pe):
    """
    P4 —— 解除「升级前必须先注册」的限制（可选，--allow-update）。

    形状（FUN_0042DFB0 —— 更新对话框「现在更新」按钮的 WM_COMMAND 处理器）：
        call [RegQueryValueExA]        ; 读 HKLM/HKCU ...\\Internet Download Manager\\Serial
        85 C0                          test eax, eax
        0F 85 xx xx xx xx              jne  <弹「在升级 IDM 之前请注册」+ EndDialog>
        ...                            ; 成功路径：拼 "update.cgi?<serial>"
        68 <"update.cgi" VA>           push "update.cgi"

    把那条 jne 换成 6 个 NOP = 「查不到 Serial 也走成功路径」。
    安全性：序列号缓冲区在函数入口已被 memset 成 0，所以查不到时它是空串，
    拼出来就是 "update.cgi?"，不会把未初始化栈数据带进 URL。
    """
    notes = []
    va_lit, off_lit = pe.find_string(UPDATE_ANCHOR)
    if va_lit is None:
        notes.append("没找到 'update.cgi' 字面量")
        return None, notes
    notes.append("'update.cgi' VA 0x%08X" % va_lit)

    pat = b"\x68" + struct.pack("<I", va_lit)
    tstart, tend = pe.text_span()
    cands = []
    for m in pe.find_all(pat):
        if not (tstart <= m < tend):
            continue
        for back in range(2, 80):
            p = m - back
            if p < tstart:
                break
            if (pe.data[p] == 0x85 and pe.data[p + 1] == 0xC0 and
                    pe.data[p + 2] == 0x0F and pe.data[p + 3] == 0x85):
                cands.append((p, m))
                break
    if not cands:
        notes.append("在 push 'update.cgi' 之前没找到 test eax,eax / jne rel32 形状")
        return None, notes
    if len(cands) > 1:
        notes.append("匹配到 %d 处，不唯一，放弃（避免改错分支）" % len(cands))
        return None, notes

    p, m = cands[0]
    jne_off = p + 2
    va = pe.image_base + pe.off_to_rva(jne_off)
    notes.append("闸门 VA 0x%08X（test eax,eax 在 push 'update.cgi' 前 %d 字节）"
                 % (va, m - p))
    old = bytes(pe.data[jne_off:jne_off + 6])
    new = b"\x90" * 6
    if old == new:
        return Site("allow_update", "解除升级前注册限制", jne_off, new, new,
                    va=va, detail="已打过"), notes
    if old[:2] != b"\x0F\x85":
        notes.append("闸门处不是 jne rel32（实际 %s），放弃" % old.hex(" "))
        return None, notes
    return Site("allow_update", "解除升级前注册限制", jne_off, old, new, va=va,
                detail="jne -> 6x NOP：查不到 Serial 也走成功路径"), notes


# --------------------------------------------------------------------------- #
# 补丁集
# --------------------------------------------------------------------------- #

def build_sites(pe, want_expiry=True, want_nag_kill=True, want_allow_update=False):
    sites, log = [], []
    for fn, enabled, label in (
        (find_registration_flag, True, "P1 注册状态"),
        (find_expiry_format, want_expiry, "P2 到期显示"),
        (find_nag_function, want_nag_kill, "P3 弹窗函数"),
        (find_update_gate, want_allow_update, "P4 升级闸门"),
    ):
        log.append("")
        log.append("=== %s ===" % label)
        if not enabled:
            log.append("  （已按参数跳过）")
            continue
        try:
            site, notes = fn(pe)
        except Exception as exc:                     # 单点失败不影响其它补丁
            log.append("  [异常] %s" % exc)
            continue
        for n in notes:
            log.append("  · " + n)
        if site is None:
            log.append("  [跳过] 未能可靠定位")
        else:
            log.append("  [命中] " + site.describe())
            if site.old != site.new:
                sites.append(site)
    return sites, log


def apply_sites(pe, sites):
    """在内存里施加补丁，返回逐条结果。"""
    results = []
    for s in sites:
        st = s.check(pe)
        if st == "already":
            results.append((s, "already"))
            continue
        if st != "ready":
            results.append((s, "mismatch"))
            continue
        pe.data[s.offset:s.offset + len(s.new)] = s.new
        results.append((s, "patched"))
    return results


# --------------------------------------------------------------------------- #
# 安装目录 / 提权 / 部署
# --------------------------------------------------------------------------- #

def find_install_dir(explicit=None):
    if explicit:
        return explicit if os.path.isfile(os.path.join(explicit, EXE_NAME)) else None
    # 1) 注册表 ExePath
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager") as k:
            try:
                p, _ = winreg.QueryValueEx(k, "ExePath")
                d = os.path.dirname(p)
                if os.path.isfile(os.path.join(d, EXE_NAME)):
                    return d
            except OSError:
                pass
    except Exception:
        pass
    # 2) 常见路径
    for d in DEFAULT_INSTALL_DIRS:
        if os.path.isfile(os.path.join(d, EXE_NAME)):
            return d
    return None


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("fMask", ctypes.c_ulong),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_ulong),
        ("hIcon", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


class Tee:
    """把 stdout 同时写到控制台和一个日志文件（提权子进程用它回传输出）。"""

    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8", errors="replace")

    def write(self, s):
        try:
            sys.__stdout__.write(s)
        except Exception:
            pass
        try:
            self.f.write(s)
            self.f.flush()
        except Exception:
            pass

    def flush(self):
        try:
            sys.__stdout__.flush()
        except Exception:
            pass
        try:
            self.f.flush()
        except Exception:
            pass


def elevate_and_rerun(log_path=None):
    """以管理员身份重新拉起自己，并**等待它结束**，然后把它的输出打回当前控制台。

    用 ShellExecuteExW 而不是 ShellExecuteW，是为了拿到进程句柄才能 Wait。
    （本机 UAC=不提示时，这一步不会弹任何窗口。）
    """
    argv = [a for a in sys.argv[1:]]
    if log_path:
        argv += ["--log", log_path]
    params = " ".join('"%s"' % a if " " in a else a for a in argv)

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040 | 0x00000100          # NOCLOSEPROCESS | NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = '"%s" %s' % (os.path.abspath(__file__), params)
    sei.lpDirectory = os.getcwd()
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False
    if sei.hProcess:
        INFINITE = 0xFFFFFFFF
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(sei.hProcess), INFINITE)
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(ctypes.c_void_p(sei.hProcess),
                                                  ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(sei.hProcess))
    if log_path and os.path.exists(log_path):
        try:
            print("")
            print("---------- 提权进程的输出 ----------")
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                sys.__stdout__.write(f.read())
            print("------------------------------------")
        except Exception:
            pass
    return True


def do_elevate():
    """申请提权重跑，并回收提权进程的输出。"""
    tmp = os.path.join(tempfile.gettempdir(), "idm-unlock-%d.log" % os.getpid())
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except Exception:
        pass
    return elevate_and_rerun(tmp)


def stop_idm():
    """部署前停掉 IDM，否则 IDMan.exe 被占用会写不进去（WinError 32）。"""
    try:
        r = subprocess.run(["taskkill", "/F", "/IM", EXE_NAME, "/T"],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def dir_writable(path):
    probe = os.path.join(path, ".idm_unlock_probe")
    try:
        with open(probe, "wb") as f:
            f.write(b"x")
        os.remove(probe)
        return True
    except Exception:
        return False


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# 注册表
# --------------------------------------------------------------------------- #

def reg_set_dword(name, value):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager", 0,
                            winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))


def reg_get(name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager") as k:
            v, t = winreg.QueryValueEx(k, name)
            return v
    except Exception:
        return None


def reg_delete(name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def banner():
    print("=" * 74)
    print(" IDM-Unlock  ——  去试用/付费弹窗 + 解锁 Full + 到期显示 9999")
    print(" 特征码驱动 · 版本无关 · 失败即安全（找不到特征码就不改）")
    print("=" * 74)


def cmd_scan(pe, install_dir, args, out):
    print("目标   : %s" % pe.path)
    print("架构   : %s" % ("x86 (PE32)" if pe.magic == 0x10B else "x64 (PE32+)"))
    print("ImageBase: 0x%08X" % pe.image_base)
    print("SHA256 : %s" % pe.sha256())
    print("")

    sites, log = build_sites(pe, want_expiry=not args.no_expiry,
                             want_nag_kill=not args.no_nag_kill,
                             want_allow_update=args.allow_update)
    for line in log:
        print(line)

    print("")
    print("--- 将要施加的补丁 ---")
    if not sites:
        print("  （没有需要施加的补丁）")
    for s in sites:
        st = s.check(pe)
        print("  [%s] %s" % (st, s.describe()))
        if s.detail:
            print("         %s" % s.detail)
        if st == "mismatch":
            print("         !! 当前字节与预期不符，apply 时会拒绝这一条")

    print("")
    print("--- 到期时间说明 ---")
    print("  IDM 把到期日存在 HKCU\\Software\\DownloadManager\\nExpDt，")
    print("  用 __localtime64_s + strftime(\"%%b/%%d/%%Y\") 显示。")
    print("  但 RegQueryValueExA 的 lpcbData=4，只读 32 位 -> 硬上限 0x7FFFFFFF = 2038-01-19。")
    print("  => 9999 年在那个字段里结构上不可达；本工具改为把格式串写成 \"%%b/%%d/9999\"，")
    print("     再把 nExpDt 设为 %d（2037-12-31 12:00 UTC），界面即显示 12/31/9999。" % _expiry_ts())
    print("  当前 nExpDt = %s" % reg_get("nExpDt"))
    print("")

    if out:
        out.update({"mode": "scan", "exe": pe.path, "sha256": pe.sha256(),
                    "sites": [{"key": s.key, "offset": "0x%08X" % s.offset,
                               "va": ("0x%08X" % s.va) if s.va else None,
                               "old": s.old.hex(" "), "new": s.new.hex(" "),
                               "state": s.check(pe)} for s in sites]})
    return 0


def cmd_apply(pe, install_dir, args, out):
    rc = cmd_scan(pe, install_dir, args, None)
    print("")
    print("=" * 74)

    sites, _ = build_sites(pe, want_expiry=not args.no_expiry,
                           want_nag_kill=not args.no_nag_kill,
                           want_allow_update=args.allow_update)
    todo = [s for s in sites if s.check(pe) == "ready"]
    if not todo:
        print("没有需要施加的补丁（可能已经打过）。")
        if out:
            out.update({"mode": "apply", "result": "nothing-to-do"})
        return 0

    bad = [s for s in sites if s.check(pe) == "mismatch"]
    if bad:
        print("!! 有 %d 处补丁的当前字节与预期不符，已拒绝：" % len(bad))
        for s in bad:
            print("   %s" % s.describe())
        print("   这通常意味着 IDM 版本变了。请先用 --scan 复核，不要强行打。")
        if out:
            out.update({"mode": "apply", "result": "refused-mismatch"})
        return 3

    results = apply_sites(pe, todo)
    ok = 0
    for s, st in results:
        print("  [%s] %s" % (st, s.describe()))
        if st == "patched":
            ok += 1
    print("已在内存中施加 %d 处补丁。" % ok)

    # ---- 离线模式：只写指定输出文件 ----
    if args.out:
        try:
            with open(args.out, "wb") as f:
                f.write(bytes(pe.data))
        except Exception as exc:
            print("!! 写输出失败：%s" % exc)
            return 5
        print("输出   : %s" % args.out)
        print("         sha256 %s" % file_sha256(args.out))
        print("（离线模式：未改动安装目录、未改注册表、未提权）")
        if out:
            out.update({"mode": "apply", "result": "ok-offline", "patched": ok,
                        "out": args.out, "sha256": file_sha256(args.out)})
        return 0

    # ---- 写文件 + 部署 ----
    exe_path = os.path.join(install_dir, EXE_NAME)
    bak_path = exe_path + BACKUP_SUFFIX
    tmp_path = exe_path + ".idm-unlock-new"

    if not dir_writable(install_dir) and not is_admin():
        print("")
        print("安装目录不可写，正在申请管理员权限重新运行 ...")
        if do_elevate():
            return 0
        print("!! 提权失败。请右键以管理员身份运行本脚本。")
        return 4

    try:
        if stop_idm():
            print("已停止正在运行的 IDM（避免文件占用）")
            time.sleep(2)

        if not os.path.exists(bak_path):
            shutil.copy2(exe_path, bak_path)
            print("备份   : %s" % bak_path)
            print("         sha256 %s" % file_sha256(bak_path))
        else:
            print("备份   : 已存在，保持不动 %s" % bak_path)

        with open(tmp_path, "wb") as f:
            f.write(bytes(pe.data))
        # 先写临时文件再替换，避免半截状态
        shutil.move(tmp_path, exe_path)
        print("部署   : %s" % exe_path)
        print("         sha256 %s" % file_sha256(exe_path))
    except Exception as exc:
        print("!! 部署失败：%s" % exc)
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return 5

    # ---- 注册表：到期时间 ----
    if not args.no_expiry:
        ts = _expiry_ts()
        old = reg_get("nExpDt")
        reg_set_dword("nExpDt", ts)
        print("注册表 : nExpDt %s -> %d（2037-12-31 12:00 UTC，界面显示 12/31/9999）"
              % (old, ts))

    # ---- 防回退 ----
    if args.lockdown:
        try:
            reg_set_dword("LastCheckQU", int(time.time()))
            print("防回退 : LastCheckQU 已刷新为当前时间（关闭 7 天自动更新门控）")
        except Exception as exc:
            print("防回退 : 刷新 LastCheckQU 失败：%s" % exc)

    print("")
    print("完成。请打开 IDM -> 帮助 -> 关于 IDM，版本行应显示 'Full'。")
    if out:
        out.update({"mode": "apply", "result": "ok", "patched": ok,
                    "deployed": exe_path, "sha256": file_sha256(exe_path)})
    return 0


def cmd_restore(install_dir, out):
    exe_path = os.path.join(install_dir, EXE_NAME)
    bak_path = exe_path + BACKUP_SUFFIX
    if not os.path.exists(bak_path):
        print("!! 找不到备份 %s，无法还原。" % bak_path)
        return 6
    if not dir_writable(install_dir) and not is_admin():
        print("安装目录不可写，正在申请管理员权限重新运行 ...")
        if do_elevate():
            return 0
        print("!! 提权失败。")
        return 4
    try:
        shutil.copy2(bak_path, exe_path)
        print("已还原 : %s" % exe_path)
        print("         sha256 %s" % file_sha256(exe_path))
        reg_delete("nExpDt")
        print("注册表 : 已删除 nExpDt（恢复官方默认：不显示到期行）")
        if out:
            out.update({"mode": "restore", "result": "ok", "sha256": file_sha256(exe_path)})
        return 0
    except Exception as exc:
        print("!! 还原失败：%s" % exc)
        return 5


def main():
    ap = argparse.ArgumentParser(
        description="IDM 一键解锁：去试用/付费弹窗 + 解锁 Full + 到期显示 9999（特征码驱动，版本无关）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法示例")[-1])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--scan", action="store_true", help="只分析不修改（默认）")
    g.add_argument("--apply", action="store_true", help="备份 + 打补丁 + 部署")
    g.add_argument("--restore", action="store_true", help="从备份还原官方原版")
    ap.add_argument("--install-dir", default=None, help="IDM 安装目录（默认自动查找）")
    ap.add_argument("--exe", default=None,
                    help="直接指定要处理的 IDMan.exe；此模式下部署目标是该文件所在目录，"
                         "绝不会回落到自动查找的安装目录")
    ap.add_argument("--out", default=None,
                    help="纯离线：把打过补丁的文件写到这个路径，不碰安装目录、不改注册表、不提权")
    ap.add_argument("--no-expiry", action="store_true", help="不改到期显示（不打 9999）")
    ap.add_argument("--no-nag-kill", action="store_true", help="不做 P3 弹窗函数置空")
    ap.add_argument("--allow-update", action="store_true",
                    help="打 P4：解除「升级前必须先注册」的限制，让「快速更新」可用")
    ap.add_argument("--lockdown", action="store_true", help="顺便关闭自动更新门控")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--log", default=None,
                    help=argparse.SUPPRESS)          # 提权子进程内部使用：回传输出
    args = ap.parse_args()

    if args.log:
        try:
            sys.stdout = Tee(args.log)
        except Exception:
            pass

    out = {}
    banner()

    # ---- 解析目标路径（顺序很重要：--install-dir > --exe > 自动查找）----
    if args.install_dir:
        install_dir = find_install_dir(args.install_dir)
        if not install_dir:
            print("!! 指定的安装目录里没有 %s：%s" % (EXE_NAME, args.install_dir))
            return 1
        target = os.path.join(install_dir, EXE_NAME)
    elif args.exe:
        target = os.path.abspath(args.exe)
        install_dir = os.path.dirname(target)      # 绝不回落到自动查找的目录
    else:
        install_dir = find_install_dir(None)
        if not install_dir:
            print("!! 找不到 IDM 安装目录。请用 --install-dir 指定。")
            return 1
        target = os.path.join(install_dir, EXE_NAME)

    if not os.path.isfile(target):
        print("!! 文件不存在：%s" % target)
        return 1

    if args.restore:
        rc = cmd_restore(install_dir, out)
    else:
        try:
            pe = PE(target)
        except Exception as exc:
            print("!! 解析失败：%s" % exc)
            return 2
        if args.apply:
            rc = cmd_apply(pe, install_dir, args, out)
        else:
            rc = cmd_scan(pe, install_dir, args, out)

    if args.json and out:
        print("")
        print(json.dumps(out, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
