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
  P16 corrupt_flag_gate   : 「IDM is corrupt」告警**根治** —— 损坏判定标志的写者改成 5×NOP，
                            让 IDM 根本不认为自身 exe 损坏（唯一读者就是弹窗 gate）。
  P17 corrupt_alert_exit  : 兜底 —— 告警对话框的**唯一显示出口** `call` 改成 `mov eax,1`
                            （等价「用户点了继续下载」；**禁止补清栈**）。
  P18 corrupt_nag_route_31: **【已 RETIRED·实测崩溃，不要启用】** OnTimer 字节表路由改道（id=0x31）。
                            实测 P18/P19 × 3 = 崩 2；改道后 `KillTimer` 不再执行 ⇒ timer 一直响
                            ⇒ 反复走 `0x4882A9` 的虚调用清理 ⇒ `0xC0000005`。
  P19 corrupt_nag_route_26: **【已 RETIRED·同上】** 同族平行变体（id=0x26）。实现保留作否证记录。
  P21 corrupt_nag_thread_b: **当前方案** —— 把 case 0x1517 里 `call _beginthreadex`（线程 0x484DB0）
                            换成 `mov eax,1` ⇒ nag 线程不创建 ⇒ 弹窗不可能出现。
  P22 corrupt_nag_thread_c: **当前方案** —— 同族变体 C（case 0x14BF，线程 0x47D520）。
                            ⚠️ 变体 A（线程 0x483FB0，`0x49626B`）= **菜单功能，故意不覆盖**。

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
        # 按 old/new 各自的长度分别比对 —— P2 的 old/new 长度不同
        # （`%b/%d/%Y\0` -> `%b/%d/9999\0` 复用了原来的结尾 NUL，净变化 4 字节），
        # 若统一用 len(old) 去比 new 会永远不相等，进而误报 mismatch。
        for probe, verdict in ((self.new, "already"), (self.old, "ready")):
            cur = bytes(pe.data[self.offset:self.offset + len(probe)])
            if cur == probe:
                return verdict
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


def find_counterfeit_guard(pe):
    """P4 counterfeit 闸门 —— 「注册校验失败 -> 写 MData 标记 -> ExitProcess」那条路。

    这条路径是 x32dbg 运行时逆向出来的（静态是加密的，反汇编是垃圾）。
    完整逻辑：

        cmp  eax, 17            ; strlen(serial) == 23 ?
        jne  <counterfeit>      ; 否 -> 写标记并退出
        cmp  [ebp+831], bl      ; serial[5]  == '-' ?
        jne  <counterfeit>
        cmp  [ebp+837], bl      ; serial[11] == '-' ?
        jne  <counterfeit>
        cmp  [ebp+83D], bl      ; serial[17] == '-' ?
        je   <valid>            ; 全部合法 -> 正常返回 1
    <counterfeit>:
        mov  ecx, [global]      ; <<< 入口：开始拼 MData
        ...
        call RegSetValueExA(hk, "MData", 0, REG_NONE, buf, 256)
        call RegFlushKey
        ...
        call ExitProcess(0)     ; 直接退出，用户看到「假冒的序列号…IDM 正在退出」

    **关键**：前面 4 个 RegQueryValueExA 读不到值（jne）也会跳到这个入口 ——
    也就是说只要注册信息**不完整**就会写 MData 并退出。这正是
    「重复检测把激活状态搞掉」的根源，也是守护必须清 MData 的原因。

    把入口那 6 字节的 `mov ecx,[global]` 换成 `jmp <valid>`，任何失败路径
    都直接变成「返回成功」，既不写标记也不退出 —— 从根上杜绝。

    特征码（disp32 通配）：
        38 9D ?? ?? ?? ??    cmp byte ptr [ebp+disp32], bl
        0F 84 ?? ?? ?? ??    je  <valid>
        8B 0D ?? ?? ?? ??    mov ecx, [global]      <- 补丁点
        8D 95 ?? ?? ?? ??    lea edx, [ebp+disp32]
    """
    import re as _re
    import struct as _s

    notes = []
    tstart, tend = pe.text_span()
    body = bytes(pe.data[tstart:tend])
    pat = _re.compile(
        rb"\x38\x9d(....)\x0f\x84(....)\x8b\x0d(....)\x8d\x95(....)",
        _re.DOTALL)

    cands = []
    for m in pat.finditer(body):
        off = tstart + m.start()
        je_off = off + 6
        rel = _s.unpack("<i", m.group(2))[0]
        valid_target = je_off + 6 + rel          # je 的下一条指令是 off+12
        cands.append((off + 12, valid_target))

    if not cands:
        notes.append("  没找到 counterfeit 闸门特征码（版本可能已变）")
        return None, notes
    if len(cands) > 1:
        notes.append("  特征码命中 %d 处，不唯一，放弃" % len(cands))
        return None, notes

    patch_off, target = cands[0]
    old = bytes(pe.data[patch_off:patch_off + 6])
    if old[:2] != b"\x8b\x0d":
        notes.append("  补丁点字节不符：%s" % old.hex(" "))
        return None, notes

    rel32 = target - (patch_off + 5)
    new = b"\xe9" + _s.pack("<i", rel32) + b"\x90"

    va = pe.off_to_va(patch_off)
    notes.append("  counterfeit 入口 @ file 0x%08X / VA 0x%08X" % (patch_off, va or 0))
    notes.append("  成功出口 target = 0x%08X（相对跳转 %+d 字节）" % (target, rel32))
    notes.append("  %s -> %s   (mov ecx,[global] -> jmp <返回成功>)" %
                 (old.hex(" "), new.hex(" ")))

    return Site("counterfeit_guard", "P4 counterfeit 闸门封堵",
                patch_off, old, new, va=va,
                detail="任何注册校验失败路径直接返回成功，不再写 MData、不再 ExitProcess"), notes


# --------------------------------------------------------------------------- #
# P5 / P6 —— 免守护方案的核心：让 IDM 结构上无法自杀、无法弹 counterfeit 框
# --------------------------------------------------------------------------- #

def _data_directories(pe):
    """返回可选头数据目录列表 [(rva, size), ...]。"""
    e = struct.unpack_from("<I", pe.data, 0x3C)[0]
    coff = e + 4
    opt_size = struct.unpack_from("<H", pe.data, coff + 16)[0]
    opt = coff + 20
    n = struct.unpack_from("<I", pe.data, opt + 92)[0]
    out = []
    for i in range(n):
        out.append(struct.unpack_from("<II", pe.data, opt + 96 + i * 8))
    return out


def _import_iat_va(pe, func_name):
    """从导入表解析某个导入函数的 IAT 槽 VA。找不到返回 None。

    不写死地址：这样即使版本变化、IAT 槽搬家，也能重新定位。
    """
    dirs = _data_directories(pe)
    if len(dirs) < 2:
        return None
    imp_rva, _ = dirs[1]
    if not imp_rva:
        return None
    off = pe.rva_to_off(imp_rva)
    if off is None:
        return None
    while True:
        oft, _ts, _fc, nm, ft = struct.unpack_from("<IIIII", pe.data, off)
        if nm == 0:
            break
        thunk = oft or ft
        to = pe.rva_to_off(thunk)
        iat_off = pe.rva_to_off(ft)
        if to is None or iat_off is None:
            break
        i = 0
        while True:
            t = struct.unpack_from("<I", pe.data, to + i * 4)[0]
            if t == 0:
                break
            if not (t & 0x80000000):
                no = pe.rva_to_off(t)
                if no is not None:
                    end = pe.data.find(b"\x00", no + 2)
                    s = bytes(pe.data[no + 2:end]).decode("latin-1", "replace")
                    if s == func_name:
                        return pe.off_to_va(iat_off + i * 4)
            i += 1
        off += 20
    return None


def _func_bounds(pe, off):
    """用 int3 填充近似函数边界。返回 (start_off, end_off)。"""
    import re as _re
    ts, te = pe.text_span()
    lo = max(ts, off - 0x8000)
    seg = bytes(pe.data[lo:off])
    ms = list(_re.finditer(rb"\xcc{2,}", seg))
    s = lo + ms[-1].end() if ms else lo
    hi = min(te, off + 0x8000)
    fwd = _re.search(rb"\xcc{2,}", bytes(pe.data[off:hi]))
    e = off + fwd.start() if fwd else hi
    return s, e


def find_tripwire_exits(pe):
    """P5 —— 封死 counterfeit tripwire 的 4 处 `ExitProcess(0)` 出口。

    背景（实测）：伪造序列号后，IDM 会在 ~62 秒判定 counterfeit，写 256 字节
    `MData` 标记并 `ExitProcess(0)`，用户看到「假冒的序列号…IDM 正在退出」。
    全文件共 7 处 `call [ExitProcess]`，其中 4 处属这条自杀路径，而现有 P4
    只封住了其中一条的入径 —— 另外 3 条照样能杀进程。P5 直接封出口。

    两种形态，都用内容锚定，不写死地址：

    (a) push-form（3 处）：`6A 00 FF 15 <ExitProcess IAT>`
        整段 8 字节 -> `83 C4 04` + 5×NOP：既丢弃栈上实参，又保持栈平衡。
        判别条件：所在函数内必须含 `push <MData 串 VA>`。这一条很关键 ——
        通用错误出口 `sub_410C60` 同样是 `push 0; call [ExitProcess]`，
        但它不引用 MData，必须排除。

    (b) branch-form（1 处）：`80 BF disp32 00 75 rel8 C6 87 disp32 01`
        该形态全文件唯一。它由 `jne` 直跳 ExitProcess 且**前面没有 push**，
        所以不能加 `add esp,4`（会栈失衡）——改为把 `75 xx` 换成 `90 90`
        让分支落空，走 `mov byte[edi+disp],1` 的正常路径。
    """
    import re as _re
    notes = []
    iat_va = _import_iat_va(pe, "ExitProcess")
    if iat_va is None:
        notes.append("  未能从导入表解析 ExitProcess 的 IAT 槽，P5 跳过")
        return [], notes
    notes.append("  ExitProcess IAT 槽 VA = 0x%08X" % iat_va)

    mdata_va, _ = pe.find_string(b"MData")
    if mdata_va is None:
        notes.append("  未找到 MData 字符串，P5(a) 无法做归属判别，跳过")
        mdata_va = None
    else:
        notes.append("  MData 串 VA = 0x%08X" % mdata_va)

    tstart, tend = pe.text_span()
    exit_call = b"\xff\x15" + struct.pack("<I", iat_va)
    sites = []

    # --- (a) push-form ---
    # 两趟搜索：先找未补丁形态，再找已补丁形态 —— 这样重复运行工具时
    # 能报「已在位」而不是「未命中」，补丁保持幂等。
    #
    # 补丁内容必须是「8 个 NOP」，不能是 `add esp,4` + NOP：
    #   本形态的 8 字节整体就是 `push 0; call [ExitProcess]`，两者一起删掉
    #   才不改变栈状态。W3(sub_521050) 的分支 `je 0x52177A` 恰好**直接跳到
    #   那个 push 上**，若改成 `add esp,4` 就会把从未压入的 4 字节弹掉 ——
    #   实测表现为 IDM 在 ~61s 以 0x80000003 (STATUS_BREAKPOINT) 崩溃。
    NEW_A = b"\x90" * 8
    if mdata_va is not None:
        mdata_push = b"\x68" + struct.pack("<I", mdata_va)
        old_a = b"\x6a\x00" + exit_call
        for pat in (old_a, NEW_A):
            for m in _re.finditer(_re.escape(pat), bytes(pe.data[tstart:tend])):
                off = tstart + m.start()
                fs, fe = _func_bounds(pe, off)
                if mdata_push not in bytes(pe.data[fs:fe]):
                    if pat is old_a:
                        notes.append("  [排除] file 0x%08X：所在函数不引用 MData（通用错误出口）" % off)
                    continue
                va = pe.off_to_va(off)
                sites.append(Site(
                    "tripwire_exit_%X" % off, "P5 tripwire 出口封死 (push 形态)",
                    off, old_a, NEW_A, va=va,
                    detail="push 0; call [ExitProcess] -> nop×8（push 与 call 一起去掉，栈不变）"))
                notes.append("  [命中] VA 0x%08X：%s -> %s"
                             % (va or 0, old_a.hex(" "), NEW_A.hex(" ")))

    # --- (b) branch-form ---
    # 同样两趟：`75 rel8`（未补丁）与 `90 90`（已补丁）。
    patb_old = _re.compile(rb"\x80\xbf(....)\x00\x75(.)\xc6\x87(....)\x01", _re.DOTALL)
    patb_new = _re.compile(rb"\x80\xbf(....)\x00\x90\x90\xc6\x87(....)\x01", _re.DOTALL)
    for patb, applied in ((patb_old, False), (patb_new, True)):
        for m in patb.finditer(bytes(pe.data[tstart:tend])):
            off = tstart + m.start()
            jne_off = off + 7
            if applied:
                old_b = b"\x75\x41"          # 名义值；check() 先比对 new，故不影响判定
            else:
                rel = struct.unpack("<b", m.group(2))[0]
                target = jne_off + 2 + rel
                if bytes(pe.data[target:target + 6]) != exit_call:
                    continue
                old_b = bytes(pe.data[jne_off:jne_off + 2])
            va = pe.off_to_va(jne_off)
            sites.append(Site(
                "tripwire_branch_%X" % jne_off, "P5 tripwire 出口封死 (branch 形态)",
                jne_off, old_b, b"\x90\x90", va=va,
                detail="jne -> call [ExitProcess] 改为落空（此形态无前置 push，不能动栈）"))
            notes.append("  [命中] VA 0x%08X：%s -> 90 90" % (va or 0, old_b.hex(" ")))

    if len(sites) != 4:
        notes.append("  ⚠ 期望 4 处 tripwire 出口，实际命中 %d 处" % len(sites))
    return sites, notes


# counterfeit 文案的特征词 —— 用于按「内容」而不是「地址」定位消息 CString
_COUNTERFEIT_NEEDLES = (
    b"counterfeit Serial Number",
    b"blocked because of different registrations",
)


def find_counterfeit_popups(pe):
    """P6 —— 静音 counterfeit 弹窗。

    思路（全内容锚定，不写死地址）：

      1. 在 .rdata 里按 ASCII 内容找到 counterfeit 文案串；
      2. 找 `push <串VA>` 的初始化序列，读出紧随其后的
         `mov <reg>, <全局CString>` —— 该全局就是文案的载体；
      3. 在 .text 里找引用该全局的指令；若其前方 28 字节内同时出现
         `push 0x50030`（MB 标志）与 `push <标题>`，则其后第一条 `E8 call`
         就是弹窗调用；
      4. 仅当该 call 之后紧跟 `83 C4 10`（清理 4 个压栈实参）时才补丁 ——
         这样把 call 换成 NOP 不会破坏栈平衡；调用点之后都是
         `jmp`，不使用返回值，因此返回值丢失无害。

    实测命中 2 处，均位于 license 消息派发器 `sub_451E30` 内。
    """
    import re as _re
    notes = []
    sites = []

    str_vas = set()
    for nd in _COUNTERFEIT_NEEDLES:
        pos = 0
        while True:
            i = pe.data.find(nd, pos)
            if i < 0:
                break
            pos = i + 1
            # 回退到字符串起点（前一个 NUL 之后）
            s = pe.data.rfind(b"\x00", max(0, i - 600), i)
            s = s + 1
            va = pe.off_to_va(s)
            if va:
                str_vas.add(va)
    if not str_vas:
        notes.append("  未找到 counterfeit 文案串，P6 跳过")
        return [], notes
    for v in sorted(str_vas):
        notes.append("  counterfeit 文案串 VA = 0x%08X" % v)

    # 2) 文案 -> CString 全局
    globs = {}
    tstart, tend = pe.text_span()
    for sv in sorted(str_vas):
        p = b"\x68" + struct.pack("<I", sv)
        for m in _re.finditer(_re.escape(p), bytes(pe.data[tstart:tend])):
            off = tstart + m.start()
            mm = _re.match(rb"\xb9(....)|\xba(....)|\xa1(....)",
                           bytes(pe.data[off + 5:off + 15]), _re.DOTALL)
            if mm:
                g = struct.unpack("<I", [x for x in mm.groups() if x][0])[0]
                globs[g] = sv
    if not globs:
        notes.append("  未能从初始化序列推出 CString 全局，P6 跳过")
        return [], notes
    for g, sv in sorted(globs.items()):
        notes.append("  文案全局 0x%08X（承载 VA 0x%08X）" % (g, sv))

    # 3) 由已知 counterfeit 调用点反推「弹窗包装函数」与「宿主消息派发器」
    #
    #    只补丁「引用 counterfeit 文案的那两个调用点」是不够的：实测该派发器
    #    sub_451E30 内共有 6 处 call <弹窗包装>，其中 4 处后面跟 add esp,0x10、
    #    另 2 处跟更大的清理量。IDM 的提示文案来自语言文件（Languages\*.lng，
    #    形如 `20349=...`），消息号是运行期决定的 —— 服务端返回的提示、以及
    #    “fake Serial Number / Be aware that the cracked product…” 这类**既不在
    #    二进制、也不在任何 .lng 里**的文案，都会走这个派发器的其它调用点。
    #    因此这里改为：**静音整个派发器内的所有弹窗调用**。
    FLAGS = b"\x68\x30\x00\x05\x00"
    NEW_P = b"\x90" * 5
    wrapper = None
    host_bounds = None
    glob_ref = None
    for g in sorted(globs):
        gp = struct.pack("<I", g)
        for m in _re.finditer(_re.escape(gp), bytes(pe.data[tstart:tend])):
            off = tstart + m.start()
            if FLAGS not in bytes(pe.data[max(tstart, off - 28):off]):
                continue
            glob_ref = off
            cm = _re.search(rb"\xe8(....)", bytes(pe.data[off:off + 24]), _re.DOTALL)
            if not cm:
                continue
            call_off = off + cm.start()
            tgt = (pe.off_to_va(call_off) + 5
                   + struct.unpack("<i", bytes(pe.data[call_off + 1:call_off + 5]))[0])
            wrapper = tgt
            host_bounds = _func_bounds(pe, call_off)
    if wrapper is None and glob_ref is not None:
        # 已补丁形态的兜底：包装函数的反推依赖「文案全局引用点之后 24B 内的 E8 call」，
        # 而那个 call 一旦被打成 5×NOP，反推链就断了（旧版会直接 return 0 点，
        # 导致二次施加后 P6 从 7 变 0，「点数不变」的幂等验收无法成立）。
        # 但**引用点本身没被打补丁**（补丁只覆盖其后的 call），仍可用它定位派发器边界，
        # 让老 7 点被下面的 `\x90{5}\x83\xC4` 认回。
        host_bounds = _func_bounds(pe, glob_ref)
    if host_bounds is None:
        notes.append("  未能定位弹窗派发器边界，P6 跳过")
        return [], notes
    if wrapper is None:
        notes.append("  包装函数无法反推（其 call 已被 NOP）——改用文案全局引用点定派发器边界")
    else:
        notes.append("  弹窗包装函数 VA = 0x%08X" % wrapper)
    notes.append("  宿主消息派发器 file 0x%08X - 0x%08X" % host_bounds)

    # 4) 静音该派发器内的全部弹窗调用（两趟：未补丁 / 已补丁，保证幂等）
    hs, he = host_bounds
    body = bytes(pe.data[hs:he])
    todo = []
    for m in _re.finditer(rb"\xe8(....)", body, _re.DOTALL):
        call_off = hs + m.start()
        tgt = (pe.off_to_va(call_off) + 5
               + struct.unpack("<i", m.group(1))[0])
        if tgt == wrapper:
            todo.append((call_off, bytes(pe.data[call_off:call_off + 5])))
    # 已补丁形态：5×NOP 紧跟 `83 C4 imm`（add esp,imm）
    done_offs = set()
    for m in _re.finditer(rb"\x90{5}\x83\xc4", body, _re.DOTALL):
        done_offs.add(hs + m.start())
    for call_off in sorted(done_offs):
        todo.append((call_off, b"\xe8\x00\x00\x00\x00"))   # 名义值；check() 先比 new

    seen = set()
    for call_off, old_p in sorted(todo):
        if call_off in seen:
            continue
        seen.add(call_off)
        # 栈平衡校验：call 之后必须是 `83 C4 imm`（add esp,imm）。
        # 只要满足，把 call 换成 5×NOP 就不会破坏栈 —— 实参仍被同一条 add 清理。
        after = bytes(pe.data[call_off + 5:call_off + 8])
        if not (len(after) == 3 and after[0] == 0x83 and after[1] == 0xC4):
            notes.append("  [跳过] file 0x%08X：call 之后不是 add esp,imm（%s），"
                         "为保栈平衡不补丁" % (call_off, after.hex(" ")))
            continue
        va = pe.off_to_va(call_off)
        sites.append(Site(
            "license_popup_%X" % call_off, "P6 许可消息弹窗静音",
            call_off, old_p, NEW_P, va=va,
            detail="call <弹窗包装> -> nop×5（后续 add esp,imm 仍清理实参）"))
        notes.append("  [命中] VA 0x%08X：%s -> 90 90 90 90 90（清理 add esp,0x%02X）"
                     % (va or 0, old_p.hex(" "), after[2]))

    if not sites:
        notes.append("  ⚠ 未命中任何弹窗调用点")
    return sites, notes


# --------------------------------------------------------------------------- #
# P7 —— 封死 counterfeit「广播」线程（用户实际看到的那条弹窗）
#
# 这条路径**不是** MessageBox：它以 AfxBeginThread 起一个 worker，
# worker 里把 .data 里的两段 XOR 0x0F 密文（标题 + 正文）就地解密成 CString，
# 再用 PostMessageA(hWnd, WM_COMMAND=0x111, wParam=0x1509, lParam=CString[2])
# 投递给主窗口。因此：
#   · 它的 uType（按钮形态）不在任何 `push imm` 里 —— 这正是
#     「全库 287 个 MessageBox 站点都找不到压 `6a 01`」的原因；
#   · 它也不在 P6 的 `sub_451E30` 派发器里，所以 P1–P6 全部漏过。
#
# 实测（b15 工作副本，IDA 会话 idm643b15 双向核对）：
#   · 正文密文 VA 0x77BED0（XOR 0x0F 后 255B 的 counterfeit 英文正文）
#     **全文件仅 1 处 xref**；标题密文 VA 0x77BEB0 同样**仅 1 处 xref**；
#   · 该 worker `sub_468C60`(0x468C60) **仅 1 处 xref**：`0x49A241`
#     处作为 `AfxBeginThread(sub_468C60, 0, 0, 0, 0)` 的**线程入口**；
#   · 它的签名是 `unsigned int __cdecl f(void*)`，函数体**恒 return 0**
#     （含 `operator new` 失败分支），返回值即线程退出码，无人消费；
#   · ⇒ 把入口换成 `31 C0 C3`（xor eax,eax; ret）与原型为**语义等价**，
#     唯一差别是那条 PostMessage 不再发出 → 弹窗结构上不可能出现。
# --------------------------------------------------------------------------- #

# counterfeit 正文的明文特征词（落盘是 XOR 0x0F 密文，按内容锚定不写死地址）
_COUNTERFEIT_BODY_NEEDLE = (
    b"Internet Download Manager has been registered with a fake Serial Number")
_XOR_KEY = 0x0F
# worker 的入口形态：`push 8` + `call <operator new>`（函数首两指令）
_WORKER_ENTRY_HEAD = b"\x6a\x08\xe8"
_WORKER_ENTRY_PATCH = b"\x31\xc0\xc3"          # xor eax,eax ; ret


def find_counterfeit_broadcast(pe):
    """P7 —— 让 counterfeit 广播 worker 结构上无法再弹框。

    全内容锚定（不写死任何地址）：
      1. 把明文特征词 XOR 0x0F，得到密文特征 → 全文件唯一定位正文密文串 VA=S；
      2. `.text` 里找 `push S` → 唯一命中处所在函数即该 worker；
      3. 复查该函数内**同时**含标题密文的 `push`（专用性双重确认），
         且入口首 3 字节 == `6a 08 e8`（push 8 + call operator new）；
      4. 入口 3 字节原地换成 `31 C0 C3` —— **等长替换，不影响任何相对位移**。

    幂等：已补丁形态（入口已是 `31 C0 C3`）用同一套锚点认回（第 2/3 步的
    锚点都没被改动），重复施加第二次仍然报同一个点、状态 `already`。
    """
    import re as _re
    notes = []
    sites = []
    enc = bytes(b ^ _XOR_KEY for b in _COUNTERFEIT_BODY_NEEDLE)
    cand_off = pe.find_all(enc)
    # 只保留 .data 里、且解密后整段是可打印 ASCII 的候选（防误命中 .text 巧合）
    body_va = None
    for o in cand_off:
        va = pe.off_to_va(o)
        if va is None:
            continue
        dec = bytes(b ^ _XOR_KEY for b in bytes(pe.data[o:o + len(enc)]))
        if dec == _COUNTERFEIT_BODY_NEEDLE:
            body_va = va
            break
    if body_va is None:
        notes.append("  未找到 counterfeit 正文密文串（XOR 0x%02X），P7 跳过" % _XOR_KEY)
        return [], notes
    notes.append("  正文密文 VA = 0x%08X（XOR 0x%02X，命中 %d 处）"
                 % (body_va, _XOR_KEY, len(cand_off)))

    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    push_body = b"\x68" + struct.pack("<I", body_va)
    sites_off = [tstart + m.start() for m in _re.finditer(_re.escape(push_body), text)]
    if len(sites_off) != 1:
        notes.append("  `push <正文密文>` 命中 %d 处（期望 1），P7 跳过" % len(sites_off))
        return [], notes
    push_off = sites_off[0]
    fs, fe = _func_bounds(pe, push_off)
    notes.append("  `push <正文密文>` file 0x%08X；宿主函数 file 0x%08X - 0x%08X"
                 % (push_off, fs, fe))
    if (fe - fs) > 0x800:
        notes.append("  ⚠ 宿主函数跨度异常（>0x800），疑似 _func_bounds 跨函数合并，P7 跳过")
        return [], notes

    # 专用性复查：同一函数内必须也有标题密文的 push，且没有第二个正文 push
    body = bytes(pe.data[fs:fe])
    n_body = body.count(push_body)
    if n_body != 1:
        notes.append("  ⚠ 宿主函数内 `push <正文密文>` 出现 %d 次（期望 1），P7 跳过" % n_body)
        return [], notes

    head = bytes(pe.data[fs:fs + 3])
    if head == _WORKER_ENTRY_PATCH:
        notes.append("  入口已是 31 C0 C3（P7 已在位，幂等认回）")
    elif head != _WORKER_ENTRY_HEAD:
        notes.append("  ⚠ 宿主函数首 3 字节为 %s（期望 %s = push 8 + call），P7 跳过"
                     % (head.hex(" "), _WORKER_ENTRY_HEAD.hex(" ")))
        return [], notes

    va = pe.off_to_va(fs)
    sites.append(Site(
        "counterfeit_broadcast_%X" % fs, "P7 counterfeit 广播线程封死",
        fs, _WORKER_ENTRY_HEAD, _WORKER_ENTRY_PATCH, va=va,
        detail="worker 入口 push 8;call new -> xor eax,eax;ret（等长，恒返回 0；"
               "仅少发一次 PostMessage(0x111,0x1509)）"))
    notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                 % (va or 0, _WORKER_ENTRY_HEAD.hex(" "), _WORKER_ENTRY_PATCH.hex(" "),
                    "已在位" if head == _WORKER_ENTRY_PATCH else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P9 —— 让 `MData` 不再被写入（counterfeit 记账标记的**产生端**）
#
# 实机证据（verdict 实测）：活体注册表里 `Model=288` / `Therad=1` 只可能由
# `sub_466EE0` 写出 ⇒ 该函数确实执行过；而同函数内的 `MData` 写入是那条
# 「62s 自杀 + 标记」链路里**唯一还活着的**写入点（`sub_521050` 的三处
# `"MData"` 写入已被证明落在 `v22==0` 死分支）。
#
# 该函数内共有 **3 处** `RegSetValueExA`，各自独立调用点（实测）：
#   0x467274 写 "Model"（push 0x6A13B0）、0x46729A 写 "Therad"（push 0x6A13A8）、
#   0x4676D9 写 "MData"（push 0x69D1E4）← **本补丁只封这一处**。
#
# 三关（实测）：
#   ① 栈平衡：`RegSetValueExA` 是 stdcall，**被调方清 24B**；`call` 之后没有
#      `add esp`（0x4676DF 直接 `mov edx,[ebp-0x14]`）⇒ 只把 call 换 NOP 会残留
#      6 个实参 ⇒ 必须补 `add esp,0x18`。故补丁 = `83 c4 18` + 3×NOP（6→6 等长）。
#   ② 返回值：`RegSetValueExA` 的 eax 立刻被紧随的 `RegFlushKey` 覆盖，
#      无 `cmp/test eax`、无存局部 ⇒ 跳过写入无副作用。
#   ③ 退出：紧随其后的 `push 0; call [ExitProcess]`（VA 0x4676F9）**已被 P5 覆盖**
#      （P5 的 W2 站点，8×NOP）⇒ 只封写入、不封退出，语义成立：
#      MData 不再产生，进程也不会因这条路径而死。
# --------------------------------------------------------------------------- #

_MDATA_WRITE_HEAD = b"\x83\xc4\x18\x90\x90\x90"     # 已补丁形态：add esp,0x18 + 3×NOP


def find_mdata_write(pe):
    """P9 —— 封死 `MData` 的写入调用点（只封 MData，不动 Model/Therad）。

    全内容锚定（不写死任何地址）：
      1. `pe.find_string(b"MData")` 取字面量 VA；
      2. 逐条 `push <MData VA>`（`68 xx xx xx xx`）向后 24B 内找
         `call dword ptr [<RegSetValueExA IAT>]`（IAT 由导入表解析）——
         **同函数内的另一处 `push <MData VA>` 是 RegQueryValueExA 的读**，由此天然排除；
      3. **唯一保留的排除条件 = 可达性**：落在 P4（`find_counterfeit_guard`）已封入口的
         同一个函数内的写入，其入口已被改道 ⇒ 写入不可达 ⇒ 跳过（防投机扩点）。
         ⚠️ **教训（P9 修订）**：早期版本还要求「调用点 +10B 处必是
         `call dword ptr [<RegFlushKey IAT>]`」——**该锚点过严**，只对 `sub_466EE0` 型
         （写后立刻 flush）成立；`sub_521050` 型写后**不** flush ⇒ 它把**活路径**
         file 0x120A54 误判为假候选而漏掉。**锚点过严 = 假阴性，与过松 = 假阳性同样危险。**
         也**不要**用 `call [ExitProcess]` 当锚点：P5 施加后会把它打成 8×NOP，
         导致 P9 认不回自己（实测踩过）。
      4. 命中 → 把那条 6 字节 `ff 15 <iat>` 换成 `83 c4 18 90 90 90`
         （`add esp,0x18` 清 stdcall 的 6 个实参 + 3×NOP）。

    幂等：已补丁形态（第 2 步位置已是 `83 c4 18 90 90 90`）由第 2 步的
    `push <MData VA>` 内容锚 + old-bytes 硬断言原样认回（不依赖任何会被补丁破坏的字节）。
    """
    import re as _re
    notes = []
    sites = []
    mdata_va, _ = pe.find_string(b"MData")
    if mdata_va is None:
        notes.append("  未找到 MData 字面量，P9 跳过")
        return [], notes
    iat_set = _import_iat_va(pe, "RegSetValueExA")
    iat_flush = _import_iat_va(pe, "RegFlushKey")
    iat_query = _import_iat_va(pe, "RegQueryValueExA")
    if not (iat_set and iat_flush):
        notes.append("  导入表缺少 RegSetValueExA/RegFlushKey，P9 跳过")
        return [], notes
    notes.append("  MData 字面量 VA = 0x%08X" % mdata_va)
    notes.append("  IAT: RegSetValueExA=0x%08X RegFlushKey=0x%08X RegQueryValueExA=%s"
                 % (iat_set, iat_flush, ("0x%08X" % iat_query) if iat_query else "-"))

    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    push_mdata = b"\x68" + struct.pack("<I", mdata_va)
    call_set = b"\xff\x15" + struct.pack("<I", iat_set)
    call_flush = b"\xff\x15" + struct.pack("<I", iat_flush)
    qpat = struct.pack("<I", iat_query) if iat_query else None

    def has_mdata_gate(fs, fe):
        """反向门控：函数内存在 `push <MData VA>` 之后紧跟 `mov reg, ds:[RegQueryValueExA]`。"""
        if qpat is None:
            return False
        body = bytes(pe.data[fs:fe])
        for mm in _re.finditer(_re.escape(push_mdata), body):
            win = body[mm.start():mm.start() + 20]
            for q in _re.finditer(_re.escape(qpat), win):
                if q.start() >= 2 and win[q.start() - 2] == 0x8B:
                    return True
        return False

    # 可达性排除：P4 闸门所在的函数（**必须兼容「未补丁 / 已补丁」两种状态**）
    # ⚠️ 实测教训：不能只调 find_counterfeit_guard —— 它的特征码只认**原始**字节，
    #    打完 P4 之后它返回 None ⇒ sealed_fns 静默变空 ⇒ 被排除的点重新入选，
    #    二次施加就从 clean 变成「再打一遍」（P9 从 2 点变 3 点、幂等被破坏）。
    #    故此处自己扫**两种形态**（P9 内部自洽，不改动 P4 finder 的任何行为）。
    sealed_fns = set()
    _GATE_PATS = (
        rb"\x38\x9d(....)\x0f\x84(....)\x8b\x0d(....)\x8d\x95(....)",   # 原始
        rb"\x38\x9d(....)\x0f\x84(....)\xe9(....)\x90\x8d\x95(....)",   # P4 已施加（jmp+nop）
    )
    for _p in _GATE_PATS:
        for _mm in _re.finditer(_p, text, _re.DOTALL):
            try:
                sealed_fns.add(tuple(_func_bounds(pe, tstart + _mm.start())))
            except Exception:
                pass
    notes.append("  P4 闸门函数 %d 个（其内写入按不可达跳过）" % len(sealed_fns))

    cands = []
    for m in _re.finditer(_re.escape(push_mdata), text):
        off = tstart + m.start()
        win = bytes(pe.data[off:off + 24])
        i_un = win.find(call_set)              # 未补丁形态
        i_pa = win.find(_MDATA_WRITE_HEAD)     # 已补丁形态
        if i_un >= 0:
            cands.append((off + i_un, False))
        elif i_pa >= 0:
            cands.append((off + i_pa, True))
    if not cands:
        notes.append("  `push <MData VA>` 之后 24B 内既无 RegSetValueExA 调用、"
                     "也无已补丁形态，P9 未命中")
        return [], notes

    for call_off, applied in sorted(set(cands)):
        fs, fe = _func_bounds(pe, call_off)
        # ★ 硬断言（Lead 要求保留）：落点 6 字节必须逐字节等于两种形态之一，
        #   否则说明偏移算错 —— 直接跳过并报错，绝不静默施加。
        here = bytes(pe.data[call_off:call_off + 6])
        if here not in (call_set, _MDATA_WRITE_HEAD):
            notes.append("  [❌断言失败] file 0x%08X 落点字节 = %s，"
                         "既非 %s 也非 %s —— 偏移计算有误，拒绝施加"
                         % (call_off, here.hex(" "), call_set.hex(" "),
                            _MDATA_WRITE_HEAD.hex(" ")))
            continue
        # ── P9 修订（动态定案）──────────────────────────────────────────────
        # ⚠️ 教训：原先要求「+10B 必是 RegFlushKey」——**该锚点过严**。它只对
        #    `sub_466EE0` 型（写后立刻 flush）成立；`sub_521050` 型写后**不** flush
        #    ⇒ 它把**活路径** file 0x120A54 误判为「假候选」而漏掉。
        #    **锚点过严 = 假阴性，与「锚点过松 = 假阳性」同样危险。**
        #    现只保留：内容锚（push<MData> + call[RegSetValueExA]）+ old-bytes 硬断言。
        # 唯一保留的排除条件 = **可达性**：落在 P4（find_counterfeit_guard）已封入口的
        # 同一个函数内的写入，入口已被改道 ⇒ 写入不可达，封它零收益（防投机扩点）。
        if (fs, fe) in sealed_fns:
            notes.append("  [跳过] file 0x%08X：位于 P4 已封入口的函数内（写入不可达）"
                         % call_off)
            continue
        if has_mdata_gate(fs, fe):
            notes.append("  · file 0x%08X 宿主含「查后写」反向门控（sub_466EE0 型）" % call_off)
        else:
            notes.append("  · file 0x%08X 宿主无反向门控、写后不 flush（sub_521050 型）" % call_off)
        va = pe.off_to_va(call_off)
        # `old` 一律用**名义值**（未补丁形态的 call 字节），与 P5/P6 同理：
        # check() 先比 new，所以已补丁形态会判成 already；而 old != new 保证该点
        # 不会被 build_all_sites 过滤掉 ⇒ 二次施加后总点数不变（幂等验收要求）。
        sites.append(Site(
            "mdata_write_%X" % call_off, "P9 MData 写入封死",
            call_off, call_set, _MDATA_WRITE_HEAD, va=va,
            detail="call [RegSetValueExA] -> add esp,0x18 + nop×3"
                   "（stdcall 被调方本应清 24B；只封 MData，Model/Therad 不受影响）"))
        notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                     % (va or 0, call_set.hex(" "), _MDATA_WRITE_HEAD.hex(" "),
                        "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P8 —— 封 `IDMGrHlp.exe`（**第二目标二进制**）的 counterfeit 弹窗显示端
#
# 背景：用户看到的弹窗来自独立进程 `IDMGrHlp.exe`（class #32770，标题
# `Internet Download Manager`，按钮 确定/取消），**不是** IDMan.exe 内的弹窗链。
# 正文/标题是该 exe 内**本地内嵌**的密文（逐字节立即数 → `sub_4051B0` 分组解密，
# key "506938841"）；正文密文仅 216B = 27 块 ⇒ 只可能是 217 字符的「无从句短版」，
# 与 IDMan.exe 的 255B 长版（P7 已封）是两份不同密文。
#
# 三关（两处同形，实测）：
#   ① 栈平衡：call 前 4 个 push = 16B；call 之后紧跟 `cmp`/`mov`、**没有** `add esp`
#      ⇒ MessageBoxA 是 stdcall（被调方清 16B）⇒ 跳过 call **必须自己补 `add esp,0x10`**。
#      ⛔ 禁止使用 `31 c0 90 90 90 90`（只清 eax 不清栈 ⇒ 每点泄漏 16B ⇒ 栈失衡）。
#   ② 返回值：uType 0x1031 那处被 `cmp eax,1` 消费（决定是否 ShellExecuteA 打开 URL）；
#      uType 0x1030 那处的 eax 随后被 `xor eax,eax` 清掉。两处统一 `xor eax,eax`
#      既安全又更保守。
#   ③ 调用方分支：eax=0 ⇒ 走「用户未确认」分支，不再打开 URL，也不再显示弹窗。
# --------------------------------------------------------------------------- #

_GRHLP_STUB = b"\x83\xc4\x10\x31\xc0\x90"        # add esp,0x10 ; xor eax,eax ; nop
_GRHLP_STUB_ALT = b"\x83\xc4\x10\x90\x90\x90"    # 早期形态（仅清栈），仍可认回


def find_idmgrhlp_popups(pe):
    """P8 —— 封 `IDMGrHlp.exe` 内两处 counterfeit `MessageBoxA` 调用点。

    全内容锚定（不写死任何偏移）：
      1. `MessageBoxA` 的 IAT 项地址 ← 由导入表解析；
      2. 逐条 `push 0x1030` / `push 0x1031`，在其后 48B 内找
         `call dword ptr [<MessageBoxA IAT>]`（未补丁）或已补丁桩（幂等识别）；
      3. **old-bytes 硬断言**：落点 6 字节必须逐字节 ∈ {原 call, 两种桩}，否则拒绝。
    """
    import re as _re
    notes, sites = [], []
    iat = _import_iat_va(pe, "MessageBoxA")
    if not iat:
        notes.append("  导入表无 MessageBoxA，P8 跳过")
        return [], notes
    notes.append("  MessageBoxA IAT = 0x%08X" % iat)
    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    call = b"\xff\x15" + struct.pack("<I", iat)
    forms = (call, _GRHLP_STUB, _GRHLP_STUB_ALT)
    for ut, label in ((0x1030, "单按钮 MB_OK"), (0x1031, "双按钮 MB_OKCANCEL")):
        for m in _re.finditer(_re.escape(b"\x68" + struct.pack("<I", ut)), text):
            off = tstart + m.start()
            win = bytes(pe.data[off:off + 48])
            hit = next(((off + win.find(f), f) for f in forms if f in win), None)
            if hit is None:
                continue
            co, form = hit
            here = bytes(pe.data[co:co + 6])
            if here not in forms:
                notes.append("  [断言失败] file 0x%08X 落点字节 = %s，"
                             "不属于任何已知形态 —— 拒绝施加"
                             % (co, here.hex(" ")))
                continue
            sites.append(Site(
                "grhlp_msgbox_%X" % co, "P8 IDMGrHlp 弹窗静音",
                co, call, _GRHLP_STUB, va=pe.off_to_va(co),
                detail="uType=0x%X(%s) call [MessageBoxA] -> add esp,0x10+xor eax,nop"
                       % (ut, label)))
            notes.append("  [命中] VA 0x%08X uType=0x%X(%s)：%s -> %s（%s）"
                         % (pe.off_to_va(co) or 0, ut, label, form.hex(" "),
                            _GRHLP_STUB.hex(" "),
                            "已在位" if form != call else "本次施加"))
    return sites, notes


HELPER_FINDERS = (
    (find_idmgrhlp_popups, "P8 IDMGrHlp counterfeit 弹窗静音"),
)


# --------------------------------------------------------------------------- #
# P10 —— `IDMan.exe` 内「**长版（带从句）** counterfeit 弹窗」的显示端
#
# 动态定案（prober 实测 t=77.89s）：返回地址 `IDMan.exe+0x76049`
#   ⇒ `call` 在 RVA `0x76044` / VA `0x476044` / **file `0x75444`**
#   ⇒ uType `0x41030`(MB_TOPMOST|MB_SYSTEMMODAL|MB_ICONWARNING，单按钮)，正文 = 255 字符长版
#
# 该函数在**弹窗之前**有一段**运行期解密循环**（实测）：
#     0x476024 xor byte ptr [esp+ecx+0x10], 17h ; inc ecx ; cmp ecx,eax ; jl 0x476024
# ⇒ 正文是**运行期解密进栈缓冲**的 —— 这正是「`.data 0x77BED0` 密文直接引用只有 1 处、却仍能显示」
#   的原因，也说明**封显示端比封文本来源更稳**（与文本来源完全解耦）。
#
# 三关（实测）：
#   ① 栈平衡：call 前 4 个 push = 16B；call **之后 3 字节就是 `83 C4 10`**（add esp,0x10）
#      ⇒ **cdecl、调用方清栈** ⇒ 删掉 call 后**绝不能补 `add esp`**（补了就多清 16B ⇒ 栈失衡）。
#      ⚠️ 与 P8/P9 相反：那两处被调方是 stdcall、无调用方清栈，所以**必须**自补。
#   ② 返回值：`add esp,0x10` 后紧跟 `push 0xFA; call [<api>]` ⇒ eax **未被消费**。
#   ③ 调用方分支：删掉后原样继续（其后还会 `PostMessageA(hwnd,0x111,0x149B,0)`）。
# --------------------------------------------------------------------------- #

_P10_PRELUDE = (b"\x68\x30\x10\x04\x00"      # push 0x41030
                b"\x8d\x54\x24\x14"          # lea edx, [esp+0x14]
                b"\x52\x50\x51")             # push edx ; push eax ; push ecx
_P10_STUB = b"\x31\xc0\x90\x90\x90"          # xor eax,eax ; nop×3（纯 5B，不动栈）
_P10_CLEANUP = b"\x83\xc4\x10"               # call 后由调用方自带的 add esp,0x10


def find_counterfeit_longtext_popup(pe):
    """P10 —— 封「长版（带从句）counterfeit 弹窗」的显示调用点。

    内容锚定（**不写死任何偏移**）：
      1. 锚 = 调用点**前 12 字节**的指令序列
         `push 0x41030` + `lea edx,[esp+0x14]` + `push edx/push eax/push ecx`。
         用「call **之前**」的字节做锚 ⇒ **与补丁状态无关** ⇒ 天然支持幂等；
      2. 锚后紧跟的 5 字节必须是 `e8 rel32`（未补丁）或 `31 c0 90 90 90`（已补丁）；
      3. 校验 A（结构）：`e8` 的 rel32 目标函数体内含 `MessageBoxA/W` 调用，防锚串味；
      4. 校验 B（形态前提）：调用点 **+5 处必须是 `83 c4 10`**，证明「调用方清栈」成立；
      5. **old-bytes 硬断言**：落点 5 字节必须逐字节 ∈{原 call, 桩}，否则拒绝施加。
    """
    import re as _re
    notes, sites = [], []
    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    mb_iat = [v for v in (_import_iat_va(pe, "MessageBoxA"),
                          _import_iat_va(pe, "MessageBoxW")) if v]
    hits = list(_re.finditer(_re.escape(_P10_PRELUDE), text))
    notes.append("  前锚命中 %d 处（push 0x41030 + lea edx,[esp+0x14] + push×3）" % len(hits))
    for m in hits:
        call_off = tstart + m.start() + len(_P10_PRELUDE)
        here = bytes(pe.data[call_off:call_off + 5])
        applied = here == _P10_STUB
        if not applied:
            if here[:1] != b"\xe8":
                notes.append("  [❌断言失败] file 0x%08X 落点字节 = %s，既非 E8 开头亦非桩 —— 拒绝"
                             % (call_off, here.hex(" ")))
                continue
            rel = struct.unpack("<i", here[1:5])[0]
            tgt = (pe.off_to_va(call_off) + 5 + rel) & 0xFFFFFFFF
            to = pe.va_to_off(tgt)
            fs_, fe_ = _func_bounds(pe, to)
            body = bytes(pe.data[fs_:fe_])
            if not any((b"\xff\x15" + struct.pack("<I", i)) in body for i in mb_iat):
                notes.append("  [跳过] file 0x%08X：call 目标 0x%X 函数体内无 MessageBox，非同族包装"
                             % (call_off, tgt))
                continue
            notes.append("  · file 0x%08X call 目标 = 0x%X（含 MessageBox ✓）" % (call_off, tgt))
        tail = bytes(pe.data[call_off + 5:call_off + 8])
        if tail != _P10_CLEANUP:
            notes.append("  [跳过] file 0x%08X：call 后不是 `83 c4 10`"
                         "（「调用方清栈」前提不成立，形态须重算）" % call_off)
            continue
        # `old` 必须用**当前实际字节**（`e8 rel32` 的位移随版本/包装位置变化），
        # 否则 Site.check() 第 3 分支会判成 mismatch、apply_all 直接拒绝。
        # 已补丁时用名义值（只要 != new 即可，保证该点不被 build_all_sites 过滤）。
        old_bytes = b"\xe8\x00\x00\x00\x00" if applied else here
        sites.append(Site(
            "longtext_popup_%X" % call_off, "P10 长版 counterfeit 弹窗静音",
            call_off, old_bytes, _P10_STUB, va=pe.off_to_va(call_off),
            detail="call rel32 -> xor eax,eax + nop×3（5→5 等长；cdecl 且已有 add esp,0x10，"
                   "**禁止补清栈**）"))
        notes.append("  [命中] VA 0x%08X -> 桩（%s）"
                     % (pe.off_to_va(call_off) or 0, "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P11 —— 补齐**最后一条已知显示点**（静态存在、当前场景未被触发）「纵深防御」
#
# 站点：file `0x79E49` / VA `0x47AA49`，宿主 `sub_47AA00`（线程过程，
#       由 `sub_48F7D0` 的 **case `0x1509`** 经 `AfxBeginThread` 启动；全库仅 1 处立即数引用）。
# 与 P10 **同型**（同一弹窗包装 `0x474D20`、同为 uType `0x41030`、同为 cdecl + 调用方 `add esp,0x10`）
#       ⇒ 形态完全一致：`E8 rel32` → `31 C0 90 90 90`，**禁止补清栈**。
#
# 它**不是投机扩点**的理由：调用目标同为弹窗包装；宿主真实存在；启动点唯一；
# 只是 prober 在「下载」场景里没命中（属潜在/遗留路径）。用户要求「最稳妥」⇒ 一并封掉。
# --------------------------------------------------------------------------- #

# 前锚 = 调用点**之前 13 字节**的完整指令序列（与 P10 的前锚不同，故互不干扰）：
#   push 0x41030 ; push eax ; push ecx ; mov eax,[hWnd 全局] ; push eax
_P11_PRELUDE = (b"\x68\x30\x10\x04\x00"      # push 0x41030
                b"\x50\x51"                  # push eax ; push ecx   （caption / text）
                b"\xa1\xd0\x93\x78\x00"      # mov eax, dword ptr [0x7893D0]   （hWnd 全局）
                b"\x50")                     # push eax


def find_latent_longtext_popup(pe):
    """P11 —— 封「静态存在但当前未被触发」的第三条长版 counterfeit 显示点。

    定位与校验**沿用 P10 的双校验**（内容锚定，不写死偏移）：
      1. 锚 = 调用点前 13 字节的指令序列（**call 之前**的字节 ⇒ 与补丁状态无关 ⇒ 天然幂等）；
      2. 锚后 5 字节必须 `e8 rel32`（未补丁）或 `31 c0 90 90 90`（已补丁）；
      3. 校验 A：rel32 目标函数体内含 `MessageBoxA/W`（防锚串味）；
      4. 校验 B：调用点 +5 处必须是 `83 c4 10`（「调用方清栈」前提成立，形态才成立）；
      5. **old-bytes 硬断言**：落点 5 字节必须逐字节 ∈{原 call, 桩}，否则拒绝施加。
    """
    import re as _re
    notes, sites = [], []
    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    mb_iat = [v for v in (_import_iat_va(pe, "MessageBoxA"),
                          _import_iat_va(pe, "MessageBoxW")) if v]
    hits = list(_re.finditer(_re.escape(_P11_PRELUDE), text))
    notes.append("  前锚命中 %d 处（push 0x41030 + push eax/ecx + mov eax,[hWnd] + push eax）"
                 % len(hits))
    for m in hits:
        call_off = tstart + m.start() + len(_P11_PRELUDE)
        here = bytes(pe.data[call_off:call_off + 5])
        applied = here == _P10_STUB
        if not applied:
            if here[:1] != b"\xe8":
                notes.append("  [❌断言失败] file 0x%08X 落点字节 = %s，既非 E8 开头亦非桩 —— 拒绝"
                             % (call_off, here.hex(" ")))
                continue
            rel = struct.unpack("<i", here[1:5])[0]
            tgt = (pe.off_to_va(call_off) + 5 + rel) & 0xFFFFFFFF
            to = pe.va_to_off(tgt)
            fs_, fe_ = _func_bounds(pe, to)
            body = bytes(pe.data[fs_:fe_])
            if not any((b"\xff\x15" + struct.pack("<I", i)) in body for i in mb_iat):
                notes.append("  [跳过] file 0x%08X：call 目标 0x%X 函数体内无 MessageBox" %
                             (call_off, tgt))
                continue
            notes.append("  · file 0x%08X call 目标 = 0x%X（含 MessageBox ✓）" % (call_off, tgt))
        tail = bytes(pe.data[call_off + 5:call_off + 8])
        if tail != _P10_CLEANUP:
            notes.append("  [跳过] file 0x%08X：call 后不是 `83 c4 10`（清栈前提不成立）" % call_off)
            continue
        old_bytes = b"\xe8\x00\x00\x00\x00" if applied else here
        sites.append(Site(
            "latent_popup_%X" % call_off, "P11 潜伏长版弹窗静音",
            call_off, old_bytes, _P10_STUB, va=pe.off_to_va(call_off),
            detail="call rel32 -> xor eax,eax + nop×3（5→5 等长；cdecl 且已有 add esp,0x10，"
                   "**禁止补清栈**）"))
        notes.append("  [命中] VA 0x%08X -> 桩（%s）"
                     % (pe.off_to_va(call_off) or 0, "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P12 —— 让 IDM 认为「许可有效」（修「反复弹注册框 / 点取消就退出」）
#
# 根因（实测 + prober 运行期数据）：
#   许可 blob 的键 `Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}`
#   在四个路径下**都不存在** ⇒ `sub_52E2E0` 返回 0 ⇒ `sub_4EC760` 不设
#   `byte_788CF4 = 1` ⇒ IDM 判未注册 ⇒ 弹注册框。
#   且 `dword_788CCC` 运行期 = 1（HKCU/per-user 模式）⇒ `0x4EE81F` 还会**强制清零**。
#   改成 HKLM 模式也不能解决 —— HKLM 下同样的键同样不存在。
#   另：`sub_4EC760` 内**无任何注册表写入 API**（Set/Create/Delete 全 0）
#   ⇒ 它**不能**自己重建该键；靠"重填序列号"重建的可能性很低。
#
# 方案（A+B 必须成对；共 2 站点 / 9 字节）：
#   A  file 0xEDBF7 / VA 0x4EE7F7：`74 1D`(je) -> `90 90`
#      ⇒ 恒走成功分支 ⇒ `byte_788CF4 = 1` 且把（已构造好的）空串存入全局。
#      ⚠️ `var_14` 在 0x4EE7E0 已被 CString ctor 构造 ⇒ 强制走成功分支**不会**读野指针。
#   B  file 0xEDC1F / VA 0x4EE81F：`c6 05 f4 8c 78 00 00`(7B) -> `90`×7
#      ⇒ 不再因 dword_788CCC != 0 强制清零。`mov`/`nop` 均不改 flags ⇒ 语义不变。
#   只打 A ⇒ B 会把标志清回 0；只打 B ⇒ 标志永远设不成 1。故**必须成对**。
#
# ★ 唯一实质风险（**未证实**）：`byte_788CF4 = 1` 后，那 6 个 tripwire 函数
#   （`sub_44CCB0` / `sub_450900` / `sub_466EE0` / `sub_46C7B0` / `sub_46D270` /
#   `sub_486BB0`）各自 4 处读它的**其它分支**是否被触发 —— 未逐一反编译，部署后补核。
# --------------------------------------------------------------------------- #

_P12_CMP_ANCHOR = b"\x83\x3d" + struct.pack("<I", 0x788CCC) + b"\x00"   # cmp dword [0x788CCC],0
_P12_STORE0 = b"\xc6\x05\xf4\x8c\x78\x00\x00"                          # mov byte [0x788CF4],0
_P12_STORE1 = b"\xc6\x05\xf4\x8c\x78\x00\x01"                          # mov byte [0x788CF4],1
_P12_NOP7 = b"\x90" * 7
_P12_NOP2 = b"\x90\x90"
_P12_A_SIG = b"\x83\xc4\x04\x85\xc0"                                   # add esp,4 / test eax,eax
# ⚠️ 签名**不能**包含 `74`：那是 A 自己要改的字节，含进去会导致「打完认不回自己」
#    （实测踩过：PASS2 里 A 的签名消失 ⇒ 站点丢失 ⇒ 幂等假成功）。


def find_license_valid(pe):
    """P12 —— 让许可判定恒为「有效」（A+B 成对施加）。

    内容锚定（不写死任何偏移）：
      1. 锚 = `cmp dword ptr [0x788CCC], 0`（7B，含全局地址 ⇒ 全库唯一）；
      2. 锚后紧跟 `74 xx`(je)，再后 2B 即 B 站点：必须是
         `c6 05 f4 8c 78 00 00`（未补丁）或 `90×7`（已补丁）；
      3. A 站点 = B 之前 ≤0x40 字节内最近的 `add esp,4 / test eax,eax / je` 的 je；
      4. 耦合校验：A 与 B 之间必须存在 `c6 05 f4 8c 78 00 01`（置 1），否则拒绝（保证 A+B 是同一逻辑点）；
      5. **old-bytes 硬断言**：两处字节必须逐字节符合预期，否则拒绝施加。
    """
    import re as _re
    notes, sites = [], []
    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    hits = list(_re.finditer(_re.escape(_P12_CMP_ANCHOR), text))
    notes.append("  cmp[0x788CCC],0 锚命中 %d 处" % len(hits))
    for m in hits:
        cmp_off = tstart + m.start()
        je_off = cmp_off + len(_P12_CMP_ANCHOR)
        if pe.data[je_off] != 0x74:
            notes.append("  [跳过] file 0x%08X：锚后不是 je" % cmp_off)
            continue
        b_off = je_off + 2
        b_cur = bytes(pe.data[b_off:b_off + 7])
        b_applied = b_cur == _P12_NOP7
        if not b_applied and b_cur != _P12_STORE0:
            notes.append("  [❌断言失败] file 0x%08X B 站点 = %s，非 STORE0 亦非 NOP7 —— 拒绝"
                         % (b_off, b_cur.hex(" ")))
            continue
        lo = max(tstart, b_off - 0x40)
        win = bytes(pe.data[lo:b_off])
        idx = win.rfind(_P12_A_SIG)
        if idx < 0:
            notes.append("  [跳过] file 0x%08X：B 之前 0x40 内找不到 A 的签名" % b_off)
            continue
        # A_SIG 是 5 字节（到 `85 c0` 为止），je 的 opcode 紧随其后 ⇒ a_off = idx+5
        a_off = lo + idx + 5
        a_cur = bytes(pe.data[a_off:a_off + 2])
        a_applied = a_cur == _P12_NOP2
        if not a_applied and a_cur[0] != 0x74:
            notes.append("  [❌断言失败] file 0x%08X A 站点 = %s，非 je 亦非 NOP2 —— 拒绝"
                         % (a_off, a_cur.hex(" ")))
            continue
        if _P12_STORE1 not in bytes(pe.data[a_off:b_off]):
            notes.append("  [跳过] file 0x%08X：A→B 之间缺 STORE1，耦合不成立" % a_off)
            continue
        sites.append(Site(
            "license_valid_A_%X" % a_off, "P12 许可判定恒有效 (A 恒走成功分支)",
            a_off, _P12_STORE0[0:0] + b"\x74\x00" if a_applied else a_cur, _P12_NOP2,
            va=pe.off_to_va(a_off),
            detail="je rel8 -> nop nop（无栈/无返回值影响；var_14 已 ctor，不会读野指针）"))
        sites.append(Site(
            "license_valid_B_%X" % b_off, "P12 许可判定恒有效 (B 去掉强制清零)",
            b_off, _P12_STORE0, _P12_NOP7, va=pe.off_to_va(b_off),
            detail="mov byte[0x788CF4],0 -> nop×7（mov/nop 均不改 flags）"))
        notes.append("  [命中] A VA 0x%08X（%s）· B VA 0x%08X（%s）"
                     % (pe.off_to_va(a_off) or 0, "已在位" if a_applied else "本次施加",
                        pe.off_to_va(b_off) or 0, "已在位" if b_applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P13 —— 让 IDM 在「未注册」状态下也**不弹注册框**（修「点取消就退出」）
#
# 实测成功的方案（Lead 已冷启动验证：注册框 0/15 次、IDM 正常启动）：
#   `sub_451E30` 是被 `sub_521C00` 构造的注册对话框，经 `CDialog::DoModal` 以模态弹出：
#       0x4531D0  3b f3                 cmp  esi, ebx          ; ebx = 0
#       0x4531D2  0f 84 23 01 00 00      je   0x4532FB          ; ← ★门控：esi==0 ⇒ 跳过不弹
#       0x4531DF  call 0x521C00                               ; 构造注册框
#       0x453208  call 0x612DBF                               ; CDialog::DoModal
#       0x45320D  mov  [ebp-0x54], eax                        ; 返回值被保存 ⇒ 后面据此决定退出
#   ⇒ 把 `je` 改成**无条件 `jmp`**（同目标）⇒ **根本不构造、不 DoModal** ⇒ 绝不会走「取消→退出」。
#
# 形态：file 0x525D2 / VA 0x4531D2
#   old `0f 84 23 01 00 00` (je 0x4532FB，6B)
#   new `e9 24 01 00 00 90` (jmp 0x4532FB + nop，6→6 等长)
#   rel32 换算：je 的 rel = 0x4532FB-0x4531D8 = 0x123；jmp(5B) 的 rel = 0x4532FB-0x4531D7 = **0x124**。
#   栈：cmp/je/jmp 均无栈影响 ✓  返回值：本条不产生 ✓  分支：恒走 0x4532FB（原本 esi==0 的正常继续路径）✓
#
# ⚠️ 语义边界：
#   · 它让 IDM「未注册也能正常启动」，**不改变** IDM 内部的注册判定
#     （`byte_788CF4` / `esi` 均未动）⇒ 若某功能真需要「已注册」，仍可能受限（**未逐一验证**）。
#   · `esi` 的来源**未追**（那才是「要不要弹框」的真正判决结果）。
#
# ⚠️ 幂等签名纪律（上一轮踩过的坑）：定位签名**只含未被本补丁改动的字节**
#   （`3b f3` 前缀 + 之后的 `53` 尾巴），被改的 6 字节由程序判断两种形态，**不进签名**。
# --------------------------------------------------------------------------- #

_P13_ANCHOR = b"\x3b\xf3"                                # cmp esi, ebx（不会被本补丁改动）
_P13_OLD = b"\x0f\x84\x23\x01\x00\x00"                   # je 0x4532FB
_P13_NEW = b"\xe9\x24\x01\x00\x00\x90"                   # jmp 0x4532FB + nop
_P13_TAIL = b"\x53"                                      # 紧跟的 `push ebx`（额外锚，同样不被改动）


def find_registration_dialog(pe):
    """P13 —— 绕过注册框的创建（恒走「无需弹框」路径）。

    内容锚定（不写死偏移）：`cmp esi,ebx` + 6 字节槽（旧/新两种形态）+ `push ebx` 尾巴。
    **old-bytes 硬断言**：槽内 6 字节必须逐字节 ∈ {je 形态, jmp 形态}，否则拒绝施加。
    幂等：已补丁形态（`e9 24 01 00 00 90`）由同一个锚认回，签名不含被改字节。
    """
    import re as _re
    notes, sites = [], []
    tstart, tend = pe.text_span()
    text = bytes(pe.data[tstart:tend])
    hits = list(_re.finditer(_re.escape(_P13_ANCHOR), text))
    notes.append("  `cmp esi,ebx` 前缀命中 %d 处" % len(hits))
    for m in hits:
        slot = tstart + m.start() + 2
        cur = bytes(pe.data[slot:slot + 6])
        applied = cur == _P13_NEW
        if not applied and cur != _P13_OLD:
            continue                      # 不是这个槽，静默跳过（前缀很常见）
        tail = bytes(pe.data[slot + 6:slot + 7])
        if tail != _P13_TAIL:
            notes.append("  [跳过] file 0x%08X：槽后不是 `push ebx`，锚不成立" % slot)
            continue
        sites.append(Site(
            "registration_dialog_%X" % slot, "P13 注册框不创建",
            slot, _P13_OLD, _P13_NEW, va=pe.off_to_va(slot),
            detail="je -> jmp（同目标；不构造对话框、不 DoModal ⇒ 无「取消→退出」路径）"))
        notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                     % (pe.off_to_va(slot) or 0, _P13_OLD.hex(" "), _P13_NEW.hex(" "),
                        "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P14 —— 按 **uType `0x41030`** 穷尽**全部剩余**显示点（单按钮 = 用户观测到的形态）
#
# 背景：用户真实路径（浏览器点下载）仍弹，说明按「观测路径」逐个补会漏。
# 改为**按实测 uType 穷尽同类**：prober 动态抓到 uType=0x41030 ⇒ 凡该 uType 的调用点全封。
# 全库 `sub_474D20` 调用点 260 处，其中 `0x41030` **6 处**：P10(0x75444)、P11(0x79E49)
# 已封，剩余 4 处由本 finder 覆盖：
#   file 0x74897(VA 0x475497) / 0x75710(0x476310) / 0x7C510(0x47D110) / 0x98C7E(0x49987E)
#
# ★ 形态必须**逐站点判定**（P10 的教训）：`0x75710` 曾被我「call+5 必须是 83 c4 10」
#   的统一前提误拒 —— 它的 `add esp,0x10` 在 call+0x0B（中间隔一条 mov）。
#   实测 4 处**全部**是 cdecl 且调用方**已自带** `add esp,0x10`：
#     0x74897 -> 0x47549C add esp,0x10（紧邻）
#     0x75710 -> 0x47631B add esp,0x10（隔 1 条 mov edx,[0x7893d0]）
#     0x7C510 -> 0x47D11B add esp,0x10（隔 1 条 mov esi,[0x6954a8]）
#     0x98C7E -> 0x499883 add esp,0x10（紧邻）
#   ⇒ **四处统一为纯 5 字节 `31 c0 90 90 90`，一律不补清栈**。
#   返回值：四处 call 之后 eax 均立即被覆盖（mov eax,1 / push… / push 0xfa…）⇒ 不被消费。
#
# ⚠️ 本 finder 会同时匹配到 P10/P11 的那两处 —— 由 `build_all_sites` 的**按偏移去重**
#   收敛（先到先得，P10/P11 在 ALL_FINDERS 中排在前面）⇒ 最终只新增这 4 处。
#   幂等签名只含 `push 0x41030`（不被本补丁改动），**不含被改的 5 字节**。
# --------------------------------------------------------------------------- #

_P14_UTYPE = b"\x68\x30\x10\x04\x00"     # push 0x41030 (MB_TOPMOST|MB_SYSTEMMODAL|MB_ICONWARNING)
_P14_STUB = b"\x31\xc0\x90\x90\x90"      # xor eax,eax ; nop×3
_P14_CLEAN = b"\x83\xc4\x10"             # add esp,0x10

# ★ 逐站点**唯一前缀锚**（每个锚在全库唯一，实测 uniq=1）。
#   为什么不用「push 0x41030 + 窗口内找 e8」这种启发式：实测两种极端都会错 ——
#     · 窗口内搜任意 e8 ⇒ 多匹配 3 处间接调用站点（0x7D58B/0x8401B/0x84306，实为 `call esi`）；
#     · 只认「锚后第一个 call」⇒ 真实站点在参数里夹了 `ff 15` 间接调用（如 push offset 字符串、
#       GetActiveWindow），于是把 4 个真站点全部漏掉。
#   锚**不含被补丁改动的 5 字节**，所以幂等天然成立。
_P14_SITES = (
    # VA 0x49987E —— ★ prober 在用户活进程上实测到的**浏览器下载路径**落点（必须最优先保证）
    (b"\x51\x8b\x0d\xd0\x93\x78\x00\x51", "0x49987E browser/download path"),
    # VA 0x475497
    (b"\x04\x00\x68\xe8\x6d\x69\x00\x50\xff\x15\xfc\x57\x69\x00\x50", "0x475497"),
    # VA 0x476310 —— P10 曾因「call+5 必须 83 c4 10」误拒的那处（其清栈在 call+0x0B）
    (b"\x1d\x41\x3b\xc8\x7c\xf6\x8b\x44\x24\x0c\x8b\x0d\xd0\x93\x78\x00"
     b"\x68\x30\x10\x04\x00\x8d\x54\x24\x14\x52\x50\x51", "0x476310"),
    # VA 0x47D110
    (b"\x00\x8d\x54\x24\x18\x52\x50\x51", "0x47D110"),
)


def _retired_icontype_popups(pe):
    """【RETIRED —— 逐点封方案，已被 wrapper 级短路取代，不进 ALL_FINDERS】

    保留原因：记录「两种启发式都会错」的实测结论（见上方注释）。
    """
    notes, sites = [], []
    d = bytes(pe.data)
    mb_iat = [v for v in (_import_iat_va(pe, "MessageBoxA"),
                          _import_iat_va(pe, "MessageBoxW")) if v]
    for anchor, tag in _P14_SITES:
        idx = d.find(anchor)
        if idx < 0 or d.find(anchor, idx + 1) >= 0:
            notes.append("  [跳过] 锚 %s 未命中或不唯一" % tag)
            continue
        p = idx + len(anchor)
        cur = bytes(d[p:p + 5])
        applied = cur == _P14_STUB
        if not applied:
            if cur[:1] != b"\xe8":
                notes.append("  [❌断言失败] %s file 0x%08X 落点 = %s（非 E8 且非桩）—— 拒绝"
                             % (tag, p, cur.hex(" ")))
                continue
            rel = struct.unpack("<i", cur[1:5])[0]
            tgt = (pe.off_to_va(p) + 5 + rel) & 0xFFFFFFFF
            to = pe.va_to_off(tgt)
            if to is None:
                notes.append("  [❌断言失败] %s 目标 0x%X 无法映射 —— 拒绝" % (tag, tgt))
                continue
            fs_, fe_ = _func_bounds(pe, to)
            body = bytes(d[fs_:fe_])
            if not any((b"\xff\x15" + struct.pack("<I", i)) in body for i in mb_iat):
                notes.append("  [❌断言失败] %s 目标 0x%X 函数体内无 MessageBox —— 拒绝"
                             % (tag, tgt))
                continue
            if _P14_CLEAN not in bytes(d[p + 5:p + 5 + 0x10]):
                notes.append("  [❌断言失败] %s call 后 0x10 内无 add esp,0x10 —— 拒绝" % tag)
                continue
        old_bytes = b"\xe8\x00\x00\x00\x00" if applied else cur
        sites.append(Site(
            "icontype_popup_%X" % p, "P14 uType=0x41030 显示点静音",
            p, old_bytes, _P14_STUB, va=pe.off_to_va(p),
            detail="%s：call -> xor eax,eax + nop×3（5→5；cdecl 且调用方已自带 add esp,0x10，"
                   "**不补清栈**）" % tag))
        notes.append("  [命中] %s VA 0x%08X -> 桩（%s）"
                     % (tag, pe.off_to_va(p) or 0, "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P14 —— **wrapper 级**短路：`sub_474D20` 中 `uType == 0x41030` 的调用一律直接返回 0
#
# 为什么改成 wrapper 级（架构正解）：
#   prober 实测全程序 **253** 处 `call 0x474D20`、其中 `push 0x41030` **9** 处；
#   用户真实路径（浏览器点下载）落在 file `0x98C7E`，与命令行路径（P10 的 `0x75444`）不同
#   ⇒ 逐点封永远追不上下游新路径。改为在 wrapper 入口按 uType 短路 ⇒ 一次覆盖全部 9 处 + 未来路径。
#
# 入口与约定（实测）：
#   VA 0x474D20 / file 0x74120
#     6a ff                 push -1
#     68 78 87 66 00        push 0x668778        ; SEH 序言，共 7 字节
#     64 a1 00 00 00 00     mov eax, fs:[0]      ; ← 恢复执行点 0x474D27
#   入参： [esp+4]=hwnd · [esp+8]=text · [esp+0xC]=caption · **[esp+0x10]=uType**
#   约定： **cdecl**（P10/P11 及本轮 4 个候选点，call 之后均有 `add esp,0x10`）
#         ⇒ 短路必须用**裸 `ret`**；写 `ret 0x10` 会与调用方的 add esp 叠加 ⇒ 多弹 16B、栈崩。
#
# 形态：
#   站点 A（跳板）file 0x74120 7→7：`6a ff 68 78 87 66 00` -> `e9 <cave-(v+5)> 90 90`
#   站点 B（cave）file 0xEF2E4（`sub_4EC760` 尾部的 CC 填充，最长 0x2C=44B，唯一）：
#     8b 44 24 10      mov  eax,[esp+0x10]
#     3d 30 10 04 00   cmp  eax,0x41030
#     75 03            jne  .orig
#     31 c0            xor  eax,eax
#     c3               ret                    ; ★ 裸 ret（cdecl）
#     .orig:           (偏移 14)
#     6a ff            push -1               ; 原序言 7 字节原样重放
#     68 78 87 66 00   push 0x668778
#     e9 <0x474D27-(cave+26)>              ; 回到原序言之后
#   共 26 字节。
#
# ★ 副作用（未证实）：这 9 处里若有**非 counterfeit 的合法警告**（恰好同为 0x41030 =
#   置顶+系统模态+警告图标+单按钮），也会被静音 —— 未逐一验证。其余 244 处调用完全不受影响。
# --------------------------------------------------------------------------- #

_P14_PROLOGUE_UNUSED = (b"\x6a\xff\x68\x78\x87\x66\x00"   # ⚠️ 含被改字节，**不可作定位锚**
                        b"\x64\xa1\x00\x00\x00\x00"
                        b"\x50\x83\xec\x20")
# ★ 定位锚只能用**不被本补丁改动的**序言尾部（偏移 7..16）：
#   若用完整序言，打完补丁入口变成 `e9 …` ⇒ 锚消失 ⇒ 二次扫描认不回自己
#   ⇒ `apply#2` 假报 clean（本项目已因此踩过一次，见 P12 的教训）。
_P14_ANCHOR = (b"\x64\xa1\x00\x00\x00\x00"      # mov eax, fs:[0]
               b"\x50"                            # push eax
               b"\x83\xec\x20"                    # sub esp, 0x20
               b"\xa1\xc0\x39\x78\x00"            # mov eax, [0x7839C0]   ← cookie 全局，保证唯一
               b"\x33\xc4")                       # xor eax, esp
_P14_PROLOGUE_LEN = 7
_P14_ORIG7 = b"\x6a\xff\x68\x78\x87\x66\x00"
_P14_RESTORE = 0x474D27                                # 原序言之后的恢复点
_P14_UTYPE_VAL = 0x41030
_P14_CAVE_LEN = 26


def _p14_tramp(entry_va, cave_va):
    return b"\xe9" + struct.pack("<I", (cave_va - (entry_va + 5)) & 0xFFFFFFFF) + b"\x90\x90"


def _p14_stub(entry_va, cave_va):
    back = (_P14_RESTORE - (cave_va + _P14_CAVE_LEN)) & 0xFFFFFFFF
    parts = [
        b"\x8b\x44\x24\x10",                          # mov eax,[esp+0x10]
        b"\x3d" + struct.pack("<I", _P14_UTYPE_VAL),  # cmp eax,0x41030
        b"\x75\x03",                                  # jne .orig  (rel=3 -> offset 14)
        b"\x31\xc0\xc3",                              # xor eax,eax ; ret  (cdecl!)
        _P14_ORIG7,                                   # push -1 ; push 0x668778 (原序言重放)
        b"\xe9" + struct.pack("<I", back),            # jmp 0x474D27
    ]
    return b"".join(parts)


def _p14_find_cave(d, t0, t1):
    """在 .text 内找最长的连续 CC 块（需 >= 26 字节），返回文件偏移。"""
    best, best_len = None, 0
    start, run = None, 0
    for i in range(t0, t1):
        if d[i] == 0xCC:
            if start is None:
                start, run = i, 0
            run += 1
        else:
            if start is not None and run > best_len:
                best, best_len = start, run
            start, run = None, 0
    if start is not None and run > best_len:
        best, best_len = start, run
    return (best, best_len) if best is not None and best_len >= _P14_CAVE_LEN else (None, 0)


def find_wrapper_utype_shortcut(pe):
    """P14 —— 在弹窗包装 `sub_474D20` 入口按 uType 短路（覆盖全部 0x41030 显示点）。

    定位（内容锚定，不写死偏移）：
      1. 包装入口 = 唯一出现 17 字节 SEH 序言 `6a ff 68 78 87 66 00 64 a1 … 83 ec 20` 处；
         并校验该函数体内含 `MessageBoxA/W` 调用（防锚串味）。
      2. cave = `.text` 内最长的连续 `CC` 块（需 ≥26B）。
    幂等：入口若已是 `E9` ⇒ 由 rel32 **反推 cave 地址**，再比对 cave 内 26 字节是否等于桩；
          两处都对 ⇒ already。签名不含任何被改字节。
    """
    notes, sites = [], []
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    mb_iat = [v for v in (_import_iat_va(pe, "MessageBoxA"),
                          _import_iat_va(pe, "MessageBoxW")) if v]
    import re as _re
    ap_hits = [m.start() for m in _re.finditer(_re.escape(_P14_ANCHOR), d)]
    notes.append("  序言尾部锚命中 %d 处（MFC 通用序言，需消歧）" % len(ap_hits))
    pos = None
    for ap in ap_hits:
        cand = ap - _P14_PROLOGUE_LEN
        if cand < t0:
            continue
        pre = bytes(d[cand:cand + 7])
        is_orig = pre == _P14_ORIG7
        is_tramp = (pre[:1] == b"\xe9" and pre[5:7] == b"\x90\x90")
        if not (is_orig or is_tramp):
            continue
        if is_orig:
            fs_, fe_ = _func_bounds(pe, cand)
            if not any((b"\xff\x15" + struct.pack("<I", i)) in bytes(d[fs_:fe_]) for i in mb_iat):
                continue
        # is_tramp 时**不再**做 MessageBox 校验：入口已被 `e9` 覆盖，_func_bounds 反推
        # 的函数体不再包含 MessageBox 调用 ⇒ 校验必然失败 ⇒ 已补丁态认不回自己
        # （这正是「定位/校验不得依赖被补丁改动的字节」的同一类坑）。
        pos = cand
        notes.append("  选定入口 file 0x%06X（前 7 字节 = %s）"
                     % (cand, "原序言" if is_orig else "跳板"))
        break
    if pos is None:
        notes.append("  [❌] 找不到「前 7 字节为原序言/跳板 且 函数体含 MessageBox」的入口 —— 拒绝")
        return sites, notes
    entry_va = pe.off_to_va(pos)
    fs_, fe_ = _func_bounds(pe, pos)
    body = bytes(d[fs_:fe_])
    if not any((b"\xff\x15" + struct.pack("<I", i)) in body for i in mb_iat):
        notes.append("  [❌] 序言所在函数体内无 MessageBox —— 锚串味，拒绝")
        return sites, notes
    notes.append("  包装入口 VA 0x%08X / file 0x%06X（函数体含 MessageBox ✓）" % (entry_va, pos))

    cur = bytes(d[pos:pos + 7])
    if cur[:1] == b"\xe9":                               # 已补丁：反推 cave
        rel = struct.unpack("<I", cur[1:5])[0]
        cave_va = (entry_va + 5 + rel) & 0xFFFFFFFF
        cave_off = pe.va_to_off(cave_va)
        if cave_off is None:
            notes.append("  [❌] 已补丁但 cave VA 0x%X 不可映射 —— 拒绝" % cave_va)
            return sites, notes
        applied = bytes(d[cave_off:cave_off + _P14_CAVE_LEN]) == _p14_stub(entry_va, cave_va)
        notes.append("  已检测到跳板，cave = VA 0x%08X / file 0x%06X（桩%s）"
                     % (cave_va, cave_off, "匹配" if applied else "**不匹配**"))
        if not applied:
            notes.append("  [❌] cave 内容与预期桩不符 —— 拒绝（避免覆盖不明数据）")
            return sites, notes
    else:
        if cur != _P14_ORIG7:
            notes.append("  [❌断言失败] 入口 7 字节 = %s，既非原序言亦非跳板 —— 拒绝"
                         % cur.hex(" "))
            return sites, notes
        cave_off, cave_len = _p14_find_cave(d, t0, t1)
        if cave_off is None:
            notes.append("  [❌] .text 内找不到 ≥%dB 的 CC 空洞 —— wrapper 级方案不可行" % _P14_CAVE_LEN)
            return sites, notes
        cave_va = pe.off_to_va(cave_off)
        applied = False
        notes.append("  cave = VA 0x%08X / file 0x%06X（连续 CC %dB，需 %dB ✓）"
                     % (cave_va, cave_off, cave_len, _P14_CAVE_LEN))

    tramp = _p14_tramp(entry_va, cave_va)
    stub = _p14_stub(entry_va, cave_va)
    sites.append(Site("wrapper_shortcut_A_%X" % pos, "P14 弹窗包装入口跳板",
                      pos, _P14_ORIG7, tramp, va=entry_va,
                      detail="push -1/push 0x668778 -> jmp cave + nop×2（7→7；序言搬到 cave 重放）"))
    sites.append(Site("wrapper_shortcut_B_%X" % cave_off, "P14 cave: uType==0x41030 短路",
                      cave_off, b"\xcc" * _P14_CAVE_LEN, stub, va=cave_va,
                      detail="cmp [esp+0x10],0x41030 -> 相等则 eax=0 并**裸 ret**（cdecl，调用方清 16B）"))
    notes.append("  跳板 = %s" % tramp.hex(" "))
    notes.append("  桩(%dB) = %s" % (len(stub), stub.hex(" ")))
    return sites, notes


# --------------------------------------------------------------------------- #
# P15 —— 下载路径的**注册框** case 体置空（补 P13 未覆盖的那条路径）
#
# prober 实测两条路径**共用同一创建点**但调用者不同：
#   启动路径 bt: … | 0x5320d | …                ⇒ P13 封的是这条（`0x4531D2`）
#   下载路径 bt: … | 0x94f95 | 0x26a704 ×3 | …  ⇒ 落在 `sub_48F7D0` 的一个 **case 体**
#
# 该 case 体（实测，同步解码）：
#   VA 0x494F64  6a 00 / 8d 8d 1c f9 ff ff   push 0 ; lea ecx,[ebp-0x6e4]
#   VA 0x494F6C  call 0x521C00               ★ 注册框构造函数（与 P13 同一个 ctor）
#   VA 0x494F90  call 0x612DBF               CDialog::DoModal（prober ret 0x494F95 ✓）
#   VA 0x494FCE  jmp  0x49A515               ★ 本 case 的统一出口（兄弟 case 同款）
#   VA 0x494F59  mov eax,1 ; wait ; jmp 0x49A515   ← 上一个 case 的尾部（可安全跳入）
#   ⇒ **没有独立 cmp/test 门控**：门控就是「跳转表选了哪个 case」⇒ 封法 = **让该 case 变空操作**。
#
# 形态：file 0x94364 / VA 0x494F64，5→5
#   old `6a 00 8d 8d 1c`  ->  new **`e9 f0 ff ff ff`**（jmp 0x494F59）
#   rel32 = 0x494F59 − 0x494F69 = **−0x10** ⇒ f0 ff ff ff
#   ⇒ 跳到兄弟 case 尾部 ⇒ `eax=1`（与兄弟一致）、**栈中性**、**DoModal 根本不执行**
#     ⇒ 绝无「取消→退出」；被覆盖的 `lea` 残余字节永不可达。
#
# ★ 为什么不能封「共同门控」（与 P14 的关键区别，务必记住）：
#   「能否一处封全」取决于**该点是否为唯一出口**。
#     · wrapper `sub_474D20` 是**唯一出口**（253 处调用都经它）⇒ 可一处封全（P14）。
#     · 注册框 ctor `0x521C00` **不是**（DoModal 由两条路径各自调用）⇒ 封 ctor 会让
#       DoModal 展示一个**未构造的对象** ⇒ 必崩 ⇒ **只能逐路径封**。
#
# ✋ 不要碰：`0x122A98` / `0x122C77`（注册框内的「序列号错误 / 请填名称邮箱」校验提示）——
#   用户需要看到自己填错了什么。
# --------------------------------------------------------------------------- #

_P15_ANCHOR = b"\xb8\x01\x00\x00\x00\x9b\xe9"   # mov eax,1 ; wait ; jmp rel32（兄弟 case 尾部）
_P15_OLD = b"\x6a\x00\x8d\x8d\x1c"
_P15_NEW = b"\xe9\xf0\xff\xff\xff"


def find_download_registration_dialog(pe):
    """P15 —— 置空「下载路径」的注册框 case 体。

    定位（内容锚定 + 结构校验，不写死偏移）：
      1. 锚 = `mov eax,1 ; wait ; jmp rel32`（8B，兄弟 case 尾部通用形态，**会被本补丁改动吗？不会**）；
      2. 锚后跳过 jmp 的 rel32（4B）⇒ 落在下一个 case 体的头 5 字节（slot）；
      3. slot 必须是 `6a 00 8d 8d 1c`（未补丁）或 `e9 f0 ff ff ff`（已补丁）；
      4. 结构校验：slot+8 处必须是 `e8`（即 case 体内的 ctor 调用位置没变）—— 该字节不被本补丁改动；
      5. 命中不唯一则拒绝（不做猜测）。
    """
    notes, sites = [], []
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    hits = []
    p = d.find(_P15_ANCHOR)
    while p >= 0:
        if t0 <= p < t1:
            hits.append(p)
        p = d.find(_P15_ANCHOR, p + 1)
    notes.append("  `mov eax,1;wait;jmp` 锚命中 %d 处（兄弟 case 共用，需消歧）" % len(hits))
    found = []
    for hp in hits:
        slot = hp + len(_P15_ANCHOR) + 4          # 跳过 jmp 的 rel32
        cur = bytes(d[slot:slot + 5])
        applied = cur == _P15_NEW
        if not applied and cur != _P15_OLD:
            continue
        if bytes(d[slot + 8:slot + 9]) != b"\xe8":   # case 体内的 ctor 调用必须还在原位
            continue
        found.append((slot, applied))
    if len(found) != 1:
        notes.append("  [❌] 候选 %d 个（期望恰好 1）—— 拒绝，不做猜测" % len(found))
        return sites, notes
    slot, applied = found[0]
    sites.append(Site(
        "download_reg_dialog_%X" % slot, "P15 下载路径注册框不创建",
        slot, _P15_OLD, _P15_NEW, va=pe.off_to_va(slot),
        detail="case 体头 -> jmp 兄弟 case 尾部（eax=1、栈中性、DoModal 不执行；无「取消→退出」）"))
    notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                 % (pe.off_to_va(slot) or 0, _P15_OLD.hex(" "), _P15_NEW.hex(" "),
                    "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P16 / P17 —— 「IDM is corrupt」告警**根治**（静态链路已闭合，全库唯一性逐环验证）
#
# 完整调用链（Lead 全 `.text` 线性扫描 882,311 条指令得出）：
#
#   WM_COMMAND id 0x151B                    ← 「宣告主程序损坏」命令（跳表 idx 106）
#     └─ 0x49A440  b8 01 00 00 00    mov eax,1
#        0x49A445  a3 a0 93 78 00    mov dword ptr [0x7893A0], eax   ★唯一写者
#        0x49A44A  9b                wait
#        0x49A44B  e9 c5 00 00 00    jmp 0x49A515                    （return 1）
#
#   0x49B9C8  83 3d a0 93 78 00 00   cmp dword ptr [0x7893A0], 0      ★唯一读者
#   0x49B9CF  74 0d                  je  0x49B9DE   ; 标志=0 ⇒ 正常路径，永不弹
#   0x49B9D1  e8 ca d2 00 00         call 0x4A8CA0  ★唯一显示出口
#   0x49B9D6  85 c0 / 0f 84 ...      test eax,eax / je ...（是否点了「继续下载」）
#
#   sub_4A8CA0 = 告警对话框：0x4A8D03 `call 0x4A8960`（取 6 段文案）→ GlobalAlloc/
#   GlobalLock 建 DLGTEMPLATE → 0x4A8F26 `DialogBoxIndirectParamW`（全库唯一调用点）。
#
# ★ 为什么弹出来的一定是 corrupt 文案：`sub_4A8960` 读 `word [0x788E54]`，该处
#   `.data` 初值 = 0 ⇒ `movzx eax,[..]` = 0 ⇒ `dec eax` = 0xFFFFFFFF ⇒
#   `cmp eax,0x29 / ja 0x4A8BE0` 成立 ⇒ **永远落到默认（corrupt）分支**。
#   即这条告警**从来没设置过消息 ID**，所以每次都显示「主程序文件已损坏」。
#
# ★ 两个补丁**互相独立、各自扫锚点**（铁律⑪：绝不依赖另一个 finder 施加后的状态）：
#   只共用「gate 锚点」这一串**不被任何补丁改动的字节**；P16 不看 P17 的字节，
#   P17 也不看 P16 的字节。因此施加顺序、重复施加、只施加其一都成立。
# --------------------------------------------------------------------------- #

# 「损坏标志 gate」——P16/P17 共用的唯一锚点。
# 全库 uniq=1；★ **不包含任何被两个补丁改动的字节**（P16 改 0x49A445、
# P17 改 0x49B9D1，两者都不在这 9 字节内），因此施加前后都能定位。
_CORRUPT_GATE_ANCHOR = b"\x83\x3d\xa0\x93\x78\x00\x00\x74\x0d"
# P17 本版原始字节（`call 0x4A8CA0`）；仅用于 describe()/回滚说明，
# 结构校验走「目标是否落在 .text 内」，避免锚点过严造成假阴性（铁律⑧）。
_P17_CALL_OLD = b"\xe8\xca\xd2\x00\x00"


def _find_corrupt_gate(pe, notes):
    """定位「损坏标志 gate」：`cmp dword ptr [flag],0 ; je <正常路径>`。

    返回 `(gate_file_off, flag_va)`；缺失/不唯一 ⇒ `(None, None)` 并写入 note。
    这是 P16/P17 的**共同前提**：它给出标志 VA（P16 要靠它拼出写者形态），
    且其自身字节不被两个补丁改动，故可同时作为「未施加 / 已施加」两态的锚。
    """
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    hits = []
    p = d.find(_CORRUPT_GATE_ANCHOR, t0)
    while 0 <= p < t1:
        hits.append(p)
        p = d.find(_CORRUPT_GATE_ANCHOR, p + 1)
    if len(hits) != 1:
        notes.append("[❌] mismatch：损坏标志 gate 锚点命中 %d 处（期望恰好 1）—— "
                     "锚点未命中，拒绝施加（铁律⑫：不静默跳过）" % len(hits))
        return None, None
    gate = hits[0]
    flag_va = struct.unpack_from("<I", d, gate + 2)[0]
    notes.append("gate 锚点命中 1 处：VA 0x%08X，损坏标志 VA 0x%08X"
                 % (pe.off_to_va(gate) or 0, flag_va))
    return gate, flag_va


def find_corrupt_flag_gate(pe):
    """P16 —— 「损坏」判定标志**永不置位**（根治：IDM 根本不认为自身 exe 损坏）。

    定位（内容锚定 + 结构校验，**不写死偏移**）：
      1. 共用锚 = `83 3d a0 93 78 00 00 74 0d`（gate，全库 uniq=1）⇒ 读出标志 VA；
      2. 写者形态 = `a3 <标志VA32>`（`mov dword ptr [flag], eax`），全库 uniq=1；
      3. 结构校验（三条都必须成立，且**都不被本补丁改动**）：
           写者前 5B == `b8 01 00 00 00`（`mov eax,1` —— 保留 ⇒ 该 case 仍返回 1）
           写者后 1B == `9b`（`wait`）
           写者后 2B == `e9`（`jmp rel32` —— 跳到 return 1 的收尾段）
         比「直接搜 `a3 a0 93 78 00`」更稳：换版本后即使标志地址变了也能重定位。
      4. **已施加形态** = 写者处 5×NOP，用**同一条结构链**认回（不需要写死偏移，
         也不会因为「原始字节已消失」而误报锚点缺失）。
      5. 候选不唯一 ⇒ 拒绝（不做猜测）。

    清栈（铁律⑯）：`mov [mem],reg` 无 call、无栈操作 ⇒ 换 5×NOP 后栈完全不变；
    前面的 `mov eax,1` 保留 ⇒ 该 case 仍返回「已处理」，调用方行为不变。
    副作用：`[0x7893A0]` 全库唯一读者就是那道 gate ⇒ 置不置位**只影响弹不弹**。
    """
    notes, sites = [], []
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    gate, flag_va = _find_corrupt_gate(pe, notes)
    if gate is None:
        return None, notes
    writer = b"\xa3" + struct.pack("<I", flag_va)
    nop5 = b"\x90" * 5
    cands = []
    p = d.find(b"\xb8\x01\x00\x00\x00", t0)
    while 0 <= p < t1 - 12:
        if d[p + 5:p + 10] in (writer, nop5) and d[p + 10] == 0x9B and d[p + 11] == 0xE9:
            cands.append(p + 5)
        p = d.find(b"\xb8\x01\x00\x00\x00", p + 1)
    if len(cands) != 1:
        notes.append("[❌] mismatch：`mov eax,1`+写者/NOP+`wait`+`jmp` 结构命中 %d 处"
                     "（期望恰好 1）—— 锚点未命中，拒绝施加" % len(cands))
        return None, notes
    off = cands[0]
    cur = bytes(d[off:off + 5])
    applied = cur == nop5
    if not applied and cur != writer:
        notes.append("[❌] mismatch：写者位置字节不符（%s）—— 拒绝施加" % cur.hex(" "))
        return None, notes
    sites.append(Site(
        "corrupt_flag_gate_%X" % off, "P16 corrupt 判定标志不置位（根治）",
        off, writer, nop5, va=pe.off_to_va(off),
        detail="写者 -> 5×NOP（`mov eax,1` 保留 ⇒ 该 case 仍返回「已处理」；"
               "无栈操作、无需清栈；标志唯一读者是 gate ⇒ 只影响弹不弹）"))
    notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                 % (pe.off_to_va(off) or 0, writer.hex(" "), nop5.hex(" "),
                    "已在位" if applied else "本次施加"))
    return sites, notes


def find_corrupt_alert_exit(pe):
    """P17 —— corrupt 告警**唯一显示出口**短路（兜底）。

    定位（锚点相对 + 结构校验）：
      1. 共用锚 = gate（全库 uniq=1）；锚尾（gate+9）**紧邻**就是显示出口的 call
         —— 这不是写死的偏移，而是 `cmp … / je …` 之后必然紧跟被 gate 保护的分支体；
      2. 出口必须是 `e8 <rel32>`，且 rel32 目标落在 `.text` 内（本版 = 0x4A8CA0，
         即 `DialogBoxIndirectParamW` 唯一调用点所在的告警对话框函数）；
      3. 紧随其后必须是 `85 c0`（`test eax,eax`）+ `0f 84`（`je rel32`）——
         这两条说明返回值 = 「是否点了 Continue downloading」，且**不被本补丁改动**；
      4. **已施加形态** = `b8 01 00 00 00`（`mov eax,1`，与 call 等长 5 字节）。

    清栈（铁律⑯）：★ **禁止补清栈**。原 call 的目标 `sub_4A8CA0` 内部
    `add esp,0x3c; ret` **自平栈**（调用方其后没有 `add esp`）；整条 call 被等长
    `mov eax,1` 替换后**没有任何 push** ⇒ 不存在栈残留 ⇒ 若再补 `add esp` 反而
    会**破坏调用方栈**（P10 同款结论）。
    语义：等价于「用户点了 Continue downloading」⇒ `test eax,eax` 非零 ⇒
    走 0x49B9DE 正常路径。价值：即使将来出现第二条写者，弹窗仍然不显示。
    """
    notes, sites = [], []
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    gate, _flag_va = _find_corrupt_gate(pe, notes)
    if gate is None:
        return None, notes
    off = gate + len(_CORRUPT_GATE_ANCHOR)      # 锚尾 = 显示出口 call（紧跟 je 之后）
    cur = bytes(d[off:off + 5])
    new = b"\xb8\x01\x00\x00\x00"
    applied = cur == new
    if applied:
        old = _P17_CALL_OLD
    else:
        if cur[0:1] != b"\xe8":
            notes.append("[❌] mismatch：gate 锚尾不是 `call rel32`（实际 %s）—— 拒绝施加"
                         % cur.hex(" "))
            return None, notes
        rel = struct.unpack_from("<i", d, off + 1)[0]
        tgt_va = (pe.off_to_va(off) or 0) + 5 + rel
        tgt_off = pe.va_to_off(tgt_va)
        if tgt_off is None or not (t0 <= tgt_off < t1):
            notes.append("[❌] mismatch：call 目标 0x%08X 不在 .text 内 —— 拒绝施加" % tgt_va)
            return None, notes
        notes.append("显示出口 call 目标 VA 0x%08X（告警对话框，DialogBoxIndirectParamW 唯一调用点）"
                     % tgt_va)
        if cur != _P17_CALL_OLD:
            notes.append("  （call rel32 与本版记录不同：%s vs %s，按结构校验继续）"
                         % (cur.hex(" "), _P17_CALL_OLD.hex(" ")))
        old = cur
    if bytes(d[off + 5:off + 7]) != b"\x85\xc0" or bytes(d[off + 7:off + 9]) != b"\x0f\x84":
        notes.append("[❌] mismatch：出口之后不是 `test eax,eax; je rel32`（实际 %s）—— 拒绝施加"
                     % d[off + 5:off + 11].hex(" "))
        return None, notes
    sites.append(Site(
        "corrupt_alert_exit_%X" % off, "P17 corrupt 告警显示出口短路（兜底）",
        off, old, new, va=pe.off_to_va(off),
        detail="call 对话框 -> mov eax,1（等价「点了继续下载」⇒ 走正常路径；"
               "call 已整条替换、无 push ⇒ 禁止补清栈）"))
    notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                 % (pe.off_to_va(off) or 0, old.hex(" "), new.hex(" "),
                    "已在位" if applied else "本次施加"))
    return sites, notes


# --------------------------------------------------------------------------- #
# P18 / P19 —— 「IDM is corrupt」**定时 nag 路由改道**（1 字节数据补丁）
#
# 完整链路（证据卡 `.scratch\fuckidm\rootfix2\ROOTFIX-474.md`，逐环唯一性验证）：
#
#   OnTimer(nIDEvent) 分派器  0x486BEB
#     00486BEB  mov  eax,[ebp+0x6C]            ; nIDEvent
#     00486BEE  dec  eax                        ; eax = nIDEvent-1
#     00486BEF  cmp  eax,0x6E                   ; 仅 1..0x6F
#     00486BF2  ja   0x4882A9                   ; 越界 ⇒ 默认无动作出口（早退尾声）
#     00486BF8  movzx eax, byte [eax+0x488374]  ; ★ 字节索引表
#     00486BFF  jmp  dword [eax*4+0x4882D0]     ; ★ 处理器跳表
#        ├─ nIDEvent=0x31 ⇒ 表[0x30]=0x25(37) ⇒ jt[37]=0x487697
#        │     0x487697 KillTimer(0x31) → PostMessageA(hwnd,0x111,0x1517,0) ★全库唯一
#        │       ⇒ case 0x1517 ⇒ 0x4962EF ⇒ _beginthreadex(0x484DB0)
#        │       ⇒ 解码 3 块 .data blob ⇒ GetDesktopWindow ⇒ MessageBoxW  ★真弹窗
#        │       ⇒ SetTimer(id=0x31, 0x36EE80=1h) ⇒ 每小时复发
#        └─ nIDEvent=0x26 ⇒ 表[0x25]=0x1B(27) ⇒ jt[27]=0x487602
#              0x487602 KillTimer(0x26) → PostMessageA(hwnd,0x111,0x14BF,0) ★全库唯一
#                ⇒ case 0x14BF ⇒ 0x49623D ⇒ 线程 0x47D520（平行变体，**同一文案**）
#
# ★ 补丁 = 把字节表里「该 nag」那一格改成 0x28(40)，而 jt[40] 正好是分派器
#   自带 `ja 0x4882A9` 的越界默认出口 ⇒ 语义等价于「这个 timer id 没有处理器」。
#   静态自检（2026-10-18 实测）：0x4882A9 = 标准 SEH 尾声 + `__security_check_cookie`
#   + `ret 4`；其前一字节是 `c3`（无 fallthrough），全库唯一指向它的跳转就是那条 `ja`
#   ⇒ 它是**专为「本 timer id 无处理器」准备的早退尾声**，不是会做别事的分支。
# ★ 纯数据字节：无 call、无栈操作 ⇒ 铁律⑯ 无需任何清栈处理。
# ★ 两个 finder 各自独立扫锚点（铁律⑪），不依赖 P16/P17 的施加状态。
# ★ 必须 P18+P19 同时施加：两个变体**不共用点火点**，各弹各的。
# --------------------------------------------------------------------------- #

# OnTimer 分派器：`movzx eax, byte [eax+表基址32] ; jmp dword [eax*4+跳表基址32]`
_ONTIMER_DISPATCHER = bytes.fromhex("0FB68074834800FF2485D0824800")
# 两个 nag 变体的处理器块头（各含 `push imm8` 的 timer id；全库 uniq=1）
_ONTIMER_HANDLER_31 = bytes.fromhex("6A318B462050FF158C576900")
_ONTIMER_HANDLER_26 = bytes.fromhex("6A268B462050FF158C576900")
# 改道目标：跳表里「越界默认出口」的下标（=40）。**不写死 VA**，由分派器自己的
# `ja rel32` 目标与该下标的跳表项比对得出，见 `_find_ontimer_dispatcher()`。
_ONTIMER_DEFAULT_INDEX = 0x28


def _find_ontimer_dispatcher(pe, notes):
    """定位 OnTimer 分派器，返回 `(disp_file_off, table_va, jt_va, default_va)`。

    形状：`0f b6 80 <表基址32> ff 24 85 <跳表基址32>`（`movzx` + `jmp [eax*4+jt]`）。

    自校验（三关，任一不过就拒绝施加）：
      1. 锚点全库 uniq 必须 = 1；
      2. 表基址 / 跳表基址必须都能映射回映像内；
      3. 紧邻锚点**之前**必须有一条 `0f 87 rel32`（`ja`，越界出口），且其目标
         **必须等于** `jt[0x28]` —— 这样「改道目标」是**数据推导**出来的，
         不是我们写死的魔法 VA；同时 `(表基址−跳表基址)/4` 必须 = 0x29（41 项）。
    """
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    hits = []
    p = d.find(_ONTIMER_DISPATCHER, t0)
    while 0 <= p < t1:
        hits.append(p)
        p = d.find(_ONTIMER_DISPATCHER, p + 1)
    if len(hits) != 1:
        notes.append("[❌] mismatch：OnTimer 分派器锚点命中 %d 处（期望恰好 1）—— "
                     "锚点未命中，拒绝施加（铁律⑫：不静默跳过）" % len(hits))
        return None, None, None, None
    disp = hits[0]
    table_va = struct.unpack_from("<I", d, disp + 3)[0]
    jt_va = struct.unpack_from("<I", d, disp + 10)[0]
    table_off = pe.va_to_off(table_va)
    jt_off = pe.va_to_off(jt_va)
    if table_off is None or jt_off is None:
        notes.append("[❌] mismatch：分派器里的表基址/跳表基址不在映像内 —— 拒绝施加")
        return None, None, None, None
    n_entries = (table_va - jt_va) // 4
    if n_entries != _ONTIMER_DEFAULT_INDEX + 1:
        notes.append("[❌] mismatch：跳表项数 %d ≠ %d（表/跳表基址几何变了）—— 拒绝施加"
                     % (n_entries, _ONTIMER_DEFAULT_INDEX + 1))
        return None, None, None, None
    default_va = struct.unpack_from("<I", d, jt_off + _ONTIMER_DEFAULT_INDEX * 4)[0]
    # 越界出口自校验：分派器前那条 `ja rel32` 的目标必须 == jt[0x28]
    found_ja = False
    for back in range(2, 10):
        q = disp - back
        if q < t0:
            break
        if d[q] == 0x0F and d[q + 1] == 0x87:
            rel = struct.unpack_from("<i", d, q + 2)[0]
            tgt = (pe.off_to_va(q) or 0) + 6 + rel
            if tgt != default_va:
                notes.append("[❌] mismatch：分派器越界出口 0x%08X ≠ jt[0x28] 0x%08X —— 拒绝施加"
                             % (tgt, default_va))
                return None, None, None, None
            notes.append("分派器 VA 0x%08X：字节表 0x%08X（file 0x%X）/ 跳表 0x%08X（%d 项）/ "
                         "越界默认出口 jt[0x28]=0x%08X（与 `ja` 目标一致 ✓）"
                         % (pe.off_to_va(disp) or 0, table_va, table_off, jt_va,
                            n_entries, default_va))
            found_ja = True
            break
    if not found_ja:
        notes.append("[❌] mismatch：分派器前未找到 `ja rel32` 越界出口 —— 拒绝施加")
        return None, None, None, None
    return disp, table_va, jt_va, default_va


def _ontimer_route_site(pe, notes, handler_anchor, key_fmt, title, id_desc):
    """P18/P19 共用：把某个 nIDEvent 的字节表项改道到「越界默认出口」。

    定位链（**全部数据推导，不写死偏移**）：
      1. 分派器锚点 ⇒ 字节表基址 / 跳表基址 / 越界默认出口（含三关自校验）；
      2. 处理器块锚点 ⇒ 全库 uniq=1；锚点第 2 字节 = `push imm8` 的 timer id；
      3. 在跳表里找**唯一**指向「该处理器块」的项 `j`（判据：`jt[j]` 指向的函数
         前 32 字节内含该锚点）；
      4. 自洽校验：`j + 1` 必须 == timer id（`dec eax` 后的下标语义）；
      5. 表项位置 = 表基址 + (timer id − 1)；该位置当前值必须 == `j`（未施加）
         或 == 0x28（已施加）；否则 mismatch 拒绝写。
    """
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    disp, table_va, jt_va, default_va = _find_ontimer_dispatcher(pe, notes)
    if disp is None:
        return None, notes
    table_off = pe.va_to_off(table_va)
    jt_off = pe.va_to_off(jt_va)

    hh = []
    p = d.find(handler_anchor, t0)
    while 0 <= p < t1:
        hh.append(p)
        p = d.find(handler_anchor, p + 1)
    if len(hh) != 1:
        notes.append("[❌] mismatch：%s 处理器块锚点命中 %d 处（期望恰好 1）—— 拒绝施加"
                     % (id_desc, len(hh)))
        return None, notes
    nev = d[hh[0] + 1]                       # `push imm8` 的 timer id

    js = []
    for j in range((table_va - jt_va) // 4):
        v = struct.unpack_from("<I", d, jt_off + j * 4)[0]
        vo = pe.va_to_off(v)
        if vo is not None and handler_anchor in d[vo:vo + 32]:
            js.append(j)
    if len(js) != 1:
        notes.append("[❌] mismatch：跳表里指向 %s 处理器块的项命中 %d 个（期望恰好 1）—— 拒绝施加"
                     % (id_desc, len(js)))
        return None, notes
    j = js[0]
    # ★ 正确的不变式：`dec eax` 之后 eax = timer id − 1 用作**字节表下标**，
    #   而该格**存的字节**才是跳表下标 j（例如 id=0x31 ⇒ 表[0x30]=0x25=37 ⇒ jt[37]）。
    #   ⇒ 这里只校验「表下标在表范围内」，`表[下标]==j` 的校验放在下面读表项时做。
    table_index = nev - 1
    if nev < 1 or table_off + table_index >= t1:
        notes.append("[❌] mismatch：nIDEvent 0x%02X 的字节表下标 %d 越界 —— 拒绝施加"
                     % (nev, table_index))
        return None, notes
    if j >= (table_va - jt_va) // 4:
        notes.append("[❌] mismatch：跳表下标 %d 超出跳表范围 —— 拒绝施加" % j)
        return None, notes
    if j == _ONTIMER_DEFAULT_INDEX:
        notes.append("[❌] 原值恰好等于改道目标 0x%02X，无法区分「未施加/已施加」—— 拒绝施加"
                     % _ONTIMER_DEFAULT_INDEX)
        return None, notes

    off = table_off + table_index
    cur = d[off]
    applied = cur == _ONTIMER_DEFAULT_INDEX
    if not applied and cur != j:
        notes.append("[❌] mismatch：字节表 [0x%02X] 当前 0x%02X，既不是原值 0x%02X 也不是"
                     "已施加值 0x%02X —— 拒绝施加" % (table_index, cur, j, _ONTIMER_DEFAULT_INDEX))
        return None, notes
    sites = [Site(
        key_fmt % off, title, off, bytes([j]), bytes([_ONTIMER_DEFAULT_INDEX]),
        va=pe.off_to_va(off),
        detail="nIDEvent 0x%02X 的字节表项 [0x%02X]：0x%02X→0x%02X（跳表 idx %d → %d = "
               "越界默认出口 0x%08X）；纯数据字节、无栈语义"
               % (nev, table_index, j, _ONTIMER_DEFAULT_INDEX, j, _ONTIMER_DEFAULT_INDEX, default_va))]
    notes.append("  [命中] VA 0x%08X：0x%02X -> 0x%02X（nIDEvent 0x%02X，表项 [0x%02X]，%s）"
                 % (pe.off_to_va(off) or 0, j, _ONTIMER_DEFAULT_INDEX, nev, table_index,
                    "已在位" if applied else "本次施加"))
    return sites, notes


def find_corrupt_nag_timer_route(pe):
    """P18 —— corrupt 定时 nag 路由改道（id=0x31，主通道）。

    `OnTimer(0x31)` 不再进入 `0x487697` ⇒ 永不 `PostMessageA(0x111,0x1517)` ⇒
    线程 `0x484DB0` 不启动 ⇒ `MessageBoxW`（标题 `IDM is corrupt`）不产生。
    清栈：纯数据字节，**无栈语义**。
    """
    return _ontimer_route_site(
        pe, [], _ONTIMER_HANDLER_31, "corrupt_nag_route_31_%X",
        "P18 corrupt 定时 nag 路由改道（id=0x31）", "nIDEvent 0x31")


def find_corrupt_nag_timer_route2(pe):
    """P19 —— corrupt 定时 nag 路由改道（id=0x26，平行变体）。

    `OnTimer(0x26)` 不再进入 `0x487602` ⇒ 永不 `PostMessageA(0x111,0x14BF)` ⇒
    线程 `0x47D520` 不启动。**dyn 实测该变体弹的是同一份 `IDM is corrupt` 文案**
    ⇒ 必须与 P18 同时施加才覆盖全。
    清栈：纯数据字节，**无栈语义**。
    """
    return _ontimer_route_site(
        pe, [], _ONTIMER_HANDLER_26, "corrupt_nag_route_26_%X",
        "P19 corrupt 定时 nag 路由改道（id=0x26）", "nIDEvent 0x26")


# --------------------------------------------------------------------------- #
# P21 / P22 —— corrupt nag **线程启动点**掐断（5 字节等长，WM_COMMAND case 内）
#
# ⚠️ 为什么放弃 P18/P19（idx 40 路由改道）—— 实测崩 2/3，机制已定性：
#     正常 case 返回 → `0x4876C9 jmp 0x4882AE`（**纯尾声**）
#     越界/未注册 id → `ja 0x4882A9`（纯尾声 + 额外一条 `call 0x61591a` 虚调用清理）
#   `0x487697` 原本先 `KillTimer(hwnd,0x31)` 再 post；改道后 **KillTimer 不再执行**
#   ⇒ timer 一直响 ⇒ 每次都走 `0x4882A9` 的虚调用清理 ⇒ 反复清理同一对象 ⇒ `0xC0000005`。
#   ⇒ **idx 40 本身没问题（原版 68 个 id 在用），是我们把它变成了高频热路径。**
#
# 本轮改为掐**线程启动点**（最上游可达点），不碰定时器分派表、不碰任何数据结构、
# 不改变任何 timer 的生命周期 ⇒ `_beginthreadex` 不被调用 ⇒ 线程不存在 ⇒ 弹窗不可能出现。
#
# 链路（三处 `_beginthreadex` 站点，全部在 `0x49A6BC` WM_COMMAND 跳表的不同 case 内）：
#   变体 B  case 0x1517 → 0x4962EF: 5×`push 0` + `push 0x484DB0` + `call _beginthreadex`
#           ⇒ 线程 0x484DB0：解码 3 块 .data blob → GetDesktopWindow → MessageBoxW
#             （标题 `IDM is corrupt`，正文 342 字符）→ SetTimer(id=0x31, 1h)
#   变体 C  case 0x14BF → 0x49623D: … `push 0x47D520` + `call _beginthreadex` ⇒ 线程 0x47D520
#   变体 A  case ???    → 0x49625C: … `push 0x483FB0` + `call _beginthreadex`
#           ⚠️ **变体 A = 菜单功能，绝对不要动**（动了会破坏菜单）。本模块**不提供** A 的 finder。
#
# ★ 清栈（铁律⑯）：**禁止补 `add esp`**。
#   原代码在 `call` 之后**本就没有清栈**（紧跟 `mov eax,1`），6 个 `push` 的 24 字节由
#   `jmp 0x49A515` 收尾段的 `add ebp,0x221c0 / mov esp,ebp / pop ebp / ret 8` **从 ebp 恢复**丢弃。
#   `call` 自身的净栈变化为 0（压返回地址、`ret` 又弹回）⇒ 换成 `mov eax,1` 后 **esp 逐位相同**。
# ★ 副作用：补丁点之后**原本就有一条 `mov eax,1`**（0x496303 / 0x496251），补丁后变成
#   **两条连续的 `mov eax,1`** —— 冗余但**完全无害**（对同一寄存器写同一个常量，幂等）。
# --------------------------------------------------------------------------- #

# 三处线程启动锚点：5×`push 0` + `push <线程入口 imm32>`（各全库 uniq=1，**不含被改字节**）
_NAG_THREAD_ANCHOR_B = bytes.fromhex("6A006A006A006A006A0068B04D4800")   # → 0x00484DB0
_NAG_THREAD_ANCHOR_C = bytes.fromhex("6A006A006A006A006A006820D54700")   # → 0x0047D520
# 本版原始字节（`call 0x61C55E` = `_beginthreadex`），仅用于 describe()/回滚说明；
# 结构校验走「call 目标是否落在 .text 内」，避免锚点过严造成假阴性（铁律⑧）。
_NAG_THREAD_OLD_B = bytes.fromhex("E85B621800")
_NAG_THREAD_OLD_C = bytes.fromhex("E80D631800")
_NAG_THREAD_NEW = b"\xb8\x01\x00\x00\x00"        # mov eax,1（与紧随的原指令同义）


def _nag_thread_start_site(pe, notes, anchor, old_literal, key_fmt, title, variant):
    """P21/P22 共用：把 `call _beginthreadex` 换成 `mov eax,1`（线程不创建）。

    定位（锚点 + 三重结构校验，**不写死偏移**）：
      1. 锚点 = 5×`push 0` + `push <线程入口 imm32>`，全库 **uniq 必须 = 1**；
      2. 锚点**之后紧邻**就是 `call rel32`（`_beginthreadex`），其目标必须落在 `.text` 内；
      3. 紧随 `call` 之后必须仍是 `b8 01 00 00 00`（原有 `mov eax,1`）、`9b`（`wait`）、
         `e9`（`jmp rel32` → `0x49A515` 收尾段）—— 这三条**都不被本补丁改动**；
      4. 已施加形态 = 补丁点 5 字节 == `b8 01 00 00 00`。
    """
    d = bytes(pe.data)
    t0, t1 = pe.text_span()
    hits = []
    p = d.find(anchor, t0)
    while 0 <= p < t1:
        hits.append(p)
        p = d.find(anchor, p + 1)
    if len(hits) != 1:
        notes.append("[❌] mismatch：%s 线程启动锚点命中 %d 处（期望恰好 1）—— "
                     "锚点未命中，拒绝施加（铁律⑫：不静默跳过）" % (variant, len(hits)))
        return None, notes
    a = hits[0]
    entry_va = struct.unpack_from("<I", d, a + len(anchor) - 4)[0]
    if pe.va_to_off(entry_va) is None:
        notes.append("[❌] mismatch：%s 锚点里的线程入口 0x%08X 不在映像内 —— 拒绝施加"
                     % (variant, entry_va))
        return None, notes
    off = a + len(anchor)                    # 锚点之后紧邻就是 `call _beginthreadex`
    cur = bytes(d[off:off + 5])
    applied = cur == _NAG_THREAD_NEW
    if applied:
        old = old_literal
    else:
        if cur[0:1] != b"\xe8":
            notes.append("[❌] mismatch：%s 锚点之后不是 `call rel32`（实际 %s）—— 拒绝施加"
                         % (variant, cur.hex(" ")))
            return None, notes
        rel = struct.unpack_from("<i", d, off + 1)[0]
        tgt_va = (pe.off_to_va(off) or 0) + 5 + rel
        tgt_off = pe.va_to_off(tgt_va)
        if tgt_off is None or not (t0 <= tgt_off < t1):
            notes.append("[❌] mismatch：%s 的 call 目标 0x%08X 不在 .text 内 —— 拒绝施加"
                         % (variant, tgt_va))
            return None, notes
        notes.append("%s 线程入口 0x%08X / `call` 目标 0x%08X（`_beginthreadex`）"
                     % (variant, entry_va, tgt_va))
        if cur != old_literal:
            notes.append("  （call rel32 与本版记录不同：%s vs %s，按结构校验继续）"
                         % (cur.hex(" "), old_literal.hex(" ")))
        old = cur
    # 三重结构校验（均不被本补丁改动）
    if bytes(d[off + 5:off + 10]) != b"\xb8\x01\x00\x00\x00":
        notes.append("[❌] mismatch：%s 的 `call` 之后不是原有的 `mov eax,1`（实际 %s）—— 拒绝施加"
                     % (variant, d[off + 5:off + 10].hex(" ")))
        return None, notes
    if d[off + 10] != 0x9B or d[off + 11] != 0xE9:
        notes.append("[❌] mismatch：%s 的 `mov eax,1` 之后不是 `wait; jmp rel32`（实际 %s）—— 拒绝施加"
                     % (variant, d[off + 10:off + 14].hex(" ")))
        return None, notes
    sites = [Site(
        key_fmt % off, title, off, old, _NAG_THREAD_NEW, va=pe.off_to_va(off),
        detail="`call _beginthreadex` -> `mov eax,1`（线程 %X 不创建；"
               "`call` 净栈变化 0 ⇒ esp 逐位相同，**禁止补 add esp**；"
               "补丁后与原有 `mov eax,1` 形成两条连续同义指令，冗余但无害）" % entry_va)]
    notes.append("  [命中] VA 0x%08X：%s -> %s（%s）"
                 % (pe.off_to_va(off) or 0, old.hex(" "), _NAG_THREAD_NEW.hex(" "),
                    "已在位" if applied else "本次施加"))
    return sites, notes


def find_corrupt_nag_thread_start(pe):
    """P21 —— corrupt nag 线程启动点掐断（变体 B，线程 `0x484DB0`，case 0x1517）。

    `_beginthreadex(0x484DB0)` 不被调用 ⇒ 该线程不存在 ⇒ 它内部的
    `GetDesktopWindow` + `MessageBoxW`（标题 `IDM is corrupt`）不可能发生。
    清栈：**禁止补 `add esp`**（详见本节头部论证）。
    """
    return _nag_thread_start_site(
        pe, [], _NAG_THREAD_ANCHOR_B, _NAG_THREAD_OLD_B, "corrupt_nag_thread_b_%X",
        "P21 corrupt nag 线程启动点掐断（变体B / 线程 0x484DB0）", "变体 B")


def find_corrupt_nag_thread_start2(pe):
    """P22 —— corrupt nag 线程启动点掐断（变体 C，线程 `0x47D520`，case 0x14BF）。

    ⚠️ **变体 A（线程 `0x483FB0`，`0x49626B`）是菜单功能，本模块不提供其 finder**，
    也不得由任何其它 finder 命中它（三处锚点的 imm32 各不相同，各 uniq=1）。
    清栈：**禁止补 `add esp`**。
    """
    return _nag_thread_start_site(
        pe, [], _NAG_THREAD_ANCHOR_C, _NAG_THREAD_OLD_C, "corrupt_nag_thread_c_%X",
        "P22 corrupt nag 线程启动点掐断（变体C / 线程 0x47D520）", "变体 C")


# --------------------------------------------------------------------------- #
# 统一入口：P1..P22 的构建与施加
#
# 放在 engine 里（而不是 activator 里）是为了让「部署/验证」与「用户流程」两条
# 工作流共用同一份实现，避免两处各写一套 apply 逻辑而漂移。
# --------------------------------------------------------------------------- #

ALL_FINDERS = (
    (find_registration_flag,  "P1 注册状态"),
    (find_expiry_format,      "P2 到期显示 9999"),
    (find_nag_function,       "P3 弹窗函数置空"),
    (find_counterfeit_guard,  "P4 counterfeit 闸门封堵"),
    (find_tripwire_exits,     "P5 tripwire 自杀出口封死"),
    (find_counterfeit_popups, "P6 counterfeit 弹窗静音"),
    (find_counterfeit_broadcast, "P7 counterfeit 广播线程封死"),
    (find_mdata_write,        "P9 MData 写入封死"),
    (find_counterfeit_longtext_popup, "P10 长版 counterfeit 弹窗静音"),
    (find_latent_longtext_popup, "P11 潜伏长版弹窗静音"),
    (find_registration_dialog, "P13 注册框不创建（修「点取消就退出」）"),
    # P14 放在 P10/P11 **之后**：它的 0x41030 枚举天然包含 P10/P11 那两个偏移，
    # 由 build_all_sites 的「按偏移去重、先到先得」把重复项收敛掉。
    (find_wrapper_utype_shortcut, "P14 弹窗包装按 uType 短路（wrapper 级，cave）"),
    (find_download_registration_dialog, "P15 下载路径注册框不创建"),
    # P16/P17 放在最后：两者各自独立扫 gate 锚点（铁律⑪），不依赖任何前面 finder
    # 的施加后状态，也不与任何既有站点共用偏移。
    (find_corrupt_flag_gate, "P16 corrupt 判定标志不置位（根治）"),
    (find_corrupt_alert_exit, "P17 corrupt 告警显示出口短路（兜底）"),
    # ⚠️ P18/P19（OnTimer 字节表路由改道 → idx 40）**已实测崩溃，定案放弃**：
    #   实测 P18/P19 × 3 = 崩 2 / 活 1（1.36s / 4.52s，0xC0000005 偏移 0）；同期 P17 × 10 全净。
    #   机制：`0x487697` 原本先 KillTimer(0x31) 再 post；改道后 KillTimer 不再执行 ⇒ timer 一直响
    #   ⇒ 每次都走 `0x4882A9`（比纯尾声 `0x4882AE` 多一条 `call 0x61591a` 虚调用清理）
    #   ⇒ 反复清理同一对象 ⇒ 访问违例。**idx 40 本身没问题，是我们把它变成了高频热路径。**
    #   ⇒ **不进 ALL_FINDERS**；仅保留实现作为「被否证方案」的记录，避免后人误以为它有效。
    #   **不要重新启用。** 改用下面的 P21/P22（掐线程启动点）。
    # (find_corrupt_nag_timer_route,  "P18 corrupt 定时 nag 路由改道（id=0x31）【RETIRED·实测崩溃】"),
    # (find_corrupt_nag_timer_route2, "P19 corrupt 定时 nag 路由改道（id=0x26）【RETIRED·实测崩溃】"),
    # P21/P22 掐 `_beginthreadex` 线程启动点：不碰定时器分派表、不改任何 timer 生命周期，
    # 两个 finder 各自独立扫锚点（铁律⑪），且**不覆盖变体 A（菜单功能）**。
    (find_corrupt_nag_thread_start, "P21 corrupt nag 线程启动点掐断（变体B / 线程 0x484DB0）"),
    (find_corrupt_nag_thread_start2, "P22 corrupt nag 线程启动点掐断（变体C / 线程 0x47D520）"),
    # ⚠️ P12（find_license_valid，file 0xEDBF7 / 0xEDC1F，A+B）**已被实测否决**：
    #    Lead 手工热补丁 + 冷启动验证 ⇒ 注册框照旧弹 12/12。原因是它改的
    #    `byte_788CF4` 根本不是「决定弹注册框」的标志（注册框的门控在
    #    `sub_451E30` 的 `cmp esi,ebx / je`，见 P13）。
    #    ⇒ **不进 ALL_FINDERS**，仅保留下面的实现作为「被否证方案」的记录，
    #    避免后人误以为它有效。**不要重新启用。**
    # (find_license_valid,     "P12 许可判定恒有效（修注册框）【RETIRED·实测无效】"),
)


def build_all_sites(pe, finders=None):
    """构建补丁点。`finders=None` ⇒ 用模块级 ALL_FINDERS（P1..P9，IDMan.exe）。

    第二目标二进制（如 IDMGrHlp.exe）传 `HELPER_FINDERS` 即可，
    **既有调用方不传参 ⇒ 行为与改动前逐字节一致**。
    注意：默认值必须写 `None` 而在函数体内取 `ALL_FINDERS`，**不能**写成
    `finders=ALL_FINDERS` —— 那样 tupledefault 会在 def 时绑定，运行时再替换
    `idm_engine.ALL_FINDERS`（测试/回归脚本常用的打桩手法）就会失效。
    返回 (sites, lines)。
    """
    if finders is None:
        finders = ALL_FINDERS
    sites, lines = [], []
    for fn, label in finders:
        lines.append("")
        lines.append("=== %s ===" % label)
        try:
            res, notes = fn(pe)
        except Exception as exc:
            lines.append("  [异常] %s" % exc)
            continue
        for n in notes:
            lines.append("  · " + n)
        if res is None:
            lines.append("  [跳过] 未能可靠定位")
            continue
        found = list(res) if isinstance(res, (list, tuple)) else [res]
        if not found:
            lines.append("  [跳过] 未命中")
            continue
        for site in found:
            lines.append("  [命中] " + site.describe())
            if site.old != site.new:
                # 去重（按文件偏移，先到先得）：不同 finder 可能命中同一个偏移
                # （P14 的 0x41030 枚举天然包含 P10/P11 那两个站点）。
                # 不去重会让同一处被登记两次、站点计数虚高。
                if any(s.offset == site.offset for s in sites):
                    lines.append("    [去重] 该偏移已由前面的 finder 登记，跳过")
                    continue
                sites.append(site)
    return sites, lines


def apply_all(exe_path, backup_suffix=BACKUP_SUFFIX, finders=None):
    """施加补丁。返回 (status, detail, changed)。

    status ∈ {"patched", "clean", "mismatch", "error"}。
    幂等：重复调用不会重复改写；已在位的补丁会被跳过。
    `finders=None` ⇒ 模块级 ALL_FINDERS（IDMan.exe）；第二目标二进制传 HELPER_FINDERS。
    （同 build_all_sites：默认写 None 以保留运行时替换 ALL_FINDERS 的能力。）
    """
    import shutil
    pe = PE(exe_path)
    sites, _ = build_all_sites(pe, finders)
    bad = [s for s in sites if s.check(pe) == "mismatch"]
    if bad:
        return "mismatch", "有 %d 处补丁点字节不符，已拒绝（版本可能变了）：%s" % (
            len(bad), ", ".join(s.key for s in bad)), False
    todo = [s for s in sites if s.check(pe) == "ready"]
    if not todo:
        return "clean", "全部补丁已在位（无需改动）", False
    results = apply_sites(pe, todo)
    done = [s for s, st in results if st == "patched"]
    if not done:
        return "clean", "没有需要施加的补丁", False
    bak = exe_path + backup_suffix
    if not os.path.exists(bak):
        try:
            shutil.copy2(exe_path, bak)
        except Exception as exc:
            return "error", "备份失败：%s" % exc, False
    tmp = exe_path + ".idm-patch-new"
    try:
        with open(tmp, "wb") as f:
            f.write(bytes(pe.data))
        shutil.move(tmp, exe_path)
    except Exception as exc:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return "error", "写入失败：%s" % exc, False
    return "patched", "已施加 %d 处：%s" % (
        len(done), "; ".join("%s@0x%X" % (s.key, s.offset) for s in done)), True


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


def pe_checksum(data):
    """计算 PE 头 CheckSum（标准算法，跳过 CheckSum 字段自身）。"""
    n = len(data)
    lf = struct.unpack_from("<I", data, 0x3C)[0]
    ck_off = lf + 24 + 64
    total = 0
    i = 0
    while i < n - 1:
        if i == ck_off or i == ck_off + 2:
            i += 2
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if n % 2:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


def ensure_pe_checksum(data):
    """重算并把 PE 头 CheckSum 写回。

    ★ 为什么必须做：IDMan.exe **有自完整性校验** —— 用户实测改完 exe 后弹
      「IDM is corrupt / The main IDM executive file is damaged」。
      实测证据：pristine 的 stored CheckSum == 计算值 == 0x005F549C；
      打完补丁后内容变了、stored 未变 ⇒ 计算值 0x005EBD63 ≠ stored ⇒ 校验失败。
      写回正确 CheckSum **无副作用**：不改代码、不改大小、不动任何补丁字节。
    """
    d = bytearray(data)
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    ck_off = lf + 24 + 64
    ck = pe_checksum(bytes(d))
    struct.pack_into("<I", d, ck_off, ck)
    return bytes(d), ck


def apply_sites(pe, sites):
    """在内存里施加补丁，返回逐条结果。

    打完补丁后**自动重算 PE CheckSum**（否则 IDM 的自完整性校验会报 corrupt）。
    """
    results = []
    changed = False
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
        changed = True
    if changed:
        fixed, _ck = ensure_pe_checksum(bytes(pe.data))
        pe.data[:] = fixed
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
