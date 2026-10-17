#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM-Activator —— Internet Download Manager 6.43 一键激活（免守护 / 静态方案）

================================================================================
本版最大的变化：**彻底删掉「守护」**
================================================================================
旧版装了一个 30 分钟一次的计划任务守护，它做三件事：清 MData、轮换序列号、重打补丁。
实测证明这个守护**本身就是 bug 的来源**：

    伪造序列号 -> IDM 在 ~62s 判定 counterfeit -> 写 MData 标记 + ExitProcess(0)
    -> 守护发现 MData -> 删掉它并把序列号换成新的 -> 新序列号又被判假 -> 回到第一步

这是一个**自伤闭环**：守护在给 IDM 反复上供新的假序列号，于是 IDM 反复自杀。
用户看到的现象就是「IDM 用一会儿就自己退了」。

新方案改成**静态、无进程**：跑一次，机器进入一个不需要任何维护的稳定状态。

================================================================================
新的分层设计（层 A / B / C）
================================================================================
  层 A  注册状态   : 清掉 counterfeit 残留（MData + 缓存的校验判决值），
                     写格式合法的注册信息（抑制「注册 IDM」对话框）。
  层 B  二进制补丁 : P1..P6 共 10 个补丁点（由 idm_engine.apply_all 施加）。
                     P5 封死 4 处 tripwire 自杀出口，P6 静音 2 处 counterfeit 弹窗。
                     => 即使误入 counterfeit 分支，IDM 也无法 ExitProcess(0)。
  层 C  防回退     : (a) IDMan.exe 文件系统 ACL 不可变（DENY Everyone WD,DE）
                        —— 官方更新包无法覆盖补丁。这是**替代守护**的关键一步。
                     (b) hosts 屏蔽注册/校验域名（域名级，抗 IP 漂移）
                        —— 假序列号永远不可能被上报。

  **不安装任何计划任务，不写任何 Run 自启项。**

================================================================================
为什么不再用「守护轮换序列号」那一套
================================================================================
  1. 序列号被判假 -> 写 MData -> 退出的根因是**序列号是伪造的**，
     轮换只是换一个新的伪造品，问题永远存在；
  2. 现在有 P5/P6 + hosts 三层，counterfeit 分支既不能自杀也弹不出窗，
     且序列号根本出不了本机 —— 不需要有人去「自愈」；
  3. 防回退用**预防**（ACL 不可变）而不是**修补**（守护重打补丁），
     所以不需要常驻任何东西。

================================================================================
用法
================================================================================
  IDM-Activator.exe                   一键激活（默认，自动提权）—— 无守护
  IDM-Activator.exe --activate        同上（显式写法）
  IDM-Activator.exe --status          只查看状态（只读，不需要管理员）
  IDM-Activator.exe --scan            只分析会改什么，不动手（只读）
  IDM-Activator.exe --uninstall       完全还原（幂等，跑两次也不报错）
  IDM-Activator.exe --no-guard        历史兼容参数，现在是**空操作**（无守护）
  IDM-Activator.exe --guard           打印「守护模型已移除」并退出 0（不装任何东西）
  IDM-Activator.exe --no-lock         跳过 ACL 不可变那一步（调试用）

  --install-dir / --serial / --fname / --lname / --email  同旧版，保留。
"""

import os
import re
import sys
import time
import shutil
import ctypes
import argparse
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import idm_engine as eng
except Exception:
    sys.path.insert(0, getattr(sys, "_MEIPASS", "."))
    import idm_engine as eng

APP = "IDM-Activator"
EXE_NAME = "IDMan.exe"
BACKUP_SUFFIX = eng.BACKUP_SUFFIX          # ".bak-original"

# 旧守护留下的计划任务名（现在只用来**删除**，绝不创建）
LEGACY_TASKS = ("IDM-Activator-Guard", "IDM-Activator-Guard-Logon")
# 旧 lockdown 脚本留下的任务名（脚本里就是这个）
LEGACY_TASKS_EXTRA = ("IDM-Patch-Lockdown",)
# ★ 只按名字匹配是不够的：将来可能再加第三个任务名。
#   所以还要扫 schtasks 全表，凡是**动作里引用 IDM-Activator.exe / IDM-Patch-Lockdown**
#   的任务一律算残留守护（见 find_guard_tasks）。
LEGACY_ACTION_MARKERS = ("idm-activator", "idm-patch-lockdown", "idm_patch_lockdown")
# Run 自启项：HKCU + HKLM + WOW6432Node 三个位置都要查，
# 且**按值内容**判断（不只按键名）—— 旧 lockdown 脚本的键名不一定带这些关键词。
RUN_KEY_SUB = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_SUB_WOW = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

DEFAULT_DIRS = [r"C:\Program Files (x86)\Internet Download Manager",
                r"C:\Program Files\Internet Download Manager"]

REG_SUBKEY = r"SOFTWARE\Internet Download Manager"
REG_SUBKEY_WOW = r"SOFTWARE\WOW6432Node\Internet Download Manager"
REG_VALUES = ("Serial", "FName", "LName", "Email")
MDATA_NAME = "MData"

# counterfeit 标记（MData）的存放位置：HKCU\Software\Classes\[Wow6432Node\]CLSID\{GUID}
# GUID 是二进制里的硬编码字面量（实测命中 {79873CC5-...} 与 {E6871B76-...}），
# 但键**可能新增**，所以绝对不能写死 —— 必须遍历整棵 CLSID 树按「值名恰好是 MData」找。
CLSID_TREES = (
    r"Software\Classes\CLSID",
    r"Software\Classes\Wow6432Node\CLSID",
)
CLSID_TREES_HKLM = (
    r"SOFTWARE\Classes\CLSID",
    r"SOFTWARE\WOW6432Node\Classes\CLSID",
)
# sub_51FFC0 把服务端判决缓存在这个键下（值名是 XOR 派生的，整键清值最稳）
VERDICT_KEY = r"Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}"

# --------------------------------------------------------------------------- #
# hosts 屏蔽（与 scripts\idm-permanent-fix.ps1 完全一致的语义）
#   * 同一个 marker、同一批域名、同一个备份文件名 —— 两个工具可以互相接手/互相回滚
#   * 域名级屏蔽（而不是 IP 级）：服务器换 IP 也拦得住
# --------------------------------------------------------------------------- #
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          r"System32\drivers\etc\hosts")
HOSTS_BACKUP = HOSTS_PATH + ".bak-permanentfix"
HOSTS_MARKER = "# IDM-Activator-PermanentFix"
HOSTS_DOMAINS = (
    # 主域名 + 全部已知子域名。
    # ⚠️ hosts 是**精确匹配**，不认通配：写了 internetdownloadmanager.com
    #    并不覆盖 www./secure./register. 三个子域名。实测踩过这个坑 ——
    #    父域名已屏蔽，但 ping www.internetdownloadmanager.com 仍解析到
    #    67.18.60.145（真实服务器），于是 IDM 的联网校验照旧能跑。
    "internetdownloadmanager.com",
    "www.internetdownloadmanager.com",
    "secure.internetdownloadmanager.com",
    "register.internetdownloadmanager.com",
    "update.internetdownloadmanager.com",
    "support.internetdownloadmanager.com",
    "idm.internetdownloadmanager.com",
    "tonec.com",
    "www.tonec.com",
    "secure.tonec.com",
    "register.tonec.com",
)

# 已知哈希（仅用于**提示**，不用于判定成败）
KNOWN_ORIGINALS = {
    "74f177c8a44a6feb95a88e1d8b385bc2683b4b87e7ef8bfe333a058c436cc9b8": "6.43 Build 8（原版）",
    "279ceed9aaa646650716ee326c0d996be4ce5db4b252cf5b2747f4938a7ce737": "6.43 Build 15（原版）",
}
# ⚠️ 这个哈希**只当提示**：它是早期 P1..P4 时代的产物，引擎后来加了 P5/P6，
#    同一个原始 b15 打完后哈希已经变成 cb2a3e6b…（实测）。
#    **判定「补丁全不全」绝不能依赖硬编码哈希** —— 引擎一升级就会误报失败。
#    真正的判定见 verify_patched()：拿备份（原版）在临时目录里重跑一遍引擎，
#    自证式地算出「期望的补丁后哈希」，再和实际文件比对。
KNOWN_PATCHED_HINT = {
    "4b089abbb770c9c38edd9aeb4ed9d91a1243fe70724f6c21d153968e677c8ce6":
        "6.43 Build 15（历史记录：P1..P4 时代的补丁后哈希）",
}
# ★ 补丁点表只能当参考，不能当判定依据：
#   idm_engine 的 find_* 全部以「原始字节」为锚点，文件一旦打过补丁这些锚点就失效
#   （实测：原始 b15 定位到 10 点，全补丁 b15 只剩 3~6 点）。
#   所以 --status/--activate 的成败判定走 verify_patched() 的哈希自证。
EXPECTED_SITE_COUNT = 10

LOG_PATH = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                        "IDM-Activator", "activator.log")


# --------------------------------------------------------------------------- #
# 基础
# --------------------------------------------------------------------------- #

def log(msg, quiet=False):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    if not quiet:
        try:
            print(line)
        except Exception:
            pass
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def say(msg=""):
    """安全输出：--noconsole 打包 + 某些启动方式下 sys.stdout 可能是 None。

    直接 print 会抛 AttributeError 把整个流程打断（补丁已经打了、后面却没跑完），
    所以所有面向用户的输出都走这里。
    """
    try:
        if sys.stdout is not None:
            sys.stdout.write(str(msg) + "\n")
            sys.stdout.flush()
    except Exception:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_console():
    """打包成 windowed（无窗口）exe 后双击不会自带控制台，交互模式下自己分配一个。

    为什么这么做：EXE 用 --noconsole 打包（PE Subsystem = 2，绝不闪黑窗）。
    """
    if not getattr(sys, "frozen", False):
        return                      # 直接跑 .py 时本来就有控制台
    try:
        k32 = ctypes.windll.kernel32
        if k32.GetConsoleWindow():
            return
        if not k32.AllocConsole():
            return
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        sys.stderr = sys.stdout
        try:
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
        except Exception:
            pass
    except Exception:
        pass


class SEI(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong),
                ("hwnd", ctypes.c_void_p), ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.c_void_p), ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
                ("dwHotKey", ctypes.c_ulong), ("hIcon", ctypes.c_void_p),
                ("hProcess", ctypes.c_void_p)]


def elevate_and_wait():
    sei = SEI()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x40 | 0x100
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    args = " ".join('"%s"' % a if " " in a else a for a in sys.argv[1:])
    sei.lpParameters = args if getattr(sys, "frozen", False) else \
        '"%s" %s' % (os.path.abspath(__file__), args)
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False
    if sei.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(sei.hProcess), 0xFFFFFFFF)
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(sei.hProcess))
    return True


def find_install_dir(explicit=None):
    return eng.find_install_dir(explicit)


# --------------------------------------------------------------------------- #
# ★ 隔离护栏（最重要的一段代码，请勿削弱）
#
# 事故记录：开发期用 `--install-dir .scratch\fresh` 跑 --activate/--uninstall，
# 二进制补丁确实只落在 scratch 里，但**注册表 / hosts / 计划任务 / 杀进程**
# 这四条路径用的是**全局**位置，不认 --install-dir。后果：
#   1) 打掉了另一个队友正在做的实机验证（IDMan.exe 被 taskkill 掉两次）；
#   2) 清空了实机的 HKLM 注册信息（Serial/FName/LName/Email）；
#   3) 还原了实机 hosts。
# 所以现在加一道硬护栏：**只有在「目标就是实机安装目录」时才允许碰系统级状态**，
# 否则一律跳过并打印原因。scratch 目录再也不会泄漏到实机。
# --------------------------------------------------------------------------- #

LIVE_INSTALL_DIRS = [r"C:\Program Files (x86)\Internet Download Manager",
                     r"C:\Program Files\Internet Download Manager"]


def _norm_path(p):
    try:
        return os.path.normcase(os.path.abspath(p)).rstrip("\\")
    except Exception:
        return ""


def _registry_install_dir():
    """从注册表读 IDM 的真实安装目录（只读）。读不到返回 None。"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager") as k:
            return os.path.dirname(winreg.QueryValueEx(k, "ExePath")[0])
    except Exception:
        return None


def is_live_install_dir(path):
    """判断 path 是不是**实机**的 IDM 安装目录。

    认定条件（任一）：
      * 等于两个标准安装目录之一；
      * 等于注册表 ExePath 指向的目录。
    """
    if not path:
        return False
    n = _norm_path(path)
    if not n:
        return False
    for d in LIVE_INSTALL_DIRS:
        if n == _norm_path(d):
            return True
    rd = _registry_install_dir()
    return bool(rd) and n == _norm_path(rd)


def system_changes_allowed(args, install_dir):
    """本进程是否被允许修改**系统级**状态（注册表 / hosts / 计划任务 / 杀进程）。

    允许的两种情况：
      1. 目标是实机安装目录 —— 这是正常的「一键激活」路径；
      2. 显式传了 --allow-system-changes（只在明确知情时使用）。
    其它情况一律拒绝，避免 scratch 测试污染实机。
    """
    if getattr(args, "allow_system_changes", False):
        return True, "已显式指定 --allow-system-changes"
    if is_live_install_dir(install_dir):
        return True, "目标是实机安装目录"
    return False, ("目标 %s 不是实机安装目录 —— 隔离护栏已跳过所有系统级改动"
                   "（注册表 / hosts / 计划任务 / 杀进程）" % install_dir)


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def kill_idm(quiet=False, allowed=True):
    """停掉所有 IDM 进程（IDMan.exe / idmBroker.exe）。

    ★ allowed=False 时**完全不碰进程表**。这是隔离护栏的一部分：
      事故记录：开发期用 scratch 目录跑 --activate，补丁只落 scratch，
      但这里按**进程名**杀，把队友正在做验证的实机 IDMan.exe 一起杀了。
      只要目标不是实机安装目录，就绝不执行 taskkill。
    """
    if not allowed:
        if not quiet:
            log("  已跳过：不停止 IDM 进程（非实机目标，隔离护栏）")
        return []
    killed = []
    for name in (EXE_NAME, "idmBroker.exe"):
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", name, "/T"],
                               capture_output=True, timeout=20)
            if r.returncode == 0:
                killed.append(name)
        except Exception:
            pass
    if killed and not quiet:
        log("  已停止：%s" % ", ".join(killed))
    time.sleep(1)
    return killed


def _run(cmd, timeout=60):
    """跑外部命令，返回 (returncode, 输出文本)。

    ★ 不能依赖 text=True：Windows 中文系统上 icacls / schtasks 输出是 **GBK**，
      Python 会用 locale 编码去解，可能抛 UnicodeDecodeError。
      所以统一按字节收，再用 errors="replace" 解 —— 永远不会因为编码炸掉。
    """
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception as exc:
        return -1, str(exc)
    out = (r.stdout or b"") + b"\n" + (r.stderr or b"")
    return r.returncode, out.decode("utf-8", errors="replace")


def _reg_flag(view):
    """注册表视图 flag：64 = KEY_WOW64_64KEY，32 = KEY_WOW64_32KEY。"""
    import winreg
    return winreg.KEY_WOW64_64KEY if view == 64 else winreg.KEY_WOW64_32KEY


# --------------------------------------------------------------------------- #
# 注册表 —— counterfeit 清理
# --------------------------------------------------------------------------- #

def _enum_subkeys(hive, base, view):
    """递归枚举 base 下所有子键的完整路径（迭代式，避免深递归）。"""
    import winreg
    out, stack = [], [base]
    while stack:
        sub = stack.pop()
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | _reg_flag(view)) as k:
                i = 0
                while True:
                    try:
                        child = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    stack.append(sub + "\\" + child)
                    out.append(sub + "\\" + child)
        except Exception:
            continue
    return out


def find_mdata_keys(verbose=False):
    """遍历 CLSID 树，找出所有含 MData 值的键。返回 [(hive, path, view)]。"""
    import winreg
    found = []
    targets = [(winreg.HKEY_CURRENT_USER, p, 64) for p in CLSID_TREES] + \
              [(winreg.HKEY_CURRENT_USER, p, 32) for p in CLSID_TREES] + \
              [(winreg.HKEY_LOCAL_MACHINE, p, 64) for p in CLSID_TREES_HKLM] + \
              [(winreg.HKEY_LOCAL_MACHINE, p, 32) for p in CLSID_TREES_HKLM]
    for hive, base, view in targets:
        for sub in [base] + _enum_subkeys(hive, base, view):
            try:
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | _reg_flag(view)) as k:
                    i = 0
                    has = False
                    while True:
                        try:
                            if winreg.EnumValue(k, i)[0].lower() == MDATA_NAME.lower():
                                has = True
                            i += 1
                        except OSError:
                            break
                    if has:
                        found.append((hive, sub, view))
            except Exception:
                continue
    if verbose:
        for hive, sub, view in found:
            log("    命中 %s\\%s (view=%d)" % (
                "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", sub, view))
    return found


def clean_counterfeit(quiet=False):
    """清除 counterfeit 标记：先删 MData 值，再尝试删掉整个 CLSID 键。

    这是 IDM 官方的清理语义（0x42F03A 附近就是这条路径），删掉安全。
    顺序很重要：DeleteKeyEx 对非空键会失败，所以必须先删值。
    """
    import winreg
    cleaned = []
    for hive, sub, view in find_mdata_keys():
        ok = False
        try:
            with winreg.OpenKey(hive, sub, 0,
                                winreg.KEY_SET_VALUE | _reg_flag(view)) as k:
                winreg.DeleteValue(k, MDATA_NAME)
            ok = True
        except Exception:
            pass
        try:
            winreg.DeleteKeyEx(hive, sub, _reg_flag(view))
            cleaned.append(sub + " (整键)")
        except Exception:
            if ok:
                cleaned.append(sub + " (仅删值)")
    if cleaned and not quiet:
        log("  已清除 counterfeit 标记：%s" % "; ".join(cleaned))
    return cleaned


def has_counterfeit():
    return bool(find_mdata_keys())


def clear_verdict_cache(quiet=False):
    """清掉 sub_51FFC0 缓存的服务端校验判决（值名 XOR 派生，整键清值最稳）。

    必须同时清 64 位与 32 位视图：IDM 是 32 位进程（写 32 位视图），
    但旧脚本是 64 位 PowerShell（写 64 位视图），两边都可能留残留。
    """
    import winreg
    n, hits = 0, []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (64, 32):
            try:
                with winreg.OpenKey(hive, VERDICT_KEY, 0,
                                    winreg.KEY_READ | winreg.KEY_SET_VALUE
                                    | _reg_flag(view)) as k:
                    names, i = [], 0
                    while True:
                        try:
                            names.append(winreg.EnumValue(k, i)[0])
                            i += 1
                        except OSError:
                            break
                    for nm in names:
                        try:
                            winreg.DeleteValue(k, nm)
                            n += 1
                        except Exception:
                            pass
                    if names:
                        hits.append("%s\\%s (view=%d, %d 个值)" % (
                            "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            VERDICT_KEY, view, len(names)))
            except Exception:
                continue
    if hits and not quiet:
        log("  已清除缓存的校验判决：%s" % "; ".join(hits))
    return n, hits


# --------------------------------------------------------------------------- #
# 注册表 —— 注册信息
# --------------------------------------------------------------------------- #

def _reg_views():
    import winreg
    return [(winreg.HKEY_LOCAL_MACHINE, REG_SUBKEY_WOW, 64),
            (winreg.HKEY_LOCAL_MACHINE, REG_SUBKEY, 64),
            (winreg.HKEY_CURRENT_USER, REG_SUBKEY, 64)]


def write_registration(serial, fname, lname, email, quiet=False):
    """写注册信息。**IDM 读的是 HKLM 的 32 位视图（WOW6432Node）**，
    写 HKCU 是无效的 —— 这是实测纠正过的关键点。"""
    import winreg
    written = []
    for hive, sub, view in _reg_views():
        try:
            with winreg.CreateKeyEx(hive, sub, 0,
                                    winreg.KEY_SET_VALUE | _reg_flag(view)) as k:
                for n, v in (("Serial", serial), ("FName", fname),
                             ("LName", lname), ("Email", email)):
                    winreg.SetValueEx(k, n, 0, winreg.REG_SZ, v)
            written.append("%s\\%s" % (
                "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", sub))
        except Exception as exc:
            if not quiet:
                log("  [失败] %s : %s" % (sub, exc))
    return written


def read_registration():
    """读回注册信息：优先 HKLM 32 位视图，其次 HKLM 64 位视图，最后 HKCU。

    返回 (values, 来源描述)。IDM 真正读的是 HKLM 的 32 位视图。
    """
    import winreg
    for hive, sub, view in _reg_views():
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | _reg_flag(view)) as k:
                got = {}
                for n in REG_VALUES:
                    try:
                        got[n] = winreg.QueryValueEx(k, n)[0]
                    except FileNotFoundError:
                        got[n] = None
                if got.get("Serial"):
                    return got, "%s\\%s" % (
                        "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", sub)
        except Exception:
            continue
    return {n: None for n in REG_VALUES}, None


def purge_registration(quiet=False):
    """删掉 Serial/FName/LName/Email（三个视图都清）。"""
    import winreg
    removed = []
    for hive, sub, view in _reg_views():
        for name in REG_VALUES:
            try:
                with winreg.OpenKey(hive, sub, 0,
                                    winreg.KEY_SET_VALUE | _reg_flag(view)) as k:
                    winreg.DeleteValue(k, name)
                removed.append(name)
            except Exception:
                pass
    if removed and not quiet:
        log("  已移除注册信息：%s" % ", ".join(sorted(set(removed))))
    return removed


def gen_serial(rng=None):
    """生成格式合法的 IDM 序列号：XXXXX-XXXXX-XXXXX-XXXXX。

    IDM 的校验只有两条：(1) 长度 23、第 5/11/17 位是 '-';
    (2) 用**前 8 个字符**查本地黑名单。没有密码学校验、不需要联网。
    """
    import random, string
    rng = rng or random.SystemRandom()
    alphabet = string.ascii_uppercase + string.digits
    while True:
        s = "-".join("".join(rng.choice(alphabet) for _ in range(5)) for _ in range(4))
        if s[:4] not in ("AAAA", "1234", "TEST", "0000"):
            return s


def check_serial(serial):
    if len(serial) != 23:
        return False, "长度应为 23，实际 %d" % len(serial)
    for i in (5, 11, 17):
        if serial[i] != "-":
            return False, "第 %d 位应为 '-'" % i
    return True, "格式合法"


def read_idmvers():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\DownloadManager") as k:
            return winreg.QueryValueEx(k, "idmvers")[0]
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# hosts 屏蔽
# --------------------------------------------------------------------------- #

def _read_hosts():
    with open(HOSTS_PATH, "rb") as f:
        raw = f.read()
    return raw.decode("utf-8", errors="replace").splitlines()


def _hosts_has_marker(path):
    """判断某个 hosts 类文件里是否已经含有我们的屏蔽块（marker 字符串）。

    ★ 必须校验备份的「干净度」：实测本机 `hosts.bak-permanentfix` 是在**屏蔽已经生效之后**
      才被创建的（旧 PowerShell 脚本先屏蔽、后备份，或重复运行时备份被覆盖），
      于是备份里本身就带 marker。如果 --uninstall 无条件用这个备份去还原，
      结果就是「日志说还原成功、屏蔽其实还在」——一个静默失败。
      所以：只有当备份**不含** marker 时，才允许用它还原。
    """
    try:
        with open(path, "rb") as f:
            return HOSTS_MARKER in f.read().decode("utf-8", errors="replace")
    except Exception:
        return None                     # None = 读不到（不存在或没权限）


def _write_hosts(lines):
    """临时文件 + 原子替换：写失败也绝不会把现有 hosts 截断。

    编码用 ASCII（与 PowerShell 版一致）：域名与 marker 全是 ASCII，
    任何非 ASCII 的残留注释会被替换成 '?'，但绝不会写坏文件。
    """
    tmp = HOSTS_PATH + ".new"
    data = "\r\n".join(lines) + "\r\n"
    with open(tmp, "wb") as f:
        f.write(data.encode("ascii", errors="replace"))
    os.replace(tmp, HOSTS_PATH)


def hosts_block_lines():
    return [HOSTS_MARKER] + ["0.0.0.0 %s %s" % (d, HOSTS_MARKER) for d in HOSTS_DOMAINS]


# --------------------------------------------------------------------------- #
# hosts 的「真·生效」判定
#
# ★ 两个实测踩出来的坑，都在这里修掉了：
#
#   坑 1（计数假阳性）：早期按「行里含 marker 字符串」计数。结果**被 # 注释掉的**
#     行也算数 —— 实测有 3/6 行被注释掉（www./secure./register. 其实没被屏蔽），
#     检查却报成功。现在只认**真正的生效行**：行首不能是 #，且必须是
#     `0.0.0.0 <domain>` 形式。
#
#   坑 2（DNS 缓存让屏蔽失效）：只写 hosts 文件是不够的。实测在 hosts 内容
#     完全正确（6 行、无 BOM、CRLF）的情况下，`ping internetdownloadmanager.com`
#     仍然解析到真实 IP 67.18.60.145 —— 因为 Windows 的 DNS 客户端缓存还留着
#     旧结果，必须 `ipconfig /flushdns` 才真正生效。所以写完和还原后都要刷缓存，
#     而且**验证要用 ping**（`Resolve-DnsName` 会返回 0.0.0.0 造成假通过）。
# --------------------------------------------------------------------------- #

def _active_domains(lines):
    """返回 hosts 里**真正生效**的屏蔽域名集合（排除被 # 注释掉的行）。"""
    active = set()
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        mm = re.match(r"^0\.0\.0\.0\s+([^\s#]+)", s)
        if mm and mm.group(1).lower() in HOSTS_DOMAINS:
            active.add(mm.group(1).lower())
    return active


def hosts_state():
    """返回 (是否全部生效, 生效域名数, 域名总数)。

    ★ 只统计**生效**行，被注释掉的不算（见上面坑 1）。
    """
    try:
        lines = _read_hosts()
    except Exception:
        return False, 0, len(HOSTS_DOMAINS)
    active = _active_domains(lines)
    return len(active) >= len(HOSTS_DOMAINS), len(active), len(HOSTS_DOMAINS)


def flush_dns(quiet=False):
    """刷新 Windows DNS 客户端缓存。

    ★ 不刷缓存的话，hosts 改了也可能不生效（实测：文件正确但 ping 仍解析到真实 IP）。
      只应在**确实改动了 hosts** 之后调用 —— 这是个系统级动作。
    """
    rc, out = _run(["ipconfig", "/flushdns"], timeout=60)
    if not quiet:
        log("  DNS 缓存：%s" % ("已刷新" if rc == 0 else "刷新失败(exit %d)" % rc))
    return rc == 0


# 真实服务器网段特征：判定「没被屏蔽」用
_REAL_IP_RE = re.compile(r"67\.18\.")


def probe_domain(domain, timeout_ms=800):
    """用 **ping** 探测一个域名当前解析到哪儿。返回 (状态, 说明)。

    状态 ∈ {"blocked", "resolved_real", "no_resolve", "unknown"}。
    ★ 为什么不用 Resolve-DnsName / getaddrinfo：实测它们会读 hosts 并返回 0.0.0.0，
      给出**假通过**。ping 反映的是真实可用性，更接近「屏蔽到底有没有生效」。
    """
    rc, out = _run(["ping", "-n", "1", "-w", str(timeout_ms), domain],
                   timeout=15)
    if _REAL_IP_RE.search(out):
        return "resolved_real", "仍解析到真实服务器网段（未生效）"
    if rc == 0:
        return "blocked", "已不可达（0.0.0.0）"
    low = out.lower()
    if "could not find host" in low or "找不到主机" in out or "transmit failed" in low \
            or "无法解析" in out:
        return "blocked", "无法解析/不可达"
    if "unreachable" in low or "超时" in out or "timed out" in low:
        return "blocked", "不可达（超时/目标不可达）"
    return "unknown", "无法判定（ping 输出无法识别）"


def probe_hosts_block(quiet=False):
    """探测屏蔽是否真的生效。返回 (结果列表, 生效数, 总数)。

    这是**尽力而为**的检查：依赖本机网络与 DNS 状态，不参与成败判定，
    只作为给用户看的证据（避免「只看文件内容就宣称已屏蔽」）。
    """
    results = []
    for d in HOSTS_DOMAINS:
        st, det = probe_domain(d)
        results.append((d, st, det))
    n_ok = sum(1 for _, st, _ in results if st == "blocked")
    if not quiet:
        log("  DNS 探测：%d/%d 个域名已不可达" % (n_ok, len(HOSTS_DOMAINS)))
    return results, n_ok, len(HOSTS_DOMAINS)


def _hosts_acl_unlock():
    """解除 hosts 上的 DENY(WD)。

    ★ 为什么需要：IDM 会**主动把针对 internetdownloadmanager.com 的 hosts 屏蔽行注释掉**
      （官方 .lng 原文："IDM will repair this file now"）。实测 2026-10-17：手动取消
      注释后，IDM 启动几秒内又把 www./secure./register./update./support./idm. 六行
      全部重新加 `#` 前缀，而 tonec.com 的两行不动 —— 说明是定向修复。
      因此 hosts 必须加 DENY(WD) 保护；但加了之后自己写不进去，所以写前先解、写后加回。
    """
    try:
        subprocess.run(["icacls", HOSTS_PATH, "/remove:d", "Everyone"],
                       capture_output=True, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def _hosts_acl_lock():
    """给 hosts 加 DENY(WD)，阻止 IDM 再改它（幂等）。"""
    try:
        subprocess.run(["icacls", HOSTS_PATH, "/deny", "Everyone:(WD)"],
                       capture_output=True, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def apply_hosts(quiet=False):
    """写 hosts 屏蔽块 + 刷 DNS 缓存（幂等）。返回 (ok, 说明)。

    ok 以**生效行数**为准，不以「写过文件」为准。
    """
    try:
        lines = _read_hosts()
    except Exception as exc:
        return False, "读取 hosts 失败：%s" % exc
    kept = [l for l in lines if HOSTS_MARKER not in l]
    # 备份原始 hosts：只在「备份不存在」且「当前 hosts 还是干净的」时候备份，
    # 否则会把已经带 marker 的内容当成「原始」备份下来（见 _hosts_has_marker 的说明）。
    if _hosts_has_marker(HOSTS_BACKUP) is None and not _hosts_has_marker(HOSTS_PATH):
        try:
            shutil.copy2(HOSTS_PATH, HOSTS_BACKUP)
        except Exception as exc:
            log("  [警告] hosts 备份失败：%s" % exc)
    try:
        _hosts_acl_unlock()
        _write_hosts(kept + hosts_block_lines())
    except Exception as exc:
        return False, "写入 hosts 失败：%s" % exc
    finally:
        _hosts_acl_lock()
    # ★ 写完必须刷 DNS 缓存，否则屏蔽可能完全不生效
    flush_dns(quiet=quiet)
    ok, n, want = hosts_state()
    if not quiet:
        log("  hosts 生效行：%d/%d" % (n, want))
    if not ok:
        return False, "hosts 只写入了 %d/%d 个生效域名（可能被注释掉了）" % (n, want)
    return True, "已屏蔽 %d/%d 个域名（生效行）" % (n, want)


def restore_hosts(quiet=False):
    """还原 hosts + 刷 DNS 缓存。返回 (ok, 说明)。

    优先级：
      1. 备份存在**且不含 marker** -> 用备份还原（最干净）；
      2. 否则把当前 hosts 里的 marker 行删掉（备份被污染时的兜底）。
    绝不允许出现「日志说还原了、屏蔽其实还在」的静默失败。
    ★ 还原后也要刷缓存：否则缓存里的 0.0.0.0 会让屏蔽「死而不僵」。
    """
    bak_dirty = _hosts_has_marker(HOSTS_BACKUP)
    _hosts_acl_unlock()          # 先解 DENY，否则还原写不进去
    try:
        return _restore_hosts_inner(bak_dirty, quiet)
    finally:
        _hosts_acl_lock()        # 还原完再加回保护


def _restore_hosts_inner(bak_dirty, quiet):
    if bak_dirty is False:                      # 备份存在且干净
        try:
            shutil.copy2(HOSTS_BACKUP, HOSTS_PATH)
            flush_dns(quiet=quiet)
            if not quiet:
                log("  已从备份还原 hosts：%s" % HOSTS_BACKUP)
            return True, "已从 %s 还原（并已刷 DNS 缓存）" % os.path.basename(HOSTS_BACKUP)
        except Exception as exc:
            log("  [警告] 从备份还原 hosts 失败（改用删行方式）：%s" % exc)
    elif bak_dirty is True and not quiet:
        log("  [提示] 备份 %s 本身含有屏蔽块（是屏蔽生效后才备份的），"
            "改用删行方式还原" % os.path.basename(HOSTS_BACKUP))

    try:
        lines = _read_hosts()
    except Exception as exc:
        return False, "读取 hosts 失败：%s" % exc
    kept = [l for l in lines if HOSTS_MARKER not in l]
    if len(kept) == len(lines):
        return True, "hosts 本来就没有屏蔽块"
    try:
        _write_hosts(kept)
    except Exception as exc:
        return False, "写入 hosts 失败：%s" % exc
    flush_dns(quiet=quiet)
    if not quiet:
        log("  已删除 hosts 屏蔽块（%d 行）" % (len(lines) - len(kept)))
    # 用删行方式还原成功的话，那个被污染的备份已经没有价值，顺手删掉
    if bak_dirty is True:
        try:
            os.remove(HOSTS_BACKUP)
        except Exception:
            pass
    return True, "已删除 %d 行屏蔽块（并已刷 DNS 缓存）" % (len(lines) - len(kept))


# --------------------------------------------------------------------------- #
# 层 C 第三层：防火墙出站阻断 —— 挡住 IDM 直连授权/更新服务器
#
# ★ 为什么 hosts 不够（实测 + 官方自述）：
#   1. IDM 自带的 Languages\*.lng 里明确写着
#        "IDM will check for updates successfully even with your damaged hosts file"
#      —— hosts 只挡浏览器，挡不住 IDMan.exe 自己。
#   2. 实测：hosts 6/6 全绿时，www./secure./register.internetdownloadmanager.com
#      仍解析到 67.18.60.145 / 67.18.140.140，ping 可达。
#   3. 后果：联网校验判定主程序被修改 → 弹 "IDM is corrupt / 主程序已损坏"
#      （文案前半句 "The main IDM executive file is damaged." 就内嵌在
#       IDMan.exe 的 .data 里，XOR 0x3D 编码）。
#
# ★ 为什么只挡 IP 段、不整体断网：
#   IDM 的本职是下载，整体断网等于废掉它。67.18.0.0/16 是 IDM/tonec 的服务器段
#   （67.18.60.145 / 67.18.140.140 都在内），与用户下载的目标站点无关。
# --------------------------------------------------------------------------- #
FW_RULE = "FuckIDM-Block-AuthServers"
FW_REMOTE = "67.18.0.0/16"


def _netsh(args, timeout=25):
    """跑一条 netsh 命令，返回 (rc, 输出文本)。输出按 mbcs 解码（中文系统是 GBK）。"""
    try:
        p = subprocess.run(["netsh"] + list(args), capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("mbcs", "replace") + (p.stderr or b"").decode("mbcs", "replace")
        return p.returncode, out
    except Exception as exc:
        return -1, str(exc)


def firewall_state():
    """返回 (state, detail)。state ∈ {"block", "none", "unknown"}。

    ⚠️ 非管理员下 `netsh advfirewall show rule` 直接返回
       "The requested operation requires elevation" 且 rc=1。
       此时**不能**断言「没有规则」—— 必须返回 unknown，否则 --status 会误报。
    """
    rc, out = _netsh(["advfirewall", "firewall", "show", "rule", "name=%s" % FW_RULE])
    if rc != 0:
        low = out.lower()
        if ("requires elevation" in low or "需要提升" in out or "拒绝访问" in out
                or "access is denied" in low):
            return "unknown", "查询需要管理员权限（--status 以普通权限运行）"
        return "none", "未找到规则 %s" % FW_RULE
    if FW_RULE not in out:
        return "none", "未找到规则 %s" % FW_RULE
    enabled = re.search(r"Enabled:\s*Yes", out) is not None
    m = re.search(r"Action:\s*(\w+)", out)
    act = m.group(1) if m else "?"
    if enabled and act.lower() == "block":
        return "block", "出站阻断 -> %s" % FW_REMOTE
    return "unknown", "规则存在但未生效（Enabled=%s Action=%s）" % (enabled, act)


def apply_firewall_block(install_dir, quiet=False):
    """加/刷新出站阻断规则（幂等）。返回 (ok, 说明)。"""
    exe = os.path.join(install_dir, "IDMan.exe")
    if not os.path.isfile(exe):
        return False, "找不到 %s，跳过防火墙规则" % exe
    remove_firewall_block(quiet=True)                     # 幂等：先删再加
    rc, out = _netsh([
        "advfirewall", "firewall", "add", "rule",
        "name=%s" % FW_RULE,
        "dir=out", "action=block",
        "program=%s" % exe,
        "remoteip=%s" % FW_REMOTE,
        "enable=yes", "profile=any",
        "description=Block IDM auth/update servers (hosts cannot stop IDMan.exe itself)",
    ])
    st, det = firewall_state()
    if st == "block":
        if not quiet:
            log("  防火墙：已阻断 IDMan.exe -> %s（hosts 挡不住的那部分由这层兜底）" % FW_REMOTE)
        return True, det
    return False, "防火墙规则未生效：%s" % ((out.strip()[:200]) or det)


def remove_firewall_block(quiet=False):
    """删除出站阻断规则（幂等）。"""
    rc, out = _netsh(["advfirewall", "firewall", "delete", "rule", "name=%s" % FW_RULE])
    if not quiet:
        if rc == 0:
            log("  防火墙：已移除规则 %s" % FW_RULE)
        else:
            log("  防火墙：本来就没有规则 %s（无需移除）" % FW_RULE)
    return True, "已移除（或本来不存在）"


# --------------------------------------------------------------------------- #
# 层 C 第四层：清掉 IDM 已下载的更新包
#
# ★ 为什么：IDM 会把待安装的更新包下载到 %APPDATA%\IDM\idmupdt.exe（约 12.5 MB），
#   并在**后台反复读取它**做版本/完整性比对。实测（2026-10-17）：
#     · 该文件 created 2026-10-16 23:02、modified 23:03（当时 hosts 只挡 3/6，能联网）
#     · IDM 每次启动后数秒内就会 access 它（atime 15:51:56，紧跟重启时刻）
#     · 它与被修改的 IDMan.exe 一起构成 "IDM is corrupt" 弹窗的判定输入
#   ⇒ 删掉它（改名保留备份）即可去掉这一路输入，且**不影响任何已完成的下载**。
# --------------------------------------------------------------------------- #
UPDATE_PKG = os.path.join(os.environ.get("APPDATA", ""), "IDM", "idmupdt.exe")
UPDATE_PKG_BAK = UPDATE_PKG + ".bak-fuckidm"


def update_package_state():
    """返回 (state, detail)。state ∈ {"present", "absent", "backup"}。"""
    if os.path.isfile(UPDATE_PKG):
        try:
            sz = os.path.getsize(UPDATE_PKG)
        except Exception:
            sz = -1
        return "present", "存在（%s B）—— IDM 会后台读取它做校验" % sz
    if os.path.isfile(UPDATE_PKG_BAK):
        return "backup", "已清理（备份：%s）" % os.path.basename(UPDATE_PKG_BAK)
    return "absent", "不存在"


def cleanup_update_package(quiet=False):
    """把 idmupdt.exe 改名成 .bak-fuckidm（幂等，可回滚）。返回 (ok, 说明)。"""
    if not os.path.isfile(UPDATE_PKG):
        st, det = update_package_state()
        if not quiet:
            log("  更新包：%s" % det)
        return True, det
    # 需要 IDM 不持有句柄 —— 调用方（--activate）此前已停止 IDM 进程
    try:
        if os.path.isfile(UPDATE_PKG_BAK):
            os.remove(UPDATE_PKG_BAK)
        os.replace(UPDATE_PKG, UPDATE_PKG_BAK)
        if not quiet:
            log("  更新包：已隔离 %s -> %s" % (os.path.basename(UPDATE_PKG),
                                               os.path.basename(UPDATE_PKG_BAK)))
        return True, "已隔离（备份 %s）" % os.path.basename(UPDATE_PKG_BAK)
    except Exception as exc:
        return False, "隔离更新包失败：%s（先完全退出 IDM 再试）" % exc


def restore_update_package(quiet=False):
    """把 idmupdt.exe 还原回来（幂等）。"""
    if not os.path.isfile(UPDATE_PKG_BAK):
        if not quiet:
            log("  更新包：没有备份，无需还原")
        return True, "没有备份"
    try:
        if os.path.isfile(UPDATE_PKG):
            os.remove(UPDATE_PKG)
        os.replace(UPDATE_PKG_BAK, UPDATE_PKG)
        if not quiet:
            log("  更新包：已还原 %s" % os.path.basename(UPDATE_PKG))
        return True, "已还原"
    except Exception as exc:
        return False, "还原更新包失败：%s" % exc


# --------------------------------------------------------------------------- #
# 层 C 第五层：停用 IDM 的内核文件系统驱动 `idmwfp`（★ 改 hosts 的真正元凶）
#
# ★ 根因（2026-10-17 实测确认）：
#   `sc query idmwfp` 显示 **TYPE = 2 (FILE_SYSTEM_DRIVER)**、AUTO_START、依赖 BFE。
#   它挂在文件系统栈上，**在 ACL 检查之前/之后都能直接操作文件** ——
#   所以 hosts 加 `Everyone:(DENY)(DE,WD)` 也挡不住它。
#   实测时间线（同一天六次观测）：
#     16:00:18 手动取消注释 -> hosts 11 行
#     16:00:39 IDM 启动（/onboot）
#     16:00:40 hosts 6 行被重新注释
#     16:02:04 加 DENY(DE,WD) 再修 -> 11 行
#     16:02:15 IDM 重启
#     16:02:18 又是 6 行被注释      ← ACL 完全无效
#     16:38:34 sc stop idmwfp + config disabled -> 修 hosts 11 行
#     16:38:40 IDM 启动
#     16:41:38 起连续 120s 观测：hosts 恒为 11 行、mtime 不变  ← ★ 元凶确认
#
# ⚠️ 代价：IDM 的「高级浏览器集成」（注册表 AdvIntDriverEnabled2=1）会失效 ——
#   浏览器里点下载不再自动接管。手动「添加任务」/ 拖链接 / 剪贴板监听**不受影响**。
#   要恢复：`--uninstall` 会 `sc config idmwfp start= auto` 并还原安装目录里的 .sys 副本。
# --------------------------------------------------------------------------- #
WFP_SERVICE = "idmwfp"


def _sc(args, timeout=20):
    """跑一条 sc 命令，返回 (rc, 输出文本)。"""
    try:
        p = subprocess.run(["sc"] + list(args), capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("mbcs", "replace") + (p.stderr or b"").decode("mbcs", "replace")
        return p.returncode, out
    except Exception as exc:
        return -1, str(exc)


def wfp_driver_state():
    """返回 (state, detail)。state ∈ {"running", "disabled", "stopped", "absent", "unknown"}。"""
    rc, out = _sc(["query", WFP_SERVICE])
    if rc != 0:
        return "absent", "驱动服务 %s 不存在（可能已卸载或从未安装）" % WFP_SERVICE
    m = re.search(r"STATE\s*:\s*(\d)", out)
    st = m.group(1) if m else "?"
    rc2, out2 = _sc(["qc", WFP_SERVICE])
    m2 = re.search(r"START_TYPE\s*:\s*(\d)", out2)
    start = m2.group(1) if m2 else "?"
    names = {"1": "STOPPED", "2": "START_PENDING", "3": "STOP_PENDING", "4": "RUNNING"}
    starts = {"0": "BOOT", "1": "SYSTEM", "2": "AUTO", "3": "DEMAND", "4": "DISABLED"}
    detail = "STATE=%s START_TYPE=%s" % (names.get(st, st), starts.get(start, start))
    if start == "4" and st != "4":
        return "disabled", detail
    if st == "4":
        return "running", detail
    return "stopped", detail


def disable_wfp_driver(install_dir=None, quiet=False):
    """停用 + 禁用 idmwfp 驱动，并把安装目录里的 .sys 副本改名（幂等）。

    返回 (ok, 说明)。这是**修好 hosts 被反复拆掉**的关键一步。
    """
    notes = []
    # 1) 停止（已在停就跳过）
    rc, out = _sc(["stop", WFP_SERVICE])
    if rc == 0:
        notes.append("已停止")
    elif "1062" in out or "尚未启动" in out or "not been started" in out.lower():
        notes.append("本来就是停止状态")
    else:
        notes.append("停止返回 rc=%s" % rc)
    time.sleep(1)
    # 2) 设为 disabled（开机不加载）
    rc2, out2 = _sc(["config", WFP_SERVICE, "start=", "disabled"])
    notes.append("设为 DISABLED" if rc2 == 0 else "config 失败 rc=%s" % rc2)
    # 3) 安装目录里的驱动副本改名（防止 IDM 重新装回来）
    renamed = 0
    if install_dir and os.path.isdir(install_dir):
        for fn in os.listdir(install_dir):
            if fn.lower().startswith(("idmwfp", "idmtdi")) and fn.lower().endswith(".sys"):
                src = os.path.join(install_dir, fn)
                try:
                    if not os.path.exists(src + ".disabled-fuckidm"):
                        os.replace(src, src + ".disabled-fuckidm")
                        renamed += 1
                except Exception:
                    pass
    if renamed:
        notes.append("安装目录驱动副本改名 %d 个" % renamed)
    st, det = wfp_driver_state()
    if not quiet:
        log("  驱动 idmwfp：%s（%s）" % (st, det))
        log("  ⚠️ 代价：IDM 的「高级浏览器集成」会失效；手动添加任务/拖链接不受影响")
    if st in ("disabled", "stopped", "absent"):
        # 收尾自证：手动 sc start 必须失败（证明内核特权真的移除了）
        rc3, out3 = _sc(["start", WFP_SERVICE])
        if rc3 == 0:
            # 居然起来了 —— 说明 DISABLED 没生效，回滚为失败
            _sc(["stop", WFP_SERVICE])
            return False, "驱动仍可被启动（DISABLED 未生效）：%s" % out3.strip()[:120]
        notes.append("sc start 已被拒绝（内核特权移除）")
        return True, "；".join(notes) + "（当前 %s）" % det
    return False, "驱动仍未停用（%s）" % det


def restore_wfp_driver(install_dir=None, quiet=False):
    """把 idmwfp 恢复成 AUTO_START，并还原安装目录里的 .sys 副本（幂等）。"""
    renamed_back = 0
    if install_dir and os.path.isdir(install_dir):
        for fn in os.listdir(install_dir):
            if fn.lower().endswith(".sys.disabled-fuckidm"):
                src = os.path.join(install_dir, fn)
                dst = src[: -len(".disabled-fuckidm")]
                try:
                    os.replace(src, dst)
                    renamed_back += 1
                except Exception:
                    pass
    rc, out = _sc(["config", WFP_SERVICE, "start=", "auto"])
    if not quiet:
        log("  驱动 idmwfp：已恢复 AUTO_START（rc=%s）%s"
            % (rc, "，还原 .sys 副本 %d 个" % renamed_back if renamed_back else ""))
    return True, "已恢复（下次开机加载；需要立即生效请重启）"


# --------------------------------------------------------------------------- #
# 文件不可变（DENY ACE）—— 替代守护的关键一步
# --------------------------------------------------------------------------- #

_SID_EVERYONE = "*S-1-1-0"


def _volume_is_ntfs(path):
    """ACL 只有在 NTFS 上才有意义；FAT/exFAT 上 icacls 会直接失败。

    用 GetVolumeInformationW 取文件系统名（icacls 的输出是本地化的，不可靠）。
    """
    try:
        drive = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
        fsname = ctypes.create_unicode_buffer(261)
        k32 = ctypes.windll.kernel32
        ok = k32.GetVolumeInformationW(ctypes.c_wchar_p(drive), None, 0, None, None,
                                       None, fsname, 261)
        return bool(ok) and fsname.value.upper() == "NTFS"
    except Exception:
        return False


def _sid_string(sid_ptr):
    """把 PSID 转成字符串形式（S-1-1-0 / S-1-5-32-544 ...）。失败返回 None。"""
    try:
        adv = ctypes.windll.advapi32
        s = ctypes.c_wchar_p()
        if not adv.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr), ctypes.byref(s)):
            return None
        return s.value
    except Exception:
        return None


def _everyone_identifiers():
    """返回 icacls 输出里可能用来表示 `Everyone`(S-1-1-0) 的所有写法。

    ★ 这里踩过一次坑，必须说清楚：`icacls <file>` **回读时不会打印 S-1-1-0**，
      而是把 SID 解析成账户名 —— 实测输出是 `Everyone:(DENY)(DE,WD)`。
      只匹配 SID 字符串的写法会导致「明明加上了，回读却看不到」，
      于是 apply_immutable 误报失败。所以这里动态查一次真实名字，
      并且始终保留 SID 字符串本身作为兜底（两种写法都能命中）。
    """
    out = {_SID_EVERYONE.strip("*").upper(), "EVERYONE"}
    try:
        adv = ctypes.windll.advapi32
        cb = ctypes.c_ulong(0)
        # 第一趟只问长度（官方用法）；失败也无所谓，后面用固定大小缓冲再试
        adv.LookupAccountNameW(None, ctypes.c_wchar_p("Everyone"), None,
                               ctypes.byref(cb), None, ctypes.byref(cb))
        sid = ctypes.create_string_buffer(max(cb.value, 64))
        cch_dom, use = ctypes.c_ulong(256), ctypes.c_ulong(0)
        dom = ctypes.create_unicode_buffer(256)
        if adv.LookupAccountNameW(None, ctypes.c_wchar_p("Everyone"), sid,
                                  ctypes.byref(cb), dom, ctypes.byref(cch_dom),
                                  ctypes.byref(use)):
            s = _sid_string(ctypes.addressof(sid))
            if s:
                out.add(s.upper())
    except Exception:
        pass
    return out


def _parse_acl(rc, out):
    """从 icacls 输出解析出针对 Everyone 的 DENY 条目。

    icacls 输出形如（账户名与分隔符都是本地化的）：
        IDMan.exe Everyone:(DENY)(DE,WD)
    判定：同一行里既有 Everyone 的某种写法（SID 或账户名），又有 `(DENY)`。
    """
    if rc != 0:
        return None
    idents = _everyone_identifiers()
    hits = []
    for line in out.splitlines():
        up = line.upper()
        if not re.search(r"\(DENY\)", up):
            continue
        if any(i and i in up for i in idents):
            hits.append(line.strip())
    return hits


def acl_state(exe):
    """返回 (状态, 说明, 明细)。

    状态 ∈ {"deny"(已不可变), "none"(未加锁), "unsupported", "unknown"}
    """
    if not os.path.isfile(exe):
        return "unsupported", "文件不存在", []
    if not _volume_is_ntfs(exe):
        return "unsupported", "文件系统不是 NTFS，ACL 不可用", []
    rc, out = _run(["icacls", exe], timeout=30)
    hits = _parse_acl(rc, out)
    if hits is None:
        return "unknown", "icacls 读取失败（exit %d）" % rc, []
    if hits:
        return "deny", "已设置 DENY ACE（文件不可变）", hits
    return "none", "未设置 DENY ACE", []


def apply_immutable(exe, quiet=False):
    """给 IDMan.exe 加 DENY(WD,DE) —— 官方更新包无法覆盖/删除这个文件。

    ★ 这一步放在**补丁之后**：先写完补丁再加锁。
      （管理员对 DENY 有绕过权，理论上不会挡写，但不能靠这个假设。）
    """
    if not _volume_is_ntfs(exe):
        return "unsupported", "文件系统不是 NTFS，跳过不可变设置", []
    # 先移除旧的（避免重复叠加 ACE），再加
    _run(["icacls", exe, "/remove:d", _SID_EVERYONE], timeout=30)
    rc, out = _run(["icacls", exe, "/deny", "%s:(WD,DE)" % _SID_EVERYONE], timeout=30)
    if rc != 0:
        return "error", "icacls /deny 失败（exit %d）：%s" % (rc, out.strip()[:200]), []
    st, detail, hits = acl_state(exe)
    if st != "deny":
        return "error", "icacls 报告成功但回读没有看到 DENY ACE（%s）" % detail, []
    if not quiet:
        log("  已设置文件不可变：%s" % "; ".join(hits))
    return "deny", detail, hits


def remove_immutable(exe, quiet=False):
    """移除 DENY ACE。幂等：本来没有也算成功，而且不会谎报「已移除」。"""
    if not os.path.isfile(exe):
        return "skipped", "文件不存在", []
    if not _volume_is_ntfs(exe):
        return "skipped", "文件系统不是 NTFS", []
    had = acl_state(exe)[0] == "deny"
    if not had:
        return "ok", "本来就没有 DENY ACE（无需移除）", []
    rc, _ = _run(["icacls", exe, "/remove:d", _SID_EVERYONE], timeout=30)
    st, detail, hits = acl_state(exe)
    if st == "deny":
        return "error", "仍然存在 DENY ACE（icacls exit %d）：%s" % (rc, "; ".join(hits)), hits
    if not quiet:
        log("  已移除文件不可变（DENY ACE）")
    return "ok", "已移除 DENY ACE", []


# --------------------------------------------------------------------------- #
# 旧守护清理（只删不装）
#
# ★ 为什么不能只按两个已知任务名删：
#   `IDM-Activator-Guard-Logon` 是「登录时触发」的任务（RunLevel=Highest），
#   它会拉起 `dist\IDM-Activator.exe --guard`。只要它还活着，下次登录就会把守护
#   重新装回来，「无守护」就是假的。而且将来完全可能出现第三个任务名。
#   所以这里做**两层**：已知名字 + 全表扫描「动作里引用 IDM-Activator 的任务」。
# --------------------------------------------------------------------------- #

def _norm_task_name(n):
    """schtasks 返回的任务名可能带前导反斜杠，统一成不带的形式。"""
    return (n or "").strip().lstrip("\\")


def find_guard_tasks():
    """扫 schtasks 全表，返回所有「动作里引用本工具」的任务名列表（去重、排序）。

    用 `schtasks /query /fo CSV /v` 拿全量字段（含 "Task To Run"），
    用 csv 模块解析（任务名/路径里可能有逗号）。
    编码：中文系统下输出是 GBK，所以按字节收再解 —— 绝不让编码问题把清理打断。
    """
    rc, out = _run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=120)
    if rc != 0:
        return []
    try:
        import csv as _csv, io
        rows = list(_csv.DictReader(io.StringIO(out)))
    except Exception:
        return []
    found = set()
    for row in rows:
        tname = _norm_task_name(row.get("TaskName"))
        if not tname:
            continue
        action = (row.get("Task To Run") or "").lower()
        if not action:
            continue
        if any(mk in action for mk in LEGACY_ACTION_MARKERS):
            found.add(tname)
    return sorted(found)


def legacy_tasks():
    """返回当前存在的旧守护计划任务名（已知名字 ∪ 全表扫描结果）。"""
    out = set()
    for tn in LEGACY_TASKS + LEGACY_TASKS_EXTRA:
        rc, _ = _run(["schtasks", "/Query", "/TN", tn], timeout=30)
        if rc == 0:
            out.add(tn)
    out.update(find_guard_tasks())
    return sorted(out)


def remove_legacy_tasks(quiet=False):
    """删除所有残留守护计划任务（幂等）。返回 [(任务名, 是否删掉了)]。"""
    out = []
    for tn in legacy_tasks():
        rc, _ = _run(["schtasks", "/Delete", "/TN", tn, "/F"], timeout=60)
        out.append((tn, rc == 0))
        if rc == 0 and not quiet:
            log("  已删除计划任务：%s" % tn)
        elif rc != 0 and not quiet:
            log("  [警告] 删除计划任务失败：%s" % tn)
    return out


def _run_key_targets():
    """返回需要检查的 Run 键：(hive, 子键, 视图, 显示名)。"""
    import winreg
    return [
        (winreg.HKEY_CURRENT_USER, RUN_KEY_SUB, 64, "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER, RUN_KEY_SUB_WOW, 64, "HKCU\\WOW6432Node\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, RUN_KEY_SUB, 64, "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, RUN_KEY_SUB_WOW, 64, "HKLM\\WOW6432Node\\Run"),
    ]


def legacy_run_entries():
    """列出 Run 键里引用本工具的残留自启项。

    按**值内容**判断（也兼顾键名）：旧 lockdown 脚本的键名不一定带关键词。
    返回 [(显示位置, 键名, 值)]。
    """
    import winreg
    found = []
    for hive, sub, view, label in _run_key_targets():
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | _reg_flag(view)) as k:
                i = 0
                while True:
                    try:
                        nm, val, _ = winreg.EnumValue(k, i)
                        i += 1
                    except OSError:
                        break
                    low = ("%s %s" % (nm, val)).lower()
                    if any(mk in low for mk in LEGACY_ACTION_MARKERS):
                        found.append((label, nm, val))
        except Exception:
            continue
    return found


def remove_legacy_run_entries(quiet=False):
    """删除残留自启项（幂等）。返回 [(显示位置, 键名, 是否删掉了)]。"""
    import winreg
    out = []
    for label, nm, _ in legacy_run_entries():
        hive, sub, view = None, None, None
        for h, s, v, lb in _run_key_targets():
            if lb == label:
                hive, sub, view = h, s, v
                break
        if hive is None:
            continue
        try:
            with winreg.OpenKey(hive, sub, 0,
                                winreg.KEY_SET_VALUE | _reg_flag(view)) as k:
                winreg.DeleteValue(k, nm)
            out.append((label, nm, True))
            if not quiet:
                log("  已删除自启项：%s\\%s" % (label, nm))
        except Exception as exc:
            out.append((label, nm, False))
            if not quiet:
                log("  [警告] 删除自启项失败 %s\\%s：%s" % (label, nm, exc))
    return out


def cleanup_legacy(quiet=False):
    """清掉所有旧守护痕迹。返回 (删掉的任务列表, 删掉的自启项列表)。"""
    tasks = [t for t, ok in remove_legacy_tasks(quiet=quiet) if ok]
    runs = ["%s\\%s" % (lb, nm) for lb, nm, ok in remove_legacy_run_entries(quiet=quiet) if ok]
    return tasks, runs


def guard_state():
    """状态查询：返回 (残留任务列表, 残留自启项列表)。

    自启项用「位置\\键名」形式返回，方便用户直接定位。
    """
    return legacy_tasks(), ["%s\\%s" % (lb, nm) for lb, nm, _ in legacy_run_entries()]


# --------------------------------------------------------------------------- #
# 补丁点枚举（--status / --scan 共用）
# --------------------------------------------------------------------------- #

_STATE_CN = {"already": "已到位", "ready": "未施加", "mismatch": "字节不符"}


def hash_verdict(h):
    """按哈希给出**提示性**识别：返回 (状态, 说明)。

    状态 ∈ {"original", "patched_hint", "unknown"}。
    ⚠️ 这只是提示，不是成败判定 —— 判定请用 verify_patched()。
    """
    if h in KNOWN_ORIGINALS:
        return "original", KNOWN_ORIGINALS[h]
    if h in KNOWN_PATCHED_HINT:
        return "patched_hint", KNOWN_PATCHED_HINT[h]
    return "unknown", "未知哈希（不是已知原版；补丁是否完整请看下面的校验）"


def verify_patched(exe, quiet=False):
    """**自证式**校验补丁是否完整。返回 (状态, 说明, 期望哈希)。

    为什么不能用硬编码哈希：
      引擎一升级（例如加进 P5/P6），同一个原版打完的哈希就变了，硬编码常量会立刻
      误报「补丁不完整」。实测：b15 原版 279ceed9… 打完 P1..P6 = cb2a3e6b…，
      而文档里记的 4b089abb… 是 P1..P4 时代的旧值。

    做法（不需要联网、不需要已知常量）：
      1. 取备份 `IDMan.exe.bak-original`（= 未打补丁的原版）；
      2. 在临时目录里复制一份，用**同一个引擎**跑一遍 apply_all；
      3. 得到「本机原版 + 本版引擎」应有的补丁后哈希；
      4. 与实际文件哈希比对：相等 => 补丁确实全了。

    状态 ∈ {"ok", "mismatch", "no_backup", "original", "error"}。
    """
    try:
        actual = sha256_file(exe)
    except Exception as exc:
        return "error", "无法读取实际文件哈希：%s" % exc, None
    bak = exe + BACKUP_SUFFIX
    if not os.path.isfile(bak):
        if actual in KNOWN_ORIGINALS:
            return "original", "这是未打补丁的原版（且没有备份可用来校验）", None
        return "no_backup", "没有备份文件，无法自证补丁完整性（只能看哈希提示）", None

    # 与备份完全一致 => 就是原版（--uninstall 还原后就是这个状态），直接判定
    try:
        if actual == sha256_file(bak):
            return "original", "这是未打补丁的原版（与备份一致）", None
    except Exception:
        pass

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="idm-activator-verify-")
    tmp = os.path.join(tmpdir, EXE_NAME)
    try:
        shutil.copy2(bak, tmp)
        st, detail, _ = eng.apply_all(tmp)
        if st in ("error", "mismatch"):
            return "error", "参考副本打补丁失败（%s）：%s" % (st, detail), None
        expect = sha256_file(tmp)
    except Exception as exc:
        return "error", "自证校验异常：%s" % exc, None
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    if actual == expect:
        return "ok", "补丁完整（10/10，已用备份自证：期望哈希 %s）" % expect[:16], expect
    if actual in KNOWN_ORIGINALS:
        return "original", "这是未打补丁的原版", expect
    return "mismatch", ("补丁不完整或文件被改动过：实际 %s ≠ 期望 %s"
                        % (actual[:16], expect[:16])), expect


def patch_state(exe):
    """返回 (sites, [(key, offset, 状态, 标题)], 统计)。

    状态来自 idm_engine.Site.check()：already / ready / mismatch。
    ★ 注意：idm_engine 的 find_* 以**原始字节**为锚点，所以这个表在**已打补丁**
      的文件上只会返回能找到的那几个点（实测全补丁 b15 上只剩 3 个）。
      判断补丁是否完整必须用哈希（见 hash_verdict）。
    """
    pe = eng.PE(exe)
    sites, _ = eng.build_all_sites(pe)
    rows = [(s.key, s.offset, s.check(pe), s.title) for s in sites]
    stat = {"already": 0, "ready": 0, "mismatch": 0}
    for _, _, st, _ in rows:
        stat[st] = stat.get(st, 0) + 1
    return sites, rows, stat


# --------------------------------------------------------------------------- #
# 命令：--activate
# --------------------------------------------------------------------------- #

def do_activate(args, install_dir):
    exe = os.path.join(install_dir, EXE_NAME)
    say("=" * 76)
    say(" %s  ——  IDM 一键激活（免守护 / 静态方案）" % APP)
    say("=" * 76)
    say("安装目录 : %s" % install_dir)
    h = sha256_file(exe)
    say("IDMan.exe: %s" % h)
    say("哈希判定 : %s" % hash_verdict(h)[1])
    say("")
    say("本工具不安装任何计划任务、不写任何自启项。")
    say("")

    # 隔离护栏：决定本进程能不能碰系统级状态
    sys_ok, sys_why = system_changes_allowed(args, install_dir)
    say("系统级改动 : %s" % ("允许（%s）" % sys_why if sys_ok else "已禁用（%s）" % sys_why))
    if not sys_ok:
        say("")
        say("!! 注意：本次**只**会修改 %s 下的 IDMan.exe。" % install_dir)
        say("   注册表 / hosts / 计划任务 / 进程 都不会被触碰。")
        say("   要在实机上做真正的激活，请直接双击 EXE（不带 --install-dir）。")
    say("")

    # ---------------- [1/8] 停止 IDM ----------------
    say("[1/8] 停止正在运行的 IDM ...")
    kill_idm(allowed=sys_ok)

    # ---------------- [2/8] 二进制补丁 ----------------
    say("[2/8] 施加二进制补丁 P1..P6（10 个补丁点）...")
    try:
        st, detail, changed = eng.apply_all(exe)
    except Exception as exc:
        st, detail, changed = "error", "补丁引擎异常：%s" % exc, False
    if st == "patched":
        say("  已施加：%s" % detail)
    elif st == "clean":
        say("  引擎报告没有需要改动的补丁点")
    elif st == "mismatch":
        say("  !! %s" % detail)
        say("  （补丁点字节不符 —— IDM 版本可能变了，本工具拒绝盲改）")
    else:
        say("  !! %s" % detail)

    # ★ 关键校验：**自证式**确认补丁真的全了。
    #   为什么不能信引擎的 "clean"：find_* 用原始字节当锚点，在已打补丁的文件上
    #   找不到东西（实测全补丁 b15 只剩 3~6 点），所以它对「半新半旧」的文件会误判。
    #   为什么也不能信硬编码哈希：引擎一升级哈希就变（P1..P4 -> P1..P6 已经变过一次）。
    #   做法：拿备份（原版）在临时目录重跑一遍引擎，自证算出期望哈希再比对。
    vst, vdetail, vexpect = verify_patched(exe)
    patch_ok = (vst == "ok")
    if patch_ok:
        say("  校验通过：%s" % vdetail)
    else:
        say("  !! 补丁完整性校验未通过（%s）：%s" % (vst, vdetail))
        say("     可能原因：IDM 版本不同、之前打过部分补丁、或文件被改动过。")
        say("     建议先 --uninstall 还原官方原版，再重跑一次 --activate。")

    # ---------------- [3/8] 清 counterfeit 残留 ----------------
    say("[3/8] 清除 counterfeit 残留（遍历 CLSID 树找 MData）...")
    md, n_verdict, verdict_hits = [], 0, []
    if sys_ok:
        md = clean_counterfeit()
        if not md:
            say("  无残留（正常）")
        n_verdict, verdict_hits = clear_verdict_cache()
        if not verdict_hits:
            say("  缓存的校验判决：无残留（正常）")
    else:
        say("  已跳过（隔离护栏：不碰实机注册表）")

    # ---------------- [4/8] 注册信息 ----------------
    say("[4/8] 写入注册信息（抑制「注册 IDM」对话框）...")
    serial = args.serial or gen_serial()
    ok, why = check_serial(serial)
    if not ok:
        say("  !! 序列号不合法：%s" % why)
        return 3
    say("  序列号 : %s  (%s)" % (serial, why))
    written = []
    if sys_ok:
        written = write_registration(serial, args.fname, args.lname, args.email)
        for wt in written:
            say("  写入   : %s" % wt)
        if not written:
            say("  !! 一个都没写成功（权限不足？）")
            return 4
        say("  说明   : hosts 已屏蔽注册/校验域名，所以这个序列号不可能被上报；")
        say("           P5 已封死自杀出口、P6 已静音 counterfeit 弹窗，")
        say("           即使 IDM 本地判假也无法退出、无法弹窗。")
    else:
        say("  已跳过（隔离护栏：不写实机 HKLM/HKCU）")

    # ---------------- [5/8] hosts 屏蔽 ----------------
    say("[5/8] 屏蔽注册/校验域名（hosts，域名级抗 IP 漂移）...")
    hok, hmsg = False, "已跳过（隔离护栏：不碰实机 hosts）"
    if sys_ok:
        hok, hmsg = apply_hosts()
        if not hok:
            say("  !! %s" % hmsg)
        else:
            say("  %s" % hmsg)
            say("  备份   : %s" % HOSTS_BACKUP)
            say("  DNS    : 已刷新（不刷缓存的话 hosts 可能不生效）")
    else:
        say("  %s" % hmsg)

    # ---------------- [5.5/8] 防火墙出站阻断 ----------------
    # hosts 只挡浏览器，挡不住 IDMan.exe 自己（官方 .lng 里自己承认了这一点）。
    # 这一层把 IDM 直连授权/更新服务器 IP 段的出站包丢掉，且**不影响正常下载**。
    say("[5.5/8] 防火墙阻断 IDM 授权/更新服务器（67.18.0.0/16，不影响下载）...")
    fok, fmsg = False, "已跳过（隔离护栏：不碰实机防火墙）"
    if sys_ok:
        fok, fmsg = apply_firewall_block(install_dir)
        say("  %s %s" % ("OK  " if fok else "!!  ", fmsg))
    else:
        say("  %s" % fmsg)

    # ---------------- [5.6/8] 隔离 IDM 已下载的更新包 ----------------
    # %APPDATA%\IDM\idmupdt.exe 是 IDM 后台反复读取的待安装更新包；
    # 与被修改的 IDMan.exe 一起构成 "IDM is corrupt" 的判定输入。
    say("[5.6/8] 隔离 IDM 已下载的更新包（idmupdt.exe）...")
    if sys_ok:
        uok, umsg = cleanup_update_package()
        say("  %s %s" % ("OK  " if uok else "!!  ", umsg))
    else:
        say("  已跳过（隔离护栏）")

    # ---------------- [5.7/8] 停用 idmwfp 内核文件系统驱动 ----------------
    # ★ 这是 hosts 被反复拆掉的**真正元凶**：idmwfp 是 TYPE=2 文件系统驱动，
    #   挂在文件系统栈上，ACL(DENY) 对它完全无效。停用后 hosts 才真的保得住。
    say("[5.7/8] 停用 IDM 内核文件系统驱动 idmwfp（改 hosts 的元凶）...")
    if sys_ok:
        wok, wmsg = disable_wfp_driver(install_dir)
        say("  %s %s" % ("OK  " if wok else "!!  ", wmsg))
    else:
        say("  已跳过（隔离护栏）")

    # ---------------- [6/8] 文件不可变 ----------------
    say("[6/8] 设置 IDMan.exe 不可变（替代守护：官方更新包无法覆盖补丁）...")
    if not sys_ok:
        say("  已跳过（隔离护栏：非实机目标，不写文件 ACL）")
    elif args.no_lock:
        say("  已跳过（--no-lock）")
    else:
        lst, lmsg, lhits = apply_immutable(exe)
        if lst == "deny":
            say("  已设置：icacls /deny %s:(WD,DE)" % _SID_EVERYONE)
            for hh in lhits:
                say("    回读 : %s" % hh)
        else:
            say("  !! %s" % lmsg)
            say("  （不可变没设上，IDM 自动更新可能覆盖补丁；其余各层仍然有效）")

    # ---------------- [7/8] 移除旧守护 ----------------
    say("[7/8] 移除旧守护（计划任务 + 自启项）...")
    if sys_ok:
        tasks, runs = cleanup_legacy()
        if not tasks and not runs:
            say("  没有发现旧守护痕迹（正常）")
    else:
        say("  已跳过（隔离护栏：不碰实机计划任务/自启项）")
    say("  本工具不会安装任何计划任务或自启项。")

    # ---------------- [8/8] 汇总 ----------------
    say("")
    say("[8/8] 结果汇总")
    say("-" * 76)
    say("二进制补丁   : %s" % ("全部 10 点已到位（已自证）" if patch_ok
                               else "!! 未通过完整性校验，请复核"))
    say("补丁后哈希   : %s" % sha256_file(exe))
    say("counterfeit  : %s" % ("!! 仍有 MData 残留" if has_counterfeit() else "干净"))
    got, where = read_registration()
    say("注册信息     : %s" % ("Serial=%s @ %s" % (got.get("Serial"), where)
                               if got.get("Serial") else "缺失"))
    hb, hn, hw = hosts_state()
    say("hosts 屏蔽   : %s" % ("生效 %d/%d" % (hn, hw) if hb
                               else "!! 只生效 %d/%d（可能被注释掉了）" % (hn, hw)))
    ast, adetail, _ = acl_state(exe)
    say("文件不可变   : %s" % adetail)
    gt, gr = guard_state()
    say("残留守护任务 : %d 个%s" % (len(gt), ("  —— " + "、".join(gt)) if gt else ""))
    say("残留守护自启 : %d 个%s" % (len(gr), ("  —— " + "、".join(gr)) if gr else ""))
    say("-" * 76)
    say("")
    if not sys_ok:
        say("!! 本次为隔离模式：只改了 IDMan.exe，系统级各层被护栏跳过。")
        say("   二进制补丁：%s" % ("已完整" if patch_ok else "未通过校验"))
        say("   想在实机上真正生效，请直接双击 EXE（不带 --install-dir）。")
    elif patch_ok and not has_counterfeit() and hb and ast == "deny" and not gt and not gr:
        say("完成：无守护、无弹窗、可长期使用。")
        say("  没有计划任务、没有常驻进程 —— 跑完这一次就不需要再管它。")
        say("  IDM 自动更新无法覆盖补丁（文件已不可变），")
        say("  注册/校验域名已在本机屏蔽，伪造序列号永远不会被上报。")
        say("")
        say("下一步：正常打开 IDM 即可。想确认状态请跑 --status。")
    else:
        say("完成，但有项目需要留意（见上面带 !! 的行）。")
        say("  最要紧的是「二进制补丁」那一行：如果它没通过完整性校验，")
        say("  说明补丁不完整，请先 --uninstall 还原再重跑一次 --activate。")
        say("  其余各项（hosts / ACL）失败只会降低抗更新能力，不影响激活本身。")
    log("ACTIVATE 完成: sys_ok=%s patch=%s hash_ok=%s; mdata=%d; verdict=%d; hosts=%s; acl=%s" % (
        sys_ok, st, patch_ok, len(md), n_verdict, hb, ast))
    return 0 if patch_ok else 1


# --------------------------------------------------------------------------- #
# 命令：--status（只读）
# --------------------------------------------------------------------------- #

def do_status(install_dir):
    import winreg
    exe = os.path.join(install_dir, EXE_NAME)
    say("=" * 76)
    say(" %s  ——  状态（只读，不做任何修改）" % APP)
    say("=" * 76)
    if not os.path.isfile(exe):
        say("IDMan.exe    : <不存在> %s" % exe)
        return 2

    h = sha256_file(exe)
    say("安装目录     : %s" % install_dir)
    say("系统级改动   : %s" % ("允许" if is_live_install_dir(install_dir)
                               else "禁止（非实机安装目录；--activate 只会改这里的 IDMan.exe）"))
    say("IDMan.exe    : %s" % h)
    say("哈希提示     : %s" % hash_verdict(h)[1])
    say("idmvers      : %s   <== 含 Full 即已激活" % read_idmvers())
    say("")

    vst, vdetail, vexpect = verify_patched(exe)
    patch_ok = (vst == "ok")
    if patch_ok:
        say("二进制补丁   : 完整（10/10，已用备份自证）")
    elif vst == "original":
        say("二进制补丁   : 未施加（这是已知原版）")
    elif vst == "no_backup":
        say("二进制补丁   : 无法自证（%s）" % vdetail)
    else:
        say("二进制补丁   : !! %s" % vdetail)
    if vexpect:
        say("               期望哈希 = %s" % vexpect)
        say("               实际哈希 = %s" % h)
    say("")
    say("补丁点表（参考）：")
    try:
        _, rows, stat = patch_state(exe)
        for key, off, stt, title in rows:
            say("  [%-8s] %-28s file 0x%06X  %s" % (
                _STATE_CN.get(stt, stt), key, off, title))
        say("  ---- 定位到 %d 点：已到位 %d / 未施加 %d / 字节不符 %d" % (
            len(rows), stat["already"], stat["ready"], stat["mismatch"]))
        if len(rows) < EXPECTED_SITE_COUNT:
            say("  · 只定位到 %d/%d 点：idm_engine 的特征码以**原始字节**为锚点，" % (
                len(rows), EXPECTED_SITE_COUNT))
            say("    文件一旦打过补丁，这些锚点就失效了。所以补丁是否完整请以上面的")
            say("    「哈希判定」为准，这张表只用于在**原版**上预览将要改什么。")
        if stat["mismatch"]:
            say("  !! 有补丁点字节不符 —— IDM 可能被更新过或版本变了")
    except Exception as exc:
        say("  !! 无法构建补丁点：%s" % exc)
    say("")

    got, where = read_registration()
    say("注册信息     :")
    for n in REG_VALUES:
        v = got.get(n)
        say("  %-6s = %s" % (n, v if v else "<缺失>"))
    say("  来源       : %s" % (where or "<无>"))
    say("")

    md = find_mdata_keys()
    if md:
        say("counterfeit  : !! 存在 MData 残留")
        for hive, sub, view in md:
            say("  %s\\%s (view=%d)" % (
                "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", sub, view))
    else:
        say("counterfeit  : 干净（无 MData）")

    n_v = 0
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (64, 32):
            try:
                with winreg.OpenKey(hive, VERDICT_KEY, 0,
                                    winreg.KEY_READ | _reg_flag(view)) as k:
                    i = 0
                    while True:
                        try:
                            winreg.EnumValue(k, i)
                            i += 1
                        except OSError:
                            break
                    n_v += i
            except Exception:
                continue
    say("缓存校验判决 : %s" % ("%d 个值残留" % n_v if n_v else "无残留"))
    say("")

    hb, hn, hw = hosts_state()
    say("hosts 屏蔽   : %s" % ("生效 %d/%d 个域名" % (hn, hw) if hb
                               else "!! 只生效 %d/%d 个域名（有行被注释掉了？）" % (hn, hw)))
    for d in HOSTS_DOMAINS:
        say("  %-38s -> 0.0.0.0" % d)
    say("hosts 备份   : %s" % (HOSTS_BACKUP if os.path.exists(HOSTS_BACKUP) else "<无>"))
    _fst, _fdet = firewall_state()
    say("防火墙阻断   : %s" % (
        ("已生效（%s）" % _fdet) if _fst == "block"
        else ("需要管理员权限才能查询（用管理员跑 --status 可确认）") if _fst == "unknown"
        else "未设置 —— IDM 可直连授权/更新服务器（hosts 挡不住它）"))
    # ★ 文件内容正确 ≠ 屏蔽真的生效：Windows DNS 客户端缓存会让旧结果继续可用。
    #   所以这里额外做一次 ping 级探测，把「文件写了」和「真的拦住了」区分开。
    _ust, _udet = update_package_state()
    say("IDM 更新包   : %s" % _udet)
    _wst, _wdet = wfp_driver_state()
    say("内核驱动     : %s（%s）%s" % (
        _wst, _wdet,
        "  <== 已停用，hosts 不会被 IDM 拆掉" if _wst in ("disabled", "stopped", "absent")
        else "  <== 仍在运行！它会绕过 ACL 改 hosts，建议跑 --activate"))
    say("DNS 实际探测 : （用 ping，不用 Resolve-DnsName —— 后者会读 hosts 给出假通过）")
    try:
        pres, pn, pt = probe_hosts_block(quiet=True)
        for d, st, det in pres:
            mark = {"blocked": "已不可达", "resolved_real": "!! 仍解析到真实 IP",
                    "no_resolve": "无法解析", "unknown": "无法判定"}.get(st, st)
            say("  %-38s %s（%s）" % (d, mark, det))
        say("  小结         : %d/%d 个域名已不可达" % (pn, pt))
        if pn < pt:
            say("  !! 有域名仍可达。请先确认 hosts 内容正确，再跑 --activate 刷新 DNS 缓存；")
            say("     若仍可达，可能是本机 DNS/代理绕过了 hosts。")
    except Exception as exc:
        say("  无法探测（%s）" % exc)
    say("")

    ast, adetail, ahits = acl_state(exe)
    say("文件不可变   : %s" % adetail)
    for hh in ahits:
        say("  %s" % hh)
    if ast == "none":
        say("  !! 未加锁 —— IDM 自动更新可能覆盖补丁")
    say("")

    gt, gr = guard_state()
    say("残留守护任务 : %d 个%s" % (
        len(gt), ("  —— " + "、".join(gt)) if gt else "（干净）"))
    for t in gt:
        say("  · %s" % t)
    say("残留守护自启 : %d 个%s" % (
        len(gr), ("  —— " + "、".join(gr)) if gr else "（干净）"))
    for r in gr:
        say("  · %s" % r)
    say("备份文件     : %s" % (exe + BACKUP_SUFFIX
                               if os.path.exists(exe + BACKUP_SUFFIX) else "<无>"))
    say("日志         : %s" % LOG_PATH)

    say("")
    ok = (patch_ok and not md and hb and ast == "deny" and not gt and not gr)
    if ok:
        say("结论：无守护、无弹窗、可长期使用（各层均已就位）。")
    else:
        why = []
        if not patch_ok:
            why.append("二进制补丁未确认完整")
        if md:
            why.append("有 MData 残留")
        if not hb:
            why.append("hosts 屏蔽未生效")
        if ast != "deny":
            why.append("IDMan.exe 未加锁")
        if gt or gr:
            why.append("存在旧守护残留")
        say("结论：有项目未就位（%s），建议跑一次 --activate。" % "、".join(why))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# 命令：--scan（只读）
# --------------------------------------------------------------------------- #

def do_scan(install_dir):
    exe = os.path.join(install_dir, EXE_NAME)
    say("=" * 76)
    say(" %s  ——  扫描（只分析会改什么，不动手）" % APP)
    say("=" * 76)
    say("安装目录 : %s" % install_dir)
    h = sha256_file(exe)
    say("IDMan.exe: %s" % h)
    say("哈希判定 : %s" % hash_verdict(h)[1])
    pe = eng.PE(exe)
    sites, lines = eng.build_all_sites(pe)
    for l in lines:
        say(l)
    say("")
    say("可施加补丁点：%d 个" % len([s for s in sites if s.old != s.new]))
    if len(sites) < EXPECTED_SITE_COUNT:
        say("（只定位到 %d/%d 点：特征码以原始字节为锚点，已打补丁的文件上会失效）"
            % (len(sites), EXPECTED_SITE_COUNT))
    say("（--scan：未做任何修改）")
    return 0


# --------------------------------------------------------------------------- #
# 命令：--uninstall（幂等）
# --------------------------------------------------------------------------- #

def do_uninstall(install_dir, args=None):
    exe = os.path.join(install_dir, EXE_NAME)
    say("=" * 76)
    say(" %s  ——  完全还原" % APP)
    say("=" * 76)
    say("安装目录 : %s" % install_dir)

    # 隔离护栏：还原二进制只动 --install-dir，但清注册表 / hosts / 计划任务
    # 动的是**全局**位置 —— 必须确认目标是实机安装目录才允许做。
    sys_ok, sys_why = system_changes_allowed(args, install_dir) if args else (False, "无参数上下文")
    say("系统级改动 : %s" % ("允许（%s）" % sys_why if sys_ok else "已禁用（%s）" % sys_why))
    if not sys_ok:
        say("  注意：本次只会还原 %s 下的 IDMan.exe，不碰注册表/hosts/计划任务。" % install_dir)
    say("")

    say("[1/6] 移除旧守护（计划任务 + 自启项）...")
    if sys_ok:
        tasks, runs = cleanup_legacy()
        if not tasks and not runs:
            say("  没有旧守护痕迹（跳过）")
    else:
        say("  已跳过（隔离护栏）")

    say("[2/6] 移除文件不可变（DENY ACE）...")
    if os.path.isfile(exe):
        rst, rmsg, _ = remove_immutable(exe)
        say("  %s" % rmsg)
        if rst == "error":
            say("  !! 仍无法移除，请手动跑：icacls \"%s\" /remove:d \"%s\""
                % (exe, _SID_EVERYONE))
    else:
        say("  文件不存在，跳过")

    say("[3/6] 还原 IDMan.exe ...")
    bak = exe + BACKUP_SUFFIX
    if not os.path.isfile(exe):
        say("  IDMan.exe 不存在，跳过")
    elif not os.path.exists(bak):
        say("  没有备份 %s，跳过" % os.path.basename(bak))
    else:
        try:
            if sha256_file(exe) == sha256_file(bak):
                say("  当前文件已与备份一致，无需还原")
            else:
                kill_idm(quiet=True, allowed=sys_ok)
                shutil.copy2(bak, exe)
                say("  已还原 -> %s" % sha256_file(exe))
        except Exception as exc:
            say("  !! 还原失败：%s" % exc)

    say("[4/6] 清除 counterfeit 标记与缓存判决 ...")
    if sys_ok:
        if not clean_counterfeit():
            say("  无 MData 残留（跳过）")
        clear_verdict_cache()
    else:
        say("  已跳过（隔离护栏）")

    say("[5/6] 清除注册信息（Serial/FName/LName/Email）...")
    if sys_ok:
        if not purge_registration():
            say("  本来就没有（跳过）")
    else:
        say("  已跳过（隔离护栏）")

    say("[5.5/6] 移除防火墙阻断规则 ...")
    if sys_ok:
        remove_firewall_block()
    else:
        say("  已跳过（隔离护栏）")

    say("[5.6/6] 还原 IDM 更新包 ...")
    if sys_ok:
        _rok, _rmsg = restore_update_package()
        say("  %s" % _rmsg)
    else:
        say("  已跳过（隔离护栏）")

    say("[5.7/6] 恢复 IDM 内核驱动 idmwfp ...")
    if sys_ok:
        _wok, _wmsg = restore_wfp_driver(install_dir)
        say("  %s" % _wmsg)
    else:
        say("  已跳过（隔离护栏）")

    say("[6/6] 还原 hosts ...")
    if sys_ok:
        hok, hmsg = restore_hosts()
        say("  %s" % hmsg)
        if not hok:
            say("  !! hosts 未还原，请手动检查 %s" % HOSTS_PATH)
    else:
        say("  已跳过（隔离护栏）")

    say("")
    say("-" * 76)
    say("还原结果自检：")
    if os.path.isfile(exe):
        h2 = sha256_file(exe)
        hv2, hv2desc = hash_verdict(h2)
        say("  IDMan.exe  : %s" % h2)
        if hv2 == "original":
            say("               = 已知原版（还原成功）")
        elif hv2 == "patched_hint":
            say("               = 仍是全补丁版（还原失败？）")
        else:
            vst2, _, _ = verify_patched(exe, quiet=True)
            if vst2 == "original":
                say("               = 已回到原版（由备份自证）")
            elif vst2 == "ok":
                say("               = 仍是全补丁版（还原失败？）")
            else:
                say("               = 未知哈希（无法自证）")
        ast, adetail, _ = acl_state(exe)
        say("  文件不可变 : %s" % adetail)
    gt, gr = guard_state()
    say("  残留守护任务 : %d 个%s" % (len(gt), ("  —— " + "、".join(gt)) if gt else ""))
    say("  残留守护自启 : %d 个%s" % (len(gr), ("  —— " + "、".join(gr)) if gr else ""))
    hb, hn, _ = hosts_state()
    if not sys_ok:
        say("  hosts 屏蔽 : 未检查（隔离模式，未触碰实机 hosts）")
    else:
        say("  hosts 屏蔽 : %s" % ("仍生效 %d 个域名" % hn if hb else "已移除"))
    say("  MData      : %s" % ("!! 仍有残留" if (sys_ok and has_counterfeit())
                              else ("未检查（隔离模式）" if not sys_ok else "无")))
    say("-" * 76)
    say("")
    say("已恢复到官方状态。再跑一次 --uninstall 也不会报错（幂等）。")
    log("UNINSTALL 完成")
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="IDM 一键激活（免守护 / 静态方案）",
        epilog="默认动作是 --activate（一键激活，自动提权，不装守护）。")
    ap.add_argument("--activate", action="store_true", help="一键激活（默认动作）")
    ap.add_argument("--status", action="store_true", help="只查看状态（只读）")
    ap.add_argument("--scan", action="store_true", help="只分析会改什么，不动手（只读）")
    ap.add_argument("--uninstall", action="store_true", help="完全还原（幂等）")
    ap.add_argument("--install-dir", default=None, help="IDM 安装目录")
    ap.add_argument("--no-guard", action="store_true",
                    help="历史兼容参数，现在是空操作（本版没有守护）")
    ap.add_argument("--guard", action="store_true",
                    help="历史兼容参数，只打印提示后退出 0（守护模型已移除）")
    ap.add_argument("--no-lock", action="store_true",
                    help="跳过「IDMan.exe 不可变」这一步（调试用）")
    ap.add_argument("--allow-system-changes", action="store_true",
                    help="★ 危险：即使 --install-dir 不是实机安装目录，也允许改"
                         "注册表/hosts/计划任务/杀进程。默认禁止，防止测试污染实机。")
    ap.add_argument("--serial", default=None, help="指定序列号（默认自动生成）")
    ap.add_argument("--fname", default="Lo", help="名字（写注册信息用）")
    ap.add_argument("--lname", default="Tester", help="姓氏（写注册信息用）")
    ap.add_argument("--email", default="lo@example.com", help="邮箱（写注册信息用）")
    args = ap.parse_args()

    # --guard 历史兼容：计划任务已经不装它了，但用户机器上可能还残留旧任务在拉它。
    # 绝不能在这里建控制台（会被旧任务定期拉起），也绝不做任何修改。
    if args.guard:
        say("")
        say("=" * 76)
        say(" 守护模型已移除。")
        say("=" * 76)
        say("旧版每 30 分钟跑一次的「守护」是本次 bug 的根源：")
        say("  伪造序列号 -> IDM 判假并 ExitProcess(0) -> 守护删标记+换新序列号 -> 又判假")
        say("  这是一个自伤闭环，所以整个守护被删掉了。")
        say("")
        say("现在改为静态方案：跑一次 --activate 即可，不需要任何常驻进程。")
        say("旧守护计划任务会被 --activate / --uninstall 自动清理。")
        say("")
        return 0

    # 只读命令不提权、不建控制台。
    if not (args.status or args.scan):
        ensure_console()

    install_dir = find_install_dir(args.install_dir)
    if not install_dir:
        say("!! 找不到 IDM 安装目录，请用 --install-dir 指定")
        return 2

    if args.scan:
        return do_scan(install_dir)
    if args.status:
        return do_status(install_dir)

    if not is_admin():
        say("需要管理员权限（要改 Program Files 下的 IDMan.exe、HKLM 和 hosts），正在提权 ...")
        if elevate_and_wait():
            return 0
        say("!! 提权失败，请右键以管理员身份运行")
        return 4

    if args.uninstall:
        return do_uninstall(install_dir, args)
    return do_activate(args, install_dir)


if __name__ == "__main__":
    sys.exit(main())
