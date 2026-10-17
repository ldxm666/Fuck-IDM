#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P8 —— 封 `IDMGrHlp.exe` 的 counterfeit 弹窗显示端（第二目标二进制）。

用法
----
    python scripts/apply_p8_idmgrhlp.py --check                 # 只读：报告状态（幂等校验）
    python scripts/apply_p8_idmgrhlp.py                         # 施加（自动备份 .p8bak）
    python scripts/apply_p8_idmgrhlp.py --exe D:\\copy.exe        # 对副本操作
    python scripts/apply_p8_idmgrhlp.py --check --exe D:\\copy.exe

行为与保证
----------
* **全内容锚定**：锚点 = 导入表里的 `MessageBoxA` IAT + `push 0x1030/0x1031`，
  由其反推 `call dword ptr [MessageBoxA]` 落点 —— **不依赖任何写死的地址/偏移**。
* **old-bytes 硬断言**：落点 6 字节必须逐字节 ∈ {`ff 15 <IAT>`, 桩, 旧桩}，
  否则**拒绝施加**并报错（这是唯一能拦住「VA/file 算错一位」的机制）。
* **幂等**：已补丁形态会被认回并跳过；重复运行不会重复改写。
* **自动备份**：首次改写前生成 `<exe>.p8bak`（已存在则不覆盖）。
* **只读模式**：`--check` 绝不写盘。

落点（本机 IDM 6.43b15 实测，仅作核对用，代码不写死）
----------------------------------------------------
    file 0x52A1 / VA 0x405EA1   uType 0x1030（单按钮「确定」）
    file 0x52C8 / VA 0x405EC8   uType 0x1031（「确定」「取消」）
    old `ff 15 bc 34 44 00`  ->  new `83 c4 10 31 c0 90`
    （`83 c4 10` = 清 MessageBoxA 作为 stdcall 遗留的 16B 实参；`31 c0` = eax=0）
    ⛔ 禁止 `31 c0 90 90 90 90`：不清栈 ⇒ 每点泄漏 16B ⇒ 栈失衡。

原始 sha256 : B3B6281EA820EAE8192E50B30698CF4C3B8BC3D4376C978403BC9E18E5857C23
补丁后 sha256: 63197914f0b2c0f547c0ac572c85f5a1783cf7d228befddedb6bba78461351f4
"""
import argparse
import hashlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))          # work/idm-6.43b8

import idm_engine as E                                # noqa: E402

DEFAULT_EXE = r"C:\Program Files (x86)\Internet Download Manager\IDMGrHlp.exe"
ORIG_SHA256 = "b3b6281ea820eae8192e50b30698cf4c3b8bc3d4376c978403bc9e18e5857c23"
PATCHED_SHA256 = "63197914f0b2c0f547c0ac572c85f5a1783cf7d228befddedb6bba78461351f4"


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="P8: 封 IDMGrHlp.exe 的 counterfeit 弹窗")
    ap.add_argument("--exe", default=DEFAULT_EXE, help="目标 exe（默认安装目录里的 IDMGrHlp.exe）")
    ap.add_argument("--check", action="store_true", help="只读模式：只报告状态，不写盘")
    ap.add_argument("--no-backup", action="store_true", help="不生成 .p8bak（不建议）")
    ap.add_argument("--expect-sha256", default=None,
                    help="施加前校验当前文件哈希（防错版），不符则拒绝")
    args = ap.parse_args()

    if not os.path.isfile(args.exe):
        print("[错误] 文件不存在：%s" % args.exe)
        return 2

    before = sha256(args.exe)
    print("目标      : %s" % args.exe)
    print("当前 sha256: %s" % before)
    if before == ORIG_SHA256:
        print("             (= 已知原始版)")
    elif before == PATCHED_SHA256:
        print("             (= 已知 P8 已补丁版)")
    else:
        print("             (未知版本，将按内容锚定判定)")

    if args.expect_sha256 and before.lower() != args.expect_sha256.lower():
        print("[拒绝] --expect-sha256 不符：期望 %s" % args.expect_sha256)
        return 2

    pe = E.PE(args.exe)
    sites, lines = E.build_all_sites(pe, E.HELPER_FINDERS)
    print("\n=== 锚点扫描（内容锚定）===")
    for ln in lines:
        print(ln)

    if not sites:
        print("\n[结果] 未命中任何 P8 站点 —— 版本可能已变，未做任何改动。")
        return 3

    print("\n=== 站点状态 ===")
    states = {}
    for s in sites:
        st = s.check(pe)
        states[s.key] = st
        print("  %-24s VA 0x%08X file 0x%06X  uType/形态见上  -> %s"
              % (s.key, s.va or 0, s.offset, st))
    bad = [k for k, v in states.items() if v == "mismatch"]
    if bad:
        print("\n[拒绝] 有 %d 处字节不符（断言未通过）：%s" % (len(bad), ", ".join(bad)))
        return 3

    if args.check:
        todo = [k for k, v in states.items() if v == "ready"]
        print("\n[只读检查] %d 处站点，%d 处待施加，%d 处已在位。%s"
              % (len(sites), len(todo), len(sites) - len(todo),
                 "文件已是最新（幂等 OK）" if not todo else "需要施加。"))
        return 0

    suffix = ".p8bak"
    if args.no_backup:
        suffix = None
    status, detail, changed = E.apply_all(args.exe, backup_suffix=suffix or E.BACKUP_SUFFIX,
                                         finders=E.HELPER_FINDERS)
    print("\n=== 施加结果 ===")
    print("status = %s" % status)
    print("detail = %s" % detail)
    print("changed = %s" % changed)

    after = sha256(args.exe)
    print("施加后 sha256: %s" % after)
    if after == PATCHED_SHA256:
        print("              (= 与登记值逐字节一致 ✓)")
    if status in ("patched", "clean"):
        if not args.no_backup:
            print("备份: %s%s" % (args.exe, suffix or E.BACKUP_SUFFIX))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
