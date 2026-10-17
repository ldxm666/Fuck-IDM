#!/usr/bin/env python3
"""Apply the full P1..P6 patch set to the *installed* IDMan.exe.

Kept separate from IDM-Activator.py so the patch application can be driven
directly (and elevated) while the activator's end-user flow is being rewritten.

Usage (elevated):
    python apply_patches_to_install.py [--scan] [--restore]
"""
import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import idm_engine as eng  # noqa: E402


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()

    exe = args.exe
    if not os.path.isfile(exe):
        print("找不到 %s" % exe)
        return 2

    if args.restore:
        bak = exe + eng.BACKUP_SUFFIX
        if not os.path.isfile(bak):
            print("没有备份 %s" % bak)
            return 2
        import shutil
        shutil.copy2(bak, exe)
        print("已还原 %s <- %s" % (exe, bak))
        print("sha256 = %s" % sha(exe))
        return 0

    print("目标 : %s" % exe)
    print("当前 : %s" % sha(exe))

    # 只用 engine 的公开 API —— 这样本脚本不依赖 IDM-Activator.py 的用户流程，
    # 两条工作流（部署/验证 与 用户一键流程）可以并行改动而互不影响。
    if args.scan:
        pe = eng.PE(exe)
        _, lines = eng.build_all_sites(pe)
        print("\n".join(lines))
        return 0

    st, detail, did = eng.apply_all(exe)
    print("状态 : %s" % st)
    print("详情 : %s" % detail)
    print("改动 : %s" % did)
    print("之后 : %s" % sha(exe))

    pe = eng.PE(exe)
    sites, _ = eng.build_all_sites(pe)
    print("\n可检出的补丁点：")
    for s in sites:
        print("  %-30s %s" % (s.key, s.check(pe)))
    return 0 if st in ("patched", "clean") else 1


if __name__ == "__main__":
    sys.exit(main())
