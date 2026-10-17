#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
idm-keygen.py —— IDM 6.43 Build 15 序列号生成器 / 校验器

结论依据（静态逆向，见 patches/serial-algo-b15.md）
------------------------------------------------
IDM 6.43b15 **不对序列号做任何密码学校验**。判定"已注册"的完整条件是：

  1. 格式：长度 23，第 5/11/17 字节为 '-'   ->  XXXXX-XXXXX-XXXXX-XXXXX
     （VA 0x450BA9 `cmp eax,0x17` + 0x450BAE/0x450BB7/0x450BC0 三处 `cmp byte,0x2D`
      通过后 0x450BC9 `mov dword ptr [0x77BD24],0`）
  2. 不在本地黑名单里：取序列号**前 8 个字符**拼成两个注册表值名，
     在某个键下查得到就判定为 counterfeit/blocked（FUN_0044e840）

没有任何 checksum、没有内嵌公钥、没有必须联网的校验。
所以：**任意符合格式的序列号都会被接受**，只要它的前 8 个字符没撞上黑名单。

本脚本因此是一个"序列号格式化器"，不是密码学 keygen —— 这是事实，不夸大。

用法
----
  python idm-keygen.py                     # 生成 5 个
  python idm-keygen.py --count 20          # 生成 20 个
  python idm-keygen.py --seed hello        # 可复现（同 seed 同结果）
  python idm-keygen.py --check AAAAA-BBBBB-CCCCC-DDDDD   # 校验格式
  python idm-keygen.py --selftest          # 自检
"""

import sys
import random
import argparse

# 格式常量：来自 0x450BA9 / 0x450BAE 的实测值
SERIAL_LEN = 0x17          # 23
DASH_POS = (5, 11, 17)
GROUP_LEN = 5
N_GROUPS = 4

# IDM 真序列号用大写字母 + 数字；格式检查本身不限制字符集，
# 但用这个字符集更贴近真实、也不会有奇怪字符。
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def validate(serial):
    """严格镜像 IDM 在 0x450BA9 处的判定逻辑。返回 (ok, reason)。"""
    if serial is None:
        return False, "序列号为 None"
    if len(serial) != SERIAL_LEN:
        return False, "长度 %d != %d" % (len(serial), SERIAL_LEN)
    for p in DASH_POS:
        if serial[p] != "-":
            return False, "第 %d 位是 %r，应为 '-'" % (p, serial[p])
    # 格式检查之外，IDM 还会查本地黑名单（按前 8 字符）。
    # 这里只能提示，无法离线判定。
    return True, "格式合法"


def generate(rng=None, avoid=None):
    """生成一个格式合法的序列号。avoid = 需要避开的前缀集合。"""
    rng = rng or random
    while True:
        groups = ["".join(rng.choice(ALPHABET) for _ in range(GROUP_LEN))
                  for _ in range(N_GROUPS)]
        s = "-".join(groups)
        ok, _ = validate(s)
        if not ok:
            continue
        if avoid and s[:8].upper() in avoid:
            continue
        return s


def selftest():
    print("=== selftest ===")
    bad = [
        ("", "空串"),
        ("AAAAA-BBBBB-CCCCC-DDDD", "22 字符"),
        ("AAAAA-BBBBB-CCCCC-DDDDDD", "24 字符"),
        ("AAAAABBBBB-CCCCC-DDDDD", "第 5 位不是 -"),
        ("AAAAA-BBBBBCCCCC-DDDDD", "第 11 位不是 -"),
        ("AAAAA-BBBBB-CCCCCDDDDD", "第 17 位不是 -"),
    ]
    for s, why in bad:
        ok, r = validate(s)
        print("  [%s] %-26r %s" % ("PASS" if not ok else "FAIL", s, why))
        if ok:
            print("     !! 应当被拒绝却通过了")
            return 1
    good = "AAAAA-BBBBB-CCCCC-DDDDD"
    ok, r = validate(good)
    print("  [%s] %-26r %s" % ("PASS" if ok else "FAIL", good, r))
    if not ok:
        return 1
    # 生成器产出一致性
    for i in range(200):
        s = generate()
        ok, r = validate(s)
        if not ok:
            print("  !! 生成器产出了非法序列号: %r (%s)" % (s, r))
            return 1
    print("  [PASS] 连续生成 200 个，全部通过格式校验")
    # 可复现性
    a = generate(random.Random(12345))
    b = generate(random.Random(12345))
    print("  [%s] seed 可复现: %s == %s" % ("PASS" if a == b else "FAIL", a, b))
    return 0 if a == b else 1


def main():
    ap = argparse.ArgumentParser(description="IDM 6.43b15 序列号生成/校验（格式驱动，非密码学）")
    ap.add_argument("--count", type=int, default=5, help="生成个数（默认 5）")
    ap.add_argument("--seed", default=None, help="随机种子，同种子同结果")
    ap.add_argument("--check", default=None, help="校验一个序列号并退出")
    ap.add_argument("--selftest", action="store_true", help="运行自检")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.check is not None:
        ok, reason = validate(args.check)
        print("%s  %r  -- %s" % ("OK  " if ok else "BAD ", args.check, reason))
        return 0 if ok else 2

    rng = random.Random(args.seed) if args.seed is not None else random.Random()
    print("IDM 6.43b15 序列号（格式：XXXXX-XXXXX-XXXXX-XXXXX，共 23 字符）")
    print("注意：格式合法即被本地接受；IDM 另有一个按前 8 字符查的本地黑名单，")
    print("      已尽量避开重复前缀，但黑名单内容无法离线枚举。")
    print("")
    seen = set()
    for i in range(max(1, args.count)):
        s = generate(rng, avoid=seen)
        seen.add(s[:8].upper())
        print("  %2d.  %s" % (i + 1, s))
    print("")
    print("校验方式：  python %s --check <序列号>" % sys.argv[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
