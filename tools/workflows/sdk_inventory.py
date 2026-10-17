#!/usr/bin/env python3
"""Enumerate every ad-SDK class prefix present in one APK's DEX set.

Why this exists
---------------
"为了做适配各个版本的SDK都要加入拦截" means the hook must not be pinned to the
class names of one build. Baidu shuffles obfuscated names between minor versions
(`gak$12` -> `gas$12` on Tencent, whole packages disappear between 22.0.0 and
22.0.40), so the only stable handle is the SDK's own package prefix.

This script answers, per prefix: does it exist in THIS apk, and how many classes.
Feed it a list of candidate prefixes and it prints a table plus the raw class list
so a hook can be written against prefixes that are actually shipped.

Usage:
    python tools/sdk_inventory.py --Apk <apk> \
        --Prefix com/baidu/baidumaps/commonadprovider \
        --Prefix com/qq/e --Prefix com/bytedance --Prefix com/baidu/mobads
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dex_query import Dex, open_apk  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--Apk", type=Path, required=True)
    ap.add_argument("--Prefix", action="append", required=True,
                    help="class-descriptor prefix, e.g. com/qq/e (repeatable)")
    ap.add_argument("--List", action="store_true", help="print every matching class")
    args = ap.parse_args()

    dexes = open_apk(args.Apk)
    print(f"{len(dexes)} dex file(s) in {args.Apk.name}\n")

    want = [p.strip("/") for p in args.Prefix]
    found: dict[str, list[tuple[str, str]]] = {p: [] for p in want}

    for d in dexes:
        for desc in d.classes():
            for p in want:
                if desc.startswith("L" + p + "/") or desc == "L" + p + ";":
                    found[p].append((d.name, desc))
                    break

    for p in want:
        rows = found[p]
        dexes_hit = sorted({name for name, _ in rows})
        flag = "PRESENT" if rows else "absent "
        print(f"[{flag}] Lcom/{p};   classes={len(rows):4d}   dex={dexes_hit or '-'}")
        if args.List:
            for name, desc in rows:
                print(f"    {name:16s} {desc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
