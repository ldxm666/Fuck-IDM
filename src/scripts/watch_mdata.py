#!/usr/bin/env python3
"""Watch the IDM CLSID keys for the MData value, to pin down WHAT writes it and WHEN.

The handover assumed MData is a counterfeit marker written by a second unknown
code site.  A cold start shows no MData at all, so the trigger is something
periodic.  This tool answers that empirically instead of by inference.

Usage:
    watch_mdata.py [--seconds N] [--interval S] [--csv PATH] [--launch] [--elevate-read]

Polls the five hardcoded CLSID paths that IDMan.exe 6.43b15 references
(see patches/mdata-writer-static.md) and reports every value-level change with
a timestamp, so a ~2 minute timer cadence is visible.

Exit: 0 always (it is an observer).
"""
import argparse
import ctypes
import os
import subprocess
import sys
import time
import winreg

# The five `Software\Classes\CLSID\{GUID}` literals present in IDMan.exe 6.43b15.
GUIDS = [
    "{E6871B76-C3C8-44DD-B947-ABFFE144860D}",  # adjacent to the "MData" string
    "{84797876-C678-1780-A556-0CD06786780F}",
    "{6DDF00DB-1234-46EC-8356-27E7B2051192}",
    "{79873CC5-3951-43ED-BDF9-D8759474B6FD}",  # has Model/Therad values
    "{07999AC3-058B-40BF-984F-69EB1E554CA7}",  # ACL-protected (access denied)
]

# 32-bit IDM writing to Software\Classes\CLSID lands in the Wow6432Node view.
BASES = [
    (winreg.HKEY_CURRENT_USER, r"Software\Classes\Wow6432Node\CLSID", "HKCU/Wow"),
    (winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID", "HKCU/64"),
]

EXE = r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe"


def read_key(hive, path):
    """Return {value_name: (type, repr)} or an error string, or None if absent."""
    try:
        with winreg.OpenKey(hive, path) as k:
            out = {}
            i = 0
            while True:
                try:
                    n, v, t = winreg.EnumValue(k, i)
                    i += 1
                    out[n] = (t, v.hex() if isinstance(v, bytes) else v)
                except OSError:
                    break
            return out
    except FileNotFoundError:
        return None
    except PermissionError:
        return "ERR:access-denied"
    except OSError as exc:
        return "ERR:%s" % exc


def snapshot():
    snap = {}
    for hive, base, tag in BASES:
        for g in GUIDS:
            snap[(tag, g)] = read_key(hive, base + "\\" + g)
    return snap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=600.0)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--csv", default=None, help="append change rows to this file")
    ap.add_argument("--launch", action="store_true", help="launch IDMan.exe first")
    args = ap.parse_args()

    # IDMan.exe is a GUI app; a 32-bit process cannot read the ACL-protected key.
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    base = snapshot()
    print("=== baseline (%s) ===" % time.strftime("%H:%M:%S"))
    for (tag, g), v in base.items():
        if v not in (None, {}):
            print("  %-9s %s -> %s" % (tag, g, v))

    if args.launch:
        print("=== launching IDMan.exe ===")
        proc = subprocess.Popen([EXE])
    else:
        proc = None

    t0 = time.time()
    rows = []
    last = base
    while time.time() - t0 < args.seconds:
        time.sleep(args.interval)
        cur = snapshot()
        for key in cur:
            if cur[key] != last[key]:
                el = time.time() - t0
                tag, g = key
                print("[%7.1fs] %s %s" % (el, tag, g))
                print("           %s  ->  %s" % (last[key], cur[key]))
                rows.append((time.strftime("%H:%M:%S"), "%.1f" % el, tag, g,
                             str(last[key]), str(cur[key])))
        last = cur
        if proc is not None and proc.poll() is not None:
            print("[%7.1fs] IDMan.exe exited code=%s" % (time.time() - t0, proc.returncode))
            break

    if rows and args.csv:
        new = not os.path.exists(args.csv)
        with open(args.csv, "a", encoding="utf-8") as fh:
            if new:
                fh.write("wall,elapsed_s,hive,guid,from,to\n")
            for r in rows:
                fh.write(",".join('"%s"' % c.replace('"', '""') for c in r) + "\n")
        print("=== wrote %d change rows to %s ===" % (len(rows), args.csv))

    print("=== %d changes over %.0fs ===" % (len(rows), time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
