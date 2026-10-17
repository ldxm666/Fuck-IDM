"""
wp_introspect.py - run wp_introspect.js against a THROWAWAY target (cmd.exe) and print
the discovered hardware-watchpoint API surface. Read-only w.r.t. the system; the target
is spawned, inspected and killed.

Usage (must be elevated - Low IL cannot inject into a medium-IL process):
    python wp_introspect.py [--exe C:\\Windows\\System32\\cmd.exe]
"""
import argparse
import json
import os
import sys
import time

import frida


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=r"C:\Windows\System32\cmd.exe")
    ap.add_argument("--script", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "wp_introspect.js"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    with open(a.script, "r", encoding="utf-8") as f:
        src = f.read()

    dev = frida.get_local_device()
    pid = dev.spawn([a.exe])
    session = dev.attach(pid)
    script = session.create_script(src)
    script.load()
    dev.resume(pid)

    result = {"probe": None, "tryArm": None}
    try:
        result["probe"] = script.exports_sync.probe()
    except Exception as e:
        result["probe"] = {"error": repr(e)}
    try:
        result["tryArm"] = script.exports_sync.try_arm()
    except Exception as e:
        result["tryArm"] = {"error": repr(e)}

    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)

    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
    try:
        dev.kill(pid)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
