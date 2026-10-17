#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
run_probe.py - drive the IDM counterfeit-popup Frida probe.

Spawns (preferred) or attaches to IDMan.exe, loads idm_popup_probe.js, streams every
message as one JSON line to --log, fires an in-process self-test (proves the hooks are
live), then observes for --duration seconds and cleans up.

Usage (must be run elevated: Low-IL pwsh cannot inject into a medium-IL target):
  python run_probe.py --exe "C:\\Program Files (x86)\\Internet Download Manager\\IDMan.exe" \
      --script .agent_work\\scripts\\idm_probe\\idm_popup_probe.js \
      --log <probe dir>\\raw_probe.jsonl --duration 320 --mode spawn

Exit codes: 0 ok, 2 spawn/attach failed, 3 script load failed, 4 unexpected.
"""
import argparse
import json
import os
import sys
import time
import traceback

try:
    import frida
except Exception as e:  # pragma: no cover
    sys.stderr.write("FATAL: cannot import frida: %r\n" % (e,))
    raise SystemExit(4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=None,
                    help="executable to spawn (required for --mode spawn)")
    ap.add_argument("--exe-args", default=None,
                    help="extra argv for spawn, space-separated (e.g. \"/ch 3 /w 12345\")")
    ap.add_argument("--script", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--duration", type=int, default=320)
    ap.add_argument("--mode", default="spawn", choices=["spawn", "attach", "watch-attach"])
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--cwd", default=None)
    ap.add_argument("--watch-name", default="IDMGrHlp.exe",
                    help="for --mode watch-attach: process name to wait for")
    ap.add_argument("--watch-timeout", type=int, default=600,
                    help="for --mode watch-attach: seconds to wait for that process")
    ap.add_argument("--target-module", default=None,
                    help="override CFG.idmModule (e.g. IDMGrHlp.exe); also disables the "
                         "IDMan-specific wrapper/globals hooks")
    ap.add_argument("--call-site-rva", default=None,
                    help="hex RVA to hook inside --target-module, to prove execution "
                         "reaches a patched instruction (e.g. 0x5EC9)")
    ap.add_argument("--watch-data-rva", default=None,
                    help="hex RVA whose page should be watched for read/write access "
                         "(MemoryAccessMonitor), e.g. 0x37BED0 for the long-version buffer")
    ap.add_argument("--memwatch-interval", type=int, default=30,
                    help="seconds between memWatchReport dumps (0=off)")
    ap.add_argument("--dump-stacks-after", type=int, default=0,
                    help="if >0, dump all thread stacks once at this elapsed second "
                         "(finds a return address left on a MessageBox-blocked stack)")
    ap.add_argument("--probe-rvas", default=None,
                    help="comma-separated RVA[:len] list polled right after resume, "
                         "e.g. \"0x388CF4:1,0x388CCC:4\" (module globals such as licence flags)")
    ap.add_argument("--probe-until", type=float, default=6.0,
                    help="seconds of fine-grained --probe-rvas sampling")
    ap.add_argument("--probe-interval", type=float, default=0.5,
                    help="seconds between --probe-rvas samples (0.01 for 10ms granularity); "
                         "records are only written when a value CHANGES")
    ap.add_argument("--watch-write-rva", default=None,
                    help="hex RVA to arm a hardware WRITE watchpoint on right after resume "
                         "(e.g. 0x388CCC); hits are reported with a 14-frame backtrace")
    ap.add_argument("--hook-rvas", default=None,
                    help="comma-separated hex RVAs to hook inside --target-module, each hit "
                         "recording its return address + full stack; used to enumerate ALL "
                         "call paths to a shared ctor (e.g. \"0x121C00,0x212DBF\")")
    ap.add_argument("--selftest-delay", type=int, default=12)
    ap.add_argument("--selftest-timeout-ms", type=int, default=6000)
    ap.add_argument("--selftest-mode", default="ping", choices=["ping", "modal", "none"],
                    help="ping = thread-free PostMessage liveness check (safe for IDM); "
                         "modal = old MessageBox self-test (crashed IDMan.exe once)")
    ap.add_argument("--death-grace", type=int, default=3,
                    help="consecutive dead ticks before giving up early")
    ap.add_argument("--scan-interval", type=int, default=120,
                    help="seconds between writable-memory wording scans (0=off)")
    ap.add_argument("--globals-interval", type=int, default=20)
    ap.add_argument("--kill-on-exit", type=int, default=1)
    a = ap.parse_args()

    if a.mode == "spawn" and not a.exe:
        sys.stderr.write("--exe is required for --mode spawn\n")
        raise SystemExit(4)

    os.makedirs(os.path.dirname(os.path.abspath(a.log)), exist_ok=True)
    logf = open(a.log, "a", encoding="utf-8", buffering=1)

    def w(obj):
        if not isinstance(obj, str):
            obj = json.dumps(obj, ensure_ascii=False, default=str)
        logf.write(obj + "\n")
        logf.flush()
        try:
            print(obj, flush=True)
        except Exception:
            pass

    t0 = time.time()

    def elapsed():
        return round(time.time() - t0, 3)

    w({"type": "driver-start", "elapsed": elapsed(), "argv": sys.argv[1:],
       "frida_version": getattr(frida, "__version__", "?")})

    try:
        device = frida.get_local_device()
        w({"type": "device", "elapsed": elapsed(), "device": str(device)})
    except Exception as e:
        w({"type": "driver-fatal", "stage": "get_local_device",
           "error": repr(e), "tb": traceback.format_exc()})
        return 2

    src = open(a.script, "r", encoding="utf-8").read()
    w({"type": "script-source", "elapsed": elapsed(), "bytes": len(src), "path": a.script})

    if a.target_module:
        before = src
        src = src.replace("idmModule: 'IDMan.exe'", "idmModule: '%s'" % a.target_module)
        if a.target_module.lower() != "idman.exe":
            src = src.replace("wrapperRva: 0x74D20", "wrapperRva: 0")
            src = src.replace("displayRva: 0x7AA00", "displayRva: 0")
        w({"type": "target-module-override", "elapsed": elapsed(),
           "module": a.target_module, "source_changed": (src != before)})

    if a.call_site_rva:
        before2 = src
        src = src.replace("callSiteRva: 0,", "callSiteRva: %s," % a.call_site_rva)
        w({"type": "call-site-override", "elapsed": elapsed(),
           "rva": a.call_site_rva, "source_changed": (src != before2)})

    if a.hook_rvas:
        before3 = src
        parts = [x.strip() for x in a.hook_rvas.split(",") if x.strip()]
        lst = ", ".join(str(int(x, 16)) for x in parts)
        src = src.replace("extraRvas: []", "extraRvas: [%s]" % lst)
        w({"type": "extra-hooks-override", "elapsed": elapsed(), "rvas": parts,
           "source_changed": (src != before3)})

    pid = None
    session = None
    try:
        if a.mode == "spawn":
            spawn_kw = {}
            if a.cwd:
                spawn_kw["cwd"] = a.cwd
            pid = device.spawn([a.exe] + (a.exe_args.split() if a.exe_args else []), **spawn_kw)
            w({"type": "spawned", "elapsed": elapsed(), "pid": pid, "exe": a.exe,
               "cwd": a.cwd, "extra_args": a.exe_args})
            session = device.attach(pid)
        elif a.mode == "watch-attach":
            # The counterfeit popup is shown by IDMGrHlp.exe, a SEPARATE process that
            # IDMan.exe launches on demand. Wait for it to appear, then attach.
            w({"type": "watch-wait", "elapsed": elapsed(), "name": a.watch_name,
               "timeout": a.watch_timeout})
            dl = time.time() + a.watch_timeout
            target = None
            while time.time() < dl:
                try:
                    for p in device.enumerate_processes():
                        if p.name.lower() == a.watch_name.lower():
                            target = p
                            break
                except Exception as e:
                    w({"type": "watch-enum-error", "elapsed": elapsed(), "error": repr(e)})
                if target is not None:
                    break
                time.sleep(0.5)
            if target is None:
                w({"type": "watch-timeout", "elapsed": elapsed(), "name": a.watch_name})
                return 2
            pid = target.pid
            params = None
            try:
                params = list(getattr(target, "parameters", None) or [])
            except Exception:
                params = None
            w({"type": "watch-found", "elapsed": elapsed(), "pid": pid,
               "name": target.name, "frida_parameters": params})
            session = device.attach(pid)
            w({"type": "attached", "elapsed": elapsed(), "pid": pid, "name": target.name})
        else:
            pid = a.pid
            session = device.attach(pid)
            w({"type": "attached", "elapsed": elapsed(), "pid": pid})
    except Exception as e:
        w({"type": "driver-fatal", "stage": ("spawn" if a.mode == "spawn" else "attach"),
           "error": repr(e), "tb": traceback.format_exc()})
        return 2

    script = session.create_script(src)

    def on_message(msg, data):
        try:
            if msg.get("type") == "send":
                p = msg.get("payload")
                if isinstance(p, (dict, list)):
                    p = dict(p) if isinstance(p, dict) else {"payload": p}
                    p["elapsed"] = elapsed()
                    w(p)
                else:
                    w({"type": "raw", "elapsed": elapsed(), "payload": p})
            elif msg.get("type") == "error":
                w({"type": "script-error", "elapsed": elapsed(),
                   "description": msg.get("description"),
                   "stack": msg.get("stack"), "fileName": msg.get("fileName"),
                   "lineNumber": msg.get("lineNumber")})
            else:
                w({"type": "unknown-msg", "elapsed": elapsed(), "raw": str(msg)})
        except Exception as e:
            w({"type": "driver-msg-error", "error": repr(e)})

    script.on("message", on_message)

    try:
        script.load()
        w({"type": "script-loaded", "elapsed": elapsed()})
    except Exception as e:
        w({"type": "driver-fatal", "stage": "script.load", "error": repr(e),
           "tb": traceback.format_exc()})
        try:
            session.detach()
        except Exception:
            pass
        return 3

    if a.mode == "spawn":
        try:
            device.resume(pid)
            w({"type": "resumed", "elapsed": elapsed(), "pid": pid})
        except Exception as e:
            w({"type": "driver-fatal", "stage": "resume", "error": repr(e)})
            return 3

    # ---- hardware write watchpoint (catch the writer of a module global) ----
    if a.watch_write_rva:
        try:
            r = script.exports_sync.arm_write_watch(int(a.watch_write_rva, 16), 4)
            w({"type": "watchpoint-armed", "elapsed": elapsed(),
               "rva": a.watch_write_rva, "result": r})
        except Exception as e:
            w({"type": "watchpoint-arm-error", "elapsed": elapsed(), "error": repr(e)})

    # ---- fine-grained module-global sampling (licence flags) right after resume ----
    if a.probe_rvas:
        specs = []
        for part in a.probe_rvas.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                r, l = part.split(":")
                specs.append((int(r, 16), int(l)))
            else:
                specs.append((int(part, 16), 1))
        probe_end = time.time() + a.probe_until
        last_sig = None
        while time.time() < probe_end:
            rec = {"type": "probe-values", "elapsed": elapsed(), "values": []}
            for (rva, ln) in specs:
                try:
                    v = script.exports_sync.read_module_bytes(rva, ln)
                    rec["values"].append({
                        "rva": hex(rva), "len": ln, "va": v.get("va"),
                        "hex": v.get("hex"), "u8": v.get("u8"),
                        "u32": v.get("u32"),
                        "u32dec": (v.get("u32") - (1 << 32)) if (v.get("u32") or 0) >= (1 << 31) else v.get("u32"),
                        "error": v.get("error")
                    })
                except Exception as e:
                    rec["values"].append({"rva": hex(rva), "error": repr(e)})
            # only persist on change, so a 10ms interval does not flood the log
            sig = "|".join(str(x.get("hex")) for x in rec["values"])
            if sig != last_sig:
                rec["changed"] = True
                w(rec)
                last_sig = sig
            time.sleep(a.probe_interval)

    # ---- in-process liveness proof ----
    if a.selftest_mode != "none":
        time.sleep(a.selftest_delay)
        try:
            st = script.exports_sync.status()
            w({"type": "selftest-status-before", "elapsed": elapsed(), "status": st})
        except Exception as e:
            w({"type": "selftest-status-error", "elapsed": elapsed(), "error": repr(e)})
        try:
            if a.selftest_mode == "modal":
                r = script.exports_sync.selftest_modal(a.selftest_timeout_ms)
            else:
                r = script.exports_sync.selftest()
            w({"type": "selftest-fired", "elapsed": elapsed(),
               "mode": a.selftest_mode, "result": r})
        except Exception as e:
            w({"type": "selftest-error", "elapsed": elapsed(), "error": repr(e),
               "tb": traceback.format_exc()})

    # ---- enable the .data page access watcher (long-version ciphertext reader hunt) ----
    if a.watch_data_rva:
        try:
            r = script.exports_sync.watch_data_page(int(a.watch_data_rva, 16), 60)
            w({"type": "memwatch-enabled", "elapsed": elapsed(),
               "rva": a.watch_data_rva, "result": r})
        except Exception as e:
            w({"type": "memwatch-enable-error", "elapsed": elapsed(), "error": repr(e)})

    # ---- observe ----
    deadline = t0 + a.duration
    last_glob = 0.0
    last_scan = 0.0
    last_mw = 0.0
    stacks_dumped = False
    dead_streak = 0
    while time.time() < deadline:
        time.sleep(5)
        try:
            alive = any(p.pid == pid for p in device.enumerate_processes())
        except Exception:
            alive = None
        w({"type": "tick", "elapsed": elapsed(), "pid": pid, "alive": alive,
           "remaining": round(deadline - time.time(), 1)})
        if alive is False:
            dead_streak += 1
            if dead_streak >= a.death_grace:
                w({"type": "target-died-early", "elapsed": elapsed(), "pid": pid,
                   "dead_streak": dead_streak,
                   "note": "stopping observation early instead of idling out the window"})
                break
        else:
            dead_streak = 0
        # one-shot thread-stack dump (finds a return address left on a blocked stack)
        if a.dump_stacks_after > 0 and not stacks_dumped and time.time() - t0 >= a.dump_stacks_after:
            stacks_dumped = True
            try:
                w({"type": "thread-stacks", "elapsed": elapsed(),
                   "data": script.exports_sync.dump_thread_stacks(8192)})
            except Exception as e:
                w({"type": "thread-stacks-error", "elapsed": elapsed(), "error": repr(e)})
        # .data page access report
        if a.memwatch_interval > 0 and time.time() - last_mw >= a.memwatch_interval:
            last_mw = time.time()
            try:
                w({"type": "memwatch-report", "elapsed": elapsed(),
                   "data": script.exports_sync.mem_watch_report()})
            except Exception as e:
                w({"type": "memwatch-report-error", "elapsed": elapsed(), "error": repr(e)})
        # independent check: read the XOR-decrypted .data buffers directly
        if a.globals_interval > 0 and time.time() - last_glob >= a.globals_interval:
            last_glob = time.time()
            try:
                w({"type": "globals", "elapsed": elapsed(),
                   "data": script.exports_sync.read_globals()})
            except Exception as e:
                w({"type": "globals-error", "elapsed": elapsed(), "error": repr(e)})
        # independent check: scan writable memory for the popup wording (H1 vs H2)
        if a.scan_interval > 0 and time.time() - last_scan >= a.scan_interval:
            last_scan = time.time()
            try:
                w({"type": "memscan", "elapsed": elapsed(),
                   "data": script.exports_sync.scan_strings(20)})
            except Exception as e:
                w({"type": "memscan-error", "elapsed": elapsed(), "error": repr(e)})

    # ---- cleanup ----
    w({"type": "cleanup-begin", "elapsed": elapsed()})
    try:
        script.unload()
        w({"type": "script-unloaded", "elapsed": elapsed()})
    except Exception as e:
        w({"type": "script-unload-error", "error": repr(e)})
    try:
        session.detach()
        w({"type": "detached", "elapsed": elapsed()})
    except Exception as e:
        w({"type": "detach-error", "error": repr(e)})
    if a.mode == "spawn" and a.kill_on_exit:
        try:
            device.kill(pid)
            w({"type": "killed", "elapsed": elapsed(), "pid": pid})
        except Exception as e:
            w({"type": "kill-error", "error": repr(e)})
    w({"type": "driver-done", "elapsed": elapsed()})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        sys.stderr.write(traceback.format_exc())
        raise SystemExit(4)
