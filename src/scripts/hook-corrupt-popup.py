# -*- coding: utf-8 -*-
import frida, sys, time, os, datetime
LOG = r"D:\pojie应用\jiesuo\.scratch\fuckidm\frida_hook.log"
SCRIPT = r"D:\pojie应用\jiesuo\.scratch\fuckidm\hook_corrupt.js"
DUR = 1800

def W(s):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), s)); f.flush()

def find_pid():
    dev = frida.get_local_device()
    for proc in dev.enumerate_processes():
        if proc.name.lower() == "idman.exe":
            return proc.pid
    return None

W("=== frida hook start (dynamic pid) dur=%ds ===" % DUR)
pid = None
for i in range(60):
    pid = find_pid()
    if pid: break
    time.sleep(1)
if not pid:
    W("FATAL: IDMan.exe not found"); sys.exit(1)
W("pid=%d" % pid)
try:
    session = frida.attach(pid)
    W("attached OK")
    script = session.create_script(open(SCRIPT,"r",encoding="utf-8").read())
    def on_log(level, text):
        for line in text.splitlines(): W(line)
    script.on("message", lambda m,d: W("MSG: %s" % m))
    try: script.set_log_handler(on_log)
    except Exception: pass
    script.load()
    W("script loaded")
    t0=time.time()
    while time.time()-t0 < DUR:
        time.sleep(5)
    W("=== hook end ===")
    try: session.detach()
    except Exception: pass
except Exception as e:
    W("FATAL: %s: %s" % (type(e).__name__, e))
