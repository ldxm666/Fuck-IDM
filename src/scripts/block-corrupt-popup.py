# -*- coding: utf-8 -*-
"""常驻：拦截 IDM 的 corrupt 弹窗（所有 IDMan.exe 实例，含 -Embedding）"""
import frida, time, datetime
LOG = r"D:\pojie应用\jiesuo\.scratch\fuckidm\block_corrupt.log"
SCRIPT = r"D:\pojie应用\jiesuo\.scratch\fuckidm\block_corrupt.js"
DUR = 86400
def W(s):
    with open(LOG,"a",encoding="utf-8") as f:
        f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), s)); f.flush()
W("=== block_corrupt start dur=%ds ===" % DUR)
dev = frida.get_local_device()
attached = {}
t0 = time.time()
while time.time()-t0 < DUR:
    try:
        procs = [p for p in dev.enumerate_processes() if p.name.lower() == "idman.exe"]
        for p in procs:
            if p.pid in attached: continue
            try:
                s = frida.attach(p.pid)
                sc = s.create_script(open(SCRIPT,"r",encoding="utf-8").read())
                def mk(pid):
                    def on_msg(m, d):
                        if m.get("type") == "send":
                            pl = m.get("payload") or {}
                            if pl.get("t") == "block":
                                W("[pid %d] *** BLOCKED corrupt popup *** title=%r text=%r" % (pid, pl.get("title"), (pl.get("text") or "")[:120]))
                                for fr in (pl.get("bt") or []): W("      %s" % fr)
                            elif pl.get("t") in ("installed","miss","ready"):
                                W("[pid %d] %s %s" % (pid, pl.get("t"), pl.get("api") or ""))
                    return on_msg
                sc.on("message", mk(p.pid))
                sc.load()
                attached[p.pid] = s
                W("attached pid=%d" % p.pid)
            except Exception as e:
                W("attach %d FAIL: %s" % (p.pid, e))
        alive = set(p.pid for p in procs)
        for pid in list(attached):
            if pid not in alive:
                try: attached[pid].detach()
                except Exception: pass
                del attached[pid]
                W("pid %d gone" % pid)
    except Exception as e:
        W("loop ERR: %s" % e)
    time.sleep(4)
W("=== end ===")
