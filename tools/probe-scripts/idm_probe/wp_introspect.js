/*
 * wp_introspect.js - discover the exact hardware-watchpoint API surface of the running
 * Frida version, on a THROWAWAY target, before touching IDM.
 *
 * Rationale: Thread.setHardwareWatchpoint's signature/return type has changed across
 * Frida versions, and a wrong guess either throws or (worse) leaves debug registers in
 * an unexpected state. We verify empirically instead of guessing.
 */
'use strict';

rpc.exports.probe = function () {
  var out = {};
  try {
    out.fridaVersionHint = (typeof Frida !== 'undefined' && Frida.version) ? Frida.version : 'unknown';
  } catch (e) { out.fridaVersionHint = 'err:' + e.message; }

  out.threadModuleKeys = Object.keys(Thread);
  out.hasSetHW = typeof Thread.setHardwareWatchpoint;
  if (typeof Thread.setHardwareWatchpoint === 'function') {
    out.setHWLength = Thread.setHardwareWatchpoint.length;
    out.setHWSource = String(Thread.setHardwareWatchpoint).substring(0, 400);
  }

  try {
    var ts = Process.enumerateThreads();
    out.threadCount = ts.length;
    if (ts.length) {
      out.thread0Keys = Object.keys(ts[0]);
      out.thread0HasSetHW = typeof ts[0].setHardwareWatchpoint;
      out.thread0ProtoKeys = Object.getOwnPropertyNames(Object.getPrototypeOf(ts[0]) || {});
    }
  } catch (e) { out.threadErr = e.message; }

  return out;
};

/* Try the candidate call signatures on a THREAD OBJECT (that is where the method
 * actually lives) against a harmless writable page, and report which is accepted. */
rpc.exports.tryArm = function () {
  var results = [];
  var page = Memory.alloc(0x1000);
  var addr = page.add(0x100);
  var t = Process.enumerateThreads()[0];
  if (!t) return [{ ok: false, err: 'no threads' }];
  var attempts = [
    { name: 't.setHW(0,addr,4,"w")', fn: function () { return t.setHardwareWatchpoint(0, addr, 4, 'w'); } },
    { name: 't.setHW(addr,4,"w")', fn: function () { return t.setHardwareWatchpoint(addr, 4, 'w'); } },
    { name: 't.setHW(0,addr,4)', fn: function () { return t.setHardwareWatchpoint(0, addr, 4); } }
  ];
  attempts.forEach(function (a) {
    try {
      var r = a.fn();
      var desc = { sig: a.name, ok: true, retType: typeof r };
      if (r && typeof r === 'object') {
        desc.retKeys = Object.keys(r);
        desc.hasOn = typeof r.on;
        desc.hasDisable = typeof r.disable;
        try { r.disable(); desc.disabled = true; } catch (e) { desc.disableErr = e.message; }
      }
      results.push(desc);
      try { t.unsetHardwareWatchpoint(0); } catch (e) {}
    } catch (e) {
      results.push({ sig: a.name, ok: false, err: e.message });
    }
  });
  return results;
};
