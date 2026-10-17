/*
 * idm_io_probe.js - second-stage probe, loaded into the SAME target process as
 * idm_popup_probe.js (Frida allows several scripts per session/process).
 *
 * Purpose: decide whether the delayed "IDM is corrupt" box is caused by
 *   A) a FILE self-integrity check  (kernel32 file APIs), or
 *   B) a NETWORK update check       (wininet / winhttp / ws2_32),
 * by logging who calls those APIs and when (relative to process start).
 *
 * Every record carries an ISO timestamp so the caller can compute
 *   uptime = iso - processCreationTime
 * which is what the 1200s (20 min) timer hypothesis has to be checked against.
 */
'use strict';

var MODNAME = 'IDMan.exe';
var MAX_PER_KEY = 1;          /* dedupe: report each (api,path) pair once */
var seen = {};
var counts = { total: 0, emitted: 0 };

function nowIso() { return new Date().toISOString(); }

function emit(o) {
  try { send(o); } catch (e) {}
}

function getMod(name) {
  var ms = Process.enumerateModules();
  var lc = name.toLowerCase();
  for (var i = 0; i < ms.length; i++) {
    if (ms[i].name.toLowerCase() === lc) return ms[i];
  }
  return null;
}

function desc(p) {
  try {
    if (!p || p.isNull()) return { mod: null, rva: null, va: null };
    var ms = Process.enumerateModules();
    var a = p;
    for (var i = 0; i < ms.length; i++) {
      var m = ms[i];
      if (a.compare(m.base) >= 0 && a.compare(m.base.add(m.size)) < 0) {
        return { mod: m.name, rva: '0x' + a.sub(m.base).toString(16), va: a.toString() };
      }
    }
    return { mod: null, rva: null, va: a.toString() };
  } catch (e) { return { mod: null, rva: null, va: null, err: e.message }; }
}

function bt(ctx) {
  try {
    var frames = Thread.backtrace(ctx, Backtracer.FUZZY) || [];
    var out = [];
    for (var i = 0; i < frames.length && i < 12; i++) {
      var d = desc(frames[i]);
      out.push(d.mod ? (d.mod + '+' + d.rva) : ('<' + frames[i] + '>'));
    }
    return out;
  } catch (e) { return ['<bt-err:' + e.message + '>']; }
}

function readAnsi(p, max) {
  try { return p.isNull() ? null : p.readAnsiString(max || 512); } catch (e) { return null; }
}
function readUtf16(p, max) {
  try { return p.isNull() ? null : p.readUtf16String(max || 512); } catch (e) { return null; }
}

function hook(moduleName, fnName, kind, handler) {
  var m = getMod(moduleName);
  if (!m) { emit({ type: 'hook-skip', api: moduleName + '!' + fnName, reason: 'module-not-loaded' }); return; }
  var addr = null;
  try { addr = m.getExportByName(fnName); } catch (e) { addr = null; }
  if (!addr) { emit({ type: 'hook-skip', api: moduleName + '!' + fnName, reason: 'no-export' }); return; }
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try { handler.call(this, args, moduleName + '!' + fnName, kind); }
        catch (e) { emit({ type: 'io-error', api: fnName, err: e.message }); }
      }
    });
    emit({ type: 'hook-ok', api: moduleName + '!' + fnName, addr: addr.toString() });
  } catch (e) {
    emit({ type: 'hook-fail', api: moduleName + '!' + fnName, err: e.message });
  }
}

function rec(api, kind, extra, key) {
  counts.total++;
  if (key) {
    if (seen[key] >= MAX_PER_KEY) return;
    seen[key] = (seen[key] || 0) + 1;
  }
  var o = { type: 'hit', kind: kind, api: api, ts: nowIso(), iso: nowIso(),
            tid: this.threadId, count: counts.total };
  try { o.ret = desc(this.returnAddress); } catch (e) {}
  if (extra) { for (var k in extra) o[k] = extra[k]; }
  o.bt = bt(this.context);
  counts.emitted++;
  emit(o);
}

/* ---------------- A group: file / self-integrity ---------------- */
function installFileGroup() {
  hook('kernel32.dll', 'GetModuleFileNameA', 'file', function (args, api) {
    rec.call(this, api, 'file', { which: 'exe-path' }, 'gmfnA');
  });
  hook('kernel32.dll', 'GetModuleFileNameW', 'file', function (args, api) {
    rec.call(this, api, 'file', { which: 'exe-path' }, 'gmfnW');
  });
  hook('kernel32.dll', 'CreateFileA', 'file', function (args, api) {
    var p = readAnsi(args[0], 512);
    rec.call(this, api, 'file', { path: p, access: args[1].toInt32() },
             'cfa:' + (p || ''));
  });
  hook('kernel32.dll', 'CreateFileW', 'file', function (args, api) {
    var p = readUtf16(args[0], 512);
    rec.call(this, api, 'file', { path: p, access: args[1].toInt32() },
             'cfw:' + (p || ''));
  });
  hook('kernel32.dll', 'GetFileSize', 'file', function (args, api) {
    rec.call(this, api, 'file', { hFile: args[0].toString() }, 'gfs:' + args[0]);
  });
  hook('kernel32.dll', 'GetFileSizeEx', 'file', function (args, api) {
    rec.call(this, api, 'file', { hFile: args[0].toString() }, 'gfse:' + args[0]);
  });
  hook('kernel32.dll', 'CreateFileMappingA', 'file', function (args, api) {
    rec.call(this, api, 'file', { hFile: args[0].toString() }, 'cfmA:' + args[0]);
  });
  hook('kernel32.dll', 'CreateFileMappingW', 'file', function (args, api) {
    rec.call(this, api, 'file', { hFile: args[0].toString() }, 'cfmW:' + args[0]);
  });
  hook('kernel32.dll', 'MapViewOfFile', 'file', function (args, api) {
    rec.call(this, api, 'file', { hMap: args[0].toString() }, 'mvof:' + args[0]);
  });
  /* ReadFile is the hottest of these: only report the FIRST few call sites so the log
   * stays readable while still proving whether reads happen at all. */
  hook('kernel32.dll', 'ReadFile', 'file', function (args, api) {
    var d = null;
    try { d = desc(this.returnAddress); } catch (e) {}
    var k = 'rf:' + (d ? (d.mod + '+' + d.rva) : '?');
    rec.call(this, api, 'file', { hFile: args[0].toString() }, k);
  });
}

/* ---------------- B group: network / update check ---------------- */
function installNetGroup() {
  hook('wininet.dll', 'InternetOpenUrlA', 'net', function (args, api) {
    rec.call(this, api, 'net', { url: readAnsi(args[1], 1024) }, 'ioupA:' + args[1]);
  });
  hook('wininet.dll', 'InternetOpenUrlW', 'net', function (args, api) {
    rec.call(this, api, 'net', { url: readUtf16(args[1], 1024) }, 'ioupW:' + args[1]);
  });
  hook('wininet.dll', 'HttpOpenRequestA', 'net', function (args, api) {
    rec.call(this, api, 'net', { verb: readAnsi(args[1], 32), object: readAnsi(args[2], 1024) },
             'horA:' + args[2]);
  });
  hook('wininet.dll', 'HttpOpenRequestW', 'net', function (args, api) {
    rec.call(this, api, 'net', { verb: readUtf16(args[1], 32), object: readUtf16(args[2], 1024) },
             'horW:' + args[2]);
  });
  hook('wininet.dll', 'InternetReadFile', 'net', function (args, api) {
    rec.call(this, api, 'net', {}, 'irf');
  });
  hook('winhttp.dll', 'WinHttpOpen', 'net', function (args, api) {
    rec.call(this, api, 'net', { agent: readUtf16(args[0], 256) }, 'who');
  });
  hook('winhttp.dll', 'WinHttpConnect', 'net', function (args, api) {
    rec.call(this, api, 'net', { host: readUtf16(args[1], 256), port: args[2].toInt32() },
             'whc:' + args[1]);
  });
  hook('winhttp.dll', 'WinHttpOpenRequest', 'net', function (args, api) {
    rec.call(this, api, 'net', { verb: readUtf16(args[1], 32), object: readUtf16(args[2], 1024) },
             'whor:' + args[2]);
  });
  hook('ws2_32.dll', 'connect', 'net', function (args, api) {
    rec.call(this, api, 'net', { s: args[0].toInt32() }, 'conn');
  });
  hook('ws2_32.dll', 'send', 'net', function (args, api) {
    rec.call(this, api, 'net', { s: args[0].toInt32(), len: args[2].toInt32() }, 'send');
  });
}

rpc.exports.installAll = function () {
  installFileGroup();
  installNetGroup();
  return { total: counts.total, emitted: counts.emitted, keys: Object.keys(seen).length };
};

rpc.exports.status = function () {
  return { total: counts.total, emitted: counts.emitted, keys: Object.keys(seen).length,
           iso: nowIso() };
};

/* install immediately on load as well */
installFileGroup();
installNetGroup();
emit({ type: 'io-probe-ready', iso: nowIso(), module: MODNAME });
