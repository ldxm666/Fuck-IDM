/*
 * idm_popup_probe.js — IDM 6.43b15 counterfeit-popup DYNAMIC probe
 * Target: IDMan.exe (PE32/x86, ImageBase 0x400000, DYNAMICBASE)
 * Runtime: Frida 17.x, Windows, spawn-or-attach.
 *
 * Records, for the whole Win32 popup API family:
 *   API name + return address (module + RVA + VA) + title + body + uType(+decoded
 *   buttons) + thread id + timestamp + first N backtrace frames (module+RVA).
 * Also hooks IDM's own popup wrapper IDMan.exe!sub_474D20 (RVA 0x74D20) so we can
 * see which call sites actually reach it, and with which uType.
 *
 * Rationale: static analysis found every candidate call site pushing `6a 00`
 * (MB_OK / single button), yet the user's dialog shows OK+Cancel. Dynamic truth
 * must come from the real call site's uType.
 *
 * Read-only instrumentation: hooks only observe, never modify arguments/returns.
 */
'use strict';

var CFG = {
  btFrames: 14,         // spec asked >=12 frames so the decision-maker (above the
                        // decrypt/wrapper region) is visible in the stack
  maxStr: 700,
  wrapperRva: 0x74D20,  // 0x474D20 - 0x400000
  displayRva: 0x7AA00,  // sub_47AA00 - 0x400000: the thread that actually shows the popup
  callSiteRva: 0,       // optional: hook module.base+this RVA to prove execution reaches it
  extraRvas: [],        // optional: additional RVAs to hook (record return address + full stack)
  idmModule: 'IDMan.exe',
  heartbeatMs: 20000,
  pollMs: 200
};

/* state for the MemoryAccessMonitor-based .data read/write watcher */
var MEMWATCH = { enabled: false, page: null, seen: {}, dropped: 0 };

var KEEPALIVE = [];     // keep NativeCallbacks alive against GC

function now() { return Date.now(); }

function getMod(name) {
  var ms = Process.enumerateModules();
  var ln = name.toLowerCase();
  for (var i = 0; i < ms.length; i++) {
    if (ms[i].name.toLowerCase() === ln) return ms[i];
  }
  return null;
}

function findExport(modName, expName) {
  var m = getMod(modName);
  if (!m) return null;
  try { return m.getExportByName(expName); } catch (e) {}
  try { return Module.getExportByName(modName, expName); } catch (e2) {}
  return null;
}

function desc(addr) {
  try {
    if (addr === null || addr === undefined) return { mod: '<null>', rva: '', va: '' };
    if (addr.isNull()) return { mod: '<null>', rva: '', va: '0x0' };
    var m = Process.findModuleByAddress(addr);
    if (m) return { mod: m.name, rva: '0x' + addr.sub(m.base).toString(16), va: addr.toString() };
    return { mod: '<unmapped>', rva: '', va: addr.toString() };
  } catch (e) {
    return { mod: '<err:' + e.message + '>', rva: '', va: '' };
  }
}

function bt(ctx) {
  var out = [];
  try {
    var f = Thread.backtrace(ctx, Backtracer.FUZZY);
    for (var i = 0; i < f.length && out.length < CFG.btFrames; i++) {
      var d = desc(f[i]);
      out.push(d.mod + (d.rva ? '+' + d.rva : ''));
    }
  } catch (e) { out.push('<bt-error:' + e.message + '>'); }
  return out;
}

function rstr(p, wide) {
  if (p === null || p === undefined) return null;
  try { if (p.isNull()) return null; } catch (e) { return '<not-a-ptr>'; }
  try { return wide ? p.readUtf16String(CFG.maxStr) : p.readAnsiString(CFG.maxStr); }
  catch (e) { return '<unreadable:' + e.message + '>'; }
}

function hexOf(p, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    var s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  } catch (e) { return '<err:' + e.message + '>'; }
}

/* Read a NUL-terminated string and also report its byte length. */
function cstr(p, wide, maxBytes) {
  try {
    var bytes = new Uint8Array(p.readByteArray(maxBytes));
    var out = '', i = 0, step = wide ? 2 : 1;
    for (; i + step <= bytes.length; i += step) {
      if (wide) {
        if (bytes[i] === 0 && bytes[i + 1] === 0) break;
        out += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
      } else {
        if (bytes[i] === 0) break;
        out += String.fromCharCode(bytes[i]);
      }
    }
    return { text: out, byteLen: i, truncated: (i + step > bytes.length) };
  } catch (e) { return { err: e.message }; }
}

var BUTTONS = ['MB_OK', 'MB_OKCANCEL', 'MB_ABORTRETRYIGNORE', 'MB_YESNOCANCEL',
               'MB_YESNO', 'MB_RETRYCANCEL', 'MB_CANCELTRYCONTINUE'];

function decodeUType(u) {
  var v = u >>> 0;
  var b = v & 0xF;
  return {
    uType: v,
    uTypeHex: '0x' + v.toString(16),
    buttons: BUTTONS[b] || ('BTN_' + b),
    iconBits: (v & 0x70),
    defButton: ((v >> 8) & 0xF),
    topmost: !!(v & 0x40000),
    setForeground: !!(v & 0x10000),
    rightAlign: !!(v & 0x80000)
  };
}

function emit(o) {
  try {
    o.ts = now();
    o.iso = new Date().toISOString();
    send(o);
  } catch (e) {}
}

/* ---------------- API specs (x86 stdcall: args[] = [esp+4], [esp+8], ...) ---------------- */
var SPECS = {
  MessageBoxA:               { kind: 'mbox',     wide: false, text: 1, cap: 2, type: 3 },
  MessageBoxW:               { kind: 'mbox',     wide: true,  text: 1, cap: 2, type: 3 },
  MessageBoxExA:             { kind: 'mbox',     wide: false, text: 1, cap: 2, type: 3, lang: 4 },
  MessageBoxExW:             { kind: 'mbox',     wide: true,  text: 1, cap: 2, type: 3, lang: 4 },
  MessageBoxTimeoutA:        { kind: 'mbox',     wide: false, text: 1, cap: 2, type: 3, lang: 4, ms: 5 },
  MessageBoxTimeoutW:        { kind: 'mbox',     wide: true,  text: 1, cap: 2, type: 3, lang: 4, ms: 5 },
  MessageBoxIndirectA:       { kind: 'indirect', wide: false },
  MessageBoxIndirectW:       { kind: 'indirect', wide: true },
  SoftModalMessageBox:       { kind: 'indirect', wide: true },
  DialogBoxParamA:           { kind: 'dlg', wide: false, tpl: 1 },
  DialogBoxParamW:           { kind: 'dlg', wide: true,  tpl: 1 },
  DialogBoxIndirectParamA:   { kind: 'dlg', wide: false, tplPtr: 1 },
  DialogBoxIndirectParamW:   { kind: 'dlg', wide: true,  tplPtr: 1 },
  CreateDialogParamA:        { kind: 'dlg', wide: false, tpl: 1 },
  CreateDialogParamW:        { kind: 'dlg', wide: true,  tpl: 1 },
  CreateDialogIndirectParamA:{ kind: 'dlg', wide: false, tplPtr: 1 },
  CreateDialogIndirectParamW:{ kind: 'dlg', wide: true,  tplPtr: 1 },
  EndDialog:                 { kind: 'enddlg' }
};

function hookOne(modName, name) {
  var spec = SPECS[name];
  var addr = findExport(modName, name);
  if (!addr) { emit({ type: 'hook-skip', api: modName + '!' + name, reason: 'not-exported' }); return; }
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var rec = { type: 'hit', api: modName + '!' + name, kind: spec.kind, tid: this.threadId };
        try {
          rec.ret = desc(this.returnAddress);
          if (spec.kind === 'mbox') {
            COUNTERS.mbox++;
            var tb = cstr(args[spec.cap], spec.wide, 800);
            var bb = cstr(args[spec.text], spec.wide, 800);
            rec.title = tb.text; rec.titleByteLen = tb.byteLen;
            rec.body = bb.text; rec.bodyByteLen = bb.byteLen;
            rec.hwndOwner = args[0].toString();
            var d = decodeUType(args[spec.type].toInt32());
            for (var k in d) rec[k] = d[k];
            if (spec.lang !== undefined) rec.langId = args[spec.lang].toInt32();
            if (spec.ms !== undefined) rec.timeoutMs = args[spec.ms].toInt32();
          } else if (spec.kind === 'indirect') {
            var p = args[0];
            rec.paramsPtr = p.toString();
            rec.cbSize = p.add(0).readU32();
            rec.hwndOwner = p.add(4).readPointer().toString();
            rec.body = rstr(p.add(12).readPointer(), spec.wide);
            rec.title = rstr(p.add(16).readPointer(), spec.wide);
            var dwStyle = p.add(20).readU32();
            rec.langId = p.add(36).readU32();
            var d2 = decodeUType(dwStyle);
            for (var k2 in d2) rec[k2] = d2[k2];
          } else if (spec.kind === 'dlg') {
            rec.hInstance = args[0].toString();
            rec.hwndParent = args[2].toString();
            rec.dlgProc = desc(args[3]);
            if (spec.tpl !== undefined) {
              var tv = args[spec.tpl].toInt32() >>> 0;
              if (tv <= 0xFFFF) rec.templateId = tv;
              else rec.templateName = rstr(args[spec.tpl], spec.wide);
            } else {
              rec.templatePtr = args[spec.tplPtr].toString();
            }
          } else if (spec.kind === 'enddlg') {
            rec.hDlg = args[0].toString();
            rec.nResult = args[1].toInt32();
          }
          rec.bt = bt(this.context);
        } catch (e) {
          rec.decodeError = e.message;
          try { rec.bt = bt(this.context); } catch (e2) {}
        }
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: modName + '!' + name, addr: addr.toString() });
  } catch (e) {
    emit({ type: 'hook-fail', api: modName + '!' + name, err: e.message });
  }
}

function hookTaskDialog() {
  ['comctl32.dll', 'user32.dll'].forEach(function (m) {
    var a = findExport(m, 'TaskDialogIndirect');
    if (!a) return;
    try {
      Interceptor.attach(a, {
        onEnter: function (args) {
          var rec = { type: 'hit', api: m + '!TaskDialogIndirect', kind: 'taskdlg', tid: this.threadId };
          try {
            rec.ret = desc(this.returnAddress);
            var p = args[0];
            rec.cfgPtr = p.toString();
            rec.cbSize = p.readU32();
            rec.title = rstr(p.add(20).readPointer(), true);
          } catch (e) { rec.decodeError = e.message; }
          rec.bt = bt(this.context);
          emit(rec);
        }
      });
      emit({ type: 'hook-ok', api: m + '!TaskDialogIndirect', addr: a.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: m + '!TaskDialogIndirect', err: e.message }); }
  });
}

function hookWrapper(idmMod) {
  try {
    var addr = idmMod.base.add(CFG.wrapperRva);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var rec = { type: 'hit', api: 'IDMan.exe!sub_474D20(wrapper)', kind: 'wrapper',
                    tid: this.threadId, va: addr.toString() };
        try {
          rec.ret = desc(this.returnAddress);   // = CALLER's return address (e.g. 0x493B00)
          var cand = candidateFor(rec.ret);
          if (cand) rec.candidate = cand;
          rec.isTopCandidate_493B00 = (rec.ret.rva === '0x93b00');
          rec.hwndOwner = args[0].toString();
          var bw = cstr(args[1], false, 800);
          var tw = cstr(args[2], false, 800);
          rec.body = bw.text; rec.bodyByteLen = bw.byteLen;
          rec.title = tw.text; rec.titleByteLen = tw.byteLen;
          var d = decodeUType(args[3].toInt32());
          for (var k in d) rec[k] = d[k];
        } catch (e) { rec.decodeError = e.message; }
        rec.bt = bt(this.context);
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: 'IDMan.exe!sub_474D20', addr: addr.toString(), rva: '0x' + CFG.wrapperRva.toString(16) });
  } catch (e) {
    emit({ type: 'hook-fail', api: 'IDMan.exe!sub_474D20', err: e.message });
  }
}

/*
 * DECISIVE TARGET (lead's static finding): the popup is not a direct MessageBox.
 * sub_468C60 pushes the XOR-decrypted .data strings (0x77BEB0 title / 0x77BED0 body)
 * and PostMessageA(hWnd, WM_COMMAND 0x111, wParam=0x1509, lParam=2xCString) @0x68101,
 * i.e. the window procedure displays it. So we filter the WM_COMMAND channel.
 *
 * PostMessage/SendMessage are hot paths: the msg/wParam test below is deliberately
 * two integer reads and returns immediately for everything else, so the expensive
 * work (module lookup, backtrace, string reads) only happens on a match.
 */
var WM_COMMAND = 0x111;
var TARGET_WPARAM = 0x1509;
var PING_MSG = 0x7FFF;   // sentinel used ONLY by our in-process liveness ping

/* Lead-supplied static candidates.
 *
 * IMPORTANT (verified by reading the live binary, 2026-10-17): the lead's addresses
 * are the CALL SITES, not return addresses. Bytes at each:
 *   0x523AE1: E8 3A 12 F5 FF      -> call 0x474D20   => return addr 0x523AE6
 *   0x521157: E8 C4 3B F5 FF      -> call 0x474D20   => return addr 0x52115C
 *   0x523BD0: E8 4B 11 F5 FF      -> call 0x474D20   => return addr 0x523BD5
 *   0x468D01: 68 11 01 00 00 / FF 15 CC 57 69 00 -> push WM_COMMAND + call PostMessageA
 *                                 => return addr 0x468D07
 * A hook records this.returnAddress (the instruction AFTER the call), so the map must
 * be keyed on return-address RVAs. Keying it on the call-site VAs would never match.
 */
var CANDIDATES = {
  '0x123ae6': 'sub_522910 call@0x523AE1 -> 0x474D20 (title 0x696DE8, uType in EDI - TOP candidate)',
  '0x12115c': 'sub_522910 call@0x521157 -> 0x474D20 (non-immediate uType)',
  '0x123bd5': 'sub_522910 call@0x523BD0 -> 0x474D20 (non-immediate uType)',
  '0x68d07': 'sub_468C60 call@0x468D01 PostMessageA(0x111,0x1509) - P7 path',
  '0x74d20': 'wrapper sub_474D20 entry',
  /* --- patcher's revised table: three-element match with the user's screenshot
   * (IDM caption literal + runtime text + TWO buttons). These are the CALLER return
   * addresses seen at the sub_474D20 wrapper entry, NOT addresses inside the wrapper.
   * NOTE: a MessageBoxW/A hit reports a return address INSIDE sub_474D20, so these can
   * only be matched by the wrapper hook reading its own this.returnAddress. --- */
  '0x93b00': 'sub_493AFB -> wrapper (uType 0x50001 MB_OKCANCEL, caption 0x696DE8, runtime text) *TOP*',
  '0x93f43': 'sub_493F3E -> wrapper (uType 0x1 - only exact MB_OKCANCEL in the binary)',
  '0x93796': 'sub_493791 -> wrapper (uType 0x50001, caption via writable global 0x78A8C8)',
  '0x8f16c': 'sub_48F167 -> wrapper (uType 0x50001, text+caption both via writable globals)'
};

function candidateFor(d) {
  if (!d || d.mod !== CFG.idmModule) return null;
  return CANDIDATES[d.rva] || null;
}

function hookMsgChannel(name) {
  var a = findExport('user32.dll', name);
  if (!a) { emit({ type: 'hook-skip', api: 'user32.dll!' + name, reason: 'not-exported' }); return; }
  try {
    Interceptor.attach(a, {
      onEnter: function (args) {
        var msg, wparam;
        try {
          msg = args[1].toInt32() >>> 0;
          wparam = args[2].toInt32() >>> 0;
        } catch (e) { return; }

        // liveness ping: proves this hook is live inside the target, with no UI and
        // no extra thread (a modal self-test MessageBox previously crashed IDM).
        if (msg === PING_MSG) {
          var pr = { type: 'hit', api: 'user32.dll!' + name, kind: 'ping',
                     tid: this.threadId, hwnd: args[0].toString(),
                     msg: '0x' + msg.toString(16), wParam: '0x' + wparam.toString(16) };
          try { pr.ret = desc(this.returnAddress); } catch (e) {}
          emit(pr);
          return;
        }

        if (msg !== WM_COMMAND) return;          // cheap reject: not a command message
        COUNTERS.wmcommand++;

        var isTarget = (wparam === TARGET_WPARAM);
        var rec = {
          type: 'hit', api: 'user32.dll!' + name, kind: 'wm_command',
          tid: this.threadId,
          hwnd: args[0].toString(),
          msg: '0x' + msg.toString(16),
          wParam: '0x' + wparam.toString(16),
          isTarget1509: isTarget,
          lParam: args[3].toString()
        };
        if (isTarget) {
          try {
            rec.ret = desc(this.returnAddress);           // expect IDMan.exe+0x68D01
            var c = candidateFor(rec.ret);
            if (c) rec.candidate = c;
            rec.lParamHex = hexOf(args[3], 64);
            var p = args[3];
            // interpretation A: lParam -> array of two CString pointers (title, body)
            rec.p0 = p.readPointer().toString();
            rec.p1 = p.add(4).readPointer().toString();
            var s0 = cstr(p.readPointer(), false, 800);
            var s1 = cstr(p.add(4).readPointer(), false, 800);
            rec.ansi0 = s0.text; rec.ansi0Len = s0.byteLen;
            rec.ansi1 = s1.text; rec.ansi1Len = s1.byteLen;
            rec.utf16_0 = rstr(p.readPointer(), true);
            rec.utf16_1 = rstr(p.add(4).readPointer(), true);
            // interpretation B: lParam itself is the inline ANSI title buffer
            rec.inline_ansi = rstr(p, false);
          } catch (e) { rec.decodeError = e.message; }
          rec.bt = bt(this.context);
        } else {
          try {
            rec.ret = desc(this.returnAddress);
            var c2 = candidateFor(rec.ret);
            if (c2) rec.candidate = c2;
          } catch (e) {}
        }
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: 'user32.dll!' + name, addr: a.toString() });
  } catch (e) { emit({ type: 'hook-fail', api: 'user32.dll!' + name, err: e.message }); }
}

/* ---------------- H2: text sinks + network (server-delivered wording) ---------------- */
/*
 * H2 = the wording is delivered by the license server and displayed by an IDM CUSTOM
 * dialog (105 RT_DIALOG templates exist; static cannot exclude them). Two independent
 * ways to catch it regardless of origin:
 *   (a) the text must reach a dialog control eventually -> hook the text sinks;
 *   (b) if it comes over the wire -> hook the HTTP/socket read paths.
 * Everything is counter-instrumented so that "zero matches" can still be proven to be
 * a real observation rather than a dead hook.
 */
var KEYWORDS = ['serial', 'fake', 'be aware', 'cracked', 'registered', 'blocked', 'counterfeit',
                'license', 'answer'];

var COUNTERS = {
  textsink: 0, textsinkEmitted: 0,
  recv: 0, recvKeyword: 0,
  readfile: 0, readfileKeyword: 0,
  httpOpen: 0, httpConnect: 0,
  wmcommand: 0, mbox: 0,
  regSet: 0, regDel: 0, regMDataHit: 0
};

function printable(s) {
  var out = '';
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    out += (c >= 32 && c < 127) ? s[i] : (c === 9 || c === 10 || c === 13 ? ' ' : '.');
  }
  return out;
}

function looksInteresting(s) {
  if (!s) return false;
  var l = s.toLowerCase();
  for (var i = 0; i < KEYWORDS.length; i++) {
    if (l.indexOf(KEYWORDS[i]) >= 0) return true;
  }
  return false;
}

function hookTextSink(modName, name) {
  var a = findExport(modName, name);
  if (!a) { emit({ type: 'hook-skip', api: modName + '!' + name, reason: 'not-exported' }); return; }
  var isSendDlg = name.indexOf('SendDlgItemMessage') === 0;
  var isDlgItem = name.indexOf('SetDlgItemText') === 0;
  var wide = name.slice(-1) === 'W';
  var textIdx = isSendDlg ? 4 : (isDlgItem ? 2 : 1);
  try {
    Interceptor.attach(a, {
      onEnter: function (args) {
        COUNTERS.textsink++;
        if (isSendDlg) {
          var m;
          try { m = args[2].toInt32() >>> 0; } catch (e) { return; }
          if (m !== 0xC) return;              // WM_SETTEXT only
        }
        var s = cstr(args[textIdx], wide, 1500);
        if (!s.text) return;
        if (!looksInteresting(s.text)) return;
        COUNTERS.textsinkEmitted++;
        var rec = {
          type: 'hit', api: modName + '!' + name, kind: 'textsink', tid: this.threadId,
          target: args[0].toString(),
          ctlId: (isSendDlg || isDlgItem) ? args[1].toInt32() : null,
          text: printable(s.text), textByteLen: s.byteLen
        };
        try {
          rec.ret = desc(this.returnAddress);
          var c = candidateFor(rec.ret);
          if (c) rec.candidate = c;
        } catch (e) {}
        rec.bt = bt(this.context);
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: modName + '!' + name, addr: a.toString() });
  } catch (e) { emit({ type: 'hook-fail', api: modName + '!' + name, err: e.message }); }
}

function hookNetWininet() {
  // --- wininet: request metadata (host + URL) ---
  ['A', 'W'].forEach(function (suf) {
    var w = (suf === 'W');
    var c = findExport('wininet.dll', 'InternetConnect' + suf);
    if (c) {
      try {
        Interceptor.attach(c, {
          onEnter: function (args) {
            COUNTERS.httpConnect++;
            var rec = { type: 'hit', api: 'wininet.dll!InternetConnect' + suf, kind: 'net_connect', tid: this.threadId };
            try {
              rec.server = cstr(args[1], w, 256).text;
              rec.port = args[2].toInt32();
              rec.ret = desc(this.returnAddress);
            } catch (e) {}
            emit(rec);
          }
        });
        emit({ type: 'hook-ok', api: 'wininet.dll!InternetConnect' + suf, addr: c.toString() });
      } catch (e) { emit({ type: 'hook-fail', api: 'wininet.dll!InternetConnect' + suf, err: e.message }); }
    }
    var o = findExport('wininet.dll', 'HttpOpenRequest' + suf);
    if (o) {
      try {
        Interceptor.attach(o, {
          onEnter: function (args) {
            COUNTERS.httpOpen++;
            var rec = { type: 'hit', api: 'wininet.dll!HttpOpenRequest' + suf, kind: 'net_open', tid: this.threadId };
            try {
              rec.verb = cstr(args[1], w, 32).text;
              rec.url = cstr(args[2], w, 1024).text;
              rec.ret = desc(this.returnAddress);
            } catch (e) {}
            emit(rec);
          }
        });
        emit({ type: 'hook-ok', api: 'wininet.dll!HttpOpenRequest' + suf, addr: o.toString() });
      } catch (e) { emit({ type: 'hook-fail', api: 'wininet.dll!HttpOpenRequest' + suf, err: e.message }); }
    }
  });

  // --- wininet: response body (keyword-gated) ---
  var rf = findExport('wininet.dll', 'InternetReadFile');
  if (rf) {
    try {
      Interceptor.attach(rf, {
        onEnter: function (args) { this.buf = args[1]; this.pRead = args[3]; },
        onLeave: function (rv) {
          try {
            if (rv.toInt32() === 0) return;
            var n = this.pRead.readU32();
            if (!n) return;
            COUNTERS.readfile++;
            var s = cstr(this.buf, false, Math.min(n, 4096));
            if (looksInteresting(s.text)) {
              COUNTERS.readfileKeyword++;
              var rec = { type: 'hit', api: 'wininet.dll!InternetReadFile', kind: 'net_body',
                          tid: this.threadId, bytes: n, text: printable(s.text), textByteLen: s.byteLen };
              try { rec.ret = desc(this.returnAddress); } catch (e) {}
              emit(rec);
            }
          } catch (e) {}
        }
      });
      emit({ type: 'hook-ok', api: 'wininet.dll!InternetReadFile', addr: rf.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: 'wininet.dll!InternetReadFile', err: e.message }); }
  } else {
    emit({ type: 'hook-skip', api: 'wininet.dll!InternetReadFile', reason: 'not-exported' });
  }

}

function hookNetSockets() {
  // --- raw sockets: recv (keyword-gated). Cheapest possible onLeave. ---
  var rv = findExport('ws2_32.dll', 'recv');
  if (rv) {
    try {
      Interceptor.attach(rv, {
        onEnter: function (args) { this.buf = args[1]; },
        onLeave: function (ret) {
          try {
            var n = ret.toInt32();
            if (n <= 0) return;
            COUNTERS.recv++;
            var s = cstr(this.buf, false, Math.min(n, 2048));
            if (looksInteresting(s.text)) {
              COUNTERS.recvKeyword++;
              var rec = { type: 'hit', api: 'ws2_32.dll!recv', kind: 'net_body_recv',
                          tid: this.threadId, bytes: n, text: printable(s.text), textByteLen: s.byteLen };
              try { rec.ret = desc(this.returnAddress); } catch (e) {}
              emit(rec);
            }
          } catch (e) {}
        }
      });
      emit({ type: 'hook-ok', api: 'ws2_32.dll!recv', addr: rv.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: 'ws2_32.dll!recv', err: e.message }); }
  } else {
    emit({ type: 'hook-skip', api: 'ws2_32.dll!recv', reason: 'not-exported' });
  }
}

/* ---------------- registry write/delete of "MData" (tripwire payload) ---------------- */
/*
 * Goal: find WHO writes the 256-byte MData tripwire payload (~63.5s after start).
 * 19 static sites reference the "MData" string across >=4 functions, so instead of
 * blindly NOP-ing all of them we filter the registry API on the value NAME and take
 * the caller's return address directly.
 *
 * RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData)
 * RegDeleteValueA(hKey, lpValueName)
 */
var REG_TARGET = 'MData';
/* Broaden the watch list so the same hook can also answer "who READS the Serial
 * number", i.e. where the deep licence validation lives. */
var REG_WATCH = ['MData', 'Serial', 'nExpDt', 'FName', 'LName', 'Email', 'scansk'];

function hookReg() {
  var mod = 'advapi32.dll';
  var specs = [
    { name: 'RegSetValueExA', wide: false, kind: 'regset' },
    { name: 'RegSetValueExW', wide: true, kind: 'regset' },
    { name: 'RegDeleteValueA', wide: false, kind: 'regdel' },
    { name: 'RegDeleteValueW', wide: true, kind: 'regdel' },
    { name: 'RegQueryValueExA', wide: false, kind: 'regquery' },
    { name: 'RegQueryValueExW', wide: true, kind: 'regquery' }
  ];
  specs.forEach(function (s) {
    var a = findExport(mod, s.name);
    if (!a) { emit({ type: 'hook-skip', api: mod + '!' + s.name, reason: 'not-exported' }); return; }
    try {
      Interceptor.attach(a, {
        onEnter: function (args) {
          if (s.kind === 'regset') COUNTERS.regSet++;
          else if (s.kind === 'regdel') COUNTERS.regDel++;
          else COUNTERS.regQuery = (COUNTERS.regQuery || 0) + 1;
          var nm = cstr(args[1], s.wide, 256);
          if (!nm.text || REG_WATCH.indexOf(nm.text) < 0) return;
          if (nm.text === REG_TARGET) COUNTERS.regMDataHit++;
          var rec = {
            type: 'hit', api: mod + '!' + s.name, kind: s.kind,
            tid: this.threadId, hKey: args[0].toString(),
            valueName: nm.text, valueNameLen: nm.byteLen
          };
          try {
            rec.ret = desc(this.returnAddress);          // <-- THE ANSWER
            var c = candidateFor(rec.ret);
            if (c) rec.candidate = c;
          } catch (e) {}
          if (s.kind === 'regset') {
            try {
              rec.dwType = args[3].toInt32();
              rec.cbData = args[5].toInt32();
              rec.lpData = args[4].toString();
              rec.dataHex = hexOf(args[4], 32);
            } catch (e) { rec.decodeError = e.message; }
          } else if (s.kind === 'regquery') {
            try {
              rec.typeOut = args[3].isNull() ? null : args[3].readU32();
              rec.cbDataOut = args[5].isNull() ? null : args[5].readU32();
            } catch (e) {}
            /* remember the output buffer so onLeave can dump the raw bytes */
            this.qName = nm.text;
            this.qData = args[4];
            this.qCb = args[5];
          }
          rec.bt = bt(this.context);
          emit(rec);
        },
        onLeave: function (rv) {
          try {
            if (!this.qName) return;
            var len = 0;
            try { len = this.qCb.isNull() ? 0 : this.qCb.readU32(); } catch (e) {}
            var rec2 = {
              type: 'hit', api: mod + '!' + s.name + ':data', kind: 'regdata',
              tid: this.threadId, valueName: this.qName, rv: rv.toInt32(),
              cbData: len, lpData: this.qData.toString()
            };
            if (len > 0 && len <= 4096) rec2.dataHex = hexOf(this.qData, Math.min(len, 512));
            try { rec2.ret = desc(this.returnAddress); } catch (e) {}
            rec2.bt = bt(this.context);
            emit(rec2);
          } catch (e) { emit({ type: 'regdata-error', err: e.message }); }
        }
      });
      emit({ type: 'hook-ok', api: mod + '!' + s.name, addr: a.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: mod + '!' + s.name, err: e.message }); }
  });
}

/* ---------------- timers (find the periodic self-check period) ---------------- */
/*
 * The "IDM is corrupt" box is NOT shown at startup - the user reports it appears only
 * after a long wait - so it is driven by a periodic timer rather than a boot-time check.
 * Logging every SetTimer gives us the period directly (and which hwnd/id owns it).
 *
 * SetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc)
 * KillTimer(hWnd, nIDEvent)
 */
var TIMERS = {};

function hookTimers() {
  var mod = 'user32.dll';
  var st = findExport(mod, 'SetTimer');
  if (!st) { emit({ type: 'hook-skip', api: 'user32.dll!SetTimer', reason: 'not-exported' }); }
  else {
    try {
      Interceptor.attach(st, {
        onEnter: function (args) {
          var rec = {
            type: 'hit', kind: 'settimer', api: 'user32.dll!SetTimer',
            tid: this.threadId,
            hwnd: args[0].toString(),
            timerId: args[1].toString(),
            intervalMs: args[2].toInt32(),
            proc: args[3].toString()
          };
          try { rec.ret = desc(this.returnAddress); } catch (e) {}
          var k = rec.hwnd + ':' + rec.timerId;
          if (!TIMERS[k]) { TIMERS[k] = rec; emit(rec); }
          else if (TIMERS[k].intervalMs !== rec.intervalMs) {
            TIMERS[k].intervalMs = rec.intervalMs; rec.changed = true; emit(rec);
          }
        }
      });
      emit({ type: 'hook-ok', api: 'user32.dll!SetTimer', addr: st.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: 'user32.dll!SetTimer', err: e.message }); }
  }
  var kt = findExport(mod, 'KillTimer');
  if (kt) {
    try {
      Interceptor.attach(kt, {
        onEnter: function (args) {
          emit({ type: 'hit', kind: 'killtimer', api: 'user32.dll!KillTimer',
                 tid: this.threadId, hwnd: args[0].toString(), timerId: args[1].toString() });
        }
      });
      emit({ type: 'hook-ok', api: 'user32.dll!KillTimer', addr: kt.toString() });
    } catch (e) { emit({ type: 'hook-fail', api: 'user32.dll!KillTimer', err: e.message }); }
  }
}

/* ---------------- install (waits for user32 to be mapped) ---------------- */
var installed = false;
var wrapperHooked = false;
var netState = { wininet: false, ws2_32: false };

/*
 * wininet.dll / ws2_32.dll are not necessarily mapped when user32 is, so the network
 * hooks must be retried rather than attempted once (otherwise they would be silently
 * skipped and "no network activity" would be a dead-hook artefact, not an observation).
 */
function ensureNet() {
  if (netState.wininet && netState.ws2_32) return true;
  if (!netState.wininet && getMod('wininet.dll')) { hookNetWininet(); netState.wininet = true; }
  if (!netState.ws2_32 && getMod('ws2_32.dll')) { hookNetSockets(); netState.ws2_32 = true; }
  return netState.wininet && netState.ws2_32;
}

function ensureWrapper() {
  if (wrapperHooked) return true;
  /* Guard: wrapperRva is an IDMan.exe-specific RVA. When the probe is attached to a
   * different binary (e.g. IDMGrHlp.exe) hooking that offset would patch an unrelated
   * function - so it is explicitly disabled rather than guessed. */
  if (!CFG.wrapperRva) {
    wrapperHooked = true;
    emit({ type: 'hook-skip', api: 'wrapper sub_474D20',
           reason: 'disabled: not the IDMan.exe target (wrapperRva=0)' });
    return true;
  }
  var idm = getMod(CFG.idmModule);
  if (!idm) return false;
  hookWrapper(idm);
  wrapperHooked = true;
  return true;
}

/*
 * Call-site execution proof.
 *
 * Used for the P8 A/B: patch the MessageBoxA call at IDMGrHlp.exe+0x5EC9 so the popup
 * disappears - but "no MessageBoxA hit" alone is weak, because the process could simply
 * have exited before reaching that point. Hooking the call-site address itself shows
 * whether execution actually arrives there, in both the patched and unpatched binaries.
 */
var callSiteHooked = false;

/*
 * Generic extra-RVA hooks.
 *
 * Used to enumerate ALL construction sites of a shared object (e.g. the registration
 * dialog ctor at RVA 0x121C00 / VA 0x521C00, and CDialog::DoModal at RVA 0x212DBF /
 * VA 0x612DBF). Recording the RETURN ADDRESS of every hit is what tells us how many
 * distinct call paths exist - which is exactly how you prove "no third path is left".
 */
var extraHooked = {};

function ensureExtras() {
  if (!CFG.extraRvas || !CFG.extraRvas.length) return true;
  var m = getMod(CFG.idmModule);
  if (!m) return false;
  CFG.extraRvas.forEach(function (rva) {
    var k = rva.toString(16);
    if (extraHooked[k]) return;
    try {
      var addr = m.base.add(rva);
      Interceptor.attach(addr, {
        onEnter: function () {
          var rec = {
            type: 'hit', api: CFG.idmModule + '!rva_0x' + rva.toString(16),
            kind: 'extrahook', tid: this.threadId,
            va: addr.toString(), rva: '0x' + rva.toString(16)
          };
          try { rec.ret = desc(this.returnAddress); } catch (e) {}
          try { rec.callerVa = this.returnAddress.toString(); } catch (e) {}
          try { rec.bt = bt(this.context); } catch (e) {}
          emit(rec);
        }
      });
      emit({ type: 'hook-ok', api: CFG.idmModule + '!rva_0x' + rva.toString(16),
             addr: addr.toString() });
      extraHooked[k] = true;
    } catch (e) {
      emit({ type: 'hook-fail', api: 'rva_0x' + rva.toString(16), err: e.message });
      extraHooked[k] = true;
    }
  });
  return true;
}
var regHooked = false;
var displayHooked = false;

/*
 * sub_47AA00 (RVA 0x7AA00) = the thread that actually displays the counterfeit popup.
 * patcher: case 0x1505 -> AfxBeginThread(sub_468C60)  [P7 sealed]
 *           case 0x1509 -> AfxBeginThread(sub_47AA00)  [NOT covered by P7]
 * The text is NOT a constant inside this function: it comes from the parameter struct
 * (esi=[ebp+8]; caption=[esi]; text=[esi+4]), i.e. prepared by the CALLER. So dumping the
 * struct + the pointed-to text gives us both the wording AND the address to trace back
 * to whoever produced/decrypted it.
 */
function hookDisplayThread(m) {
  try {
    var addr = m.base.add(CFG.displayRva);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var rec = { type: 'hit', api: CFG.idmModule + '!sub_47AA00', kind: 'display',
                    tid: this.threadId, va: addr.toString(),
                    rva: '0x' + CFG.displayRva.toString(16) };
        try {
          var param = args[0];
          rec.param = param.toString();
          rec.paramHex = hexOf(param, 32);
          var capPtr = param.readPointer();
          var txtPtr = param.add(4).readPointer();
          rec.captionPtr = capPtr.toString();
          rec.textPtr = txtPtr.toString();
          rec.caption_ansi = rstr(capPtr, false);
          rec.text_ansi = rstr(txtPtr, false);
          rec.text_utf16 = rstr(txtPtr, true);
          rec.caption_utf16 = rstr(capPtr, true);
          rec.textHex128 = hexOf(txtPtr, 128);
          rec.captionHex64 = hexOf(capPtr, 64);
          /* where does text live? module .data vs heap tells us whether an in-place
           * decrypt happened or a runtime copy was built */
          var td = desc(txtPtr);
          rec.textMod = td.mod;
          rec.textRva = td.rva;
          rec.textIsInModuleData = (td.mod === CFG.idmModule &&
                                    parseInt(td.rva, 16) >= 0x37B000 && parseInt(td.rva, 16) < 0x37C000);
        } catch (e) { rec.decodeError = e.message; }
        rec.bt = bt(this.context);
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: CFG.idmModule + '!sub_47AA00@0x' + CFG.displayRva.toString(16),
           addr: addr.toString() });
    displayHooked = true;
  } catch (e) {
    emit({ type: 'hook-fail', api: 'sub_47AA00', err: e.message });
    displayHooked = true;
  }
  return true;
}

function ensureDisplay() {
  if (displayHooked) return true;
  if (!CFG.displayRva) { displayHooked = true; return true; }
  var m = getMod(CFG.idmModule);
  if (!m) return false;
  return hookDisplayThread(m);
}

/* advapi32.dll may not be mapped when user32 is, so retry rather than attempt once. */
function ensureReg() {
  if (regHooked) return true;
  if (!getMod('advapi32.dll')) return false;
  hookReg();
  regHooked = true;
  return true;
}

function ensureCallSite() {
  if (callSiteHooked) return true;
  if (!CFG.callSiteRva) { callSiteHooked = true; return true; }
  var m = getMod(CFG.idmModule);
  if (!m) return false;
  try {
    var addr = m.base.add(CFG.callSiteRva);
    Interceptor.attach(addr, {
      onEnter: function () {
        var rec = { type: 'hit', api: CFG.idmModule + '!callsite', kind: 'callsite',
                    tid: this.threadId, rva: '0x' + CFG.callSiteRva.toString(16),
                    va: addr.toString() };
        try { rec.bt = bt(this.context); } catch (e) {}
        emit(rec);
      }
    });
    emit({ type: 'hook-ok', api: CFG.idmModule + '!callsite@0x' + CFG.callSiteRva.toString(16),
           addr: addr.toString() });
    callSiteHooked = true;
  } catch (e) {
    emit({ type: 'hook-fail', api: 'callsite@0x' + CFG.callSiteRva.toString(16), err: e.message });
    callSiteHooked = true;
  }
  return true;
}

function installAll() {
  if (installed) return true;
  var u = getMod('user32.dll');
  if (!u) return false;
  installed = true;
  Object.keys(SPECS).forEach(function (n) { hookOne('user32.dll', n); });
  hookTaskDialog();
  hookTimers();
  // SendMessageA/W intentionally NOT hooked: it is the hottest of these paths and a
  // prime re-entrancy suspect after the frida-agent.dll crash. PostMessage is the
  // lead's actual target (sub_468C60 uses PostMessageA).
  ['PostMessageA', 'PostMessageW'].forEach(hookMsgChannel);
  // H2 text sinks: whatever the wording's origin, it must reach a dialog control.
  ['SetDlgItemTextA', 'SetDlgItemTextW', 'SetWindowTextA', 'SetWindowTextW',
   'SendDlgItemMessageA', 'SendDlgItemMessageW'].forEach(function (n) {
    hookTextSink('user32.dll', n);
  });
  ensureNet();
  ensureWrapper();
  ensureCallSite();
  ensureReg();
  ensureDisplay();
  ensureExtras();
  if (!wrapperHooked) {
    emit({ type: 'hook-pending', api: 'IDMan.exe!sub_474D20',
           reason: 'IDMan.exe not mapped yet; retrying' });
  }
  emit({
    type: 'probe-ready', pid: Process.id, arch: Process.arch,
    user32: u.base.toString(),
    idm: getMod(CFG.idmModule) ? getMod(CFG.idmModule).base.toString() : null
  });
  return true;
}

/* ---------------- self-test: prove the hooks are actually live ---------------- */
function runOnThread(fn) {
  try {
    var a = findExport('kernel32.dll', 'CreateThread');
    var CT = new NativeFunction(a, 'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint', 'pointer']);
    var cb = new NativeCallback(function () {
      try { fn(); } catch (e) { emit({ type: 'selftest-err', err: e.message }); }
      return 0;
    }, 'uint32', ['pointer']);
    KEEPALIVE.push(cb);
    var tid = Memory.alloc(4);
    // NOTE: the 2nd arg is SIZE_T (an integer type) - passing a NativePointer here
    // throws "UInt64 object expected", which silently made the self-test a no-op.
    CT(ptr(0), 0, cb, ptr(0), 0, tid);
    return true;
  } catch (e) {
    emit({ type: 'selftest-err', err: 'runOnThread: ' + e.message });
    return false;
  }
}

rpc.exports = {
  /*
   * Liveness ping - deliberately NOT a MessageBox.
   *
   * Measured: the earlier modal self-test (CreateThread + MessageBoxTimeoutW) coincided
   * EXACTLY with IDMan.exe crashing inside frida-agent.dll (0xC000041D
   * STATUS_FATAL_USER_CALLBACK_EXCEPTION, event-log Application Error 1000 @02:49:53/58).
   * It is therefore banned from the IDM run.
   *
   * PostMessage is non-blocking, so it can be called straight from the JS thread:
   * no extra thread, no modal loop, no window. The hook records it as kind='ping',
   * proving the hook chain is live inside the target.
   */
  selftest: function () {
    var out = [];
    var f = findExport('user32.dll', 'PostMessageA');
    if (f) {
      var pf = new NativeFunction(f, 'int', ['pointer', 'uint', 'uint', 'pointer']);
      out.push('PostMessageA ping rc=' + pf(ptr(0), PING_MSG, 0xdead, ptr(0)));
    } else {
      out.push('PostMessageA missing');
    }
    // Text-sink liveness. Interceptor fires BEFORE the API validates its arguments,
    // so passing hwnd=0 still drives our hook with a keyword-matching string - which
    // proves both the hook chain and the keyword filter, with no side effect at all.
    var sw = findExport('user32.dll', 'SetWindowTextA');
    if (sw) {
      var sf = new NativeFunction(sw, 'int', ['pointer', 'pointer']);
      var probe = Memory.allocAnsiString('PROBE SELFTEST fake Serial Number liveness');
      out.push('SetWindowTextA rc=' + sf(ptr(0), probe));
    } else {
      out.push('SetWindowTextA missing');
    }
    return out.join(' | ');
  },

  /* Modal MessageBox self-test. Validated OK on a throwaway target (cmd.exe), but it
   * crashed IDMan.exe once - do NOT use it against IDM. */
  selftestModal: function (timeoutMs) {
    timeoutMs = timeoutMs || 4000;
    var body = Memory.allocUtf16String('PROBE SELFTEST BODY (hook liveness check)');
    var cap = Memory.allocUtf16String('PROBE SELFTEST');
    var mt = findExport('user32.dll', 'MessageBoxTimeoutW');
    if (mt) {
      var f = new NativeFunction(mt, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'uint16', 'uint']);
      runOnThread(function () { f(ptr(0), body, cap, 1, 0, timeoutMs); });
      return 'selftest-MessageBoxTimeoutW(uType=1,timeout=' + timeoutMs + ')';
    }
    var mw = findExport('user32.dll', 'MessageBoxW');
    var f2 = new NativeFunction(mw, 'int', ['pointer', 'pointer', 'pointer', 'uint']);
    runOnThread(function () { f2(ptr(0), body, cap, 1); });
    return 'selftest-MessageBoxW(uType=1)';
  },
  status: function () { return { installed: installed, pid: Process.id, wrapperHooked: wrapperHooked }; },

  /*
   * Read the two .data buffers the static analysis identified (0x77BEB0 title /
   * 0x77BED0 body, RVA 0x37BEB0 / 0x37BED0) directly. sub_468C60 XORs them in place
   * with key 0x0F, so after the first use these addresses hold PLAINTEXT. Polling
   * this is an independent check that does not depend on any hook firing, and it
   * answers the lead's question about which wording variant is actually present.
   */
  readGlobals: function () {
    if (!CFG.wrapperRva) return { skipped: 'not the IDMan.exe target (wrapperRva=0)' };
    var idm = getMod(CFG.idmModule);
    if (!idm) return { error: 'IDMan.exe not mapped' };
    var out = [];
    [0x37BEB0, 0x37BED0].forEach(function (rva) {
      var p = idm.base.add(rva);
      var o = { rva: '0x' + rva.toString(16), va: p.toString(), hex: hexOf(p, 96) };
      /* XOR 0x0F decode. sub_468C60 decrypts these buffers IN PLACE, so in a state
       * where that path never runs they stay ciphertext. Decoding here makes the
       * "which wording variant is present" comparison trivial and unambiguous. */
      try {
        var raw = new Uint8Array(p.readByteArray(96));
        var dec = '';
        for (var i = 0; i < raw.length; i++) {
          var c = raw[i] ^ 0x0F;
          if (c === 0) break;
          dec += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
        o.xor0f = dec;
      } catch (e) { o.xor0fErr = e.message; }
      try { o.ansi = p.readAnsiString(400); } catch (e) { o.ansiErr = e.message; }
      try { o.utf16 = p.readUtf16String(400); } catch (e) { o.utf16Err = e.message; }
      out.push(o);
    });
    return { idmBase: idm.base.toString(), globals: out };
  },

  /*
   * Independent H1-vs-H2 probe: scan WRITABLE memory for the popup wording.
   *
   * H1 = a different local variant we have not found (maybe UTF-16 / runtime-assembled)
   * H2 = the text was delivered by the license server and stored (possibly overwriting
   *      the writable .data template, which is decrypted in place).
   *
   * Scoped to writable regions on purpose: the .data template is writable, and any
   * server-supplied copy would live on the heap or in .data. Scanning code/.rdata
   * would only re-find the compile-time constant and cost far more time.
   */
  scanStrings: function (maxMatches) {
    maxMatches = maxMatches || 20;
    var pats = [
      { name: 'ansi_fakeSerial', p: '66 61 6b 65 20 53 65 72 69 61 6c' },
      { name: 'utf16_fakeSerial', p: '66 00 61 00 6b 00 65 00 20 00 53 00 65 00 72 00 69 00 61 00 6c 00' },
      { name: 'ansi_registeredWithA', p: '72 65 67 69 73 74 65 72 65 64 20 77 69 74 68 20 61' },
      { name: 'utf16_registeredWithA', p: '72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 61 00' },
      { name: 'ansi_blockedClause', p: '68 61 73 20 62 65 65 6e 20 62 6c 6f 63 6b 65 64' },
      { name: 'utf16_blockedClause', p: '68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 62 00 6c 00 6f 00 63 00 6b 00 65 00 64 00' },
      { name: 'ansi_beAware', p: '42 65 20 61 77 61 72 65' },
      { name: 'ansi_serialNumber', p: '53 65 72 69 61 6c 20 4e 75 6d 62 65 72' },
      /* The LONG variant (with the clause). P7 sealed sub_468C60, yet a MessageBox owned by
       * IDMan.exe still shows the long wording => there must be a second reader/displayer.
       * These patterns locate the DECRYPTED long text wherever it lives (module .data or a
       * heap copy), which is the fallback identification path for P10. */
      { name: 'ansi_longClause', p: '6f 72 20 74 68 65 20 53 65 72 69 61 6c 20 4e 75 6d 62 65 72 20 68 61 73 20 62 65 65 6e 20 62 6c 6f 63 6b 65 64' },
      { name: 'utf16_longClause', p: '6f 00 72 00 20 00 74 00 68 00 65 00 20 00 53 00 65 00 72 00 69 00 61 00 6c 00 20 00 4e 00 75 00 6d 00 62 00 65 00 72 00' },
      { name: 'ansi_hasBeenRegistered', p: '68 61 73 20 62 65 65 6e 20 72 65 67 69 73 74 65 72 65 64' }
    ];
    var hits = [], scanned = 0, skipped = 0, ranges;
    try { ranges = Process.enumerateRanges('rw-'); } catch (e) { return { error: e.message }; }
    for (var ri = 0; ri < ranges.length && hits.length < maxMatches; ri++) {
      var r = ranges[ri];
      if (r.size > 64 * 1024 * 1024 || scanned > 300 * 1024 * 1024) { skipped++; continue; }
      scanned += r.size;
      for (var pi = 0; pi < pats.length && hits.length < maxMatches; pi++) {
        var m;
        try { m = Memory.scanSync(r.base, r.size, pats[pi].p); } catch (e) { continue; }
        for (var mi = 0; mi < m.length && hits.length < maxMatches; mi++) {
          var addr = m[mi].address;
          var wide = pats[pi].name.indexOf('utf16') === 0;
          var s = cstr(addr, wide, 700);
          var d = desc(addr);
          hits.push({
            pattern: pats[pi].name, addr: addr.toString(), mod: d.mod, rva: d.rva,
            wide: wide, text: s.text, byteLen: s.byteLen, err: s.err
          });
        }
      }
    }
    return { scannedBytes: scanned, skippedRanges: skipped, rangeCount: ranges.length,
             hitCount: hits.length, hits: hits };
  },

  /*
   * Dump every thread's stack and report 4-byte values that point into the target module.
   *
   * Use case: if a process is ALREADY blocked inside MessageBoxA, the call's return
   * address is still sitting on that thread's stack - so we can identify the call site
   * without reproducing anything. Each candidate is checked against the bytes 6/5 bytes
   * BEFORE it: if those form `FF 15`/`E8`, the value really is a post-call return address.
   */
  dumpThreadStacks: function (depthBytes) {
    depthBytes = depthBytes || 8192;
    var idm = getMod(CFG.idmModule);
    if (!idm) return { error: 'module ' + CFG.idmModule + ' not mapped' };
    var baseN = idm.base.toInt32() >>> 0;
    var endN = baseN + idm.size;
    var out = [];
    Process.enumerateThreads().forEach(function (t) {
      var rec = { id: t.id, name: t.name, state: t.state, candidates: [] };
      try {
        var ctx = t.context;
        if (!ctx) { rec.err = 'no context'; out.push(rec); return; }
        var sp = ctx.sp, pc = ctx.pc;
        rec.sp = sp.toString();
        rec.pc = pc.toString();
        rec.pcDesc = desc(pc).mod + '+' + desc(pc).rva;
        var buf = new Uint8Array(sp.readByteArray(depthBytes));
        for (var i = 0; i + 4 <= buf.length; i += 4) {
          var v = (buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24)) >>> 0;
          if (v >= baseN && v < endN) {
            var rva = v - baseN;
            var cand = { spOff: i, va: '0x' + v.toString(16), rva: '0x' + rva.toString(16) };
            try {
              if (rva >= 6) {
                var pre6 = new Uint8Array(idm.base.add(rva - 6).readByteArray(6));
                if (pre6[0] === 0xFF && pre6[1] === 0x15) {
                  cand.isReturnAfterIndirectCall = true;
                  cand.callTargetIat = '0x' + ((pre6[2] | (pre6[3] << 8) | (pre6[4] << 16) | (pre6[5] << 24)) >>> 0).toString(16);
                } else if (pre6[0] === 0xE8) {
                  cand.isReturnAfterDirectCall = true;
                }
              }
            } catch (e) {}
            rec.candidates.push(cand);
            if (rec.candidates.length >= 40) break;
          }
        }
      } catch (e) { rec.err = e.message; }
      out.push(rec);
    });
    return { module: CFG.idmModule, base: idm.base.toString(), size: idm.size, threads: out };
  },

  /*
   * Watch READ/WRITE access to the page holding a .data buffer (e.g. the long-version
   * ciphertext at RVA 0x37BED0). xref analysis claimed only sub_468C60 reads it, yet the
   * popup persists after P7 sealed that function - so the xref=1 claim is suspect and we
   * let the CPU tell us the truth.
   *
   * Deduplicated by accessing instruction address, with a hard cap, because .data can be
   * touched frequently.
   */
  watchDataPage: function (rva, maxUnique) {
    maxUnique = maxUnique || 60;
    var idm = getMod(CFG.idmModule);
    if (!idm) return { error: 'module ' + CFG.idmModule + ' not mapped' };
    var target = idm.base.add(rva);
    var pageBase = target.and(ptr('0xfffff000'));
    if (MEMWATCH.enabled) return { already: true, seen: Object.keys(MEMWATCH.seen).length };
    MEMWATCH.enabled = true;
    MEMWATCH.page = pageBase.toString();
    try {
      MemoryAccessMonitor.enable({ base: pageBase, size: 0x1000 }, {
        onAccess: function (d) {
          try {
            var from = d.from;
            var key = from.toString();
            if (MEMWATCH.seen[key]) { MEMWATCH.seen[key].count++; return; }
            if (Object.keys(MEMWATCH.seen).length >= maxUnique) { MEMWATCH.dropped++; return; }
            var dd = desc(from);
            MEMWATCH.seen[key] = {
              from: key, mod: dd.mod, rva: dd.rva,
              operation: d.operation, accessed: d.address.toString(),
              firstSeen: Date.now(), count: 1
            };
            emit({ type: 'hit', kind: 'memaccess', api: 'MemoryAccessMonitor', tid: -1,
                   from: dd, operation: d.operation, accessed: d.address.toString(),
                   accessedRva: d.address.sub(idm.base).toString(),
                   targetRva: '0x' + rva.toString(16) });
          } catch (e) { emit({ type: 'memwatch-error', err: e.message }); }
        }
      });
      emit({ type: 'hook-ok', api: 'MemoryAccessMonitor@0x' + rva.toString(16),
             addr: pageBase.toString() });
      return { enabled: true, page: pageBase.toString() };
    } catch (e) {
      MEMWATCH.enabled = false;
      emit({ type: 'hook-fail', api: 'MemoryAccessMonitor', err: e.message });
      return { error: e.message };
    }
  },

  memWatchReport: function () {
    var seen = [];
    for (var k in MEMWATCH.seen) seen.push(MEMWATCH.seen[k]);
    seen.sort(function (a, b) { return b.count - a.count; });
    return { enabled: MEMWATCH.enabled, page: MEMWATCH.page,
             unique: seen.length, dropped: MEMWATCH.dropped, accesses: seen };
  },

  /* Safety valve: MemoryAccessMonitor traps EVERY access to the page, so on a hot .data
   * page it can badly slow or destabilise the target. Exposed so a caller can back out. */
  stopWatchDataPage: function () {
    if (!MEMWATCH.enabled) return { already: false };
    try { MemoryAccessMonitor.disable(); } catch (e) { return { error: e.message }; }
    MEMWATCH.enabled = false;
    return { disabled: true };
  },

  /*
   * Read arbitrary module bytes by RVA - used to check runtime values of named globals,
   * e.g. byte_788CF4 (RVA 0x388CF4, the "licence valid" flag) and dword_788CCC
   * (RVA 0x388CCC, the HKCU-mode flag). Both live in .data (RVA 0x37B000..), and RVA =
   * VA - 0x400000, so pass the RVA - mixing VA and RVA here silently reads the wrong
   * bytes (the workspace's "address math" trap).
   */
  readModuleBytes: function (rva, len) {
    len = len || 1;
    var m = getMod(CFG.idmModule);
    if (!m) return { error: CFG.idmModule + ' not mapped' };
    var p = m.base.add(rva);
    var o = { rva: '0x' + rva.toString(16), va: p.toString(), len: len };
    try { o.hex = hexOf(p, len); } catch (e) { o.hexErr = e.message; }
    try { o.u8 = p.readU8(); } catch (e) {}
    try { o.u32 = p.readU32(); } catch (e) {}
    return o;
  },

  /*
   * Hardware write-watchpoint on a module global (e.g. dword_788CCC, RVA 0x388CCC).
   *
   * Verified API (Frida 17.15.3, discovered on a throwaway target):
   *   Thread.setHardwareWatchpoint does NOT exist module-level; it is a method on each
   *   thread object, and the accepted signature is (index, address, size, conditions)
   *   returning undefined. Therefore hits arrive as a debug exception, which we catch
   *   with Process.setExceptionHandler.
   *
   * x86 debug registers are PER-THREAD, so we arm index 0 on every thread and re-arm
   * periodically to cover threads created after arming. On the first hit we disarm
   * immediately (the lead's requirement) so the target is not slowed down.
   */
  armWriteWatch: function (rva, size) {
    var m = getMod(CFG.idmModule);
    if (!m) return { error: CFG.idmModule + ' not mapped' };
    if (WP.armed) return { already: true, addr: WP.addr ? WP.addr.toString() : null };
    var addr = m.base.add(rva);
    WP.addr = addr; WP.rva = rva; WP.size = size || 4; WP.hits = 0; WP.armedThreads = {};

    if (!WP.handlerInstalled) {
      Process.setExceptionHandler(function (details) {
        try {
          if (!WP.armed) return false;
          /* Only claim the watchpoint's own trap; anything else keeps default handling,
           * so we never swallow a genuine fault. */
          if (details.type !== 'single-step') {
            if (!WP.sawOther) { WP.sawOther = details.type; }
            return false;
          }
          var rec = {
            type: 'hit', kind: 'watchpoint',
            api: 'HW_WP@0x' + WP.rva.toString(16),
            tid: (details.threadId !== undefined) ? details.threadId : null,
            excType: details.type,
            pc: details.context ? details.context.pc.toString() : null,
            pcDesc: details.context ? desc(details.context.pc) : null
          };
          try { rec.valueAfter = WP.addr.readU32(); } catch (e) {}
          /* Capture the guard locals live. The store is guarded by
           *   cmp [ebp+0x1A00], esi ; jne skip
           *   mov eax,[ebp+0x19F4] ; cmp eax,6 ; jb skip
           *   mov [0x788CCC], edi   (edi is a hardcoded `mov edi,1`)
           * so reading them here tells us WHY the HKCU branch was taken. */
          try {
            var ctx = details.context;
            if (ctx && ctx.ebp) {
              rec.ebp = ctx.ebp.toString();
              try { rec.local19F4 = ctx.ebp.add(0x19F4).readU32(); } catch (e) {}
              try { rec.local1A00 = ctx.ebp.add(0x1A00).readU32(); } catch (e) {}
              try { rec.esi = ctx.esi.toUInt32(); } catch (e) {}
              try { rec.edi = ctx.edi.toUInt32(); } catch (e) {}
              try {
                rec.guard1_eq_esi = (rec.local1A00 !== undefined && rec.esi !== undefined)
                                    ? (rec.local1A00 === rec.esi) : null;
                rec.guard2_ge_6 = (rec.local19F4 !== undefined) ? (rec.local19F4 >= 6) : null;
              } catch (e) {}
            }
          } catch (e) {}
          try { rec.bt = bt(details.context); } catch (e) {}
          WP.hits++;
          emit(rec);
          disarmAll();          /* first hit only */
        } catch (e) { emit({ type: 'wp-error', err: e.message }); }
        return true;
      });
      WP.handlerInstalled = true;
    }

    armAll();
    WP.armed = Object.keys(WP.armedThreads).length > 0;
    /* re-arm for threads born after this point */
    if (WP.rearm) { try { clearInterval(WP.rearm); } catch (e) {} }
    WP.rearm = setInterval(function () {
      if (!WP.armed) { try { clearInterval(WP.rearm); } catch (e) {} return; }
      armAll();
    }, 200);
    return { armed: WP.armed, addr: addr.toString(),
             threads: Object.keys(WP.armedThreads).length, errors: WP.errors };
  },

  disarmWriteWatch: function () { disarmAll(); return { hits: WP.hits }; },

  watchStatus: function () {
    return { armed: WP.armed, addr: WP.addr ? WP.addr.toString() : null,
             threads: Object.keys(WP.armedThreads || {}).length, hits: WP.hits,
             sawOtherExceptionType: WP.sawOther || null };
  }
};

/* ---- hardware watchpoint state ---- */
var WP = { armed: false, addr: null, rva: 0, size: 4, hits: 0, armedThreads: {},
           errors: [], handlerInstalled: false, rearm: null, sawOther: null };

function armAll() {
  if (!WP.addr) return;
  Process.enumerateThreads().forEach(function (t) {
    var k = String(t.id);
    if (WP.armedThreads[k]) return;
    try {
      t.setHardwareWatchpoint(0, WP.addr, WP.size, 'w');
      WP.armedThreads[k] = true;
    } catch (e) {
      if (WP.errors.length < 5) WP.errors.push({ tid: t.id, err: e.message });
    }
  });
}

function disarmAll() {
  WP.armed = false;
  if (WP.rearm) { try { clearInterval(WP.rearm); } catch (e) {} WP.rearm = null; }
  Process.enumerateThreads().forEach(function (t) {
    try { t.unsetHardwareWatchpoint(0); } catch (e) {}
  });
  WP.armedThreads = {};
}

/* ---------------- boot ---------------- */
installAll();
var poll = setInterval(function () {
  if (!installed) installAll();
  ensureWrapper();
  ensureNet();
  ensureCallSite();
  ensureReg();
  ensureDisplay();
  ensureExtras();
  if (installed && wrapperHooked && netState.wininet && netState.ws2_32 && callSiteHooked) clearInterval(poll);
}, CFG.pollMs);
setTimeout(function () { clearInterval(poll); }, 120000);
setInterval(function () {
  if (!installed) installAll();
  ensureWrapper();
  ensureNet();
  ensureCallSite();
  ensureReg();
  ensureDisplay();
  ensureExtras();
  emit({ type: 'heartbeat', installed: installed, wrapperHooked: wrapperHooked,
         callSiteHooked: callSiteHooked, regHooked: regHooked, displayHooked: displayHooked,
         extraCount: Object.keys(extraHooked).length,
         netHooked: netState, pid: Process.id,
         threads: Process.enumerateThreads().length,
         modules: Process.enumerateModules().length, counters: COUNTERS });
}, CFG.heartbeatMs);
