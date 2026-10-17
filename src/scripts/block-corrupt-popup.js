// block_corrupt.js —— 拦截 "IDM is corrupt" 弹窗（直接返回，不显示）
'use strict';
var HITS = 0;
var BLOCK_TITLES = ["corrupt", "IDM is corrupt"];

function looksBad(s) {
    if (!s) return false;
    var t = String(s).toLowerCase();
    for (var i = 0; i < BLOCK_TITLES.length; i++) {
        if (t.indexOf(BLOCK_TITLES[i].toLowerCase()) >= 0) return true;
    }
    return false;
}

function install(name, isWide) {
    var addr = Module.findGlobalExportByName ? Module.findGlobalExportByName(name) : Module.getExportByName("user32.dll", name);
    if (!addr) { send({t:"miss", api:name}); return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.block = false;
            try {
                var title = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                var text  = isWide ? args[3].readUtf16String() : args[3].readAnsiString();
                if (looksBad(title) || (text && text.toLowerCase().indexOf("executive file is damaged") >= 0)) {
                    this.block = true;
                    HITS++;
                    send({
                        t: "block",
                        api: name,
                        title: title,
                        text: (text || "").substring(0, 200),
                        hits: HITS,
                        bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                              .map(function (a) {
                                  var m = Process.findModuleByAddress(a);
                                  return m ? (m.name + "+0x" + a.sub(m.base).toString(16)) : a.toString();
                              }).slice(0, 12)
                    });
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.block) { retval.replace(1); }   // IDOK
        }
    });
    send({t:"installed", api:name});
}

install("MessageBoxW", true);
install("MessageBoxA", false);
send({t:"ready"});
