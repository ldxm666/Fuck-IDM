// hook_corrupt.js —— 抓 "IDM is corrupt" 弹窗的创建点
'use strict';

function sym(addr) {
    try {
        var s = DebugSymbol.fromAddress(addr);
        return s.name ? (s.moduleName + '!' + s.name + '+0x' + (addr.sub(s.address).toInt32().toString(16))) : addr.toString();
    } catch (e) { return addr.toString(); }
}
function bt(ctx, n) {
    try {
        var frames = Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n || 14);
        return frames.map(function (a, i) { return '    #' + i + ' ' + sym(a); }).join('\n');
    } catch (e) { return '    <bt failed: ' + e + '>'; }
}
function readStr(p, wide) {
    if (p.isNull()) return '<null>';
    try { return wide ? p.readUtf16String() : p.readAnsiString(); } catch (e) { return '<unreadable>'; }
}

var u32 = Process.getModuleByName('user32.dll');
var hooked = [];

[['MessageBoxW', true], ['MessageBoxA', false]].forEach(function (pair) {
    var name = pair[0], wide = pair[1];
    var addr = u32.getExportByName(name);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var text = readStr(args[1], wide) || '';
            var cap = readStr(args[2], wide) || '';
            console.log('\n===== ' + name + ' =====');
            console.log('  caption: ' + JSON.stringify(cap));
            console.log('  text   : ' + JSON.stringify(text.slice(0, 200)));
            console.log('  uType  : 0x' + args[3].toInt32().toString(16));
            console.log('  backtrace:');
            console.log(bt(this.context, 16));
        }
    });
    hooked.push(name);
});

[['DialogBoxParamW', true], ['CreateDialogIndirectParamW', true]].forEach(function (pair) {
    var name = pair[0];
    var addr = u32.getExportByName(name);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log('\n===== ' + name + ' =====');
            console.log('  hInstance=' + args[0] + '  lpTemplate=' + args[1] + '  hWndParent=' + args[2]);
            console.log('  lpDialogFunc=' + args[3]);
            console.log('  backtrace:');
            console.log(bt(this.context, 16));
        }
    });
    hooked.push(name);
});

// 窗口创建：抓 #32770 且标题含 corrupt 的
var addrCEW = u32.getExportByName('CreateWindowExW');
Interceptor.attach(addrCEW, {
    onEnter: function (args) {
        var cls = readStr(args[1], true) || '';
        var title = readStr(args[2], true) || '';
        if (cls.indexOf('32770') >= 0 || /corrupt/i.test(title)) {
            console.log('\n===== CreateWindowExW (' + cls + ') =====');
            console.log('  title: ' + JSON.stringify(title));
            console.log('  backtrace:');
            console.log(bt(this.context, 16));
        }
    }
});
hooked.push('CreateWindowExW');

console.log('[hook] attached: ' + hooked.join(', '));
console.log('[hook] waiting for corrupt popup ...');
