# T7 动态探针 — IDM 6.43b15 counterfeit 弹窗定位

> 归属：task-6（owner `prober`）。写范围：`.agent_work/scripts/idm_probe/**`、`.agent_work/logs_and_dumps/idm/probe/**`。
> 目标：动态抓出用户那条 counterfeit 弹窗（标题 `Internet Download Manager`、正文英文、按钮**确定+取消**）的**真实调用点**。

## 一、文件

| 文件 | 作用 |
| --- | --- |
| `idm_popup_probe.js` | Frida 探针（27 个 hook）。全家族弹窗 API + 文本落点 + 网络 + IDM 私有 wrapper |
| `run_probe.py` | 驱动：spawn / attach / **watch-attach**、JSONL 落盘、自证、死亡早退、周期内存扫描 |
| `watch_dialogs.ps1` | 1s 轮询窗口枚举旁证（不依赖 hook），抓 `#32770` 的 TITLE+BODY+BUTTONS |
| `watch_procs.ps1` | 进程创建 + **完整命令行** + 父进程 pid 捕获（定位「谁拉起谁」） |
| `watch_hosts.ps1` | hosts 四元组（sha/行数/生效数/lastWrite）变更监控 |
| `hosts_toggle.ps1` | **H2 对照实验专用** hosts 开关（幂等 + 自动备份 + flushdns）。**未授权不得运行** |

## ★ 结论（见 `../logs_and_dumps/idm/probe/FINDINGS.md`）

弹窗来自 **`IDMGrHlp.exe`**（独立进程，非 `IDMan.exe`），调用点 **RVA `0x5EC9` / 文件偏移 `0x52C8`**，
`uType=0x1031`(MB_OKCANCEL)，正文为**无从句版**。
⇒ 只 hook `IDMan.exe` 永远抓不到它（这正是第一轮 930s `mbox:0` 的原因）。

## 二、怎么跑（**必须提权**：pwsh 是 Low IL，注入中完整性进程会被拒）

```powershell
# 模式 A：spawn 目标并全程观测
& $py run_probe.py --exe '<exe>' --cwd '<dir>' --script idm_popup_probe.js `
  --log <probe>\raw.jsonl --duration 930 --mode spawn --selftest-mode ping --scan-interval 120

# 模式 B：等某个进程出现后立刻 attach（用于 IDMGrHlp.exe 这类按需拉起的助手进程）
& $py run_probe.py --mode watch-attach --watch-name 'IDMGrHlp.exe' --watch-timeout 620 `
  --target-module 'IDMGrHlp.exe' --script idm_popup_probe.js `
  --log <probe>\grhlp_raw.jsonl --duration 180 --selftest-mode ping

# 模式 C（★最可靠）：用捕获到的命令行自己 spawn，hook 先于目标第一条指令
& $py run_probe.py --mode spawn --exe '<dir>\IDMGrHlp.exe' --exe-args '/ch 3 /w 0' `
  --target-module 'IDMGrHlp.exe' --script idm_popup_probe.js --log <probe>\spawn.jsonl --duration 75
```

> `--target-module` 会重写 `CFG.idmModule`，并在目标不是 `IDMan.exe` 时**自动关闭** IDMan 专属的
> wrapper / `.data` globals hook（`wrapperRva: 0`），避免在别的二进制上挂错地址。

`--selftest-mode ping`（默认）是**唯一**对 IDM 安全的自证方式，见 §四。

## 三、hook 清单（27）

| 组 | API |
| --- | --- |
| MessageBox 家族 | `MessageBoxA/W`、`MessageBoxExA/W`、`MessageBoxIndirectA/W`、`MessageBoxTimeoutA/W`、`SoftModalMessageBox` |
| 对话框创建 | `DialogBoxParamA/W`、`DialogBoxIndirectParamA/W`、`CreateDialogParamA/W`、`CreateDialogIndirectParamA/W`、`EndDialog`、`TaskDialogIndirect` |
| 命令通道 | `PostMessageA/W`（`msg==0x111 && wParam==0x1509` 全记录；其余 `WM_COMMAND` 只记轻量行） |
| **文本落点（H2）** | `SetDlgItemTextA/W`、`SetWindowTextA/W`、`SendDlgItemMessageA/W`（仅 `WM_SETTEXT=0xC`） |
| **网络（H2）** | `wininet!InternetConnectA/W`、`HttpOpenRequestA/W`、`InternetReadFile`、`ws2_32!recv` |
| IDM 私有 | `IDMan.exe!sub_474D20`（弹窗包装，RVA `0x74D20`） |

`SendMessageA/W` **故意不挂**：最热路径 + 重入嫌疑，见 §四。

## 四、⚠️ 实测事故：探针曾把 IDM 打崩（已定位并改设计）

第一次实跑（15 点旧二进制，2026-10-17 02:49:38 spawn）：

```
02:49:53  异常代码 0x80000026   出错模块 unknown
02:49:58  出错模块 frida-agent.dll  异常代码 0xc000041d  偏移 0x00c2a292  pid 0xAC20(44064)
```

- 崩溃时刻与我触发的**模态自测 MessageBox**（`CreateThread` + `MessageBoxTimeoutW`）**同一秒**。
- **注册表无 `MData`** ⇒ 不是 counterfeit tripwire，是**注入侧崩溃**。
- 该轮 15s 内**未**捕获任何 `PostMessageA wParam=0x1509`，也未捕获 IDMan.exe 发出的任何 MessageBox。

**据此的设计变更（勿回退）**：
1. **禁止模态自测**：改为 `PostMessageA(0, 0x7FFF, 0xdead, 0)` —— 非阻塞、无新线程、无窗口。
2. 追加 `SetWindowTextA(0, "…fake Serial Number…")` 自证文本落点链（`Interceptor` 在 API 校验参数**之前**触发，故传 `hwnd=0` 也能命中且零副作用）。
3. 摘掉 `SendMessageA/W`。
4. 驱动加**死亡早退**（连续 3 次 tick 不存活即停，不再空转 15 分钟）。

## 五、自证（探针确实工作的原始证据）

一次性目标 `cmd.exe` 冒烟：

```
{"type":"hit","api":"user32.dll!PostMessageA","kind":"ping","msg":"0x7fff","wParam":"0xdead"}
{"type":"hit","api":"user32.dll!SetWindowTextA","kind":"textsink","text":"PROBE SELFTEST fake Serial Number liveness","textByteLen":42}
{"type":"heartbeat","netHooked":{"wininet":false,"ws2_32":true},"counters":{"textsink":1,"textsinkEmitted":1,...}}
```

窗口枚举旁证（独立于 hook）：

```
hwnd=0x580FBE class=#32770 visible=True pid=19224 proc=cmd
  title=[PROBE SELFTEST]
  child=[Button|确定]  child=[Button|取消]  child=[Static|PROBE SELFTEST BODY ...]
```

⇒ 实测确认 **`MB_OKCANCEL`(uType=1) 在本机中文环境按钮就是「确定/取消」**。
这条把「用户截图 = 双按钮 = MB_OKCANCEL」钉死，也就说明静态那些 `push 6a 00`(MB_OK) 的候选点与实证矛盾。

## 六、★ 候选地址修正（重要，否则判据永不命中）

Lead 给的候选是**call 指令地址**，而 hook 记录的是 `this.returnAddress`（call **之后**那条指令）。
已读实机二进制逐字节验证：

| call 处 VA | 字节 | 目标 | **return addr** | return RVA |
| --- | --- | --- | --- | --- |
| `0x523AE1` | `E8 3A 12 F5 FF` | `0x474D20` ✓ | `0x523AE6` | `0x123AE6` |
| `0x521157` | `E8 C4 3B F5 FF` | `0x474D20` ✓ | `0x52115C` | `0x12115C` |
| `0x523BD0` | `E8 4B 11 F5 FF` | `0x474D20` ✓ | `0x523BD5` | `0x123BD5` |
| `0x468D01` | `68 11 01 00 00` + `FF 15 CC 57 69 00` | push `WM_COMMAND` + `call PostMessageA` ✓ | `0x468D07` | `0x68D07` |

探针的 `CANDIDATES` 表已按 **return RVA** 建键，命中时输出 `candidate` 字段。

## 七、H1 / H2 判定的三个独立手段

1. **hook 侧**：`MessageBoxW/A` 的 `ret` + 标题 + 正文原文 + `uType`（含 `bodyByteLen`）。
2. **直接读 `.data` 密文串**（`readGlobals`，RVA `0x37BEB0`/`0x37BED0`，`sub_468C60` 用 XOR `0x0F` 就地解密）→ 看运行期明文含不含从句。
3. **可写内存扫描**（`scanStrings`）→ 找 `fake Serial Number` 的 ANSI/UTF-16 变体，能同时覆盖「本地另一份变体」与「服务端下发后被存下来的副本」。

## 八、结果解读纪律

报「未复现」时必须同时给出：①hooks 已装且工作的自证（`hook-ok` 全表 + `kind:"ping"`/`textsink` + `heartbeat.counters`）；②本轮 hosts 状态（`hosts_toggle.ps1 -Mode status`）；③IDM 存活时长；④是否有任何 `PostMessageA 0x1509` / `MessageBox*` / 网络响应。
缺任何一项即视为证据不完整。
