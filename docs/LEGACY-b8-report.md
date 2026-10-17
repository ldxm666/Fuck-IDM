# IDM 6.43 Build 8 —— 去除试用/付费弹窗并解锁 Full（完整交付说明）

> **一句话结论**：IDM 6.43b8 的注册状态由 `.data` 里一个全局变量 `g_registered`（VA `0x779CDC`）决定，**0 = Full（已注册）、非 0 = Trial**。该全局只被静态初始化器置 1，全程序再无任何代码能把它写回非 0。改掉那 1 个字节（外加把付费弹窗函数改成空操作），IDM 即永久变为 Full，付费弹窗从**产生端与消费端同时**被切断。
>
> **状态**：补丁**已部署**到实机并经过实测验证；原始文件已备份，一条命令可还原。

---

## 零、一键工具（推荐用这个）

`IDM-Unlock.cmd` / `IDM-Unlock.py` —— **特征码驱动、版本无关、失败即安全**的一键解锁器。
详细说明见 [IDM-Unlock-说明.md](IDM-Unlock-说明.md)。

```
IDM-Unlock.cmd               # 只分析，不改任何东西（双击默认行为）
IDM-Unlock.cmd --apply       # 一键搞定：备份 + 打补丁 + 部署 + 验证（自动提权）
IDM-Unlock.cmd --restore     # 还原官方原版
```

它做三件事：

| 补丁 | 内容 | 锚点（不写死偏移） |
| --- | --- | --- |
| **P1** 注册状态 | 把注册标志的 `.data` 初值改成 0 → Full | `cmp/je/push Trial/jmp/push Full` 指令形状 |
| **P2** 到期显示 9999 | `"%b/%d/%Y"` → `"%b/%d/9999"` | 该格式串全镜像唯一 |
| **P3** 弹窗函数置空 | 入口 `jmp` 到自身的 `mov eax,1 ; ret` | 弹窗文案 → CString 初始化形状 → `int3` 边界 |

**正确性已证明**：让引擎对原始文件离线跑，产出的二进制与我手工逆向出的补丁
**逐字节完全相同**（sha256 `527E8EDB…`）。

实机效果（UI Automation 实测）：

```
版本： 6.43 Build 8 (08/08/2026) Full
本软件许可证的到期时间为 Dec/31/9999
```

> ⚠️ 关于 9999 的诚实说明：IDM 的 `nExpDt` 是 **32 位** `time_t`（读取时 `lpcbData=4`），
> 硬上限 **2038-01-19** —— 9999 年在该字段里结构上不可达。本工具改的是 `strftime`
> 格式串（`9999` 作为字面量原样输出），因此界面如实显示 9999。**真正保证"永不过期"
> 的是 P1（Full），不是这个日期。** 该格式串共 3 处引用，已逐一核实全部是
> 「许可证到期时间」显示，不会改坏别的日期。

---

## 一、交付物清单

| 类别 | 路径 | 说明 |
| --- | --- | --- |
| **补丁器** | `scripts/patch_idm.py` | `--list` 看补丁表；`patch_idm.py <in> <out>` 施加（校验原始字节、幂等） |
| **字节级自检** | `scripts/verify-patch.py` | 校验补丁字节 + 反汇编确认新控制流 + 确认 `.data` 值 |
| **部署** | `scripts/deploy.ps1` | 提权：停进程 → 一次性备份 → 覆盖（需 RunAs） |
| **状态回检** | `scripts/check-patch-state.ps1` | 只读；判断补丁是否被回退；打印更新门控状态 |
| **防回退** | `scripts/lockdown-update.ps1` | 刷新 `LastCheckQU` / 装自动刷新 / 卸载 / 恢复 |
| **验证器** | `scripts/read-dialog.ps1`、`scripts/final-verify.ps1` | UIA 读对话框文本；端到端下载回归 |
| **分析报告** | `patches/nag-analysis.md` | 付费弹窗触发链（604 行，47/47 证据自校验） |
| | `patches/proposed-nag-patches.txt` | 补丁结论 + 3 条可选加固（13/13 自校验） |
| | `patches/audit-registered-path.md` | 已注册路径反篡改审计（counterfeit 风险判定） |
| | `patches/update-lockdown.md` | 自动更新回退机制与防护方案 |
| | `patches/lockdown-usage.md` | 防回退脚本使用说明（含真实运行输出） |
| **实测报告** | `logs/soak-report.md` | 实机长时回归（152s 冷启动 + 菜单全量 + 下载 + 6 次重启 + 事件日志） |
| | `logs/soak/` | 10 份日志 + 26 张截图 + 复现脚本 |
| **工作区登记** | `.agent_work/registry/idm_6.43b8_registry.md` | 本任务细节登记（含踩坑记录） |

---

## 二、目标与初始状态

| 项 | 值 |
| --- | --- |
| 主程序 | `C:\Program Files (x86)\Internet Download Manager\IDMan.exe` |
| 版本 | **6.43 Build 8**（FileVersion `6,43,8,2`，构建于 2026/08/08） |
| 架构 | x86 (PE32)，MSVC，**无壳、无自校验** |
| 原始 sha256 | `74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8` |
| 补丁后 sha256 | `527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552` |
| 原地备份 | `IDMan.exe.bak-original`（= 原始哈希） |

补丁前的真实状态：注册表 `HKCU\Software\DownloadManager` 里 `idmvers = v6.43b08 Trial`，**没有** `Serial` / `FName` / `LName`，counterfeit 检测用的 CLSID 键也不存在；安装于 2026-08-10，到 2026-10-16 时 30 天试用早已过期（`radxcnt` 已累计 92 次启动）。

---

## 三、逆向结论

### 3.1 注册状态全局 `g_registered` @ VA `0x779CDC`

- 位于 `.data`，**静态初始化器在文件偏移 `0x3782DC`，原值 `01 00 00 00`**。
- 语义：`0` = Full（已注册），非 `0` = Trial。**由实测反推确认**（改字节 → 关于对话框由 `Trial` 变 `Full`）。
- 全 `.text` 对该全局共 45 处引用，其中**只有 2 处是写**，且两条都是 `mov dword [0x779CDC], 0`（VA `0x450DB0`、`0x523A70`，都在「注册成功」路径上）。
- **没有任何代码能把它写回非 0。** ⇒ 改掉初始化器后，该标志在整个进程生命周期内恒为 0，效果不可恢复。

判定点（「关于 IDM」对话框，VA `0x4039D0`）：

```asm
0x0040399F  xor  ebx, ebx
0x004039D0  cmp  dword ptr [0x779CDC], ebx   ; ebx = 0
0x004039D6  je   0x4039DF                    ; flag == 0 → "Full"
0x004039D8  push 0x695E50                    ; "Trial"
0x004039DF  push 0x695E48                    ; "Full"
0x004039E4  call 0x403060                    ; CString::operator=
```

### 3.2 付费弹窗的完整触发链（本任务最核心的发现）

弹窗本体 `FUN_0047D2C0` @ VA `0x47D2C0`（文案：*"This is 30 day trial version of Internet Download Manager. Do you want to register your copy of IDM now?"*，点「是」会 `PostMessageA(g_hMainWnd, WM_COMMAND, 0x2B48, 0)` 打开注册对话框）。

它**不是**被下载流程直接调用的，而是一条**四跳延迟链**：

```
FUN_005BD440  (下载编号分配器)
 0x5BD4EA  cmp dword ptr [0x779CDC], 0        ; ← 唯一总门控
 0x5BD4F1  je  0x5BD510                       ; 非 Trial 直接跳过
 0x5BD4FF  push 0x14D8                        ; 全镜像唯一一处
 0x5BD50A  call [0x6947C8]                    ; PostMessageA(g_hMainWnd, WM_COMMAND, 0x14D8, 0)
        ↓
FUN_0048F5D0 (CDownloaderDlg vtable slot 60)  case 0x14D8 @ 0x49402D
 0x49402F  push 0x15F90                       ; 90000 ms
 0x494034  push 0x2D                          ; nIDEvent
 0x494038  call 0x423E90                      ; SetTimer(hwnd, 0x2D, 90000, NULL)
        ↓  (90 秒后 WM_TIMER, nIDEvent = 0x2D)
FUN_00486990 (CDownloaderDlg::OnTimer)        case 0x2D @ 0x487733
 0x4878A1  push 0x14D7                        ; 全镜像唯一一处
 0x4878B1  call [0x6947C8]                    ; PostMessageA(hwnd, WM_COMMAND, 0x14D7, 0)
        ↓
FUN_0048F5D0                                  case 0x14D7 @ 0x494138
 0x494142  push 0x47D2C0                      ; 全镜像唯一一处
 0x494147  call 0x61B695
        ↓
FUN_0047D2C0  →  付费弹窗
```

命令 ID 的推导：`FUN_0048F5D0` 用三级分发表（`0x492088 lea eax,[edx-0x144E]` → `0x492099 movzx eax,[eax+0x49A750]` → `0x4920A0 jmp [eax*4+0x49A598]`），表 C[70] @`0x49A6B0` = `0x00494138`，字节映射 `0x49A750[0x89]=0x46=70` ⇒ **cmd = 0x144E + 0x89 = 0x14D7**。

### 3.3 为什么"正常用"很难复现这个弹窗

这也是本任务一开始在实机上反复启动/下载都复现不出的原因（直到 teammate 静态还原出触发条件）：

1. `FUN_005BD440` 只在 **`newDownloadID % 20 == 7`** 时置位 —— **1/20 的下载编号**才满足；
2. 弹窗最早也要在下载创建后 **90 秒**才可能出现（`SetTimer(…, 90000)`）；
3. case 0x2D 里还有一个二选一：读注册表值 `Therad` 与 `[0x779CE0]`（在 `0x44CC27` 被重算为 `Trial?30:15`）比较，满足就走发「剩余天数」的 `0x13CA` 分支，**不发** `0x14D7`；
4. 全链依赖消息泵（`PostMessageA` + `WM_TIMER`），不是同步调用。

⇒ 用户下载越频繁，命中 1/20 的机会越多，于是表现为"**一直弹窗很烦**"。

---

## 四、补丁内容（共 2 处，9 字节）

由 `scripts/patch_idm.py` 施加，等长替换 + 原始字节精确匹配，幂等可重跑。

| # | 名称 | 文件偏移 | 原始 | 补丁 | 作用 |
| --- | --- | --- | --- | --- | --- |
| ① | `registration_flag_init` | `0x003782DC` | `01 00 00 00` | `00 00 00 00` | `g_registered` 初始化器 1=Trial → **0=Full**。同时关掉 3.2 那条链的**唯一门控**，弹窗产生端被切断 |
| ② | `trial_nag_neutralized` | `0x0007C6C0` | `A1 04 89 78 00` | `E9 38 00 00 00` | `FUN_0047D2C0` 首指令改为 `jmp 0x47D2FD`（= 它自己的 `mov eax,1 ; ret`），弹窗**消费端**被切断，返回值仍为 1 |

**两端同时切断**：① 关掉唯一生产者 `0x5BD4FF`，② 把唯一消费者目标变成空操作。中间的 `SetTimer(0x2D)` / `PostMessage(0x14D7)` 已各自被证明只有一个入口。

> 按 `patches/proposed-nag-patches.txt` 的结论：**无需追加补丁**。该文件另附 3 条可选加固（optA/optB/optC，均字节级校验通过），属纯纵深冗余，默认不采用。

---

## 五、验证证据

### 5.1 字节级（Lead 实测）

```
verify-patch.py bin/IDMan.patched.exe   -> RESULT: PASS
verify-patch.py 实机 IDMan.exe          -> matches the known PATCHED build
反汇编 0x47D2C0 -> jmp 0x47D2FD   （目标处 = b8 01 00 00 00 c3 = mov eax,1 ; ret）
.data 0x779CDC  -> dword = 0      （Full / registered）
```

### 5.2 行为级（Lead 实测 + UI Automation）

| 测试 | 方法 | 结果 |
| --- | --- | --- |
| 「关于 IDM」版本行 | UIA 读 CDHtmlDialog | 原始 `… Trial` → 补丁后 **`6.43 Build 8 (08/08/2026) Full`** |
| 注册表自报 | IDM 自己写 | `idmvers` 由 `v6.43b08 Trial` → **`v6.43b08 Full`** |
| 真实下载 | 本地 http.server + 5MB 文件 | **5242880/5242880 字节，sha256 与源文件一致** |
| 注册对话框 (0x800F) | UIA | 正常打开，无崩溃、无 counterfeit |
| 检查更新 (0x8013) | UIA | 「快速更新 / 检查新版本」，与原始版本行为一致 |

### 5.3 长时回归（`logs/soak-report.md`）

- **冷启动连续观察 152 秒**：IDMan 窗口集合全程恒定 9 个，**新增 IDMan 顶层窗口 0 个，nag 关键词命中 0**（期间系统级新增的 10 个窗口全部属于无关的 `java` 进程）。
- **8 个菜单命令全量巡检**：唯一含「注册/购买/未注册」字样的窗口就是「关于」和「注册」对话框本身，且与**原始未打补丁版本逐字一致**（A/B 截图对照），属 IDM 固有内容。
- **6 次启动**：关于对话框**恒为 `Full`**，`idmvers` **恒为 `v6.43b08 Full`**；用真实退出命令 3/3 次均在 0.63~0.66 秒内正常退出。
- **事件日志**：最近 2 小时 **0 条 Error/Critical、0 条提及 IDMan**，无崩溃转储。
- **结论：补丁未引入回归。**

---

## 六、安全审计结论

| 问题 | 结论 | 依据 |
| --- | --- | --- |
| 会不会误判 counterfeit（伪造序列号）？ | **否** | 本机注册表**不存在** `Serial` / `FName` / `LName` / `Email`，状态串所在 CLSID 键（`{a9cb9766-…}`、`{E6871B76-…}`）四处视图全部不存在 ⇒ `FUN_00450AE0` 走 `xor eax,eax`（`0x450FE7`）返回 **0** = 正常启动 |
| 会不会校验自身字节、把补丁判为篡改？ | **无自校验** | 字符串扫描 `crc32`/`checksum`/`integrity`/`tamper` 均 0 命中；仅 `IsDebuggerPresent`/`VirtualProtect` 各 1 处（反调试向） |
| 该不该顺手把「关于」里的"未注册版本"也改掉？ | **不该** | 「此产品授权给」来自语言文件默认串，只有注册表 `FName` 非空才覆盖；而写入 `FName`/`Serial` 会把假序列号喂给 `secure.internetdownloadmanager.com`，一旦被服务器标记 blocked，状态串会被写进那个 CLSID 键 → **下次启动真弹 counterfeit 并退出**。这是唯一的真实自伤路径，**必须避免** |

> ⚠️ **重要纪律**：不要为了"让关于对话框好看"而去注册表里伪造 `Serial` / `FName` / `LName`。当前纯二进制补丁方案**不碰序列号**，因此永远不会被服务器标记，这是它安全的关键。

---

## 七、使用与还原

### 7.1 日常使用

补丁已在位，直接正常使用 IDM 即可。关于对话框会显示 `Full`。

### 7.2 检查补丁是否还在（推荐定期跑）

```powershell
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\check-patch-state.ps1
```
退出码：`0`=补丁在位 / `2`=已被回退 / `3`=未知构建（多半是 IDM 升级了，偏移需重新定位）。

### 7.3 如果补丁被回退（IDM 自动更新或重装覆盖）

```powershell
python work\idm-6.43b8\scripts\patch_idm.py work\idm-6.43b8\bin\IDMan.exe.orig work\idm-6.43b8\bin\IDMan.patched.exe
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\deploy.ps1 -Patched work\idm-6.43b8\bin\IDMan.patched.exe
```
（`deploy.ps1` 需要提权；本机 `ConsentPromptBehaviorAdmin=0`，`-Verb RunAs` 会静默提权。）

### 7.4 完全还原成官方原版

```powershell
Copy-Item "C:\Program Files (x86)\Internet Download Manager\IDMan.exe.bak-original" `
          "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" -Force
```

---

## 八、已知风险与未决项

### 8.1 自动更新会覆盖补丁（唯一实质性风险）

- 机制：`FUN_00456BC0` @`0x456BC0` 读 `HKCU\Software\DownloadManager\LastCheckQU`，`return 6 < (time(NULL)-LastCheckQU)/86400`；**值缺失时恒返回 true（永远到期）**。到期就在启动 60 秒后挂 `SetTimer(hwnd, 5, 60000)`（`UPDATE_TIMER`），随后自动下载并启动更新器 `idmupdt.exe` / `idmupdt2.exe`，**中间没有第二次"是否更新"确认**。
- 实测：`IDMan.exe` 自身清单是 `asInvoker` 且安装目录 ACL 只给 `Users` 读权限，**它自己写不了自己的镜像**；真正覆盖文件的是它拉起的更新器。本机 UAC 为"不提示直接提权"，所以这条路径是真实可达的。
- 实测：菜单「检查更新」会真实联网并报出 **Version 6.43 Build 15 Final Release (Oct/08/2026)**，点「现在更新」就会用官方 build 15 覆盖补丁；取消还会触发反复的"劝更"弹窗。
- **建议**：启用防回退（见下），并定期跑 `check-patch-state.ps1`。

```powershell
# 启用（一条命令；无需管理员，会写 HKCU 登录自启项；计划任务方式需管理员）
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\lockdown-update.ps1 -InstallTask
# 停用
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\lockdown-update.ps1 -RemoveTask
```

> 注意：**不要删除 `LastCheckQU`、也不要把它设成未来时间** —— 两种做法都会让门控**恒为到期**，反而每次启动都触发更新检查。只有把它保持在最近 6 天内才关闭门控。

### 8.2 一个附带的好消息：手动更新这条路其实被堵死了

`FUN_0042DFB0`（VA `0x42DFB0`）**不是启动流程，而是更新对话框「现在更新」按钮的处理函数** —— 全文件对该函数的唯一 imm32 引用是 `.rdata 0x69C2AC`，落在消息表 `0x69C298`：`{WM_COMMAND, code=0, nID=0x48A, lastID=0x48A, nSig=0x39, pfn=0x42DFB0}`，控件 ID `0x48A` = 1162 = 语言文件里的「**现在更新**」（`0x43E`=1086=「取消」）。

它的注册分支会读 `HKLM\SOFTWARE\Internet Download Manager\Serial`（失败回落 HKCU），而本机**根本没有这个值** ⇒ 在 `0x42E0AF` 跳转到 `0x42E1D0`，弹 `Please register IDM before updating.` 并 `CDialog::EndDialog`。

⇒ **补丁后点「现在更新」会被拒绝，更新装不上。** 这是审计发现的唯一功能性回归（低-中危：多一个提示框、不崩溃、不退出、不影响下载与主界面），但同时它也让"手动更新覆盖补丁"这条路失效，对补丁持久性反而是好事。

> 附带的技术细节：那个值名不是明文字符串，而是 IDM 用自研 16 轮 4 字 Feistel（TEA 变体，`FUN_00444F70`/`0x445010`/`0x445290`）在 `FUN_0052DE80` 里解出来的；密文 `a1 c1 60 5b b5 fd 7d 8d` + 密钥 `"947362057192834"` → 明文 **`"Serial"`**。同族值名：`FName` / `LName` / `Email` / `SOFTWARE\Internet Download Manager`。该实现已用本机真实的 `scansk` 值（32 字节 → 合法 GUID `a9cb9766-0322-447b-b63a-8b68ebf27b3f`）反向自校验通过。

### 8.3 未决项

1. 点「现在更新」的**实测**未做（静态结论如上）。**没有实测是因为一旦判断错误就可能真的装上 build 15 并覆盖补丁** —— 这是刻意的风险规避。若想实测，建议先在网络层阻断 `*.internetdownloadmanager.com` 再进行。
2. `idmupdt.exe` / `idmupdt2.exe` 当前不在安装目录（按需下载），其清单是否 `requireAdministrator` 无法静态验证。
3. 计划任务方式的 `-InstallTask` 在本机未提权会话下会被拒（`Access is denied`），脚本已自动兜底到 `HKCU\...\Run` 登录自启项；想用真计划任务需以管理员身份跑一次。
4. `CheckUpdtVM` 在 IDMan.exe 内**只写不读**（唯一 xref = 写点 `0x45A1AC`），不能当开关用。

---

## 九、踩坑记录（下次直接省时间）

1. **`Get-Process IDMan` 会漏实例**：`IDMan_test.exe` 的进程名不同，旧实例没被杀掉时，单实例机制会让新进程**静默退出**（表现为 `EXITED code=0`），极易误判成"补丁导致崩溃"。必须用 `Where-Object { $_.ProcessName -like "IDMan*" }`。
2. **「关于」/「注册」是 `CDHtmlDialog`**：`GetWindowText` 读不到内容，`PrintWindow` 返回**全黑图**。**唯一可靠办法是 UI Automation**（`System.Windows.Automation`）。
3. **`SetForegroundWindow` 会被系统拒绝**，置顶截图会拍到别的窗口。
4. **脚本目录里别放 `dis.py`**：会遮蔽标准库 `dis`，导致 `import capstone` 循环导入。
5. **IDM 的 PE 导入表是幌子**：`Import` 目录只有 2 个描述符，绝大多数 API 走运行时动态解析，按 IAT 认 API 会认错。
6. **Ghidra 工程被并发打开会锁冲突**：多人协作时用 `-readOnly` 或各自复制一份工程。
