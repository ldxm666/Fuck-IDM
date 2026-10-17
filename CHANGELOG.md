# 更新日志（CHANGELOG）

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.1] - 2026-10-17

修复实机反馈的 **「后台挂一段时间后弹 `IDM is corrupt`（主程序已损坏）」**。

### 根因

IDM 会**绕过 hosts** 直连授权/更新服务器做联网校验，发现主程序被修改后弹损坏提示。
两条独立证据：

1. **官方自述**：`Languages\*.lng` 里原文写着
   *"IDM will check for updates successfully even with your damaged hosts file."*
2. **实测**：hosts 6/6 全绿时，`www.` / `secure.` / `register.internetdownloadmanager.com`
   仍解析到 `67.18.60.145` / `67.18.140.140`，`ping` 可达。

### 修复

- **新增层 C 第三层：防火墙出站阻断**（`FuckIDM-Block-AuthServers`）
  - `dir=out action=block program=<IDMan.exe> remoteip=67.18.0.0/16 profile=any`
  - 只挡 IDM 服务器网段，**不影响正常下载**
  - `--activate` 施加 / `--uninstall` 移除 / `--status` 显示
- **修掉一个真 bug：hosts 3 行被注释导致「生效 3/6 却判成功」**
  - `HOSTS_DOMAINS` 从 6 个扩到 **11 个**：补 `update.` / `support.` / `idm.` 与
    `secure.tonec.com` / `register.tonec.com`
  - 起因：hosts 是**精确匹配**，写 `internetdownloadmanager.com` 并不覆盖
    `www.internetdownloadmanager.com` —— 父域名屏蔽 ≠ 子域名屏蔽
- `firewall_state()` 区分「无规则」与「无权查询」：非管理员下 `netsh` 返回
  `requires elevation` 时返回 `unknown`，**不再误报「未设置」**

### 排查记录（供后续复现）

| 观测 | 结论 |
| --- | --- |
| 补丁完整性 | ✅ 20/24 点认回，自证哈希 = 装机 `B6C45453…` |
| PE CheckSum | ✅ stored = 计算值（引擎 `ensure_pe_checksum` 已处理） |
| 数字签名校验 | ❌ IDM **没有** `WinVerifyTrust` 导入 → corrupt 不是签名问题 |
| 「检查更新」菜单（网络放开 A/B） | 90 s 无弹窗 → 不是这条命令直接触发 |
| 下载触发（1 MB 本地 HTTP） | 150 s 无弹窗 |
| 文案定位 | `The main IDM executive file is damaged.` @ `.data` VA `0x37C5CC`（XOR `0x3D`） |
| 完整正文 | **不在本地任何文件**（11 个 exe/dll/lng 全扫）→ 服务端下发 |

### 新增

- `README` 新增 FAQ **Q5**（corrupt 弹窗的成因与三层防御）
- `docs/FAQ.md` 同步该章节

---

### 追加修复（同日第二轮，实机反馈「又弹了」）

第一轮的 hosts + 防火墙**不够**，因为漏了两件事：

**1. IDM 会主动把 hosts 屏蔽行注释掉（决定性发现）**

实测 2026-10-17：手动取消注释后，IDM 启动数秒内把下面六行**全部重新加上 `#`**：

```
#0.0.0.0 www.internetdownloadmanager.com
#0.0.0.0 secure.internetdownloadmanager.com
#0.0.0.0 register.internetdownloadmanager.com
#0.0.0.0 update.internetdownloadmanager.com
#0.0.0.0 support.internetdownloadmanager.com
#0.0.0.0 idm.internetdownloadmanager.com
```

而 `tonec.com` / `www.tonec.com` / `secure.tonec.com` / `register.tonec.com` **不动**
⇒ 这是**针对 internetdownloadmanager.com 的定向修复**，不是随机破坏。

官方 `.lng` 里写得很直白：

> *"Your browser may not open IDM website because an important system file is damaged
> on your computer. **IDM will repair this file now.**"*

⇒ **修复：给 hosts 加 `DENY(WD)` ACL**（`Everyone:(DENY)(WD)`），IDM 就写不进去了。
`apply_hosts()` 改为「**写前解除 DENY → 写完加回**」，`restore_hosts()` 同理。

**2. `%APPDATA%\IDM\idmupdt.exe` —— IDM 已下载的更新包（12.5 MB）**

| 项 | 值 |
| --- | --- |
| 路径 | `C:\Users\<user>\AppData\Roaming\IDM\idmupdt.exe` |
| 大小 | 12,559,240 B |
| 创建 | `2026-10-16 23:02:16`（当时 hosts 只挡 3/6，能联网） |
| 最后访问 | `2026-10-17 15:51:56`（**紧跟 IDM 重启时刻**） |
| FileVersion | `6, 43, 15, 1`（Tonec Inc. installer） |

IDM 每次启动后数秒内就 **access** 它，说明它参与版本/完整性比对。
⇒ 新增 `cleanup_update_package()`：改名为 `.bak-fuckidm` 隔离（**可回滚，不影响已完成的下载**）。

**3. 新增 Frida 抓栈工具**（下次弹窗可直接定位到指令）

`src/scripts/hook-corrupt-popup.js` + `.py`：hook
`MessageBoxW/A`、`DialogBoxParamW`、`CreateDialogIndirectParamW`、`CreateWindowExW`，
命中即打印**完整调用栈（模块+偏移）**。

```powershell
python src\scripts\hook-corrupt-popup.py      # 自动找 IDMan.exe pid，挂 30 分钟
# 日志：<repo>\.hook-corrupt.log
```

**4. 排查补充结论**

| 方向 | 结论 |
| --- | --- |
| `idmupdt.exe` 恢复 vs 删除（A/B） | 3 分钟窗口内**都不弹** ⇒ 它不是**立即**触发源 |
| `GlobalErrors.log` 的 `DR2` | 8 条（04:13…12:13），`DR2` 在 exe 里只是字符串池碎片，**与弹窗无时间对应** |
| 弹窗正文 `infected with a virus` | **全目录 × 256 key × ASCII/UTF-16 全扫 = 0 命中** ⇒ 运行时生成/服务端下发 |
| 弹窗时刻 | 15:41 抓到 hwnd `#32770`「IDM is corrupt」，正文与用户截图逐字一致 |

---

### 追加修复（同日第三轮：**找到元凶了 —— 是内核驱动**）

前两轮都在用户态打转，这轮 `sc query` 一看就明白了：

```
SERVICE_NAME: idmwfp
        TYPE               : 2  FILE_SYSTEM_DRIVER     ← 文件系统驱动
        STATE              : 4  RUNNING
        START_TYPE         : 2  AUTO_START
        DEPENDENCIES       : BFE
        BINARY_PATH_NAME   : \SystemRoot\System32\drivers\idmwfp.sys
```

**`idmwfp` 是挂在文件系统栈上的内核驱动**，**在 ACL 检查之前/之后都能直接操作文件** ——
所以 hosts 加 `Everyone:(DENY)(DE,WD)` 也挡不住它。完整时间线：

| 时刻 | 事件 | hosts |
| --- | --- | --- |
| 16:00:18 | 手动取消注释 | **11 行** |
| 16:00:39 | IDM 启动（`/onboot`） | — |
| **16:00:40** | **6 行被重新注释** | 5 行 |
| 16:02:04 | 加 `DENY(DE,WD)` 再修 | **11 行** |
| 16:02:15 | IDM 重启 | — |
| **16:02:18** | **又是 6 行** | 5 行 |
| 16:37:21 | 用 `RunLevel=Limited` 计划任务启动 IDM | 5 行（**仍被改**） |
| **16:38:34** | **`sc stop idmwfp` + `start= disabled`** | 修回 11 行 |
| 16:38:40 | IDM 启动 | **11 行** |
| 16:41:38 → 16:43:38 | 连续 120 s 观测 | **恒 11 行，mtime 不变** ✅ |

⇒ **元凶确认：`idmwfp` 内核驱动**。停用后 hosts 才真的保得住。

> 顺带证实：**`RunLevel=Limited` 对 Administrator 账户无效**（仍属 Administrators 组，
> 仍有 SeRestorePrivilege）—— 所以「降 IDM 权限」这条路走不通，**必须停驱动**。

**本轮改动**

- 新增 `disable_wfp_driver()` / `restore_wfp_driver()` / `wfp_driver_state()`
  - `sc stop idmwfp` → `sc config idmwfp start= disabled`
  - **安装目录里的 `idmwfp*.sys` / `idmtdi*.sys` 副本改名** `.disabled-fuckidm`（防 IDM 装回来）
  - `do_activate [5.7/8]` 调用、`do_status` 显示、`do_uninstall [5.7/6]` 恢复
- **实测代价**：IDM 的「高级浏览器集成」失效（浏览器点下载不再自动接管）；
  **手动「添加任务」/ 拖链接 / 剪贴板监听不受影响**。`--uninstall` 可完全恢复。

**验证（--status）**

```
hosts 屏蔽   : 生效 11/11 个域名
IDM 更新包   : 已清理（备份：idmupdt.exe.bak-fuckidm）
内核驱动     : disabled（STATE=STOPPED START_TYPE=DISABLED）  <== 已停用，hosts 不会被 IDM 拆掉
```

### 收尾加固：把「内核特权」彻底移除（不是仅停用）

`sc config start= disabled` 只保证**开机不加载**，但理论上还能被 `NtLoadDriver` 手动拉起来。
所以 `disable_wfp_driver()` 末尾加了一条**自证**：

```
sc start idmwfp
  → [SC] StartService FAILED 1058:
    The service cannot be started, either because it is disabled
    or because it has no enabled devices associated with it.
```

**启动被拒绝 ⇒ 内核特权真的移除了。** 若 `sc start` 居然成功，函数会立刻 `sc stop` 并**返回失败**
（宁可在日志里报错，也不假装修好了）。

> `C:\Windows\System32\drivers\idmwfp.sys` 本体由 **TrustedInstaller** 持有
> （`NT SERVICE\TrustedInstaller:(F)`），`icacls /deny` 会被拒绝 —— 但**不需要动它**：
> 服务 DISABLED + `sc start` 被拒，已经等于加载不了。

**实测收尾状态（17:48 起连续观测）**

| 项 | 值 |
| --- | --- |
| `hosts` | **11/11 行，mtime 16:48:26 恒定不变** |
| `idmwfp` | `STATE=STOPPED` / `START_TYPE=DISABLED` / `sc start` → **FAILED 1058** |
| 安装目录驱动副本 | `idmwfp32/64/AA.sys`、`idmtdi32/64.sys` 全部改名 `.disabled-fuckidm` |
| `idmupdt.exe` | 已隔离 |
| 弹窗 | GONE |

## [1.0.0] - 2026-10-17

首个开源版本。基线：IDM **6.43 Build 15**，24 点全量补丁（`eca4afdc…`），实机装机 MATCH。

### 新增

- `src/idm_engine.py`：极简 PE 解析器（零依赖）+ 特征码定位器 + 补丁施加器（P1–P15）。
- `src/IDM-Activator.py`：一键工具（层 A 注册状态 / 层 B 补丁 / 层 C 防回退 / 回滚），
  自动提权、自证式完整性校验、系统级护栏。
- `src/IDM-Unlock.py`：最小可用解锁器（P1–P3），保留作为参考实现。
- `src/scripts/apply_p8_idmgrhlp.py`：`IDMGrHlp.exe` 的 P8 独立施加器（幂等 + 断言 + 备份）。
- `tools/probe-scripts/`：Frida 弹窗/IO 探针、PE 资源探针、XOR 字符串全扫、
  331 个弹窗调用点全量审计脚本。
- `tools/verify/`：端到端验证脚本（soak、下载回归、P19 验收、UIA 读对话框）。
- `docs/`：11 份深度分析报告 + 锚点字典（b15 / b8）+ 完整实现细节 + 交接文档。

### 关键设计决策

- **删除守护模型**：旧版 30 分钟一次的计划任务守护**本身就是故障源**
  （伪造序列号 → counterfeit → `MData` + `ExitProcess(0)` → 守护删标记并换新假号 → 循环）。
  改为静态三层 + ACL 不可变（预防而非修补）。
- **P14 wrapper 级短路**：`sub_474D20` 入口按 `uType == 0x41030` 直接返回 0
  ⇒ **一处覆盖全部显示点 + 未来路径**，其余 244 处调用不受影响。
- **P12 标为 RETIRED**：`license_valid` 实测 12/12 注册框照弹，被否证，保留实现作为记录。
- **P8 独立 CLI**：`IDMGrHlp.exe` 不在 `IDMan.exe` 的打包范围内，需单独施加。

### 修复（开发期踩过的坑，均已固化进代码）

- 只写 hosts 不刷 DNS 缓存 → 屏蔽**静默失效**（`ping` 仍解析真实 IP）。
- 按 marker 字符串统计 hosts 生效行 → 被 `#` 注释的行也算数（3/6 行误报成功）。
- 脏备份（在屏蔽生效后才创建）→ 还原**静默失败**；改为「备份不含 marker 才允许还原」。
- 补丁点表在已打补丁的文件上失效 → 改用**自证式**完整性校验。
- `--install-dir` 不覆盖系统级路径 → 引入 `system_changes_allowed()` 硬护栏。
- P9 锚点过严（`call+10` 必为 `RegFlushKey`）导致漏点 `0x120A54` → 改为仅保留可达性排除。
- P9 用 `call [ExitProcess]` 当锚点 → P5 施加后被打成 NOP，幂等被破坏 → 移除该锚点。
- P14 曾因「`call+5` 必须 `83 C4 10`」误拒 `0x75710`（清栈在 `call+0x0B`）→ 改为逐站点判定。

### 已知限制

- 非 NTFS 卷不支持 ACL 不可变（会跳过并明确报告）。
- DNS-over-HTTPS / 代理 / VPN 环境下 hosts 屏蔽可能失效。
- `--status` 会发 6 次 ping（只读，但非零网络活动）。
- P11 为预防性补丁，无已知触发路径，无法动态验证。

---

## 历史（未开源阶段）

| 版本 | 日期 | 说明 |
| --- | --- | --- |
| b8 方案 | 2026-08 | IDM 6.43 Build 8：P1–P3，`g_registered @ 0x779CDC`，实测 Full + 9999 |
| b15 方案 | 2026-10 | IDM 6.43 Build 15：根因确认（counterfeit 自伤闭环），P1–P15 全量 24 点 |

### 追加修复（同日第四轮：**驱动必须保留 —— 浏览器集成是核心**）

用户明确：**高级浏览器集成必须有，这是最核心的功能**。
所以「停驱动」方向**撤回** —— 改成**绕开它而不是关掉它**。

**两个弹窗其实是同一件事的两面**

| 弹窗 | 触发 | 文案来源 |
| --- | --- | --- |
| `IDM is corrupt` | 后台挂几小时 | `The main IDM executive file is damaged…`（`.data` @ `0x37C5CC`，XOR `0x3D`） |
| **`需要修复这个文件吗`** | **点/周期「检查更新」** | `template.lng` **20955**：`IDM cannot check for updates because an important system file is damaged on your computer. Repair this file?` |

两者都源于 **IDM 的「完整性自检 + 自动修复」逻辑**：

1. 周期/手动触发检查更新
2. 先读 `hosts`（看有没有自己的域名被屏蔽）、再看自身文件
3. 判定「重要系统文件损坏」→ 弹框
4. 点「继续」→ **去把 hosts 屏蔽行注释掉**（实测 3 秒内完成）

**所以 hosts 屏蔽和"修复"弹窗天生打架** —— 屏蔽越狠，弹得越勤。

**最终定案：不写 hosts 屏蔽 + 关自动检查更新 + 防火墙挡 IP + 驱动保留**

| 层 | 做法 | 为什么 |
| --- | --- | --- |
| hosts | **默认不写屏蔽**（`--with-hosts` 才写） | 没有屏蔽行 → IDM 没有可"修复"的东西 |
| 自动检查更新 | **关闭**：`CheckUpdtVM 10→3650`、`LastCheckQU→2145916800`（2038） | 不检查 → 不触发自检 |
| 防火墙 | `67.18.0.0/16` + `67.18.60.0/24` + `67.18.140.0/24` + **`169.62.35.0/24`** | 挡网络且不影响正常下载 |
| **驱动 idmwfp** | **保留 RUNNING**（`--no-browser-integration` 才停） | **它就是高级浏览器集成的核心** |
| 更新包 | `idmupdt.exe` 隔离 | 去掉一路校验输入 |

**新发现的服务器 IP（之前被 hosts 挡住看不到）**

```
internetdownloadmanager.com        -> 67.18.60.145
register./update./support.…        -> 67.18.140.140
tonec.com / www.tonec.com          -> 169.62.35.21   ← 新，之前从没挡过
```

**实测最终状态**

```
hosts        28 行原始内容，mtime 恒定不变
idmwfp       STATE=RUNNING（高级浏览器集成可用）
自动检查更新  off（CheckUpdtVM=3650 LastCheckQU=2145916800）
防火墙        4 个网段 Block
弹窗          IDM is corrupt: GONE / 需要修复: GONE
IDM 主窗口    正常
```

---

## [1.0.0] - 2026-10-17