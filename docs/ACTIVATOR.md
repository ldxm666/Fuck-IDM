# IDM 一键激活工具 · 交付说明（免守护 / 静态方案）

**产物**：`dist\IDM-Activator.exe`（单文件，双击即自动提权）
**目标**：Internet Download Manager 6.43（x86 PE32）
**设计**：**跑一次，永久生效，无守护、无常驻进程**

---

## 一、这一版改了什么（最重要）

旧版装了一个**每 30 分钟跑一次的「守护」计划任务**。实测证明**守护本身就是 bug 的根源**：

```
伪造序列号
  -> IDM 在 ~62s 判定 counterfeit -> 写 MData 标记 + ExitProcess(0)   （用户看到「IDM 自己退了」）
  -> 守护发现 MData -> 删掉它，并把序列号换成一个新的假号
  -> 新假号又被判 counterfeit -> 回到第一步
```

这是一个**自伤闭环**：守护在源源不断地给 IDM 上供新的假序列号。
所以旧版的守护不是「兜底」，而是**故障源**。

**新版彻底删掉守护**，改成**静态、无进程**：跑一次，机器进入一个不需要任何维护的稳定状态。

| 维度 | 旧版（四腿 + 守护） | 本版（静态三层） |
|---|---|---|
| 常驻进程 | 计划任务，30 分钟一次 | **无** |
| 自伤闭环 | 存在 | **不存在** |
| 抗 IDM 更新 | 更新后靠守护重打补丁 | **预防**：文件 ACL 不可变，更新包根本写不进去 |
| 需要维护 | 是 | **否**（跑一次即可） |

---

## 二、三层设计

### 层 A —— 注册状态（清残留 + 抑制注册框）

- 清掉 counterfeit 残留：遍历整棵 CLSID 树删掉所有 `MData` 值（**不写死 GUID**，因为键会新增）。
- 清掉 `{E6871B76-…}` 键下缓存的**服务端校验判决**值（`sub_51FFC0` 写入的，值名是 XOR 派生的，
  整键清值最稳）。64 位与 32 位视图都清。
- 写格式合法的 `Serial`/`FName`/`LName`/`Email` 到 **HKLM 的 32 位视图**，抑制
  「注册 Internet Download Manager」对话框。

> ⚠️ **必须写 HKLM，不是 HKCU**。IDM 是 32 位进程，读的是
> `HKLM\SOFTWARE\Internet Download Manager`，在 64 位系统上落到
> `HKLM\SOFTWARE\WOW6432Node\Internet Download Manager`。实测只写 HKCU 完全无效。

> 为什么伪造序列号这次是安全的：hosts 已经屏蔽了注册/校验域名，序列号**根本出不了本机**，
> 不可能被上报；即使 IDM 本地判假，P5 已封死自杀出口、P6 已静音弹窗，它既退不了也弹不了。

### 层 B —— 二进制补丁 P1..P6（共 10 个补丁点，由 `idm_engine` 施加）

| # | 补丁点 | 作用 |
|---|---|---|
| P1 | `registration_flag` | 注册状态全局初值 `1`→`0`（0=Full） |
| P2 | `expiry_display_9999` | 到期显示改成 `9999`（32 位 time_t 硬上限 2038，结构上到不了） |
| P3 | `trial_nag_kill` | 试用弹窗函数置空 |
| P4 | `counterfeit_guard` | counterfeit 闸门封堵（失败路径改跳成功出口） |
| P5 | `tripwire_exit_*` ×4 | 封死 4 处 tripwire 自杀出口（3 处 `ExitProcess(0)` + 1 处分支） |
| P6 | `counterfeit_popup_*` ×2 | 静音 2 处 counterfeit 弹窗调用 |

**P5 是「不再自杀」的关键**：即使误入 counterfeit 分支，IDM 也无法 `ExitProcess(0)`。

### 层 C —— 防回退（替代守护，零进程）

- **(a) 文件不可变**：对 `IDMan.exe` 设 `DENY Everyone (WD,DE)`。
  官方更新包**无法覆盖或删除**这个文件 —— 这就是「不需要守护」的原因。
  - 施加：`icacls "<exe>" /deny "*S-1-1-0:(WD,DE)"`
  - 回滚：`icacls "<exe>" /remove:d "*S-1-1-0"`
  - **施加后必须回读 ACL 验证**（`icacls` 回读时会把 SID 显示成账户名 `Everyone`，
    而不是 `S-1-1-0`，所以判定要同时认两种写法）。
- **(b) hosts 屏蔽**：6 个注册/校验域名 → `0.0.0.0`，域名级（服务器换 IP 也拦得住）。
  写完**必须 `ipconfig /flushdns`**，否则缓存会让屏蔽形同虚设（见第五节）。

---

## 三、用法

```
IDM-Activator.exe                       一键激活（默认，自动提权）—— 无守护
IDM-Activator.exe --activate            同上（显式写法）
IDM-Activator.exe --status              只查看状态（只读，不需要管理员）
IDM-Activator.exe --scan                只分析会改什么，不动手（只读）
IDM-Activator.exe --uninstall           完全还原（幂等，跑两次也不报错）

IDM-Activator.exe --no-guard            历史兼容参数，现在是空操作（本版没有守护）
IDM-Activator.exe --guard               打印「守护模型已移除」并退出 0
IDM-Activator.exe --no-lock             跳过「文件不可变」这一步（调试用）
IDM-Activator.exe --serial XXXXX-XXXXX-XXXXX-XXXXX   指定序列号
IDM-Activator.exe --fname 名 --lname 姓 --email 邮箱   自定义注册信息
IDM-Activator.exe --install-dir <目录>  指定 IDM 安装目录
```

### 关于 `--guard`（旧守护入口）

**保留但已废弃**。它现在只打印一段说明然后退出 0，**不装任何东西**。
保留它的原因：用户机器上可能还残留旧计划任务在定期拉起这个命令 ——
不能让它变成报错或闪窗。真正的清理由 `--activate` / `--uninstall` 完成。

### `--no-guard`

历史兼容参数，**空操作**（本版本来就没有守护）。保留是为了让旧快捷方式不报错。

---

## 四、`--activate` 到底改了什么（可核查清单）

| # | 动作 | 作用域 |
|---|---|---|
| 1 | 停止 `IDMan.exe` / `idmBroker.exe` | 进程 |
| 2 | 施加 P1..P6，并用**备份自证**校验补丁完整性 | `IDMan.exe` + `.bak-original` |
| 3 | 清 `MData`（遍历 CLSID 树，双 hive 双视图）+ 清缓存校验判决 | `HKCU`/`HKLM` |
| 4 | 写 `Serial`/`FName`/`LName`/`Email` | `HKLM`（32 位视图）+ `HKCU` |
| 5 | 写 hosts 屏蔽块 + `ipconfig /flushdns` | `%SystemRoot%\System32\drivers\etc\hosts` |
| 6 | 设 `DENY Everyone (WD,DE)` 并回读验证 | `IDMan.exe` 的 ACL |
| 7 | **删除**旧守护计划任务与 Run 自启项 | 任务计划 / `HKCU`·`HKLM` Run |
| 8 | 汇总并打印「无守护、无弹窗、可长期使用」 | — |

**不会做的事**：不装计划任务、不写 Run 自启、不改 IDM 的其它设置。

### 备份文件

| 备份 | 位置 | 用途 |
|---|---|---|
| 原始 `IDMan.exe` | `<安装目录>\IDMan.exe.bak-original` | `--uninstall` 还原 |
| 原始 hosts | `...\etc\hosts.bak-permanentfix` | `--uninstall` 还原 |

---

## 五、两个实测踩出来的坑（都已修掉，请勿回退）

### 坑 1：只写 hosts 不刷 DNS 缓存 → 屏蔽**静默失效**

实测：hosts 内容完全正确（6 行、无 BOM、CRLF），但
`ping internetdownloadmanager.com` 仍然解析到真实 IP `67.18.60.145`，
`register.` 解析到 `67.18.140.140` —— 授权服务器**依然可达**。
只有执行 `ipconfig /flushdns` 之后屏蔽才真正生效。

**修法**：`apply_hosts()` 写完、`restore_hosts()` 还原后，都调用 `ipconfig /flushdns`。
（还原后也要刷：否则缓存里的 `0.0.0.0` 会让屏蔽「死而不僵」。）

**验证必须用 `ping`**：`Resolve-DnsName` / `getaddrinfo` 会读 hosts 并返回 `0.0.0.0`，
给出**假通过**。`--status` 里因此加了 ping 级探测，并显式说明这一点。

### 坑 2：按 marker 字符串计数 → **注释掉的行也算数**

实测有 3/6 行被 `#` 注释掉（`www.` / `secure.` / `register.internetdownloadmanager.com`
其实**没被屏蔽**），但旧检查因为「行里含 marker 字符串」而报成功。

**修法**：只统计**真正生效**的行 —— 行首不能是 `#`，且必须匹配
`^0\.0\.0\.0\s+<域名>`。`--status` 现在显示 `生效 N/6`，注释行不算数。

### 坑 3：脏备份 → 还原**静默失败**

`hosts.bak-permanentfix` 是在**屏蔽已经生效之后**才被创建的（旧 PowerShell 脚本
先屏蔽后备份），所以备份里本身就带 marker。无条件用它还原 = 日志说「还原成功」、
屏蔽其实还在。

**修法**：只有备份**不含** marker 时才允许用它还原；否则改用「删掉 marker 行」的方式，
并顺手删掉这个已经没价值的脏备份。

### 坑 4：补丁点表在已打补丁的文件上会失效

`idm_engine` 的 `find_*` 全部以**原始字节**为锚点。文件一旦打过补丁，锚点就失效 ——
实测：原始 b15 定位到 10 点，**全补丁** b15 只剩 3~6 点。
所以补丁是否完整**不能**用补丁点表判断，也**不能**依赖硬编码哈希
（引擎一升级哈希就变：b15 原版 `279ceed9…` 打完 P1..P6 = `cb2a3e6b…`，
而文档里记的 `4b089abb…` 是 P1..P4 时代的旧值）。

**修法**：`verify_patched()` 做**自证式**校验 —— 拿 `IDMan.exe.bak-original`（原版）
在临时目录里用**同一个引擎**重跑一遍，算出「本机原版 + 本版引擎」应有的补丁后哈希，
再和实际文件比对。不依赖任何硬编码常量。

---

## 六、安全护栏（开发期事故后加的，请勿削弱）

**事故**：开发期用 `--install-dir .scratch\...` 跑 `--activate`，二进制补丁确实只落在
scratch 里，但**注册表 / hosts / 计划任务 / 杀进程**这四条路径用的是**全局**位置，
不认 `--install-dir`。后果：清空了实机的 HKLM 注册信息、还原了实机 hosts、
并 `taskkill` 掉了另一个队友正在验证的 `IDMan.exe`。

**修法**：`system_changes_allowed(args, install_dir)` 硬护栏 ——
只有当**目标就是实机安装目录**（两个标准路径之一，或注册表 `ExePath` 指向的目录）
时，才允许碰系统级状态；否则一律跳过并打印原因。

- 想强行在别处做系统级改动，必须显式加 `--allow-system-changes`（危险，默认禁止）。
- scratch 目录再也不会泄漏到实机。
- `--status` 会显示「系统级改动：允许/禁止」。

---

## 七、回滚

```
IDM-Activator.exe --uninstall
```

依次：删旧守护任务/自启项 → 移除 DENY ACE → 从 `.bak-original` 还原 `IDMan.exe`
→ 清 `MData` 与缓存判决 → 清注册信息 → 还原 hosts 并刷 DNS 缓存。

**幂等**：连跑两次不会报错（第二次会显示「本来就没有」「无需还原」等）。

> ⚠️ 还原 hosts 时如果备份是脏的（见坑 3），会用「删行」方式，并在自检里如实报告。
> 跑完请用 `--status` 确认「hosts 屏蔽：已移除」。

---

## 八、已知限制 / 未验证项

1. **`--activate` 的实机端到端验证由 Lead / 部署者执行**。开发期只在 scratch 副本上
   验证了二进制补丁路径（哈希自证通过）。
2. **hosts 屏蔽可能被绕过**：如果本机配了 DNS-over-HTTPS、代理或 VPN，
   hosts 不一定拦得住。`--status` 的 ping 探测会如实报告「仍解析到真实 IP」。
3. **DNS 探测是尽力而为**：依赖本机网络状态，不参与「成功/失败」判定，
   只作为给用户看的证据。
4. **`--status` 会发 6 次 ping**（每个域名一次，超时 800ms），因此大约需要数秒。
   它是只读的，但**不是零网络活动**。
5. **`MData` 可能被 IDM 重新写入**：它只是 IDM 反复覆盖的注册表值，无害；
   但 `--status` 报「存在 MData 残留」不代表激活失败（P5 已让 tripwire 无法自杀）。
6. **非 NTFS 卷**：ACL 不可用，会跳过「文件不可变」并明确报告（不静默失败）。

---

## 九、文件清单

| 文件 | 说明 |
|---|---|
| `dist\IDM-Activator.exe` | **交付物**：单文件一键激活（无守护） |
| `IDM-Activator.py` | 源码（EXE 由它打包） |
| `idm_engine.py` | PE 解析 + 特征码定位 + 补丁引擎（P1..P6） |
| `scripts\idm-permanent-fix.ps1` | 等价的 PowerShell 版（注册表/hosts 部分），语义与 Python 版一致 |
| `patches\permanent-plan.md` | 免守护方案的设计与实测记录 |
| `patches\mdata-writer-static.md` | MData 写入点的静态精析 |
| `bin\` | 原始/已打补丁的 `IDMan.exe` 备份 |

日志：`%LOCALAPPDATA%\IDM-Activator\activator.log`
