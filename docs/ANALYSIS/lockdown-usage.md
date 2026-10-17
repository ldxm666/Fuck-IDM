# IDM 6.43b8 防回退：LastCheckQU 刷新与自动刷新机制 —— 使用说明

- 脚本：`work/idm-6.43b8/scripts/lockdown-update.ps1`
- 依赖的背景结论：`work/idm-6.43b8/patches/update-lockdown.md`（task-4）
- 回检脚本（不改动）：`work/idm-6.43b8/scripts/check-patch-state.ps1`

---

## 0. 一句话

IDMan.exe 的自动更新门控只看 `HKCU\Software\DownloadManager\LastCheckQU` 这一个值
（`FUN_00456BC0` @ VA 0x00456BC0：`return 6 < (time(NULL) - LastCheckQU) / 86400`）。
**把这个值保持在最近 6 天内，门控就一直关闭，IDM 就不会自动下载并启动提权更新器 `idmupdt.exe`。**

本脚本负责：刷新这个值 / 把它变成自动刷新 / 一键恢复到官方默认。

---

## 1. 快速上手：三条命令

### 1.1 刷新一次（默认动作，手动用）

```powershell
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\lockdown-update.ps1
```

预期输出（真实运行结果，2026-10-16 21:54:43）：

```
--- LastCheckQU 刷新 ---
 旧值 : 1792156831  (2026-10-16 21:20:31 +08:00, 距今 0.02 天)
 旧门控: 关闭
 新值 : 1792158883  (2026-10-16 21:54:43 +08:00)
 新门控: 关闭 —— 距今 0 天 <= 6 天 -> 未到期（还需约 7 天）

 计划任务: 不存在 —— 门控会在 7 天后重新打开；建议执行 -InstallTask 长期保持。

 结论: [OK] LastCheckQU 已刷新，门控关闭（有效约 7 天）。
```

退出码 `0`。**不写任何文件、不启动 IDMan.exe、不碰安装目录**，只改 HKCU 下一个 REG_DWORD。

### 1.2 安装自动刷新机制（长期防回退）

```powershell
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\lockdown-update.ps1 -InstallTask
```

预期输出（真实运行结果，2026-10-16 21:56:51）：

```
--- 安装自动刷新机制 ---
 机制 A（首选）: Windows 计划任务
 任务名   : IDM-Patch-Lockdown
 触发     : 每 3 天一次（首次 2026-10-17 03:00:00）
 身份     : WIN-DH3F0OEOI2M\Administrator（交互式登录，RunLevel=Limited，无需最高权限）
 已存在   : 否（新建）
 机制 B（兜底）: 当前用户登录自启项（不需要管理员权限）
 注册表   : HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\IDM-Patch-Lockdown
 已存在   : 否（新建）
 命令行   : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "D:\pojie应用\jiesuo\work\idm-6.43b8\scripts\lockdown-update.ps1" -Quiet
 说明     : 本机实测未提权会话下计划任务会被 "Access is denied" 拒绝；
            此时脚本会自动改用机制 B，并明确告知。

 [!] 计划任务注册失败: Access is denied.

     原因通常是当前会话未提权（写任务库需要管理员权限）。
     已自动改用兜底机制 B：当前用户登录自启项（不需要管理员权限）。
 [OK] 登录自启项已写入（机制 B 生效）: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\IDM-Patch-Lockdown

 刷新     : LastCheckQU = 1792159011
 机制 A   : 未生效（计划任务注册被拒绝）
 机制 B   : 登录自启项 HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\IDM-Patch-Lockdown（每次登录刷新一次）

 结论: [OK] 已用登录自启项（机制 B）替代计划任务，门控已关闭。
       如需真正的计划任务，请以管理员身份重跑: -InstallTask
```

退出码 `0`。**注意**：`-InstallTask` 会顺便立刻刷新一次 `LastCheckQU`，避免装完还留出最长 7 天的暴露窗口。

> 关于「机制 A 被拒」：这不是脚本 bug。见 §6 —— 本机未提权会话下
> `Register-ScheduledTask` 与 `schtasks.exe /Create` **都**返回 `Access is denied`。
> 脚本会自动回退到机制 B（HKCU Run 项），并把实际生效的机制打印出来。
> 想让机制 A 生效，**以管理员身份**跑一次同样的 `-InstallTask` 即可。

### 1.3 卸载并恢复官方默认

```powershell
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\lockdown-update.ps1 -Restore
```

预期输出（结构如下；**本次为保护补丁未真跑，仅用 `-DryRun` 预览**）：

```
--- 恢复官方默认（可自动更新） ---
 说明: 这会删除 LastCheckQU，并移除全部自动刷新机制（计划任务 + 登录自启项）。
       删除该值后 FUN_00456BC0 直接返回 true —— 也就是 IDM 的官方出厂行为：
       每次启动 IDMan.exe 都可能自动检查更新。
 [OK] 已删除计划任务 IDM-Patch-Lockdown
 [OK] 已删除登录自启项 HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\IDM-Patch-Lockdown
 [OK] 已删除 HKCU:\Software\DownloadManager\LastCheckQU（原值 …）

 当前门控 : 打开 —— 值缺失 -> FUN_00456BC0 直接 return true（永远到期）

 结论: [OK] 已恢复官方默认行为（下次启动 IDMan.exe 会重新具备自动更新能力）。
       注意: 这意味着补丁可能被更新覆盖 —— 需要防回退时请重新执行 -InstallTask。
```

真实跑过的预览（2026-10-16 21:57:2x，`-Restore -DryRun`）：

```
*** 预览模式（-DryRun / -WhatIf）：不会修改任何注册表项或计划任务 ***

--- 恢复官方默认（可自动更新） ---
 说明: 这会删除 LastCheckQU，并移除全部自动刷新机制（计划任务 + 登录自启项）。
       删除该值后 FUN_00456BC0 直接返回 true —— 也就是 IDM 的官方出厂行为：
       每次启动 IDMan.exe 都可能自动检查更新。
 [DRY-RUN] 未删除 LastCheckQU，未移除计划任务/登录自启项。

 结论: [PREVIEW] 未做任何修改。
```

`-Restore` 会**先卸载自动刷新机制再删值**——否则机制会在 3 天内把值写回来，恢复就失效了。

---

## 2. 其它用法

| 命令 | 作用 |
|---|---|
| `... -Status` | 只读：`LastCheckQU` / 距今天数 / 门控是否打开 / 机制 A、B 是否在装 |
| `... -RemoveTask` | 只卸载机制 A + B（幂等：都不存在也返回 0） |
| `... -DryRun` | 预览：只打印将做什么，不落地（等价 `-WhatIf`） |
| `... -WhatIf` | 同上（由 `CmdletBinding(SupportsShouldProcess)` 提供） |
| `... -Quiet` | 安静模式，只输出一行结论；计划任务/自启项就是用这个参数调用的 |
| `... -RefreshIntervalDays 1` | 自定义刷新间隔（1–30，默认 3） |
| `... -RegPath / -ValueName` | 指向别的注册表键值（便于测试；见 §3.3） |

动作开关互斥，同时给两个会明确报错并返回退出码 1：

```
[X] 用法错误: 动作开关互斥，只能给一个，收到 -Status, -RemoveTask
    用法: lockdown-update.ps1 [-Status|-InstallTask|-RemoveTask|-Restore] [-DryRun] [-WhatIf] [-Quiet]
```

---

## 3. 实跑记录（真实输出）

以下全部是 2026-10-16 在本机（`WIN-DH3F0OEOI2M\Administrator`，**未提权**）的真实运行结果。

### 3.1 `-Status`（刷新前）

```
==================================================================
 IDM 防回退状态 (lockdown-update.ps1 -Status)
==================================================================
 检查时间    : 2026-10-16 21:54:15 +08:00
 注册表       : HKCU:\Software\DownloadManager\LastCheckQU
 LastCheckQU : 1792156831
               2026-10-16 21:20:31 +08:00
 距今        : 0.02 天
 门控         : 关闭 —— 距今 0 天 <= 6 天 -> 未到期（还需约 7 天）
                本次启动不会自动检查更新。
 阈值         : 6 天（FUN_00456BC0 @ VA 0x00456BC0）
 计划任务     : 不存在（IDM-Patch-Lockdown）
                提醒: 没有计划任务时，LastCheckQU 不会自动保持新鲜。
```

### 3.2 一次真实刷新 + 刷新后 `-Status`

刷新输出见 §1.1。刷新后的 `-Status`（2026-10-16 21:54:46）：

```
==================================================================
 IDM 防回退状态 (lockdown-update.ps1 -Status)
==================================================================
 检查时间    : 2026-10-16 21:54:46 +08:00
 注册表       : HKCU:\Software\DownloadManager\LastCheckQU
 LastCheckQU : 1792158883
               2026-10-16 21:54:43 +08:00
 距今        : 0 天
 门控         : 关闭 —— 距今 0 天 <= 6 天 -> 未到期（还需约 7 天）
                本次启动不会自动检查更新。
 阈值         : 6 天（FUN_00456BC0 @ VA 0x00456BC0）
 计划任务     : 不存在（IDM-Patch-Lockdown）
                提醒: 没有计划任务时，LastCheckQU 不会自动保持新鲜。
```

### 3.3 「门控打开 → 刷新 → 关闭」闭环验证（用临时键，绝不碰 IDM 真实键）

为了演示「门控打开」的判定与修复，用 `-RegPath` 指向一个**临时**注册表键
`HKCU:\Software\DownloadManager-LockdownTest`，把它设成 10 天前：

```
##### 3a) 临时键: 10 天前 -> 应判定门控打开 #####
 注册表       : HKCU:\Software\DownloadManager-LockdownTest\LastCheckQU
 LastCheckQU : 1791294874
               2026-10-06 21:54:34 +08:00
 距今        : 10 天
 门控         : 打开 —— 距今 10 天 > 6 天 -> 到期
                下次启动 IDMan.exe 会在 60s 后挂 UPDATE_TIMER，自动下载并启动更新器。

##### 3b) 对临时键执行刷新（真实写入） #####
--- LastCheckQU 刷新 ---
 旧值 : 1791294874  (2026-10-06 21:54:34 +08:00, 距今 10 天)
 旧门控: 打开
 新值 : 1792158875  (2026-10-16 21:54:35 +08:00)
 新门控: 关闭 —— 距今 0 天 <= 6 天 -> 未到期（还需约 7 天）

 结论: [OK] LastCheckQU 已刷新，门控关闭（有效约 7 天）。

##### 3c) 临时键: 刷新后 #####
 门控         : 关闭 —— 距今 0 天 <= 6 天 -> 未到期（还需约 7 天）
```

**为什么用临时键而不是把真实的 `LastCheckQU` 改成 10 天前**：soak-verifier 正在并发地
反复重启 IDMan.exe。若真实门控在那几秒窗口里变成「打开」，IDM 启动后会挂上
`UPDATE_TIMER` 并在 60 s 后真的去下载更新器 —— 那正是我们要防的事。所以闭环演示
全部在临时键上做，**真实的 `LastCheckQU` 只做单向刷新（只会让门控更关闭）**。

### 3.4 机制 B 真的会工作（模拟登录触发）

把注册的命令行原样跑一遍（`-Quiet`）：

```
quiet output: [ 结论: [OK] LastCheckQU 已刷新，门控关闭（有效约 7 天）。]
before=1792159021 after=1792159024  refreshed=True
```

即：`-Quiet` 下只输出一行结论，且确实完成了刷新。

### 3.5 幂等性

| 操作 | 第二次执行的结果 |
|---|---|
| `-InstallTask` | `机制 B ... 已存在: 是（将覆盖）`，覆盖后仍返回 0 |
| `-RemoveTask` | `机制 A ... 不存在 / 机制 B ... 不存在` → `结论: [OK] 本来就没有安装任何自动刷新机制。`，返回 0 |
| 默认刷新 | 每次都成功，值单调前移 |
| `-Restore` | 值本来缺失时输出 `[--] LastCheckQU 本来就缺失（已是官方默认状态）` |

---

## 4. 副作用与恢复路径

### 4.1 默认刷新（无参数）

| 项目 | 说明 |
|---|---|
| 改了什么 | 仅 `HKCU\Software\DownloadManager\LastCheckQU` 一个 REG_DWORD（HKCU，不需要管理员） |
| 对 IDM 功能的影响 | **无**。该值只被 `FUN_00456BC0` 读一次，用来决定「要不要在 60 s 后检查更新」。IDM 本来就会自己写这个值。 |
| 对其它软件的影响 | 无 |
| 需要重启 IDM 吗 | 改值本身不需要；但 `FUN_00456BC0` **只在启动时读一次**。若 IDMan.exe 正在运行且 `UPDATE_TIMER` 已挂上，改注册表撤不掉已挂的定时器 —— 必须关闭 IDM 再改、再启动。 |
| 恢复路径 | 什么都不用做（IDM 下次检查会自己覆盖）；要立刻恢复「可自动更新」就执行 `-Restore` |

### 4.2 `-InstallTask`

| 项目 | 机制 A（计划任务） | 机制 B（HKCU 登录自启项） |
|---|---|---|
| 改了什么 | 计划任务 `IDM-Patch-Lockdown`（任务库里） | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 下新增值 `IDM-Patch-Lockdown` |
| 需要管理员 | **需要**（本机实测：否则 Access is denied） | 不需要 |
| 触发时机 | 每 3 天 03:00（可 `-RefreshIntervalDays`） | 每次用户登录 |
| 对 IDM 功能的影响 | 无 | 无 |
| 副作用 | 登录时会短暂出现一个隐藏的 powershell 进程（`-WindowStyle Hidden`） | 同左，但每次登录都会跑一次 |
| 其它软件的可见性 | 安全软件/任务计划视图里能看到 | `msconfig` / 任务管理器「启动」页能看到 |
| 恢复路径 | `-RemoveTask` 或 `-Restore`；也可手工 `Unregister-ScheduledTask -TaskName IDM-Patch-Lockdown` | `-RemoveTask` / `-Restore`；也可手工删除该 Run 值 |

### 4.3 `-RemoveTask` / `-Restore`

| 项目 | 说明 |
|---|---|
| 改了什么 | 移除计划任务与/或 Run 值；`-Restore` 额外删除 `LastCheckQU` |
| 副作用 | 无。移除后门控会在约 7 天后重新打开（即回到有回退风险的状态） |
| 恢复路径 | 重新执行 `-InstallTask` 与/或默认刷新 |

### 4.4 一个必须记住的次序

**恢复/卸载时一定要「先移除自动刷新机制，再删值」。**
否则机制会在下一次触发（≤3 天 / 下次登录）把 `LastCheckQU` 写回来，你以为恢复了、其实没有。
`-Restore` 已经内置这个次序。

---

## 5. 为什么不能删值、不能设未来时间

`FUN_00456BC0` @ VA 0x00456BC0 的原始语义（Ghidra 反编译 + 逐条指令核对）：

```c
bool FUN_00456bc0(void) {
  local_18 = 4;
  LVar1 = RegQueryValueExA(DAT_00786ce8, "LastCheckQU", 0, 0, (LPBYTE)&local_1c, &local_18);
  if (LVar1 == 0) {
    uVar2 = time(NULL);                       /* uint32 */
    uVar2 = (uVar2 - local_1c) / 0x15180;     /* 0x15180 = 86400 = 1 天；无符号减法 */
    return 6 < uVar2;                         /* 严格大于 6 天才到期 */
  }
  return true;                                /* 读不到值 -> 永远到期 */
}
```

三条必须记住的推论：

1. **删值 = 每次都到期。**
   `RegQueryValueExA` 返回非 0 时函数直接 `return true`。所以删掉 `LastCheckQU` 不是「关闭更新」，
   而是**把它变成每次启动都检查**。这正是 IDM 的官方出厂状态。
   → 想「恢复官方行为」用 `-Restore`；想「防回退」**绝不能**删。

2. **设成未来时间 = 同样每次都到期。**
   `uVar2 - local_1c` 是 **32 位无符号**减法（`uVar2` 与 `local_1c` 都是 `uint`）。
   若 `LastCheckQU > time(NULL)`，差值是接近 2³² 的巨大数，除以 86400 后仍然巨大，
   `6 < 巨大` 恒为真 → **门控每次都是打开的**。
   这不是「设远一点就永久关闭」，恰恰相反。
   → 只能用「保持在最近 6 天内」这一个方向。

3. **只有「新鲜」才关闭门控。**
   `(now - LastCheckQU) / 86400 <= 6` 才返回 false。因为整数除法向下取整，
   实际有效窗口是 **约 7 天**（第 0–6 天关闭，第 7 天起打开）。
   所以刷新间隔必须 **≤ 6 天**；脚本默认 3 天，留了一倍余量。
   （`-Status` 会直接算给你看：「还需约 N 天」。）

补充：`CheckUpdtVM` 虽然名字像开关，但它在 IDMan.exe 内**只写不读**
（唯一 xref = 写点 0x0045A1AC，见 `update-lockdown.md` §1.2(5)），
删它/改它对本模块的更新决策没有任何影响 —— **不要拿它当开关**。

---

## 6. 本机实测发现：计划任务需要提权（已内置兜底）

task-5 的原设想是「计划任务，当前用户，无需最高权限」。本机实测**不成立**：

```
user      : WIN-DH3F0OEOI2M\Administrator
elevated  : False                      # 管理员组，但令牌已被 UAC 过滤
Schedule  : Running / Automatic        # 任务计划服务正常

Register-ScheduledTask -TaskName IDM-Patch-Lockdown ...   -> Access is denied.
schtasks.exe /Create /TN IDM-Patch-Lockdown-Probe /TR "cmd /c exit" /SC DAILY /MO 3 /ST 03:00 /F
                                                          -> ERROR: Access is denied.
```

结论：**在本机未提权会话下，两种注册计划任务的方式都会被拒绝**（写任务库需要管理员权限）。
`-InstallTask` 因此内置了自动兜底：

- 先试机制 A（计划任务，`RunLevel=Limited`，不申请最高权限运行）；
- 被拒时打印原因，自动改用**机制 B：当前用户登录自启项**（`HKCU\...\Run`，零管理员权限）；
- 明确打印**实际生效的是哪个机制**，不会让你误以为计划任务装上了。

机制 B 对「让 `LastCheckQU` 保持新鲜」这个目标其实更贴切：IDM 的 `LaunchOnStart=1`，
登录时 IDM 与被刷新的时机一致；且刷新间隔（每次登录）远小于 7 天窗口。

想用真正的计划任务：**以管理员身份**重跑一次 `-InstallTask` 即可，机制 B 的 Run 项会被覆盖为计划任务优先。

---

## 7. 测试清理声明

task-5 的验收要求「测完不留计划任务」。本次测试的清理状态（2026-10-16 21:57，实测）：

```
计划任务残留 : False      # Get-ScheduledTask -TaskName IDM-Patch-Lockdown -> 无
Run 项残留   : False      # HKCU\...\Run\IDM-Patch-Lockdown -> 无
临时注册表键 : False      # HKCU:\Software\DownloadManager-LockdownTest 已删除
IDMan.exe    : 527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552   # 补丁未受影响
LastCheckQU  : 1792159024 (2026-10-16 21:57:04 +08:00)
```

- `-InstallTask` 真实安装过一次（触发机制 B），随后用 `-RemoveTask` 删除，并**二次执行 `-RemoveTask` 验证幂等**。
- `schtasks /Create` 的探测任务 `IDM-Patch-Lockdown-Probe` **从未创建成功**（同样被 Access is denied 拒绝），无需清理。
- 临时注册表键 `HKCU:\Software\DownloadManager-LockdownTest`（§3.3 的门控闭环演示用）已删除。
- **没有启动过 IDMan.exe；没有修改安装目录任何文件**（`IDMan.exe` 属性仍为 `Archive`，哈希仍为补丁值）。
- 唯一留下的真实改动是：**`LastCheckQU` 被刷新到 2026-10-16 21:57:04**（单向收紧门控，只会更安全）。

---

## 8. 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 用法错误（多个动作开关同时给出） |
| 2 | 操作失败（注册表写入 / 计划任务注册或删除 / 兜底机制写入失败） |
| 3 | 环境不满足（`HKCU\Software\DownloadManager` 不存在，或本机无 `ScheduledTasks` 模块） |

---

## 9. 与其它交付物的关系（分工）

| 脚本 | 角色 | 何时跑 |
|---|---|---|
| `scripts/lockdown-update.ps1` | **预防**：让自动更新门控一直关闭 | 手动一次 + `-InstallTask` 常驻 |
| `scripts/check-patch-state.ps1` | **检测**：`IDMan.exe` 哈希是否还是补丁值 + 门控是否打开 | 定期 / IDM 升级后 / 重启后 |
| `scripts/patch_idm.py` + `scripts/deploy.ps1` | **修复**：重打补丁并部署 | `check-patch-state.ps1` 报 `REVERTED` 时 |

三者合起来才是完整的防回退闭环：**预防 → 检测 → 修复**。
只装 `lockdown-update.ps1` 不能防住「用户手动点检查更新」和「手工重装官方包」，
所以 `check-patch-state.ps1` 必须一起挂上。
