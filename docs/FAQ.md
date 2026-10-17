# 常见问题（FAQ）

## 一、功能相关

### Q1：为什么 `--status` 说「存在 MData 残留」，但弹窗确实没了？

`MData` 只是 IDM 反复覆盖的注册表值（256 B `REG_NONE`），**本身无害**。
它原本的作用是给 tripwire 记账，而 tripwire 的**出口**已经被 P5 封死、**弹窗**已经被
P6/P7/P8/P10/P11/P14 封死。所以「有 MData」≠「激活失败」。
想清理就再跑一次 `--activate`，也可以直接忽略。

### Q2：到期时间显示 `Dec/31/9999`，是真的永不过期吗？

**不是。** IDM 的 `nExpDt` 是 **32 位 `time_t`**（读取时 `lpcbData = 4`），硬上限 **2038-01-19**，
9999 在该字段里**结构上不可达**。本工具改的是 `strftime` **格式串**
（`%b/%d/%Y` → `%b/%d/9999`，`9999` 作为字面量原样输出），所以界面如实显示 9999。

**真正保证「不过期」的是 P1（`g_registered = 0` → Full）**，不是这个日期。
这个补丁只是让显示与状态一致，避免「Full 但到期 2026」这种自相矛盾的画面。

### Q3：为什么改一个字节就能解锁？

因为 `g_registered` 是**唯一总门控**：

- 全 `.text` 对它 45 处引用，**只有 2 处是写**，且都是 `mov dword [flag], 0`（注册成功路径）；
- **没有任何代码能把它写回非 0**；
- 付费弹窗的触发链第一跳就是 `cmp dword [flag], 0` / `je`。

所以改掉静态初始化器的那 1 个字节后，该标志在**整个进程生命周期内恒为 0**，效果不可恢复。

### Q4：为什么「点下载之后要等一会儿才弹」？

不是网络请求，是 **90 秒 `SetTimer`**：

```
下载编号分配器 → PostMessageA(WM_COMMAND, 0x14D8)
  → case 0x14D8: SetTimer(hwnd, 0x2D, 90000, NULL)
  → WM_TIMER(0x2D) → 弹窗本体
```

详见 [`ARCHITECTURE.md`](ARCHITECTURE.md) 第 4.1 节。

### Q5：为什么 P12 被标成 RETIRED？

P12（`license_valid`，改 `byte_788CF4`）**实测无效**：手工热补丁 + 冷启动验证，
注册框照旧弹 **12/12**。根因是 `byte_788CF4` 根本不是「决定弹注册框」的标志，
真正的门控在 `sub_451E30` 的 `cmp esi,ebx / je`（也就是 P13）。
实现保留在代码里作为「被否证方案」的记录，**不要重新启用**。

### Q6：为什么 b15 上 P3 经常「不命中」？

b15 把那段试用文案**整段删掉了**（连 `"Trial"` 字符串都从镜像移除，`"Full"` 变成默认分支）。
P3 是靠文案字面量定位的，所以不命中是**正常现象**，不是失败 ——
b15 的等价效果由 P1 + P13 + P14 承担。

---

## 二、安全 / 回滚

### Q7：会留下常驻进程或计划任务吗？

**不会。** 这是本版与旧版最大的区别：

| 维度 | 旧版（守护方案） | 本版（静态三层） |
| --- | --- | --- |
| 常驻进程 | 计划任务，30 分钟一次 | **无** |
| 自伤闭环 | 存在 | **不存在** |
| 抗 IDM 更新 | 更新后靠守护重打补丁 | **预防**：ACL 不可变，更新包写不进去 |
| 需要维护 | 是 | **否** |

`--activate` 会**主动删除**旧版遗留的守护计划任务与 `Run` 自启项。

### Q8：`--guard` 还有用吗？

已废弃。它现在只打印一段说明并 `exit 0`，**不装任何东西**。
保留的原因是：用户机器上可能还残留旧计划任务在定期拉起这个命令，
不能让它变成报错或闪窗。`--no-guard` 同理，是空操作。

### Q9：怎么完全回滚？

```powershell
.\release\IDM-Activator.exe --uninstall
```

依次：删旧守护任务/自启项 → 移除 `DENY` ACE → 从 `.bak-original` 还原 `IDMan.exe`
→ 清 `MData` 与缓存判决 → 清注册信息 → 还原 hosts 并刷 DNS 缓存。**幂等，跑两次不报错。**

最彻底的做法：`--uninstall` 后重装官方安装包。

### Q10：备份在哪里？

| 备份 | 位置 |
| --- | --- |
| 原始 `IDMan.exe` | `<安装目录>\IDMan.exe.bak-original` |
| 原始 `IDMGrHlp.exe` | `<安装目录>\IDMGrHlp.exe.p8bak` |
| 原始 hosts | `...\drivers\etc\hosts.bak-permanentfix` |

---

## 三、环境 / 网络

### Q11：hosts 写了但 `ping` 还是真实 IP？

1. **必须 `ipconfig /flushdns`** —— 实测 hosts 完全正确（6 行、无 BOM、CRLF）时，
   `ping internetdownloadmanager.com` 仍会解析到真实 IP `67.18.60.145`，刷完才生效。
2. **DNS-over-HTTPS / 代理 / VPN** 可能绕过 hosts，此时 `--status` 会如实报告「仍解析到真实 IP」。
3. **注释行不算数** —— 早期检查因为「行里含 marker 字符串」把被 `#` 注释的行也统计成成功
   （实测 3/6 行被注释）。现在的判据是：行首不是 `#`，且匹配 `^0\.0\.0\.0\s+<域名>`。

### Q12：为什么验证 DNS 必须用 `ping`，不能用 `Resolve-DnsName`？

`Resolve-DnsName` / `getaddrinfo` **会读 hosts** 并返回 `0.0.0.0`，给出**假通过**。
`ping` 走的是完整解析 + 实际发包路径，能暴露缓存未刷新的情况。

### Q13：ACL 加了之后 Frida 注入失败？

`DENY Everyone (WD,DE)` 会让 Frida spawn 报 `frida.NotSupportedError … 0x00000005`
（Frida 注入需要该 exe 的**写权限**）。动态观测前：

```powershell
icacls "<IDMan.exe>" /remove:d Everyone
```

观测结束后重新施加。**ACL 防更新只能在全部动态观测/验证结束后施加。**

### Q14：`IDMan.exe` 提示「being used by another process」但没有 IDM 进程？

这是**瞬时独占锁定**（连重命名都失败）。标准姿势：

1. 可写探测：`[IO.File]::Open($p,'Open','ReadWrite','None')` 试开即关
2. 失败则退避重试（2s × 15）
3. 仍失败再用 **Restart Manager API**（`RmStartSession` / `RmRegisterResources` / `RmGetList`）报出持有者 pid

**不要直接杀进程** —— 实测持有者常常是一个 powershell 进程，它退出后锁自动释放。

---

## 三·五、专项：`IDM is corrupt`（主程序已损坏）弹窗

> 症状：**后台挂一段时间后**弹出 `IDM is corrupt`，正文大意是
> "The main IDM executive file is damaged. It's possible that it was infected with a virus…"

### 根因：hosts 挡不住 IDMan.exe 自己

IDM 自带的 `Languages\*.lng` 里就写着：

> *"IDM will check for updates successfully even with your damaged hosts file."*
> （就算你把 hosts 改坏了，IDM 照样能检查更新。）

实测也印证：hosts 6/6 全绿时，`www.` / `secure.` / `register.internetdownloadmanager.com`
仍解析到 `67.18.60.145` / `67.18.140.140` 并可达（`ping` 实测）。
hosts 是**按域名**拦截，而 IDM 可以直连 IP 或走自己的解析路径。

### 修复（v1.0.1 层 C 第三层）：防火墙出站阻断

```powershell
netsh advfirewall firewall add rule name="FuckIDM-Block-AuthServers" ^
  dir=out action=block ^
  program="C:\Program Files (x86)\Internet Download Manager\IDMan.exe" ^
  remoteip=67.18.0.0/16 enable=yes profile=any
```

- 只挡 **67.18.0.0/16**（IDM/tonec 服务器段），**不影响普通下载**
- `--activate` 自动施加，`--uninstall` 自动移除
- `--status` 显示：已生效 / 需要管理员权限才能查询 / 未设置

### 顺带修掉的真 bug：hosts 三行被注释

旧版 hosts 里 `www.` / `secure.` / `register.` 三行被写成 `#0.0.0.0 ...`（注释掉了），
于是「生效 3/6」却被旧检查判成成功（因为旧检查只数「行里含 marker 的行数」）。
现在 `HOSTS_DOMAINS` 扩到 **11 个**，`hosts_state()` 只统计**真正生效**的行。

> ⚠️ **父域名屏蔽 ≠ 子域名屏蔽**。hosts 是精确匹配：
> `0.0.0.0 internetdownloadmanager.com` **不会**拦住
> `www.internetdownloadmanager.com`。必须逐个写。

### 为什么 hosts 的屏蔽行总被拆掉？加 ACL 也挡不住？

**因为 IDM 装了一个内核文件系统驱动。**

```powershell
sc query idmwfp
# SERVICE_NAME: idmwfp
#         TYPE               : 2  FILE_SYSTEM_DRIVER     ← 文件系统驱动
#         STATE              : 4  RUNNING
#         START_TYPE         : 2  AUTO_START
#         BINARY_PATH_NAME   : \SystemRoot\System32\drivers\idmwfp.sys
```

它挂在**文件系统栈**上，**在 ACL 检查之前/之后都能直接操作文件** ——
所以 `Everyone:(DENY)(DE,WD)` 对它**完全无效**。实测时间线（同一天六次观测）：

| 时刻 | 事件 | hosts |
| --- | --- | --- |
| 16:00:18 | 手动取消注释 | **11 行** |
| 16:00:40 | IDM 启动后 1 秒 | **6 行被重新注释** |
| 16:02:04 | 加 `DENY(DE,WD)` 再修 | **11 行** |
| 16:02:18 | IDM 重启后 3 秒 | **又是 6 行** |
| 16:37:21 | 用 `RunLevel=Limited` 计划任务启动 | **仍被改** |
| **16:38:34** | **`sc stop idmwfp` + `start= disabled`** | 修回 11 行 |
| 16:41:38→16:43:38 | 连续 120 s 观测 | **恒 11 行，mtime 不变** ✅ |

**修复**：`--activate` 会自动

1. `sc stop idmwfp`
2. `sc config idmwfp start= disabled`
3. 把安装目录里的 `idmwfp*.sys` / `idmtdi*.sys` **副本改名**（防 IDM 装回来）

> ⚠️ **`RunLevel=Limited` 对 Administrator 账户无效** —— 仍属 Administrators 组、
> 仍有 `SeRestorePrivilege`，所以「降 IDM 权限」这条路走不通，**必须停驱动**。

**代价**：IDM 的「高级浏览器集成」会失效（浏览器里点下载不再自动接管）。
**手动「添加任务」/ 拖链接 / 剪贴板监听不受影响**。要恢复：`--uninstall`（会 `start= auto` 并还原 .sys）。

### 怎么确认已经挡住

1. `--status` 看两项：`hosts 屏蔽：生效 11/11` + `防火墙阻断：已生效`
2. `ping www.internetdownloadmanager.com` → 应「不可达 / 无解析」
3. 挂机观察 ≥ 40 分钟（弹窗是周期性的）
4. 若仍弹，请提供：弹窗**完整截图** + **精确标题** + `--status` 全文 +
   弹窗时刻前后的 `%LOCALAPPDATA%\IDM-Activator\activator.log`

### 已排除的方向（避免重复劳动）

| 方向 | 结论 |
| --- | --- |
| 补丁完整性 | ✅ 20/24 点认回，自证哈希 = 装机 `B6C45453…` |
| PE CheckSum | ✅ stored = 计算值（`ensure_pe_checksum` 已处理） |
| 数字签名校验 | ❌ IDM **没有** `WinVerifyTrust` 导入 → 不是签名问题 |
| 「检查更新」菜单（网络放开 A/B） | 90 s 无弹窗 → 不是这条命令直接触发 |
| 下载触发（1 MB 本地 HTTP） | 150 s 无弹窗 |
| 文案定位 | `The main IDM executive file is damaged.` @ `.data` VA `0x37C5CC`（XOR `0x3D`） |
| 完整正文 | **不在本地任何文件**（11 个 exe/dll/lng 全扫）→ 服务端下发 |

---

## 四、开发 / 贡献

### Q15：新版 IDM 出来了怎么办？

1. 先跑 `--scan` 看命中情况（不写任何东西）
2. 若某补丁点不命中，按 `docs/PATCHES.md` 的「抗混淆锚点」重新定位
3. 提交 PR 时请附：原始文件 SHA-256、`--scan` 输出、命中的锚点、反汇编片段

### Q16：为什么锚点有时「过严」导致假阴性？

真实踩过的坑：P9 曾要求「调用点 +10 B 处必是 `RegFlushKey`」当锚点 ——
这个锚点**对 `sub_466EE0` 成立、对 `sub_521050` 不成立**，把 `0x120A54`（MData 真·活路径）
判为假候选排除，直接造成漏点。

**教训：凡用于「排除」候选的锚点，都要反问「它会不会对别的函数形态不成立」。**
锚点过严 = 假阴性，与过松 = 假阳性**同样危险**。

### Q17：为什么不能只靠静态分析判定「死代码」？

实测反例：曾据 `cmp eax,7DCh`（2012）判定 `sub_521050` 三处 `MData` 写入为死代码，
而动态实测（`t = 62.425 s`）证明活路径**正是那一处**。

**死代码结论必须有动态证据**：断点命中 + 命中时刻 + 参数值三重对齐。

### Q18：补丁点表为什么不能用来判断「补丁是否完整」？

finder 以**原始字节**为锚点。文件一旦打过补丁，锚点就失效 ——
实测原始 b15 定位到 10 点，**全补丁** b15 只剩 3~6 点。

所以完整性校验改用**自证式**：拿 `.bak-original` 在临时目录用同一引擎重跑一遍，
算出应有的哈希再比对。也不要用硬编码哈希（引擎一升级哈希就变）。
