# 技术原理（ARCHITECTURE）

> 本文是 README 第七章的展开版。所有结论均来自**实机动态验证 + 静态双向交叉引用**，
> 原始证据与逐条证据卡见 [`REGISTRY/idm_6.43b15_registry.md`](REGISTRY/idm_6.43b15_registry.md)。

---

## 1. 目标身份

| 项 | 值 |
| --- | --- |
| 安装目录 | `C:\Program Files (x86)\Internet Download Manager\` |
| 主程序 | `IDMan.exe`（PE32，x86，ImageBase `0x400000`，MSVC，**无壳、无自校验**） |
| 辅助进程 | `IDMGrHlp.exe`（519,992 B，另一条弹窗路径的宿主） |
| 版本（基线） | 6.43 Build 15（`vCOUFP = 643b15`） |
| 版本（历史） | 6.43 Build 8（`FileVersion 6,43,8,2`） |

### 1.1 三套文件偏移公式（强制分别校验）

```
.text   RVA 0x001000  RAW 0x000400   文件偏移 = VA − 0x400C00
.rdata  RVA 0x295000  RAW 0x293600   文件偏移 = VA − 0x401A00
.data   RVA 0x37B000  RAW 0x378800   文件偏移 = VA − 0x402800
```

| 校验锚点 | VA | 文件偏移 |
| --- | --- | --- |
| P4 闸门点 | `0x44DE52` | `0x4D252` |
| `MData` 字符串 | `0x69D1E4` | `0x29B7E4` |
| `g_registered` 初值 | `0x77BD24` | `0x379524` |

> ⚠️ **踩过的坑**：曾把节表 `VirtualAddress`（RVA）当成绝对 VA，得出「`0x29D1E4` 才是真 VA」的误判。
> `.text` 的公式**不能**套到 `.rdata` 上。

---

## 2. 根因（实测确认）

```
伪造序列号
  → ~62 秒后本地/缓存判定 counterfeit
  → 写 MData 标记（256 B，REG_NONE，CLSID 树下）
  → ExitProcess(0)
  → 旧守护删 MData + 轮换新假号
  → 新假号又被判假
  → 自伤闭环
```

| 观测时刻 | 配置 | 结果 |
| --- | --- | --- |
| 01:00:46 | 伪造序列号 + hosts 全屏蔽 | **64.0 s 写 MData，exit 0** |
| 00:38:43 | 伪造序列号 + 防火墙单 IP | **62.0 s 写 MData，exit 0** |
| 00:58:23 | **无**序列号 + hosts 全屏蔽 | **93 s+ 存活，无 MData、无退出**（弹注册框） |

- 网络已被 hosts 劫持到 `0.0.0.0`（DNS 实测）后 tripwire **仍精准触发** ⇒ 判定是**本地/缓存逻辑**，不是实时联网。
- `MData` 是 tripwire 载荷，不是良性心跳。
- `MData` 的引用代码**未加密**：文件内 **19 处明文 `68 E4 D1 69 00`**，19/19 带 type-3 HIGHLOW 重定位。

---

## 3. 层 A · 注册状态

### 3.1 关键全局 `g_registered`

- 位于 `.data`，静态初始化器在文件偏移 `0x379524`，原值 `01 00 00 00`。
- 语义：**`0` = Full（已注册），非 `0` = Trial**。由「改字节 → 关于对话框由 Trial 变 Full」实测反推确认。
- 全 `.text` 对该全局 45 处引用，**只有 2 处是写**，且两条都是 `mov dword [flag], 0`（都在「注册成功」路径上）。
- **没有任何代码能把它写回非 0** ⇒ 改掉初始化器后，该标志在整个进程生命周期内恒为 0，效果不可恢复。

判定点（「关于 IDM」对话框）：

```asm
0x0040399F  xor  ebx, ebx
0x004039D0  cmp  dword ptr [0x779CDC], ebx   ; ebx = 0
0x004039D6  je   0x4039DF                    ; flag == 0 → "Full"
0x004039D8  push 0x695E50                    ; "Trial"
0x004039DF  push 0x695E48                    ; "Full"
0x004039E4  call 0x403060                    ; CString::operator=
```

### 3.2 counterfeit 残留清理

- 遍历**整棵 CLSID 树**删掉所有 `MData` 值（**不写死 GUID** —— 键会随版本新增）。
- 清 `{E6871B76-…}` 键下缓存的服务端校验判决值（值名由 XOR 派生，整键清值最稳）。64 位与 32 位视图都清。
- 写 `Serial` / `FName` / `LName` / `Email` 到 **HKLM 的 32 位视图**（`WOW6432Node`）。

> ⚠️ **必须写 HKLM，不是 HKCU**。IDM 是 32 位进程，读 `HKLM\SOFTWARE\Internet Download Manager`，
> 在 64 位系统上落到 `HKLM\SOFTWARE\WOW6432Node\Internet Download Manager`。实测只写 HKCU 完全无效。

> ⚠️ `MData` 的真实落点在
> `HKCU\Software\Classes\WOW6432Node\CLSID\{79873CC5-3951-43ED-BDF9-D8759474B6FD}`；
> **只搜 `HKCU\Software\DownloadManager` 会得到假阴性**。

---

## 4. 层 B · 二进制补丁

补丁清单与证据卡见 [`PATCHES.md`](PATCHES.md)。

### 4.1 付费弹窗的四跳延迟链（b8 主线，解释「为什么过一会儿才弹」）

```
FUN_005BD440  (下载编号分配器)
  0x5BD4EA  cmp dword ptr [0x779CDC], 0        ; ← 唯一总门控
  0x5BD4F1  je  0x5BD510                       ; 非 Trial 直接跳过
  0x5BD4FF  push 0x14D8                        ; 全镜像唯一一处魔数
  0x5BD50A  call [0x6947C8]                    ; PostMessageA(hMainWnd, WM_COMMAND, 0x14D8, 0)
        ↓
FUN_0048F5D0 (CDownloaderDlg vtable slot 60)   case 0x14D8 @ 0x49402D
  0x49402F  push 0x15F90                       ; 90000 ms
  0x494034  push 0x2D                          ; nIDEvent
  0x494038  call 0x423E90                      ; SetTimer(hwnd, 0x2D, 90000, NULL)
        ↓  (90 秒后 WM_TIMER, nIDEvent = 0x2D)
FUN_00486990 (CDownloaderDlg::OnTimer)         case 0x2D @ 0x487733
        ↓
FUN_0047D2C0 (弹窗本体)
  「是」→ PostMessageA(g_hMainWnd, WM_COMMAND, 0x2B48, 0) → 注册对话框
```

**结论**：弹窗不是被下载流程直接调用的，中间隔着 **90 秒 `SetTimer`**；
而 `0x14D8` 的唯一 `push` 处前 13 字节就是 `g_registered` 门控 ⇒ P1 改一个字节即可从入口短路整条链。

### 4.2 b15 的多显示点现实

b15 之后 counterfeit 走的是**广播线程**路径（P7），且显示端存在多个变体：

| 变体 | 位置 | 覆盖补丁 |
| --- | --- | --- |
| 双按钮 / 无从句 | `IDMGrHlp.exe` `0x52A1` / `0x52C8` | **P8**（受控 A/B 验证） |
| 单按钮 / 带从句（命令行路径） | `IDMan.exe` file `0x75444` | **P10**（端到端 PASS） |
| 潜伏长版 | `IDMan.exe` | **P11**（预防性，无法动态触发） |
| 其余 `uType==0x41030` 显示点 ×4 | `IDMan.exe` | **P14**（枚举 + wrapper 短路） |
| 下载路径（浏览器触发） | `IDMan.exe` file `0x98C7E` | **P14 wrapper 短路覆盖** |

全库 `sub_474D20` 调用点 **260 处**，其中 `uType == 0x41030` 的 **6 处**。
P14 在 wrapper 入口按 `uType` 短路 ⇒ **一处覆盖全部显示点 + 未来路径**，其余 244 处不受影响。

### 4.3 为什么 P14 能「一处封全」，而 P15 必须逐点

| | 共同门控是否存在 | 结论 |
| --- | --- | --- |
| 弹窗显示（P14） | `sub_474D20` 是**唯一出口**（253 处调用都经它） | ✅ 一处封全 |
| 注册框创建（P13/P15） | 启动路径与下载路径是**两条独立 case 体** | ❌ 必须分别封 |

---

## 5. 层 C · 防回退

### 5.1 文件不可变

```powershell
icacls "<IDMan.exe>" /deny "*S-1-1-0:(WD,DE)"     # 施加
icacls "<IDMan.exe>" /remove:d "*S-1-1-0"          # 回滚
```

- 官方更新包**无法覆盖或删除**打过补丁的二进制 —— 这就是**不需要守护**的根本原因。
- 施加后**必须回读 ACL 验证**：`icacls` 回读时会把 SID 显示成账户名 `Everyone`，判定要同时认两种写法。
- ⚠️ **`DENY(W,D)` 会让 Frida spawn 失败**（`frida.NotSupportedError … 0x00000005`）。
  需要动态观测前先 `/remove:d`，观测结束后再重新施加。
- ⚠️ 非 NTFS 卷上 ACL 不可用，会跳过并**明确报告**（不静默失败）。

### 5.2 hosts 屏蔽

- 6 个注册/校验域名 → `0.0.0.0`（域名级，抗 IP 漂移）。
- 写完**必须 `ipconfig /flushdns`**，否则缓存让屏蔽形同虚设。
- 还原后也要刷：否则缓存里的 `0.0.0.0` 会让屏蔽「死而不僵」。
- **验证必须用 `ping`**：`Resolve-DnsName` / `getaddrinfo` 会读 hosts 并返回 `0.0.0.0`，给出**假通过**。
- 统计生效行时**不能按 marker 字符串计数**：被 `#` 注释掉的行也算数（实测 3/6 行被注释，旧检查误报成功）。
  正确判据：行首不能是 `#`，且必须匹配 `^0\.0\.0\.0\s+<域名>`。

---

## 6. 引擎设计

### 6.1 极简 PE 解析器（`idm_engine.PE`）

- 零第三方依赖，只用 `struct`。
- 提供：节表遍历、RVA/文件偏移互转、导入表解析（拿 `ExitProcess` / `RegSetValueExA` / `MessageBoxA` 的 IAT 槽）、
  字符串查找（`find_string` / `find_all`）、`text_span()`。

### 6.2 特征码定位原则

1. **不用硬编码偏移**：全部靠指令形状 + 字符串 + 重定位交叉验证。
2. **双校验**：内容锚定（字符串/密文）+ 结构锚定（前后指令序列）。
3. **失败即安全**：任一校验不过 ⇒ `return None, notes`，**拒绝**打这一处并明确报告。
4. **幂等**：finder 必须同时认「未补丁形态」和「已补丁形态」，否则二次施加会误判或叠加。

### 6.3 自证式完整性校验

补丁点表**不能**用来判断补丁是否完整（finder 以原始字节为锚点，文件打过补丁后锚点即失效 ——
实测：原始 b15 定位到 10 点，全补丁 b15 只剩 3~6 点）。

`verify_patched()` 的做法：拿 `IDMan.exe.bak-original` 在临时目录用**同一个引擎**重跑一遍，
算出「本机原版 + 本版引擎」应有的补丁后哈希，再与实际文件比对。不依赖任何硬编码常量。

### 6.4 系统级护栏

`system_changes_allowed(args, install_dir)`：只有目标确实是实机安装目录（两个标准路径之一，
或注册表 `ExePath` 指向的目录）时才允许碰注册表 / hosts / 计划任务 / 杀进程；否则一律跳过并打印原因。
强行动系统级状态必须显式加 `--allow-system-changes`。

---

## 7. 已知限制

1. **`--activate` 的端到端验证需在目标机器上执行**；scratch 副本只能验证二进制补丁路径（哈希自证）。
2. **hosts 屏蔽可能被绕过**：DNS-over-HTTPS、代理或 VPN 环境下 hosts 不一定拦得住；`--status` 的 ping 探测会如实报告。
3. **DNS 探测是尽力而为**：依赖本机网络状态，不参与「成功/失败」判定，只作为给用户看的证据。
4. **`--status` 会发 6 次 ping**（每域名一次，超时 800 ms），因此需要数秒；它是只读的，但**不是零网络活动**。
5. **`MData` 可能被重新写入**：它只是 IDM 反复覆盖的注册表值，无害；`--status` 报「存在 MData 残留」不代表激活失败。
6. **非 NTFS 卷**：ACL 不可用，会跳过「文件不可变」并明确报告。
