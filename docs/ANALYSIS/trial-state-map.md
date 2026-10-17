# IDM 6.43b8 —— 试用状态数据模型 与 用户可见出口全量普查

**目标**：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（IDM 6.43 Build 8，x86 MSVC，ImageBase 0x400000）
**分析副本**：`work/idm-6.43b8/bin/IDMan.exe.orig`，sha256 `74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8`
**方法**：纯静态（PE 手工解析 + capstone 线性反汇编 + 跳转表/RTTI 还原 + Ghidra 12.1.2 headless `-readOnly` 反编译）。
**合规**：未启动 IDMan.exe；未修改安装目录任何文件；注册表仅只读查询；Ghidra 全程 `-readOnly`。

**地址换算**
- `.text`：`file_off = 0x400 + (VA - 0x401000)`
- `.rdata`：`file_off = 0x292800 + (VA - 0x694000)`
- `.data`：`file_off = 0x377600 + (VA - 0x779000)`

---

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| **除了 `g_registered`，还有没有第二个能独立让 IDM 认为"试用已到期"的状态源？** | **有，而且是三个独立的轴。** ① 注册表 `Therad`/`Model` 天数计数器（`days_used >= [0x779CE0]`）；② 已注册分支的**许可证持有人一致性检查**（HKLM `FName`/`LName` 读不到就落到"未注册"分支）；③ 三个**完全不查 `g_registered`** 的 EndTrial 弹窗产生者。 |
| P1（`g_registered=0`）是"关掉试用"的正确做法吗？ | **一半对。** 它关掉了 0x14D7 那条链（已验证），但它**同时把试用天数阈值从 30 降到 15**，并且把 IDM 推进了一个需要 HKLM 许可证数据的分支。 |
| 用户看到的"免费试用已经到期"弹窗是什么？ | `CShowEndTrialDlg`（RTTI `.?AVCShowEndTrialDlg@@`），由 `FUN_004747A0` @VA 0x4747A0 通过 `DoModal` 弹出，触发命令 = **WM_COMMAND 0x14DF**。 |
| 修它最省事的下刀点？ | **`FUN_004747A0` 入口 3 字节改成 `33 C0 C3`**（`xor eax,eax; ret`）—— 三个产生者全部汇流到这一个函数，一处改动全灭。 |

---

## 1. 试用状态数据模型

### 1.1 全局变量

| # | 名称 | 位置 | 写入点 | 读取点 | **本机当前值** | 对可见行为的贡献 |
|---|---|---|---|---|---|---|
| G1 | `g_registered` | VA `0x779CDC`（`.data` 初值 @file `0x3782DC`） | **仅 2 处，且都写 0**：`0x450DB0`、`0x523A70`（均为 `c7 05 dc 9c 77 00 00 00 00 00`） | 24 处 | **0 = Full**（P1 已改） | 主开关：选 Full 分支还是 Trial 分支；并且**决定 G2 的取值** |
| G2 | `trial_day_thresh` | VA `0x779CE0` | **仅 1 处** @`0x44CC36` | 5 处：`0x44DB3C`、`0x4670A1`、`0x4670C3`、`0x487313`、`0x48786A` | **15**（P1 之前是 30） | "允许的试用天数"上限，与注册表天数计数器比较 |
| G3 | `g_hMainWnd` | VA `0x7873B0` | — | 多处 `PostMessageA` | 有效窗口句柄 | 所有命令派发的目标窗口 |
| G4 | `license_expiry_cached` | VA `0x787844` | 2 处：`0x51F52B`（注册对话框 ctor）、`0x520F1A`（**注册校验路径**，写前先 `RegDeleteValueA("nLst")` @`0x520F0C`） | 1 处：`0x523D7E`（用 `%b/%d/%Y` 格式化显示） | 进程内 0（未注册） | 注册对话框里的许可证到期显示 |
| G5 | `lic_name_FName` | VA `0x788608`（值名运行时 Feistel 解密为 `"FName"`） | 由解密器填充 | `0x44DB8C`、`0x467114` 等（作为 `RegQueryValueExA` 的值名） | 解密后为 `FName` | 读 HKLM 许可证持有人名字 |
| G6 | `lic_name_LName` | VA `0x78860C`（→ `"LName"`） | 同上 | `0x44DBB9`、`0x46713A` | 解密后为 `LName` | 同上（姓） |
| G7 | `lic_name_Serial` | 由 `FUN_0052DE80` @`0x52DE80` 解密 | 密文 `a1 c1 60 5b b5 fd 7d 8d` + 密钥 `"947362057192834"` → `"Serial"` | `0x42E0A0`（更新按钮路径） | 解密后为 `Serial` | 更新前校验序列号 |
| G8 | `expiry_fmt` | VA `0x695E60` = `"%b/%d/%Y"`（**全镜像唯一**） | — | 3 处 `push`：`0x40380A`、`0x48A2B9`、`0x523D8E` | 已被 P2 改为 `"%b/%d/9999"` | 三处都是"许可证到期时间"显示 |

**G2 的完整算法**（VA `0x44CC27`，逐字节）：

```asm
0x0044CC27  mov  eax, dword ptr [0x779cdc]   ; A1 DC 9C 77 00
0x0044CC2C  neg  eax                         ; F7 D8
0x0044CC2E  sbb  eax, eax                    ; 1B C0   (eax = -1 if trial, 0 if full)
0x0044CC30  and  eax, 0xf                    ; 83 E0 0F
0x0044CC33  add  eax, 0xf                    ; 83 C0 0F
0x0044CC36  mov  dword ptr [0x779ce0], eax   ; A3 E0 9C 77 00   => Trial?30:15
```

> **这就是 P1 的副作用**：`g_registered=0` ⇒ `eax=0` ⇒ `0+0xF = 15`。阈值从 30 变成 **15**，
> 天数计数器只需累积到 15 天就会判"到期"，**触发速度翻倍**。

### 1.2 注册表值（HKCU\Software\DownloadManager，全部为本次实测只读查询）

| 值名 | 类型 | 写入点 | 读取点 | **本机当前值** | 贡献 |
|---|---|---|---|---|---|
| `Therad` | REG_DWORD | `RegSetValueExA` @`0x44DB21`（变体 @`0x467089`） | `RegQueryValueExA` @`0x44DB18`（变体 @`0x467080`） | **不存在（=0）** | **"已用试用天数"累加器** —— 第二个状态源的核心 |
| `Model` | REG_DWORD | @`0x44DB30`（变体 @`0x467095`） | 与 `Therad` 同块 | **不存在** | 与 `Therad` 配对的基准时间戳 |
| `tvfrdt` | REG_DWORD | 未定位（名字为运行时解密，非明文） | 未定位 | `2107457418` → **2036-10-13** | 疑似"试用版本首次运行/到期"时间戳（未来日期） |
| `scansk` | REG_BINARY | 未定位 | 未定位 | **64 字节** | 加密的许可证状态串；`FUN_00450AE0` 解密后与关键字比较决定 counterfeit |
| `nLst` | REG_DWORD | 被**删除** @`0x520F0C` | @`0x4038B6`（About 分支） | **不存在** | 许可证标记；`==1` 时 About 用 `DAT_00788928` 设置文案 |
| `nExpDt` | REG_DWORD | IDM 内无写入点（由外部/我们写） | @`0x4037E2`（About）、@`0x48A28E` | `2145873600`（我们设的） | 纯显示：许可证到期行 |
| `radxcnt` | REG_DWORD | 每次启动 +1 | — | **108** | 启动计数 |
| `idmvers` | REG_SZ | IDM 自己写 | — | `v6.43b08 Full` | 版本串（P1 后由 `Trial` 变 `Full`） |
| `FName`/`LName`/`Serial`/`Email` | REG_SZ | — | `0x44DB8C`、`0x44DBB9`、`0x42E0A0` | **全部不存在** | 许可证持有人身份（HKLM 优先，回落 HKCU） |

### 1.3 天数计数器的完整逻辑（**第二个状态源的实体**）

两处**独立但同构**的副本 —— `0x44DAE0` 区块（属 `FUN_0044CBE0`）与 `0x467040` 区块（Ghidra 未分析）：

```asm
; ---- 读 Therad ----
0x00467049  mov  ecx, dword ptr [ebp - 0x24]      ; days_used（来自 Therad）
0x0046704C  cmp  ecx, dword ptr [0x779ce0]        ; vs 阈值（P1 后 = 15）
0x00467052  jae  0x4670d2                          ; >= 阈值 => 判到期
; ---- 未到期：累加并写回 ----
0x00467054  mov  eax, [ebp-0x2c]                  ; Model（上次时间戳）
0x00467057  mov  ecx, [ebp-0x34]                  ; 本次时间戳
0x0046705A  cmp  eax, ecx
0x0046705C  je   0x4670c3                          ; 同一天，不累加
0x0046705E  jbe  0x46706e
0x00467060  sub  eax, ecx
0x00467062  cmp  eax, 0x14                         ; 单次增量上限 20 天
0x00467065  jbe  0x467073
0x00467067  mov  eax, 0x14
0x0046706E  mov  eax, 1
0x00467073  add  dword ptr [ebp - 0x24], eax       ; days_used += delta
0x00467080  push 0x6a0318  ; "Therad"              ; <-- 值名 VA
0x00467089  call ebx                                ; RegSetValueExA
0x00467095  push 0x6a0320  ; "Model"
0x0046709E  call ebx                                ; RegSetValueExA
; ---- 剩余天数提示 ----
0x004670A0  mov  eax, [0x779ce0]
0x004670A5  sub  eax, [ebp-0x24]                   ; remaining = 阈值 - days_used
0x004670A8  lea  ecx, [eax - 1]
0x004670AB  cmp  ecx, 0xe                          ; remaining ∈ [1,15]
0x004670AE  ja   0x4670c3
0x004670B1  push 0x13ca                            ; WM_COMMAND 0x13CA（"还剩 N 天"）
0x004670BE  call 0x43b030                          ; 发消息
; ---- 到期分支 ----
0x004670C3  mov  edx, [0x779ce0]
0x004670C9  cmp  [ebp-0x24], edx
0x004670CC  jb   0x4673ea                          ; 仍未到期 -> 正常路径
0x004670D2  cmp  dword ptr [0x779cdc], 0            ; <== 到期了，再按 g_registered 分流
0x004670D9  jne  0x46734d                            ; Trial -> 0x46734D
                                                    ; Full  -> 落到 0x4670DF
```

**关键**：`0x4670DF` 起的 Full 分支**并不是"什么都不做"**，它去读 HKLM 的许可证持有人：

```asm
0x004670DF  lea  eax, [ebp - 0x20]
0x004670E7  push 0x695e78  ; "SOFTWARE\Internet Download Manager"
0x004670EC  push 0x80000002 ; HKEY_LOCAL_MACHINE
0x004670F1  call dword ptr [0x694098]              ; RegOpenKeyExA
0x004670F7  mov  ebx, 0x32
0x004670FC  test eax, eax
0x004670FE  jne  0x46721d                          ; 打开失败 -> 走另一分支
0x00467114  mov  eax, dword ptr [0x788608]         ; "FName"
0x0046711E  call esi                                ; RegQueryValueExA
0x00467120  test eax, eax
0x00467122  jne  0x46721d                          ; 读不到 -> 走另一分支
0x0046713A  mov  ecx, dword ptr [0x78860c]         ; "LName"
0x00467145  call esi
0x00467147  test eax, eax
0x00467149  jne  0x46721d
```

`FUN_0044CBE0` 里的同构副本（`0x44DB55` 起）读的是同一对值：`0x44DB8C`(`FName`)、`0x44DBB9`(`LName`)。

**⇒ 本机 HKLM 下没有 `Internet Download Manager` 键的许可证值**（实测：只有 `AdvIntDriverEnabled2` / `MaxClientId`），
所以"到期 + Full"这条组合会**读不到持有人而落到"未注册"分支**。

### 1.4 第 1 问的明确回答

> **有。除了 `g_registered`，至少还有两个能独立让 IDM 认为"试用已到期"的状态源：**
>
> 1. **`Therad` 天数计数器**（HKCU，与 `Model` 配对）。判据是 `days_used >= [0x779CE0]`。
>    `g_registered` 只影响**阈值大小**（30/15），**不参与**"是否到期"这个判断本身。
>    也就是说：即使 `g_registered` 已经是 0（Full），只要 `Therad` 累积到阈值，这条路径照样判到期。
> 2. **许可证持有人一致性检查**。已注册分支要求 HKLM/HKCU 里存在 `FName`/`LName`（乃至 `Serial`）；
>    本机全都没有，于是"Full"这个状态在 IDM 自己看来是**自相矛盾**的，会退回"未注册/请购买"的表现。
>
> 另有第三个轴的候选：`tvfrdt`（2036-10-13）与 64 字节的 `scansk` 状态串。二者的值名/语义都由
> 运行时 Feistel 解密产生（非明文），本次未完成到指令级定论，**标注为未决**（见 §6）。

---

## 2. 用户可见出口清单

| # | 弹窗 / 出口 | 类名 / 文案来源 | 创建点 VA | 门控表达式 | 覆盖状态 |
|---|---|---|---|---|---|
| E1 | **试用到期购买弹窗** | `CShowEndTrialDlg`（RTTI `.?AVCShowEndTrialDlg@@` @file `0x37BDCC`；COL @file `0x3366CC`；vtable VA `0x6C4D94` / `0x6C4D64`） | ctor VA **`0x532340`**（file `0x131740`）；执行者 **`FUN_004747A0`** @VA `0x4747A0`（file `0x73BA0`），`DoModal` @`0x474830` | **WM_COMMAND `0x14DF`**（跳转表 idx 74 / 字节映射 0x91） | ❌ **未覆盖（重点）** |
| E2 | 试用登记弹窗 "…Do you want to register your copy of IDM now?" | 文案 VA `0x6AC330`（`0x6AC33F` 起为正文），CString 全局 `0x788904` | **`FUN_0047D2C0`** @VA `0x47D2C0` | 四跳延迟链 `0x5BD4EA cmp[0x779CDC],0 → 0x5BD4FF push 0x14D8 → SetTimer(0x2D,90000) → 0x4878A1 push 0x14D7 → case 0x14D7` | ✅ **P1 覆盖产生端 + P3 覆盖消费端** |
| E3 | 试用到期消息框（15 天 / 30 天） | 文案 VA `0x6B9402`（15 天）、`0x6B945A`（30 天） | **`FUN_0044B490`** @VA `0x44B490`（body `0x44B490..0x44B6BA`）case 4 | `param_2==6 && [0x779CDC]==0` → 弹 `DAT_00787FB4` | ❌ **未覆盖**（且 P1 恰好把 15 天那条**打开**了） |
| E4 | counterfeit / blocked serial | 文案 VA `0x6B94E5`、`0x6B956D`、`0x6B951D`、`0x6AE435`、`0x6B148A`；`ShellExecute("…blocked_serial_info.html?sn=")`（VA `0x69FF33`） | `FUN_0044B490` case 2 / 3 / 0xc | 注册表加密状态串解密后命中关键字 | ⚠️ **理论上不可达**（本机无 Serial、两个 CLSID 键四视图均不存在），但**未加固** |
| E5 | "Please register IDM before updating." | 文案 VA `0x6B8630` | **`FUN_0042DFB0`** @VA `0x42DFB0`，分支 `0x42E0AF → 0x42E1D0` | 更新对话框「现在更新」按钮（控件 ID 0x48A=1162）+ `HKLM\...\Serial` 缺失 | ❌ **未覆盖**（P1 **新引入**，见 §5） |
| E6 | 注册对话框 | `CRegistrationDlg`（RTTI @file `0x37BBB0`；ctor VA `0x521EF0`） | — | 菜单 WM_COMMAND `0x800F` | ⚪ 用户主动触发，非弹窗骚扰 |
| E7 | 关于对话框 | `CAboutDlg`（RTTI @file `0x377644`） | 初始化 @`0x403390`，注册分支入口 `0x403683` | 菜单 WM_COMMAND `0x8012` | ⚪ 用户主动触发 |
| E8 | 托盘提示 | `CTipAboutRunInTray`（RTTI @file `0x37C5EC`） | — | — | ⚪ 非试用类 |

### 2.1 E1 的三个产生者（都不查 `g_registered`）

WM_COMMAND `0x14DF` 在整份镜像里只有 **3 个产生者**：

| 产生者 VA | 所属 | 现场字节 | 备注 |
|---|---|---|---|
| `0x4084C0` | `FUN_00408370`（无直接 `call` 调用者 → 回调） | `50 68 DF 14 00 00 68 11 01 00 00 A1 B0 73 78 00` | lParam 由 `0x63D3E1` 解析出的数字 |
| `0x47A7EC` | `FUN_0047A790`（作为函数指针被压栈 @file `0x996AF`，无直接调用者） | `6A 00 68 DF 14 00 00 68 11 01 00 00 8B 0D B0 73 78 00` | lParam = 0 |
| `0x49A27B` | `FUN_0048F5D0` 的 **case `0x1507`**（idx 94 / 字节 0xB9） | `6A FF 68 DF 14 00 00 68 11 01 00 00 8B 0D B0 73 78 00` | lParam = -1 |

**这三个产生者没有任何一个读取 `[0x779CDC]`。** 这是"为什么 flag=0 还弹"的直接原因之一。

### 2.2 E1 执行者内部的门控

`FUN_004747A0`（body `0x4747A0..0x4748E1`，309 字节，结尾 `mov esp,ebp; pop ebp; ret` = 普通 `ret`）：

```asm
0x004747CE  call 0x456240          ; 门控 A（返回 void，只看残留 eax）
0x004747D3  test eax, eax
0x004747D5  je   0x474805
0x004747DE  call 0x524A50          ; 门控 B
0x004747E3  test eax, eax
0x004747E5  jne  0x4747F0
0x004747E8  call 0x463160
0x0047480A  call 0x470610
0x00474818  lea  ecx, [ebp-0x144]
0x0047481E  call 0x532340          ; <== 构造 CShowEndTrialDlg
0x00474830  call 0x611F3B          ; CDialog::DoModal  -> 弹窗
0x00474861  cmp  dword ptr [ebp-0x20], 3
0x00474869  push 0x2B48             ; 「注册」命令
0x004748A4  push 0x150B             ; 另一个后续命令
```

> `FUN_00456240` 经反编译是在 `SHGetFolderPathW(CSIDL_COMMON_APPDATA)` 之后拼 `System32`/`Sysnative`
> 路径并做文件存在性检查（**环境/完整性向**），不是纯"试用判定"。门控 A 的真实语义标为**未决**。

---

## 3. 为什么 `g_registered=0` 之后仍然会弹

三条彼此独立的机制，任一条都能单独造成"已经 Full 了还在弹购买窗"：

**机制 ① 阈值被 P1 减半（30 → 15）。**
`0x44CC27` 的 `neg/sbb/and 0xF/add 0xF` 把 `[0x779CE0]` 算成 `Trial?30:15`。
P1 让 `g_registered=0`，阈值变成 **15**。天数计数器只需 15 天就判到期（原本 30 天）。
文案证据：`0x6B9402` = `"has not been registered for 15 days. IDM is exiting..."`（15 天那条）。
**⇒ P1 让这条路径更容易触发，而不是更难。**

**机制 ② "Full" 状态自相矛盾。**
到期后 `0x4670D2 / 0x44DB49` 按 `g_registered` 分流，`==0` 走 Full 分支；
而 Full 分支**必须**能从 HKLM/HKCU 读到 `FName`/`LName`（`0x467114`/`0x46713A`、`0x44DB8C`/`0x44DBB9`）。
本机**一个都没有** ⇒ 读值失败 ⇒ `jne 0x46721d` / `jne 0x44DC9D` 落到"未注册/请购买"表现。
**⇒ 光翻标志位、不提供许可证数据，IDM 自己就知道这个"Full"是假的。**

**机制 ③ 三个产生者根本不看 `g_registered`。**
`0x4084C0`、`0x47A7EC`、`0x49A27B`（case `0x1507`）都会无条件 `PostMessageA(WM_COMMAND, 0x14DF)`。
`0x49A27B` 那条尤其值得注意：它的 lParam 是 **-1**，与"剩余天数"语义无关，属于**另一类触发源**。

---

## 4. 加固建议（按性价比排序）

> 原则：**优先砍"汇流点"，不要逐个弹窗打地鼠。**
> 每条都给了 file offset + 原始字节 + 补丁字节，并注明能否特征码化（供 `IDM-Unlock.py` 采用）。
> **所有候选的调用约定已核实**：`FUN_004747A0` 结尾 `mov esp,ebp; pop ebp; ret`、
> `FUN_0044B490` 结尾 `add esp,0x14; ret` —— **都是普通 `ret`，`33 C0 C3` 存根栈安全**。

### ★★★ 建议 1（首选收敛点）：把 EndTrial 弹窗执行者改成空操作

- **目标**：`FUN_004747A0` @VA `0x4747A0`（file **`0x00073BA0`**）
- **原始字节**：`55 8B EC 6A FF 68 5B 79 67 00`（`push ebp; mov ebp,esp; push -1; push <SEH>`）
- **补丁字节**：`33 C0 C3`（`xor eax,eax; ret`）
- **理由**：`FUN_004747A0` 是**唯一**执行 `CShowEndTrialDlg::DoModal` 的函数，三个产生者（`0x4084C0`/`0x47A7EC`/`0x49A27B`）**全部汇流到这里**。
  一处 3 字节改动 ⇒ 整类"试用到期购买弹窗"永久不可达，**且不依赖 `g_registered`、不依赖注册表**。
  返回 0 是该函数自己的合法返回值之一（`0x47484D` 处 `xor eax,eax` 就是这条路径）。
- **副作用**：菜单里若有"显示试用到期提示"的入口会变成静默无反应。不崩溃、不退出、不影响下载。
- **能否特征码化**：**能，而且很稳。** 锚点用 RTTI：
  `".?AVCShowEndTrialDlg@@"` → TypeDescriptor（名字前 8 字节）→ 指向它的 Complete Object Locator
  → 指向 COL 的 vtable 槽 → vtable → 找 `mov dword ptr [reg], <vtable>` 的唯一引用点即**构造函数**（本版 VA `0x532340`）
  → 全镜像唯一 `call <ctor>` 即 `FUN_004747A0`（本版 @`0x47481E`）。
  这一整条链只依赖 **RTTI 名字**，跨版本稳定性高（MSVC RTTI 名不会随 build 变）。

### ★★ 建议 2：把试用/伪造序列号消息派发器改成空操作

- **目标**：`FUN_0044B490` @VA `0x44B490`（file **`0x0004A890`**，body `0x44B490..0x44B6BA`）
- **原始字节**：`6A FF 68 F8 40 66 00 64`（`push -1; push <SEH>; mov eax,fs:[0]`）
- **补丁字节**：`33 C0 C3`
- **理由**：E3（15/30 天到期）、E4（counterfeit/blocked）**全部**经由这一个派发器。
  一处改动把整个"试用/伪造/封号"文案族一起关掉。
  已知调用点：`0x402BA2`、`0x489714`、`0x4534CB`、`0x494E36`。
- **副作用**：counterfeit 提示也没了 —— 对本用途是**优点**。
- **能否特征码化**：**中等。** 该函数没有 RTTI。可行锚点：它内部会 `push "Internet Download Manager"`(VA `0x695DE8`) 与
  `MessageBox` 包装 `0x4748F0`，或以其**四个调用点的公共目标**反推。建议做成"找到就用、找不到就跳过"。

### ★★ 建议 3：冻结试用天数阈值，抵消 P1 的副作用

- **目标**：VA `0x44CC30`（file **`0x0004C030`**）
- **原始字节**：`83 E0 0F 83 C0 0F`（`and eax,0xF; add eax,0xF`）
- **补丁字节**：`83 E0 00 83 C0 7F`（`and eax,0; add eax,0x7F`）→ 阈值恒为 **127 天**
- **理由**：让"已用天数"这条路径在现实时间内不可能触顶。注意 `imm8` 是**符号扩展**的，
  所以最大只能给 `0x7F`(127)，给 `0xFF` 会变成 `-1`。
- **副作用**：About/提示里的"剩余 N 天"会显示 127 天量级。纯显示。
- **能否特征码化**：**能。** 锚点 = `A1 DC 9C 77 00 F7 D8 1B C0`（读 `g_registered` + `neg` + `sbb`）这段唯一序列，
  其中 `DC 9C 77 00` 可由建议 1 的 RTTI 链顺带定位（`g_registered` 在 About 分支的 `cmp` 里出现过）。

### ★ 建议 4：补上许可证持有人数据（**不推荐**）

写注册表 `FName`/`LName` 能让机制 ② 闭嘴，但会**连带把序列号送进 `update.cgi?sn=`** 上传到
`secure.internetdownloadmanager.com`；一旦被服务端标记 blocked，状态串会被写进 CLSID 键
`{a9cb9766-0322-447b-b63a-8b68ebf27b3f}`，**之后每次启动真弹 counterfeit 并退出**。
**收益一行文案、风险是自伤，明确不做。**

### ✗ 不建议：逐个改三个产生者（`0x4084C0`/`0x47A7EC`/`0x49A27B`）

纯粹打地鼠：产生者可能随版本增减，而汇流点只有一个。**建议 1 已经把它们全覆盖。**

---

## 5. 把 `g_registered` 设成 0 是否**引入**了新的弹窗路径？

**是，至少两条：**

1. **E5「Please register IDM before updating.」**（`FUN_0042DFB0` @`0x42DFB0`，分支 `0x42E0AF → 0x42E1D0`）。
   该函数是更新对话框「现在更新」按钮的处理函数；其**注册分支**（`0x42DFF8 cmp [0x779cdc],esi / jne 0x42E20F`）
   要求 `HKLM\SOFTWARE\Internet Download Manager\Serial` 存在。P1 之后才会走到这里，而本机没有该值
   ⇒ 弹出提示并 `EndDialog`。**这是 P1 打开的一条新路径**（同时它也堵死了手动更新覆盖补丁的路）。
2. **E3 的 15 天文案**（`0x6B9402`）。P1 把阈值降到 15，使 `FUN_0044B490` case 4 的那条
   `param_2==6 && [0x779CDC]==0` 判定**更容易命中**，并把文案从 30 天版切换成 15 天版。

另外机制 ② 本身也可以算"引入"：P1 把 IDM 推入一个**需要 HKLM 许可证数据才能自洽**的分支。

---

## 6. 未决项与局限性

1. **`tvfrdt` 与 `scansk` 未追到指令级。** 二者的注册表值名由 IDM 自研 16 轮 4 字 Feistel
   （`FUN_00444F70`/`0x445010`/`0x445290`，包装 `FUN_00447BD0`；密钥 `"947362057192834"`）
   在 `FUN_0052DE80`/`FUN_0052E040` 里运行时解密，镜像中无明文。
   已确认的同族明文：`Serial`（密文 `a1 c1 60 5b b5 fd 7d 8d`）、`FName`、`LName`、`Email`、
   `SOFTWARE\Internet Download Manager`、`58BE20at4si5ls2D13`。
   `tvfrdt = 2107457418`（2036-10-13，**未来日期**）与 64 字节 `scansk` 是否参与"到期"判定**尚未证实**。
2. **门控 A `FUN_00456240` 的返回语义未定。** Ghidra 反编译其为 `void`，但调用点做 `test eax,eax`
   —— 说明它通过残留寄存器返回，或 Ghidra 误判返回类型。它内部拼 `System32`/`Sysnative` 路径做文件检查，
   更像环境/完整性探测而非试用判定。
3. **`FUN_0047A790` 与 `FUN_00408370` 无直接 `call` 调用者**（均以函数指针形式被使用：
   `FUN_0047A790` 在 file `0x996AF` 被 `push`）。它们的**上游触发源未定位**。
4. 本报告的所有"当前值"来自 2026-10-16 的只读注册表查询与 `.data` 文件读取；
   `Therad`/`Model` 在被测时刻**不存在**，因此机制 ① 的"正在生效"是**结构性可达**而非**观测到已触发**。

---

## 7. 复现命令

```powershell
# 反汇编任意区间
python work\idm-6.43b8\scripts\idmdis.py 0x4747A0 320
# 某全局的读/写分类
python work\idm-6.43b8\scripts\writers2.py 0x779ce0
# 某 VA 的所有引用 + 上下文
python work\idm-6.43b8\scripts\xref2.py va 0x788920
# 注册表只读
Get-ItemProperty 'HKCU:\Software\DownloadManager' | Select-Object Therad,Model,tvfrdt,radxcnt,nExpDt,idmvers
```

*本文件为静态分析产物：未运行 IDMan.exe，未修改安装目录任何文件。*
