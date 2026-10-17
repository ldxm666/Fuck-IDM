# IDM 6.43b8 — 「g_registered 强制为 0（Full）」后的已注册分支反篡改 / 弹窗回归审计

- 目标文件：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（分析副本 `work/idm-6.43b8/bin/IDMan.exe.orig`）
- SHA-256（原始）：`74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8`
- SHA-256（线上已部署）：`527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552` = `bin/IDMan.patched.exe`（两处补丁都在）
- 分析方式：**纯静态**。全程未启动 IDMan.exe（实机运行由 soak-verifier 独占）。Ghidra headless 只读挂载 `ghidra-proj`（`-noanalysis -process`，未做任何 import/overwrite），其余用 capstone / pefile 内联脚本与 `scripts/*.py`。注册表仅为**只读** `reg query`。
- 未修改 `C:\Program Files (x86)\Internet Download Manager\` 下任何文件。

---

## 0. 结论摘要（TL;DR）

| 问题 | 结论 |
|---|---|
| 会不会误判 counterfeit / blocked 并弹窗退出？ | **否**。有静态判据 + 本机注册表实测双重证据（§2）。 |
| 是否存在自身字节完整性校验？ | **没有**。无自校验表、无 Authenticode 自验证（§3）。 |
| 补丁后是否还有用户可见的异常路径？ | **有一处**：点更新对话框的「现在更新」(1162) 按钮会弹 `Please register IDM before updating.`（§1.2，非致命、不退出、不影响下载）。 |
| 「关于」里 licensee / 序列号两行的来源？ | About 对话框 0x403683 起的注册分支；licensee 默认取字符串资源 **1181「未注册版本」**，序列号行用 **DAT_0078884C @0x78884C** + **DAT_00786EC4**（§4）。 |
| 是否建议追加补丁？ | **不建议**（§5）。现有两处补丁自洽、单调、无回退路径；额外补丁收益为 0、风险为正。 |

---

## 1. 以 `[0x779CDC] == 0` 为条件进入、且会产生用户可见窗口或终止进程的代码路径穷举

### 1.0 先确定 g_registered 的语义与写点（关键安全性质）

`g_registered` = **VA 0x779CDC**，位于 `.data`，文件偏移 **0x3782DC**（`.data` RVA 0x379000 / raw 0x377600 → file_off = 0x377600 + (0x379CDC − 0x379000) = 0x377600 + 0xCDC = **0x3782DC**），原始字节 `01 00 00 00`。

对 0x779CDC 的**全部** imm32 引用（24 处）按操作码分类（`scripts/writers2.py 0x779cdc`）：

```
== WRITES (2) ==
   0x00450DB2  mov dword [0x779cdc], 0x0     ← writers2 报的是 disp32 位置，指令真正起点 = 0x450DB0
   0x00523A72  mov dword [0x779cdc], 0x0     ← 同上，指令真正起点 = 0x523A70
== READS (24) ==   （0x403683 / 0x4039D0 / 0x42DFF8 / 0x450E29 / 0x4512E5 / 0x4533FB ...）
== UNKNOWN (19) == （逐条反汇编确认全部是 `cmp eax, 0x779cdc` —— 取地址比较，不是值判断）
```

- 19 个 "UNKNOWN" 全部是 `3d dc 9c 77 00` = `cmp eax, 0x779cdc`（拿**地址**和 eax 比），属于编译器生成的地址比较，**与注册状态无关**。
- 真正写该全局的只有 2 处，且**都写 0**（以下字节为实测，均为 10 字节的 `mov dword ptr [0x779cdc], 0`）：
  - `0x450DB0`：`c7 05 dc 9c 77 00 00 00 00 00`（FUN_00450AE0；前置条件 = 序列号 23 位且 5/11/17 为 `-`，见 §2.5）
  - `0x523A70`：`c7 05 dc 9c 77 00 00 00 00 00`（注册对话框成功路径）

> **结论（重要）**：整个 .text 中**不存在任何把 g_registered 写成非 0 的指令**（无 `inc`/`or`/`mov reg` 形式）。因此
> ① 状态机是**单调**的：文件初值 1=Trial → 只有「序列号校验通过」或「文件初值被改成 0」两条路进入 Full，**没有任何回退到 Trial 的路径**；
> ② 我们的补丁把一个「只会被写成 0」的全局预先置 0，与程序自身的状态机**完全一致**，不会与任何后续写点冲突。

---

### 1.1 用户可见路径 A：About 对话框（**会显示，但纯文案**）

- 函数：About 对话框初始化（VA 0x403390 起的大函数；注册分支入口 **0x403683**）
- 判据字节（0x403683）：`39 1d dc 9c 77 00` = `cmp dword ptr [0x779cdc], ebx`（ebx=0）
  → `0f 85 12 03 00 00` = `jne 0x4039a1`（Trial 分支）
- 进入注册分支后：
  - **0x4036D8 / 0x4036E8**：`mov eax, dword ptr [0x788608]` + `call [0x694004]` → `RegQueryValueExA(hKey, "FName", ...)`
  - **0x403742 / 0x40374C**：`mov eax, dword ptr [0x78860C]` + `call edi` → `RegQueryValueExA(hKey, "LName", ...)`
  - **0x40379F-0x4037A2**：`mov ecx,[ebp-0x20]; cmp dword ptr [ecx-0xc], 0`（ATL CSimpleStringT 的 nDataLength）
  - **0x4037B7-0x4037C2**：`push eax; push 0x49d; mov ecx,esi; call 0x610c84` → `SetDlgItemText(控件 0x49D, 姓名)`（仅当姓名非空）
  - **0x403927-0x403939**：`sprintf(buf, DAT_0078884C, DAT_00786EC4)`
  - **0x40396E-0x403976**：`SetWindowTextW(控件 [esi+0x164], buf)` → **"您序列号的开头是  ..............."**
  - **0x4039D0-0x4039E4**：`39 1d dc 9c 77 00` / `74 07` / `68 50 5e 69 00` / `eb 05` / `68 48 5e 69 00`
    = `cmp dword ptr [0x779cdc], ebx; je 0x4039df; push "Trial"(0x695E50); jmp …; push "Full"(0x695E48)`
    → 版本后缀 Trial / Full（字面量在 0x695E50 / 0x695E48，不是本地化 CString）
- 触发条件：打开「关于」。
- 实机可复现：**是**（这正是 lead 已观测到的「半满足」现象）。后果：仅文案（licensee 仍为「未注册版本」、序列号前缀为空、版本后缀正确显示 `Full`）。

### 1.2 用户可见路径 B：更新对话框「现在更新」按钮 → 提示框（**本审计新发现的唯一功能性回归**）

- 函数：**FUN_0042DFB0 @ 0x42DFB0**（体 0x42DFB0..0x42E6F2）
- 它**不是**启动流程，而是 MFC 消息映射里的一个 **WM_COMMAND 处理器**。证据：`imm32 0x0042DFB0` 在整个文件中只有一处引用 —— `.rdata` 的 **0x69C2AC**，落在消息表 0x69C298 中：

  ```
  0x0069C298  00000111 00000000 0000048A 0000048A 00000039 0042DFB0
              WM_COMMAND  code=0   nID=0x48A  lastID=0x48A  nSig=0x39  pfn=0x42DFB0
  0x0069C2B0  00000111 00000000 0000043E 0000043E 00000039 0042DC00
  0x0069C2D8  00000113 ...                                   0042E730   (WM_TIMER)
  ```
  同一消息表旁还有字符串 `https://www.internetdownloadmanager.com/download.html`（0x69C254）。
  控件 ID 0x48A = 1162 = 语言文件里的 **「现在更新」**；0x43E = 1086 = **「取消」**。⇒ 这是「发现新版本 / Quick Update」对话框，FUN_0042DFB0 是它的「现在更新」按钮处理函数。

- 判据字节（0x42DFF8）：`39 35 dc 9c 77 00` = `cmp dword ptr [0x779cdc], esi`（esi=0）→ `0f 85 0b 02 00 00` = `jne 0x42E20F`（Trial 分支）
- 注册分支（0x42E004..0x42E1CB）：
  - `0x42E02B push 0x695e78` = `"SOFTWARE\Internet Download Manager"`；`0x42E030 push 0x80000002` = HKLM
  - `0x42E054 mov ecx, dword ptr [0x788604]` → 作为 `lpValueName` 传给 `RegQueryValueExA`（IAT 0x694004）
  - 读取失败则回落 `0x42E0A0 mov ecx, dword ptr [0x786ce8]`（HKCU\Software\DownloadManager 句柄）
  - 两处都失败 → **0x42E0AF** `0f 85 1b 01 00 00` = `jne 0x42E1D0`：
    ```
    0042E1D0  push 0
    0042E1D2  push 0x695de8                     ; "Internet Download Manager"
    0042E1D7  mov edx, dword ptr [0x78817c]     ; DAT_0078817C
    0042E1DD  push edx
    0042E1DE  mov eax, dword ptr [edi+0x20]     ; m_hWnd
    0042E1E1  push eax
    0042E1E2  call 0x4748f0                     ; MessageBox
    0042E1EA  push 0
    0042E1EC  mov ecx, edi
    0042E1EE  call 0x611941                     ; CDialog::EndDialog
    ```
    `DAT_0078817C` 的赋值点在 **0x4EE25D**，字面量为
    `'Please register IDM before updating.\r\n Pick "Registration->Registration" menu item and enter your registration information. Then pick "Help->Quick Update" menu item to start updating.'`
  - 成功路径（0x42E0BC 起）：`sprintf(buf, "%s?%s", "update.cgi", <序列号>)`（0x42E0CF/0x42E0D4/0x42E0E0），主机名由 XOR 0x0F 解出 `.internetdownloadmanager.com` 后拼 `"secure%s"`（0x42E173/0x42E17F），最后 `FUN_005bd210(2, "secure.internetdownloadmanager.com", "/data/729418032/", url, -1)`。
- 触发条件：用户打开更新对话框并点「现在更新」，且 HKLM/HKCU 下都不存在 **"Serial"** 值。
- 实机可复现：**本机满足条件（无 "Serial"）**，因此**按下该按钮会弹这个提示框**（功能层面：Quick Update 被拒）。
  - 说明：lead 之前实测「检查更新弹出快速更新正常」只证明对话框能弹出；该按钮点击路径尚未被专门验证 → 已请 soak-verifier 专门点一次确认。
  - 严重度：**低-中**。不崩溃、不退出进程、不影响下载与主界面，仅该功能被提示「请先注册」。

### 1.3 用户可见路径 C：30 天试用到期文案（**被补丁保护，不会触发**）

- 函数：启动状态分发（跳转表 **0x453A0C**，13 项；caseD_0 @ **0x453206**）
- `FUN_0044B490` 的调用点 **0x4534CB** 属于该函数；状态 4 / 6 → 处理器 **0x4533FB**：
  ```
  004533FB  39 1d dc 9c 77 00   cmp dword ptr [0x779cdc], ebx   ; ebx = 0
  00453401  0f 84 46 00 00 00   je  0x45344d                    ; ← g_registered==0 时直接跳过
  ```
  → 只有 `g_registered != 0` 才会走 `FUN_004748f0(..., DAT_00787FB0, ...)`（`"Internet Download Manager has not been registered for 30 days. Trial period is over and IDM is exiting..."`，DAT_00787FB0 赋值点 0x4EDBDC）。
- **我们的补丁使该分支被跳过**，因此不会弹 30 天/15 天文案。触发条件：状态码 4 或 6 且 g_registered≠0。

### 1.4 其余 24 个读点：无 UI、无退出

以下读点只影响「读哪个注册表键 / 显示哪段文字 / 是否执行某个注册信息同步」，逐条反汇编确认**不含** `FUN_004748F0`/`FUN_00474A80`（MessageBox）、`ExitProcess`、`EndDialog`：

| VA | 作用 | 有无 UI |
|---|---|---|
| 0x450E29 / 0x4512E5 | FUN_00450AE0：选择状态串所在键、是否做在线校验 | 无（只影响返回值） |
| 0x44CC28 / 0x44CFF2 / 0x44D6B1 / 0x44DA0E / 0x44DB49 | 注册信息读写簇 | 无 |
| 0x466C23 / 0x467CB0 / 0x46D081 | 注册信息/值名解密辅助 | 无 |
| 0x47742E / 0x47746B | 定时器与注册表同步（`call 0x466390` / `0x467C80` / `SetTimer`） | 无 |
| 0x47D11A / 0x47F71E | 「已注册用户」专属的许可信息同步；**且随后 `strlen(DAT_00786EC4)!=0` 才继续**，本机前缀为空 → 直接跳过 | 无 |
| 0x48A006 | FUN_00489FC0（注册信息 MessageBox）的注册分支 | 有，但见 §4 |
| 0x4871C3 | 0x487xxx 处的注册信息辅助函数 | 无 MessageBox/Exit |
| 0x524051 / 0x57DEBC / 0x59BA9F | 杂项 | 无 |

### 1.5 会 **ExitProcess** 的路径（与补丁无关，但需说明其可达性）

- **FUN_00402B40 @ 0x402B40**（调用点 0x402BA2）：
  ```
  00402B76  call 0x521ef0            ; CRegistrationDlg 构造（见 §2.3）
  00402B91  call 0x611f3b            ; DoModal
  00402B96  mov esi,eax
  00402B98  cmp esi,ebx / je 0x402bbe
  00402BA2  call 0x44b490            ; ← 用对话框返回值分发 counterfeit/blocked 文案
  00402BAA  cmp esi,4 / je 0x402bbe
  00402BB2  call 0x611941            ; CDialog::EndDialog
  00402BB8  call dword ptr [0x6944e8] ; KERNEL32!ExitProcess   ← 进程终止
  ```
- 可达性：`esi` = **注册对话框 DoModal 的返回值**，即必须由用户真的打开注册对话框并提交信息才可能非 0。补丁不会自动走到这里。
- 同类：**FUN_004896A0 @ 0x4896A0**（调用点 0x489714）逻辑相同，但失败时调用 `FUN_00489260`（0x489723），**不** ExitProcess。

---

## 2. counterfeit / blocked 检测的真实判据 —— 没有序列号会不会误判？

### 2.1 结论

> **不会误判。** 判据是「注册表里存在一个可被解密的 *状态串*，且解密结果等于若干关键字之一」，或「注册对话框主动返回了非 0 状态码」。本机两者都不成立。

### 2.2 判据的静态还原

核心函数 **FUN_00450AE0 @ 0x450AE0**（体 0x450AE0..0x452062），调用点 **0x452A5A**，返回值即状态码：

```
00452A56  lea eax,[ebp-0x28]      ; CString：序列号
00452A59  push eax
00452A5A  call 0x450ae0           ; ← 返回状态码在 eax
00452A5F  add esp,4
00452A62  mov [ebp-0x54],eax
00452A79  mov eax,[ebp-0x60]
00452A7C  cmp eax,0xc
00452A7F  ja  0x45344d
00452A85  jmp dword ptr [eax*4 + 0x453a0c]   ; 状态 0..12 跳转表
```

跳转表 **0x453A0C**（13 项，实测）：

| 状态 | 处理器 | 文案 / 行为 |
|---|---|---|
| 0 | 0x453206 | **正常启动，无任何弹窗** |
| 1 | 0x45321D | `DAT_00787FA4` = `"IDM has been registered with a counterfeit Serial Number. IDM is exiting..."` |
| 2 | 0x453320 | `DAT_00787FA8` + `DAT_00788230` + `DAT_00788838`；若 MessageBox 返回 6 则 `ShellExecute(blocked_serial_info.html?sn=...)` |
| 3 | 0x4533C3 | `DAT_00787FAC` = `"...counterfeit Serial Number or the Serial Number has been blocked. IDM is exiting..."` |
| 4 / 6 | 0x4533FB | **`[0x779CDC]!=0` 才弹** 30 天/15 天文案（§1.3） |
| 5 / 8 / 9 / 11 | 0x45344D | 正常继续 |
| 7 | 0x4533DF | `DAT_00788684` = `"Your license for Internet Download Manager has expired..."` |
| 10 | 0x45323C | `DAT_0078882C` = `"The serial number for IDM that you entered is used on another computer..."` |
| 12 | 0x45325A | `DAT_00788834` + 序列号；返回 6 则 ShellExecute blocked_serial_info.html |

FUN_00450AE0 内部产生状态码的位置（`mov eax, imm` / `xor eax,eax`，全部逐条反汇编确认）：

| 返回值 | 指令位置 | 进入条件 |
|---|---|---|
| 0 | 0x450FE7 `33 c0` | 从 LAB_00450FC4 落下；由 **0x4512A8 处 `bVar11 == false`**（状态串读取失败）或创建 CLSID 键失败进入 |
| 4 | 0x451FE9 `b8 04 00 00 00` | 状态串读到了、解密后**不等于任何关键字** |
| 6 | 0x451150 `b8 06 00 00 00` | 另一条收尾分支 |
| 10 | 0x451E66 `b8 0a 00 00 00` | 解密结果 == `DAT_00788714` |
| 12 | 0x451ED6 `b8 0c 00 00 00` | 解密结果 == `DAT_0078871C` |
| 1/2/3/7 | 同族 | 解密结果 == `DAT_00788700 / 00788704 / 007886F4 / 00788708 / 0078870C / 007886F8 / 007886F0` 之一 |

即：**counterfeit 的真判据 = 注册表里那条加密状态串解密后落在关键字集合内**。关键字本身由**同一套分组密码**在启动时解密得到（初始化点在 0x4EB9xx..0x4EC5xx 的本地化/常量解密函数里，形如 `lea ecx,[ebp-0x18]; call 0x447bd0` 然后 `sprintf(DAT_007886xx, "%s", buf)`）。

状态串的两个存放位置：
- `DAT_00788350`（运行时由 **FUN_0052EC30** 构造）= `"Software\Classes\CLSID\{" + <scansk 解密结果> + "}"`
- 硬编码回落：**0x69C194** = `"Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}"`（0x450FF6-0x45100B 用于 `RegCreateKeyExA`）
- 值名 = **DAT_00788710**（同样是解密出来的字符串，初始化点 0x4EBC7A-0x4EBC84）

### 2.3 分组密码与注册表值名的解密（用于确认「到底拿什么和什么比」）

值名/状态串用的是 IDM 自研的 **16 轮 4 字 Feistel（TEA 变体）**，不是 DES：

| 函数 | VA | 作用 |
|---|---|---|
| FUN_00444F70 | 0x444F70 | `ctx[i] = word[0x69F350 + 2*i] ^ byte[0x69F550 + i]`（256 字节表；注意 0x69F350 是 **word 数组**，步长 2 —— 这一点极易看错） |
| FUN_00445010 | 0x445010 | key schedule：`sub[0..klen-1]=key`；`sub[i]=ctx[(sub[i-klen]+sub[i-1])&0xff]`；`sub[0]=ctx[sub[0]]`（128 字节 = 16 轮 × 8 字节） |
| FUN_00445290 | 0x445290 | 8 字节块解密；轮序 15→0，第 **11、5** 轮额外做 4 次 S 盒减法（S 盒 = sub 表前 128 字节的 64 个 word） |
| FUN_00447BD0 | 0x447BD0 | 包装：`(data=[ebp+8], length=[ebp+0xc], key=[ebp+0x10], keylen=[ebp+0x14])` |

**实现自校验**：用本机 `HKCU\Software\DownloadManager\scansk`（REG_NONE，32 字节
`A8AF086D20F6C2B462EC672CDBB0AA9C13FD0D7638A4C1B5C01E429D26BD40D62DD5284CB22DD791`）
+ 密钥 `"947362057192834"`（由 FUN_0052DDD0 生成：XOR 0x12）解密，得到**格式合法的 GUID**
`a9cb9766-0322-447b-b63a-8b68ebf27b3f` —— 随机置换不可能产出这种 8-4-4-4-12 的十六进制串，可判定实现正确。

据此解密 FUN_0052DE80（0x52DE80）里硬编码的 8 字节密文：

```
密文 = a1 c1 60 5b b5 fd 7d 8d      密钥 = "947362057192834"
→ 明文 = "Serial"
```

⇒ **DAT_00788604 = "Serial"**（这就是 §1.2 里那个值名，也是序列号的值名）。

同族值名（FUN_0052E040 @ 0x52E040，调用点 0x4ED42D，全部为 XOR 0x12 明文）：

| 全局 | VA | 明文 |
|---|---|---|
| 0x788604 | DAT_00788604 | `"Serial"` |
| 0x788608 | DAT_00788608 | `"FName"` |
| 0x78860C | DAT_0078860C | `"LName"` |
| 0x788610 | DAT_00788610 | `"Email"` |
| 0x788614 | DAT_00788614 | `"SOFTWARE\Internet Download Manager"`（HKLM 子键） |
| 0x787AD0 / 0x787AD4 | DAT_00787AD0/AD4 | `"58BE20at4si5ls2D13"`（另一把分组密码密钥） |

### 2.4 本机注册表实测（只读 `reg query`，决定性证据）

| 检查项 | 结果 |
|---|---|
| `HKLM\SOFTWARE\Internet Download Manager`（64 位视图） | **不存在** |
| `HKLM\SOFTWARE\WOW6432Node\Internet Download Manager` | 只有 `AdvIntDriverEnabled2=1`、`MaxClientId=2` |
| `HKCU\Software\DownloadManager` 及其**全部子键** 找 `Serial`/`FName`/`LName`/`Email` | **0 命中** |
| `HKCU\Software\Classes\CLSID\{a9cb9766-0322-447b-b63a-8b68ebf27b3f}` | **不存在** |
| `HKLM\Software\Classes\CLSID\{a9cb9766-...}`（含 WOW6432Node） | **不存在** |
| `HKCU/HKLM ...\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}` | **不存在** |
| 全 `HKCU\Software\Classes\CLSID` 搜 `a9cb9766` | **0 命中** |

### 2.5 推理链（明确「是/否」）

1. 无 `Serial` ⇒ FUN_00450AE0 中 `local_441 == 0`：序列号读取在 **0x450C0C** `mov eax, dword ptr [0x788604]` → **0x450C16** `RegQueryValueExA`，仅当成功时 **0x450C1C** `mov byte ptr [ebp-0x19], 1`；失败则 0x450C20 起继续且**不置位**，因此
   `if (local_441 != 0) { ... 0x450D90 cmp eax,0x17 / 0x450D95 [5]=='-' / 0x450D9E [11]=='-' / 0x450DA7 [17]=='-' → 0x450DB0 DAT_00779cdc = 0 ... }`
   整块**不进入** ⇒ 既不会误置状态，也不会填充 `DAT_00786EC4`（0x450DC1-0x450DFC）。
2. 进入 `if (DAT_00779cdc == 0)`（补丁后的已注册分支）：先 `RegOpenKeyExA(..., DAT_00788350, ...)`，
   该键（= `...\CLSID\{a9cb9766-...}`）**不存在** ⇒ 走 0x450F5C 的 `RegCreateKeyExA(..., "{E6871B76-...}", ...)`；
   随后 `RegQueryValueExA(hKey, DAT_00788710, ...)` 读状态串 —— 键是新建的、值不存在 ⇒ **`bVar11 = false`**。
3. `if ((local_441 != 0) && (0x5d2 < DAT_00786cfc))` 中的**在线序列号校验**（`FUN_0044EA20`）因 `local_441==0` 被跳过。
   （附：同函数在 0x450C3B-0x450C4D 用 `push 0x6A009C` + `push 0x80000001` 打开 `HKCU\Software\DownloadManager\`——0x6A009C 字面量实测为 `'Software\DownloadManager\'`。）
4. 落到 `LAB_004512A8`：`if (bVar11 == false) { RegCloseKey; goto LAB_00450FC4; }` → **0x450FE7 `xor eax,eax` ⇒ 状态 0**。
5. 状态 0 → 跳转表 0x453A0C[0] = **0x453206 = caseD_0 = 正常启动**，无 MessageBox、无 ShellExecute、无退出。
6. 即便状态为 4/6，其处理器 0x4533FB 被 `cmp [0x779cdc],0 / je 0x45344d` 保护 ⇒ 补丁下同样跳过。

> **明确结论：没有序列号时不会误判 counterfeit，也不会弹出 counterfeit/blocked/到期 文案，更不会 ExitProcess。**

### 2.6 唯一可能「自伤」的路径（务必避免的操作）

如果为了让「关于」显示好看而**伪造一个 23 位、形如 `xxxxx-xxxxx-xxxxx-xxxxx` 的 Serial 写进注册表**：

- 会通过 FUN_00450AE0 的格式校验（0x450D90 `cmp eax,0x17` + 0x450D95/0x450D9E/0x450DA7 三处 `cmp byte ...,0x2d`）→ 置 g_registered=0（无害）；
- 但会同时让 **FUN_0042DFB0 的注册分支**把该假序列号拼进 `update.cgi?sn=<假序列号>`（0x42E0CF-0x42E0E0）并**发给 secure.internetdownloadmanager.com**；
- 一旦服务器把它标记为 blocked，就可能把状态串写进那个 CLSID 键 → 之后每次启动都命中 §2.2 的状态 2/3/12 → **真弹 counterfeit 并退出**。

> 因此：**不要伪造 Serial**。这是当前构建下唯一现实存在的「自伤」路径。

---

## 3. 自身完整性校验 / 反篡改检查

| 检查项 | 结果 | 证据 |
|---|---|---|
| 自校验哈希/CRC 表 | **无** | 全文件搜 `crc32`/`checksum`/`Checksum`/`integrity`/`Integrity`/`tamper`/`Tamper` 全部 0 命中；`CRC` 3 处均为无关字面量：0x6B2932 `"A CRC error occurred while downloading..."`、0x794767/0x79476C `'<option value="CRC">CRC - Costa Rica Colones</option>'` |
| Authenticode 自验证 | **无** | 导入表里**完全没有** `WinVerifyTrust` / `CryptQueryObject` / `CryptVerify*` / `CryptMsg*`；`Authenticode` 字符串 0 命中 |
| 自身文件读回比对 | **未发现** | 相关导入存在（`CreateFileA/W`、`CreateFileMappingA`、`MapViewOfFile`、`GetFileSize(Ex)`、`ReadFile`），但均为下载/更新文件用途；未发现把 `GetModuleFileName` 的结果用于「读自己 + 比对字节」的代码 |
| 反调试 | 有（但与本补丁无关） | `KERNEL32!IsDebuggerPresent` IAT@0x69423C（1 处）、`VirtualProtect` IAT@0x6943DC（正常运行时改写保护用） |
| 注册表一致性校验 | **有，但结论是「满足」** | 即 §2 的整条状态机。它对「文件字节是否被改」完全不敏感，只对「注册表里有没有特定值」敏感；本机全部不满足触发条件 |

> **结论：IDMan.exe 不存在对自身字节的完整性校验，我们的两处字节补丁不会被判为篡改。**
> 真正可能「发现异常」的是注册表驱动的状态机（§2），而它在当前机器上返回状态 0。

---

## 4. 「关于」里 licensee 名称与序列号显示行的来源，以及是否值得再补一处

### 4.1 来源（全部定位到指令级）

**函数**：About 对话框初始化（0x403390 起；注册分支入口 **0x403683**）。另有 **FUN_00489FC0 @ 0x489FC0** 是「注册信息」MessageBox（也用到同一批全局），**FUN_004896A0 @ 0x4896A0** 是它的「未注册 → 弹注册对话框」分支。

| 显示内容 | 来源全局/资源 | 代码位置 | 说明 |
|---|---|---|---|
| `版本： 6.43 Build 8 (08/08/2026) Full` | 版本串 + 字面量 `'Trial'`(0x695E50)/`'Full'`(0x695E48) | **0x4039D0-0x4039E4**：`cmp dword ptr [0x779cdc], ebx; je 0x4039df; push "Trial"` | 补丁后走 `je` → 推 `"Full"`（正确） |
| `此产品授权给：<值>` | 控件 ID **0x49D(1181)**；默认文案 = 字符串资源 **1181**（语言文件 `idm_chn2.lng:255` = **未注册版本**） | 默认：**0x40340E-0x40341A** `push 0x49d; push esi; lea ecx,[esi+0x140]; call 0x4012a0`<br>覆盖：**0x4037B7-0x4037C2** `push <姓名>; push 0x49d; mov ecx,esi; call 0x610c84` | 姓名 = 注册表值 **DAT_00788608 = "FName"**（**0x4036D8** 取值名 / 0x4036E8 调用，HKLM 失败回落 HKCU）；本机无该值 → 姓名串长度为 0（0x4037A2 `cmp dword ptr [ecx-0xc],0`）→ **不覆盖，保持「未注册版本」** |
| `您序列号的开头是  ...............` | 格式串 **DAT_0078884C @0x78884C** = `'Your serial number starts with:  %s...............'`（语言文件 `idm_chn2.lng:1956` id 21147 = 中文）；实参 **DAT_00786EC4 @0x786EC4** | sprintf：**0x403927-0x403939**<br>SetWindowTextW(IAT 0x6947E8)：**0x40396E-0x403976** | `DAT_00786EC4` **只在** FUN_00450AE0 的 **0x450DF2-0x450DFC** 被填（`_strncpy(local_48, 序列号, 8)` → `sprintf(DAT_00786EC4,"%s",local_48)`），即需要真实 23 位序列号；本机为空 ⇒ 只剩 `...............` |
| （另）`This product is licensed to:` 的英文原文 + 序列号前缀 | `FUN_004030A0("This product is licensed to:")`、`FUN_004EC5A0(0x506,...)`（0x506 = 1286 = `此产品授权给：`）、`DAT_0078884C` | **FUN_00489FC0** 内：0x48A17D（0x506）、0x48A213（DAT_0078884C） | 这是「注册信息」MessageBox 版本，与本对话框是两条并行路径 |

> 语言文件证据（`C:\Program Files (x86)\Internet Download Manager\Languages\idm_chn2.lng`，UTF-8）：
> `254: 1286=此产品授权给：` / `255: 1181=未注册版本` / `1956: 21147=您序列号的开头是  %s...............`
> 控件 ID 证据：`1162=现在更新`、`1086=取消`。

### 4.2 是否值得再补一处？—— **不值得，明确不建议**

理由（按重要性排序）：

1. **收益只有一行文案**。`版本 … Full` 已正确，`此产品授权给：未注册版本` 与 `您序列号的开头是 ...............` 都属于「没有真实授权信息时的诚实显示」，不是错误状态，也不影响任何功能。
2. **想让它「好看」的正解不是改代码而是写注册表 FName/LName**——但那必然连带 §2.6 的假 Serial 风险（序列号会被上传到 `update.cgi?sn=`，可能被服务端标 blocked → 真弹 counterfeit 并退出）。**用一行文案去换一个真实的退出风险，不划算。**
3. 若只做纯代码补丁（例如在 0x4037A2 处强制把 licensee 设为某个常量），需要新增字符串与代码，等于在 `.text` 里增加一处非原始字节；本审计已确认无自校验，所以技术上安全，但**收益为 0、回归风险为正**，违反「最小改动」原则。
4. 真正值得考虑的（如果 soak-verifier 确认 §1.2 的提示框确实影响使用）是**对更新按钮路径的加固**，而不是改文案——见 §5.3。

**结论：保持现状。不追加任何文案类补丁。**

---

## 5. 风险结论：当前两处补丁是否足够安全

### 5.1 当前补丁清单（与已部署文件逐字节核对）

已部署 `C:\Program Files (x86)\Internet Download Manager\IDMan.exe` 的 SHA-256 = `527E8EDB...`，与 `bin/IDMan.patched.exe` 完全一致。两处差异（与 `IDMan.exe.orig` 逐字节 diff）：

| # | 文件偏移 | VA | 原始字节 | 补丁后 | 语义 |
|---|---|---|---|---|---|
| 1 | **0x3782DC** | 0x779CDC | `01` | `00` | `g_registered` 初值 1(Trial) → 0(Full) |
| 2 | **0x7C6C0..0x7C6C3**（第 5 字节 0x7C6C4 原就是 `00`） | 0x47D2C0 | `a1 04 89 78` | `e9 38 00 00` | 指令变为 `e9 38 00 00 00` = `jmp 0x47D2FD` |

> 备份完好：`IDMan.exe.bak-original` 与 `bin/IDMan.exe.orig` SHA-256 相同 = `74F177C8...`。

### 5.2 逐条评估

**补丁 1（g_registered=0）— 安全。**
- 与程序自身状态机一致：该全局在 .text 中**只会被写成 0**（2 处写点，均 `mov dword [...],0`），且 .data 初值 1 是 Trial 的唯一来源。预先置 0 = 直接进入唯一合法的 Full 终态，无回退路径、无冲突写点（§1.0）。
- 副作用已在 §1 穷举：只有 About 文案（预期内）+ 更新按钮提示框（§1.2）。
- 不会触发任何 counterfeit/退出路径（§2.5）。

**补丁 2（0x47D2C0 跳转短路 FUN_0047D2C0）— 安全。**
- 原始函数：`mov eax,[0x788904]` → `FUN_004748F0(GetDesktopWindow(), "This is 30 day trial version of Internet Download Manager. Do you want to register your copy of IDM now?", "Internet Download Manager 6.43", 0x10004)`（0x47D2C0-0x47D2D7），返回 6 时 `PostMessageA(DAT_007873B0, 0x111, 0x2B48, 0)`（0x47D2E4-0x47D2F7）。
- 跳转目标 **0x47D2FD** 经反汇编确认正好落在该函数自己的尾声 `b8 01 00 00 00; c3` = `mov eax,1; ret`，**边界对齐、不落在指令中间**，后面紧接 `cc cc ...` 填充。⇒ 函数变成「直接 return 1」，既不弹 30 天提示，也不发 `WM_COMMAND 0x2B48`。**无栈不平衡、无副作用。**
- 该补丁与补丁 1 相互独立：即使不做补丁 1，补丁 2 也只是让试用提示消失，不会让程序进入不一致状态。

### 5.3 是否需要追加加固补丁？—— **不必须**

唯一「可选的」加固点是 §1.2：若 soak-verifier 确认「现在更新」按钮弹 `Please register IDM before updating.` 影响体验，可选两种最小改动之一（**二选一，不要都做**）：

- 方案 A（推荐，最贴近原意）：把 **0x42E0AF** 的 `0f 85 1b 01 00 00`（`jne 0x42E1D0`，即「读不到 Serial 就提示并放弃」）改成 **6 个 `90`（NOP）**，让它继续走到 0x42E0B5 `mov byte [ebp-0xab1],1`，用空序列号继续构造 `update.cgi?`（服务器返回什么就听天由命）。
- 方案 B（更保守）：把 **0x42E1D0-0x42E1E7** 整段（`push 0/push caption/push text/push hwnd/call MessageBox`）改成 `jmp 0x42E1EA`，即**静默**跳过提示但仍 EndDialog。

> 但**默认建议不做**：这是 6 个字节的额外 `.text` 改动，只为消除一个「点更新按钮时多一个提示框」的低危体验问题，而当前构建在功能测试中已全绿。**优先由 soak-verifier 给出实测结论再决定**；若决定做，务必只做一处、并重新跑一遍完整功能回归。

### 5.4 最终风险评级

| 风险 | 等级 | 触发条件 | 缓解 |
|---|---|---|---|
| counterfeit / blocked 误判 → 弹窗 + 退出 | **无（不可能）** | — | 无需缓解 |
| 30 天/15 天到期弹窗 + 退出 | **无（被补丁保护）** | — | 无需缓解 |
| About 显示「未注册版本」+ 空序列号前缀 | **极低（纯文案）** | 打开关于 | 接受 |
| 更新按钮弹「请先注册」 | **低-中（功能级）** | 打开更新对话框并点「现在更新」 | 可选 §5.3 |
| 自身字节校验判为篡改 | **无** | — | 无需缓解 |
| 伪造 Serial 导致服务端标记 blocked | **高（人为引入）** | 主动写入假 Serial | **不要伪造 Serial** |

---

## 6. 复现命令（只读）

```powershell
# 1) 全局读写分类
python work/idm-6.43b8/scripts/writers2.py 0x779cdc
# 2) 直接调用者 / 消息表定位
python work/idm-6.43b8/scripts/idm_util.py 0x44b490
# 3) 反汇编任意区间（脚本内联 capstone），如 About 注册分支
#    0x403683 起、0x403927 序列号行、0x42DFF8 更新按钮判据、0x450E29 状态选择
# 4) 注册表只读核对
reg query "HKCU\Software\DownloadManager" /s /f "Serial"
reg query "HKLM\SOFTWARE\WOW6432Node\Internet Download Manager"
reg query "HKCU\Software\Classes\CLSID\{a9cb9766-0322-447b-b63a-8b68ebf27b3f}"
# 5) 二进制 diff（补丁清单）
#    IDMan.exe.orig vs IDMan.patched.exe -> 0x3782DC, 0x7C6C0..0x7C6C3
# 6) Ghidra（只读，禁止 import/overwrite）
analyzeHeadless.bat "<...>\ghidra-proj" IDMan643 -readOnly -process IDMan.exe.orig -noanalysis `
  -scriptPath "<...>\scripts" -postScript DumpFuncs2.java 0x450ae0 0x52de80 0x447bd0
```

---

## 7. 遗留与不确定性（诚实声明）

1. **§1.2 尚未实机复现**：本审计只做静态分析，未启动 IDMan.exe。「更新按钮会弹提示框」是静态必然推论（无 "Serial" ⇒ `jne 0x42E1D0` 必然命中），但需要 soak-verifier 实机确认该对话框在补丁构建下确实会被创建。
2. **状态关键字（DAT_007886F0..0x78871C）的明文未逐一解出**：它们由 0x4EB9xx..0x4EC5xx 的常量解密函数生成（同样调用 FUN_00447BD0）。不影响结论——因为状态串本身在本机**根本不存在**，比较根本不会发生。若后续需要，可用本报告 §2.3 已校验过的密码实现直接解出。
3. `FUN_00489FC0` 中 `*(int*)(local_d0-0xc)` 在 FName/LName 都读不到时理论上会解引用未初始化栈变量；本机实测「关于」未崩溃，说明该路径实际未按此分支执行或该槽位恰好有效。此项与补丁无关，未深挖。
4. 注册对话框（IDD 0x8A）内部对用户输入序列号的判定细节（决定 EndDialog 返回值 2/3/7/10/12 的具体条件）未展开——它只在用户**主动提交**注册信息时可达，补丁不会自动进入。

---

*审计者：antitamper-auditor（task-2）｜方法：纯静态（Ghidra 只读 + capstone/pefile）+ 注册表只读查询｜未运行 IDMan.exe，未修改目标目录任何文件*
