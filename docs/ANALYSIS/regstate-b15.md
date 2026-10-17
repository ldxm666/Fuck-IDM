# IDM 6.43 Build 15 —— 注册状态存储逆向（能否伪造注册状态）

- 目标：`work/idm-6.43b8/bin/b15/IDMan.exe.b15`
- SHA-256：`279CEED9AAA646650716EE326C0D996BE4CE5DB4B252CF5B2747F4938A7CE737`（= 实机 `C:\Program Files (x86)\Internet Download Manager\IDMan.exe`，FileVersion `6,43,15,3`）
- 方式：**纯静态**（capstone 线性反汇编 + PE 手工解析 + Ghidra 12.1.2 headless 反编译，独立工程 `%TEMP%\b15ghidra`，`-readOnly`）+ **只读**注册表查询
- 未启动 IDMan.exe，未写任何注册表，未修改安装目录任何文件
- 地址换算：`.text` `file_off = 0x400 + (VA - 0x401000)`

---

## 0. 结论速览（TL;DR）

| 问题 | 结论 |
|---|---|
| **只写注册表能不能把 IDM 变成已注册？** | **不能作为独立方案。** 写一个"格式合法"的 `Serial` 确实会让 IDM 把注册标志翻成 Full（这一步纯注册表驱动），但**紧接着**代码会调用真正的序列号校验 `FUN_0044e840(serial,…)`，并由内置黑名单决定是否写入 counterfeit 标记。注册表只是**输入**，判决权在代码。 |
| 那到底需要什么？ | 一个能通过 `FUN_0044e840` **且不在内置黑名单里**的序列号（→ 交给 serial-reverser）。 |
| 已注册状态由哪些注册表数据决定？ | 4 个值（`Serial`/`FName`/`LName`/`Email`，都在 `SOFTWARE\Internet Download Manager` 下，值名运行时解密）+ 一个**必须不存在**的负向标记 `MData`。 |
| 伪造失败的后果 | **会写 `MData` 到 CLSID 键 → 之后每次启动真弹 counterfeit 并退出。** 这是唯一现实存在的自伤路径。 |
| `scansk` 是什么？ | **不是激活凭据。** 它是每机器唯一的加密 GUID，只用来拼出 counterfeit 状态键的路径 `Software\Classes\CLSID\{<GUID>}`。 |

---

## 1. 注册标志：`DAT_0077bd24`（VA `0x77BD24`）

与 Build 8（`0x779CDC`）语义完全一致：**0 = Full（已注册），非 0 = Trial**。

`scripts/writers2.py 0x77bd24` 结果：43 处引用 → **2 writes / 23 reads / 18 unknown**。

```
== WRITES (2) ==
   0x00450BCB  mov dword [0x77bd24], 0x0     ; FUN_00450900 内（序列号格式检查通过）
   0x00523782  mov dword [0x77bd24], 0x0     ; 注册对话框成功路径
```

> **关键安全性质（与 b8 相同）**：全镜像**没有任何指令把它写成非 0**。
> 所以状态机是**单调的** —— 一旦为 0 就不会回到 Trial。
> 这也意味着：**唯一能让它变成 Full 的两条路，都在代码里，不在注册表里。**

「关于」对话框的判定在 `0x403683`：`cmp dword ptr [0x77bd24], ebx / jne 0x4039a1`（`ebx = 0`）→ flag == 0 走 Full 分支。

---

## 2. `FUN_00450900`（VA `0x450900`）—— 注册状态读取器

**唯一调用者：`0x4527DA`**（`mov [ebp-0x54], eax` 把返回值当状态码）。

反编译（Ghidra，`%TEMP%\decomp-450900.log`）核心流程：

```c
void FUN_00450900(int outSerialBuf)
{
  bool haveFName=false, haveLName=false, haveEmail=false, haveSerial=false;
  int  status = 0;                                   // 见 §2.2
  char serial[256] = {0};

  // ---- 阶段 1：从 HKCU\SOFTWARE\Internet Download Manager 读 4 个值 ----
  if (RegOpenKeyExA(HKCU, DAT_0078a634 /* "SOFTWARE\Internet Download Manager" */,
                    0, KEY_QUERY_VALUE, &hk) == 0) {
    haveFName  = RegQueryValueExA(hk, DAT_0078a628, ...) == 0;   // FName
    haveLName  = RegQueryValueExA(hk, DAT_0078a62c, ...) == 0;   // LName
    haveEmail  = RegQueryValueExA(hk, DAT_0078a630, ...) == 0;   // Email
    haveSerial = RegQueryValueExA(hk, DAT_0078a624, ...) == 0;   // ★ Serial
    RegCloseKey(hk);
  }

  // ---- 阶段 2：RegCreateKeyExA(HKLM, "Software\DownloadManager\")，注意是 Create ----
  if (RegCreateKeyExA(HKLM, "Software\\DownloadManager\\", 0, NULL, 0,
                      0xf003f /* KEY_ALL_ACCESS */, NULL, &hk, NULL) == 0) {
    if (!haveFName) { if (RegQueryValueExA(hk, FName, ...) != 0) status = 5; }
    if (!haveLName) { if (RegQueryValueExA(hk, LName, ...) != 0) status = 5; }
    if (!haveEmail) { if (RegQueryValueExA(hk, Email, ...) != 0) status = 5; }
    // 再从 HKLM 读 Serial，与 HKCU 的比对（__stricmp）→ 不一致置 local_449
    ...
  }

  // ---- 阶段 3：★ 序列号"格式检查" —— 这就是翻转标志的地方 ----
  if (haveSerial) {
    if (strlen(serial) == 0x17 /* 23 */ &&
        serial[5] == '-' && serial[11] == '-' && serial[17] == '-') {
        DAT_0077bd24 = 0;                              // ★★★ Full
        sprintf(outSerialBuf, "%s", serial);
        strncpy(local_48, serial, 8);                  // "序列号开头" 显示用
        sprintf(&DAT_00788ee4, "%s", local_48);
    }
  }

  // ---- 阶段 4：只有 flag==0（Full）才进入 ----
  if (DAT_0077bd24 == 0) {
     RegOpenKeyExA(hive, DAT_0078a370 /* scansk 派生路径，见 §4 */, 0, 1, &hk);
     ... RegQueryValueExA(hk, DAT_0078a730 /* "MData" */, ...) ...   // 读负向标记
     RegCreateKeyExA(HKLM, "Software\\Classes\\CLSID\\{E6871B76-…}", ...);   // 回落到硬编码键

     if (haveSerial && 0x5d2 < DAT_00788d1c) {
        int e1=0, e2=0;
        iVar8 = FUN_0044e840(serial, bVar11, &e1, &e2);     // ★ 真正的序列号校验
        if (iVar8 != 0) { ... goto LAB_004510ab; }
        // 再对 HKLM 里的 Serial 做一次 FUN_0044e840
     }

     // ---- 阶段 5：★ 内置黑名单比对，命中就写 MData ----
     if (strcmp(serial, DAT_0078a720) == 0) {              // 以及 a724 / a728 / a72c / a714 / a718
        strcpy(mdata, DAT_0078a728);
        FUN_00445560(mdata, 0x100, DAT_00789af0, ...);
        RegSetValueExA(hk, DAT_0078a730 /* "MData" */, 0, 0, mdata, 0x100);   // ★ 写负向标记
     }
     ...
  }
  ...
  return;   // 正常出口在 0x450F53: mov eax, 6
}
```

### 2.1 逐条证据（VA / 字节）

| 内容 | VA | 字节 / 证据 |
|---|---|---|
| `haveSerial` 置位 | `0x450A31` | `mov byte ptr [ebp-0x15], 1`（`RegQueryValueExA` 返回 0 时） |
| 格式检查：长度 23 | `0x450BA9` | `cmp eax, 0x17` |
| 第 5 位 `-` | `0x450BAE` | `cmp byte ptr [ebp+0x3f1], 0x2d` |
| 第 11 位 `-` | `0x450BB7` | `cmp byte ptr [ebp+0x3f7], 0x2d` |
| 第 17 位 `-` | `0x450BC0` | `cmp byte ptr [ebp+0x3fd], 0x2d` |
| **标志置 Full** | **`0x450BC9`** | **`mov dword ptr [0x77bd24], 0`** |
| 正常出口返回值 | `0x450F53` | `mov eax, 6` |
| `MData` 写入 | `0x44DEAB` | `push 0x69d1e4 ; "MData"` + `RegSetValueExA` |
| `MData` 读取 | `0x44D9FB` | `push 0x69d1e4 ; "MData"` + `RegQueryValueExA` |
| `MData` 删除 | `0x42F03A` | `push 0x69d1e4` + `RegDeleteValueA` |
| 状态跳转表 | `0x45378C` | 13 项：0→`0x452F86`(正常) / 4,6→`0x45317B` / 5,8,9,11→`0x4531CD` / 10→`0x452FBC` |
| CLSID 状态键（硬编码） | `0x69D1A4` | `Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}`，以 `KEY_ALL_ACCESS` 打开（`0x42F05E`，hive = HKLM `0x80000001`） |

### 2.2 `status` 只可能是 0 或 5

对函数体内 `[ebp-0x50]`（= Ghidra 的 `local_478`）的全部写入点扫描：

```
0x00450947  status = edi (=0)      ; 初始化
0x00450A96  status = 5             ; HKLM 的 FName 也找不到
0x00450ACC  status = 5             ; HKLM 的 LName 也找不到
0x00450B04  status = 5             ; HKLM 的 Email 也找不到
0x00450B33  status = 5             ; Serial 在 HKLM 也找不到
```

⇒ **status 5 = "注册信息不完整"**（FName/LName/Email/Serial 在 HKCU 与 HKLM 都没有）。

---

## 3. 「已注册」由哪些注册表数据决定（Q2）

### 3.1 正向（必需）

| 键 | 值名 | 类型 | 期望内容 | 读取处 VA |
|---|---|---|---|---|
| `HKCU\SOFTWARE\Internet Download Manager` | `Serial` | REG_SZ | 23 字符，形如 `XXXXX-XXXXX-XXXXX-XXXXX`（第 5/11/17 位为 `-`） | `0x450A21`（名字全局 `DAT_0078a624`） |
| 同上 | `FName` | REG_SZ | 任意非空 | `0x4509A9` / `0x450A82`（`DAT_0078a628`） |
| 同上 | `LName` | REG_SZ | 任意非空 | `0x4509D3` / `0x450AB5`（`DAT_0078a62c`） |
| 同上 | `Email` | REG_SZ | 任意非空 | `0x4509FA`（`DAT_0078a630`） |
| `HKCU\Software\DownloadManager` | `nExpDt` | REG_DWORD | 仅用于「关于」显示到期日；`lpcbData=4` → 硬上限 `0x7FFFFFFF` = 2038-01-19 | `0x4037E2`（b8/b15 同址） |

> 值名全部**运行时解密**：`"scansk"`/`"Serial"`/`"FName"`/`"LName"` 在镜像里都不是明文
> （`xref2.py str "FName"` → 0 命中；`"Serial"` 只出现在提示文案里）。
> 解密器：`FUN_0052DE50`（1 个名字 → `DAT_0078a624`）、`FUN_0052E010`（4 个名字 →
> `DAT_0078a634`/`a628`/`a62c`/`a630`），底层 `FUN_0052DDA0`。

### 3.2 负向（必须不存在）

| 键 | 值名 | 含义 | 证据 |
|---|---|---|---|
| `HKLM\Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}` | `MData` | **counterfeit/blocked 标记**。存在即"这个序列号被判定为伪造/封禁" | 读 `0x44D9FB`、写 `0x44DEAB`、删 `0x42F03A` |
| 同上 | `Model` | 与 MData 配套的状态字段 | `0x44DA36`（`push 0x6a13b0 ; "Model"`） |
| 同上 | `Therad` | 试用剩余天数（b8 已知） | `0x44DA6E`（`push 0x6a13a8 ; "Therad"`） |

**实测（只读）**：本机 `{E6871B76-…}` 与 `{a9cb9766-…}` 在 HKLM/HKCU × 64/32 **四视图全部不存在** ⇒ 当前无 counterfeit 记录。

---

## 4. `scansk` 到底是什么（Q1）

### 4.1 事实

- `HKCU\Software\DownloadManager\scansk` = **REG_NONE，64 字节，前 40 字节有效**：
  ```
  E2 50 4E 26 5D 14 2D FE F0 DD E1 4D D2 6D 39 44
  33 60 C2 BC 99 B1 2F 36 3A DF EE 7A B0 91 3B 3E
  0E BB 2C 96 B7 E5 7C AE 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ```
- `"scansk"` 在镜像里**不是明文**（`xref2.py str "scansk"` → 0 命中）→ 名字也是运行时解密的。

### 4.2 谁读它、读来干什么 —— `FUN_0052EC00`（VA `0x52EC00`）

反编译（`%TEMP%\decomp-52ec00.log`）：

```c
void FUN_0052EC00(int outPath)
{
  char  scansk[76];
  DWORD sz = 0x31;                                   // 49
  FUN_0052DD20(&name);                               // 解密出值名 "scansk"
  RegQueryValueExA(DAT_00788d08 /* HKCU\Software\DownloadManager */,
                   name, 0, 0, scansk + 0x18, &sz);  // ★ 读 scansk 的 40 字节
  if (ok) {
     FUN_0052DDA0(&key);                             // 解密出密钥串
     FUN_0052DBC0(scansk + 0x18, 0x28, key, len);    // ★ 用密钥把 scansk 解成 GUID 文本
     // 构造前缀：逐字节 XOR 0x12
     scansk[0..0x17] = 41 7d 74 66 65 73 60 77 4e 51 7e 73 61 61 77 61 4e 51 5e 41 5b 56 4e
     for (i...) scansk[i] ^= 0x12;                   // → "Software\Classes\CLSID\"
     FUN_00402F20(outPath, "%s{%s}", scansk, scansk + 0x18);   // → "Software\Classes\CLSID\{<GUID>}"
  }
}
```

**前缀解码验证**（`XOR 0x12`）：

```
41^12=53 S   7d^12=6f o   74^12=66 f   66^12=74 t   65^12=77 w   73^12=61 a
60^12=72 r   77^12=65 e   4e^12=5c \   51^12=43 C   7e^12=6c l   73^12=61 a
61^12=73 s   61^12=73 s   77^12=65 e   61^12=73 s   4e^12=5c \   51^12=43 C
5e^12=4c L   41^12=53 S   5b^12=49 I   56^12=44 D   4e^12=5c \
→ "Software\Classes\CLSID\"
```

### 4.3 结论

**`scansk` 不是激活凭据，是"counterfeit 状态键的路径定位器"。**

- 它是一段**每机器唯一的加密 GUID**，解密后拼成
  `Software\Classes\CLSID\{<GUID>}` —— 也就是**负向标记 `MData` 的存放位置**。
- 与之配套的第二个路径由 `FUN_0052E2E0`（VA `0x52E2E0`）构造，写入全局 `DAT_0078a374`；
  第一个写入 `DAT_0078a370`（构造点 `0x4EE7B0`–`0x4EE7DA`）。
- **`FUN_00450900`（激活判定）完全不读 `scansk`** —— 它只读 §3.1 那 4 个值 + §3.2 的 CLSID 键。
  所以：**动 `scansk` 不会让 IDM 变成已注册**，只会改变 counterfeit 记录存在哪里。

> 未定位：`scansk` 的**写入者**（很可能是安装/首次运行时生成）。已确认它不由 `FUN_00450900` 写。

---

## 5. 风险：写错数据会不会触发 counterfeit（Q5）

**会。判据链如下（全部静态证据）：**

1. 序列号格式合法 → `DAT_0077bd24 = 0`（`0x450BC9`）。
2. 随后 `FUN_0044E840(serial, …)` 做真正校验（`0x450F0D` 附近）。
3. 若进入阶段 5，代码把 `serial` 与**内置黑名单**逐条 `strcmp`：
   `DAT_0078a714`、`DAT_0078a718`、`DAT_0078a720`、`DAT_0078a724`、`DAT_0078a728`、`DAT_0078a72c`
   （反编译里可见 6 段完全相同的比较循环，见 `LAB_00451188` / `LAB_00451255` / `LAB_004512d5` / `LAB_00451315` / `LAB_00451355`）。
4. 命中 → `strcpy(mdata, DAT_0078a728)` → `FUN_00445560` 加密 → **`RegSetValueExA(hk, "MData", 0, 0, mdata, 0x100)`**（`0x44DEAB`）。
5. 下次启动读到 `MData` → 消息派发器（b15 的 `0x44B5F5` 附近，即 b8 `FUN_0044B490` 的新版）弹出
   `Internet Download Manager has been registered with a counterfeit Serial Number or the Serial Number has been blocked. IDM is exiting...`（`0x6BA530`）或
   `…This serial number is blocked on IDM servers. IDM is exiting...`（`0x6AF468`，**b15 新增**）→ **退出**。

**⇒ 用网上流传的"注册机序列号"是本构建下最危险的做法**：它们大概率就在那份黑名单里，会直接把 IDM 打成 counterfeit 状态。

**缓解**：`MData` 是可清除的 —— `0x42F03A` 处的 `RegDeleteValueA(hk,"MData")` 就是官方的清理路径。若已中招，删除该值即可恢复（但要先关掉 IDM）。

---

## 6. 完整回答

### Q1 `scansk` 是什么？
每机器唯一的加密 GUID（REG_NONE 64B，前 40B 有效），由 `FUN_0052EC00`/`FUN_0052E2E0` 解密后拼成
`Software\Classes\CLSID\{<GUID>}`，即**counterfeit 负向标记的存放路径**。
**与激活无关** —— 激活判定函数 `FUN_00450900` 根本不读它。

### Q2 「已注册」由哪些注册表数据决定？
正向：`HKCU\SOFTWARE\Internet Download Manager` 下的 `Serial`(格式 23 位+3 短横线) + `FName` + `LName` + `Email`。
负向：`HKLM\Software\Classes\CLSID\{<scansk 派生 GUID> 或硬编码 {E6871B76-…}}` 下**不能有 `MData`**。

### Q3 是否存在"只写注册表就能变成已注册"的路径？
**不存在可用的路径。** 精确说法：
- 注册表 `Serial` 的存在 + **格式合法**，确实会执行 `DAT_0077bd24 = 0`（Full）—— 这是唯一一处由注册表数据直接驱动的状态翻转。
- **但**同一函数紧接着用 `FUN_0044E840` 做真正的序列号校验，并用内置黑名单判定，结果决定状态码（`0x45378C` 跳转表分派）。
- 注册表里**没有任何一个值能直接表示"已注册"**；标志的两个写点都在代码里，且都要求先通过校验。
- 结论：**必须有一个能通过 `FUN_0044E840` 且不在黑名单里的序列号**（serial-reverser 的任务）。单纯伪造注册表**不可行**，而且**有把 IDM 打成 counterfeit 的实际风险**。

### Q4 真正注册成功的 IDM 的最小完备集合
```
HKCU\SOFTWARE\Internet Download Manager
    Serial  REG_SZ   "<通过 FUN_0044E840 校验的 23 字符序列号>"
    FName   REG_SZ   "<任意非空>"
    LName   REG_SZ   "<任意非空>"
    Email   REG_SZ   "<任意非空>"

HKCU\Software\DownloadManager
    nExpDt  REG_DWORD  <可选，仅影响「关于」显示；32 位上限 2038-01-19>
    scansk  REG_NONE   <保持原值，不要动>

HKLM\Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}
    (必须不存在 MData / Model / Therad —— 或只存在 MData 以外的无害值)
```
即：**4 个正向值 + 1 个"负向标记不存在"**。缺 FName/LName/Email 任一 → status 5。

### Q5 风险提示
见 §5。**用流传的注册机序列号极可能命中内置黑名单 → 写 `MData` → 下次启动 counterfeit 并退出。**

---

## 7. 复现命令

```powershell
# 只读查看注册表现场
reg query "HKCU\Software\DownloadManager" /v scansk
reg query "HKCU\SOFTWARE\Internet Download Manager"        # 本机不存在
reg query "HKLM\Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}"   # 本机不存在

# 静态复核（私有工具，指向 b15）
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
$d  = "$env:TEMP\b15tool"
& $py "$d\writers2.py" 0x77bd24          # 注册标志：2 writes，都是 0
& $py "$d\writers2.py" 0x78a370          # scansk 派生路径全局
& $py "$d\idmdis.py" 0x450BA9 20         # 序列号格式检查 + 标志写入
& $py "$d\xref2.py" va 0x69D1E4          # "MData" 的全部引用
& $py "$d\xref2.py" va 0x6BA530          # counterfeit 文案引用
```

Ghidra 反编译（独立只读工程）：
```
analyzeHeadless.bat "$env:TEMP\b15ghidra" b15proj -readOnly -process "IDMan.exe.b15" `
  -noanalysis -scriptPath "D:\pojie应用\jiesuo\work\idm-6.43b8\scripts" `
  -postScript DumpFuncs2.java 0x450900
```

---

## 8. 局限与未决项

1. **`FUN_0044E840` 的内部算法未展开** —— 那是 serial-reverser 的任务范围。本报告只确认：
   它是真正的序列号判决者，`FUN_00450900` 在格式检查之后调用它。
2. `FUN_00450900` 的返回值在 Ghidra 里被识别为 `void`（SEH 尾声干扰），但调用点 `0x4527DA`
   确实把 `eax` 当状态码用（`0x4527FC cmp eax,0xc` / `0x452805 jmp [eax*4+0x45378c]`）。
   已确认的正常出口设 `eax = 6`（`0x450F53`）；其余出口的 `eax` 未逐条穷举。
3. `scansk` 的**写入者**未定位（已确认不由 `FUN_00450900` 写）。
4. `DAT_0078a720` 等 6 个黑名单条目**未解密出明文** —— 它们是运行时解密的字符串，
   需要复现 `FUN_0052DDA0` 的算法才能读出。**这正是"不要用流传注册机序列号"这一警告的量化依据的缺口**，
   但方向性结论（命中即写 MData）已由 `RegSetValueExA(hk,"MData",…)` 的代码路径直接证明。
5. 本报告**未做任何动态验证**（按任务约束不启动 IDMan.exe、不写注册表）。
