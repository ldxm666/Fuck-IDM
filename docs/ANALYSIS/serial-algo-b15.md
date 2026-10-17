# IDM 6.43 Build 15 —— 序列号校验算法逆向

- 目标：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（FileVersion **6,43,15,3**）
- 分析副本：`work/idm-6.43b8/bin/b15/IDMan.exe.b15`
- sha256：`279CEED9AAA646650716EE326C0D996BE4CE5DB4B252CF5B2747F4938A7CE737`（已核对一致）
- 方法：纯静态（pefile + capstone 手工反汇编 + Ghidra 12.1.2 headless 反编译，独立工程）
- 全程**未启动 IDMan.exe**、未写注册表、未修改安装目录

---

## 0. 结论（先说答案）

> ## **能。可以生成被 IDM 接受的序列号。**
>
> IDM 6.43b15 对序列号**没有任何密码学校验** —— 没有 checksum、没有内嵌公钥、没有必须联网的校验。
> 判定"已注册"只有两个条件：
>
> 1. **格式**：长度 `0x17`(23)，第 5/11/17 字节是 `'-'` → `XXXXX-XXXXX-XXXXX-XXXXX`
> 2. **不在本地黑名单里**：取序列号**前 8 个字符**拼成值名，在注册表里查得到就判 counterfeit
>
> 因此**任意**符合格式的序列号都会被接受。已交付生成器 `scripts/idm-keygen.py`。

---

## 1. 完整调用链（问题 1）

### 1.1 注册状态的最终判定：`FUN_00450900`（VA 0x450900）

这是 IDM 启动时/注册后决定 **Full 还是 Trial** 的函数。Ghidra 反编译（`local_43c` 是
`HKCU\Software\DownloadManager` 的键句柄）：

```c
RegOpenKeyExA(HKEY_LOCAL_MACHINE /*0x80000002*/, DAT_0078a634, 0, 1, &local_43c);
if (opened) {
    RegQueryValueExA(hk, DAT_0078a628, ..., local_1b0, &sz);  bVar11   = (ok)
    RegQueryValueExA(hk, DAT_0078a62c, ..., local_1e4, &sz);  local_44a = (ok)
    RegQueryValueExA(hk, DAT_0078a630, ..., local_218, &sz);  local_44b = (ok)
    RegQueryValueExA(hk, DAT_0078a624, ..., local_3c,  &sz);  local_43d = (ok)  // ← "Serial"
    RegCloseKey(hk);
}
RegCreateKeyExA(HKEY_CURRENT_USER /*0x80000001*/, "Software\\DownloadManager\\", ...);
// ... 同样的 4 个值再从 HKCU 读一遍（HKLM 没读到才回落）...

if (local_43d != 0) {                       // Serial 值存在
    pbVar6 = local_3c;                       // 算 strlen
    do { bVar1 = *pbVar6; pbVar6++; } while (bVar1 != 0);
    if ((((int)pbVar6 - (int)(local_3c + 1) == 0x17)     // 长度 == 23
         && (local_37 == '-'))                            // [5]  == '-'
        && (local_31 == '-'))                             // [11] == '-'
        && (local_2b == '-')) {                           // [17] == '-'
        DAT_0077bd24 = 0;                                 // ★ 注册标志 = 0 = Full
        FUN_00402f20(local_474[0], &DAT_00696f00, local_3c);   // 保存序列号到全局
        _strncpy(local_48, (char *)local_3c, 8);               // 取前 8 字符
        local_40 = 0;
        FUN_00402f20(&DAT_00788ee4, &DAT_00696f00, local_48);  // 序列号前缀 -> 显示用全局
    }
}
```

**注意 `DAT_0077bd24 = 0` 之前只有格式判断，没有任何别的运算。**

对应的机器码（反汇编实证）：

```asm
0x00450B90  lea   eax, [ebp + 0x3ec]        ; 序列号缓冲区
0x00450BA0  mov   cl, byte ptr [eax]        ; 内联 strlen
0x00450BA7  sub   eax, edx
0x00450BA9  cmp   eax, 0x17                 ; ★ 长度 == 23
0x00450BAC  jne   0x450c1d                  ; 否 -> 跳过（保持 Trial）
0x00450BAE  cmp   byte ptr [ebp + 0x3f1], 0x2d   ; ★ [5]  == '-'
0x00450BB5  jne   0x450c1d
0x00450BB7  cmp   byte ptr [ebp + 0x3f7], 0x2d   ; ★ [11] == '-'
0x00450BBE  jne   0x450c1d
0x00450BC0  cmp   byte ptr [ebp + 0x3fd], 0x2d   ; ★ [17] == '-'
0x00450BC7  jne   0x450c1d
0x00450BC9  mov   dword ptr [0x77bd24], 0         ; ★★ 注册标志 = 0（Full）
0x00450BD3  lea   edx, [ebp + 0x3ec]
0x00450BE3  call  0x402f20                  ; CString::Format(保存序列号)
0x00450BF8  call  0x63e280                  ; strncpy(dst, serial, 8)
0x00450C15  call  0x402f20                  ; 序列号前缀 -> DAT_00788ee4
```

> **b15 的注册标志是 `0x77BD24`**（b8 是 `0x779CDC`）。这是本报告最重要的地址之一。

### 1.2 格式检查在镜像里共 4 处，分属 2 个函数

对 `cmp eax,0x17` + 三连 `cmp byte [reg+disp32],0x2D` 做全镜像扫描：

| 簇 | VA | 所属函数 |
| --- | --- | --- |
| 1 | `0x450BA9`（破折号 0x450BAE/0x450BB7/0x450BC0） | `FUN_00450900` (0x450900) |
| 2 | `0x451D31`（0x451D36/0x451D3F/0x451D48） | `FUN_00450900` |
| 3 | `0x467529`（0x46752E/0x467537/0x467540） | `FUN_00466EE0` (0x466EE0) |
| 4 | `0x467659`（0x46765E/0x467667/0x467670） | `FUN_00466EE0` |

`FUN_00466EE0` 是**注册对话框的字段校验**（`ret 8`，返回 bool，成功路径 `xor eax,eax`）：

```asm
0x004674FD  je  0x46754d              ; 字段1 为空 -> 失败
0x00467511  je  0x46754d              ; 字段2 为空 -> 失败
0x00467529  cmp eax, 0x17             ; ★ 序列号长度 == 23
0x0046752E  cmp byte [ebp+0x1a1], 0x2d   ; '-'
0x00467537  cmp byte [ebp+0x1a7], 0x2d   ; '-'
0x00467540  cmp byte [ebp+0x1ad], 0x2d   ; '-'
0x00467547  je  0x467338              ; 全通过 -> 成功
```

**它要求"姓名 + 另一个字段 + 序列号"都非空，但序列号本身仍然只看格式。**

### 1.3 唯一的"额外检查"：`FUN_0044E840`（VA 0x44E840）—— 本地黑名单查表

`FUN_00450900` 在置标志之后，会调用它做二次判定（`local_480 = 1` 表示被判定为 counterfeit/blocked）：

```c
void FUN_0044e840(char *serial, int param_2, int *out_flag, int *out_blocked) {
  FUN_0044e1c0(&local_a34, &local_a30);          // 取两个键名（运行时解密）
  if (RegOpenKeyExA(HKLM, local_a34, ...) == 0) {
      RegCloseKey();
      if (RegOpenKeyExA(HKLM, local_a30, ...) == 0) { *out_flag = 1; RegCloseKey(); }
  }
  if (*out_flag != 0) { if (!serial || strlen(serial) <= 9) { cleanup; return; } }
  if (param_2 == 0) { cleanup; return; }

  _strncpy(local_81c, serial, 8);                // ★ 只取序列号前 8 个字符
  local_82c = { 0x4A,0x41,0x4C,0x4A,0x42,0x7B,0x4C,0x5A,
                0x0C,0x45,0x4D,0x76,0x0C,0x5A,0x00 };   // "JALJB{LZ\fEMv\fZ"
  FUN_00447590(&local_82c);                      // ★ 运行时解密（IDM 自研 Feistel）
  FUN_00402f20(&local_a1c, &local_82c, 1, local_81c);   // 值名1 = f(解密串, 前8字符)
  FUN_00402f20(&local_a20, &local_82c, 2, local_81c);   // 值名2
  local_a18[1] = 0x800;
  LVar3 = RegQueryValueExA(DAT_00788d08, local_a1c, ..., local_810, &size);
  if (LVar3 == 0) {
      FUN_00402f20(&local_a24, "%s", local_810);
      size = 0x800;
      LVar3 = RegQueryValueExA(DAT_00788d08, local_a20, ..., local_810, &size);
      if (LVar3 != 0) goto LAB_00450766;
      FUN_00402f20(&local_a28, "%s", local_810);
      *out_blocked = 1;                          // ★ 命中黑名单 -> blocked
  }
  ...
}
```

**要点**：这里**没有任何对序列号本身的计算**。它只是拿前 8 个字符当**查表键**，
去注册表里看有没有对应的"封禁"记录。查不到 → 不是 counterfeit → 通过。

---

## 2. 纯本地还是必须联网？（问题 2）

> ## **纯本地。不需要联网。**

证据：

1. **`FUN_00450900` 全程没有任何网络调用** —— 反编译里只有 `RegOpenKeyExA` /
   `RegCreateKeyExA` / `RegQueryValueExA` / `RegCloseKey` / 字符串格式化 / `_strncpy`。
2. **`FUN_0044E840` 同样只有注册表操作** —— 没有 `InternetOpen`/`HttpSendRequest`/
   `WinHttp*` 之类调用。
3. **`CRegistrationDlg::OnOkreg`（0x522910..0x523B46，4662 字节）内部不含任何 URL 字符串。**
   把该函数范围内所有 `push imm32` 解引用后得到的字符串是：
   `"Internet Download Manager"`、`"%s"`、`"SOFTWARE\Internet Download Manager"`、
   `"Reg err1/2/3/4 in CRgDlg::OnOk, err = %ld"`、`"%s\%s"`、`"MData"`、`"SpecVersion"`、
   三个 `Software\Classes\CLSID\{...}`、`"CURRENT_USER\%s"`、`"ptrk_scdt"`、`"bshexmsg"`、
   `"nExpDt"`、`"nLst"`、`"S"`、`"%b/%d/%Y"`、`"CRegistrationDlg::OnOkreg()"`。
   **没有 `secure.internetdownloadmanager.com`、没有 `update.cgi`、没有任何 http(s) 串。**
4. 判定 Full/Trial 的那个 `DAT_0077bd24 = 0` 完全由**本地字节比较**决定。

> 需要说明的边界：IDM **别处**（更新检查、`update.cgi` 上报）确实会联网，
> 但**那与"序列号是否被接受"无关** —— 本地判定不看服务器。

---

## 3. 能否构造合法序列号？（问题 3）

> ## **能。**

### 3.1 算法

就是格式规则，没有别的：

```
序列号 = G1 "-" G2 "-" G3 "-" G4
其中每个 Gi 是 5 个字符（IDM 真号用大写字母+数字，但检查本身不限制字符集）
总长度必须是 23，'-' 必须落在下标 5、11、17
```

判定伪码（严格镜像 `0x450BA9` 处的逻辑）：

```python
def validate(s):
    return len(s) == 0x17 and s[5] == '-' and s[11] == '-' and s[17] == '-'
```

### 3.2 可用示例序列号

以下均由 `scripts/idm-keygen.py --seed idm643` 生成（可复现），**全部通过格式校验**：

```
DQI64-NGF4D-VQ2KM-8NRZI
F6K2H-ODA9G-YDAN6-ORFQO
ERRTC-WNW81-OL1HW-3G7OI
F71HR-K7DJK-YP4TI-5O7QE
4225H-48RH2-W77YI-G6CJ1
4YA8L-8Z3TZ-DDLME-YF13V
```

最小可用样例（纯占位）：

```
AAAAA-BBBBB-CCCCC-DDDDD
```

> ⚠️ **唯一的不确定性**：`FUN_0044E840` 的本地黑名单。黑名单是**按前 8 个字符**
> 查表，所以理论上"某个特定前缀"可能已被 IDM 标记。生成器默认让每个序列号
> 前缀唯一，且用随机字符，撞上已封禁前缀的概率可忽略。
> 黑名单的**内容**无法离线枚举（它由 IDM 运行时从服务器响应或本地状态写入）。

### 3.3 生成器

`work/idm-6.43b8/scripts/idm-keygen.py`（已实跑自检通过）：

```
python idm-keygen.py --selftest      # 自检：6 个非法输入全部被拒 + 200 次生成全合法 + seed 可复现
python idm-keygen.py --count 6 --seed idm643
python idm-keygen.py --check AAAAA-BBBBB-CCCCC-DDDDD
```

自检实测输出：

```
[PASS] ''                         空串
[PASS] 'AAAAA-BBBBB-CCCCC-DDDD'   22 字符
[PASS] 'AAAAA-BBBBB-CCCCC-DDDDDD' 24 字符
[PASS] 'AAAAABBBBB-CCCCC-DDDDD'   第 5 位不是 -
[PASS] 'AAAAA-BBBBBCCCCC-DDDDD'   第 11 位不是 -
[PASS] 'AAAAA-BBBBB-CCCCCDDDDD'   第 17 位不是 -
[PASS] 'AAAAA-BBBBB-CCCCC-DDDDD'  格式合法
[PASS] 连续生成 200 个，全部通过格式校验
[PASS] seed 可复现: 0ATXM-R1KXH-1Q9L9-LWF70 == 0ATXM-R1KXH-1Q9L9-LWF70
```

> 诚实说明：因为校验是格式驱动的，这个脚本本质是**序列号格式化器**，不是密码学 keygen。
> 它不"破解"任何算法，因为**没有算法可破**。

---

## 4. 必须联网？（问题 4）

不适用 —— 见第 2 节，校验纯本地。

---

## 5. 序列号与 `scansk` / CLSID 状态串的因果关系（问题 5）

> **状态串独立于序列号。序列号校验通过只是把标志置 0；状态串是另一套并行的机制。**

证据与机制：

1. **序列号 → 标志**：`FUN_00450900` 里，`local_43d`（Serial 值存在）→ 格式检查 →
   `DAT_0077bd24 = 0`。这条路径**不读写任何 CLSID 键、不碰 scansk**。
2. **状态串 → counterfeit 判定**：`FUN_0044E840` 通过 `FUN_0044e1c0(&local_a34, &local_a30)`
   取到两个键名，在 **HKLM** 下探测；命中则 `*out_flag = 1`，然后才进入按前 8 字符的
   黑名单查表。这条路径**与序列号的字符内容无关**（只取前 8 字符当查表键）。
3. **CLSID 键由注册流程写**：`CRegistrationDlg::OnOkreg` 里出现三个 CLSID 键
   `{E6871B76-C3C8-44DD-B947-ABFFE144860D}`、`{79873CC5-3951-43ED-BDF9-D8759474B6FD}`、
   `{6DDF00DB-1234-46EC-8356-27E7B2051192}`，每个都配 `"MData"` / `"SpecVersion"` 值
   （push 点：0x5232BB、0x523361、0x52341C，及对应的 `"MData"`/`"SpecVersion"`）。
   同一函数还写 `nExpDt`(0x52352E)、`nLst`(0x52353C)、`ptrk_scdt`(0x523513)、`bshexmsg`(0x523520)。
4. 当前实机注册表实测：`Serial`/`FName`/`LName`/`Email` **全部不存在**，
   `nExpDt = 2145873600`，`scansk` 存在（**64 字节**，b8 时是 32 字节）。
   → 说明用户机器处于"有 scansk 但没有序列号"的**半状态**，这正是
   "试用到期 + 快捷更新要求注册"的来源。

**因果结论**：
- 写序列号 → `DAT_0077bd24 = 0` → 关于对话框显示 Full。
- `scansk` / CLSID 状态串是**另一条独立通道**，它能把一个格式合法的序列号
  判定为 counterfeit/blocked（通过黑名单），但**不会**反过来让合法序列号变得"非法"。
- 所以：**不需要伪造 scansk 或 CLSID 状态串**；写一个干净的、未上黑名单的
  合法序列号即可。

---

## 6. 顺带确认：用户看到的"快捷更新需要激活"

用户截图里的 `在升级 IDM 之前请注册。请选择"注册 - 注册"菜单项...` 对应
**更新对话框按钮处理器**里的这段（VA 0x42E290 起）：

```asm
0x0042E29B  push "SOFTWARE\Internet Download Manager"
0x0042E2A0  push 0x80000002                 ; HKEY_LOCAL_MACHINE
0x0042E2A5  call dword ptr [0x695098]       ; RegOpenKeyExA
0x0042E2AB  test eax, eax
0x0042E2AD  jne  0x42e2f5                   ; 打不开 -> 回落 HKCU
0x0042E2C4  mov  ecx, dword ptr [0x78a624]  ; 值名 = "Serial"
0x0042E2D2  call dword ptr [0x695004]       ; RegQueryValueExA
0x0042E2D8  test eax, eax
0x0042E2DA  jne  0x42e2e4
0x0042E2DC  mov  bl, 1                      ; ★ 值存在 -> bl = 1
0x0042E2DE  mov  byte ptr [ebp - 0xab1], bl
...
0x0042E2F1  test bl, bl
0x0042E2F3  jne  0x42e32c                   ; 存在 -> 放行
0x0042E2F5  ...                             ; 不存在 -> 试 HKCU，再不行就报"请先注册"
```

> **这个门槛只检查 `Serial` 值"存不存在"，完全不看内容。**
> 也就是说：只要在 `HKLM\SOFTWARE\Internet Download Manager`（或回落 HKCU）
> 下存在一个名为 `Serial` 的值，`在升级 IDM 之前请注册` 就不会再出现。

---

## 7. 证据索引

| # | 结论 | VA / 字节 | 方法 |
| --- | --- | --- | --- |
| E1 | 注册标志 = `0x77BD24` | `0x450BC9` `C7 05 24 BD 77 00 00 00 00 00` | 反汇编 |
| E2 | 序列号长度必须 23 | `0x450BA9` `83 F8 17` | 反汇编 |
| E3 | 三处破折号位置 | `0x450BAE`/`0x450BB7`/`0x450BC0` = `80 BD F1 03 00 00 2D` 等 | 反汇编 + 全镜像扫描（4 簇） |
| E4 | 格式通过即置标志，无其它运算 | Ghidra 反编译 `FUN_00450900` 第 146-153 行 | 反编译 |
| E5 | 二次校验只做前 8 字符查表 | `FUN_0044e840`：`_strncpy(local_81c, param_1, 8)` + `RegQueryValueExA(DAT_00788d08, ...)` | 反编译 |
| E6 | 黑名单密文常量 | `FUN_0044e840` 内 `local_82c = {4A 41 4C 4A 42 7B 4C 5A 0C 45 4D 76 0C 5A 00}` | 反编译 |
| E7 | 注册对话框无任何 URL | `0x522910..0x523B46` 全部 `push imm32` 字符串枚举 | 脚本扫描 |
| E8 | 更新门槛只看 Serial 是否存在 | `0x42E2A5` RegOpenKeyExA / `0x42E2D2` RegQueryValueExA / `0x42E2DC` `mov bl,1` | 反汇编 |
| E9 | 三个 CLSID 键 + MData/SpecVersion | push @ `0x5232BB`/`0x523361`/`0x52341C`/`0x523282`/`0x523293` | 脚本扫描 |
| E10 | 注册对话框字段校验 | `FUN_00466EE0` `0x467529` 等 | 反汇编 |

---

## 8. 未决项与局限（不掩盖）

1. **黑名单的键名与内容未解出。** `DAT_00788d08` 是被全镜像高频引用的键句柄
   （极可能是 `HKCU\Software\DownloadManager`），但未找到其赋值点，因此**无法确认**
   黑名单值挂在哪个键下。这不影响"能否生成序列号"的结论（随机前缀撞黑名单概率可忽略），
   但如果要 100% 确认，需要动态观察或继续解 `FUN_0044e1c0` 的两个键名。
2. **`FUN_00447590`（解密 `local_82c`）的明文未还原。** 它是 IDM 自研 Feistel
   （与 b8 的 `FUN_004447BD0` 同族）。解出它才能知道值名的确切格式串
   （形如 `xxx%s`）。不影响结论。
3. **未做动态验证。** 任务约束禁止启动 IDMan.exe / 写注册表，所以"写入序列号后
   IDM 真的显示 Full"这一步**没有实测**，属于静态推断链。静态证据链完整
   （E1+E2+E4），但建议 Lead 在实机上按第 6 节写 `Serial` 值后验证。
4. **`DAT_00788d1c` 与 `0x5d2` 的比较**（`FUN_00450900` 第 223 行
   `if ((local_43d != '\0') && (0x5d2 < DAT_00788d1c))`）语义未确定 ——
   看起来是个计数/日期阈值，可能是"运行足够久才做深检查"的门槛。不影响主结论。
