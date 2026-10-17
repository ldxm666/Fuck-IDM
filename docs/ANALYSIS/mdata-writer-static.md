# IDM 6.43 Build 15 — `MData` 写入点静态分析（含 Hook 决策证据卡）

> 目标：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe.bak-original`
> sha256 `279CEED9AAA646650716EE326C0D996BE4CE5DB4B252CF5B2747F4938A7CE737`（6201712 B，PE32 x86，ImageBase `0x400000`）
> 与 `work/idm-6.43b8/bin/b15/IDMan.exe.b15` **逐字节相同**（同 sha256）。分析全程**只读**。
> 工具：`patches/mdata_probe.py`、`patches/mdata_sites.py`（本次新建，见 §10）。
>
> **本文件推翻了任务书中的一条前提**，见 §1。请先读 §1 再读其余部分。

---

## 0. 结论速览

| 问题 | 结论 |
| --- | --- |
| Q1 为什么"零静态引用" | **前提不成立。** `0x29D1E4` 是 **RVA**，不是 VA。真实 VA 是 `0x69D1E4`，全文件有 **19 处 `push 0x69D1E4`**。原扫描找的是 RVA，故为 0。 |
| Q1 候选 (a) 代码自解密 | **否定。** `68 E4 D1 69 00`（`push "MData"`）在文件里是**明文**，四处写入点全部明文可读。 |
| Q1 候选 (b) 运行时算地址 | **部分成立，但不是"零引用"的原因。** 另有一类站点通过 **BSS 里的 CString 全局 `0x78A730`** 取值名（`mov eax,[0x78a730]; push eax; call RegSetValueExA` @`0x5214B7`），这类站点 `push imm32` 扫描看不见。 |
| Q1 候选 (c) 死数据 | **否定。** 19 处引用全部落在 `RegSetValueExA`/`RegQueryValueExA`/`RegDeleteValueA` 调用前。 |
| Q2 `.reloc` | 92224 条重定位（91829 × type3 HIGHLOW + 395 × type0 ABS）。**19 个 `push imm32` 站点的立即数字段全部有 type3 重定位**——这是它们是绝对地址引用的铁证。`.rdata` 字符串区内 0 条重定位（正常，该处不存放被重定位的指针）。 |
| Q3 `0x44DE52` 所在函数 | 函数体 `0x44CCB0`；`MData` 写入 `push 0x69D1E4` @**`0x44DEAB`**，`RegSetValueExA` 调用点 @**`0x44DEB4`**，随后 `RegFlushKey`@`0x44DEBE`、**`ExitProcess(0)`@`0x44DED6`**。 |
| Q4 `m::OnTimer()` 归属 | 该串是 **`"Unknown error during CConfirm::OnTimer()\n"`（VA `0x69D168`）的尾巴**。类名是 **`CConfirm`**，不是 `m`。`CConfirm` 的 **WM_TIMER 处理入口 = `0x42E9A0`**（消息映射 @VA `0x69D2D8`）。**该 timer 路径只 `RegDeleteValueA("MData")`，从不写 `MData`。** |
| **总判定** | **`MData` 是 counterfeit/封禁负向标记（handover 的判断正确），不是 timer 写的良性周期值。** 决定性证据：两处写入点后 20 字节内就是 `RegFlushKey` + `ExitProcess(0)`；第三处的 worker 在 verdict ∈ {1,2,7,0xA,0xC} 时同样 `ExitProcess`。良性心跳不可能杀进程。 |

**给 Lead 的可执行结论**

1. **P4（`0x44DE52` → `jmp 0x44DB10`）方向正确且有效**，它精确封死了 W1（`0x44DEAB` 写 + `ExitProcess`）。
2. **但线上二进制只补了 4 个字节段**（见 §5 全文件 diff），**W2（`0x4676D0`）与 W3（`0x521633`/`0x52164B`）完全没补**。这两条路同样会写 `MData`，其中 W3 是**自我重挂的后台校验 worker**，是"每 ~2 分钟复发"的头号嫌疑。
3. **不要再改 IDM 去迁就守护。** 守护的 `run_guard()`（`IDM-Activator.py:579-592`）一看到 `MData` 就 `purge_fake_serial()` + 轮换序列号；而 IDM 判定当前序列号假冒才会写 `MData`——这是**守护自己造出来的闭环**。正确修法是改守护的判定策略，而不是继续加补丁。
4. 唯一未闭合项：`MData` 复发的**精确 2 分钟节拍**未在静态层面定位到（见 §9 残余未知 + 动态探针）。

---

## 1. 【必须先纠正】地址数学：`0x29D1E4` 是 RVA，不是 VA

任务书给的段表把 `VirtualAddress` 列当成了绝对 VA。PE 里段表的 `VirtualAddress` 字段**是 RVA**，绝对 VA = `ImageBase + VirtualAddress`。

```
ImageBase = 0x400000        DllCharacteristics = 0x8140 (DYNAMICBASE=1)   SizeOfImage = 0x5F5000

段      RVA(段表)   RAW       vsize      rawsize    |  绝对 VA 区间
.text   0x001000    0x000400  0x2931FC   0x293200   |  0x401000 .. 0x694200
.rdata  0x295000    0x293600  0x0E500E   0x0E5200   |  0x695000 .. 0x77A200
.data   0x37B000    0x378800  0x0136DC   0x00A400   |  0x77B000 .. 0x78E6DC  (仅 0x77B000..0x785400 有文件映射，其余是 BSS)
.rsrc   0x38F000    0x382C00  0x22D738   0x22D800   |  0x78F000 .. 0x9BC738
.reloc  0x5BD000    0x5B0400  0x037282   0x037400   |  0x9BD000 .. 0x9F4282
```

文件偏移公式（三套，**不能混用**）：

| 段 | 公式 | 校验 |
| --- | --- | --- |
| `.text` | `file = VA − 0x400C00` | VA `0x44DE52` → file `0x4D252` ✓（= P4 补丁点，与 `p4-apply.ps1` 一致） |
| `.rdata` | `file = VA − 0x401A00` | VA `0x69D1E4` → file `0x29B7E4` ✓（与任务书给的 file 一致） |
| `.data` | `file = VA − 0x402800` | VA `0x77BD24` → file `0x379524` ✓（= 全文件 diff 里 `g_registered` 初始化器） |

**所以**：
- 任务书说"handover 用 `VA = offset + 0x400C00` 处理所有段，因此把 `MData` 算成 VA `0x69D1E4`，这是一个不在任何段内的地址" ——**这句话本身是错的**。`0x69D1E4` 落在 `.rdata`（`0x695000..0x77A200`）**之内**，是正确的 VA。
- 任务书给出的"REAL address is VA 0x29D1E4" —— `0x29D1E4` 落在 `.text`（`0x401000..0x694200`）**之外**（它在 `.rdata` 的 RVA 区间内），作为 VA 是无效地址。
- `regstate-b15.md` 里 `push 0x69d1e4 ; "MData"` 的写法**一直是对的**。§4 中 `patches/` 其他文档里的 `0x44DEAB` / `0x44D9FB` / `0x42F03A` 等地址也全部正确。

> 教训（已写入 §8 锚点规范）：**引用地址一律带段名 + 明确标注 VA/RVA**。

---

## 2. Q1 — "零静态引用"的真相

### 2.1 实测：`push 0x69D1E4` 有 19 处

```
$ python mdata_probe.py refs 0x69D1E4
VA  0x0069D1E4 : 19 hit(s)   ... (.text)
RVA 0x0029D1E4 : 0 hit(s)
```

`MACHINE`(VA `0x69D1EC`) 35 处、`CURRENT_USER`(VA `0x69D1F4`) 35 处、
`Software\Classes\CLSID\{E6871B76-…}`(VA `0x69D1A4`) 33 处、
`CURRENT_USER\%s`(VA `0x69D194`) 24 处、`{84797876-…}` 2 处、`{6DDF00DB-…}` 4 处、`{79873CC5-…}` 4 处、`{07999AC3-…}` 2 处。

任务书描述的"5 个 GUID 全零命中"同样是 RVA 误用所致。

### 2.2 候选 (a) 自解密 —— 否定

四处写入点的原始文件字节（明文）：

```
VA 0x0044DEAB  file 0x04D2AB  bytes  68 e4 d1 69 00 8b      ; push 0x69D1E4 ; mov edx,[ebp-0x14]
VA 0x004676D0  file 0x066AD0  bytes  68 e4 d1 69 00 8b
VA 0x00521633  file 0x120A33  bytes  68 e4 d1 69 00 8b
VA 0x0052164B  file 0x120A4B  bytes  68 e4 d1 69 00 8b
```

`0x69D1E4` 的 19 处出现**全部**是 `push imm32`（`68 E4 D1 69 00`），且**全部带 type3 重定位**（§3）。
引用了 `MData` 的代码在磁盘上是**明文**，不存在"被加密的自解密区"。

附带核查 handover 声称的 `rol al,0xC0` / `add al,al` 解密循环：`.text` 中字节模式 `C0 C0 C0` 仅 7 处、`00 C0` 201 处（后者绝大多数是普通指令的巧合字节），且 `0x44D000–0x44E000` 区间反汇编出的是一段语义完整、`Reg*` 调用密集的正常代码（§4）。**判定：无覆盖 `MData` 引用代码的加密区。候选 (a) 否定。**

### 2.3 候选 (b) 运行时算地址 —— 部分成立（另一类站点）

存在**第二类**访问方式：值名从 **BSS 里的 MFC `CString` 全局 `0x78A730`** 取。

```
VA 0x005214A0  6a 00 6a 00 a1 30 a7 78 00 50 8b 4d ec 51 8b 3d 90 50 69 00 ff d7
                 push 0      ; dwType = REG_NONE
                 push 0      ; Reserved
                 mov  eax,[0x78A730]      <-- 值名指针来自 BSS 全局
                 push eax
                 mov  ecx,[ebp-0x14] ; hKey
                 push ecx
                 mov  edi,[0x695090] ; ADVAPI32!RegSetValueExA
                 call edi
```

- `0x78A730` 位于 `.data` 的 **BSS 区**（RVA `0x38A730` > `.data` rawsize `0xA400`），静态值全 0，运行时才被赋值。
- 该全局共 20 处引用，逐条分类：**17 处 LOAD**（`8B 0D` / `8B 15` / `A1`，含 `0x5214A8`）、**2 处取地址**（`mov ecx,0x78A730`，`0x68EA80` 与 `0x693730`）、**1 处巧合字节匹配**（`0x4EBAF9`）；**0 处 STORE**。取地址的两处分别是 CString 构造/析构注册：
  ```
  0x0068EA80  mov ecx, 0x78A730 ; call 0x4024F0 (CString 构造) ; push 0x693730 ; call 0x64007E (atexit) ; ret
  0x00693730  mov ecx, 0x78A730 ; jmp  0x402560 (CString 析构 thunk)
  ```
- 它被用在**同一个 `{E6871B76-…}` 键**上（`0x450D55`：`RegQueryValueExA(hk,[0x78A730],…)`；hk 由 `0x450D75..0x450D92` 对 `HKEY_LOCAL_MACHINE(0x80000001)` + `"Software\Classes\CLSID\{E6871B76-…}"` 的调用取得——该处共 9 个实参，形状符合 `RegCreateKeyExA`，`call` 为寄存器间接 `call edi`，未在 IAT 扫描中显名）。

**结论**：`push imm32` 扫描天然看不见这类站点——这就是"还有第二个未知写入点"这一直觉的**真正来源**。但它的**值来源无法静态确定**（无静态赋值、无立即数），列入 §9 残余未知。

> 顺带排除一个假阳性：全文件 ASCII `"MData"` 有 2 处，第二处在 `.data` VA `0x78204F`——它是 C++ RTTI 名字 `.?AVCIDMDatabase@@` 里的 `MData` 子串（`CIDMDatabase`），**不是**第二份 `MData` 字符串。

### 2.4 候选 (c) 死数据 —— 否定

19 处 `push 0x69D1E4` 全部紧跟 `RegSetValueExA` / `RegQueryValueExA` / `RegDeleteValueA`（§5 表），不存在无引用的死字符串。

---

## 3. Q2 — `.reloc` 核查

```
reloc 目录: RVA 0x5BD000  size 0x2E968
总条目 92224 = type3 (IMAGE_REL_BASED_HIGHLOW) 91829 + type0 (IMAGE_REL_BASED_ABSOLUTE/padding) 395
```

- **`0x69D184..0x69D1F4` 区间内 0 条重定位** —— 这是**正确且预期**的：`.reloc` 记录的是"**哪个位置存放了一个需要基址修正的地址**"，而不是"哪个地址被引用"。`.rdata` 字符串本身不是被修正的对象。
- **真正有判别力的检查**：19 个 `push imm32` 站点的**立即数字段**（`push@VA + 1`）是否各自有一条 type3 重定位。实测 **19/19 全部 YES**：

```
push@VA      funcStart    call@VA      reloc  API
0x0042F03A   0x0042E220   0x0042F043   YES    ADVAPI32.dll!RegDeleteValueA
0x0042F0D6   0x0042E220   0x0042F0DF   YES    ADVAPI32.dll!RegDeleteValueA
0x0044D9FB   0x0044CCB0   0x0044DA04   YES    (寄存器间接调用 RegQueryValueExA)
0x0044DEAB   0x0044CCB0   0x0044DEB4   YES    ADVAPI32.dll!RegSetValueExA
0x00466862   0x004666F0   0x00466871   YES
0x00466987   0x004666F0   0x00466996   YES
0x00466CF1   0x004666F0   0x00466CFA   YES    ADVAPI32.dll!RegDeleteValueA
0x00466D96   0x004666F0   0x00466D9F   YES    ADVAPI32.dll!RegDeleteValueA
0x004671FF   0x00466EE0   0x0046720E   YES
0x004676D0   0x00466EE0   0x004676D9   YES    ADVAPI32.dll!RegSetValueExA   <-- 写入 W2
0x00468174   0x00467F90   0x0046817D   YES    ADVAPI32.dll!RegDeleteValueA
0x0046820E   0x00467F90   0x00468217   YES    ADVAPI32.dll!RegDeleteValueA
0x00521585   0x00521050   0x00521594   YES
0x00521633   0x00521050   0x00521654   YES    ADVAPI32.dll!RegSetValueExA   <-- 写入 W3a
0x0052164B   0x00521050   0x00521654   YES    ADVAPI32.dll!RegSetValueExA   <-- 写入 W3b
0x00523282   0x00522910   0x00523291   YES
0x00523336   0x00522910   0x0052333F   YES
0x005233D9   0x00522910   0x005233E2   YES
0x00523497   0x00522910   0x005234A0   YES
```

**这是对 Q1 结论的最强旁证**：在一个 DYNAMICBASE 镜像里，`push offset str` 会生成 `68 imm32` 且在 imm32 处留下 HIGHLOW 重定位。19/19 命中说明这些确实是编译期就存在的绝对地址引用，代码明文、未被加密。

（补充：`.rdata`/`.data` 中 `0x78A720`、`0x789AE8` 等 BSS 描述符块内也 0 条重定位，印证它们是运行时填充的 BSS。）

---

## 4. Q3 — `0x44DE52` 所在函数（W1）

**函数体**：`.text` VA `0x44CCB0`（含 `0x44D9FB` 读点与 `0x44DEAB` 写点）。
**P4 补丁点**：VA `0x44DE52` / file `0x4D252`，原字节 `8B 0D 2C A7 78 00`。

### 4.1 分支结构（原版）

```asm
0x0044DE25  lea   edx, [eax + 1]
0x0044DE28  mov   cl, byte ptr [eax]          ; strlen 循环
0x0044DE2A  inc   eax
0x0044DE2B  test  cl, cl
0x0044DE2D  jne   0x44de28
0x0044DE2F  sub   eax, edx
0x0044DE31  cmp   eax, 0x17                   ; 长度必须 == 0x17 (23)
0x0044DE34  jne   0x44de52                    ; ┐
0x0044DE36  cmp   byte ptr [ebp + 0x831], bl  ; │ 三个字段必须为 0
0x0044DE3C  jne   0x44de52                    ; │ 否则落到 counterfeit 块
0x0044DE3E  cmp   byte ptr [ebp + 0x837], bl  ; │
0x0044DE44  jne   0x44de52                    ; │
0x0044DE46  cmp   byte ptr [ebp + 0x83d], bl  ; │
0x0044DE4C  je    0x44db10                    ; ┘ 全 0 → 跳过（正常路径）
; ---------------- counterfeit 块 ----------------
0x0044DE52  mov   ecx, dword ptr [0x78a72c]   ; <-- P4 补丁点（原 6 字节）
0x0044DE58  lea   edx, [ebp + 0x63c]
0x0044DE60  mov   al, byte ptr [ecx]          ; strcpy(dest, [0x78A72C])
0x0044DE62  mov   byte ptr [edx], al
...
0x0044DE6A  mov   edx, dword ptr [0x789af0]   ; 第二段载荷
0x0044DE7E  push  eax                         ; strlen([0x789AF0])
0x0044DE7F  push  edx
0x0044DE80  push  0x100
0x0044DE85  lea   eax, [ebp + 0x63c]
0x0044DE8B  push  eax
0x0044DE8C  call  0x445560                   ; 载荷构造/混淆
0x0044DE9B  push  0x100
0x0044DEA0  lea   ecx, [ebp + 0x63c]
0x0044DEA6  push  ecx
0x0044DEA7  push  0
0x0044DEA9  push  0
0x0044DEAB  push  0x69d1e4                   ; ★ 值名 "MData"
0x0044DEB0  mov   edx, [ebp - 0x14]           ; hKey
0x0044DEB3  push  edx
0x0044DEB4  call  dword ptr [0x695090]        ; ★ RegSetValueExA
0x0044DEBA  mov   eax, [ebp - 0x14]
0x0044DEBD  push  eax
0x0044DEBE  call  dword ptr [0x69505c]        ; ★ RegFlushKey
0x0044DED4  push  0
0x0044DED6  call  dword ptr [0x6954e8]        ; ★ KERNEL32!ExitProcess(0)
```

**值名参数的产生方式**：编译期常量，直接 `push imm32 = 0x69D1E4`（即 `.rdata` 里的 `"MData"`），无任何运行时拼接。
**调用点 VA**：`RegSetValueExA` @ **`0x44DEB4`**；值名压栈 @ **`0x44DEAB`**。

### 4.2 P4 补丁语义

线上二进制 `0x44DE52` = `E9 B9 FC FF FF 90` → `jmp 0x44DE52+5-0x347 = 0x44DB10`，即跳到 `0x44DE4C` 那条"正常路径"的同一目标，**完整跳过 W1 的写入 + ExitProcess**。方向正确、语义等价于原版 `je 0x44db10`。

---

## 5. Q4 — `m::OnTimer()` 的真正归属 + 全文件补丁态

### 5.1 字符串是"尾巴"，类名是 `CConfirm`

```
VA 0x0069D140  file 0x29B740
0069D160  74 65 2e 63 67 69 00 00  55 6e 6b 6e 6f 77 6e 20   te.cgi..Unknown
0069D170  65 72 72 6f 72 20 64 75  72 69 6e 67 20 43 43 6f   error during CCo
0069D180  6e 66 69 72 6d 3a 3a 4f 6e  54 69 6d 65 72 28 29   nfirm::OnTimer()
0069D190  0a 00 00 00 43 55 52 52  45 4e 54 5f 55 53 45 52   ....CURRENT_USER
0069D1A0  5c 25 73 00 53 6f 66 74  77 61 72 65 5c 43 6c 61   \%s.Software\Cla
```

任务书里的 `m::OnTimer()\n`（VA `0x29D184`）是 **`"Unknown error during CConfirm::OnTimer()\n"` 的尾部**。完整串起始 **VA `0x69D168`**（file `0x29B768`），全文件**唯一 1 处引用**：

```asm
0x0042F1A8  push  1
0x0042F1AA  push  0x69d168                  ; "Unknown error during CConfirm::OnTimer()\n"
0x0042F1AF  lea   ecx, [ebp]
0x0042F1B2  call  0x4c4d00                  ; CString::Format
0x0042F1BB  lea   ecx, [ebp]
0x0042F1BE  call  0x4c4cf0                  ; 日志输出
0x0042F1CA  mov   eax, 0x42eccf
0x0042F1CF  ret
```

### 5.2 消息映射证明它是真 timer

在 `.rdata` 扫到该 dialog 的 `AFX_MSGMAP_ENTRY`（24 字节/项）：

```
VA 0x0069D2A8  24-aligned  nMessage=0x0111 WM_COMMAND  nID=0x48A  nSig=0x39  pfn=0x0042E220
VA 0x0069D2C0  24-aligned  nMessage=0x0111 WM_COMMAND             nSig=0x39  pfn=0x0042DE70
VA 0x0069D2D8  24-aligned  nMessage=0x0113 WM_TIMER               nSig=0x14  pfn=0x0042E9A0   ★
```

配套的 `SetTimer` 调用（同一处理体区域内）：`0x42E92A`、`0x42EA31`、`0x42EB7D`、`0x42ED5A`。

> 说明：`func_start`（CC 填充回溯）对 `0x42F03A` 报 `0x42E220`，是因为 `WM_COMMAND` 处理体与 `WM_TIMER` 处理体相邻、之间不足 2 字节 `CC` 填充。**WM_TIMER 的真实入口是 `0x42E9A0`**；`0x42F03A`/`0x42F0D6`/`0x42F1AA` 都落在 `0x42E9A0 .. 0x42F1D0` 这一段处理体内。这是启发式局限，不是结论差异。

### 5.3 timer 路径对 `MData` 做什么 —— 只删，不写

```
0x0042F053  lea   ecx, [ebp - 0x14]
0x0042F057  push  0xf003f                    ; KEY_ALL_ACCESS
0x0042F05E  push  0x69d1a4                   ; "Software\Classes\CLSID\{E6871B76-…}"
0x0042F063  push  0x80000001                 ; HKEY_LOCAL_MACHINE
0x0042F068  call  ebx                        ; RegOpenKeyExA
0x0042F071  je    0x42f0d6                   ; 成功 → 走第二处删除
0x0042F03A  push  0x69d1e4                   ; ★ "MData"
0x0042F043  call  dword ptr [0x695094]       ; ★ RegDeleteValueA  (HKLM 视图)
0x0042F089  push  0x69d194                   ; "CURRENT_USER\%s"
0x0042F092  call  0x402f20                   ; CString::Format → "CURRENT_USER\Software\Classes\CLSID\{…}"
0x0042F0D6  push  0x69d1e4                   ; ★ "MData"
0x0042F0DF  call  dword ptr [0x695094]       ; ★ RegDeleteValueA  (CURRENT_USER 视图)
```

`CConfirm::OnTimer` 的 `MData` 操作**只有删除**（`0x42F03A`、`0x42F0D6`）。
**因此：`MData` 的写入不在 `CConfirm` 的 timer 路径里。timer 路径反而是官方清理路径。**

### 5.4 线上二进制 vs 原版：全文件 diff（只有 4 段）

```
file 0x04D252..0x04D258 (6)  VA 0x0044DE52   orig: 8b 0d 2c a7 78 00   live: e9 b9 fc ff ff 90   <- P4 counterfeit 闸门
file 0x07C8D0..0x07C8D4 (4)  VA 0x0047D4D0   orig: a1 24 a9 78 00      live: e9 38 00 00 00      <- 试用弹窗 neutralized
file 0x29545E..0x295462 (4)  VA 0x00696E5E   orig: 25 59 00 00         live: 39 39 39 39         <- .rdata 文本改写（"9999"）
file 0x379524..0x379525 (1)  VA 0x0077BD24   orig: 01                  live: 00                  <- g_registered 初始化器 1→0
```

**`0x4676D0`(W2)、`0x521633`/`0x52164B`(W3) 在线上二进制里保持原样 —— 未被封堵。**

---

## 6. 判定：benign 周期值 vs counterfeit 标记

### 判定：**COUNTERFEIT / 封禁负向标记**（handover 的判断成立，任务书的"benign timer 假设"不成立）

| # | 证据 | 反证力 |
| --- | --- | --- |
| 1 | W1/W2 写入后 20 字节内即 `RegFlushKey` → **`ExitProcess(0)`**（`0x44DED6` / `0x4676FB`）。 | 良性心跳**不可能**杀进程。这是"标记并终结"的 tripwire 特征。 |
| 2 | W3 所在 worker `0x521050` 在 verdict 码 `EBX ∈ {1,2,7,0xA,0xC}` 时 `push 0; call ExitProcess`（`0x52177A`/`0x52177C`）。 | 同上；且这些码与 §5 消息派发器的 kind（2/3/4/7/0xc/10）同族。 |
| 3 | 三处写入点写入的是**同一个派生载荷**：`strcpy(buf,[0x78A72C])` 后 `FUN_00445560(buf,0x100,[0x789AF0],strlen([0x789AF0]))`。三处构造完全一致。 | 良性周期值/心跳**每拍必须变化**（计数/时间戳）；常量载荷只能是"判决令牌"。 |
| 4 | `CConfirm::OnTimer`（官方 timer 路径）**删除** `MData`（`0x42F03A`/`0x42F0D6`），"正常"分支同样删除（`0x466CF1`/`0x466D96`、`0x468174`/`0x46820E`）。 | 程序把 `MData` 当作"需要被清掉的负向标记"，而非"需要维护的良性状态"。 |
| 5 | 写 `MData` 的分支同时 `RegDeleteValueA("Version")` / `("Version32")`（`0x521608`-`0x521624`）。 | 反篡改"抹除痕迹"动作，非心跳。 |
| 6 | 5 个 GUID 键之一 `{07999AC3-058B-40BF-984F-69EB1E554CA7}` 读取返回 WinError 5（ACL 保护）。 | 受保护键 = tripwire 键的典型做法。 |

**关于"每 ~2 分钟复发"**

- 守护自己的节拍是 **30 分钟**（`IDM-Activator.py:533` `schtasks /SC MINUTE /MO 30`），**不是 2 分钟**，所以复发不是守护轮询本身。
- 静态上，**唯一不必然终结进程的写入者是 W3（函数 `0x521050`）**：它在写完 `MData` 后**自我重挂**——
  ```asm
  0x0052168F  push  esi
  0x00521690  call  0x521050                 ; 直接自递归
  ...
  0x005216A1  push 0 / push 0 / push 0 / push 0 / push esi / push 0x521050
  0x005216AF  call  0x61c55e                 ; 6 参数、最后压入 0x521050 为线程函数
                                              ; → 疑似 AfxBeginThread(pfn=0x521050, pParam=esi, 0,0,0,0)
                                              ;   （0x61c55e 本体未反编译，属推断，非直证）
  ```
  > 推断依据：6 个实参 + 末压入者为函数指针，与 MFC `AfxBeginThread(pfnThreadProc, pParam,
  > nPriority, nStackSize, dwCreateFlags, lpSecurityAttrs)` 的调用约定一致。若需直证，
  > 反编译 `0x61c55e` 看它是否转调 `_beginthreadex`/`CreateThread`。
  同一模式在 `0x52187F` 再次出现。`0x521820` 是它的 `AfxBeginThread` 包装，被 `0x456D30`(→`0x456F77`) 与 `0x522910`(→`0x523917`) 调用。
  → **W3 是一个自我重挂的后台注册校验 worker，是"周期性复发"的头号嫌疑。**
- 但静态层面**没有定位到精确的 2 分钟节拍**（该函数范围内无 `Sleep`/`WaitForSingleObject`）。见 §9。

**对"自伤"问题的回答**：任务书设想的"若 `MData` 是 timer 写的良性值，则守护删它是自伤"这一情形**不成立**——`MData` 确实是负向标记。但**自伤依然存在，只是机制不同**：守护 `run_guard()` 一见 `MData` 就 `purge_fake_serial()` + **轮换序列号**（`IDM-Activator.py:579-592`），而 IDM 正是判定"当前序列号假冒"才写 `MData`——**轮换 → 新序列号仍被判假冒 → 再写 `MData` → 再轮换**，闭环由守护驱动。**正确修法是改守护的判定/处置策略（例如：不再因 `MData` 轮换序列号，改为一次性清理 + 报警），而不是继续给 IDM 加补丁。**

---

## 7. Hook 决策证据卡（每个候选写入点）

### 卡片 W1 —— `0x44DEAB`（P4 已封堵）

```
[Hook 决策证据卡]
- 目标定位: .text -> VA 0x0044DEAB (file 0x04D2AB)  encloses function start VA 0x0044CCB0
- 反汇编证据:
    0x0044DE9B  push  0x100
    0x0044DEA0  lea   ecx, [ebp + 0x63c]
    0x0044DEA6  push  ecx
    0x0044DEA7  push  0                        ; Reserved
    0x0044DEA9  push  0                        ; dwType = REG_NONE
    0x0044DEAB  push  0x69d1e4                 ; lpValueName = "MData"      <-- 目标
    0x0044DEB0  mov   edx, [ebp - 0x14]
    0x0044DEB3  push  edx                      ; hKey
    0x0044DEB4  call  dword ptr [0x695090]     ; RegSetValueExA
    0x0044DEBA  mov   eax, [ebp - 0x14]
    0x0044DEBD  push  eax
    0x0044DEBE  call  dword ptr [0x69505c]     ; RegFlushKey
    0x0044DED4  push  0
    0x0044DED6  call  dword ptr [0x6954e8]     ; ExitProcess(0)   <-- 终端
  原始字节: 68 e4 d1 69 00 (push 0x69D1E4)，该立即数字段带 type3 重定位。
- 调用方分支验证:
  上游是本函数内的"校验失败"合流点 0x44DE52，由 0x44DE34/0x44DE3C/0x44DE44 三条
  jne 汇聚而来；正常路径在 0x44DE4C `je 0x44db10` 分流。函数 0x44CCB0 的直接调用者：
  0x452F89(函数 0x451E30)、0x453221、0x453256。
  调用方不需要返回值做空指针检查——该分支以 ExitProcess 结束，不返回；
  因此把它整体跳过（P4 的 jmp 0x44DB10）不会引发 NPE，也不会误伤其它功能：
  0x44DB10 正是原版 `je 0x44db10` 的落点。
- 抗混淆锚点:
  值名串: .rdata "MData"（按内容重定位，b8→b15 段基址已漂移 0x1000）
  指令形状: 6A 00 6A 00 68 E4 D1 69 00 8B 55 EC 52 FF 15 ?? ?? ?? ??
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (push 0; push 0; push "MData")
  终结锚点: 后续 20 字节内出现 RegFlushKey + ExitProcess 组合
```

### 卡片 W2 —— `0x4676D0`（**线上未封堵**）

```
[Hook 决策证据卡]
- 目标定位: .text -> VA 0x004676D0 (file 0x066AD0)  encloses function start VA 0x00466EE0
- 反汇编证据:
    0x004676C3  push  0x100
    0x004676C8  lea   eax, [ebp]
    0x004676CB  push  eax
    0x004676CC  push  0
    0x004676CE  push  0
    0x004676D0  push  0x69d1e4                 ; "MData"                    <-- 目标
    0x004676D5  mov   ecx, [ebp - 0x14]
    0x004676D8  push  ecx
    0x004676D9  call  dword ptr [0x695090]     ; RegSetValueExA
    0x004676E2  push  edx
    0x004676E3  call  dword ptr [0x69505c]     ; RegFlushKey
    0x004676F9  push  0
    0x004676FB  call  dword ptr [0x6954e8]     ; ExitProcess(0)   <-- 终端
  载荷构造与 W1 逐指令同构: 先 strcpy 自 [0x78A72C]，再 FUN_00445560(buf,0x100,[0x789AF0],len)。
- 调用方分支验证:
  函数 0x466EE0 的直接 E8 调用者 = 0（不是 MFC 消息映射项：在 0x6A51C0 处的匹配
  不是 24 字节对齐的 AFX_MSGMAP_ENTRY，属于普通数据指针/vtable）。
  即它是**经函数指针/vtable 间接调用**的，无法用静态直接调用图确定调用方。
  → 拦截方式建议与 W1 相同（把 0x4676C3 起的整块跳到紧随 ExitProcess 之后），
    因为该块同样以 ExitProcess 结束、不返回，跳过不会引发 NPE。
  风险: 未定位调用方，需动态确认是否会命中正常注册流程。
- 抗混淆锚点:
  指令形状: 6A 00 6A 00 68 E4 D1 69 00 8B 4D EC 51 FF 15 90 50 69 00
  终结锚点: RegFlushKey + ExitProcess
  函数序言: 0x466EE0 起点（CC 填充回溯确认）
```

### 卡片 W3a/W3b —— `0x521633` / `0x52164B`（**线上未封堵，周期性复发头号嫌疑**）

```
[Hook 决策证据卡]
- 目标定位: .text -> VA 0x00521633 (file 0x120A33) 与 VA 0x0052164B (file 0x120A4B)
            encloses function start VA 0x00521050
- 反汇编证据（两个 case 合流到同一个 RegSetValueExA）:
    0x00521626  push  0x100
    0x0052162B  lea   edx, [ebp]
    0x0052162E  push  edx
    0x0052162F  push  0
    0x00521631  push  0
    0x00521633  push  0x69d1e4                 ; "MData"                    <-- 目标 A
    0x00521638  mov   eax, [ebp - 0x14]
    0x0052163B  push  eax
    0x0052163C  jmp   0x521654
    0x0052163E  push  0x100
    0x00521643  lea   ecx, [ebp]
    0x00521646  push  ecx
    0x00521647  push  0
    0x00521649  push  0
    0x0052164B  push  0x69d1e4                 ; "MData"                    <-- 目标 B
    0x00521650  mov   edx, [ebp - 0x14]
    0x00521653  push  edx
    0x00521654  call  dword ptr [0x695090]     ; RegSetValueExA
- 调用方分支验证:
  同一函数的"正常"分支（0x521608..0x521624）改为 RegDeleteValueA("Version") /
  ("Version32") 后 jmp 0x52165A —— 即 MData 写入是"失败/假冒"分支。
  写完后 0x52168F 自递归 / 0x5216AF AfxBeginThread(0x521050,…) 自我重挂（周期性来源）。
  ExitProcess 在 0x52177C，由 EBX ∈ {1,2,7,0xA,0xC} 触发（0x521761..0x521778）。
  → 该 worker 以线程方式运行，不返回给调用者；跳过 MData 写入块不会引发 NPE。
  风险: 它是线程入口，Hook 需在 RegSetValueExA 层做**值名过滤**（name == "MData" 时
        跳过调用并返回 ERROR_SUCCESS），比改代码分支更安全。
- 抗混淆锚点:
  指令形状: 6A 00 6A 00 68 E4 D1 69 00 (两处)
  分支锚点: 相邻的 68 88 2D 6A 00 ("Version") / 68 7C 2D 6A 00 ("Version32") + RegDeleteValueA
  线程锚点: 0x5216AF / 0x52187F 处的 AfxBeginThread(0x521050, …)
```

### 卡片 W4（间接类）—— `0x5214B7`，值名来自 BSS CString `0x78A730`

```
[Hook 决策证据卡]
- 目标定位: .text -> VA 0x005214B7 (file 0x1208B7)  encloses function start VA 0x00521050
- 反汇编证据:
    0x005214A3  6a 00                 push  0            ; dwType
    0x005214A5  6a 00                 push  0            ; Reserved
    0x005214A7  a1 30 a7 78 00        mov   eax, dword ptr [0x78A730]   <-- 值名来自 BSS 全局
    0x005214AC  50                    push  eax
    0x005214AD  8b 4d ec              mov   ecx, [ebp - 0x14]           ; hKey
    0x005214B0  51                    push  ecx
    0x005214B1  8b 3d 90 50 69 00     mov   edi, dword ptr [0x695090]   ; RegSetValueExA
    0x005214B7  ff d7                 call  edi
  （原始字节 file 0x1208A7: A1 30 A7 78 00 50 8B 4D EC 51 8B 3D 90 50 69 00 FF D7）
- 调用方分支验证:
  同卡片 W3（同属函数 0x521050）。**但值名无法静态确定**：
  0x78A730 位于 .data BSS（RVA 0x38A730 > .data rawsize 0xA400，静态全 0），
  20 处引用中 17 处为 LOAD、0 处为 STORE，另 2 处为 `mov ecx,0x78A730`（取地址，
  0x68EA80 处配 CString 构造 0x4024F0 + atexit 0x64007E；0x693730 处为析构 thunk）。
  → 该值名由运行时经"地址传递"的路径赋值，静态不可达。
  它被用在同一个 {E6871B76-…} 键上（0x450D55 RegQueryValueExA(hk,[0x78A730],…)，
  hk 来自 0x450D75..0x450D92 处对 HKLM(0x80000001) + "Software\Classes\CLSID\{E6871B76-…}"
  的 9 实参 Reg*Key* 调用（形状符合 RegCreateKeyExA，call 为寄存器间接）。
  **在确认它是否等于 "MData" 之前，禁止对它下 Hook。**
- 抗混淆锚点:
  指令形状: A1 30 A7 78 00 50 8B 4D EC 51 8B 3D 90 50 69 00 FF D7
  全局锚点: BSS CString 0x78A730；其取地址点 0x68EA80 / 0x693730
  关联键锚点: 0x69D1A4 "Software\Classes\CLSID\{E6871B76-…}"
```

### 其它相关点（读取/删除，非写入）

| 类别 | VA | 函数 | API |
| --- | --- | --- | --- |
| 读取 | `0x44D9FB` | `0x44CCB0` | `RegQueryValueExA`（寄存器间接，`mov esi,[0x695004]` 后 `call esi`） |
| 读取 | `0x466862`、`0x466987` | `0x4666F0` | 寄存器间接 |
| 读取 | `0x4671FF` | `0x466EE0` | 寄存器间接 |
| 读取 | `0x521585` | `0x521050` | 寄存器间接 |
| 读取 | `0x523282`、`0x523336`、`0x5233D9`、`0x523497` | `0x522910`（WM_COMMAND nID 0x4A7 → 0x522910，映射项 @VA 0x6C3E70） | 寄存器间接 |
| 删除 | `0x42F03A`、`0x42F0D6` | `0x42E9A0`（CConfirm WM_TIMER） | `RegDeleteValueA` |
| 删除 | `0x466CF1`、`0x466D96` | `0x4666F0` | `RegDeleteValueA` |
| 删除 | `0x468174`、`0x46820E` | `0x467F90` | `RegDeleteValueA` |

---

## 8. 抗混淆锚点规范（供未来版本重定位）

**段基址会漂移，锚点必须用"字符串内容 + 指令形状"，不要硬编码 VA。**

b8 → b15 实测漂移：`.rdata` VA `0x294000` → `0x295000`（+0x1000），`.text` 与 `.data` 亦不同。

| 锚点 | 内容 | 用法 |
| --- | --- | --- |
| A1 | ASCII `"MData"`（.rdata，紧跟 `"Software\Classes\CLSID\{E6871B76-…}"`） | 全文件搜 ASCII，取其 VA 记为 `S`；`push S` 的立即数字节即 `68 <S_LE 4B>` |
| A2 | ASCII `"Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}"` | 键路径锚点 |
| A3 | ASCII `"Unknown error during CConfirm::OnTimer()\n"` | 定位 `CConfirm` timer 处理体（`0x42E9A0` 一带） |
| A4 | 写入形状 `6A 00 6A 00 68 <S_LE>` | 匹配全部 `RegSetValueExA(hk,"MData",0,REG_NONE,…)` 写入点 |
| A5 | 终结形状 `… 68 <S_LE> … FF 15 <IAT> … FF 15 <IAT> … 6A 00 FF 15 <IAT>` 后接 `ExitProcess` | 识别 tripwire 写入点 |
| A6 | 删除形状 `68 <S_LE> … FF 15 94 50 69 00`（`0x695094` = RegDeleteValueA 槽） | 识别清理点 |
| A7 | MFC 消息映射项 `nMessage=0x0113 (WM_TIMER)` 的 24 字节对齐项 | 定位 timer 处理入口 |
| A8 | 线程重挂形状 `6A 00 6A 00 6A 00 6A 00 56 68 <pfn_LE> FF 15 …`（AfxBeginThread） | 识别自我重挂 worker |

> ⚠️ IAT 槽位（如 `0x695090`）**不是**稳定锚点（跨构建会变），只能用于本版本内的交叉验证。

---

## 9. 残余未知 + 建议的动态探针

| # | 未知 | 为什么静态解决不了 | 探针 |
| --- | --- | --- | --- |
| U1 | `MData` 复发的**精确 ~2 分钟节拍**由谁驱动 | 函数 `0x521050` 范围内无 `Sleep`/`WaitForSingleObject`；重挂是自递归/AfxBeginThread，节拍可能在网络请求超时或调用方 `0x456D30`/`0x522910` 中 | 在 IDM 进程内 Hook `ADVAPI32!RegSetValueExA`，当 `lpValueName == "MData"` 时 `XposedBridge.log(Log.getStackTraceString(new Throwable()))`（或 Frida `Thread.backtrace`），取真实调用栈 + 时间戳 |
| U2 | BSS CString `0x78A730` 的值是否就是 `"MData"` | 静态 0 处 STORE、无立即数；赋值走"地址传递"路径 | 动态：在 `0x450D55` 命中时 dump `[0x78A730]` 指向的字符串（前 32 字节）；或在 `RegQueryValueExA` 入口打印 `lpValueName` |
| U3 | 函数 `0x466EE0`（W2）的调用方 | 0 个直接 E8 调用者，经 vtable/函数指针间接调用 | 动态：在 `0x4676D0` 下断点，取调用栈 |
| U4 | 载荷 `[0x78A72C]` / `[0x789AF0]` 的运行时内容 | 两者均为 BSS（静态全 0） | 动态：在 `0x44DE8C`（`call 0x445560`）返回后 dump `[ebp+0x63c]`，比对是否等于当前序列号 |
| U5 | `0x521050` 的重挂节拍由 `[esi+0x514]` / `[esi+0x508]` / `[esi+0x50c]` 哪个成员控制 | 对象布局需运行时确定 | 动态：在 `0x52165A` 处 dump `esi+0x500..0x520` |

**所有探针都只读/只观测，不写注册表、不改 IDM。**

---

## 10. 复现命令

```powershell
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
cd "D:\pojie应用\jiesuo\work\idm-6.43b8\patches"

# 段表 / DYNAMICBASE / reloc 目录
& $py mdata_probe.py secs

# Q1: VA vs RVA（注意 19 vs 0）
& $py mdata_probe.py refs 0x69D1E4
& $py mdata_probe.py refs 0x29D1E4

# Q2: 重定位
& $py mdata_probe.py reloc 0x290000 0x2A0000
& $py mdata_sites.py classify --str MData --fwd 110      # 含 reloc 列

# Q3: 0x44DE52 所在函数
& $py mdata_sites.py func 0x44DE52
& $py mdata_sites.py dis 0x44DE20 176
& $py mdata_sites.py apiscan 0x44CCB0 0x44DF40

# Q4: CConfirm / 消息映射
& $py mdata_probe.py str 0x69D168
& $py mdata_sites.py msgmap 0x42E220
& $py mdata_sites.py apiscan 0x42E220 0x42F200

# 线上 vs 原版全文件 diff
& $py mdata_probe.py diff "C:\Program Files (x86)\Internet Download Manager\IDMan.exe"

# 调用图 / 线程重挂
& $py mdata_sites.py callers 0x521050 --depth 1
& $py mdata_sites.py dis 0x521650 128
```

新增工具（本次固化，均在 `patches/`）：

| 文件 | 用途 |
| --- | --- |
| `patches/mdata_probe.py` | 段表/DYNAMICBASE、VA↔RVA↔file、全文件 dword 扫描、`.reloc` 查询、hex/str、全文件 diff |
| `patches/mdata_sites.py` | 字符串引用点分类（含 reloc 列 + IAT 解析）、函数起点回溯、反汇编、调用者、MFC 消息映射解码、区间 API 扫描 |

> 两者都**硬编码指向 `IDMan.exe.bak-original`（b15）**，刻意不复用 `scripts/idm_util.py`（其 `BIN` 指向 b8 构建）。`scripts/` 下脚本**未做任何修改**。

---

## 附：`MData` 字符串表（b15，绝对 VA）

| VA | file | 内容 |
| --- | --- | --- |
| `0x69D168` | `0x29B768` | `"Unknown error during CConfirm::OnTimer()\n"` |
| `0x69D184` | `0x29B784` | （上式尾部 `"m::OnTimer()\n"`，任务书误当独立串） |
| `0x69D194` | `0x29B794` | `"CURRENT_USER\%s"` |
| `0x69D1A4` | `0x29B7A4` | `"Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}"` |
| `0x69D1E4` | `0x29B7E4` | `"MData"` |
| `0x69D1EC` | `0x29B7EC` | `"MACHINE"` |
| `0x69D1F4` | `0x29B7F4` | `"CURRENT_USER"` |
