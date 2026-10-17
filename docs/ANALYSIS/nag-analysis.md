# IDM 6.43 Build 8 —— 「试用/付费弹窗」触发链静态分析

**目标**：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（IDM 6.43 Build 8，x86 MSVC，ImageBase 0x400000）
**分析副本**：`work/idm-6.43b8/bin/IDMan.exe.orig`
**sha256**：`74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8`
**方法**：纯静态（PE 手工解析 + capstone 线性反汇编 + 跳转表/字节映射表解码 + Ghidra 12.1.2 headless 反编译）。**未启动 IDMan.exe**，未修改安装目录任何文件。

**地址换算（全文通用）**
- `.text`：`file_off = 0x400 + (VA - 0x401000)`　（`.text` raw=0x400 / VA=0x401000 / rawsize=0x292400）
- `.data`：`file_off = 0x377600 + (VA - 0x779000)`
- 所有字节均取自 `IDMan.exe.orig` 原始副本。

---

## 0. 结论速览

弹窗本体 `FUN_0047D2C0`（"This is 30 day trial version of Internet Download Manager. Do you want to register your copy of IDM now?"）**不是**被下载流程直接调用的。它是一条 **「下载编号分配 → WM_COMMAND 0x14D8 → SetTimer(0x2D, 90000ms) → WM_TIMER 0x2D → WM_COMMAND 0x14D7 → 弹窗」** 的四跳延迟链，并且整条链的**唯一入口门控就是 `[0x779CDC]`**：

```
FUN_005BD440 @0x5BD440  (下载编号分配器)
    ...
0x5BD4EA  cmp dword ptr [0x779CDC], 0     ; 83 3D DC 9C 77 00 00
0x5BD4F1  je  0x5BD510                    ; 74 1D     <== 门控：非 Trial 直接跳过
0x5BD4F3  test cl, cl
0x5BD4F5  je  0x5BD510
0x5BD4FF  push 0x14D8                     ; 68 D8 14 00 00   <== 全镜像唯一一处
0x5BD504  push 0x111                      ; WM_COMMAND
0x5BD509  push dword ptr [0x7873B0]       ; g_hMainWnd
0x5BD50A  call dword ptr [0x6947C8]       ; PostMessageA
        ↓  (WM_COMMAND 0x14D8)
FUN_0048F5D0 (CDownloaderDlg vtable slot 60) case 0x14D8 @0x49402D
0x49402D  push 0        ; lpTimerFunc
0x49402F  push 0x15F90  ; uElapse = 90000 ms
0x494034  push 0x2D     ; nIDEvent
0x494036  mov ecx, esi
0x494038  call 0x423E90 ; SetTimer(this->m_hWnd, 0x2D, 90000, NULL)
0x494045  mov byte ptr [esi+0x292], 1
        ↓  (90 秒后 WM_TIMER, nIDEvent=0x2D)
FUN_00486990 (CDownloaderDlg::OnTimer) case 0x2D @0x487733
0x487733  KillTimer(hwnd, 0x2D)
0x48773F  mov byte ptr [esi+0x292], 0
0x487764  RegQueryValueExA(hKey, "Therad", ...)
0x48786A  mov eax, [0x779CE0] ; 试用天数阈值（Trial=30 / Registered=15）
0x48786A..0x487873  if (Therad < [0x779CE0]) PostMessageA(hwnd,0x111,0x13CA,[0x779CE0]-Therad)
0x4878A1  push 0                  ; lParam
0x4878A3  push 0x14D7             ; wParam  <== 全镜像唯一一处
0x4878A8  push 0x111              ; WM_COMMAND
0x4878AD  mov edx, [esi+0x20]     ; hwnd
0x4878B1  call dword ptr [0x6947C8]; PostMessageA
        ↓  (WM_COMMAND 0x14D7)
FUN_0048F5D0 case 0x14D7 @0x494138
0x494138  push 0 / push 0 / push 0 / push 0 / push 0
0x494142  push 0x47D2C0           ; 弹窗函数指针
0x494147  call 0x61B695
        ↓
FUN_0047D2C0  →  30 天试用登记弹窗
```

**核心结论**：部署补丁①把 `[0x779CDC]` 的 `.data` 初始化器改成 0 之后，`0x5BD4F1 je 0x5BD510` **必然跳转**，`PostMessageA(...,0x14D8,0)` 永不执行 ⇒ 定时器 0x2D 永不建立 ⇒ `PostMessageA(...,0x14D7,0)` 永不发出 ⇒ 弹窗分支永不可达。全镜像对 `[0x779CDC]` 只有两条写指令，且**两条都写 0**，没有任何代码能把它写回 1。

---

## 1. (a) 0x494138 所在 switch case 的命令 ID

### 1.1 定位函数边界（Ghidra 未识别的区域）

`0x494138` 所在的巨型函数 **Ghidra 未建函数**（`GhidraNear.java 0x494138` → `containing: NONE`，附近只有 `Catch@00493fcf`）。手工定位：

- `0x494152 jmp 0x49A3F1`，而 `0x49A3F1` 是**函数尾声**，不是分发器：
  ```
  0x0049A3F1  mov  ecx, dword ptr [ebp - 0xc]     ; 8B 4D F4
  0x0049A3F4  mov  dword ptr fs:[0], ecx
  0x0049A3FB  pop  ecx / pop edi / pop esi / pop ebx
  0x0049A3FF  mov  ecx, dword ptr [ebp + 0x221cc]
  0x0049A405  xor  ecx, ebp
  0x0049A407  call 0x63bbb0                        ; __security_check_cookie
  0x0049A40C  add  ebp, 0x221d0
  0x0049A412  mov  esp, ebp
  0x0049A414  pop  ebp
  0x0049A415  ret  8                               ; C2 08 00  ← 2 个栈参数
  ```
  所以每个 case 末尾的 `mov eax,1 ; wait ; jmp 0x49A3F1` 就是 **`return 1`**。
- 用「帧大小立即数 `0x221d0`」反查函数序言：`b8 d0 21 02 00`（`mov eax,0x221d0`）唯一命中 **VA 0x48F5D8**；其前 8 字节 `CC CC CC CC CC CC CC CC` 填充，函数入口为：
  ```
  0x0048F5D0  push ebp                    ; 55
  0x0048F5D1  lea  ebp, [esp - 0x221d0]  ; 8D AC 24 30 DE FD FF  (disp32 = 0xFFFDDE30 = -0x221D0)
  0x0048F5D8  mov  eax, 0x221d0          ; B8 D0 21 02 00
  0x0048F5DD  call 0x63d2e0               ; __alloca_probe
  0x0048F5E2  push -1 ; push 0x669a16     ; SEH
  ```
  ⇒ **函数 = `FUN_0048F5D0`，VA 0x48F5D0，帧 0x221D0，`ret 8`。**
- 签名推导：`push ebp` 后 `ebp = S-4-0x221D0`（S = 入口 esp），故 `[ebp+0x221D4]` = 返回地址，`[ebp+0x221D8]` = arg1，`[ebp+0x221DC]` = arg2。
  ```
  0x0048F613  mov  esi, ecx                 ; this
  0x0048F62A  mov  edx, dword ptr [ebp + 0x221d8]   ; edx = arg1 = 命令 ID
  0x0048F618  mov  ebx, dword ptr [ebp + 0x221dc]   ; ebx = arg2
  ```
  ⇒ `int __thiscall FUN_0048F5D0(this, int cmd, int param)`。

### 1.2 三级分发表

```
0x0048F630  cmp  edx, 3
0x0048F633  jb   0x48F706                    ; cmd < 3 → return 1
0x0048F639  lea  edi, [edx - 0x8049]
0x0048F63F  cmp  edi, 0x95
0x0048F645  ja   0x48F71E
   ...   ; [0x8049,0x80DE] 走另一条分支
0x0048F836  cmp  edx, 0x144d
0x0048F83C  ja   0x492076                    ; ← 0x14D7 / 0x14D8 走这里
0x0048F842  je   0x492012
0x0048F848  lea  eax, [edx - 0x1392]
0x0048F84E  cmp  eax, 0xb7
0x0048F853  ja   0x49A391                    ; default
0x0048F859  movzx eax, byte ptr [eax + 0x49a4c0]   ; 字节映射表 A
0x0048F860  jmp  dword ptr [eax*4 + 0x49a418]      ; 跳转表 A（42 项）
```
```
0x00492076  cmp  edx, 0x2721
0x0049207C  ja   0x49A389
0x00492082  je   0x49A35B
0x00492088  lea  eax, [edx - 0x144e]         ; ★ 0x14D7 → 0x89, 0x14D8 → 0x8A
0x0049208E  cmp  eax, 0xcf
0x00492093  ja   0x49A391                    ; default
0x00492099  movzx eax, byte ptr [eax + 0x49a750]   ; 字节映射表 C
0x004920A0  jmp  dword ptr [eax*4 + 0x49a598]      ; ★ 跳转表 C（110 项）
```

### 1.3 表 C 与字节映射 —— 命令 ID = **0x14D7 (5335)**

- 跳转表 C 基址 `0x49A598`，长度 `0x49A750 - 0x49A598 = 0x1B8` = **110 项**（index 0..109）。
- 表内 **唯一** 出现 `0x00494138` 的位置：
  ```
  0x0049A6B0 [70] = 0x00494138        ; (0x49A6B0 - 0x49A598)/4 = 70
  ```
- 字节映射表 `0x49A750`，索引 = `cmd - 0x144E`，208 字节（覆盖 `cmd ∈ [0x144E, 0x151D]`）。
  全表中值 `0x46`（=70）只出现一次：
  ```
  0x49A750[0x89] = 0x46      ⇒  cmd = 0x144E + 0x89 = 0x14D7
  ```
  映射表原始字节（节选）：
  ```
  0x49A750 +0x080 (cmd 0x14CE): 3D 3E 3F 40 41 42 43 44 45 46 47 6D 6D 48 6D 49
  ```
  `+0x89` 处 = `0x46`；`0x6D`(=109) 是 default 项（`0x49A74C` 即表 C 最后一项）。

⇒ **(a) 结论：`0x494138` 是命令 ID `0x14D7`（十进制 5335）的 case 体。**
旁证：紧邻的 `0x14D8`（cmd = `0x144E+0x8A`，映射值 `0x47`=71）指向 `0x49402D`，正是启动本链定时器的那条 case（见 §3.2）。

### 1.4 case body 原始字节与语义

```
VA 0x494138  bytes: 6A 00 6A 00 6A 00 6A 00 6A 00 68 C0 D2 47 00 E8 49 75 18 00 B8 01 00 00 00 9B E9 9A 62 00 00
```
```
0x00494138  push 0                ; 6A 00
0x0049413A  push 0                ; 6A 00
0x0049413C  push 0                ; 6A 00
0x0049413E  push 0                ; 6A 00
0x00494140  push 0                ; 6A 00
0x00494142  push 0x47D2C0         ; 68 C0 D2 47 00   ← 弹窗函数地址
0x00494147  call 0x61B695         ; E8 49 75 18 00
0x0049414C  mov  eax, 1           ; B8 01 00 00 00
0x00494151  wait                  ; 9B   （MSVC 内联汇编残留，无害）
0x00494152  jmp  0x49A3F1         ; E9 9A 62 00 00    → return 1
```
`0x61B695` 是 6 参数辅助函数（`ret 0x18` @0x61B709），其内部：
```
0x0061B6A1  push 0x44              ; 分配 0x44 字节对象
0x0061B6A3  call 0x60FFAA          ; operator new
0x0061B6B7  push [ebp+0xC] ; push [ebp+8] ; call 0x61B077   ; 以 (0x47D2C0, 0) 初始化
0x0061B6D1  or   eax, 4            ; 创建标志 4
0x0061B6D7  call 0x61B58A          ; Create/DoModal 类调用
```
即 `push 0x47D2C0` 传入的正是弹窗函数指针。全镜像中值 `0x0047D2C0` **只出现一次**（VA 0x494143，即上面 `push` 的立即数），所以 `0x494138` 是弹窗的**唯一调用点**。

### 1.5 这个函数是谁

- `0x48F5D0` 以 4 字节值出现在 `.rdata` **唯一一处**：`VA 0x006A1AEC`。
- 该处所属 vtable 起点 `0x6A19FC`，其 `vtable[-4] = 0x00735340` = MSVC RTTI CompleteObjectLocator：
  ```
  COL 0x735340: sig=0, offset=0, cdOffset=0, pType=0x0077A368, pClass=0x00735354, pSelf=0
  TypeDescriptor @0x77A368+8 = ".?AVCDownloaderDlg@@"
  ```
  ⇒ **vtable 属于 `CDownloaderDlg`**（IDM 主窗口类），`FUN_0048F5D0` 是 **slot 60**（`(0x6A1AEC-0x6A19FC)/4 = 60`，即 `[this+0xF0]`）。
- `CDownloaderDlg` 的 MFC 消息映射：vtable slot 10 = `0x0049BA00`（`jmp 0x49B9F0`）→
  ```
  0x0049B9F0  mov eax, 0x6A34A4      ; B8 A4 34 6A 00
  0x0049B9F5  ret                    ; = GetMessageMap()
  ```
  `AFX_MSGMAP @0x6A34A4 = { pBaseMap=0x00611D7F, pEntries=0x006A34B0 }`。
- **WM_COMMAND 路由**（MFC 框架，全 `.text` 中唯一一处 `[reg+0xF0]` 间接调用）：
  ```
  0x00616B78  mov  ebx, dword ptr [ebp + 8]     ; message
  0x00616B7E  cmp  ebx, 0x111                   ; WM_COMMAND
  0x00616B84  jne  0x616BA8
  0x00616B86  push dword ptr [ebp + 0x10]       ; lParam
  0x00616B89  mov  eax, dword ptr [edi]         ; vtable
  0x00616B8B  push dword ptr [ebp + 0xC]        ; wParam = 命令 ID
  0x00616B8E  call dword ptr [eax + 0xF0]       ; FF 90 F0 00 00 00  → CDownloaderDlg slot 60
  0x00616B94  test eax, eax
  0x00616B96  je   0x616D6E
  ```
  ⇒ **`WM_COMMAND(wParam = 命令 ID)` → `FUN_0048F5D0(wParam, lParam)`**，闭环成立。

---

## 2. (b) 谁发出该命令（0x14D7），触发条件是什么

### 2.1 全镜像唯一生产者：`FUN_00486990` 的 case 0x2D

值 `0x14D7` 在整个 `.text` 中作为立即数**只出现一次**：`VA 0x004878A4`。
`VA 0x4878A1` 所在函数 Ghidra 同样未识别，手工定位：
```
0x0048698F  ret                                ; 上一个函数结束
0x00486990  push ebp                           ; 55
0x00486991  lea  ebp, [esp - 0x64]             ; 8D 6C 24 9C
0x00486995  sub  esp, 0x64                     ; 83 EC 64
0x00486998  push -1 ; push 0x668EA6            ; SEH
0x004869A6  sub  esp, 0x128
0x004869C6  mov  esi, ecx                      ; this
0x004869C8  mov  dword ptr [ebp + 0x34], esi
0x004869CB  mov  eax, dword ptr [ebp + 0x6C]   ; 8B 45 6C   ← arg1（ret 地址在 ebp+0x68）
0x004869CE  dec  eax
0x004869CF  cmp  eax, 0x6E
0x004869D2  ja   0x488089                      ; default
0x004869D8  movzx eax, byte ptr [eax + 0x488154]; 字节映射表
0x004869DF  jmp  dword ptr [eax*4 + 0x4880B0]  ; 跳转表（41 项）
```
⇒ `FUN_00486990(this, arg1)`，`switch(arg1 - 1)`，`arg1 ∈ [1, 0x6F]`。

**case 归属**：
- 字节映射表 `0x488154`，索引 `arg1-1`；`0x488154[0x2C] = 0x21`（=33）⇒ 跳转表 `0x4880B0[33] = 0x00487733`。
- `arg1 = 0x2C + 1 = 0x2D`（45），case 体 `[0x487733, 0x487996)` 包含 `0x4878A1`。
- 自洽证据：case 体首指令就是 `KillTimer(hwnd, 0x2D)`：
  ```
  0x00487733  push 0x2D                    ; 6A 2D
  0x00487735  mov  ecx, dword ptr [esi + 0x20]
  0x00487738  push ecx
  0x00487739  call dword ptr [0x694788]    ; KillTimer
  ```

**该函数就是 `CDownloaderDlg::OnTimer`**（MFC 消息映射，`AFX_MSGMAP_ENTRY` @0x6A3A68，24 字节/项）：
```
0x6A3A68: nMessage = 0x00000113   ; WM_TIMER
0x6A3A6C: nCode    = 0
0x6A3A70: nID      = 0
0x6A3A74: nLastID  = 0
0x6A3A78: nSig     = 0x14
0x6A3A7C: pfn      = 0x00486990   ; ← FUN_00486990
```
⇒ **`arg1` = WM_TIMER 的 `nIDEvent`。**

### 2.2 case 0x2D 的完整反编译（Ghidra，`FUN_00486990`）

```c
case 0x2d:
    KillTimer(*(HWND *)(param_1 + 0x20), 0x2d);            // 0x487733
    param_1[0x292] = 0;                                    // 0x48773F
    pCStack_34 = (CWnd *)0x1;                              // 0x487746  [ebp+0x34] = 1
    FUN_0051f080();                                        // CString ctor
    LVar11 = RegOpenKeyExA((HKEY)((DAT_00786cd4 != '\0') + 0x80000001),
                           DAT_00788354 /*"Software\Classes\CLSID\{07999AC3-...}"*/,
                           0, 1 /*KEY_QUERY_VALUE*/, &pHStack_30);   // 0x48775C
    if (LVar11 == 0) {
LAB_00487843:
        tStack_18.bottom = 4;
        LVar11 = RegQueryValueExA(pHStack_30, "Therad", 0, 0,
                                  (LPBYTE)&puStack_3c, &tStack_18.bottom);   // 0x487764
        pCVar20 = pCStack_34;                              // = 1
        if ((LVar11 == 0) && (puStack_3c < DAT_00779ce0)) {
            PostMessageA(*(HWND *)(param_1 + 0x20), 0x111, 0x13ca,
                         (int)DAT_00779ce0 - (int)puStack_3c);           // 0x487886
            pCVar20 = (CWnd *)0x0;
        }
        RegCloseKey(pHStack_30);                           // 0x487897
        if (pCVar20 != (CWnd *)0x0) goto LAB_004878a1;
    } else {
        FUN_004024f0();
        FUN_00402f20(&pHStack_2c, "%s\\%s");               // "CURRENT_USER"/"MACHINE" + key
        ... 重试 RegOpenKeyExA ...
        if (LVar11 == 0) goto LAB_00487843;
LAB_004878a1:
        PostMessageA(*(HWND *)(param_1 + 0x20), 0x111, 0x14d7, 0);          // 0x4878A1
    }
    uStack_6c = 0xffffffff;
    FUN_0051f0e0();
    break;
```

对应的原始机器码（`0x4878A1` 起，`VA 0x4878A1` 是合法指令边界）：
```
VA 0x4878A1  bytes: 6A 00 68 D7 14 00 00 68 11 01 00 00 8B 56 20 52 FF 15 C8 47 69 00
0x004878A1  push 0                       ; lParam = 0
0x004878A3  push 0x14D7                  ; wParam = 命令 ID
0x004878A8  push 0x111                   ; WM_COMMAND
0x004878AD  mov  edx, dword ptr [esi + 0x20]   ; hwnd
0x004878B0  push edx
0x004878B1  call dword ptr [0x6947C8]    ; PostMessageA
```

### 2.3 触发条件（0x14D7 何时发出）

`0x14D7` 只在 `pCVar20 != 0`（即 `[ebp+0x34]` 仍为 1）时发出。综合两条路径，**发出 0x14D7 的充要条件是**：

> `RegOpenKeyExA` 最终失败（`LVar11 != 0`）
> **或** `RegQueryValueExA(hKey,"Therad") != 0`（值不存在 / 类型不符）
> **或** `Therad >= [0x779CE0]`

反之，若 `Therad` 可读且 `< [0x779CE0]`，则改发 `0x13CA`（携带 `[0x779CE0]-Therad` 作为 lParam），**不发 0x14D7**。

### 2.4 定时器 0x2D 由谁建立：`FUN_0048F5D0` 的 case 0x14D8

值 `0x14D8` 在整个 `.text` 中作为立即数**只出现一次**：`VA 0x005BD500`。

```
0x0049402D  push 0            ; 6A 00        lpTimerFunc
0x0049402F  push 0x15F90      ; 68 90 5F 01 00   uElapse = 90000 ms
0x00494034  push 0x2D         ; 6A 2D        nIDEvent
0x00494036  mov  ecx, esi     ; 8B CE
0x00494038  call 0x423E90     ; E8 53 FE F8 FF
0x0049403D  test eax, eax
0x0049403F  je   0x493603
0x00494045  mov  byte ptr [esi + 0x292], 1   ; C6 86 92 02 00 00 01
0x0049404C  mov  eax, 1
0x00494052  jmp  0x49A3F1     ; return 1
```
`FUN_00423E90` 是 `__thiscall` 的 SetTimer 包装（`ret 0xC`，3 参数）：
```
0x00423E90  mov  eax, dword ptr [esp + 0xC]     ; lpTimerFunc
0x00423E94  mov  edx, dword ptr [esp + 8]       ; uElapse
0x00423E98  mov  ecx, dword ptr [ecx + 0x20]    ; this->m_hWnd
0x00423E9B  push eax
0x00423EA0  push edx
0x00423EA1  push eax                            ; nIDEvent
0x00423EA2  push ecx
0x00423EA3  call dword ptr [0x69478C]           ; SetTimer
0x00423EA9  ret  0xC
```
⇒ **`SetTimer(hwnd, 0x2D, 90000, NULL)`。**

**定时器 0x2D 的唯一建立点**：全镜像 100 个 `SetTimer` 调用点中，nIDEvent 为立即数的取值集合为
`{1,2,3,4,5,0xC,0x14,0x16,0x19,0x1B,0x20,0x21,0x22,0x24,0x25,0x26,0x31}` ∪ `{寄存器}`；
**没有任何一处以 `0x2D` 为 nIDEvent**，且 7 处 `mov reg, 0x2D`（0x49B4C0 / 0x4D5592 / 0x5C1B28 / 0x5C4ACE / 0x5C88B0 / 0x5C8C22 / 0x5DE454）都不在 SetTimer 调用点附近。
⇒ 定时器 0x2D **只能**由 case 0x14D8 建立。

### 2.5 链条起点：谁发出 0x14D8 —— `FUN_005BD440`

```
0x005BD440  sub esp, 0x10 ; push ebx/ebp/esi/edi
...
0x005BD45C  push 0x6969DC                       ; 值名/类名
0x005BD463  push 0x6A904C  ; "Software\DownloadManager\maxID"
0x005BD468  push 0x80000001                     ; HKEY_CURRENT_USER
0x005BD46D  call dword ptr [0x69408C]           ; RegCreateKeyExA
0x005BD485  push 0x69F73C  ; "maxID"
0x005BD493  call dword ptr [0x694004]           ; RegQueryValueExA → [esp+0x10]
0x005BD499  test eax, eax ; je +2 : xor eax,eax  ; 失败则 0
0x005BD4A5  mov  edx, dword ptr [0x787374]      ; 全局最高 ID
0x005BD4AB  inc  eax                            ; id = maxID + 1
0x005BD4B2  cmp  edx, eax
0x005BD4B4  jbe  0x5BD4BF
0x005BD4B6  lea  eax, [edx + 1]                 ; id = global+1
0x005BD4B9  mov  cl, 1                          ; cl=1（计数器被抬高）
0x005BD4BF  mov  dword ptr [esi + 0x510], eax   ; this->newID
0x005BD4DC  mov  edi, 0x14                       ; 20
0x005BD4E1  idiv edi                             ; edx = id % 20
0x005BD4E3  cmp  edx, 7
0x005BD4E6  jne  0x5BD4EA
0x005BD4E8  mov  cl, 1                          ; cl=1（id % 20 == 7）
0x005BD4EA  cmp  dword ptr [0x779CDC], 0        ; ★★★ 门控
0x005BD4F1  je   0x5BD510                       ; 非 Trial → 直接跳过
0x005BD4F3  test cl, cl
0x005BD4F5  je   0x5BD510
0x005BD4F7  mov  edx, dword ptr [0x7873B0]      ; g_hMainWnd
0x005BD4FD  push 0
0x005BD4FF  push 0x14D8                          ; ★ 全镜像唯一
0x005BD504  push 0x111                           ; WM_COMMAND
0x005BD509  push edx
0x005BD50A  call dword ptr [0x6947C8]            ; PostMessageA
0x005BD510  ...
```
`FUN_005BD440` 的直接 `E8` 调用者共 11 处，全部落在 IDM 下载管理代码区（下载被创建/入队时）：
`0x478E3B, 0x478EBA, 0x4798A1, 0x479BAD, 0x482639, 0x48B8F6, 0x48BAB0, 0x48BF24, 0x48C807, 0x48CBE4, 0x5CE2F1`。

`0x7873B0` 被写入的唯一点是 `0x48D309-0x48D30C`：
```
0x0048D309  mov  edx, dword ptr [ebx + 0x20]    ; 8B 53 20
0x0048D30C  mov  dword ptr [0x7873B0], edx      ; 89 15 B0 73 78 00
```
即 `g_hMainWnd = this->m_hWnd`（MFC `CWnd::m_hWnd` 在 +0x20），与 `FUN_00486990` case 0x2D 使用的 `[esi+0x20]` 是同一个窗口。

### 2.6 完整触发链（一跳一证据）

| # | 位置 (VA) | 指令 / 字节 | 语义 |
|---|---|---|---|
| 1 | 0x5BD440 | `sub esp,0x10` + `E8`×11 调用者 | 下载创建 → 分配下载编号 |
| 2 | 0x5BD4EA | `83 3D DC 9C 77 00 00` | `cmp [0x779CDC], 0` |
| 3 | 0x5BD4F1 | `74 1D` | 非 Trial 跳过（门控） |
| 4 | 0x5BD4FF | `68 D8 14 00 00` | `push 0x14D8` |
| 5 | 0x5BD50A | `FF 15 C8 47 69 00` | `PostMessageA(g_hMainWnd, WM_COMMAND, 0x14D8, 0)` |
| 6 | 0x616B8E | `FF 90 F0 00 00 00` | MFC：`WM_COMMAND` → vtable slot 60 |
| 7 | 0x48F5D0 | `55 8D AC 24 30 DE FD FF` | `CDownloaderDlg` 命令分发器 |
| 8 | 0x49402D | `6A 00 68 90 5F 01 00 6A 2D 8B CE E8 53 FE F8 FF` | case 0x14D8 → `SetTimer(hwnd,0x2D,90000,NULL)` |
| 9 | 0x494045 | `C6 86 92 02 00 00 01` | `this+0x292 = 1` |
| 10 | 0x487733 | `6A 2D 8B 4E 20 51 FF 15 88 47 69 00` | `KillTimer(hwnd,0x2D)`（90 s 后 WM_TIMER） |
| 11 | 0x487764 | `RegQueryValueExA(hKey,"Therad",...)` | 读试用天数 |
| 12 | 0x48786A | `A1 E0 9C 77 00` / `3B 4D 2C` | 与 `[0x779CE0]` 比较 |
| 13 | 0x4878A1 | `6A 00 68 D7 14 00 00 68 11 01 00 00 8B 56 20 52 FF 15 C8 47 69 00` | `PostMessageA(hwnd, WM_COMMAND, 0x14D7, 0)` |
| 14 | 0x494138 | `6A 00 ×5, 68 C0 D2 47 00, E8 49 75 18 00` | case 0x14D7 → `push 0x47D2C0; call 0x61B695` |
| 15 | 0x47D2C0 | `A1 04 89 78 00` … | 30 天试用登记弹窗 |

---

## 3. (c) 该触发是否受 `[0x779CDC]` 或试用天数门控

**两者都受门控，但作用在不同环节。**

### 3.1 `[0x779CDC]` —— 链条总开关（生产者侧）

- 唯一门控点：`0x5BD4EA` `cmp dword ptr [0x779CDC], 0` / `0x5BD4F1` `je 0x5BD510`。
- 语义由**写入方**确定（全 `.text` 中对 `0x779CDC` 的写指令只有两条，且都是写 0）：
  ```
  0x00450DB0  mov dword ptr [0x779CDC], 0    ; C7 05 DC 9C 77 00 00 00 00 00
  0x00523A70  mov dword ptr [0x779CDC], 0    ; C7 05 DC 9C 77 00 00 00 00 00
  0x00523A7A  mov eax, dword ptr [0x7873B0]  ; g_hMainWnd
  0x00523A85  push 0x139F                    ; WM_COMMAND 0x139F
  0x00523A90  call dword ptr [0x6947C8]      ; PostMessageA
  ```
  `0x523A70` 处于序列号校验/注册成功路径上，随后向主窗口发 `0x139F`。⇒ **`[0x779CDC] != 0` = 试用态，`== 0` = 已注册/Full**。
- 该 dword 的初始值来自 `.data` 初始化器：`VA 0x779CDC` = 文件偏移 `0x3782DC`，原始字节 `01 00 00 00`（= 出厂即试用态）。
- **没有任何代码把它写回 1**（见 §4.2 证明）。

### 3.2 `[0x779CE0]` —— 试用天数阈值（消费者侧）

- 初始值：`VA 0x779CE0` = 文件偏移 `0x3782E0`，原始字节 `1E 00 00 00`（= **30**）。
- 运行期重算，位于 `FUN_0044CBE0`：
  ```
  0x0044CC27  mov  eax, dword ptr [0x779CDC]   ; A1 DC 9C 77 00
  0x0044CC2C  neg  eax                         ; F7 D8
  0x0044CC2E  sbb  eax, eax                    ; 1B C0
  0x0044CC30  and  eax, 0xF                    ; 83 E0 0F
  0x0044CC33  add  eax, 0xF                    ; 83 C0 0F
  0x0044CC36  mov  dword ptr [0x779CE0], eax   ; A3 E0 9C 77 00
  ```
  ⇒ `[0x779CE0] = (Trial ? 30 : 15)` —— **正是「试用天数阈值」**。
- 使用点（case 0x2D，VA 0x487869-0x487873）：
  ```
  0x00487869  mov  eax, dword ptr [0x779CE0]   ; A1 E0 9C 77 00
  0x0048786E  mov  ecx, dword ptr [ebp + 0x2c] ; 刚读到的 "Therad"
  0x00487871  cmp  eax, ecx
  0x00487873  jbe  0x487890                    ; Therad >= 阈值 → 走 0x14D7 分支
  ```
- 同一阈值在 case 0x0F（`arg1 = 0x0F`，case 体起点 `0x48701F`）也被使用，但方向相反（"剩余天数 ≤ 15 才提示"）：
  ```
  0x00487312  mov  eax, dword ptr [0x779CE0]
  0x00487317  sub  eax, dword ptr [ebp + 0x5c]   ; 剩余天数
  0x0048731A  cmp  eax, 0xF
  0x0048731D  ja   0x487331
  0x0048731F  push eax ; push 0x13CA ; push 0x111 ; call 0x43B030
  ```

### 3.3 门控结论

- **0x14D7 弹窗链的总开关 = `[0x779CDC]`**（在 `0x5BD4EA`，生产者侧）。只要它是 0，`0x14D8` 就不会被发出，后面所有环节都不可达。
- **`[0x779CE0]`（试用天数阈值）只决定 case 0x2D 走 `0x13CA` 还是 `0x14D7`**（消费者侧），它**不是**总开关：即使阈值为 30，`Therad >= 30` 时照样发 `0x14D7`。
- `[0x779CDC]` **不**在 case 0x2D 中被读取（该 case 只读 `[0x779CE0]`）。

---

## 4. (d) 为什么实机上按正常启动/下载流程复现不出这个弹窗

### 4.1 直接原因：已部署补丁①把总开关永久置 0

补丁①（`patch_idm.py` 的 `registration_flag_init`）：文件偏移 `0x3782DC`，`01 00 00 00 → 00 00 00 00`。
该 4 字节就是 `VA 0x779CDC` 的 `.data` 初始化器（`0x377600 + (0x779CDC-0x779000) = 0x3782DC`，已二次校验原始字节 `01 00 00 00`）。

后果逐跳推演：

1. 进程启动后 `[0x779CDC] == 0`。
2. `0x5BD4EA cmp dword ptr [0x779CDC], 0` → ZF=1 → `0x5BD4F1 je 0x5BD510` **必然跳转**。
3. `0x5BD4F3 test cl,cl` / `0x5BD4F5 je 0x5BD510` 与 `0x5BD4FF push 0x14D8` **永不执行**。
4. ⇒ `PostMessageA(g_hMainWnd, WM_COMMAND, 0x14D8, 0)` 永不发出。
5. ⇒ `FUN_0048F5D0` 的 case `0x14D8`（`0x49402D`）永不执行 ⇒ `SetTimer(hwnd, 0x2D, 90000, NULL)` 永不调用。
6. ⇒ 定时器 0x2D 永不建立 ⇒ 不可能产生 `WM_TIMER(nIDEvent = 0x2D)`。
7. ⇒ `FUN_00486990` 的 case 0x2D（`0x487733`）永不执行 ⇒ `0x4878A1` 处的 `PostMessageA(..., 0x14D7, 0)` 永不执行。
   （旁证：`0x14D7` 作为立即数在整个 `.text` 中**只出现这一处**，`VA 0x4878A4`。）
8. ⇒ `FUN_0048F5D0` 的 case `0x14D7`（`0x494138`）永不执行 ⇒ `push 0x47D2C0; call 0x61B695` 永不执行。
   （旁证：值 `0x0047D2C0` 在整份镜像中**只出现一次**，`VA 0x494143`。）
9. ⇒ `FUN_0047D2C0` 永不被调用 ⇒ 弹窗不出现。

此外补丁②（文件偏移 `0x7C6C0`，`A1 04 89 78 00 → E9 38 00 00 00`）把 `FUN_0047D2C0` 入口直接改成 `jmp 0x47D2FD`：
```
0x0047D2C0  (原) mov eax, dword ptr [0x788904]
0x0047D2FD        mov eax, 1        ; B8 01 00 00 00
0x0047D302        ret               ; C3
```
即使有别的路径调用它也只会立刻返回 1。

### 4.2 「无法被写回 1」的证明

对 `VA 0x779CDC` 的 4 字节小端模式 `DC 9C 77 00` 在 `.text` 中做全量扫描（45 处命中），逐条回看前置操作码：
- 只有 **2 处** 是写操作，操作码均为 `C7 05`（`mov dword ptr [imm32], imm32`），且两条的立即数都是 `0x00000000`。
- 其余 43 处均为读（`cmp [0x779CDC], reg`、`mov reg, [0x779CDC]`、`movzx` 等）。

⇒ **`.text` 中不存在能把 `[0x779CDC]` 置为非 0 的指令。** 一旦补丁①把初始化器改为 0，该标志在进程整个生命周期内恒为 0，链条**不可恢复**。

### 4.3 即使不补丁①，正常流程也很难复现（稀疏性证据）

1. **生产者条件极稀疏**（`0x5BD4E3-0x5BD4F5`）：
   `cl = (global 0x787374 高于 maxID+1) || (newDownloadID % 20 == 7)`。
   `id % 20 == 7` 只覆盖 1/20 的下载编号。
2. **90 秒延迟**（`0x49402F push 0x15F90` = 90000 ms）：弹窗至少在下载被创建后 **90 秒**才可能出现；短时启动/下载测试窗口看不到。
3. **消费者优先发 0x13CA**（`0x487867-0x487873`）：只要注册表值 `"Therad"` 可读且 `< [0x779CE0]`，case 0x2D 就发 `0x13CA`（携带剩余天数）而**不发** `0x14D7`。
4. **必须等到 WM_TIMER 而不是同步调用**：整条链依赖消息泵，且 `0x494045` 先置 `this+0x292 = 1`，`0x48773F` 再清 0 —— 单次运行只走一次。

---

## 5. 补丁评估

详见 `work/idm-6.43b8/patches/proposed-nag-patches.txt`。

**结论：针对本弹窗（`FUN_0047D2C0`）无需追加补丁。**
理由：补丁① 已把唯一生产者（`0x5BD4FF`）的门控永久关闭，且 §4.2 证明该标志不可能被写回；补丁② 又把唯一消费者（`0x494138`）的目标函数变成空操作。生产者与消费者同时被覆盖，链条两端都已断开。该文件另附 3 条**可选加固**补丁（均已二次校验原始字节），供 Lead 决定是否采用。

---

## 6. 证据索引

| VA | 文件偏移 | 原始字节（节选） | 含义 |
|---|---|---|---|
| 0x48F5D0 | 0x08E9D0 | `55 8D AC 24 30 DE FD FF` | CDownloaderDlg 命令分发器入口 |
| 0x49A3F1 | 0x0997F1 | `8B 4D F4 64 89 0D 00 00 00 00` | 该函数尾声（`ret 8` @0x49A415） |
| 0x48F836 | 0x08EC36 | `81 FA 4D 14 00 00` | `cmp edx,0x144D` |
| 0x492088 | 0x091488 | `8D 82 B2 EB FF FF` | `lea eax,[edx-0x144E]` |
| 0x492099 | 0x091499 | `0F B6 80 50 A7 49 00` | 字节映射表 C 取值 |
| 0x4920A0 | 0x0914A0 | `FF 24 85 98 A5 49 00` | 跳转表 C 分发 |
| 0x49A598 | 0x099998 | 表 C 110 项（首项 `57 41 49 00`） | 命令 → case 体 |
| 0x49A6B0 | 0x099AB0 | `38 41 49 00` | 表 C[70] = 0x00494138 |
| 0x49A750 | 0x099B50 | `00 6D 01 02 03 04 05 06`（208 字节） | 字节映射，[0x89] = 0x46 |
| 0x494138 | 0x093538 | `6A 00 6A 00 6A 00 6A 00 6A 00 68 C0 D2 47 00 E8 49 75 18 00 B8 01 00 00 00 9B E9 9A 62 00 00` | case 0x14D7 |
| 0x61B695 | 0x21AA95 | `6A 04 B8 13 5F 68 00` | 6 参数创建辅助（`ret 0x18`） |
| 0x47D2C0 | 0x07C6C0 | `A1 04 89 78 00 68 04 00 01 00` | 弹窗函数（补丁②目标） |
| 0x47D2FD | 0x07C6FD | `B8 01 00 00 00 C3` | 弹窗函数尾声 `mov eax,1; ret` |
| 0x6A19FC | 0x2A01FC | `A1 19 61 00`（vtable[0]） | `.rdata` vtable，RTTI 名 `.?AVCDownloaderDlg@@` |
| 0x6A1AEC | 0x2A02EC | `D0 F5 48 00` | vtable slot 60 = 0x0048F5D0 |
| 0x735340 | 0x333B40 | `00 00 00 00 00 00 00 00` | RTTI CompleteObjectLocator（sig=0） |
| 0x77A370 | 0x378970 | `2E 3F 41 56 43 44 6F 77 6E 6C 6F 61 64 65 72 44 6C 67 40 40` | TypeDescriptor 名称 `.?AVCDownloaderDlg@@` |
| 0x49B9F0 | 0x09ADF0 | `B8 A4 34 6A 00 C3` | GetMessageMap → 0x6A34A4 |
| 0x6A34A4 | 0x2A1CA4 | `7F 1D 61 00 B0 34 6A 00` | AFX_MSGMAP {base=0x611D7F, entries=0x6A34B0} |
| 0x6A3A68 | 0x2A2268 | `13 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 00 00 00 90 69 48 00` | AFX_MSGMAP_ENTRY：WM_TIMER(0x113) → 0x00486990 |
| 0x616B7E | 0x215F7E | `81 FB 11 01 00` | `cmp ebx, 0x111 (WM_COMMAND)` |
| 0x616B8E | 0x215F8E | `FF 90 F0 00 00 00` | `call [eax+0xF0]`（vtable slot 60） |
| 0x486990 | 0x085D90 | `55 8D 6C 24 9C 83 EC 64 6A FF 68 A6 8E 66 00` | CDownloaderDlg::OnTimer 入口 |
| 0x4869CB | 0x085DCB | `8B 45 6C 48 83 F8 6E 0F 87` | `mov eax,[ebp+0x6C]; dec; cmp 0x6E; ja` |
| 0x4869DF | 0x085DDF | `FF 24 85 B0 80 48 00` | OnTimer 跳转表分发 |
| 0x4880B0 | 0x0874B0 | `E6 69 48 00`（41 项） | OnTimer case 表 |
| 0x488154 | 0x087554 | `00 28 28 01 02 03 04 28` | OnTimer 字节映射（[0x2C]=0x21） |
| 0x487733 | 0x086B33 | `6A 2D 8B 4E 20 51 FF 15 88 47 69 00` | case 0x2D：`KillTimer(hwnd,0x2D)` |
| 0x48773F | 0x086B3F | `C6 86 92 02 00 00 00` | `this+0x292 = 0` |
| 0x487764 | 0x086B64 | `A1 54 83 78 00 50 33 C9 38 0D D4 6C 78 00` | 打开注册表键 |
| 0x4878A1 | 0x086CA1 | `6A 00 68 D7 14 00 00 68 11 01 00 00 8B 56 20 52 FF 15 C8 47 69 00` | `PostMessageA(hwnd,WM_COMMAND,0x14D7,0)` |
| 0x48789F | 0x086C9F | `74 16` | `je 0x4878B7`（跳过 0x14D7） |
| 0x49402D | 0x09342D | `6A 00 68 90 5F 01 00 6A 2D 8B CE E8 53 FE F8 FF` | case 0x14D8：SetTimer(0x2D,90000) |
| 0x494045 | 0x093445 | `C6 86 92 02 00 00 01` | `this+0x292 = 1` |
| 0x49404C | 0x09344C | `B8 01 00 00 00 9B E9 9A 63 00 00` | case 0x14D8 的 `mov eax,1`（optB 目标） |
| 0x423E90 | 0x023290 | `8B 44 24 0C 8B 54 24 08 8B 49 20` | SetTimer 包装（`ret 0xC`） |
| 0x5BD440 | 0x1BC840 | `83 EC 10 53 55 56 57` | 下载编号分配器 |
| 0x5BD4EA | 0x1BC8EA | `83 3D DC 9C 77 00 00` | `cmp [0x779CDC], 0` |
| 0x5BD4F1 | 0x1BC8F1 | `74 1D` | 总门控 `je 0x5BD510` |
| 0x5BD4FF | 0x1BC8FF | `68 D8 14 00 00` | `push 0x14D8` |
| 0x5BD50A | 0x1BC90A | `FF 15 C8 47 69 00` | `PostMessageA` |
| 0x7873B0 | 0x3859B0 | `00 00 00 00` | `g_hMainWnd`（`.data`） |
| 0x48D30C | 0x08C70C | `89 15 B0 73 78 00` | `g_hMainWnd = this->m_hWnd` |
| 0x450DB0 | 0x0501B0 | `C7 05 DC 9C 77 00 00 00 00 00` | 写 `[0x779CDC] = 0` |
| 0x523A70 | 0x122E70 | `C7 05 DC 9C 77 00 00 00 00 00` | 写 `[0x779CDC] = 0`（注册成功路径） |
| 0x44CC27 | 0x04C027 | `A1 DC 9C 77 00 F7 D8 1B C0 83 E0 0F 83 C0 0F A3 E0 9C 77 00` | `[0x779CE0] = Trial?30:15` |
| 0x779CDC | 0x3782DC | `01 00 00 00` | `g_registered` 初始化器（补丁①目标，`.data`） |
| 0x779CE0 | 0x3782E0 | `1E 00 00 00` | 试用天数阈值初始化 = 30（`.data`） |
| 0x6A904C | 0x2A784C | `Software\DownloadManager\maxID` | 注册表键 |
| 0x69F73C | 0x29DF3C | `maxID` | 注册表值名 |
| 0x6A0318 | 0x29EB18 | `Therad` | 试用天数注册表值名 |
| 0x6947C8 | IAT | `PostMessageA` | 导入 |
| 0x69478C | IAT | `SetTimer` | 导入 |
| 0x694788 | IAT | `KillTimer` | 导入 |
| 0x694004 | IAT | `RegQueryValueExA` | 导入 |
| 0x69408C | IAT | `RegCreateKeyExA` | 导入 |
| 0x694098 | IAT | `RegOpenKeyExA` | 导入 |
| 0x694048 | IAT | `RegCloseKey` | 导入 |
| 0x6947F8 | IAT | `GetDesktopWindow` | 导入 |
| 0x6942E4 | IAT | `ResumeThread` | 导入 |

**复现命令（只读，不修改任何文件）**

```powershell
# 跳转表 C 第 70 项 = 0x494138，字节映射 [0x89] = 0x46 ⇒ cmd = 0x14D7
python work\idm-6.43b8\scripts\idmdis.py 0x494138 0x20
python work\idm-6.43b8\scripts\idmdis.py 0x4878A1 0x18
python work\idm-6.43b8\scripts\idmdis.py 0x5BD4EA 0x20
python work\idm-6.43b8\scripts\xref2.py va 0x779CDC 0x779CE0
```

---
*本报告所有地址均来自 `work/idm-6.43b8/bin/IDMan.exe.orig`；未对 `C:\Program Files (x86)\Internet Download Manager\` 下任何文件做读写；未运行 IDMan.exe。*
