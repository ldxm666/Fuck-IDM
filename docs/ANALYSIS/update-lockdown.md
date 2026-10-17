# IDM 6.43b8 自动更新回退风险与防回退方案

- 目标二进制：`C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（已打补丁，sha256 `527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552`）
- 原始备份：同目录 `IDMan.exe.bak-original`（sha256 `74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8`）
- 静态分析对象：`work/idm-6.43b8/bin/IDMan.exe.orig`（sha256 `74F177C8…`，与备份一致），Ghidra 12.1.2 / REA
- 分析方式：纯静态反编译 + 注册表读取 + 文件系统 ACL 读取。**未启动 IDMan.exe**，**未修改安装目录任何文件**。
- 分析时刻：2026-10-16 21:48 (+08:00)

---

## 0. 结论摘要（TL;DR）

| 问题 | 结论 |
|---|---|
| 自动更新检查会不会触发？ | 会。启动时若 `LastCheckQU` 距今 > 6 天，就挂 60 s 定时器 `UPDATE_TIMER`（timer id 5），随后在后台线程发起更新检查。周期约 **7 天**。 |
| 自动检查会不会**静默替换 IDMan.exe**？ | **IDMan.exe 自己永远不会覆盖自己的镜像**（没有写自身镜像的代码；清单是 `asInvoker`；安装目录 ACL 只给 `Users` 读权限）。真正覆盖文件的是它下载并以管理员身份启动的 `idmupdt.exe` / `idmupdt2.exe`。 |
| 那还需要防吗？ | 需要。自动路径会**自行下载并启动**这个更新器，中间没有第二次“是否更新”的确认。在 UAC 关闭、或 IDMan.exe 被以管理员身份启动、或有人手工重装官方包的机器上，等效于静默回退。 |
| 当前窗口 | `LastCheckQU = 1792156831` → **2026-10-16 21:20:31**，距今 0.02 天。**下一次自动检查最早在 2026-10-23 之后**。 |
| 最推荐的防回退做法 | ① 每 ≤6 天把 `LastCheckQU` 刷新为当前 Unix 时间（零副作用，唯一有效的注册表手段）；② 定期跑 `scripts/check-patch-state.ps1`，发现哈希变了就重跑 `patch_idm.py` + `deploy.ps1`；③ 可选：给 `IDMan.exe` 设只读属性做减速带；④ 永远不要以管理员身份运行 IDMan.exe，UAC 保持默认。 |

---

## 1. 更新触发条件与频率

### 1.1 注册表证据

读取 `HKCU\Software\DownloadManager`（2026-10-16 21:48）：

| 值名 | 类型 | 数据 | 作用（证据见下） |
|---|---|---|---|
| `LastCheckQU` | REG_DWORD | `1792156831` → 2026-10-16 21:20:31 +08 | 上一次 Quick-Update 检查的 Unix 时间。**唯一的 7 天门控输入** |
| `CheckUpdtVM` | REG_SZ | `10` | 更新方案标记，仅在 `LstCheck` 过期时被写入 |
| `LstCheck` | REG_SZ | `08/10/26`（= 2026-10-08，MM/DD/YY） | 上次更新检查日期，喂给 `CheckUpdtVM` 的计算 |
| `idmvers` | REG_SZ | `v6.43b08 Full` | 打完补丁后为 Full（原始为 Trial），决定走哪条更新分支 |
| `vCOUFP` | REG_SZ | `643b08` | 上次更新检查载荷的版本号 |
| `radxcnt` | REG_DWORD | `92` | 启动计数（每次启动 +1，VA 0x004772B0 内） |
| `tvfrdt` | REG_DWORD | `2107457418` → 2036-10-13 | 未来日期标记（与更新无关，记录备查） |

同机另有 `HKLM\SOFTWARE\WOW6432Node\Internet Download Manager`（仅 `AdvIntDriverEnabled2` / `MaxClientId`），`HKLM\SOFTWARE\Internet Download Manager` 与 `HKCU\Software\Internet Download Manager` 均不存在。

### 1.2 二进制证据：完整的触发链

**(1) 7 天门控 —— `FUN_00456BC0`（VA 0x00456BC0，body 0x456BC0–0x456C76，183 B）**

```c
bool FUN_00456bc0(void) {
  local_18 = 4;
  LVar1 = RegQueryValueExA(DAT_00786ce8, "LastCheckQU", 0, 0, (LPBYTE)&local_1c, &local_18);
  if (LVar1 == 0) {
    uVar2 = time(NULL);
    uVar2 = (uVar2 - local_1c) / 0x15180;   /* 0x15180 = 86400 = 1 天 */
    return 6 < uVar2;                       /* 严格大于 6 天 → 到期 */
  }
  return true;                              /* 值不存在 → 永远到期 */
}
```

- 字符串 `LastCheckQU` @ VA 0x006A11B4；xref 只有两处：**读** 0x00456C08（本函数）、**写** 0x00487928（见 (3)）。
- `DAT_00786CE8` 是启动时预先打开的 `HKCU\Software\DownloadManager` 句柄。
- **门控语义**：距今 > 6×86400 s，即**第 7 天起**才到期。**若 `LastCheckQU` 缺失，函数恒返回 true（永远到期）**——这一点决定了防回退方案不能用“删除该值”。
- 注意：减法是无符号 32 位。把 `LastCheckQU` 设到**未来**会得到巨大的商，同样恒为“到期”。**只有把时间戳保持在最近 6 天内才能关闭门控。**

**(2) 启动时挂定时器 —— `FUN_004772B0`（VA 0x004772B0），唯一调用者 `FUN_00477530`（VA 0x00477530）**

```c
if (*(char *)(in_ECX + 0x27e) == '\0') {          /* 定时器未挂 */
    iVar2 = FUN_00456bc0();                        /* 7 天门控 */
    if ((iVar2 != 0) && (SetTimer(*(HWND *)(in_ECX + 0x20), 5, 60000, 0) != 0)) {
      *(undefined1 *)(in_ECX + 0x27e) = 1;         /* 已挂标记 */
    }
    /* …同时读/写 radxcnt… */
}
```

- **`SetTimer(hwnd, 5, 60000, NULL)`：到期就在启动后 60 s 挂上 `UPDATE_TIMER`（timer id = 5）。**
- 同一函数还挂了其它定时器（id 6 @60 s、0x11 @10 s、0x15 @180 s、0x1E @99 s、0x1F @121 s、0x22 @225 s、0x23 @255 s、0x25 @1200 s），与更新无关。

**(3) `UPDATE_TIMER` 到点后做什么 —— `CDownloaderDlg::OnTimer` 的 timer 5 分支**

Ghidra 没有为 VA 0x00486100–0x00488210 建立函数边界（该区间夹在 `FUN_00486100` 与 `FUN_00488210` 之间），因此用逐条指令/字节取证：

| VA | 字节 | 语义 |
|---|---|---|
| 0x004878D3 | `6A 05` / `8B 46 20` / `50` / `FF 15 88 47 69 00` | `PUSH 5; PUSH [ESI+0x20]; CALL [0x694788]` → `PTR_KillTimer` → **`KillTimer(hwnd, 5)`** |
| 0x004878DF | `C6 86 7E 02 00 00 00` | `MOV BYTE [ESI+0x27E], 0` → 清“已挂”标记 |
| 0x004878F9 | `6A 00 ×3` / `8B 8E 98 01 00 00` / `51` / `68 E0 4D 45 00` / `E8 …` | `AfxBeginThread(0x454DE0, [ESI+0x198], 0, 0, 0)` → **后台线程跑更新检查** |
| 0x00487922–0x00487938 | `6A 04; 8D 4D 2C; 51; 6A 04; 6A 00; 68 B4 11 6A 00; 8B 15 E8 6C 78 00; 52; FF 15 90 40 69 00` | `RegSetValueExA(HKCU\Software\DownloadManager, "LastCheckQU", 0, REG_DWORD(4), &time(), 4)` → **IDM 自己把 `LastCheckQU` 盖成当前时间** |
| 0x0048794B–0x00487960 | `68 C0 D4 01 00; 6A 05; 8B 46 20; 50; FF 15 8C 47 69 00; …; C6 86 7E 02 00 00 01` | `SetTimer(hwnd, 5, 0x1D4C0 /*120000 ms*/, NULL)` + `MOV BYTE [ESI+0x27E],1` → **2 分钟后再挂一次** |
| 0x00487974 | `6A 01; 68 98 2A 6A 00; …` | `PUSH 1; PUSH 0x6A2A98` → 字符串 **`"Unknown error during CDownloaderDlg::OnTimer(nIDEvent = UPDATE_TIMER)\n"`** → **证明这段就是 `CDownloaderDlg::OnTimer` 的 `UPDATE_TIMER` 分支** |

旁证：RTTI 名字 `.?AVCDownloaderDlg@@` @ VA 0x0077A370；同类调试串还有 `QUEUE_TIMER` / `CHECK_LNG_TIMER` / `TIPOFTHEDAY_TIMER` / `REGISTR_TIMER`。

**(4) 更新检查后台线程 —— `FUN_00454DE0`（VA 0x00454DE0，96 B）**

```c
undefined4 FUN_00454de0(undefined4 param_1) { FUN_004ba1c0(1,0,1,param_1); return 1; }
```

**(5) `CheckUpdtVM` 是谁写的 —— `FUN_0045A0B0`（VA 0x0045A0B0）**

```c
local_2c[1] = 0x10;
if (RegQueryValueExA(DAT_00786ce8, "LstCheck", 0, 0, local_24, &size) == 0) {
    __strdate(local_14);                                  /* 今天 MM/DD/YY */
    if (sscanf(local_24, "%ld/%ld/%ld", &local_38,&local_3c,&local_34) == 3   /* 存储值 */
     && sscanf(local_14, "%ld/%ld/%ld", &local_30,&local_40,local_2c) == 3) { /* 今天 */
        local_30 = ((local_2c[0]-local_34)*0x16d + (local_40-local_3c)*0x1e - local_38) + local_30;
        if (10 < local_30 || local_30 < 0) {              /* 0x16d=365, 0x1e=30 */
            local_44 = "10";                              /* 3 字节含 NUL */
            RegSetValueExA(DAT_00786ce8, "CheckUpdtVM", 0, REG_SZ(1), local_44, 3);
        }
    }
}
```

- 写入点 **VA 0x0045A1AC**，字符串 `CheckUpdtVM` @ 0x006A1590，`LstCheck` @ 0x006A03A0。
- **实机复算**：`LstCheck = "08/10/26"`（月=8, 日=10, 年=26），今天 10/16/26（月=10, 日=16, 年=26）→ `(26-26)*365 + (16-10)*30 - 8 + 10 = 182 > 10` → 写入 `"10"`。**与注册表实测值 `CheckUpdtVM = 10` 完全一致，机制确认。**
- `CheckUpdtVM` 在 IDMan.exe 内**只有这 1 处 xref（写）**，没有任何读取点 → 它对本模块的更新决策**没有影响**，消费者在本模块之外（更新器 / 安装器 / 服务器侧载荷）。**不可作为开关使用。**
- `FUN_0045A0B0` 没有已解析的调用者（Ghidra 报告有 1 个未解析的 call 引用进入其函数体），属于被消息映射/间接调用触发的例程。

**(6) 频率的旁证字符串**

- VA 0x006B4AD8：`"IDM checks for a new release every 2 weeks by requesting an update page from its home site. …"`（帮助文本说“两周”，与二进制里 7 天的门控**不一致**，以二进制为准）
- VA 0x009B7EDA：`"Check for available updates on www.internetdownloadmanager.com"`（菜单/状态文本）
- VA 0x006BB250：`"You are using the latest version of Internet Download Manager. Please check back again for updates at a later time."`
- VA 0x006AEE70：`"Check for updates failed, because update information is invalid. …"`
- VA 0x006ABC90：`"…Are you sure that you don't need to update to the latest version of IDM?"`（唯一一处“跳过更新”的追问文本）
- VA 0x006AE730：`"…IDM will check for updates successfully even with your damaged \"hosts\" file."` → **IDM 会绕过被 hosts 屏蔽的更新域名**
- VA 0x006C4448：`https://www.internetdownloadmanager.com/support/updateblocked.html`

### 1.3 自动更新会不会静默替换 `IDMan.exe`？

**不会由 IDMan.exe 自己完成，但会由它拉起的更新器完成。**

证据一：**IDMan.exe 无法写安装目录。**
- 内嵌清单 @ VA 0x00792350：`<requestedExecutionLevel level="asInvoker"/>`，`assemblyIdentity name="Tonec.IDM.IDMan"` → 以调用者完整性级别运行（普通用户 = Medium IL）。
- 安装目录 ACL（实测）：`BUILTIN\Users` = `ReadAndExecute, Synchronize`；`BUILTIN\Administrators` = `FullControl`；`NT SERVICE\TrustedInstaller` = FullControl。当前会话 `win-dh3f0oeoi2m\administrator`，`IsInRole(Administrator) = False`（未提权）。
- 经验证据：本工程此前把测试副本写进安装目录时必须用提权辅助脚本，`work/idm-6.43b8/logs/elevcopy.txt` 记录 `ELEVATED_COPY_OK dest=…\IDMan_test.exe`。

证据二：**IDMan.exe 里没有任何写自身镜像的代码。** 更新路径中唯一触碰安装目录的文件操作是 `GetFileAttributesW` + `MoveFileW`，且对象是 `idmupdt.exe` → `idmupdt.exe.del`（见 §2.3）。

证据三：**真正覆盖文件的是 `idmupdt.exe` / `idmupdt2.exe`**（§2）。这两个文件**当前不在安装目录**（完整目录列表已核对，见 §2.5），是**按需下载**的，因此其自身清单（是否 `requireAdministrator`）**无法静态验证**——这一点必须在报告中保留为未知项。

**因此风险表述应为：** 自动路径会自行下载并启动提权更新器，中间没有“是否更新”的二次确认；在以下任一条件下即等效静默回退——
1. UAC 被关闭 / 设为“从不通知”；
2. IDMan.exe 被以管理员身份启动（此时其子进程继承 High IL）；
3. 有人手工运行官方安装包或 `idmupdt.exe`。

**当前实际风险窗口：** `LastCheckQU = 2026-10-16 21:20:31`，门控需 > 6 天 → **2026-10-23 之后**才会再次到期。

---

## 2. 更新下载后的落地流程（idmupdt.exe / idmupdt2.exe 是谁拉起的、是否提权）

### 2.1 入口

- 菜单“检查更新 / Help→Check for updates” = `WM_COMMAND 0x8013` → “快速更新 / Quick Update”对话框。
- 该对话框的实现体是 **`FUN_0042DFB0`（VA 0x0042DFB0，1858 B，body 0x42DFB0–0x42E6F1）**。它没有已解析的调用者 → 通过 `CDownloaderDlg` 的 MFC 消息映射间接调用（典型 MFC 对话框过程）。
- 自动路径（§1.2 (3)）最终也会走到同一套“快速更新”编排代码：`FUN_004EC900`（VA 0x004EC900，14 171 B，body 0x4EC900–0x4F005A），由 `FUN_004F6BF0`（VA 0x004F6BF0，577 B）调用。

### 2.2 更新器 URL 的构造（VA 0x0042E0xx–0x0042E2xx）

`FUN_0042DFB0` 开头先取注册信息：`RegOpenKeyExA(HKEY_LOCAL_MACHINE /*DAT_80000002*/, "SOFTWARE\\Internet Download Manager", 0, KEY_QUERY_VALUE(1), &hKey)`，读值名 `DAT_00788604`；失败则回退到预先打开的 HKCU 句柄 `DAT_00786CE8`（`HKCU\Software\DownloadManager`）。取不到就直接 `CDialog::EndDialog` 退出。

**分支 A —— `DAT_00779CDC == 0`（即“已注册 / Full”，也就是我们打补丁后的状态）：**

```c
cVar1 = FUN_00421040(&DAT_00787af0, "/data/fv/");        /* 字符串 @0x0069C124 */
if (cVar1 == '\0') {
    cVar1 = FUN_00421040(&DAT_00787af0, "/a/dc/");
    pcVar3 = "idmupdt.exe";                              /* @0x0069C0E0 */
    if (cVar1 != '\0') goto LAB_0042e24f;
} else { LAB_0042e24f: pcVar3 = "idmupdt2.exe"; }        /* @0x0069C100 */
FUN_00402f20(local_ab0, "%s?v=%s", pcVar3, DAT_00786eb0);   /* 形如 idmupdt.exe?v=6.43 */
...
FUN_005bd210(2, "www.internetdownloadmanager.com", DAT_00787af0, local_ab0[0], 0xffffffff);
```

- **选择规则**：更新路径前缀 `DAT_00787AF0` 含 `/data/fv/` 或 `/a/dc/` → 用 `idmupdt2.exe`，否则用 `idmupdt.exe`。
- `FUN_005BD210(2, host, path, url, -1)` 是 IDM 自己的“把 URL 加进下载队列”入口 → **IDMan.exe 用自己的下载引擎把更新器拉下来**。宿主是 `www.internetdownloadmanager.com`，路径前缀来自 `DAT_00787AF0`。
- 另一分支用 XOR 0x0F 解出的域名：VA 0x0042E1xx 处 `MOV` 立即数 `0x21,0x66,0x61,0x7B,0x6A,0x7D,0x61,0x6A,0x7B,0x6B,0x60,0x78,0x61,0x63,0x60,0x6E,0x6B,0x62,0x6E,0x61,0x6E,0x68,0x6A,0x7D,0x21,0x6C,0x60,0x62`，逐字节 `^ 0x0F` → `".internetdownloadmanager.com"`，再 `FUN_00402f20(&s, "www%s", &decoded)` 得到 `www.internetdownloadmanager.com`。

**分支 B —— `DAT_00779CDC != 0`（未注册 / Trial）：**

```c
FUN_00402f20(&local_ab4, "%s?%s", "update.cgi", local_6c);   /* "update.cgi" @0x0069C14C */
/* 同样 XOR 0x0F 解码 ".internetdownloadmanager.com" */
FUN_00402f20(&local_abc, "secure%s", &local_38);             /* → secure.internetdownloadmanager.com */
FUN_005bd210(2, local_abc, "/data/729418032/", local_ab4, 0xffffffff);
```

- 即 `https://secure.internetdownloadmanager.com/data/729418032/update.cgi?<注册值>`，把 HKLM/HKCU 里读到的注册串作为查询参数回传（版本/授权上报）。
- **副作用提示**：我们的补丁把注册标志翻成“已注册”，所以 IDM 现在走的是**分支 A（真正下载 `idmupdt.exe` 的那条）**，而原始 Trial 版本走的是分支 B。**补丁在“注册”这条路上是打开了更新器下载通道，而不是关掉它。**（另一侧也有好处：`FUN_004EC900` 里的 `"Please register IDM before updating. …"` @0x006B8630 这个门槛现在也通过了。）

### 2.3 下载落地：只动更新器，不动 IDMan.exe

`FUN_0042DFB0` 末尾（VA 0x0042E4xx 起）：

```c
FUN_00402170(puVar4);            /* puVar4 = DAT_00786d40 ?: &DAT_00786d44 → 安装目录 */
FUN_00402170(L"idmupdt.exe");    /* 拼出 <安装目录>\idmupdt.exe */
FUN_00405390(local_89c);
FUN_0063f723(pWVar7);            /* 目标路径（local_878 ?: local_874） */
DVar6 = GetFileAttributesW(pWVar7);
if (DVar6 != 0xffffffff) {                       /* 已存在 */
    FUN_004021a0("%s.del", pWVar7, 0);           /* 拼出 …\idmupdt.exe.del */
    FUN_0063f723(pWVar7);
    MoveFileW(lpExistingFileName, pWVar7);       /* 旧更新器改名成 .del */
}
FUN_005c44e0(local_878);
```

**这里被改名的是 `idmupdt.exe`，不是 `IDMan.exe`。** 全二进制里 `idmupdt.exe` 字符串的 xref 只有 0x0042E3C4 与 0x0042E524（都在本函数内），`idmupdt2.exe` 的 xref 是 0x0042E24F / 0x0042E25B（也在本函数内）。

### 2.4 启动更新器 + 签名校验

`FUN_004EC900`（VA 0x004EC900）持有更新流程的全部用户可见文本，可确认“下载 → 校验 → 启动”三段：

| 字符串 VA | 文本 | xref |
|---|---|---|
| 0x006B8B1C | `Quick Update` | 0x004EE07D |
| 0x006B8630 | `Please register IDM before updating. … Then pick "Help->Quick Update" menu item to start updating.` | 0x004EE25D |
| 0x006BAEF8 | `Quick update failed, an error occurred while downloading new IDM files. Try to update later.` | 0x004ED3BD |
| 0x006B972C | `Unable to find Quick Update application.` | 0x004EDB37 |
| 0x006AEBC0 | `IDM could not start Update application. This may be due to incorrect antivirus software settings for the folder containing IDM service files. IDM will now open this folder, and you can run "idmupdt.exe" file manually. …` | 0x004EFA96 |
| 0x006AE258 | `IDM cannot download the update file. …` | — |
| 0x006AE2F0 | `The digital signature of IDM update file is invalid. It's possible that the update file is corrupted. …` | — |
| 0x006BAFA0 | `QuickUpdate for IDM from www.internetdownloadmanager.com. Receiving new files...` | — |

- `"IDM could not start Update application"` 直接证明 **IDMan.exe 会去启动 `idmupdt.exe`**，并提示“文件夹里的服务文件权限可能被杀软拦了”。
- `"The digital signature of IDM update file is invalid"` 证明 **IDM 对下载下来的更新载荷做 Authenticode 校验**——这既是保护，也意味着**我们自己造的假更新器会被拒**（想用“假更新器”来固化补丁这条路走不通）。
- `"Unable to find Quick Update application."` 是“更新器不在预期位置”的失败分支。

### 2.5 提权（UAC）判定

- **IDMan.exe 自身不提权**：清单 `asInvoker`（VA 0x00792350），实测 ACL 也证实它写不进安装目录。
- **IDMan.exe 内没有 ShellExecuteEx / CreateProcess 的 `runas` 用法**：
  - `search_procedures "ShellExecute"` 只返回导入桩 `SHELL32.DLL::ShellExecuteExW/ExA/W/A` 与 `DelayLoad_ShellExecute*`（0x0065CAF0 / 0x0065CB33 / 0x0065CB3D / 0x0065CB47）；
  - `find_xrefs_to_name` 对 `ShellExecuteExW / ShellExecuteExA / CreateProcessW / WinExec` 全部 `name_not_found`（无静态 xref 记录）；
  - 唯一的 `RunAs` 字符串（VA 0x0069FF74）在 `FUN_0044B6F0`（VA 0x0044B6F0）里被用作 **COM AppID 值**：`RegSetValueExA(hkAppID, "RunAs", 0, REG_SZ(1), "Interactive User", 0x11)`，写 `IDMan.CIDMLinkTransmitter` / `{AC746233-E9D3-49CD-862F-068F7B7CCCA4}` 的注册项 —— **与更新器提权无关**。
- 结论：**提权必须来自被下载的 `idmupdt.exe` / `idmupdt2.exe` 自己的清单**（`requireAdministrator` → 弹 UAC）。这两个文件当前不在安装目录（§2.5 目录列表），**其清单无法在本机静态验证，属明确未知项**。

### 2.6 安装目录实测（2026-10-16 21:48）

目录中**没有** `idmupdt.exe`、`idmupdt2.exe`、`IDMan.exe.del`。存在的相关程序：`IDMIntegrator64.exe`、`IDMGrHlp.exe`、`idmBroker.exe`、`IDMMsgHost.exe`、`MediumILStart.exe`、`IEMonitor.exe`、`Uninstall.exe`。
`IDMan.exe`（2026-10-16 21:37:29，已打补丁）与 `IDMan.exe.bak-original`（2026-08-08 14:48:22，原始）并存；`IDMan.exe` 属性为 `Archive`（**非只读**）。

### 2.7 更新器回写之后：`/isupdt`

更新器替换完文件后会用带参数的方式拉起 `IDMan.exe`。命令行解析器在：

- `FUN_00453BD0`（VA 0x00453BD0，宽字符版）
- `FUN_00453FC0`（VA 0x00453FC0，ANSI 版）

两者都识别开关 `isupdt`（字符串 @0x006A0A8C / 0x006A0B74；xref 0x00453DF8 / 0x004541EF），命中后置 `*(this+0x51) = 1`。同族开关：`download`(0x28)、`onboot`(0x29)、`rtr`(0x4F)、`forcerbt`(0x52)、`rbmsg`(0x50)、`isupdt`(0x51)、`Embedding`(0x4E)、`setlngid`(mode 4)、`fulllngfile`(mode 5)、**`onsilentsetup`（置 `this+0x55=1` 且 `DAT_00786CCC=1`）**、`instjs9`(0x56)、`d`(mode1, 0x48)、`p`(mode2)、`f`(mode3)、`s`(0x49)、`q`(0x4A)、`n`(0x4B)、`h`(0x4C)、`a`(0x4D)。

→ 也就是说：**更新器的“落地”是「下载 idmupdt.exe → 校验签名 → 改名为 .del 备份旧件 → 启动 idmupdt.exe（提权）→ 替换安装目录文件 → 以 `IDMan.exe /isupdt …` 重启」**。

---

## 3. 防回退方案

### 方案 (a) —— 用 IDM 自身设置 / 注册表关闭自动更新

**先给结论：IDM 6.43b8 里不存在“自动更新开关”这个注册表值。** 全部相关值的静态归属如下（`search_strings "Upd"` + 逐条 xref 核对）：

| 值名 | IDMan.exe 内的角色 | 能否当开关 |
|---|---|---|
| `LastCheckQU` | 唯一门控输入（读：0x00456C08；写：0x00487928） | **唯一可用**，但只能“保持新鲜”，不能一次关掉 |
| `CheckUpdtVM` | **只写不读**（唯一 xref = 0x0045A1AC 的写） | 否。消费者在本模块之外 |
| `LstCheck` | 仅用于计算 `CheckUpdtVM` | 否 |
| `idmvers` | 决定走分支 A/B（`Full` → 下载 idmupdt.exe；`Trial` → `update.cgi` 上报） | 否（且改回 Trial 会带回试用弹窗） |
| `radxcnt` | 启动计数 | 否 |

**具体做法（唯一有效）：**

```powershell
# 每次运行 IDMan.exe 之前（或每 ≤6 天一次）把门控时间戳刷新为“现在”
$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Set-ItemProperty -Path 'HKCU:\Software\DownloadManager' -Name 'LastCheckQU' -Value $now -Type DWord
```

- 依据：`FUN_00456BC0` 计算 `(time(NULL) - LastCheckQU) / 86400`，只有结果 ≤ 6 才不会挂 `UPDATE_TIMER`。
- **不需要重启 IDM**：`LastCheckQU` **只在启动时被读一次**（`FUN_00456BC0` 的唯一调用者是 `FUN_004772B0`，而它由启动路径 `FUN_00477530` 调用）。
  - 若 IDMan.exe 当前**没在运行**：改完再启动即可，本次会话不会自动检查。
  - 若 IDMan.exe **正在运行且定时器已挂上**：改注册表**不会**撤销已挂的 timer，必须关闭 IDM 再改、再启动。

**为什么不能用“删除”或“设成未来”：**
- 值缺失 → `RegQueryValueExA != 0` → 函数 `return true` → **每次启动都到期**（更糟）。
- 值 > 当前时间 → `uVar2 - local_1c` 是无符号减法，得到巨大数 → `/86400` 仍巨大 → `6 < 巨大` → **同样每次到期**。

**优劣**

| | |
|---|---|
| 优点 | 零文件改动、零副作用、随时可逆、不影响 IDM 功能与浏览器集成；不触发杀软/完整性告警。 |
| 缺点 | **不是持久开关**，必须周期性刷新（>6 天不刷新就失效）；只挡“自动”路径，挡不住用户手动点“检查更新”或手工重装。 |
| 副作用 | 无。仅 `LastCheckQU` 这一个值变化（IDM 本来就会自己写它）。 |
| 恢复方法 | 什么都不用做（IDM 下次检查会自己覆盖）；要立刻恢复“可自动更新”，删除该值即可：`Remove-ItemProperty -Path 'HKCU:\Software\DownloadManager' -Name 'LastCheckQU'`。 |

### 方案 (b) —— 文件系统层防护

安装目录 ACL 现状：`Users = ReadAndExecute`，`Administrators = FullControl`，`TrustedInstaller = FullControl`。

| 手段 | 具体命令 | 拦得住谁 | 拦不住谁 | 副作用 | 恢复方法 |
|---|---|---|---|---|---|
| **B1. 只读属性**（减速带） | `attrib +R "C:\Program Files (x86)\Internet Download Manager\IDMan.exe"` | 朴素的 `CopyFile` 覆盖会失败；普通用户完全无影响 | 提权进程可先清属性再写；`MoveFileEx(REPLACE_EXISTING)` 等也能绕过 | 某些安装器遇到只读文件会报错甚至回滚，可能留下半更新状态 | `attrib -R <path>` |
| **B2. 对 Everyone/Administrators 加 DENY(Write,Delete,WriteDAC)** | `icacls "<path>" /deny "Everyone:(W,DE,WDAC)"` | 非提权进程；也会让**我们自己的重打补丁**失败 | 提权的 Administrators/SYSTEM/TrustedInstaller 可 `SeTakeOwnership`+改 DACL 后覆盖 | ① 打补丁/升级必须先移除 DENY；② 更新器失败可能留下 `idmupdt.exe` 残留；③ 部分完整性/EDR 工具会告警 | `icacls "<path>" /remove:d Everyone` |
| **B3. 目录级 DENY（禁止建文件/写数据）** | `icacls "<dir>" /deny "Everyone:(WD,AD)"` | 更新器往目录里写 `idmupdt.exe` | 同上（提权可改） | **影响面最大**：IDM 写日志/辅助文件、浏览器集成安装、语言包更新都可能失败 | `icacls "<dir>" /remove:d Everyone` |
| **B4. 所有者改到专用账户 + DENY Administrators** | `takeown` + `icacls /setowner` | 提高提权绕过的成本 | 域管理员/SYSTEM 仍可改 | 结构脆弱；可能破坏 `Uninstall.exe`；系统还原点/映像工具会报错 | 需 `takeown /f <path> /a` 再 `icacls /setowner` 回 `Administrators` |
| **B5. 哈希看门狗（不阻断，只检测+重打）** | 见 §4 的 `check-patch-state.ps1` | 不阻断任何东西 | —— | 无 | 无需恢复 |
| **B6. 出口/网络层** | 防火墙阻止 `*.internetdownloadmanager.com` 出站；hosts 屏蔽 | 挡下载更新器 | **IDM 明确会绕过 hosts**（0x006AE730），纯 hosts 不可靠 | 会一并挡掉语言包、下载规则库更新 | 删除防火墙规则 / 恢复 hosts |

### 方案对比与推荐

| 维度 | (a) 注册表刷新 `LastCheckQU` | (b) 文件系统 DENY/只读 |
|---|---|---|
| 挡住自动更新 | ✅ 有效（需 ≤6 天刷新） | ✅ 有效（提权可绕过） |
| 挡住手动“检查更新” | ❌ | ✅ |
| 影响 IDM 正常功能 | 无 | B1 基本无；B2 中；B3 明显 |
| 需要管理员权限执行 | 不需要（HKCU） | 需要 |
| 可逆性 | 随时、零成本 | 需要显式移除 ACL/属性 |
| 风险 | 忘了刷新就失效 | 更新失败留下半状态、可能影响卸载 |

**推荐组合（按顺序）：**
1. **主防线**：方案 (a) —— 每次启动 IDM 前 / 每 ≤6 天把 `LastCheckQU` 刷成当前时间（HKCU，无需管理员，零副作用）。
2. **检测线**：把 `work/idm-6.43b8/scripts/check-patch-state.ps1` 挂到计划任务或手工在 IDM 升级/重启后跑一次；发现哈希变了就重跑 `patch_idm.py` + `deploy.ps1`。
3. **可选减速带**：`attrib +R IDMan.exe`（B1）。代价最小，能拦住一部分朴素覆盖。
4. **纪律**：**永远不要以管理员身份运行 IDMan.exe**，UAC 保持默认（默认下更新器替换文件必然弹 UAC，人工可见）。
5. **不推荐** B3/B4：副作用大于收益。

> 注：本节所有命令**仅作为方案给出，未在本机执行**。`IDMan.exe` 当前属性仍是 `Archive`（非只读），安装目录文件未做任何改动。

---

## 4. 补丁回检脚本

脚本：`work/idm-6.43b8/scripts/check-patch-state.ps1`

**检查的常量**

| 常量 | 值 | 来源 |
|---|---|---|
| 补丁后 sha256 | `527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552` | 部署产物 |
| 原始 sha256 | `74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8` | `IDMan.exe.bak-original` / `bin/IDMan.exe.orig` |
| 补丁点 1（文件偏移 `0x3782DC`，VA 0x779CDC `g_registered` 初始化） | 补丁后 `00 00 00 00`；原始 `01 00 00 00` | `patch_idm.py` PATCHES[0] |
| 补丁点 2（文件偏移 `0x007C6C0`，VA 0x0047D2C0 `FUN_0047d2c0`） | 补丁后 `E9 38 00 00 00`；原始 `A1 04 89 78 00` | `patch_idm.py` PATCHES[1] |
| 更新门控 | `HKCU\Software\DownloadManager\LastCheckQU`（REG_DWORD）+ 阈值 6 天 | `FUN_00456BC0` @ VA 0x00456BC0 |

**判定逻辑**

1. 计算 `IDMan.exe` 的 SHA256。
   - `== 补丁值` → **PATCHED**（退出码 0）
   - `== 原始值` → **REVERTED**（退出码 2），提示重跑 `patch_idm.py`
   - 其它 → **UNKNOWN BUILD**（退出码 3），提示这是新版本，`patch_idm.py` 的偏移大概率失效，需要重新定位
2. 双补丁点字节交叉校验（区分“被我们打过”与“恰好像但不是同一构建”）。
3. 打印注册表状态：`LastCheckQU`（解码为本地时间 + 距今天数）、门控是否打开（>6 天）、`CheckUpdtVM` / `LstCheck` / `idmvers` / `vCOUFP`。
4. 若非 PATCHED，直接打印可直接复制的重打命令。
5. `-Json` 输出机器可读结果，便于挂计划任务。

**用法**

```powershell
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\check-patch-state.ps1
powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\check-patch-state.ps1 -Json
```

脚本**只读**：不启动 IDMan.exe，不修改任何文件、注册表或 ACL。

---

## 附录 A：证据索引

| 主题 | 类型 | 位置 |
|---|---|---|
| 7 天门控 | 函数 | `FUN_00456BC0` @ VA 0x00456BC0（body 0x456BC0–0x456C76） |
| 门控值名 | 字符串 | `LastCheckQU` @ 0x006A11B4（读 0x00456C08，写 0x00487928） |
| 启动挂 UPDATE_TIMER | 函数 | `FUN_004772B0` @ VA 0x004772B0（调用者 `FUN_00477530`） |
| UPDATE_TIMER 分支 | 代码区 | VA 0x004878D3（KillTimer）／0x00487928（写 LastCheckQU）／0x0048794B（SetTimer 120 s）／0x00487974（异常串） |
| 定时器名 | 字符串 | `…CDownloaderDlg::OnTimer(nIDEvent = UPDATE_TIMER)` @ 0x006A2A98（xref 0x00487976） |
| 类 RTTI | 数据 | `.?AVCDownloaderDlg@@` @ 0x0077A370 |
| 更新线程 | 函数 | `FUN_00454DE0` @ VA 0x00454DE0 → `FUN_004BA1C0(1,0,1,…)` |
| CheckUpdtVM 写入 | 函数 | `FUN_0045A0B0` @ VA 0x0045A0B0（写点 0x0045A1AC；`CheckUpdtVM` @ 0x006A1590；`LstCheck` @ 0x006A03A0） |
| Quick Update 对话框体 | 函数 | `FUN_0042DFB0` @ VA 0x0042DFB0（body 0x42DFB0–0x42E6F1） |
| 更新器文件名 | 字符串 | `idmupdt.exe` @ 0x0069C0E0（xref 0x42E3C4, 0x42E524）；`idmupdt2.exe` @ 0x0069C100（xref 0x42E24F, 0x42E25B） |
| 更新 URL | 字符串 | `update.cgi` @ 0x0069C14C（xref 0x42E0CF）；`/data/fv/` @ 0x0069C124（xref 0x42E21E）；`/a/dc/`；`/data/729418032/` |
| 域名（XOR 0x0F） | 立即数 | VA 0x0042E1xx → `.internetdownloadmanager.com` → `www.` / `secure.` 前缀 |
| 更新编排 | 函数 | `FUN_004EC900` @ VA 0x004EC900（body 0x4EC900–0x4F005A），调用者 `FUN_004F6BF0` @ 0x004F6BF0 |
| 更新用户文本 | 字符串 | 0x006B8B1C `Quick Update`；0x006B8630 需注册；0x006BAEF8 下载失败；0x006B972C 找不到更新器；0x006AEBC0 无法启动更新器；0x006AE2F0 签名无效 |
| 提权判定 | 清单 | `requestedExecutionLevel level="asInvoker"` @ VA 0x00792350（`Tonec.IDM.IDMan`） |
| `RunAs` 真实用途 | 函数 | `FUN_0044B6F0` @ VA 0x0044B6F0（COM AppID `"Interactive User"`，与更新器无关） |
| 命令行开关 | 函数 | `FUN_00453BD0` @ 0x00453BD0 / `FUN_00453FC0` @ 0x00453FC0（`isupdt` @ 0x006A0A8C / 0x006A0B74） |
| 安装目录 ACL | 文件系统 | `Users = ReadAndExecute`；`Administrators = FullControl` |
| 提权写目录的经验证据 | 日志 | `work/idm-6.43b8/logs/elevcopy.txt` → `ELEVATED_COPY_OK` |
| 补丁定义 | 脚本 | `work/idm-6.43b8/scripts/patch_idm.py`（偏移 0x3782DC / 0x7C6C0） |

## 附录 B：明确未知项 / 局限性

1. **`idmupdt.exe` / `idmupdt2.exe` 当前不在安装目录**，无法验证其清单是否 `requireAdministrator`、也无法验证其替换 `IDMan.exe` 的具体顺序（是否先删后写、是否保留 `.del`）。§2 的“提权来自更新器自身清单”是**推断**，依据是 IDMan.exe 侧没有任何提权调用点。
2. `CheckUpdtVM` 的**读取方不在 IDMan.exe 内**（单 xref 仅写），其确切语义（是否影响服务器是否下发新版本）未知。
3. `FUN_0045A0B0` 的调用者未被 Ghidra 解析（有 1 个未解析 call 引用），因此 `CheckUpdtVM` 的**触发时机**只能确定为“启动/定时路径中的某处”。
4. VA 0x00486100–0x00488210 区间 Ghidra 未建立函数边界；§1.2(3) 的结论基于逐条指令与字节读取，不是反编译器输出。
5. 帮助文本称“每 2 周检查一次”（0x006B4AD8），与二进制 7 天门控不一致；以二进制为准，但官方可能在服务端侧做额外节流。
6. 本次分析**没有联网**，未实际请求任何 `internetdownloadmanager.com` 端点；URL 语义来自字符串与参数构造的静态还原。
