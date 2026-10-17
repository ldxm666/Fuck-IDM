# Fuck IDM — 完整源码与实现细节

> 目标程序：**Internet Download Manager 6.43 Build 15**（PE32 x86，ImageBase `0x400000`）
> 最终基线：**`IDMan.exe` 24 点补丁 + PE CheckSum 修正** = `b6c454530184d9c69b204219b9b36ca0251fd1988138f83a460f5f8d8890338a`（6,201,712 B）
> `IDMGrHlp.exe`：**P8** = `63197914f0b2c0f547c0ac572c85f5a1783cf7d228befddedb6bba78461351f4`
> 实测结论：counterfeit 弹窗、注册框、MData 写入、`IDM is corrupt` —— **全部不再出现**

---

## 1. 地址换算铁律（先看这个）

| 区段 | 换算 |
|---|---|
| `.text` | **file = VA − 0x400C00** |
| `.rdata` | file = VA − 0x401A00 |
| `.data` | file = VA − 0x402800 |

**任何地址必须双向反算校验**（VA→file、file→VA），最终以 **old-bytes 断言**为准。

---

## 2. 最终补丁清单（24 点 + CheckSum）

| 组 | file 偏移 | old → new | 作用 |
|---|---|---|---|
| P1 | `0x379524` | 4B → `00 00 00 00` | 注册提醒门控 `.data` 全局 `0x77BD24`（`!=0` 提醒 / `==0` 抑制） |
| P2 | `0x29545E` | `%b/%d/%Y` → `%b/%d/9999` | 到期日显示 |
| P3 | `0x7C8D0` | — | 试用 nag |
| P4 | `0x4D252` | — | 序列号**格式**门（`strlen==23` + 3 个 `-`）失败路径改道为"有效" |
| P5 | 4 点 | — | 早期补丁组 |
| P6 | 7 点（`0x523AF/523CD/52430/524DF/52555/52571/525B9`） | — | license 弹窗族 |
| P7 | `0x68060` | `6a 08 e8` → `31 c0 c3` | 线程 `sub_468C60` 封口（case `0x1505`） |
| **P9a** | `0x66AD9` | `ff 15 90 50 69 00` → `83 c4 18 90 90 90` | `RegSetValueExA("MData")`（stdcall，6 参=24B 清栈） |
| **P9b** | `0x120A54` | 同上 | 同上（**实际生效的写入点**，`sub_521050`） |
| **P10** | `0x75444` | `E8 D7 EC FF FF` → `31 C0 90 90 90` | counterfeit 显示点（**命令行 `/d` 路径**，cdecl 无需补清栈） |
| **P11** | `0x79E49` | `E8 D2 A2 FF FF` → `31 C0 90 90 90` | 同上（`sub_47AA00`，**潜在路径**，动态零命中，预防性） |
| **P13** | `0x525D2` | `0f 84 23 01 00 00` → `e9 24 01 00 00 90` | **启动路径注册框**：`je`→`jmp`，`DoModal` 根本不调用 |
| **P14-A** | `0x74120` | `6a ff 68 78 87 66 00` → `e9 bf b1 07 00 90 90` | **wrapper 入口跳板** → cave |
| **P14-B** | `0xEF2E4` | `CC×44` → 26B 桩 | **uType 短路桩**（见下） |
| **P15** | `0x94364` | `6a 00 8d 8d 1c` → `e9 f0 ff ff ff` | **下载路径注册框**：case 体跳兄弟分支，`DoModal` 不调用 |
| **CheckSum** | PE 头 `0x148` | 重算写回 | **修 `IDM is corrupt`**（原厂 `0x005F549C` 自洽；打补丁后必须重算） |

### P14 cave 桩（26 字节，file `0xEF2E4` / VA `0x4EFEE4`）
```
8b 44 24 10        mov  eax,[esp+0x10]     ; uType（第 4 参）
3d 30 10 04 00     cmp  eax,0x41030
75 03              jne  .orig
31 c0              xor  eax,eax
c3                 ret                     ; ★ 裸 ret（cdecl，调用方 add esp,0x10）
6a ff              push -1                 ; .orig：原序言重放
68 78 87 66 00     push 0x668778
e9 29 4e f8 ff     jmp  0x474D27           ; 回原序言之后
```
**原理**：`sub_474D20` 是 IDM 弹窗的**唯一出口**（253 处调用都经它）；`uType==0x41030`（单按钮+警告+置顶）就是 counterfeit 弹窗签名（全库 **9 处**）⇒ **一处封全 + 未来任何新路径**。

---

## 3. 关键 Hook 点 / 地址表

| 用途 | 地址 |
|---|---|
| 弹窗包装（唯一出口） | `sub_474D20` VA `0x474D20` / file `0x74120`；序言 7B，恢复点 `0x474D27` |
| counterfeit 显示点（命令行） | RVA `0x76049` / file `0x75444` |
| counterfeit 显示点（**浏览器**） | RVA `0x99883` / file `0x98C7E` |
| counterfeit 显示点（全 9 处 `push 0x41030`） | `0x75485 0x76038 0x76304 0x7AA3C 0x7D104 0x7E17D 0x84C0D 0x84EF8 0x99870` |
| 注册框创建点（MFC 通用） | RVA `0x212D1D`，dlgProc `0x21269E` |
| 注册框 ctor | VA `0x521C00`（RVA `0x121C00`） |
| 注册框 DoModal | VA `0x612DBF`（RVA `0x212DBF`） |
| 启动路径门控 | file `0x525D2`（`cmp esi,ebx / je`） |
| 下载路径门控 | file `0x94364`（case 体，宿主 `sub_48F7D0` 主窗口过程） |
| 序列号深层校验失败提示 | RVA `0x122A98`（"您输入了错误的序列号"，**不封**） |
| MData 写入 | file `0x120A54`（`sub_521050`）· file `0x66AD9`（`sub_466EE0`，非活路径） |
| 许可标志 | `.data` `byte_788CF4`（"许可有效"，30 处引用 / 7 函数） |
| HKCU/HKLM 模式选择 | `.data` `dword_788CCC`（写入点 RVA `0x51F01` `mov [0x788CCC],edi`，`edi` 硬编码 1） |
| 20 分钟定时器 | `id=0x25` / 1200000ms，setter `sub_486680` @ `0x487868` |
| 10s / 30s 定时器 | `id=0x18` @`0x87DF8` · `id=0x4` @`0x88206` |
| 字符串解密器（**勿改**） | `sub_52DBC0`（8 字节分组密码，9 个解密包装调用它） |
| `CProtection` vftable | `0x6A1F94`（**运行期解密字符串** ⇒ 静态 grep 抓不到值名） |

---

## 4. 方法学（踩过的坑，务必先读）

1. **「能否一处封全」取决于该点是否为唯一出口**
   - wrapper `sub_474D20` **是**（253 处都经它）⇒ 一处封全（P14）
   - 注册框 ctor `0x521C00` **不是**（`DoModal` 由两条路径各自调用）⇒ 封 ctor 会让 `DoModal` 展示未构造对象 ⇒ **必崩** ⇒ 只能逐路径封（P13/P15）
2. **验证必须走用户真实工作流** —— 用 `IDMan.exe /d` 代替浏览器点下载 ⇒ 走了不同显示点（`0x76049` vs `0x99883`）⇒ 连续多轮"假通过"
3. **清栈责任只能从 `call` 后的字节判断**（E13 三步法：数 push → 看 call 后有无 `add esp`/`mov esp,ebp` → 看返回值是否被消费）
4. **锚点/校验过严 = 假阴性**（P9 的 `RegFlushKey`、P10 的 `+5 必须 83 c4 10` 都因此误拒真站点）
5. **幂等签名不得包含补丁自己要改的字节**（否则二次扫描认不回自己、假报 clean）
6. **「零命中」不能当「有效」**；**「没看到 X」不能排除「X 本来不会发生」**
7. **抑制点与下游副作用必须同时埋点**，才能区分「被拦」与「没发生」（P14 的证明方式）
8. **写二进制后必须校验文件大小 + 哈希**；**PowerShell 变量名大小写不敏感**（`$b`/`$B` 曾导致 exe 被写成 26 字节）
9. **IDM 是单实例** ⇒ spawn 探针前必须确认无用户实例，否则改 attach
10. **地址必须标明 VA 或 RVA 之一**，并用另一形态反算校验

---

## 5. 目录结构

```
bin/dist/            IDM-Activator.exe（成品工具）
src/                 idm_engine.py（补丁引擎，含全部 finder + CheckSum 重算）
                     IDM-Activator.py / IDM-Unlock.py / scripts/
docs/patches/        permanent-plan.md（完整补丁表 + 抗混淆锚点）+ 14 篇分析
docs/plans/          p8/p9/p10/p12 方案（hook 点设计、cave 字节、锚点推演）
docs/registry/       idm_6.43b15_registry.md（哈希表 / 铁律 E1–E14 / 36 条教训 / 开放项）
docs/probe-evidence/ FINDINGS.md + 原始探针 JSONL
docs/verify-logs/    验证日志
tools/               探针脚本（idm_popup_probe.js / run_probe.py）+ 提权工作流
```

---

## 6. 回滚

备份链（每级均为 6,201,712 B 完整镜像）：

| 级别 | sha256 |
|---|---|
| 24 点 + CheckSum（**当前**） | `b6c45453…` |
| 24 点（CheckSum 未修） | `eca4afdc…` |
| 23 点（+P15 前） | `32965204…` |
| 21 点（+P13） | `16289e9f…` |
| 20 点 | `2e9f12c0…` |
| 原始 pristine | 见 `bin/` |

回滚 = 把对应备份覆盖回 `C:\Program Files (x86)\Internet Download Manager\IDMan.exe`（需先关 IDM）。

---

## 7. 已知副作用 / 开放项

- **P14 会静音全部 9 处 `uType=0x41030` 弹窗** —— 其中若有同类型的**合法警告**也会一起消失（未逐一验证）。
- **P13/P15 让 IDM 在"未注册"状态下正常启动**，**不改变**内部注册判定 ⇒ 若某功能真需要"已注册"仍可能受限（未逐一验证）。
- 深层序列号校验函数**未定位**（`sub_52E2E0` 只负责读+解密许可快照，判定在其调用者 `sub_4EC760`）。
- 许可快照键 `HKCU\...\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}` **不存在**，且 IDM 不会自建（`sub_4EC760` 内注册表写入 API 0 命中）。
- 是否存在**第 3 条注册框路径**未排除（用 `0x521C00` 作 hook 点枚举即可判定）。

---

## 8. 环境

- Windows 10/11 x64；IDM 6.43 Build 15（PE32）
- 需管理员权限修改 `Program Files (x86)` 下的文件
- 探针依赖：Frida（`frida-server` 需与设备 ABI 匹配）；提权通道见 `tools/workflows/run-elevated.ps1`
- 加固（可选）：防火墙目的限定出站阻断 `IDMan.exe`/`IDMGrHlp.exe` → `67.18.0.0/16,169.62.35.21`
