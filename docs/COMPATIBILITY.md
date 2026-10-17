# 版本兼容性与校验和（COMPATIBILITY）

## 1. 版本矩阵

| IDM 版本 | Build | 主程序文件版本 | 原始 `IDMan.exe` SHA-256 | 全补丁 SHA-256 | 大小 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| **6.43** | **b15** | `vCOUFP = 643b15` | `279CEED9AAA646650716EE326C0D996BE4CE5DB4B252CF5B2747F4938A7CE737` | `eca4afdc292f2f5dcb711f06939a2aafdbc35dd46945693555aee74daa45db67` | 6,201,712 B | ✅ **当前基线**（24 点，装机 MATCH） |
| **6.43** | **b8** | `6,43,8,2` | `74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8` | `527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552` | — | ✅ 已实测（P1–P3 最小集） |
| 6.43 其它 build | — | — | — | — | — | ⚠️ 未实测；先跑 `--scan` 看命中 |
| ≤ 6.42 | — | — | — | — | — | ❌ 不保证 |
| ≥ 6.44 | — | — | — | — | — | ❌ 未验证 |

### 1.1 b15 的历史中间产物（可用于逐级回滚核对）

| 说明 | SHA-256 |
| --- | --- |
| 24 点（最终基线） | `eca4afdc292f2f5dcb711f06939a2aafdbc35dd46945693555aee74daa45db67` |
| 摘掉 P15（23 点） | `329652204…` |
| 摘掉 P14（21 点） | `16289e9f…` |
| 摘掉 P13（20 点） | `2e9f12c0…` |
| 18 点（无 P10） | `f66da55fec007519acc637e1af7c025a53626784631f09e3a7af8796d1be4d60` |
| 17 点（仅 P9 站点 2） | `2879bda68d1ebb2cce0ed77c7975248a40de89f7b02e94fcb1831b270ba3c47a`（**已证不足**） |
| 16 点（P1–P7） | `bf853e81ddcdd3a4e41d0093f92404c67253adf7285b5feb022e1c4cd83029bc` |
| 15 点（P1–P6，回归锚点） | `18275A73A5ED8F78CA14219D50A5ABCA665654B2712B91840EE780B78C45A5E9` |
| 仅 P1–P4 | `57879FBF3499078CB2665C0C00E95BA8C3046611FCED5C47516A0196876386CA` |
| ~~含栈损坏 bug~~ | ~~`4B089ABBB770C9C38EDD9AEB4ED9D91A1243FE70724F6C21D153968E677C8CE6`~~ 已作废 |

> ⚠️ **不要把补丁后哈希当判据**：引擎升级会改变产出。判断「补丁是否完整」请用
> `verify_patched()` 的**自证式**校验（原始备份 + 同一引擎重跑）。

## 2. 第二目标 `IDMGrHlp.exe`（P8）

| 状态 | SHA-256 | 大小 |
| --- | --- | --- |
| 原始 | `B3B6281EA820EAE88192E50B30698CF4C3B8BC3D4376C978403BC9E18E5857C23` | 519,992 B |
| 补丁后 | `63197914f0b2c0f547c0ac572c85f5a1783cf7d228befddedb6bba78461351f4` | 519,992 B |

物理落地核对：`0x52A1` 与 `0x52C8` 均已是 `83 C4 10 31 C0 90`。

## 3. 发布物

```text
release/IDM-Activator.exe
  SHA-256  205C9B22DD50F0DDA9AA8E0CEC355AD08BB4CCEE94BD37CE4C2E6410C439071C
  Size     8,513,859 bytes
  PE       MZ / PE32+ (machine 0x8664, x64) / 7 sections / Subsystem 2
  Packer   PyInstaller onefile
```

校验方法：

```powershell
Get-FileHash .\release\IDM-Activator.exe -Algorithm SHA256
```

## 4. 运行环境

| 项 | 要求 |
| --- | --- |
| OS | Windows 10 / 11 (x64)；Windows 7 未验证 |
| IDM 架构 | x86 (PE32)，ImageBase `0x400000` |
| 权限 | 施加补丁需管理员（工具自动提权）；`--scan` / `--status` 不需要 |
| 文件系统 | NTFS（否则跳过「文件不可变」） |
| Python | 3.9+（仅标准库）；用 EXE 时无需 Python |
| 网络 | `--status` 会发 6 次 ping 做 DNS 屏蔽探测（只读，非零网络活动） |

## 5. 已知不兼容 / 限制

1. **非 NTFS 卷**：ACL 不可用 → 跳过「文件不可变」并明确报告。
2. **DNS-over-HTTPS / 代理 / VPN**：hosts 屏蔽可能失效；`--status` 会如实报告「仍解析到真实 IP」。
3. **`IDMGrHlp.exe` 不在 EXE 打包范围内**：P8 需单独跑 `src/scripts/apply_p8_idmgrhlp.py`。
4. **`DENY(W,D)` 与 Frida 冲突**：动态注入前需 `/remove:d Everyone`。
5. **b15 已删除 P3 的文案字面量**：P3 在 b15 上通常不命中 —— 这是**正常**，不是失败。
