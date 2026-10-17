# 使用手册（USAGE）

## 0. 三十秒版

```powershell
.\release\IDM-Activator.exe --scan        # 只分析，不动手
.\release\IDM-Activator.exe --activate    # 一键解锁（UAC 自动提权）
.\release\IDM-Activator.exe --status      # 验收
```

回滚：

```powershell
.\release\IDM-Activator.exe --uninstall
```

---

## 1. 三种使用形态

| 形态 | 适用场景 | 入口 |
| --- | --- | --- |
| 预编译 EXE | 不想装 Python，只想用 | `release/IDM-Activator.exe` |
| 源码运行 | 想审计代码、想改锚点 | `src/IDM-Activator.py` |
| 最小可用集 | 老版本 / 只想改两处 | `src/IDM-Unlock.py` |

### 1.1 EXE 形态

```powershell
# 双击 = --activate
.\release\IDM-Activator.exe
```

日志：`%LOCALAPPDATA%\IDM-Activator\activator.log`

### 1.2 源码形态

```powershell
python .\src\IDM-Activator.py --scan
python .\src\IDM-Activator.py --activate
```

> 需要 **Python 3.9+**，无第三方依赖。`--activate` 会自动弹 UAC 重新以管理员启动自己。

### 1.3 最小可用集

```powershell
python .\src\IDM-Unlock.py --scan      # 默认就是 scan
python .\src\IDM-Unlock.py --apply     # P1 + P2 + P3
python .\src\IDM-Unlock.py --restore
```

可选开关：`--no-expiry`（跳过 P2）、`--no-nag-kill`（跳过 P3）、`--json`（机器可读）。

---

## 2. `--activate` 到底改了什么（可核查清单）

| # | 动作 | 作用域 |
| --- | --- | --- |
| 1 | 停止 `IDMan.exe` / `idmBroker.exe` | 进程 |
| 2 | 施加 P1–P15，并用**备份自证**校验补丁完整性 | `IDMan.exe` + `.bak-original` |
| 3 | 清 `MData`（遍历 CLSID 树，双 hive 双视图）+ 清缓存校验判决 | `HKCU` / `HKLM` |
| 4 | 写 `Serial` / `FName` / `LName` / `Email` | `HKLM`（32 位视图）+ `HKCU` |
| 5 | 写 hosts 屏蔽块 + `ipconfig /flushdns` | `...\drivers\etc\hosts` |
| 6 | 设 `DENY Everyone (WD,DE)` 并回读验证 | `IDMan.exe` 的 ACL |
| 7 | **删除**旧守护计划任务与 Run 自启项 | 任务计划 / `HKCU`·`HKLM` Run |
| 8 | 汇总并打印「无守护、无弹窗、可长期使用」 | — |

**不会做的事**：不装计划任务、不写 Run 自启、不改 IDM 的其它设置。

---

## 3. 参数详解

### 3.1 `IDM-Activator.exe`

| 参数 | 说明 | 需要管理员 |
| --- | --- | --- |
| （无） | 等价 `--activate` | ✅ |
| `--activate` | 一键解锁 | ✅ |
| `--status` | 只读状态：补丁点、注册表、hosts 生效行数、ACL、DNS 探测 | ❌ |
| `--scan` | 只读分析：会改哪里、当前值是什么 | ❌ |
| `--uninstall` | 完全还原（幂等） | ✅ |
| `--no-lock` | 跳过 ACL 不可变（调试用） | ✅ |
| `--serial S` | 指定序列号 | ✅ |
| `--fname` / `--lname` / `--email` | 自定义注册信息 | ✅ |
| `--install-dir D` | 指定安装目录（**不会**因此放开系统级改动） | ✅ |
| `--allow-system-changes` | **危险**：允许在非实机目录下也做系统级改动 | ✅ |
| `--no-guard` | 历史兼容，空操作 | — |
| `--guard` | 打印「守护模型已移除」并 exit 0 | — |

### 3.2 `idm_engine.py`（作为库使用）

```python
import sys; sys.path.insert(0, "src")
import idm_engine

data = open(r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe", "rb").read()
pe = idm_engine.PE(data)

# 定位（只读）
sites = idm_engine.build_all_sites(pe)
for s in sites:
    print(f"{s.name:28s} {s.label}  off=0x{s.off:X}")

# 施加（自动备份 .bak-original，幂等）
result = idm_engine.apply_all(r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe")
print(result)
```

---

## 4. P8：`IDMGrHlp.exe`（需单独一次）

```powershell
# 幂等检查（不写文件）
python .\src\scripts\apply_p8_idmgrhlp.py --check

# 施加（自动 .p8bak 备份，含 old-bytes 断言）
python .\src\scripts\apply_p8_idmgrhlp.py

# 带期望哈希校验（推荐）
python .\src\scripts\apply_p8_idmgrhlp.py --expect-sha256 63197914f0b2c0f547c0ac572c85f5a1783cf7d228befddedb6bba78461351f4
```

退出码：`0` = 成功/已在位，`2` = 前置断言失败，`3` = 哈希不符。

---

## 5. 验收

### 5.1 UI 验收

1. 打开 IDM → `帮助 → 关于 IDM`
2. 应看到 `6.43 Build 15 Full` 与 `本软件许可证的到期时间为 Dec/31/9999`
3. 浏览器点一个下载链接 → **不应**出现注册框 / counterfeit 弹窗
4. 等 90 秒（老版本弹窗定时器周期）再确认一次

### 5.2 命令行验收

```powershell
.\release\IDM-Activator.exe --status
```

关注四项：

| 项 | 期望 |
| --- | --- |
| 补丁点 | 24 点全在位 |
| hosts 屏蔽 | `生效 6/6`（**注释行不算数**） |
| ACL | 存在 `DENY Everyone (WD,DE)` |
| DNS 探测 | 6 个域名均解析到 `0.0.0.0` |

> ⚠️ DNS 探测必须看 `ping` 结果。`Resolve-DnsName` 会读 hosts 并返回 `0.0.0.0`，给出**假通过**。

---

## 6. 排障

### 6.1 `--status` 报「存在 MData 残留」

**不代表激活失败**。`MData` 是 IDM 反复覆盖的注册表值，本身无害；
P5 已让 tripwire 无法自杀，P6/P7/P8/P10/P11/P14 已让弹窗无法显示。
可以再跑一次 `--activate` 清理，也可以忽略。

### 6.2 hosts 写了但 `ping` 仍解析到真实 IP

1. 执行 `ipconfig /flushdns`（工具已自动做，但手动确认一次）
2. 检查是否有 DNS-over-HTTPS / 代理 / VPN 绕过 hosts
3. 检查 hosts 行首是否被 `#` 注释（`--status` 只统计真正生效的行）

### 6.3 更新之后补丁没了

说明 ACL 没生效（可能是非 NTFS 卷，或更新包以 TrustedInstaller 身份写入）。
重新跑 `--activate`，并确认 `--status` 里 ACL 一栏为「已锁定」。

### 6.4 Frida 注入失败（`0x00000005`）

`DENY(W,D)` 阻止了注入（Frida 需要该 exe 的写权限）：

```powershell
icacls "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" /remove:d Everyone
# …… 观测结束
icacls "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" /deny "*S-1-1-0:(WD,DE)"
```

### 6.5 「点取消就退出」

需要 P13（启动路径）与 P15（下载路径）同时在位。跑 `--scan` 确认两点都命中；
b8 及更早版本可能没有这两处的对应形态。

### 6.6 想完全回到出厂状态

```powershell
.\release\IDM-Activator.exe --uninstall
```

然后重新安装 IDM 官方安装包（最彻底）。

---

## 7. 开发/调试提示

- **`--install-dir` 不会放开系统级改动**。这是刻意的护栏：曾因在 scratch 副本上跑
  `--activate` 而清空了实机注册表、还原了实机 hosts、误杀另一个进程。
- 需要动态观测（Frida / x64dbg）时，先 `/remove:d` 解除 ACL。
- **凡会 spawn `IDMGrHlp*` / `IDMan` 的测试必须串行** —— helper 进程也属于 IDM 独占范围，
  与 soak / 验收并发会让整轮结果作废。
- `IDMan.exe` 会被「瞬时独占锁定」（连重命名都失败，但没有任何 IDM 进程）：
  可写探测 → 退避重试（2s × 15）→ 仍失败再用 Restart Manager API 报出持有者 pid。
  **不要直接杀进程。**
