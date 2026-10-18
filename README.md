# Fuck IDM

IDM 6.43 一键解锁工具（Windows）。把「试用 / 未注册」变成完整版，并压掉反复弹的干扰弹窗。

> 仅供个人学习研究，请支持正版。

---

## 系统要求

- Windows 10 / 11（32 位、64 位都行）
- 已安装 Internet Download Manager 6.43（b15 / b8 已验证）
- 需要管理员权限
- 用预编译 EXE 时**不需要**装 Python

## 下载

到 [Releases](https://github.com/ldxm666/Fuck-IDM/releases) 下载最新的 `IDM-Activator.exe`。

## 使用

### 1. 先看会改什么（只读，不需要管理员）

```
IDM-Activator.exe --scan
```

### 2. 一键解锁

右键 `IDM-Activator.exe` → **以管理员身份运行**，或命令行：

```
IDM-Activator.exe --activate
```

会自动提权、备份原文件、打补丁、修 PE 校验和。

### 3. 看结果

```
IDM-Activator.exe --status
```

期望：补丁点全部「已到位」，且 `期望哈希 == 实际哈希`。

### 4. 浏览器集成弹窗（可选）

`IDMGrHlp.exe` 那一侧要单独打一次（EXE 已内置该引擎，源码方式用）：

```
python src\apply_p8_idmgrhlp.py --apply
```

## 回滚

```
IDM-Activator.exe --uninstall
```

或手动把安装目录里的 `IDMan.exe.bak-original` 复制回 `IDMan.exe`。

## 常见问题

**报 `WinError 740`？** 没有管理员权限，右键「以管理员身份运行」。

**报「文件被占用」？** 先彻底退出 IDM（托盘图标右键 → 退出），包括浏览器拉起的 `-Embedding` 实例。

**解锁后 IDM 打不开？** 用 `--uninstall` 回滚，或复制 `IDMan.exe.bak-original` 回去。

**还弹 `IDM is corrupt`？** v1.0.2 起已根治。若仍弹，用 `--status` 确认 P16 / P17 是「已到位」。

## 免责声明

本项目仅用于技术研究与学习交流，请在 24 小时内删除并购买正版授权。
使用本工具造成的一切后果由使用者自行承担。
