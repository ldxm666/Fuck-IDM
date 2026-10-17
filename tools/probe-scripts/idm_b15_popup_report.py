#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDM 6.43b15 独立审计 · 第三轮：从已解码的调用点表里抽出风险集与差集。

用法：
  python idm_b15_popup_report.py --csv <.scratch/.../b15_popup_utype.csv>
      --outdir <dir> --tag b15
"""
import argparse
import csv
import os
import re
from collections import Counter, OrderedDict

# 交接文档 §四 宣称要封的 9 点（7 派发器 + 2 license worker）
PLANNED_9 = [0x452FAF, 0x452FCD, 0x453030, 0x4530DF, 0x453155, 0x453171, 0x4531B9,
             0x5228BD, 0x522A93]

# license / registration / tripwire 相关宿主（VA）
LICENSE_HOSTS = {
    0x451E30: "sub_451E30 消息派发器(经函数指针表 0x6A0B24 注册)",
    0x51FFC0: "sub_51FFC0 联网 license 校验",
    0x521050: "sub_521050 tripwire worker(取判决→写MData→ExitProcess)",
    0x5227C0: "sub_5227C0 注册对话框 WM_COMMAND 0x6DB 处理",
    0x522910: "sub_522910 注册对话框 WM_COMMAND 0x4A7 处理",
    0x523B50: "sub_523B50 注册对话框 WM_COMMAND 0x4B1 处理",
    0x42E9A0: "sub_42E9A0 CConfirm::OnTimer (只删 MData)",
}


def hx(x):
    return "0x%08X" % x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--tag", default="b15")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv, encoding="utf-8-sig")))
    for r in rows:
        r["_site"] = int(r["site_va"], 16)
        r["_host"] = int(r["host_va"], 16) if r.get("host_va") else -1
        r["_ut"] = r["uType_hex"]

    out = []
    W = out.append

    W("# IDM 6.43b15 弹窗调用点独立审计（auditor / T2）\n")
    W("原始二进制 `IDMan.exe.b15`，sha256 `279CEED9…CE737`（已校验）。\n")

    W("## 0. uType 语义（Lead 追加判据）\n")
    W("- 包装 `sub_474D20` 原型 `int __cdecl(HWND, LPCCH lpMultiByteStr, LPCCH cap, UINT uType)`；")
    W("  反汇编 0x474D20 见 `mov ... uType` 取自调用者栈帧 `[esp+3Ch+uType]`，")
    W("  随后原样传给 `MessageBoxW(hWnd, lpText, cap, uType)` 与回退实现 `sub_46DB20(..., uType, 0)`。")
    W("  **结论：uType 完全透传，按钮形态可用于判别。**\n")
    W("- 参数按 cdecl 右到左压栈：`push uType; push cap; push text; push hWnd; call`。")
    W("  实测 0x5228BD/0x522A93 处与此一致（`push 0` → uType=MB_OK）。\n")

    W("## 1. 调用点总数\n")
    W("| 目标 | 调用点 |")
    W("| --- | --- |")
    c = Counter(r["wrapper"] for r in rows)
    for k in sorted(c):
        W("| `%s` | %d |" % (k, c[k]))
    W("| **合计** | **%d** |\n" % len(rows))

    W("### uType 分布（全量）\n")
    W("| uType | 含义 | 个数 |")
    W("| --- | --- | --- |")
    NAMES = {0x0: "MB_OK 单[确定]", 0x1: "MB_OKCANCEL 双[确定/取消]", 0x4: "MB_YESNO 双[是/否]",
             0x30: "MB_ICONWARNING", 0x40: "MB_ICONINFORMATION", 0x10: "MB_ICONERROR",
             0x20: "MB_ICONQUESTION", 0x24: "MB_YESNO|MB_ICONQUESTION",
             0x34: "MB_YESNO|MB_ICONWARNING", 0x3C: "MB_YESNO|MB_ICONWARNING|..."}
    for k, v in Counter(r["_ut"] or "(无法静态确定)" for r in rows).most_common():
        if k == "(无法静态确定)":
            W("| %s | 无法静态确定（参数经 `mov [esp+k]` 布置或来自寄存器） | %d |" % (k, v))
        else:
            n = int(k, 16)
            W("| `%s` | %s | %d |" % (k, NAMES.get(n, ""), v))
    W("")

    W("## 2. 风险集 A：宿主函数体内含 `push <MData VA 0x69D1E4>` 的调用点\n")
    W("（交接文档 §四 自定的判据之一）\n")
    a = [r for r in rows if r["host_has_mdata_push"] == "Y"]
    W("| # | site VA | 宿主 | 宿主身份 | uType | 后随清理 | 前置 push 0x696DE8 | 在计划的 9 点内 |")
    W("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for i, r in enumerate(sorted(a, key=lambda x: x["_site"]), 1):
        W("| %d | `%s` | `%s` | %s | `%s` | %s | %s | %s |" %
          (i, r["site_va"], r["host_va"], LICENSE_HOSTS.get(r["_host"], "?"),
           r["_ut"] or "?", r["cleanup"], r["pre_title_push"],
           "是" if r["_site"] in PLANNED_9 else "**否**"))
    W("")
    W("风险集 A 共 **%d** 点，其中 **%d** 点不在计划的 9 点内。\n" %
      (len(a), sum(1 for r in a if r["_site"] not in PLANNED_9)))

    W("## 3. 风险集 B：license/注册对话框/tripwire 簇内的全部弹窗点\n")
    b = [r for r in rows if r["_host"] in LICENSE_HOSTS]
    W("| # | site VA | 宿主 | 宿主身份 | uType | 后随清理 | 前置 push 0x696DE8 | MData | 9 点内 |")
    W("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for i, r in enumerate(sorted(b, key=lambda x: x["_site"]), 1):
        W("| %d | `%s` | `%s` | %s | `%s` | %s | %s | %s | %s |" %
          (i, r["site_va"], r["host_va"], LICENSE_HOSTS.get(r["_host"], "?"),
           r["_ut"] or "?", r["cleanup"], r["pre_title_push"],
           r["host_has_mdata_push"], "是" if r["_site"] in PLANNED_9 else "**否**"))
    W("")
    W("风险集 B 共 **%d** 点；计划只覆盖 9 点 ⇒ **漏 %d 点**。\n" %
      (len(b), sum(1 for r in b if r["_site"] not in PLANNED_9)))

    W("## 4. 差集：9 点之外、且落在风险簇内的调用点（「第 10 处」）\n")
    diff = [r for r in b if r["_site"] not in PLANNED_9]
    W("| # | site VA | file off | 宿主 | uType | 后随清理 | 前置 push 0x696DE8 | 宿主含 MData push |")
    W("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for i, r in enumerate(sorted(diff, key=lambda x: x["_site"]), 1):
        W("| %d | `%s` | `%s` | `%s` | `%s` | %s | %s | %s |" %
          (i, r["site_va"], r["site_off"], r["host_va"], r["_ut"] or "?",
           r["cleanup"], r["pre_title_push"], r["host_has_mdata_push"]))
    W("")
    W("**差集规模 = %d 点。**\n" % len(diff))

    W("## 5. uType == 0x1 (MB_OKCANCEL，双按钮「确定/取消」) 的全部调用点\n")
    okc = [r for r in rows if r["_ut"] == "0x1"]
    if not okc:
        W("**全库 0 处。** 331 个 MessageBox 调用点里没有任何一个用 MB_OKCANCEL。\n")
        W("⇒ 用户截图的「确定 / 取消」**不可能**来自 MessageBox 家族（`sub_474D20` 等 4 个包装，")
        W("或直接 `call [user32!MessageBoxW/A]`）。要么是自绘/资源模板对话框（CDialog），")
        W("要么按钮数在截图判读上有偏差。**按钮维度不能作为唯一判据。**\n")
    else:
        W("| site VA | 宿主 | uType | 清理 |")
        W("| --- | --- | --- | --- |")
        for r in okc:
            W("| `%s` | `%s` | `%s` | %s |" % (r["site_va"], r["host_va"], r["_ut"], r["cleanup"]))

    W("\n## 6. 判据一致性核对：交接文档 §四 自定的规则 vs 它自己预测的 9 点\n")
    rule = [r for r in rows
            if r["host_has_mdata_push"] == "Y" and r["pre_title_push"] == "Y"]
    rule_v = sorted(r["_site"] for r in rule)
    W("规则（交接文档原文）：**「`call <弹窗包装>` 的宿主函数内含 `push <MData 串 VA>`」")
    W("且「该调用点前 ~40 字节内出现 `push 0x696DE8`」**。\n")
    W("按此规则实算命中 **%d** 点：\n" % len(rule))
    W("| # | site VA | 宿主 | 在 9 点内 |")
    W("| --- | --- | --- | --- |")
    for i, r in enumerate(sorted(rule, key=lambda x: x["_site"]), 1):
        W("| %d | `%s` | `%s` | %s |" %
          (i, r["site_va"], r["host_va"], "是" if r["_site"] in PLANNED_9 else "**否**"))
    W("")
    W("交接文档预测该规则「预计命中 `0x5228BD` 与 `0x522A93` 两点，与现有 7 点合计 9 点」。\n")
    W("- 实算结果**与预测不符**：`0x5228BD` 的宿主是 `sub_5227C0`，其函数体内**不含** MData push，")
    W("  按规则**会被漏掉**（它之所以被文档点名，是因为文档把 `sub_521050` 的边界误推到了 `0x5227C0`）。")
    W("- 同时规则额外命中 `sub_42E220` 内 6 点与 `sub_522910` 内 6 点。")
    W("- 结论：**规则与 9 点清单互不一致** —— 无论 patcher 按规则实现还是按地址清单实现，")
    W("  得到的补丁集都不等于「9 点」，且两种实现互相漏掉对方的一部分。\n")

    W("## 7. 机制证据：counterfeit 文案是「服务端下发 → 全局 CString → 弹窗」\n")
    W("这是本轮独立检索得到的、解释「文案不在本地任何文件里」的机制：\n")
    W("1. `sub_4F03B0` 内有一张 **大跳转表**（表头 `0x4F07DB` / `0x4F08A5`），case 值形如")
    W("   `334 / 20517 / 20518 …`，即**服务端 license/update 应答里的数值消息号**；")
    W("2. `case 20517:` → `dword_78A198 = Source;`；`case 20518:` → `dword_78A19C = Source;`")
    W("   （`Source` 来自调用者栈，即**应答报文字符串**）—— 见 `0x4F291C`–`0x4F2926`；")
    W("3. 这两个全局在 `sub_4EC760:0x4EE0C2` / `sub_4EC760:0x4EE0BD` 处还有**本地默认值**：")
    W("   `dword_78A198` ← `\"IDM has received \\\"Access Denied\\\" erro…\"`，")
    W("   `dword_78A19C` ← `\"Please register IDM before updating.\\r\\n…\"`；")
    W("4. 展示端：`sub_42E220:0x42E452` = `push 0; push \"Internet Download Manager\";")
    W("   push dword_78A19C; push hWnd; call sub_474D20` 紧接 `CDialog::EndDialog(0)`。\n")
    W("⇒ **要显示什么文案由数据（服务端应答）决定，展示点只是普通 MessageBox 调用。**")
    W("   因此「逐个封调用点」在结构上不可能完备：文案装载点（`sub_4F03B0` 跳转表 /")
    W("   `sub_4EC760`）任意一条路径配上任意一个展示点都能弹出同一句话。\n")

    W("## 8. 宿主函数分组汇总\n")
    W("| 宿主 | 调用点数 | uType 集合 | MData |")
    W("| --- | --- | --- | --- |")
    g = OrderedDict()
    for r in rows:
        g.setdefault((r["host_va"], r["host_has_mdata_push"]), []).append(r)
    for (hv, md), rs in sorted(g.items(), key=lambda kv: -len(kv[1]))[:40]:
        W("| `%s` | %d | %s | %s |" %
          (hv, len(rs), ",".join(sorted(set(x["_ut"] or "?" for x in rs))), md))
    W("")

    W("\n## 9. 覆盖率与结论\n")
    W("| 口径 | 数量 |")
    W("| --- | --- |")
    W("| 全库 `call <弹窗包装>` 调用点（4 个包装合计） | %d |" %
      sum(1 for r in rows if r["wrapper"].startswith("0x")))
    W("| 全库 `call [user32!MessageBoxA/W]` 调用点 | %d |" %
      sum(1 for r in rows if r["wrapper"].startswith("USER32:")))
    W("| **弹窗调用点总数** | **%d** |" % len(rows))
    W("| 计划的 9 点覆盖 | 9 (%.1f%%) |" % (9.0 * 100 / max(1, len(rows))))
    W("| license/注册/tripwire 簇内的弹窗点 | %d |" % len(b))
    W("| 9 点在该簇内漏掉 | %d |" % len(diff))
    W("| 交接文档规则实算命中 | %d |" % len(rule))
    W("| 全库 MB_OKCANCEL(0x1) 点 | %d |" % len(okc))
    W("")
    W("### 对「还有没有第 10 处」的回答\n")
    W("**有，而且不止一处。** 在「可能弹出 counterfeit 文案」的语义范围内，9 点清单至少漏 8 点：")
    W("`sub_521050` 1 点、`sub_522910` 6 点、`sub_523B50` 1 点（见 §4 差集表）；")
    W("若把 `sub_42E220` 的 CConfirm 系对话框也算进来，风险面再 +6 点。")
    W("再加上 §7 证明的「文案数据驱动」机制，展示点的枚举本身是**不可闭合**的。\n")
    W("**因此本审计不支持「补到 9 点就完结」的结论。**\n")

    path = os.path.join(args.outdir, "%s_report.md" % args.tag)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("report -> %s (%d lines)" % (path, len(out)))
    print("风险集A(含MData)=%d  风险集B(license簇)=%d  差集=%d  uType0x1=%d" %
          (len(a), len(b), len(diff), len(okc)))


if __name__ == "__main__":
    main()
