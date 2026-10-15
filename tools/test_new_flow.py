# -*- coding: utf-8 -*-
"""端到端实测新的启用流程。

验证三点:
  1. 打开(启用)是否走"配置直写"通道, 从 8 分钟降到秒级;
  2. 注入是否发生在「WARP 尚未连接」的阶段 (即用户不会经历断网);
  3. 停用后再启用是否真的"无需注入"秒级完成。
"""
import os
import sys
import threading
import time

sys.path.insert(0, r"D:\C\Desktop\Cloudflare WARP")
os.chdir(r"D:\C\Desktop\Cloudflare WARP")

import warp_split as ws

RESULT = {}


def watch_phase():
    """后台采样: 记录「首次 Connected」时 daemon 里的规则数, 用来判断注入是否早于连接。"""
    t0 = time.time()
    while time.time() - t0 < 300:
        try:
            _, st = ws.warp(["status"], timeout=6)
            if "Connected" in st and "first_connected_rules" not in RESULT:
                n = len(ws.get_cli_excludes())
                RESULT["first_connected_rules"] = n
                RESULT["first_connected_at"] = round(time.time() - t0, 1)
                return
        except Exception:
            pass
        time.sleep(0.5)


def full_count():
    return len(ws.read_active_ranges())


print("=" * 70)
print(f"规则总数(含保留段): {full_count()}")
print("=" * 70)

# ---------- 第 0 步: 清空, 模拟"全新安装"的最坏情况 ----------
print("\n[0] 一键还原 (清空所有 CLI 排除), 模拟最坏起点")
t0 = time.time()
ws.restore()
print(f"    用时 {time.time()-t0:.1f}s  |  daemon 现有 {len(ws.get_cli_excludes())} 条")

print("\n[1] 启用分流 —— 应该走配置直写")
tw = threading.Thread(target=watch_phase, daemon=True)
tw.start()
t0 = time.time()
ws.enable_split()
el1 = time.time() - t0
RESULT["enable1"] = round(el1, 1)
print(f"\n    启用耗时: {el1:.1f}s")
print(f"    错误: {ws.state['error']}")
print(f"    enabled={ws.state['enabled']}  排除数={len(ws.get_cli_excludes())}")
print(f"    首次 Connected 时 daemon 已有规则数: "
      f"{RESULT.get('first_connected_rules', '未捕获')}  "
      f"(在 {RESULT.get('first_connected_at','-')}s)")

# ---------- 第 2 步: 停用 -> 再启用 (应无需注入) ----------
print("\n[2] 停用分流 (只断开, 不清规则)")
t0 = time.time()
ws.disable_split()
print(f"    用时 {time.time()-t0:.1f}s  |  规则仍保留 {len(ws.get_cli_excludes())} 条")

print("\n[3] 再次启用 —— 应该无需注入, 秒级完成")
t0 = time.time()
ws.enable_split()
el3 = time.time() - t0
RESULT["enable2"] = round(el3, 1)
print(f"\n    再次启用耗时: {el3:.1f}s")
print(f"    错误: {ws.state['error']}")
print(f"    排除数={len(ws.get_cli_excludes())}")

print()
print("=" * 70)
print("结果")
print("=" * 70)
print(f"  最坏起点启用 : {RESULT['enable1']}s   (旧版约 516s / 8分36秒)")
print(f"  再次启用     : {RESULT['enable2']}s   (旧版仍需重注全部规则)")
fcr = RESULT.get("first_connected_rules")
if fcr is None:
    print("  注入早于连接 : 未捕获")
else:
    print(f"  注入早于连接 : 首次 Connected 时规则数 {fcr} "
          f"-> {'是 [OK] 先注入后连接' if fcr > 5000 else '否 [!!] 仍是先连后注入'}")
