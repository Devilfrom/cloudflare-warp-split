# -*- coding: utf-8 -*-
"""验证: WARP 处于 disconnect 状态时, tunnel ip add-range 是否仍能写入并保留。

若成立, 就可以把「注入规则」挪到「连接 WARP」之前 —— 注入期间网络保持直连,
用户完全无感, 彻底消除"注入时断网"的问题。
"""
import subprocess
import sys
import time

CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
TEST_CIDR = "203.0.113.0/24"   # TEST-NET-3, 绝不会与中国 IP 列表冲突


def run(args, timeout=25):
    t0 = time.time()
    p = subprocess.run([CLI] + args, capture_output=True, text=True,
                       timeout=timeout, errors="ignore")
    dt = time.time() - t0
    out = (p.stdout + p.stderr).strip().replace("\n", " | ")
    print(f"  [{dt:5.2f}s] warp-cli {' '.join(args)}\n         -> rc={p.returncode} {out[:150]}")
    return p.returncode, p.stdout + p.stderr


def count_excludes():
    _, out = run(["tunnel", "ip", "list"])
    return sum(1 for ln in out.splitlines() if "(CLI exclude)" in ln)


print("=" * 68)
print("步骤 0: 记录当前状态")
print("=" * 68)
run(["status"])
base = count_excludes()
print(f"  当前 exclude 条数: {base}")

print()
print("=" * 68)
print("步骤 1: disconnect  (断开隧道, 网络回到直连)")
print("=" * 68)
run(["disconnect"])
time.sleep(2)
run(["status"])
n_after_dc = count_excludes()
print(f"  断开后 exclude 条数: {n_after_dc}  (规则是否保留: "
      f"{'是 [OK]' if n_after_dc >= base else '否 [!!]'})")

print()
print("=" * 68)
print("步骤 2: 断开状态下注入测试规则")
print("=" * 68)
t0 = time.time()
run(["tunnel", "ip", "add-range", TEST_CIDR])
batch = time.time() - t0
print(f"  单条耗时: {batch:.2f}s")

_, listing = run(["tunnel", "ip", "list"])
hit = TEST_CIDR in listing
print(f"  测试规则是否已写入 daemon: {'是 [OK]' if hit else '否 [!!]'}")

# 顺带测一下 100 条的真实吞吐, 估算全量注入时间
print()
print("=" * 68)
print("步骤 3: 断开状态下并发注入 100 条, 测吞吐")
print("=" * 68)
import concurrent.futures as cf

probe = [f"198.51.{i}.0/24" for i in range(100)]
t0 = time.time()
with cf.ThreadPoolExecutor(max_workers=20) as ex:
    list(ex.map(lambda c: subprocess.run([CLI, "tunnel", "ip", "add-range", c],
                                         capture_output=True, timeout=25), probe))
el = time.time() - t0
print(f"  100 条(并发20) 用时 {el:.2f}s  ->  {el / 100 * 1000:.0f} ms/条")
print(f"  推算 1849 条(精简列表) 约 {el / 100 * 1849:.0f}s")
print(f"  推算 5440 条(完整列表) 约 {el / 100 * 5440:.0f}s")

print()
print("=" * 68)
print("步骤 4: 清理测试规则")
print("=" * 68)
for c in probe + [TEST_CIDR]:
    subprocess.run([CLI, "tunnel", "ip", "remove-range", c],
                   capture_output=True, timeout=25)
final = count_excludes()
print(f"  清理后 exclude 条数: {final} (应为 {base})")

print()
print("=" * 68)
print("步骤 5: 恢复连接")
print("=" * 68)
run(["connect"])
time.sleep(4)
run(["status"])
print()
print(f"结论: 断开注入 {'可行 [OK]' if hit else '不可行 [!!]'}")
