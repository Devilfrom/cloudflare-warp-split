"""测量 warp-cli tunnel ip add-range 的吞吐, 用于诊断规则注入耗时。

用法:
    python tools/bench_add.py [串行次数] [并发数] [并发批量]

示例:
    python tools/bench_add.py 20 20 40

注意: 会向 daemon 写入测试网段而后删除它们。请在规则已被清空
(或已启用分流)时运行, 不要与正在进行的注入操作同时跑。
"""
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
if not os.path.exists(CLI):
    for c in (r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
              r"D:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"):
        if os.path.exists(c):
            CLI = c
            break


def run(args, timeout=30):
    r = subprocess.run([CLI] + args, capture_output=True, text=True,
                       timeout=timeout, errors="ignore")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    serial = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    bulk = int(sys.argv[3]) if len(sys.argv) > 3 else 40

    print(f"warp-cli: {CLI}")
    rc, out = run(["status"])
    print("status  :", out.strip().splitlines()[0] if out.strip() else "-")

    # 用一段不会与真实规则冲突的测试网段(198.18.0.0/15 为基准测试保留段)
    test_nets = [f"198.18.{i}.0/24" for i in range(1, max(serial, bulk) + 1)]

    print(f"\n== 串行 {serial} 条 ==")
    t0 = time.time()
    okc = 0
    per = []
    for c in test_nets[:serial]:
        t1 = time.time()
        rc, _ = run(["tunnel", "ip", "add-range", c])
        per.append(time.time() - t1)
        if rc == 0:
            okc += 1
    dur = time.time() - t0
    print(f"  成功 {okc}/{serial}  总耗时 {dur:.1f}s  平均 {dur / serial * 1000:.0f} ms/条")
    if per:
        s = sorted(per)
        print(f"  单条耗时 中位 {s[len(s)//2]*1000:.0f}ms  "
              f"最快 {s[0]*1000:.0f}ms  最慢 {s[-1]*1000:.0f}ms")

    print(f"\n== 并发 {workers} 线程, {bulk} 条 ==")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda c: run(["tunnel", "ip", "add-range", c])[0],
                              test_nets[:bulk]))
    dur = time.time() - t0
    okc = sum(1 for r in results if r == 0)
    print(f"  成功 {okc}/{bulk}  总耗时 {dur:.1f}s  "
          f"吞吐 {bulk/dur:.1f} 条/秒  等效 {bulk/dur*60:.0f} 条/分钟")
    if dur > 0 and bulk:
        print(f"  → 5440 条按此吞吐约需 {5440/(bulk/dur)/60:.1f} 分钟")

    print("\n== 清理测试网段 ==")
    n = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for rc in ex.map(lambda c: run(["tunnel", "ip", "remove-range", c])[0],
                         test_nets[:max(serial, bulk)]):
            if rc == 0:
                n += 1
    print(f"  已移除 {n} 条")


if __name__ == "__main__":
    main()
