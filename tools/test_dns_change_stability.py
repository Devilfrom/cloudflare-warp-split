# -*- coding: utf-8 -*-
"""
关键验证: 把网卡 DNS 改成 127.0.0.1 会不会把 WARP 隧道弄断?
(怀疑: 网卡配置变化 -> WARP 以 "Settings Changed" 为由断开)
"""
import sys, os, time, subprocess
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import warp_split as W

WARPCLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"


def st():
    ok, out = W.warp(["status"], timeout=20)
    line = (out or "").splitlines()
    return line[0].strip() if line else "?"


print("=" * 66)
print("改网卡 DNS 会不会弄断 WARP 隧道")
print("=" * 66)

print("\n[0] 先确保 WARP 已连接")
ok, out = W.warp(["connect"], timeout=30)
for i in range(20):
    time.sleep(3)
    if "Connected" in st():
        print("    已连接 (%ds)" % ((i + 1) * 3))
        break
else:
    print("    连接超时:", st())
print("    当前:", st())

print("\n[1] 基线(未改 DNS) —— 观察 30 秒 WARP 是否稳定")
for i in range(10):
    time.sleep(3)
    print("    [%2ds] %s" % ((i + 1) * 3, st()), end="")
    print("   <-- 断开!" if "Connected" not in st() else "")

print("\n[2] 启动代理 + 改网卡 DNS 为 127.0.0.1 —— 再观察 60 秒")
print("    启动代理:", W.start_smart_dns())
time.sleep(1)
print("    改网卡 DNS:", W.apply_nic_dns([W.DNS_LISTEN_ADDR]))
for i in range(20):
    time.sleep(3)
    s = st()
    ok, fb = W.warp(["dns", "default-fallbacks"], timeout=15)
    fbv = fb.strip().replace("\n", " ")[:40] if ok else "ERR"
    flag = "" if "Connected" in s else "   <-- 断开!"
    if i % 2 == 0 or flag:
        print("    [%2ds] %-14s fallback=%s%s" % ((i + 1) * 3, s[:12], fbv, flag))

print("\n[3] 还原")
W.stop_smart_dns()
W.apply_nic_dns([])
W.warp(["dns", "fallback", "reset"], timeout=20)
time.sleep(3)
print("    最终:", st())
print("=" * 66)
