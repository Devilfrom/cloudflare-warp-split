# -*- coding: utf-8 -*-
"""
定位: 到底是哪个操作会把 WARP 隧道弄断?
候选: ① dns fallback add  ② dns fallback reset  ③ 改网卡 DNS  ④ 改回网卡 DNS
"""
import sys, os, time
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import warp_split as W


def st():
    ok, out = W.warp(["status"], timeout=20)
    ln = (out or "").splitlines()
    return ln[0].strip() if ln else "?"


def ensure_connected(tag):
    for _ in range(15):
        if "Connected" in st():
            return True
        W.warp(["connect"], timeout=30)
        time.sleep(4)
    print("    %s: 连不上" % tag)
    return False


def probe(label, fn, wait=8):
    ensure_connected(label)
    before = st()
    fn()
    time.sleep(wait)
    after = st()
    mark = "稳定 ✅" if "Connected" in after else "断开 ❌"
    print("  %-28s %s -> %s   %s" % (label, before[:14], after[:14], mark))
    return "Connected" in after


print("=" * 70)
print("定位把 WARP 弄断的操作")
print("=" * 70)

ensure_connected("初始")
print("\n初始状态:", st())

probe("① dns fallback add", lambda: W.warp(["dns", "fallback", "add", "com"], timeout=20))
probe("② dns fallback reset", lambda: W.warp(["dns", "fallback", "reset"], timeout=20))
probe("③ 网卡 DNS -> 127.0.0.1", lambda: W.apply_nic_dns([W.DNS_LISTEN_ADDR]))
probe("④ 网卡 DNS -> 还原", lambda: W.apply_nic_dns([]))

print("\n--- 连续跑 38 条 add (模拟 apply_dns_fallbacks) ---")
ensure_connected("批量add前")
n = W.apply_dns_fallbacks()
time.sleep(8)
print("  写入 %d 条后: %s" % (n, st()))

print("\n--- 还原 ---")
W.warp(["dns", "fallback", "reset"], timeout=20)
W.apply_nic_dns([])
time.sleep(4)
print("  最终:", st())
print("=" * 70)
