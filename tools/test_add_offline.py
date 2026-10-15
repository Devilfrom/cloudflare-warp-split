# -*- coding: utf-8 -*-
"""
方案对比: 后缀应该在 WARP 连接「之前」写还是「之后」写?
已知 `dns fallback add/reset` 会触发 WARP 以 "Settings Changed" 断线,
所以「先写后缀再连接」理论上可以避免一次无谓的断线重连。
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


def fb_list_count():
    ok, out = W.warp(["dns", "fallback", "list"], timeout=20)
    return (out or "").count("CLI add")


def fb_server():
    ok, out = W.warp(["dns", "default-fallbacks"], timeout=15)
    return (out or "").strip().replace("\n", " ")[:60] if ok else "ERR"


print("=" * 68)
print("后缀写入时机对比")
print("=" * 68)

print("\n[1] 断开 WARP")
W.warp(["disconnect"], timeout=20)
time.sleep(3)
print("   状态:", st())

print("\n[2] 断开状态下写后缀 (关键: 能不能写进去?)")
W.warp(["dns", "fallback", "reset"], timeout=20)
n = W.apply_dns_fallbacks()
print("   写入条数:", n)
print("   fallback list 里 CLI add 条数:", fb_list_count())
print("   状态(应仍断开):", st())

print("\n[3] 设网卡 DNS + 连接 WARP")
print("   启动代理:", W.start_smart_dns())
print("   网卡DNS:", W.apply_nic_dns([W.DNS_LISTEN_ADDR]))
W.warp(["connect"], timeout=30)
for i in range(15):
    time.sleep(3)
    if "Connected" in st():
        break
print("   状态:", st(), " (%ds)" % ((i + 1) * 3))

print("\n[4] 等 fallback 服务器跟上")
for i in range(10):
    time.sleep(3)
    f = fb_server()
    print("   [%2ds] %s" % ((i + 1) * 3, f))
    if "127.0.0.1" in f:
        break

print("\n[5] 验证解析")
import subprocess, socket
subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Clear-DnsClientCache"], capture_output=True, timeout=60)
time.sleep(1)
for h in ["www.baidu.com", "www.taobao.com", "www.qq.com", "www.google.com"]:
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})
    except Exception:
        ips = []
    cn = sum(1 for i in ips if W.is_cn_ip(i))
    print("   %-20s %-42s %s" % (h, ",".join(ips[:2]),
          "国内 ✅" if (ips and cn == len(ips)) else "境外"))
print("   代理统计:", dict(W.dns_stats))

print("\n[6] 还原")
W.stop_smart_dns()
W.apply_nic_dns([])
W.warp(["dns", "fallback", "reset"], timeout=20)
time.sleep(2)
print("   状态:", st())
print("=" * 68)
