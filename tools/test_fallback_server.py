# -*- coding: utf-8 -*-
"""
验证: WARP 的 fallback 服务器是否跟随网卡 DNS 变化。
若是, 则「先在 127.0.0.1 起本地智能 DNS, 再把网卡 DNS 指向它」即可让
WARP 把命中后缀的域名解析正式转交我们的代理 —— 既分了流, 又不会被
路由器 DNS 污染境外域名。
"""
import sys, os, socket, subprocess, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, text=True, timeout=90)
    return (r.stdout or "").strip(), (r.stderr or "").strip()[:200]

def flush():
    ps("Clear-DnsClientCache")

def res(h):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})
    except Exception:
        return []

import warp_split as W

print("=" * 66)
print("验证 WARP fallback 服务器是否跟随网卡 DNS")
print("=" * 66)

print("\n[0] 当前 default-fallbacks")
ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
print(out.strip()[:200])

print("\n[1] 启动本地智能 DNS 代理 (127.0.0.1:53)")
print("   ", W.start_smart_dns())
time.sleep(1)

print("\n[2] 把网卡 DNS 改为 127.0.0.1")
o, e = ps("Set-DnsClientServerAddress -InterfaceAlias '以太网' "
          "-ServerAddresses @('127.0.0.1')")
print("   ", "ok" if not e else e)
time.sleep(3)
o, _ = ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' -AddressFamily IPv4).ServerAddresses -join ','")
print("    网卡 DNS 显示:", o)

print("\n[3] 再看 default-fallbacks (关键)")
ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
print(out.strip()[:200])

FB = "127.0.0.1" in out

print("\n[4] 写入 fallback 后缀并验证解析")
n = W.apply_dns_fallbacks()
print("    写入条数:", n)
time.sleep(2)
flush(); time.sleep(1)
for h in ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com",
          "www.google.com", "github.com"]:
    ips = res(h)
    cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
    print("    %-28s %-42s (%d/%d 国内)" % (h, ",".join(ips[:2]), cn, len(ips)))
print("    代理统计:", dict(W.dns_stats))

print("\n[5] 还原")
W.stop_smart_dns()
ps("netsh interface ipv4 delete dnsservers '以太网' all")
W.warp(["dns", "fallback", "reset"], timeout=30)
flush()
time.sleep(2)
o, _ = ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' -AddressFamily IPv4).ServerAddresses -join ','")
print("    网卡 DNS 还原为:", o)
ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
print("    default-fallbacks:", out.strip()[:120])

print("\n结论: fallback 服务器%s跟随网卡 DNS" % ("会" if FB else "不会"))
print("=" * 66)
