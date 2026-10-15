# -*- coding: utf-8 -*-
"""验证: 网卡 DNS 写两个(127.0.0.1 + 223.5.5.5)时, WARP 的 default-fallbacks
是否两个都学到 —— 决定「代理挂了还有备用」这个安全网是否成立。"""
import sys, os, subprocess, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=90).stdout.strip()

import warp_split as W

print("启动代理:", W.start_smart_dns())
ps("Set-DnsClientServerAddress -InterfaceAlias '以太网' "
   "-ServerAddresses @('127.0.0.1','223.5.5.5')")
time.sleep(3)
print("网卡DNS显示:", ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' "
                        "-AddressFamily IPv4).ServerAddresses -join ','"))
ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
print("default-fallbacks:")
print(out.strip()[:250])

print("\n--- 模拟代理挂掉: 停止代理后再解析 ---")
W.stop_smart_dns()
ps("Clear-DnsClientCache")
time.sleep(2)
for h in ["www.baidu.com", "www.qq.com"]:
    r = ps("(Resolve-DnsName -Name %s -Type A -ErrorAction SilentlyContinue | "
           "Where-Object { $_.Type -eq 'A' } | Select-Object -First 2 "
           "-ExpandProperty IPAddress) -join ','" % h)
    print("   %-20s -> %s" % (h, r))

print("\n还原网卡 DNS")
ps("netsh interface ipv4 delete dnsservers '以太网' all")
time.sleep(2)
print("   ", ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' "
                "-AddressFamily IPv4).ServerAddresses -join ','"))
