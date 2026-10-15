# -*- coding: utf-8 -*-
"""确认: 网卡 DNS 只写单条 127.0.0.1 时, WARP 稳定把它作为 fallback 服务器。"""
import sys, os, subprocess, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=90).stdout.strip()

import warp_split as W

print("启动代理:", W.start_smart_dns())
ps("Set-DnsClientServerAddress -InterfaceAlias '以太网' -ServerAddresses @('127.0.0.1')")

for i in range(6):
    time.sleep(3)
    ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
    fb = out.strip().replace("\n", " ")
    nic = ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' -AddressFamily IPv4).ServerAddresses -join ','")
    print("  [%ds] fallback=%-30s 网卡显示=%s" % ((i + 1) * 3, fb[:28], nic))

print("\n停止代理 + 还原")
W.stop_smart_dns()
ps("netsh interface ipv4 delete dnsservers '以太网' all")
time.sleep(2)
print("   网卡 DNS:", ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' -AddressFamily IPv4).ServerAddresses -join ','"))
