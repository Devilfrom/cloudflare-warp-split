# -*- coding: utf-8 -*-
"""验证 Set-DnsClientServerAddress -ResetServerAddresses 能否真正清掉静态 DNS"""
import sys, os, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import warp_split as W

print("网卡 ifIndex:", W._nic_indexes())

def reg_nameservers():
    rc, out = W._ps(
        "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\"
        "Tcpip\\Parameters\\Interfaces\\*' -Name NameServer -ErrorAction "
        "SilentlyContinue | Where-Object { $_.NameServer } | "
        "ForEach-Object { $_.PSChildPath + '=' + $_.NameServer }")
    return out.strip()

print("\n[1] 写一个静态 DNS 127.0.0.1")
print("   ", W.apply_nic_dns(["127.0.0.1"]))
print("   注册表:", reg_nameservers() or "(空)")

print("\n[2] 用 -ResetServerAddresses 还原")
for idx in W._nic_indexes():
    rc, out = W._ps("Set-DnsClientServerAddress -InterfaceIndex %d "
                    "-ResetServerAddresses" % idx)
    print("   idx=%s rc=%s out=%s" % (idx, rc, out.strip()[:100]))
import time; time.sleep(2)
print("   注册表:", reg_nameservers() or "(空)")

print("\n[3] 若仍有残留, 用 netsh 兜底")
if reg_nameservers():
    rc, out = W._ps("Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
                    "ForEach-Object { $_.Name }")
    print("   网卡名:", out.split())
    for nm in out.split():
        subprocess.run(["netsh", "interface", "ipv4", "delete", "dnsservers",
                        nm, "all"], capture_output=True, timeout=40)
    time.sleep(2)
    print("   netsh 后注册表:", reg_nameservers() or "(空)")
else:
    print("   无需兜底")
