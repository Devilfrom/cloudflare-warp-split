# -*- coding: utf-8 -*-
"""排查 _nic_aliases() 为什么返回空"""
import sys, os, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import warp_split as W

print("_NIC_SKIP_RE =", W._NIC_SKIP_RE)

body = ("Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and "
        "$_.InterfaceDescription -notmatch '%s' } | "
        "ForEach-Object { $_.Name }" % W._NIC_SKIP_RE)
print("\n--- 执行的命令 ---")
print(body)

r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", body],
                   capture_output=True, text=True, timeout=40)
print("\nreturncode =", r.returncode)
print("stdout =", repr(r.stdout))
print("stderr =", repr(r.stderr[:500]))

print("\n--- 所有 Up 的网卡(名称 + 描述) ---")
r2 = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
                     "ForEach-Object { $_.Name + ' || ' + $_.InterfaceDescription }"],
                    capture_output=True, text=True, timeout=40)
print(r2.stdout)

print("\n_nic_aliases() =", W._nic_aliases())
