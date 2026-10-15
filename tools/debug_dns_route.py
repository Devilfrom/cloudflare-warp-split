# -*- coding: utf-8 -*-
"""排查: WARP 的 fallback 到底把查询转发给了谁 —— 我们的本地代理还是 223.5.5.5"""
import sys, os, socket, subprocess, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=60).stdout.strip()

def dns_query(server, host, timeout=4):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    msg = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qn + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (server, 53))
        d, _ = s.recvfrom(2048)
        return "OK %d bytes" % len(d)
    except Exception as e:
        return "失败 %s" % e
    finally:
        s.close()

import warp_split as W

print("[1] 启动本地智能 DNS 代理")
print("   ", W.start_smart_dns())
time.sleep(1)

print("\n[2] UDP 53 监听")
print(ps("Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | "
         "Select-Object LocalAddress,OwningProcess | Format-Table -AutoSize | Out-String"))

print("[3] 直接发 DNS 查询")
for srv in ("127.0.0.1", "223.5.5.5", "127.0.2.2"):
    print("    %-12s -> %s" % (srv, dns_query(srv, "www.baidu.com")))

print("\n[4] WARP 声明的 fallback 服务器")
ok, out = W.warp(["dns", "default-fallbacks"], timeout=20)
print(out[:500])

print("\n[5] 当前 fallback 域名列表(含 CLI add)")
ok, out = W.warp(["dns", "fallback", "list"], timeout=20)
print("    CLI add 条数:", out.count("CLI add"))

print("\n[6] 停止代理")
W.stop_smart_dns()
print("    done")
