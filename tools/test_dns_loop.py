# -*- coding: utf-8 -*-
"""
验证回环假设: 代理向 127.0.2.2 查境外域名时, WARP 因后缀命中 fallback
又把查询转回 127.0.0.1(我们), 形成无限循环 -> 超时 -> 退回国内结果(污染)。

同时验证替代上游: 直接查公网 DNS(1.1.1.1 / 8.8.8.8) 是否被 WARP 劫持。
"""
import sys, os, time, socket, subprocess
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import warp_split as W


def build(host):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qn + b"\x00\x01\x00\x01"


def ask(server, host, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(build(host), (server, 53))
        d, _ = s.recvfrom(4096)
        return "OK %4dB %5.0fms" % (len(d), (time.time() - t0) * 1000)
    except Exception as e:
        return "超时/失败 %5.0fms" % ((time.time() - t0) * 1000)
    finally:
        s.close()


def st():
    ok, out = W.warp(["status"], timeout=20)
    ln = (out or "").splitlines()
    return ln[0].strip() if ln else "?"


print("=" * 70)
print("DNS 回环验证")
print("=" * 70)

print("\n准备: 断开 -> 写后缀 -> 起代理 -> 设网卡DNS -> 连接")
W.warp(["disconnect"], timeout=20); time.sleep(3)
W.warp(["dns", "fallback", "reset"], timeout=20)
n = W.apply_dns_fallbacks()
print("   后缀:", n)
print("   代理:", W.start_smart_dns())
print("   网卡DNS:", W.apply_nic_dns([W.DNS_LISTEN_ADDR]))
W.warp(["connect"], timeout=30)
for _ in range(15):
    time.sleep(3)
    if "Connected" in st():
        break
print("   状态:", st())
time.sleep(5)
print("   fallback server:",
      W.warp(["dns", "default-fallbacks"], timeout=15)[1].strip().replace("\n", " ")[:50])

print("\n[1] 境外域名 -> 127.0.2.2 (WARP DNS)。若回环则超时")
for h in ["www.google.com", "github.com", "www.cloudflare.com"]:
    print("   %-22s 127.0.2.2 -> %s" % (h, ask("127.0.2.2", h)))

print("\n[2] 同一批境外域名 -> 代理 127.0.0.1 (我们的分流)")
for h in ["www.google.com", "github.com", "www.cloudflare.com"]:
    print("   %-22s 127.0.0.1 -> %s" % (h, ask("127.0.0.1", h)))

print("\n[3] 公网 DNS 是否被 WARP 劫持(作为替代上游的可行性)")
for srv in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
    print("   %-10s -> %s" % (srv, ask(srv, "www.google.com")))

print("\n[4] 国内域名对照")
for h in ["www.baidu.com", "www.qq.com"]:
    print("   %-22s 127.0.0.1 -> %s" % (h, ask("127.0.0.1", h)))

print("\n[5] 撤掉后缀后再测 127.0.2.2 (若此时正常 -> 回环假设成立)")
W.warp(["dns", "fallback", "reset"], timeout=20)
time.sleep(4)
W.warp(["connect"], timeout=30)
for _ in range(10):
    time.sleep(3)
    if "Connected" in st():
        break
print("   状态:", st())
for h in ["www.google.com", "github.com"]:
    print("   %-22s 127.0.2.2 -> %s" % (h, ask("127.0.2.2", h)))

print("\n[6] 还原")
W.stop_smart_dns()
W.apply_nic_dns([])
W.warp(["dns", "fallback", "reset"], timeout=20)
print("=" * 70)
