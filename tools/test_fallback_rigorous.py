# -*- coding: utf-8 -*-
"""
智能 DNS 分流 —— 严格时序验证
=============================
之前的验证失败在时序上: WARP 连接后是**异步**把网卡 DNS 改回 127.0.2.2 的,
在它改回来之前测基线, 拿到的其实是 DHCP DNS 的结果, 看起来"本来就是国内的",
从而误判修复无效。

本脚本:
  1. 先等到网卡 DNS 确实变成 127.0.2.2 (最多等 60s), 才认为基线有效
  2. 基线解析 -> 预期海外节点
  3. 启动本地智能 DNS + 写入 fallback -> 预期变回国内节点, 且代理确实收到查询
  4. 结束时还原
"""
import sys, time, socket, subprocess, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=90).stdout.strip()

def flush():
    ps("Clear-DnsClientCache")

def nic_dns():
    out = ps("(Get-DnsClientServerAddress -InterfaceAlias '以太网' -AddressFamily IPv4).ServerAddresses -join ','")
    return out.strip()

def res(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []

import warp_split as W

DOM = ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com", "www.qq.com"]
FOREIGN = ["www.google.com", "github.com", "www.cloudflare.com"]


def classify(ips):
    cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
    return cn, len(ips)


print("=" * 70)
print("智能 DNS 分流 —— 严格时序验证")
print("=" * 70)

print("\n[0] 等到 WARP 把网卡 DNS 改成 127.0.2.2（否则基线无效）")
for i in range(30):
    d = nic_dns()
    if "127.0.2.2" in d:
        print("    第 %d 次: 已是 WARP DNS -> %s" % (i + 1, d))
        break
    time.sleep(2)
else:
    print("    超时: 网卡 DNS 仍为 %s，基线可能不准，但继续" % d)
print("    WARP:", W.warp(["status"], timeout=20)[1].splitlines()[0].strip())

print("\n[1] 基线（WARP 原生 DNS，经 LAX 出口）")
ok, out = W.warp(["dns", "fallback", "reset"], timeout=30)
time.sleep(1)
flush(); time.sleep(1)
base = {}
for h in DOM + FOREIGN:
    ips = res(h)
    base[h] = ips
    cn, n = classify(ips)
    tag = "国内 ✅" if (n and cn == n) else "境外 ⚠️"
    print("    %-28s %-42s %s (%d/%d)" % (h, ",".join(ips[:2]), tag, cn, n))

print("\n[2] 启动本地智能 DNS 代理")
ok, msg = W.start_smart_dns()
print("    ->", ok, msg)
if not ok:
    print("启动失败，中止"); sys.exit(1)
time.sleep(1)
before_stats = dict(W.dns_stats)

print("\n[3] 写入 fallback 后缀 (%d 条)" % len(W.DNS_FALLBACK_SUFFIXES))
n = W.apply_dns_fallbacks()
print("    成功:", n)
print("    fallback list:", W.warp(["dns", "fallback", "list"], timeout=20)[1].count("CLI add"))
time.sleep(3)

print("\n[4] 生效后解析")
flush(); time.sleep(1)
after = {}
for h in DOM + FOREIGN:
    ips = res(h)
    after[h] = ips
    cn, n_all = classify(ips)
    tag = "国内 ✅" if (n_all and cn == n_all) else "境外"
    print("    %-28s %-42s %s (%d/%d)" % (h, ",".join(ips[:2]), tag, cn, n_all))
print("    代理统计:", dict(W.dns_stats), "  (基线:", before_stats, ")")

print("\n[5] 结论")
hits = 0
for h in DOM:
    b, a = base.get(h, []), after.get(h, [])
    bc, bn = classify(b)
    ac, an = classify(a)
    ok_h = (an and ac == an)
    was_bad = not (bn and bc == bn)
    if ok_h:
        hits += 1
    status = "✅ 修复" if (was_bad and ok_h) else ("保持正常" if ok_h else "❌ 仍为境外")
    print("    %-28s %s  (%s -> %s)" % (h, status,
          ",".join(b[:1]) or "-", ",".join(a[:1]) or "-"))
print("    国内域名正确率: %d/%d" % (hits, len(DOM)))

print("\n[6] 境外域名未被影响（应仍可解析）")
for h in FOREIGN:
    print("    %-28s %s" % (h, ",".join(after.get(h, [])[:2]) or "解析失败"))

print("\n[7] 还原")
W.stop_smart_dns()
ok, out = W.warp(["dns", "fallback", "reset"], timeout=30)
flush()
print("    fallback reset ->", ok)
print("=" * 70)
