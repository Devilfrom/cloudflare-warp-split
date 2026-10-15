# -*- coding: utf-8 -*-
"""直接向本地智能 DNS 代理发查询, 解出 A 记录, 看每个域名到底走了哪条路。"""
import sys, os, socket, struct, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def build_query(host, qtype=1):
    tid = b"\x12\x34"
    qn = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    return tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qn + \
        struct.pack(">HH", qtype, 1)


def parse_answers(data):
    """解出所有 A 记录。"""
    if len(data) < 12:
        return []
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    i = 12
    for _ in range(qd):
        while data[i] != 0:
            i += data[i] + 1
        i += 5
    ips = []
    for _ in range(an):
        while True:
            l = data[i]
            if l == 0:
                i += 1
                break
            if l & 0xC0 == 0xC0:
                i += 2
                break
            i += l + 1
        typ, cls, ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if typ == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    return ips


def ask(host, server="127.0.0.1", timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(host), (server, 53))
        d, _ = s.recvfrom(4096)
        return parse_answers(d)
    except Exception as e:
        return ["ERR:%s" % e]
    finally:
        s.close()


import warp_split as W

print("=" * 70)
print("本地智能 DNS 代理 —— 逐域名答案解码")
print("=" * 70)

print("\n启动代理:", W.start_smart_dns())
time.sleep(1)

DOMS = ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com",
        "www.qq.com", "www.google.com", "github.com", "www.cloudflare.com",
        "www.bilibili.com"]

print("\n%-28s %-46s %s" % ("域名", "代理返回的 A 记录", "判定"))
for h in DOMS:
    t0 = time.time()
    ips = ask(h)
    dt = (time.time() - t0) * 1000
    real = [i for i in ips if not i.startswith("ERR")]
    cn = sum(1 for i in real if W.is_cn_ip(i))
    tag = "国内" if (real and cn == len(real)) else ("境外" if real else "失败")
    print("%-28s %-46s %s (%.0fms)" % (h, ",".join(real[:2]) or ips[0], tag, dt))

print("\n代理统计:", dict(W.dns_stats))
print("路由记忆:")
for k, v in list(W._DNS_ROUTE_CACHE.items())[:20]:
    print("   %-30s -> %s" % (k[0], v[1]))

print("\n停止代理")
W.stop_smart_dns()
print("=" * 70)
