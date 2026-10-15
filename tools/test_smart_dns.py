# -*- coding: utf-8 -*-
"""验证智能 DNS 分流代理: 国内域名应拿到国内 IP, 境外域名应正常解析。

用法: python tools/test_smart_dns.py   (需要管理员权限以绑定 53 端口)
"""
import random
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
import warp_split as W

LISTEN = (W.DNS_LISTEN_ADDR, W.DNS_LISTEN_PORT)


def build_query(qname, qtype=1):
    tid = random.randint(0, 65535)
    q = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in qname.split("."):
        q += bytes([len(lab)]) + lab.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return tid, q


def ask(qname, qtype=1, server=LISTEN, timeout=6.0):
    """向 DNS 服务器查询, 返回 (ip列表, 耗时ms, 原始响应)。"""
    tid, q = build_query(qname, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(q, server)
        resp, _ = s.recvfrom(4096)
    except Exception as e:
        s.close()
        return ([], (time.time() - t0) * 1000, None)
    ms = (time.time() - t0) * 1000
    s.close()
    if len(resp) < 12 or resp[0:2] != struct.pack("!H", tid):
        return ([], ms, resp)
    ips = W._dns_extract_ips(resp, qtype)
    return (ips, ms, resp)


def main():
    print("=" * 74)
    print("智能 DNS 分流代理 —— 验证")
    print("=" * 74)

    # [1] 先记录「修复前」: 直接用 WARP DNS 解析
    print("\n[1] 修复前 (直接问 WARP DNS 127.0.2.2) —— 国内站会被解析到境外节点")
    before = {}
    for h in ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com",
              "mirrors.aliyun.com"]:
        ips, ms, _ = ask(h, 1, ("127.0.2.2", 53))
        before[h] = ips
        cn = sum(1 for i in ips if W.is_cn_ip(i))
        print("    %-28s %5.0fms  %s  (国内 %d/%d)" %
              (h, ms, (ips[:3] or "-"), cn, len(ips)))

    # [2] 启动本地智能 DNS
    ok, msg = W.start_smart_dns()
    print("\n[2] 启动本地智能 DNS: ok=%s  %s" % (ok, msg))
    if not ok:
        print("    无法继续")
        return
    time.sleep(1)

    # [3] 修复后
    print("\n[3] 修复后 (问本地智能 DNS 127.0.0.1:53)")
    after = {}
    for h in ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com",
              "mirrors.aliyun.com"]:
        ips, ms, _ = ask(h)
        after[h] = ips
        cn = sum(1 for i in ips if W.is_cn_ip(i))
        print("    %-28s %5.0fms  %s  (国内 %d/%d)" %
              (h, ms, (ips[:3] or "-"), cn, len(ips)))

    # [4] 境外域名必须仍能解析(不能被国内 DNS 污染)
    print("\n[4] 境外域名解析 (必须拿到真实 IP, 不能被污染)")
    for h in ["www.google.com", "www.cloudflare.com", "github.com",
              "www.wikipedia.org"]:
        ips, ms, _ = ask(h)
        cn = sum(1 for i in ips if W.is_cn_ip(i))
        flag = "OK" if ips and cn == 0 else ("疑似被污染" if ips else "无结果")
        print("    %-28s %5.0fms  %s  -> %s" % (h, ms, (ips[:2] or "-"), flag))

    # [5] 缓存命中后的延迟
    print("\n[5] 二次查询(缓存命中)延迟")
    for h in ["www.baidu.com", "www.taobao.com"]:
        ips, ms, _ = ask(h)
        print("    %-28s %5.1fms" % (h, ms))

    # [6] 对比小结
    print("\n[6] 小结")
    print("    %-28s %-22s %-22s" % ("域名", "修复前", "修复后"))
    for h in before:
        b = ",".join(before[h][:2]) or "-"
        a = ",".join(after[h][:2]) or "-"
        bcn = before[h] and all(W.is_cn_ip(i) for i in before[h])
        acn = after[h] and all(W.is_cn_ip(i) for i in after[h])
        print("    %-28s %-22s %-22s  %s" %
              (h, b[:22], a[:22],
               ("国内✓" if acn else "国内✗") + ("  (前:" + ("国内✓" if bcn else "国内✗") + ")")))

    print("\n    统计: " + str(W.dns_stats))
    W.stop_smart_dns()
    print("=" * 74)


if __name__ == "__main__":
    main()
