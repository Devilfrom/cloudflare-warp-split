# -*- coding: utf-8 -*-
"""
智能 DNS 分流（WARP 官方 fallback 机制）最终验证
================================================
不拆 WARP 隧道，只验证 DNS fallback 分流是否真的把国内域名解析回国内节点，
以及由此带来的下载速度差异。

风险最低：全程只改 WARP 的 dns fallback 列表 + 本地 127.0.0.1:53 代理，
结束时原样还原。
"""
import sys, time, socket, subprocess, os, ipaddress

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=90).stdout.strip()

def flush():
    ps("Clear-DnsClientCache")

def res(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []

def speed(host, ip, path, seconds=6):
    """向 host(ip) 发一个 GET, 限时 seconds 秒, 返回 (字节数, 耗时)。"""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=10),
                            server_hostname=host)
        s.send(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n" % (path, host)).encode())
        s.settimeout(10)
        total = 0
        t0 = time.time()
        while True:
            try:
                b = s.recv(65536)
            except Exception:
                break
            if not b:
                break
            total += len(b)
            if time.time() - t0 > seconds:
                break
        dt = time.time() - t0
        s.close()
        return total, dt
    except Exception as e:
        return 0, 0


print("=" * 68)
print("智能 DNS 分流验证（WARP 官方 dns fallback 机制）")
print("=" * 68)

import warp_split as W
print("[0] WARP 状态:", W.warp(["status"], timeout=20)[1].splitlines()[0].strip())

DOM = ["www.baidu.com", "www.taobao.com", "mirrors.aliyun.com",
       "mirrors.cloud.tencent.com", "www.qq.com"]
FOREIGN = ["www.google.com", "github.com", "www.cloudflare.com"]


def classify(ips):
    cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
    return cn, len(ips)


print("\n[1] 基线：清空 fallback（还原 WARP 默认 DNS 行为）")
ok, out = W.warp(["dns", "fallback", "reset"], timeout=30)
print("    reset ->", ok, out.strip()[:60])
flush()
base = {}
for h in DOM + FOREIGN:
    ips = res(h)
    base[h] = ips
    cn, n = classify(ips)
    print("    %-28s %-40s %s (%d/%d)" %
          (h, ",".join(ips[:2]), "国内" if n and cn == n else "境外", cn, n))

print("\n[2] 启动本地智能 DNS 代理")
ok, msg = W.start_smart_dns()
print("    start_smart_dns ->", ok, msg)
if not ok:
    print("代理启动失败，中止")
    sys.exit(1)
time.sleep(1)

print("\n[3] 写入 fallback 后缀 (%d 条)" % len(W.DNS_FALLBACK_SUFFIXES))
n = W.apply_dns_fallbacks()
print("    成功写入:", n)
time.sleep(2)

print("\n[4] 生效后解析")
flush()
after = {}
for h in DOM + FOREIGN:
    ips = res(h)
    after[h] = ips
    cn, n_all = classify(ips)
    print("    %-28s %-40s %s (%d/%d)" %
          (h, ",".join(ips[:2]), "国内" if n_all and cn == n_all else "境外", cn, n_all))
print("    代理统计:", dict(W.dns_stats))

print("\n[5] 变化对比")
for h in DOM:
    b, a = base.get(h, []), after.get(h, [])
    changed = "✅ 回到国内" if (a and classify(a)[0] == len(a) and
                              classify(b)[0] != len(b)) else \
              ("保持" if classify(a)[0] == classify(b)[0] else "变化")
    print("    %-28s %s" % (h, changed))

print("\n[6] 下载速度对比（同一国内镜像，不同节点）")
# 腾讯云镜像大文件（13.3GB），足够跑满
T_HOST, T_PATH = "mirrors.cloud.tencent.com", \
                 "/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso"
b_ips = [i for i in base.get(T_HOST, [])]
a_ips = [i for i in after.get(T_HOST, [])]
for label, ips in (("修复前(海外节点)", b_ips), ("修复后(国内节点)", a_ips)):
    if not ips:
        print("    %s: 无 IP" % label)
        continue
    ip = ips[0]
    total, dt = speed(T_HOST, ip, T_PATH, seconds=6)
    mbps = total * 8 / dt / 1e6 if dt > 0.5 else 0
    print("    %-18s %-16s %8.2f MB  %5.1f s  ->  %7.2f Mbps" %
          (label, ip, total / 1e6, dt, mbps))

print("\n[7] 还原")
W.stop_smart_dns()
ok, out = W.warp(["dns", "fallback", "reset"], timeout=30)
print("    fallback reset ->", ok)
flush()
print("    代理已停止，fallback 已还原")
print("=" * 68)
