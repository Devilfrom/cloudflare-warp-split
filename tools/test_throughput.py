# -*- coding: utf-8 -*-
"""千兆跑不满诊断: 测量国内下载吞吐 + 关键路径判定。

只做只读测量, 不改 WARP 状态。
用法: python tools/test_throughput.py
"""
import socket
import ssl
import sys
import threading
import time
import urllib.request

sys.path.insert(0, ".")
import warp_split as W

# 国内直连测速源 (Range 请求, 只下一小段)
CN_SOURCES = [
    ("中科大镜像", "https://mirrors.ustc.edu.cn/debian-cd/current/amd64/iso-dvd/debian-13.1.0-amd64-DVD-1.iso"),
    ("阿里云镜像", "https://mirrors.aliyun.com/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso"),
    ("腾讯云镜像", "https://mirrors.cloud.tencent.com/ubuntu-releases/24.04/ubuntu-24.04.2-desktop-amd64.iso"),
]
INTL_SOURCES = [
    ("Cloudflare 测速", "https://speed.cloudflare.com/__down?bytes=100000000"),
]

CHUNK = 30 * 1024 * 1024   # 每流最多下 30MB
TIMEOUT = 20


def fetch_speed(url, seconds=8):
    """单流下载测速, 返回 (mbps, 已下载字节, 目标IP)。"""
    req = urllib.request.Request(url, headers={
        "Range": "bytes=0-%d" % (CHUNK - 1),
        "User-Agent": "Mozilla/5.0",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    total = 0
    peer_ip = "-"
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        sock = resp.fp.raw._sock if hasattr(resp.fp, "raw") else None
        if sock is not None:
            try:
                peer_ip = sock.getpeername()[0]
            except Exception:
                pass
        while True:
            if time.time() - t0 > seconds:
                break
            buf = resp.read(256 * 1024)
            if not buf:
                break
            total += len(buf)
    except Exception as e:
        return (0.0, total, peer_ip, str(e)[:60])
    dur = time.time() - t0
    mbps = total * 8 / dur / 1e6 if dur > 0.2 else 0.0
    return (mbps, total, peer_ip, "")


def parallel_speed(url, n=4, seconds=8):
    """并发 n 流下载, 返回总 mbps。"""
    res = [0.0] * n
    lock = threading.Lock()

    def one(i):
        mbps, _, _, _ = fetch_speed(url, seconds)
        with lock:
            res[i] = mbps

    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return sum(res)


def main():
    print("=" * 72)
    print("千兆跑不满 —— 吞吐诊断")
    print("=" * 72)

    # [1] 当前 WARP 状态
    ok, out = W.warp(["status"], timeout=15)
    print("\n[1] WARP 状态: %s" % (out.strip().replace("\n", " | ")[:80]))
    ok2, mode = W.warp(["mode"], timeout=15)
    print("    排除规则数: %d" % len(W.get_cli_excludes()))

    # [2] 本地 MTU / 接口
    print("\n[2] 本地网络接口")
    try:
        import subprocess
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetIPInterface -AddressFamily IPv4 | "
             "Where-Object {$_.ConnectionState -eq 'Connected'} | "
             "Select-Object InterfaceAlias,InterfaceMetric,NlMtu | "
             "ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=30)
        print("    " + (r.stdout.strip()[:300] or r.stderr.strip()[:200]))
    except Exception as e:
        print("    (读取失败: %s)" % e)

    # [3] 国内单流
    print("\n[3] 国内下载 —— 单流 (Mbps)")
    for name, url in CN_SOURCES:
        mbps, nbytes, ip, err = fetch_speed(url, seconds=8)
        if err:
            print("    %-12s 失败: %s  (IP=%s)" % (name, err, ip))
        else:
            print("    %-12s %7.1f Mbps   (IP=%s, 下载 %.1f MB)" %
                  (name, mbps, ip, nbytes / 1e6))

    # [4] 国内并发 4 流
    print("\n[4] 国内下载 —— 并发 4 流 (最接近测速站/实际体验)")
    for name, url in CN_SOURCES[:2]:
        tot = parallel_speed(url, n=4, seconds=8)
        print("    %-12s %7.1f Mbps" % (name, tot))

    # [5] 国际 (经 WARP)
    print("\n[5] 国际下载 (经 WARP 出口)")
    for name, url in INTL_SOURCES:
        mbps, nbytes, ip, err = fetch_speed(url, seconds=8)
        if err:
            print("    %-12s 失败: %s" % (name, err))
        else:
            print("    %-12s %7.1f Mbps   (IP=%s)" % (name, mbps, ip))

    # [6] 国内测速站到底走了哪条路
    print("\n[6] 关键判定: 常见测速域名在分流表里怎么判")
    hosts = ["www.speedtest.net", "speedtest.net", "speed.cloudflare.com",
             "www.speedtest.cn", "test.ustc.edu.cn", "mirrors.ustc.edu.cn",
             "mirrors.aliyun.com", "mirrors.cloud.tencent.com"]
    for h in hosts:
        way = W.route_of(h)
        ips = W._resolve_cached(h)[:3]
        cn = [i for i in ips if W.is_cn_ip(i)]
        print("    %-28s -> %-6s  IP=%s%s" %
              (h, way, ips or "-",
               ("  (国内 %d/%d)" % (len(cn), len(ips))) if ips else ""))

    # [7] IPv6 覆盖检查
    print("\n[7] IPv6 覆盖 (排除规则里有多少 IPv6 段)")
    ex = W.get_cli_excludes()
    v6 = [c for c in ex if ":" in c]
    print("    排除规则总数: %d, 其中 IPv6: %d" % (len(ex), len(v6)))
    if not v6:
        print("    !! 一条 IPv6 都没有 —— 若本机启用了 IPv6, 国内 IPv6 流量会全进 WARP")

    print("\n" + "=" * 72)


if __name__ == "__main__":
    main()
