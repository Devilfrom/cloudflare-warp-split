# -*- coding: utf-8 -*-
"""量化 DNS 泄漏对国内下载速度的影响。

同一个文件(腾讯云镜像 13.3GB CentOS ISO), 分别连:
  A) WARP DNS 解析出的节点 (当前实际状态)
  B) 国内 DNS 解析出的节点 (修复后应有的状态)
各下载 8 秒, 对比吞吐与 TCP 建连时延。

用法: python tools/test_dns_leak_speed.py
"""
import socket
import ssl
import threading
import time

HOST = "mirrors.cloud.tencent.com"
PATH = "/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso"

# (标签, IP, 来源说明)
TARGETS = [
    ("A 当前(WARP DNS)", None),      # 走系统 DNS = 127.0.2.2
]
WARP_NODES = ["101.33.20.158", "43.159.77.160"]     # WARP DNS 给的新加坡段
CN_NODES = ["120.232.191.137", "120.233.184.135"]   # 国内 DNS 给的国内段

SECONDS = 8
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def dl(host, ip, seconds=SECONDS):
    """直连指定 IP 下载, 返回 (mbps, rtt_ms, err)。"""
    t0 = time.time()
    try:
        raw = socket.create_connection((ip, 443), timeout=15)
    except Exception as e:
        return (0.0, 0.0, "建连失败 %s" % str(e)[:40])
    rtt = (time.time() - t0) * 1000
    try:
        s = CTX.wrap_socket(raw, server_hostname=host)
        s.send((
            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
            "Range: bytes=0-%d\r\nConnection: close\r\n\r\n" % (PATH, host, 400 * 1024 * 1024)
        ).encode())
        # 读响应头
        head = b""
        while b"\r\n\r\n" not in head:
            b = s.recv(4096)
            if not b:
                break
            head += b
        if b"200" not in head.split(b"\r\n")[0] and b"206" not in head.split(b"\r\n")[0]:
            s.close()
            return (0.0, rtt, "HTTP %s" % head.split(b"\r\n")[0][:20].decode("utf-8", "ignore"))
        # 限速下载
        total = len(head.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in head else 0
        t1 = time.time()
        s.settimeout(15)
        while time.time() - t1 < seconds:
            try:
                buf = s.recv(256 * 1024)
            except socket.timeout:
                break
            if not buf:
                break
            total += len(buf)
        dur = time.time() - t1
        s.close()
        return (total * 8 / dur / 1e6 if dur > 0.3 else 0.0, rtt, "")
    except Exception as e:
        return (0.0, rtt, str(e)[:40])


def group(label, ips):
    print("\n" + "-" * 66)
    print(label)
    print("-" * 66)
    res = [(0.0, 0.0, "")] * len(ips)

    def one(i, ip):
        res[i] = dl(HOST, ip)

    ts = [threading.Thread(target=one, args=(i, ip)) for i, ip in enumerate(ips)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    for ip, (mbps, rtt, err) in zip(ips, res):
        if err:
            print("    %-18s 失败: %s" % (ip, err))
        else:
            print("    %-18s %8.1f Mbps   建连 RTT %6.1f ms" % (ip, mbps, rtt))
    tot = sum(r[0] for r in res)
    print("    %-18s %8.1f Mbps  (并发合计)" % ("合计", tot))
    return tot


def main():
    print("=" * 66)
    print("DNS 泄漏对国内下载速度的影响  (同一 13.3GB 文件, 各下 8 秒)")
    print("=" * 66)

    # 先看系统 DNS 现在把域名解析到哪
    try:
        ips = socket.getaddrinfo(HOST, 443, socket.AF_INET)
        print("\n系统 DNS 当前解析 %s -> %s" %
              (HOST, sorted({i[4][0] for i in ips})))
    except Exception as e:
        print("\n解析失败: %s" % e)

    a = group("[A] 连 WARP DNS 给出的节点 (新加坡段) —— 当前实际状态", WARP_NODES)
    b = group("[B] 连国内 DNS 给出的节点 (国内段) —— DNS 修复后应有状态", CN_NODES)

    print("\n" + "=" * 66)
    if a > 0 and b > 0:
        print("结论: 修复后国内下载速度 = 当前状态的 %.1f 倍" % (b / a))
        print("      当前 %.0f Mbps  ->  修复后 %.0f Mbps" % (a, b))
    else:
        print("(有一组测速失败, 无法给出倍数)")
    print("=" * 66)


if __name__ == "__main__":
    main()
