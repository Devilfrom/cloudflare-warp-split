# -*- coding: utf-8 -*-
"""
多流并行测速 —— 单流测不准千兆(受 TCP 窗口/单线程限制), 用 8 条并发连接。
对比: 国内站被解析到「海外节点」vs「国内节点」的实际吞吐差距。
"""
import sys, os, time, socket, ssl, threading, json, urllib.request
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)
os.environ["no_proxy"] = "*"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
BASE = "http://127.0.0.1:8777"
WARPCLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
import subprocess
import warp_split as W


def api(path, obj=None, timeout=240):
    data = json.dumps(obj).encode() if obj is not None else b"{}"
    req = urllib.request.Request(BASE + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())


def cli(a, t=30):
    r = subprocess.run([WARPCLI] + a, capture_output=True, text=True, timeout=t)
    return r.returncode == 0, (r.stdout or r.stderr or "")


def flush():
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Clear-DnsClientCache"], capture_output=True, timeout=60)


def res(h):
    return sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})


def wait_connected(max_s=90):
    for _ in range(max_s // 3):
        if "Connected" in cli(["status"])[1]:
            return True
        time.sleep(3)
    return False


def wait_fallback(max_s=60):
    for _ in range(max_s // 3):
        if "127.0.0.1" in cli(["dns", "default-fallbacks"])[1]:
            return True
        time.sleep(3)
    return False


def status_ok_fallback():
    """智能 DNS 是否仍处于接管状态(用于等 teardown 完成)。"""
    ok, o = cli(["dns", "default-fallbacks"])
    return ok and ("127.0.0.1" in o)


def one_stream(host, ip, path, seconds, out, i):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t0 = time.time()
        s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=15),
                            server_hostname=host)
        s.send(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n" % (path, host)).encode())
        s.settimeout(15)
        n = 0
        while True:
            try:
                b = s.recv(262144)
            except Exception:
                break
            if not b:
                break
            n += len(b)
            if time.time() - t0 > seconds:
                break
        out[i] = (n, time.time() - t0)
        s.close()
    except Exception:
        out[i] = (0, 0)


def parallel(host, ip, path, streams=8, seconds=10):
    out = [None] * streams
    ths = [threading.Thread(target=one_stream, args=(host, ip, path, seconds, out, i))
           for i in range(streams)]
    t0 = time.time()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    wall = time.time() - t0
    total = sum(n for n, _ in out if n)
    return total, wall, sum(1 for n, _ in out if n)


HOST = "mirrors.cloud.tencent.com"
PATH = "/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso"

print("=" * 72)
print("多流并行测速 (8 并发 x 10s) —— 国内镜像")
print("=" * 72)

print("\n[A] 智能 DNS 关 -> 解析到海外节点")
api("/api/settings", {"smart_dns": False})
# 切换是后台线程做的(会触发 WARP 断线再重连), 先等它干完再测
time.sleep(12)
wait_connected()
for _ in range(10):          # 再等等 DNS 稳定
    time.sleep(3)
    if not status_ok_fallback():
        break
flush(); time.sleep(1)
ipsA = res(HOST)
print("    IP:", ",".join(ipsA[:3]))
ta, wa, na = parallel(HOST, ipsA[0], PATH)
print("    %.1f MB / %.1f s = %.1f Mbps  (成功流 %d/8)"
      % (ta / 1e6, wa, ta * 8 / wa / 1e6 if wa > 1 else 0, na))

print("\n[B] 智能 DNS 开 -> 解析回国内节点")
api("/api/settings", {"smart_dns": True})
wait_connected(); wait_fallback(); flush(); time.sleep(1)
ipsB = res(HOST)
print("    IP:", ",".join(ipsB[:3]))
tb, wb, nb = parallel(HOST, ipsB[0], PATH)
print("    %.1f MB / %.1f s = %.1f Mbps  (成功流 %d/8)"
      % (tb / 1e6, wb, tb * 8 / wb / 1e6 if wb > 1 else 0, nb))

print("\n" + "=" * 72)
if wa > 1 and wb > 1:
    sa = ta * 8 / wa / 1e6
    sb = tb * 8 / wb / 1e6
    print("海外节点 %-16s : %8.1f Mbps" % (ipsA[0], sa))
    print("国内节点 %-16s : %8.1f Mbps" % (ipsB[0], sb))
    print("提升: %.1fx" % (sb / sa if sa > 0.1 else 0))
print("=" * 72)
