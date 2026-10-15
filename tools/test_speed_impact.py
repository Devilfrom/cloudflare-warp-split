# -*- coding: utf-8 -*-
"""
量化智能 DNS 对下载速度的影响 —— 这就是"千兆跑不满"的直接证据。

同一台机、同一个国内镜像、同一个文件:
  A. 智能 DNS 关 -> 域名被解析到海外节点 -> 连到海外节点下载
  B. 智能 DNS 开 -> 域名解析回国内节点 -> 连到国内节点下载
"""
import sys, os, time, socket, ssl, json, urllib.request
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)
os.environ["no_proxy"] = "*"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
BASE = "http://127.0.0.1:8777"

import warp_split as W
WARPCLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"


def api(path, obj=None, timeout=240):
    data = json.dumps(obj).encode() if obj is not None else b"{}"
    req = urllib.request.Request(BASE + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())


def status():
    return json.loads(urllib.request.urlopen(BASE + "/api/status", timeout=30).read().decode())


def cli(a, t=30):
    import subprocess
    r = subprocess.run([WARPCLI] + a, capture_output=True, text=True, timeout=t)
    return r.returncode == 0, (r.stdout or r.stderr or "")


def flush():
    import subprocess
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Clear-DnsClientCache"], capture_output=True, timeout=60)


def res(h):
    return sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})


def wait_connected(max_s=90):
    for i in range(max_s // 3):
        ok, o = cli(["status"])
        if "Connected" in o:
            return True
        time.sleep(3)
    return False


def wait_fallback(want, max_s=60):
    for i in range(max_s // 3):
        ok, o = cli(["dns", "default-fallbacks"])
        if want:
            if "127.0.0.1" in o:
                return True
        else:
            if "127.0.0.1" not in o and ok:
                return True
        time.sleep(3)
    return False


def download(host, ip, path, seconds=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t0 = time.time()
        s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                            server_hostname=host)
        s.send(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n" % (path, host)).encode())
        s.settimeout(12)
        total = 0
        first = None
        while True:
            try:
                b = s.recv(65536)
            except Exception:
                break
            if not b:
                break
            if first is None:
                first = time.time() - t0
            total += len(b)
            if time.time() - t0 > seconds:
                break
        dt = time.time() - t0
        s.close()
        return total, dt, first
    except Exception as e:
        return 0, 0, None


HOST = "mirrors.cloud.tencent.com"
PATH = "/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso"

print("=" * 72)
print("智能 DNS 对下载速度的影响（同一国内镜像、同一文件）")
print("=" * 72)

print("\n[A] 关掉智能 DNS —— 模拟《启用分流但国内站绕境外》")
api("/api/settings", {"smart_dns": False})
wait_connected(); flush(); time.sleep(1)
ipsA = res(HOST)
print("    %s -> %s" % (HOST, ",".join(ipsA[:3])))
totalA, dtA, firstA = download(HOST, ipsA[0], PATH)
print("    下载: %.2f MB / %.1f s = %.2f Mbps  (首包 %.2fs)"
      % (totalA / 1e6, dtA, totalA * 8 / dtA / 1e6 if dtA > .5 else 0,
         firstA or 0))

print("\n[B] 打开智能 DNS —— 解析回国内节点")
api("/api/settings", {"smart_dns": True})
wait_connected(); wait_fallback(True); flush(); time.sleep(1)
ipsB = res(HOST)
print("    %s -> %s" % (HOST, ",".join(ipsB[:3])))
totalB, dtB, firstB = download(HOST, ipsB[0], PATH)
print("    下载: %.2f MB / %.1f s = %.2f Mbps  (首包 %.2fs)"
      % (totalB / 1e6, dtB, totalB * 8 / dtB / 1e6 if dtB > .5 else 0,
         firstB or 0))

print("\n" + "=" * 72)
if dtA > 0.5 and dtB > 0.5:
    sa = totalA * 8 / dtA / 1e6
    sb = totalB * 8 / dtB / 1e6
    print("节点: %s (海外) vs %s (国内)" % (ipsA[0], ipsB[0]))
    print("吞吐: %.2f Mbps  ->  %.2f Mbps   (%.1fx)" %
          (sa, sb, sb / sa if sa > 0.01 else 0))
    print("首包: %.3fs -> %.3fs" % (firstA or 0, firstB or 0))
print("=" * 72)
