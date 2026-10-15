# -*- coding: utf-8 -*-
"""
智能 DNS —— 真实流程端到端测试
==============================
走 /api/enable 与 /api/disable 真实开关, 每一步都验证:
  1. 停用状态: 国内域名解析到哪 (预期: 无所谓, 直连国内 DNS)
  2. 启用后: WARP 接管 DNS, 国内域名被解析到海外 (这是"跑不满带宽"的状态)
  3. 启用 + 智能 DNS: 国内域名回到国内节点, 境外域名仍干净
  4. 停用后: 网卡 DNS 与 WARP fallback 全部还原干净

需要后端在 127.0.0.1:8777 运行。
"""
import sys, os, json, time, socket, subprocess, urllib.request

# 本机有沙箱级 http_proxy, 会把 127.0.0.1 的请求也代理走并返回 502。
# 控制台是本机回环服务, 必须绕过代理。
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)
os.environ["no_proxy"] = "*"
os.environ["NO_PROXY"] = "*"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
BASE = "http://127.0.0.1:8777"

WARPCLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"


def api(path, obj=None, timeout=240):
    url = BASE + path
    data = json.dumps(obj).encode() if obj is not None else b"{}"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())


def status():
    return json.loads(urllib.request.urlopen(BASE + "/api/status",
                                             timeout=30).read().decode())


def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=90).stdout.strip()


def flush():
    ps("Clear-DnsClientCache")


def res(h):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})
    except Exception:
        return []


def cli(args, timeout=30):
    r = subprocess.run([WARPCLI] + args, capture_output=True, text=True,
                       timeout=timeout)
    return r.returncode == 0, (r.stdout or r.stderr or "")


import warp_split as W

DOM = ["www.baidu.com", "www.taobao.com", "mirrors.cloud.tencent.com", "www.qq.com"]
FOREIGN = ["www.google.com", "github.com"]


def classify(ips):
    cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
    return cn, len(ips)


def show(title):
    print("\n" + title)
    flush(); time.sleep(1)
    out = []
    for h in DOM:
        ips = res(h)
        cn, n = classify(ips)
        out.append((h, cn == n and n > 0))
        print("    %-28s %-40s %s (%d/%d)" %
              (h, ",".join(ips[:2]), "国内 ✅" if (n and cn == n) else "境外 ⚠️", cn, n))
    for h in FOREIGN:
        ips = res(h)
        print("    %-28s %-40s %s" % (h, ",".join(ips[:2]), "(境外, 应可解析)"))
    return sum(1 for _, okc in out if okc), len(out)


print("=" * 70)
print("智能 DNS —— 真实流程端到端")
print("=" * 70)

st = status()
print("\n后端在线. route_mode=%s enabled=%s smart_dns=%s dns_proxy=%s"
      % (st.get("route_mode"), st.get("enabled"),
         st.get("smart_dns"), st.get("dns_proxy")))

ok, out = cli(["dns", "default-fallbacks"])
print("初始 default-fallbacks:", out.strip().replace("\n", " ")[:80])

print("\n[1] 停用分流 -> 建立基线")
api("/api/disable")
for _ in range(30):
    time.sleep(2)
    if not status().get("enabled") and not status().get("running"):
        break
print("    enabled =", status().get("enabled"))
show("    基线(未分流, 直连) 国内域名:")

print("\n[2] 启用分流(带智能 DNS)")
api("/api/settings", {"smart_dns": True})
api("/api/enable")
for _ in range(60):
    time.sleep(3)
    s = status()
    if not s.get("running"):
        break
    print("    ... %s %s/%s" % (s.get("progress", {}).get("phase"),
                                s.get("progress", {}).get("done"),
                                s.get("progress", {}).get("total")))
s = status()
print("    enabled=%s dns_proxy=%s" % (s.get("enabled"), s.get("dns_proxy")))
ok, out = cli(["dns", "fallback", "list"])
print("    fallback 后缀条数:", out.count("CLI add"))

print("    等待 fallback 服务器就绪(最多 60s)...")
ready = False
for i in range(20):
    time.sleep(3)
    ok, out = cli(["dns", "default-fallbacks"])
    fb = out.strip().replace("\n", " ")
    if "127.0.0.1" in fb:
        ready = True
        print("    [%2ds] 就绪: %s" % ((i + 1) * 3, fb[:60]))
        break
    if i % 3 == 0:
        print("    [%2ds] 尚未就绪: %s" % ((i + 1) * 3, fb[:60]))
print("    就绪 =", ready)
good, tot = show("    启用后(智能 DNS 接管) 国内域名:")
print("    >>> 国内域名正确率 %d/%d" % (good, tot))

print("\n[3] 关掉智能 DNS 开关 -> 应回到 WARP 原生 DNS(海外节点)")
api("/api/settings", {"smart_dns": False})
# 切换会触发 WARP 断线并自动重连, 等它稳定下来再测
for i in range(10):
    time.sleep(3)
    ok, o = cli(["status"])
    if "Connected" in o:
        print("    [%2ds] WARP 已重连" % ((i + 1) * 3))
        break
s = status()
print("    dns_proxy =", s.get("dns_proxy"))
ok, out = cli(["dns", "default-fallbacks"])
print("    default-fallbacks:", out.strip().replace("\n", " ")[:80])
bad, tot2 = show("    对照(无智能 DNS):")

print("\n[4] 重新打开智能 DNS")
api("/api/settings", {"smart_dns": True})
for i in range(12):
    time.sleep(3)
    ok, o = cli(["dns", "default-fallbacks"])
    if "127.0.0.1" in o:
        print("    [%2ds] 已重新接管" % ((i + 1) * 3))
        break
ok, out = cli(["dns", "default-fallbacks"])
print("    default-fallbacks:", out.strip().replace("\n", " ")[:80])
good2, tot3 = show("    重新接管后:")

print("\n[5] 停用 -> 检查还原是否干净")
api("/api/disable")
for _ in range(30):
    time.sleep(2)
    if not status().get("enabled") and not status().get("running"):
        break
s = status()
print("    enabled=%s dns_proxy=%s" % (s.get("enabled"), s.get("dns_proxy")))
ok, out = cli(["dns", "fallback", "list"])
print("    fallback 后缀残留:", out.count("CLI add"), "(应为 0)")
ok, out = cli(["dns", "default-fallbacks"])
print("    default-fallbacks:", out.strip().replace("\n", " ")[:80])

print("\n" + "=" * 70)
print("汇总: 智能DNS开 %d/%d  vs  关 %d/%d" % (good, tot, bad, tot2))
print("=" * 70)
