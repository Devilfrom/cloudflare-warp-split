# -*- coding: utf-8 -*-
"""把分流恢复到启用状态, 并确认智能 DNS 已接管。"""
import sys, os, time, json, socket, urllib.request
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)
os.environ["no_proxy"] = "*"
BASE = "http://127.0.0.1:8777"


def get():
    return json.loads(urllib.request.urlopen(BASE + "/api/status", timeout=30).read().decode())


def post(p, obj=None):
    data = json.dumps(obj).encode() if obj is not None else b"{}"
    req = urllib.request.Request(BASE + p, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=300).read().decode())


st = get()
print("初始: enabled=%s dns_proxy=%s" % (st.get("enabled"), st.get("dns_proxy")))
if not st.get("enabled"):
    print("启用中...")
    post("/api/enable")
    for i in range(60):
        time.sleep(3)
        s = get()
        if not s.get("running"):
            break
    print("  完成 (%ds)" % ((i + 1) * 3))

for i in range(15):
    time.sleep(3)
    s = get()
    fb = s.get("dns_fallback") or ""
    if "127.0.0.1" in fb:
        break
s = get()
print()
print("最终状态:")
for k in ("connected", "enabled", "dns_proxy", "dns_fallback", "cli_exclude_count"):
    print("  %-18s = %s" % (k, s.get(k)))
print("  dns_stats        =", s.get("dns_stats"))
print()
print("解析校验:")
for h in ["www.baidu.com", "www.taobao.com", "www.qq.com", "www.google.com"]:
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})
    except Exception:
        ips = []
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import warp_split as W
    cn = sum(1 for i in ips if W.is_cn_ip(i))
    tag = "国内 OK" if (ips and cn == len(ips)) else "境外"
    print("  %-20s %-42s %s" % (h, ",".join(ips[:2]), tag))
