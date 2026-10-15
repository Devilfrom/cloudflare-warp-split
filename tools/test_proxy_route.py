# -*- coding: utf-8 -*-
"""端到端实测 Proxy 分路 (通过 HTTP API 驱动真实服务端)。

验证:
  1. /api/route 切到 proxy 后 /api/enable 能否拉起 SOCKS5 + 分流桥
  2. 经分流桥访问国外站 -> 走 WARP (warp=on)
  3. 经分流桥访问国内站 -> 直连 (不出国)
  4. 系统路由 / WARP 适配器是否被改动 (应为 0 改动)
  5. 系统代理开关能否写入并还原
  6. 切回 TUN 路线能否正常恢复
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8777"
PY = sys.executable
APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "warp_split.py")


def api(path, obj=None, timeout=30):
    url = BASE + path
    # 注意: data=None 时 urllib 会退化成 GET, 服务端 /api/xxx 只挂在 POST 上,
    # 于是返回 404。这里强制始终是 POST。
    data = json.dumps(obj if obj is not None else {}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def status():
    with urllib.request.urlopen(BASE + "/api/status", timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def curl(args, timeout=40):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace", startupinfo=si,
                       creationflags=0x08000000)
    return p.returncode == 0, (p.stdout or "").strip()


def ps(cmd, timeout=40):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace", startupinfo=si,
                       creationflags=0x08000000)
    return (p.stdout or "").strip()


def wait_idle(max_s=180):
    t0 = time.time()
    while time.time() - t0 < max_s:
        st = status()
        if not st.get("running"):
            return st
        time.sleep(1)
    return status()


sep = "=" * 68

# ---------- 启动服务端 ----------
si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
srv = subprocess.Popen([PY, APP, "--no-browser"], cwd=os.path.dirname(APP),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       startupinfo=si, creationflags=0x08000000)
time.sleep(4)
try:
    print(sep)
    print("[0] 启动服务端")
    print(sep)
    st = status()
    print("  route_mode  :", st.get("route_mode"))
    print("  enabled     :", st.get("enabled"), "| armed 相关:", st.get("resume_pending"))
    print("  bridge_port :", st.get("bridge_port"), "| proxy_port:", st.get("proxy_port"))

    # 若当前处于启用状态先停掉, 保证从干净状态开始
    if st.get("enabled"):
        print("  先停用当前分流...")
        api("/api/disable")
        wait_idle(60)

    print()
    print(sep)
    print("[1] 切换到 Proxy 分路并启用")
    print(sep)
    print("  /api/route ->", api("/api/route", {"mode": "proxy"}))
    time.sleep(1)
    print("  /api/enable ->", api("/api/enable"))
    st = wait_idle(240)
    print("  enabled     :", st.get("enabled"))
    print("  route_active:", st.get("route_active"))
    print("  bridge_up   :", st.get("bridge_up"))
    print("  WARP 状态   :", (st.get("warp_status") or "").replace("\n", " ")[:80])
    print("  phase       :", (st.get("progress") or {}).get("phase"))
    print("  error       :", st.get("error"))

    print()
    print(sep)
    print("[2] 关键: 系统路由 / TUN 适配器是否被改动")
    print(sep)
    print("  CloudflareWARP 适配器:", ps("(Get-NetAdapter -Name 'CloudflareWARP' "
                                     "-ErrorAction SilentlyContinue).Status") or "不存在 (正确)")
    print("  WARP 接口路由条数    :", ps("(Get-NetRoute -InterfaceAlias "
                                   "'CloudflareWARP' -ErrorAction SilentlyContinue "
                                   "| Measure-Object).Count"))
    print("  默认路由:")
    print("   ", ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object "
                "RouteMetric | Select-Object -First 2 -ExpandProperty InterfaceAlias) "
                "-join ' , '"))

    print()
    print(sep)
    print("[3] 经分流桥 127.0.0.1:%d 访问" % st.get("bridge_port", 7890))
    print(sep)
    bp = st.get("bridge_port", 7890)
    ok, out = curl(["curl", "-s", "--max-time", "25", "-x", f"http://127.0.0.1:{bp}",
                    "https://www.cloudflare.com/cdn-cgi/trace"], 40)
    m = re.search(r"warp=(\w+)", out)
    print("  国外 cloudflare trace -> warp =", m.group(1) if m else "FAIL")

    ok, out = curl(["curl", "-s", "--max-time", "25", "-x", f"http://127.0.0.1:{bp}",
                    "-o", os.devnull, "-w", "%{http_code} %{time_total}s",
                    "https://www.baidu.com"], 40)
    print("  国内 baidu.com        ->", out)

    st = status()
    print("  桥计数 直连/代理      ->",
          st.get("bridge_stats", {}).get("direct"), "/",
          st.get("bridge_stats", {}).get("proxy"),
          "| 失败", st.get("bridge_stats", {}).get("errors"))

    print()
    print(sep)
    print("[4] 裸系统流量(不走代理)应该是纯直连")
    print(sep)
    ok, out = curl(["curl", "-s", "--max-time", "15",
                    "https://www.cloudflare.com/cdn-cgi/trace"], 25)
    m = re.search(r"warp=(\w+)", out)
    print("  裸直连 trace -> warp =", m.group(1) if m else "N/A", "(应为 off)")
    ok, out = curl(["curl", "-s", "--max-time", "15", "-o", os.devnull,
                    "-w", "%{http_code}", "https://www.baidu.com"], 25)
    print("  裸直连 baidu ->", out)

    print()
    print(sep)
    print("[5] 系统代理开关")
    print(sep)
    print("  打开 ->", api("/api/system-proxy", {"on": True}))
    time.sleep(1)
    print("  注册表 ProxyEnable/ProxyServer:",
          ps("Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
             "CurrentVersion\\Internet Settings' | "
             "Select-Object -ExpandProperty ProxyEnable"),
          "/",
          ps("Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
             "CurrentVersion\\Internet Settings' | "
             "Select-Object -ExpandProperty ProxyServer"))
    print("  关闭 ->", api("/api/system-proxy", {"on": False}))
    time.sleep(1)
    print("  还原后 ProxyEnable:",
          ps("Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
             "CurrentVersion\\Internet Settings' | "
             "Select-Object -ExpandProperty ProxyEnable"))

    print()
    print(sep)
    print("[6] 停用 Proxy 分路 + 切回 TUN")
    print(sep)
    api("/api/disable")
    st = wait_idle(120)
    print("  停用后 enabled:", st.get("enabled"), "| bridge_up:", st.get("bridge_up"))
    print("  /api/route ->", api("/api/route", {"mode": "tun"}))
    time.sleep(1)
    print("  /api/enable ->", api("/api/enable"))
    st = wait_idle(300)
    print("  enabled     :", st.get("enabled"), "| route_active:", st.get("route_active"))
    print("  WARP 状态   :", (st.get("warp_status") or "").replace("\n", " ")[:80])
    print("  排除规则    :", st.get("cli_exclude_count"), "条")
    ok, out = curl(["curl", "-s", "--max-time", "15",
                    "https://www.cloudflare.com/cdn-cgi/trace"], 25)
    m = re.search(r"warp=(\w+)", out)
    print("  还原后裸连 trace -> warp =", m.group(1) if m else "N/A", "(应为 on)")
    print(sep)
finally:
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except Exception:
        srv.kill()
    print("服务端已结束")
