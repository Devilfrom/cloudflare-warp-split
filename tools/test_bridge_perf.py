# -*- coding: utf-8 -*-
"""分流桥性能: 国内站经桥访问是否和裸直连一样快 (验证 DoH IP 直连优化)。"""
import json
import os
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8777"
PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "warp_split.py")

TARGETS = ["https://www.baidu.com", "https://www.qq.com",
           "https://www.cloudflare.com/cdn-cgi/trace"]


def api(path, obj=None, timeout=30):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(obj or {}).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def status():
    with urllib.request.urlopen(BASE + "/api/status", timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def timed(args, timeout=40):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    t = time.time()
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace", startupinfo=si,
                       creationflags=0x08000000)
    return time.time() - t, (p.stdout or "").strip()


def wait_idle(max_s=240):
    t0 = time.time()
    while time.time() - t0 < max_s:
        st = status()
        if not st.get("running"):
            return st
        time.sleep(1)
    return status()


si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
srv = subprocess.Popen([PY, APP, "--no-browser"], cwd=os.path.dirname(APP),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       startupinfo=si, creationflags=0x08000000)
time.sleep(4)
try:
    st = status()
    if st.get("enabled"):
        api("/api/disable")
        wait_idle(60)
    api("/api/route", {"mode": "proxy"})
    time.sleep(1)
    api("/api/enable")
    st = wait_idle(240)
    print("bridge_up:", st.get("bridge_up"), "| route_active:", st.get("route_active"))
    bp = st.get("bridge_port", 7890)

    for url in TARGETS:
        print("\n---", url)
        for i in range(1, 3):
            t, out = timed(["curl", "-s", "--max-time", "25",
                            "-x", f"http://127.0.0.1:{bp}",
                            "-o", os.devnull, "-w", "%{http_code}", url], 40)
            print(f"   经桥 第{i}次: {t:.2f}s  HTTP {out}")
        t, out = timed(["curl", "-s", "--max-time", "25",
                        "-o", os.devnull, "-w", "%{http_code}", url], 40)
        print(f"   裸直连      : {t:.2f}s  HTTP {out}")

    st = status()
    print("\n桥计数:", st.get("bridge_stats"))
finally:
    api("/api/disable")
    wait_idle(60)
    api("/api/route", {"mode": "tun"})
    time.sleep(1)
    api("/api/enable")
    st = wait_idle(300)
    print("已还原 TUN: enabled=", st.get("enabled"),
          "route_active=", st.get("route_active"),
          "规则=", st.get("cli_exclude_count"), "条")
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except Exception:
        srv.kill()
