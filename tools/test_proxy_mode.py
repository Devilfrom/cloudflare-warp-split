# -*- coding: utf-8 -*-
"""
实测: warp-cli 原生 proxy 模式 (不开 TUN / 不改默认路由)
验证目标:
  1. mode proxy 能否建立隧道
  2. SOCKS5 监听端口是多少、能不能真的出国
  3. 系统默认路由是否被改动 (这是 net-warp 拒用 TUN 的核心理由)
  4. 国内/局域网是否仍是纯直连
跑完自动还原到 mode warp + 已连接
"""
import json
import os
import re
import subprocess
import sys
import time

WARP = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
PROXY_PORT = 40000


def run(args, timeout=30):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace", startupinfo=si,
                       creationflags=0x08000000)
    return p.returncode == 0, (p.stdout or "") + (p.stderr or "")


def w(args, timeout=30):
    return run([WARP] + args, timeout=timeout)


def status():
    ok, out = w(["status"], timeout=10)
    return out.strip().splitlines()[0] if out.strip() else "?"


def mode():
    ok, out = w(["mode"], timeout=10)
    return out.strip()


def excludes():
    ok, out = w(["tunnel", "ip", "list"], timeout=20)
    return len(re.findall(r"\(CLI exclude\)", out))


def listening(port):
    ok, out = run(["netstat", "-ano"], timeout=20)
    for line in out.splitlines():
        if f"127.0.0.1:{port}" in line and "LISTENING" in line.upper():
            return line.strip()
    return None


def curl(args, timeout=25):
    ok, out = run(args, timeout=timeout)
    return ok, out.strip()


sep = "=" * 66
print(sep)
print("[0] 基线")
print(sep)
print("  mode    :", mode())
print("  status  :", status())
print("  排除规则:", excludes(), "条")
ok, out = curl(["curl", "-s", "--max-time", "10",
                "https://www.cloudflare.com/cdn-cgi/trace"], 20)
m = re.search(r"warp=(\w+)", out)
print("  直连(未走代理)访问 cloudflare trace -> warp =", m.group(1) if m else "N/A")

# ---------------------------------------------------------------
print()
print(sep)
print("[1] 切到 proxy 模式")
print(sep)
ok, out = w(["proxy", "port", str(PROXY_PORT)])
print("  proxy port", PROXY_PORT, "->", "OK" if ok else out[:120])
ok, out = w(["mode", "proxy"])
print("  mode proxy ->", "OK" if ok else out[:120])
print("  mode 现在是:", mode())

w(["connect"], timeout=30)
for i in range(40):
    time.sleep(1.5)
    if "Connected" in status():
        break
print("  等待连接 ->", status(), f"({i + 1} 次轮询)")

# ---------------------------------------------------------------
print()
print(sep)
print("[2] SOCKS5 端口与隧道可用性")
print(sep)
lis = None
for _ in range(10):
    lis = listening(PROXY_PORT)
    if lis:
        break
    time.sleep(1)
print(f"  127.0.0.1:{PROXY_PORT} 监听 ->", lis or "未监听!")

ok, out = curl(["curl", "-s", "--max-time", "20",
                "--socks5-hostname", f"127.0.0.1:{PROXY_PORT}",
                "https://www.cloudflare.com/cdn-cgi/trace"], 30)
m = re.search(r"warp=(\w+)", out)
ip = re.search(r"ip=([\d.]+)", out)
print("  经 SOCKS5 访问 trace -> warp =", m.group(1) if m else "FAIL",
      "| 出口 IP =", ip.group(1) if ip else "-")

ok, out = curl(["curl", "-s", "--max-time", "20",
                "--socks5-hostname", f"127.0.0.1:{PROXY_PORT}",
                "-o", os.devnull, "-w", "%{http_code}",
                "https://www.google.com/"], 30)
print("  经 SOCKS5 访问 google -> HTTP", out)

# ---------------------------------------------------------------
print()
print(sep)
print("[3] 关键: 系统路由是否被改动")
print(sep)
ok, out = run(["powershell", "-NoProfile", "-Command",
               "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
               "Sort-Object RouteMetric | "
               "Select-Object InterfaceAlias,NextHop,RouteMetric | "
               "Format-Table -AutoSize | Out-String"], timeout=40)
print(out.strip())
ok, out = run(["powershell", "-NoProfile", "-Command",
               "(Get-NetAdapter -Name 'CloudflareWARP').Status"], timeout=30)
print("  CloudflareWARP 适配器状态:", out.strip())
ok, out = run(["powershell", "-NoProfile", "-Command",
               "(Get-NetRoute -InterfaceAlias 'CloudflareWARP' | "
               "Measure-Object).Count"], timeout=30)
print("  CloudflareWARP 接口路由条数:", out.strip())

# ---------------------------------------------------------------
print()
print(sep)
print("[4] 国内 / 局域网是否仍是纯直连 (不进隧道)")
print(sep)
ok, out = curl(["curl", "-s", "--max-time", "12", "-o", os.devnull,
                "-w", "%{http_code} %{time_total}s", "https://www.baidu.com"], 20)
print("  裸直连 baidu.com ->", out)
ok, trace = curl(["curl", "-s", "--max-time", "12",
                  "https://www.cloudflare.com/cdn-cgi/trace"], 20)
m = re.search(r"warp=(\w+)", trace)
print("  裸直连(不走代理) trace -> warp =", m.group(1) if m else "N/A")

# ---------------------------------------------------------------
print()
print(sep)
print("[5] 还原到 mode warp")
print(sep)
w(["mode", "warp"], timeout=20)
w(["connect"], timeout=30)
for i in range(40):
    time.sleep(1.5)
    if "Connected" in status():
        break
print("  mode  :", mode())
print("  status:", status())
print("  排除规则:", excludes(), "条")
ok, trace = curl(["curl", "-s", "--max-time", "12",
                  "https://www.cloudflare.com/cdn-cgi/trace"], 20)
m = re.search(r"warp=(\w+)", trace)
print("  还原后 trace -> warp =", m.group(1) if m else "N/A")
print(sep)
