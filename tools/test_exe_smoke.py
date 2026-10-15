# -*- coding: utf-8 -*-
"""打包后 exe 冒烟测试: 启动 -> 查状态 -> 退出 -> 确认 DNS 已还原"""
import sys, os, time, json, subprocess, urllib.request
for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(_k, None)
os.environ["no_proxy"] = "*"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "WARP-Split-Console.exe")
BASE = "http://127.0.0.1:8777"

si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
si.wShowWindow = 0

print("启动 exe ...")
p = subprocess.Popen([EXE, "--no-browser"], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, startupinfo=si,
                     creationflags=0x08000000)
try:
    st = None
    for i in range(20):
        time.sleep(2)
        try:
            st = json.loads(urllib.request.urlopen(BASE + "/api/status",
                                                   timeout=10).read().decode())
            break
        except Exception:
            continue
    if not st:
        print("  未能在 40s 内拉到状态 —— 失败")
        sys.exit(1)
    print("  已就绪 (%ds)" % ((i + 1) * 2))
    print()
    print("  关键字段:")
    for k in ("route_mode", "enabled", "smart_dns", "dns_proxy",
              "dns_fallback", "fast_write", "cli_exclude_count",
              "connected"):
        print("    %-20s = %s" % (k, st.get(k)))
    print()
    print("  dns_stats:", st.get("dns_stats"))

    # 拉 20 次状态, 确认不再每次 fork PowerShell(应很快)
    t0 = time.time()
    for _ in range(20):
        urllib.request.urlopen(BASE + "/api/status", timeout=10).read()
    dt = time.time() - t0
    print("  连拉 20 次 /api/status 耗时 %.2fs (平均 %.0fms/次)"
          % (dt, dt * 1000 / 20))
finally:
    p.terminate()
    try:
        p.wait(timeout=15)
    except Exception:
        p.kill()
    print("\n  已结束 exe")

print("\n退出后检查网卡 DNS 是否还原:")
r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
                    "Services\\Tcpip\\Parameters\\Interfaces\\*' -Name NameServer "
                    "-ErrorAction SilentlyContinue | Where-Object { $_.NameServer } | "
                    "ForEach-Object { $_.NameServer }"],
                   capture_output=True, text=True, timeout=60)
vals = (r.stdout or "").strip()
print("  注册表静态 DNS:", vals or "(无)")
print("  含 127.0.0.1 ?", "是 ❌" if "127.0.0.1" in vals else "否 ✅")
