# -*- coding: utf-8 -*-
"""验证冷启动保护: state.json 说「上次开着」, 但 daemon 没连时,
新进程不应自己去连 WARP / 自己去注入规则。"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP = Path(r"D:\C\Desktop\Cloudflare WARP")
PY = r"C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe"
CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"


def cli(*a):
    p = subprocess.run([CLI] + list(a), capture_output=True, text=True,
                       timeout=30, errors="ignore")
    return (p.stdout + p.stderr).strip()


def status():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8777/api/status", timeout=8) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_err": str(e)}


# ---- 布置场景: enabled=true 但 WARP 断开 ----
print("[准备] 把 state.json 设为 enabled=true, 并断开 WARP")
(APP / "state.json").write_text('{"enabled": true}', encoding="utf-8")
cli("disconnect")
time.sleep(3)
print("       WARP 状态:", cli("status").replace("\n", " | "))
print("       daemon 排除条数:", len([l for l in cli("tunnel", "ip", "list").splitlines()
                                     if "(CLI exclude)" in l]))

# ---- 启动程序 ----
log_path = APP / "warp_split.log"
before = log_path.stat().st_size if log_path.exists() else 0
print("\n[启动] 运行 warp_split.py --no-browser --no-tray")
proc = subprocess.Popen([PY, str(APP / "warp_split.py"), "--no-browser", "--no-tray"],
                        cwd=str(APP), creationflags=0x08000000)
print(f"       PID={proc.pid}")

try:
    # 等服务起来
    for _ in range(25):
        st = status()
        if "_err" not in st:
            break
        time.sleep(1)

    print("\n[观察] 启动后 35 秒内的行为")
    for i in range(7):
        time.sleep(5)
        s = status()
        if "_err" in s:
            print(f"  +{(i+1)*5:2d}s  接口未就绪: {s['_err']}")
            continue
        print(f"  +{(i+1)*5:2d}s  enabled={s.get('enabled')}  "
              f"running={s.get('running')}  resume_pending={s.get('resume_pending')}  "
              f"phase={s.get('progress',{}).get('phase')}")

    print("\n[结果] 最终 WARP 状态:", cli("status").replace("\n", " | "))
    print("       (期望: 仍然 Disconnected —— 程序没有自己去连)")

    # ---- 新增日志 ----
    print("\n[新增日志]")
    if log_path.exists():
        txt = log_path.read_text(encoding="utf-8", errors="ignore")
        print("\n".join("       " + l for l in txt[before:].strip().splitlines()[-14:]))
finally:
    print("\n[清理] 结束测试进程")
    subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"],
                   capture_output=True)
    time.sleep(2)
    print("       剩余监听 8777:", bool(
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "(Get-NetTCPConnection -LocalPort 8777 -State Listen "
                        "-ErrorAction SilentlyContinue | Measure-Object).Count"],
                       capture_output=True, text=True).stdout.strip() not in ("0", "")))
