# -*- coding: utf-8 -*-
"""实测打包后的 exe: 启动是否正常、是否关闭自动打开浏览器、能否正常退出。"""
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

APP = Path(r"D:\C\Desktop\Cloudflare WARP")
EXE = APP / "WARP-Split-Console.exe"


def status():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8777/api/status", timeout=8) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_err": str(e)}


def port_owner():
    p = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "(Get-NetTCPConnection -LocalPort 8777 -State Listen "
                        "-ErrorAction SilentlyContinue).OwningProcess"],
                       capture_output=True, text=True)
    return p.stdout.strip()


assert not port_owner(), "8777 已被占用, 先清理"

log_path = APP / "warp_split.log"
before = log_path.stat().st_size if log_path.exists() else 0

print(f"[启动] {EXE.name} --no-browser --no-tray")
proc = subprocess.Popen([str(EXE), "--no-browser", "--no-tray"], cwd=str(APP))
print(f"       PID={proc.pid}")

try:
    ready = False
    for _ in range(30):
        if "_err" not in status():
            ready = True
            break
        if proc.poll() is not None:
            print(f"       [!!] 进程已退出, 返回码 {proc.returncode}")
            break
        time.sleep(1)

    print(f"       服务就绪: {ready}")
    if ready:
        s = status()
        print(f"       enabled={s.get('enabled')}  fast_write={s.get('fast_write')}  "
              f"排除={s.get('cli_exclude_count')}  规则总数={s.get('list_total')}")
        print(f"       监听端口持有者 PID: {port_owner()}  (exe 的 PID={proc.pid})")

    time.sleep(3)
    print(f"       3 秒后进程是否仍在: {proc.poll() is None}")
finally:
    print("\n[关闭] taskkill")
    subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
    time.sleep(3)
    print("       端口是否释放:", not bool(port_owner()))

print("\n[新增日志]")
if log_path.exists():
    txt = log_path.read_text(encoding="utf-8", errors="ignore")
    for l in txt[before:].strip().splitlines()[-10:]:
        print("       " + l)
