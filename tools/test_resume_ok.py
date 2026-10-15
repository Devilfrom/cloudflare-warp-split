# -*- coding: utf-8 -*-
"""验证: 启动时 daemon 本来就连着 -> 程序应识别为「分流仍在生效」, 且后续允许自动重连。"""
import json
import subprocess
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


print("[准备] 把 WARP 连上 (模拟分流本来就在运行), state.json enabled=true")
(APP / "state.json").write_text('{"enabled": true}', encoding="utf-8")
cli("connect")
for _ in range(20):
    if "Connected" in cli("status"):
        break
    time.sleep(2)
print("       WARP:", cli("status").replace("\n", " | "))

proc = subprocess.Popen([PY, str(APP / "warp_split.py"), "--no-browser", "--no-tray"],
                        cwd=str(APP), creationflags=0x08000000)
print(f"\n[启动] PID={proc.pid}")
try:
    for _ in range(25):
        if "_err" not in status():
            break
        time.sleep(1)
    for i in range(4):
        time.sleep(5)
        s = status()
        if "_err" in s:
            continue
        print(f"  +{(i+1)*5:2d}s  enabled={s.get('enabled')}  "
              f"resume_pending={s.get('resume_pending')}  "
              f"auto_resume={s.get('auto_resume')}  fast_write={s.get('fast_write')}  "
              f"排除={s.get('cli_exclude_count')}  phase={s.get('progress',{}).get('phase')}")
finally:
    subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
    time.sleep(2)
    print("\n[清理] 已结束测试进程")
