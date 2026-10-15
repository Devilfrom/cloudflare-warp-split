# -*- coding: utf-8 -*-
"""验证: 停服务 -> 改写 settings.json 的 excluded_ips -> 起服务, 能否一次写入全部规则。

若成立, 5440 条规则的注入从 400 秒降到 1 秒以内, 且因为是在"未连接"状态下完成的,
用户完全不会经历断网。
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

CFG = Path(r"C:\ProgramData\Cloudflare\settings.json")
BAK = Path(r"D:\C\Desktop\Cloudflare WARP\tools\settings.json.bak")
CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
PROBE = "223.255.236.0/22"      # 真实中国 IP 段, 用来做增删测试
FAKE = "203.0.113.0/24"         # TEST-NET-3


def cli(*a, timeout=30):
    p = subprocess.run([CLI] + list(a), capture_output=True, text=True,
                       timeout=timeout, errors="ignore")
    return p.stdout + p.stderr


def excludes():
    res = set()
    for ln in cli("tunnel", "ip", "list").splitlines():
        ln = ln.strip()
        if "/" in ln:
            parts = ln.split(None, 1)
            if len(parts) == 2 and parts[1].startswith("("):
                res.add((parts[0], parts[1].strip("()")))
    return res


def read_cfg():
    return json.loads(CFG.read_text(encoding="utf-8"))


def write_cfg(d):
    tmp = CFG.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(CFG)


def ps(cmd, timeout=90):
    p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True, timeout=timeout,
                       errors="ignore")
    return (p.stdout + p.stderr).strip()


def svc_down():
    print("  停服务:", ps("Stop-Service -Name CloudflareWARP -Force") or "(已停)")
    time.sleep(5)


def svc_up():
    print("  起服务:", ps("Start-Service -Name CloudflareWARP") or "(已起)")
    time.sleep(8)


mode = sys.argv[1] if len(sys.argv) > 1 else "all"

if mode == "all":
    if not BAK.exists():
        shutil.copy2(CFG, BAK)
        print(f"已备份 -> {BAK}")
    orig = read_cfg()
    n0 = len(orig["excluded_ips"])
    print(f"当前配置 {n0} 条, daemon 报告 {len(excludes())} 条")
    BAK.write_text(json.dumps(orig, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("=" * 68)
    print("测试 B: 停服务 -> 写 -> 起服务, 验证文件写入是否生效")
    print("=" * 68)
    svc_down()
    d = read_cfg()
    before = len(d["excluded_ips"])
    d["excluded_ips"] = [e for e in d["excluded_ips"] if e[0] != PROBE]
    write_cfg(d)
    print(f"  已从配置中删除探针 {PROBE}: {before} -> {len(d['excluded_ips'])} 条")
    svc_up()
    got = excludes()
    gone = (PROBE, "CLI exclude") not in got
    print(f"  daemon 报告: {len(got)} 条")
    print(f"  探针是否已消失: {'是 [OK] 文件写入生效' if gone else '否 [!!] 未生效'}")

    print()
    print("=" * 68)
    print("测试 C: 一次性写入全量规则 + 一条伪造段, 测写入耗时")
    print("=" * 68)
    target = list(orig["excluded_ips"])
    if not any(e[0] == PROBE for e in target):
        target.append([PROBE, "CLI exclude"])
    if not any(e[0] == FAKE for e in target):
        target.append([FAKE, "CLI exclude"])
    print(f"  目标 {len(target)} 条")
    svc_down()
    t0 = time.time()
    d = read_cfg()
    d["excluded_ips"] = target
    write_cfg(d)
    dt = time.time() - t0
    svc_up()
    got = excludes()
    print(f"  文件写入耗时: {dt:.3f}s")
    print(f"  daemon 报告: {len(got)} 条")
    print(f"  伪造段 {FAKE} 已注入: {(FAKE, 'CLI exclude') in got}   <- 为真则可任意批量注入")

    print()
    print("=" * 68)
    print("清理: 还原原始配置")
    print("=" * 68)
    svc_down()
    write_cfg(orig)
    svc_up()
    got = excludes()
    print(f"  daemon 报告: {len(got)} 条 (原始 {n0})")
    print(f"  伪造段已清除: {(FAKE, 'CLI exclude') not in got}")

    cli("connect")
    time.sleep(5)
    print()
    print("最终:", cli("status").strip().replace("\n", " | "))
