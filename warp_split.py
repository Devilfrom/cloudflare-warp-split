#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare WARP 智能分流控制台 —— 后端
=========================================
功能:
  - 国际流量走 Cloudflare WARP 出口 (warp 全隧道)
  - 国内 (中国大陆) 流量直连 (通过 WARP split-tunnel 排除规则)
  - 可视化控制台 (index.html) + 一键开关 / 一键还原
  - 开机自启 (计划任务) / 断线自动重连 / 系统托盘 / 速率·延迟监控
  - 规则列表导入与管理 / 后台自动更新规则 / 暗亮主题 / Zero Trust 检测

技术要点:
  - 仅依赖 Python 标准库 (托盘用 ctypes, 无需第三方包)
  - 启用: disconnect -> mode warp -> connect -> 并发注入中国 IP 到 WARP 排除列表
  - 停用/还原: disconnect + tunnel ip reset (瞬间清空自定义排除)
  - 状态持久化到 state.json / settings.json, 异常自动回滚
"""

import os
import sys
import re
import json
import time
import struct
import shutil
import socket
import threading
import subprocess

# ====================== 子进程无窗口启动 ======================
# 必须统一走 _run(): 打包后的程序是 --windowed(无控制台), 此时任何
# subprocess 调用都会新建一个黑色控制台窗口并瞬间消失。守护线程
# (断线重连/延迟探测/出口IP/规则更新)是周期性调用的, 于是黑窗口
# 不停地闪 —— 表现为「cmd 蹦迪」。
_IS_WIN = (os.name == "nt")
_NO_WINDOW_FLAGS = 0x08000000 if _IS_WIN else 0   # CREATE_NO_WINDOW

if _IS_WIN:
    _SI = subprocess.STARTUPINFO()
    _SI.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _SI.wShowWindow = 0                        # SW_HIDE
else:
    _SI = None


def _run(cmd, **kw):
    """subprocess.run 的包装: Windows 下强制隐藏控制台窗口。

    其余行为与 subprocess.run 完全一致, 返回值对象的
    .returncode / .stdout / .stderr 用法不变。
    """
    if _IS_WIN:
        kw.setdefault("startupinfo", _SI)
        kw.setdefault("creationflags", _NO_WINDOW_FLAGS)
    return subprocess.run(cmd, **kw)
import logging
import webbrowser
import ctypes
import ctypes.wintypes  # 必须显式导入: MSG/POINT 等类型在此子模块, 仅 import ctypes 不会加载
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ====================== 配置 ======================
# PyInstaller 打包后 __file__ 指向临时解压目录(_MEIxxx), 会在进程退出后被删除。
# 因此区分两个目录:
#   RES_DIR  - 只读资源目录(内置的 index.html / china_cidr.txt 初始副本)
#   APP_DIR  - 可写数据目录(china_cidr.txt / settings.json / state.json / 日志)
#             打包后取 exe 所在目录, 保证配置能持久化。
IS_FROZEN = getattr(sys, "frozen", False)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

if IS_FROZEN:
    RES_DIR = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    APP_DIR = os.path.dirname(sys.executable)
else:
    RES_DIR = _SCRIPT_DIR
    APP_DIR = _SCRIPT_DIR


def asset_path(name):
    """定位随程序分发的资源文件。

    优先使用 APP_DIR(data 目录/exe 同级目录)下的版本，便于用户直接修改；
    若不存在则回退到打包内置的 RES_DIR 版本。
    """
    p = os.path.join(APP_DIR, name)
    if os.path.isfile(p):
        return p
    return os.path.join(RES_DIR, name)


def port_in_use(port, host="127.0.0.1", timeout=0.6):
    """检测端口是否已有服务在监听(即已有实例在运行)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def pause(msg="按回车退出..."):
    """打包为窗口模式(--windowed)时没有控制台，input() 会抛异常。"""
    try:
        if sys.stdin is None or sys.stdin.closed or not sys.stdin.isatty():
            return
        input(msg)
    except Exception:
        pass


def alert(msg, title="Cloudflare WARP 分流控制台"):
    """向用户显示错误提示。

    打包为窗口模式后没有控制台, 打印到 stdout 用户是看不到的, 提权失败
    这类致命错误必须用消息框弹出来, 否则表现为「双击后毫无反应」。
    """
    try:
        if IS_FROZEN:
            ctypes.windll.user32.MessageBoxW(None, msg, title, 0x10)  # MB_ICONERROR
        else:
            print(msg)
    except Exception:
        pass


def ensure_data_files():
    """打包模式下，把内置资源首次复制到 exe 同级目录，保证可持久化。"""
    if not IS_FROZEN:
        return
    for name in ("index.html", "china_cidr.txt"):
        dst = os.path.join(APP_DIR, name)
        src = os.path.join(RES_DIR, name)
        if not os.path.isfile(dst) and os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass


WARP_CLI_CANDIDATES = [
    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"D:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
]
CHINA_LIST = os.path.join(APP_DIR, "china_cidr.txt")
RULES_DIR = os.path.join(APP_DIR, "rules")
STATE_FILE = os.path.join(APP_DIR, "state.json")
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
LOG_FILE = os.path.join(APP_DIR, "warp_split.log")
PORT = int(os.environ.get("WARP_SPLIT_PORT", "8777"))
WORKERS = int(os.environ.get("WARP_SPLIT_WORKERS", "20"))
# 测试用: 限制注入的国内网段数量 (0 = 全部)
MAX_RANGES = int(os.environ.get("WARP_SPLIT_MAX", "0"))
APNIC_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
EGRESS_SERVICES = [
    "https://api.ipify.org",
    "https://myip.ipip.net",
    "https://ipinfo.io/ip",
]
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=25000000"
AUTOSTART_TASK = "CloudflareWARP-Split"

# ====================== 全局状态 ======================
state = {
    "enabled": False,
    "running": False,
    "action": None,
    "progress": {"total": 0, "done": 0, "phase": "空闲"},
    "error": None,
    "reconnecting": False,
    "zerotrust_locked": False,
}
state_lock = threading.Lock()
op_stop = threading.Event()
EXIT_EVENT = threading.Event()
log_lines = []
log_lock = threading.Lock()

# 设置 (持久化到 settings.json)
settings = {
    "theme": "dark",
    "auto_reconnect": True,
    "auto_update": False,
    "metrics_speed": True,
    "tray": True,
    "active_lists": ["china_cidr.txt"],
}

# 指标 (内存态, 不持久化)
metrics = {
    "latency_cn": None,
    "latency_intl": None,
    "dl_speed_mbps": None,
    "egress_ip": "—",
    "uptime_s": 0,
    "connected_since": None,
    "start_ts": time.time(),
    "last_speed_ts": 0,
}
metrics_history = []  # 近 60 个采样点 {t,cn,intl,spd}
metrics_lock = threading.Lock()

# ====================== 日志 ======================
logger = logging.getLogger("warp_split")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)


def log(msg, level=logging.INFO):
    logger.log(level, msg)
    with log_lock:
        log_lines.append(msg)
        if len(log_lines) > 600:
            del log_lines[:200]


# ====================== 工具函数 ======================
def find_warp_cli():
    for p in WARP_CLI_CANDIDATES:
        if os.path.exists(p):
            return p
    try:
        r = _run(["where", "warp-cli"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return None


def warp(args, timeout=30):
    """调用 warp-cli, 返回 (ok, output)。"""
    cli = find_warp_cli()
    if not cli:
        return False, "warp-cli 未找到"
    try:
        r = _run([cli] + args, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "命令超时"
    except Exception as e:
        return False, str(e)


def restart_warp_service():
    """重启 CloudflareWARP 服务, 用于清除卡死的 daemon 状态 (happy eyeballs 卡住时兜底)。"""
    try:
        _run(["net", "stop", "CloudflareWARP"], capture_output=True, text=True, timeout=30)
        time.sleep(3)
        _run(["net", "start", "CloudflareWARP"], capture_output=True, text=True, timeout=30)
        time.sleep(5)
        return True
    except Exception as e:
        log("重启 CloudflareWARP 服务失败: " + str(e), logging.WARNING)
        return False


def read_list_file(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    out.append(line)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def read_china_list():
    return read_list_file(CHINA_LIST)


def read_active_ranges():
    """读取所有"激活"的规则列表 (默认 china_cidr.txt + 自定义导入列表)。"""
    ranges = []
    for name in settings.get("active_lists", ["china_cidr.txt"]):
        if not name:
            continue
        p = name if os.path.isabs(name) else os.path.join(APP_DIR, name)
        if os.path.exists(p):
            ranges += read_list_file(p)
    # 去重保序
    seen = set()
    uniq = []
    for r in ranges:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def get_egress_ip():
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for url in EGRESS_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                data = resp.read().decode("utf-8", "ignore").strip()
                import re
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", data)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return "获取失败"


def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"enabled": state["enabled"]}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_settings():
    global settings
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                for k, v in d.items():
                    settings[k] = v
    except Exception:
        pass


def save_settings():
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_state():
    """从 state.json 恢复 enabled 标志 (进程重启后仍能正确反映实时分流状态)。"""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                state["enabled"] = bool(d.get("enabled", False))
    except Exception:
        pass


def tcp_rtt(host, port=443, timeout=1.0):
    """TCP 握手 RTT (ms), 作为 ICMP 不可达时的延迟兜底。"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t = time.time()
        s.connect((host, port))
        rtt = (time.time() - t) * 1000.0
        s.close()
        return round(rtt, 1)
    except Exception:
        return None


# ====================== 分流自检 / IPv6 修复 ======================
CLOUDFLARE_NETS = [ipaddress.ip_network(c) for c in [
    "104.16.0.0/12", "162.158.0.0/15", "172.64.0.0/13", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "104.28.0.0/16", "141.101.64.0/18",
    "162.159.0.0/16", "188.114.0.0/16", "190.93.240.0/20",
    "2400:cb00::/32", "2606:4700::/32",
]]


def is_cloudflare_ip(ip):
    if not ip or ip == "获取失败":
        return False
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(a in n for n in CLOUDFLARE_NETS)


def first_hop(host):
    """tracert 取第一跳 IP (用于判断该目的走直连还是 WARP 隧道)。"""
    import re
    try:
        r = _run(["tracert", "-d", "-h", "2", "-w", "700", host],
                           capture_output=True, text=True, timeout=20, errors="ignore")
        for ln in r.stdout.splitlines():
            s = ln.strip()
            if s.startswith("1 "):
                for tok in reversed(s.split()):
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", tok):
                        return tok
    except Exception:
        pass
    return None


def self_test():
    """只读自检: 验证分流是否真正生效 (不改变任何配置)。"""
    egress = get_egress_ip()
    ok, out = warp(["status"])
    connected = "Connected" in out
    ok2, listout = warp(["tunnel", "ip", "list"])
    cli_count = listout.count("(CLI exclude)")

    cn_ip = "1.0.1.1"          # 在 china_cidr.txt 首段 (1.0.1.0/24) 内
    cn_hop = first_hop(cn_ip)
    cn_direct = False
    if cn_hop:
        try:
            cn_direct = ipaddress.ip_address(cn_hop).is_private
        except Exception:
            cn_direct = False

    fx_ip = "8.8.8.8"          # 不在国内列表 -> 应走 WARP
    fx_hop = first_hop(fx_ip)
    fx_via_warp = bool(fx_hop) and is_cloudflare_ip(fx_hop)

    is_cf = is_cloudflare_ip(egress)
    verdict = connected and is_cf and cli_count > 0 and cn_direct
    return {
        "verdict": "PASS" if verdict else "FAIL",
        "connected": connected,
        "egress_ip": egress,
        "egress_via_warp": is_cf,
        "cli_exclude_count": cli_count,
        "china_test": {"ip": cn_ip, "first_hop": cn_hop, "direct": cn_direct},
        "foreign_test": {"ip": fx_ip, "first_hop": fx_hop, "via_warp": fx_via_warp},
        "msg": "" if verdict else "未通过：请确认 WARP 已连接、出口 IP 属于 Cloudflare、国内规则已注入且中国 IP 走本地网关直连。",
    }


def fix_ipv6():
    """禁用 CloudflareWARP 虚拟适配器的 IPv6, 解决 WARP 连接卡在 happy eyeballs 的问题。"""
    import re
    try:
        r = _run(["netsh", "interface", "ipv6", "show", "interfaces"],
                           capture_output=True, text=True, timeout=20, errors="ignore")
        idx = None
        for ln in r.stdout.splitlines():
            if "CloudflareWARP" in ln:
                m = re.match(r"\s*(\d+)\s+", ln)
                if m:
                    idx = m.group(1)
                    break
        if not idx:
            return False, "未找到 CloudflareWARP 适配器 (接口名可能不是 CloudflareWARP)"
        res = _run(["netsh", "interface", "ipv6", "set", "interface", idx, "disabled"],
                             capture_output=True, text=True, timeout=20, errors="ignore")
        if res.returncode != 0:
            return False, (res.stdout + res.stderr).strip() or "netsh 返回非零"
        return True, "已禁用 CloudflareWARP 适配器 IPv6 (若仍连不上可再点一次本按钮恢复)"
    except Exception as e:
        return False, str(e)


# ====================== 连接 / 重连 ======================
def connect_warp(max_attempts=4, update_phase=True):
    """连接 WARP, 带『断重连 + 服务重启』兜底。返回 (connected, last_out)。"""
    connected = False
    last_out = ""
    for attempt in range(1, max_attempts + 1):
        if op_stop.is_set():
            return False, "用户取消了操作"
        if update_phase:
            with state_lock:
                state["progress"] = {"total": 0, "done": 0,
                                     "phase": f"正在连接 WARP 隧道 (第 {attempt}/{max_attempts} 次尝试)..."}
        log(f"尝试连接 WARP (第 {attempt}/{max_attempts} 次)...")
        warp(["disconnect"], timeout=20)
        time.sleep(2)
        ok, out = warp(["--accept-tos", "connect"], timeout=30)
        log("connect: " + out)
        for _ in range(18):
            if op_stop.is_set():
                return False, "用户取消了操作"
            ok, out = warp(["status"], timeout=10)
            last_out = out
            with state_lock:
                state["warp_status"] = out.replace("\n", " ")
            if "Connected" in out:
                connected = True
                break
            time.sleep(2)
        if connected:
            break
        log(f"第 {attempt} 次连接未成功 (状态: {last_out[:90]})", logging.WARNING)
    if not connected:
        log("常规重试未连上, 尝试重启 CloudflareWARP 服务...", logging.WARNING)
        restart_warp_service()
        warp(["mode", "warp"], timeout=20)
        time.sleep(1)
        warp(["disconnect"], timeout=20)
        time.sleep(2)
        warp(["--accept-tos", "connect"], timeout=30)
        for _ in range(18):
            if op_stop.is_set():
                return False, "用户取消了操作"
            ok, out = warp(["status"], timeout=10)
            last_out = out
            with state_lock:
                state["warp_status"] = out.replace("\n", " ")
            if "Connected" in out:
                connected = True
                break
            time.sleep(2)
    return connected, last_out


# ====================== 核心操作 ======================
def enable_split():
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "enable"
        state["error"] = None
        state["progress"] = {"total": 0, "done": 0, "phase": "准备中..."}
    log("开始启用分流...")
    try:
        cli = find_warp_cli()
        if not cli:
            raise RuntimeError("未找到 warp-cli.exe，请确认 Cloudflare WARP 已安装")
        log("WARP 路径: " + cli)

        warp(["disconnect"], timeout=20)
        time.sleep(2)

        ok, out = warp(["mode", "warp"], timeout=20)
        if not ok:
            log("设置 mode warp 返回: " + out, logging.WARNING)
        else:
            log("mode warp 设置完成")

        connected, last_out = connect_warp(update_phase=True)
        if not connected:
            raise RuntimeError(
                "WARP 未能连接。最后状态: " + last_out[:160] +
                " | 常见原因: 到 Cloudflare WARP 端点(162.159.x.x:443)的握手被网络阻断, 或 IPv6 探测(happy eyeballs)卡住。"
                "建议: 多试 1-2 次; 或在『网络适配器 -> CloudflareWARP -> 属性』取消 IPv6 勾选后重试; 确认 WARP 账号可用。"
            )
        log("WARP 已连接")

        ranges = read_active_ranges()
        if MAX_RANGES > 0:
            ranges = ranges[:MAX_RANGES]
        total = len(ranges)
        if total == 0:
            raise RuntimeError("规则列表为空，请点击『更新中国IP列表』或导入规则")
        log(f"准备注入 {total} 条分流规则 (并发 {WORKERS})")
        with state_lock:
            state["progress"] = {"total": total, "done": 0, "phase": "注入分流规则..."}

        added = []
        done_cnt = 0
        done_lock = threading.Lock()

        def do_add(c):
            if op_stop.is_set():
                return False
            for _ in range(2):
                ok, out = warp(["tunnel", "ip", "add-range", c], timeout=20)
                if ok:
                    return True
                if "already" in out.lower():
                    return True
                low = out.lower()
                if any(k in low for k in ["not allowed", "not permitted", "policy",
                                          "organization", "managed by", "team", "locked"]):
                    with state_lock:
                        state["zerotrust_locked"] = True
                    log("检测到 Zero Trust 策略锁定 split-tunnel: " + out[:120], logging.ERROR)
                    return False
                time.sleep(0.3)
            return False

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(do_add, c): c for c in ranges}
            for f in futures:
                if f.result():
                    added.append(futures[f])
                with done_lock:
                    done_cnt += 1
                    if done_cnt % 100 == 0 or done_cnt == total:
                        with state_lock:
                            state["progress"]["done"] = done_cnt

        if op_stop.is_set():
            raise RuntimeError("用户取消了操作")

        with state_lock:
            state["enabled"] = True
            state["progress"] = {"total": total, "done": total, "phase": "分流已启用"}
        save_state()
        log(f"分流启用完成: 成功注入 {len(added)}/{total} 条规则 (其余已存在或被跳过)")
    except Exception as e:
        log("启用失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
        try:
            warp(["disconnect"], timeout=20)
            warp(["tunnel", "ip", "reset"], timeout=20)
        except Exception:
            pass
        with state_lock:
            state["enabled"] = False
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


def disable_split():
    """停用分流: 清空自定义排除 + 断开, 网络恢复正常。"""
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "disable"
        state["progress"] = {"total": 0, "done": 0, "phase": "正在关闭分流..."}
    log("开始停用分流...")
    try:
        warp(["tunnel", "ip", "reset"], timeout=30)
        warp(["disconnect"], timeout=20)
        with state_lock:
            state["enabled"] = False
            state["progress"] = {"total": 0, "done": 0, "phase": "已停用，网络恢复正常"}
        save_state()
        log("分流已停用，网络恢复正常")
    except Exception as e:
        log("停用失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


def restore():
    """一键还原 (紧急): 终止正在进行的操作, 强制断开 + 重置, 回到干净状态。"""
    log("执行一键还原...")
    op_stop.set()
    for _ in range(100):
        with state_lock:
            if not state["running"]:
                break
        time.sleep(0.2)
    op_stop.clear()
    try:
        warp(["disconnect"], timeout=20)
        warp(["tunnel", "ip", "reset"], timeout=30)
    except Exception:
        pass
    with state_lock:
        state["enabled"] = False
        state["error"] = None
        state["reconnecting"] = False
        state["progress"] = {"total": 0, "done": 0, "phase": "已还原 (干净状态)"}
    save_state()
    log("已执行一键还原，网络恢复默认")


def refresh_list():
    """从 APNIC 重新拉取中国大陆 IPv4 分配并生成 china_cidr.txt。"""
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "refresh"
        state["progress"] = {"total": 0, "done": 0, "phase": "更新中国IP列表..."}
    log("开始从 APNIC 更新中国IP列表...")
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = urllib.request.urlopen(APNIC_URL, timeout=60, context=ctx).read().decode("utf-8", "ignore").splitlines()
        cidrs = []
        for ln in data:
            p = ln.split("|")
            if len(p) < 7:
                continue
            if p[1].upper() == "CN" and p[2] == "ipv4" and p[6] == "allocated":
                try:
                    ip = int(ipaddress.IPv4Address(p[3]))
                    cnt = int(p[4])
                except Exception:
                    continue
                for net in ipaddress.summarize_address_range(ipaddress.IPv4Address(ip), ipaddress.IPv4Address(ip + cnt - 1)):
                    cidrs.append(net)
        merged = list(ipaddress.collapse_addresses(cidrs))
        out = [str(n) for n in merged]
        with open(CHINA_LIST, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        log(f"中国IP列表已更新: 共 {len(out)} 条")
        with state_lock:
            state["progress"] = {"total": 0, "done": 0, "phase": f"列表已更新({len(out)}条)"}
    except Exception as e:
        log("更新中国IP列表失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


# ====================== 规则列表管理 ======================
def get_cli_excludes():
    ok, out = warp(["tunnel", "ip", "list"], timeout=15)
    res = set()
    if not ok:
        return res
    for ln in out.splitlines():
        ln = ln.strip()
        if "(CLI exclude)" in ln:
            cidr = ln.split()[0].strip()
            try:
                ipaddress.ip_network(cidr, strict=False)
                res.add(cidr)
            except Exception:
                pass
    return res


def apply_diff_rules():
    """后台自动更新: 重新拉取最新列表, 对 daemon 排除列表做增量 diff (新增/删除)。"""
    try:
        old = read_active_ranges()
        refresh_list_data()
        new = read_active_ranges()
        current = get_cli_excludes()
        desired = set(new)
        to_add = desired - current
        to_del = current - desired
        if to_del:
            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                list(ex.map(lambda c: warp(["tunnel", "ip", "remove-range", c], timeout=15), to_del))
        if to_add:
            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                list(ex.map(lambda c: warp(["tunnel", "ip", "add-range", c], timeout=15), to_add))
        log(f"后台自动更新规则完成: 新增 {len(to_add)} 条, 移除 {len(to_del)} 条")
    except Exception as e:
        log("后台自动更新规则失败: " + str(e), logging.WARNING)


def refresh_list_data():
    """与 refresh_list 同逻辑但供后台线程调用 (不修改 state.running)。"""
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = urllib.request.urlopen(APNIC_URL, timeout=60, context=ctx).read().decode("utf-8", "ignore").splitlines()
        cidrs = []
        for ln in data:
            p = ln.split("|")
            if len(p) < 7:
                continue
            if p[1].upper() == "CN" and p[2] == "ipv4" and p[6] == "allocated":
                try:
                    ip = int(ipaddress.IPv4Address(p[3]))
                    cnt = int(p[4])
                except Exception:
                    continue
                for net in ipaddress.summarize_address_range(ipaddress.IPv4Address(ip), ipaddress.IPv4Address(ip + cnt - 1)):
                    cidrs.append(net)
        merged = list(ipaddress.collapse_addresses(cidrs))
        out = [str(n) for n in merged]
        with open(CHINA_LIST, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        return len(out)
    except Exception as e:
        log("刷新列表数据失败: " + str(e), logging.WARNING)
        return 0


def import_rule_list(name, source, value):
    """导入自定义规则列表。source=url|text。返回 (ok, msg)。"""
    if not name or "/" in name or "\\" in name:
        return False, "名称非法 (不能含路径分隔符)"
    os.makedirs(RULES_DIR, exist_ok=True)
    lines = []
    if source == "url":
        try:
            import urllib.request
            ctx = ssl_create()
            data = urllib.request.urlopen(value, timeout=30, context=ctx).read().decode("utf-8", "ignore").splitlines()
            for ln in data:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                try:
                    ipaddress.ip_network(ln, strict=False)
                    lines.append(ln)
                except Exception:
                    continue
        except Exception as e:
            return False, "下载失败: " + str(e)
    else:
        for ln in value.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            try:
                ipaddress.ip_network(ln, strict=False)
                lines.append(ln)
            except Exception:
                continue
    if not lines:
        return False, "未解析到任何有效 CIDR 规则"
    # 去重
    seen = set(); uniq = []
    for l in lines:
        if l not in seen:
            seen.add(l); uniq.append(l)
    path = os.path.join(RULES_DIR, name + ".txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(uniq) + "\n")
    rel = os.path.join("rules", name + ".txt").replace("\\", "/")
    if rel not in settings["active_lists"]:
        settings["active_lists"].append(rel)
        save_settings()
    return True, f"已导入 {len(uniq)} 条规则 -> rules/{name}.txt (已加入激活列表)"


def delete_rule_list(name):
    rel = name if name.startswith("rules/") else os.path.join("rules", name + ".txt").replace("\\", "/")
    if rel == "china_cidr.txt" or name == "china_cidr.txt":
        return False, "内置 china_cidr.txt 不可删除"
    path = os.path.join(APP_DIR, rel)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        return False, str(e)
    if rel in settings["active_lists"]:
        settings["active_lists"].remove(rel)
        save_settings()
    return True, "已删除 " + rel


def ssl_create():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ====================== 后台守护线程 ======================
def reconnect_loop():
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(15)
        try:
            if not settings.get("auto_reconnect", True):
                continue
            if not state["enabled"]:
                continue
            if state["running"]:
                continue
            ok, out = warp(["status"], timeout=10)
            if "Connected" in out:
                with state_lock:
                    state["reconnecting"] = False
                continue
            log("检测到 WARP 断开, 自动重连中...", logging.WARNING)
            with state_lock:
                state["reconnecting"] = True
            connected, last = connect_warp(max_attempts=3, update_phase=False)
            with state_lock:
                state["reconnecting"] = False
            if connected:
                log("WARP 已自动重连, 重新注入分流规则...")
                # 重连后排除规则可能丢失, 重新注入
                ranges = read_active_ranges()
                if MAX_RANGES > 0:
                    ranges = ranges[:MAX_RANGES]
                for c in ranges:
                    warp(["tunnel", "ip", "add-range", c], timeout=15)
            else:
                log("自动重连失败: " + last[:120], logging.ERROR)
        except Exception as e:
            log("reconnect loop err: " + str(e), logging.WARNING)


def autoupdate_loop():
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(24 * 3600)
        try:
            if not settings.get("auto_update", False):
                continue
            if state["zerotrust_locked"]:
                log("Zero Trust 锁定, 跳过自动更新", logging.WARNING)
                continue
            if state["running"]:
                continue
            if not state["enabled"]:
                # 仅刷新列表文件, 不改动 daemon
                n = refresh_list_data()
                log(f"已静默刷新中国IP列表({n}条, 未启用故不注入)")
                continue
            apply_diff_rules()
        except Exception as e:
            log("autoupdate loop err: " + str(e), logging.WARNING)


def ping_host(host, timeout_ms=1000):
    """返回延迟(ms) 或 None。"""
    try:
        r = _run(["ping", "-n", "1", "-w", str(timeout_ms), host],
                           capture_output=True, text=True, timeout=8, errors="ignore")
        import re
        m = re.search(r"(?:时间|time)[=<]\s*(\d+(?:\.\d+)?)\s*ms", r.stdout, re.IGNORECASE)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return None


# 延迟探测点池(均位于中国大陆 CIDR 列表内, 会走直连)
CN_PROBES = [
    ("36.152.44.96", 443), ("36.152.44.95", 443),
    ("110.242.68.4", 443), ("110.242.68.3", 443),
    ("182.61.200.7", 443), ("182.61.200.6", 443),
]
# 国际探测点(不在 CN 列表, 启用分流后走 WARP)
INTL_PROBES = [("1.1.1.1", 443), ("1.0.0.1", 443), ("8.8.8.8", 443)]


def probe_latency(probes, http_fallback=None, timeout=1.2):
    """依次尝试 ICMP -> 各探测点 TCP 握手 -> HTTPS 兜底, 返回首个成功值(ms)。"""
    # 1) ICMP(若本机放通则最准)
    for ip, _ in probes:
        v = ping_host(ip, timeout_ms=int(timeout * 1000))
        if v:
            return v
    # 2) TCP 握手(多数网络下最可靠)
    for ip, port in probes:
        v = tcp_rtt(ip, port, timeout=timeout)
        if v:
            return v
    # 3) HTTPS 往返兜底
    if http_fallback:
        v = http_rtt(http_fallback)
        if v:
            return v
    return None


def http_rtt(url, timeout=3.0):
    """HTTPS GET 往返耗时(ms)。用于国内目标——多数国内IP不响应ICMP/裸TCP。"""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        t0 = time.time()
        with opener.open(url, timeout=timeout, ) as resp:
            resp.read(256)
        return round((time.time() - t0) * 1000, 1)
    except Exception:
        return None


def measure_speed(url, dur=4):
    """下载 dur 秒, 返回 Mbps。绕过系统代理以测得真实吞吐。"""
    import urllib.request
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = opener.open(req, timeout=dur + 15)
        start = time.time()
        total = 0
        while time.time() - start < dur:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
        elapsed = time.time() - start
        if elapsed <= 0:
            return None
        return (total * 8) / (elapsed * 1_000_000)
    except Exception:
        return None


def egress_loop():
    """独立线程: 每 30s 刷新出口 IP, 避免拖慢延迟采样循环。"""
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(30)
        try:
            ip = get_egress_ip()
            with metrics_lock:
                metrics["egress_ip"] = ip
        except Exception:
            pass


def metrics_loop():
    intl_url = "https://www.cloudflare.com/cdn-cgi/trace"
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(3)
        try:
            lat_cn = probe_latency(CN_PROBES)
            lat_intl = probe_latency(INTL_PROBES, http_fallback=intl_url)
            with metrics_lock:
                metrics["latency_cn"] = lat_cn
                metrics["latency_intl"] = lat_intl
                # 速率每 ~30s 测一次
                if settings.get("metrics_speed", True) and (time.time() - metrics["last_speed_ts"] >= 30):
                    spd = measure_speed(SPEED_TEST_URL, dur=4)
                    if spd is not None:
                        metrics["dl_speed_mbps"] = round(spd, 1)
                    metrics["last_speed_ts"] = time.time()
                spd = metrics.get("dl_speed_mbps")
                metrics_history.append({
                    "t": int(time.time()),
                    "cn": lat_cn, "intl": lat_intl,
                    "spd": spd,
                })
                if len(metrics_history) > 60:
                    metrics_history.pop(0)
        except Exception as e:
            log("metrics err: " + str(e), logging.DEBUG)


# ====================== 开机自启 (计划任务) ======================
def autostart_enabled():
    try:
        r = _run(["schtasks", "/query", "/tn", AUTOSTART_TASK, "/fo", "LIST"],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def register_autostart():
    py = sys.executable
    script = os.path.abspath(__file__)
    # /tr 用列表传入, 避免 shell 引号问题
    # 开机自启时不去自动弹浏览器(只在托盘待命), 用 --no-browser 控制
    tr = '"%s" "%s" --tray %s' % (py, script, NO_BROWSER_FLAG)
    r = _run(
        ["schtasks", "/create", "/tn", AUTOSTART_TASK, "/tr", tr,
         "/sc", "onlogon", "/rl", "highest", "/f"],
        capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def unregister_autostart():
    r = _run(["schtasks", "/delete", "/tn", AUTOSTART_TASK, "/f"],
                       capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


# ====================== Zero Trust 检测 ======================
def detect_zerotrust():
    """判定是否为 Zero Trust(团队版) 且策略锁定分流。
    依据: warp-cli settings 中的 Switch Locked / Organization / 组织策略来源。"""
    _, so = warp(["settings"], timeout=10)
    low = so.lower()
    locked = False
    if "organization" in low or "managed by" in low:
        locked = True
    # 仅当组织策略显式锁定开关时才判定为受限
    m = re.search(r"switch locked:\s*(\w+)", low)
    if m and m.group(1) == "true":
        locked = True
    if locked:
        with state_lock:
            state["zerotrust_locked"] = True
    # 摘要: 只回传与判定相关的行, 避免把整份配置暴露给前端
    keep = [ln.strip() for ln in so.splitlines()
            if ("switch locked" in ln.lower() or "organization" in ln.lower()
                or "mode:" in ln.lower() or "compliance" in ln.lower())]
    return {"locked": bool(locked), "raw": "\n".join(keep)[:400] or so[:200]}


# ====================== 状态查询 ======================
def get_status():
    ok, out = warp(["status"], timeout=10)
    connected = "Connected" in out
    ok2, setout = warp(["settings"], timeout=10)
    mode = "unknown"
    for ln in setout.splitlines():
        if "Mode:" in ln:
            m = ln.split("Mode:")[-1].strip()
            if m:
                mode = m
                break
    ok3, listout = warp(["tunnel", "ip", "list"], timeout=10)
    cli_count = listout.count("(CLI exclude)")
    egress = get_egress_ip()
    with state_lock:
        if state["enabled"] and not connected and "Disconnected" not in out and "Failure" not in out:
            connected = True
        # 在线时长
        if connected:
            if metrics["connected_since"] is None:
                metrics["connected_since"] = time.time()
        else:
            metrics["connected_since"] = None
        uptime = int(time.time() - metrics["connected_since"]) if metrics["connected_since"] else 0

        st = {
            "warp_status": out.strip(),
            "connected": connected,
            "mode": mode,
            "cli_exclude_count": cli_count,
            "list_total": len(read_active_ranges()),
            "egress_ip": egress,
            "enabled": state["enabled"],
            "running": state["running"],
            "action": state["action"],
            "reconnecting": state["reconnecting"],
            "zerotrust_locked": state["zerotrust_locked"],
            "progress": dict(state["progress"]),
            "error": state["error"],
            "warp_cli": find_warp_cli() or "",
            "max_ranges_test": MAX_RANGES,
            "auto_reconnect": settings.get("auto_reconnect", True),
            "auto_update": settings.get("auto_update", False),
            "metrics_speed": settings.get("metrics_speed", True),
            "tray": settings.get("tray", True),
            "theme": settings.get("theme", "dark"),
            "active_lists": list(settings.get("active_lists", ["china_cidr.txt"])),
            "latency_cn": metrics["latency_cn"],
            "latency_intl": metrics["latency_intl"],
            "dl_speed_mbps": metrics["dl_speed_mbps"],
            "uptime_s": uptime,
        }
    return st


# ====================== 系统托盘 (ctypes, 零依赖) ======================
_WIN32_INITED = False


def _init_win32():
    """声明 Win32 函数原型。
    不声明时 ctypes 默认把返回值当 32 位 int, 在 64 位 Windows 上会截断 HICON/HWND/HMENU
    等指针型句柄, 导致图标创建失败或崩溃。因此必须显式设置 restype/argtypes。"""
    global _WIN32_INITED
    if _WIN32_INITED:
        return
    _WIN32_INITED = True
    u = ctypes.windll.user32
    g = ctypes.windll.gdi32
    s = ctypes.windll.shell32
    k = ctypes.windll.kernel32
    P, I, U = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint

    u.DefWindowProcW.restype = ctypes.c_ssize_t
    u.DefWindowProcW.argtypes = [P, U, ctypes.c_size_t, ctypes.c_ssize_t]
    u.CreateWindowExW.restype = P
    u.CreateWindowExW.argtypes = [U, ctypes.c_wchar_p, ctypes.c_wchar_p, U,
                                  I, I, I, I, P, P, P, P]
    u.RegisterClassW.restype = ctypes.c_ushort
    u.RegisterClassW.argtypes = [P]
    u.CreatePopupMenu.restype = P
    u.AppendMenuW.argtypes = [P, U, ctypes.c_size_t, ctypes.c_wchar_p]
    u.AppendMenuW.restype = I
    u.TrackPopupMenu.argtypes = [P, U, I, I, I, P, P]
    u.TrackPopupMenu.restype = I
    u.DestroyMenu.argtypes = [P]
    u.DestroyMenu.restype = I
    u.SetForegroundWindow.argtypes = [P]
    u.SetForegroundWindow.restype = I
    u.PostMessageW.argtypes = [P, U, ctypes.c_size_t, ctypes.c_ssize_t]
    u.PostMessageW.restype = I
    u.PostQuitMessage.argtypes = [I]
    u.GetMessageW.argtypes = [P, P, U, U]
    u.GetMessageW.restype = I
    u.TranslateMessage.argtypes = [P]
    u.DispatchMessageW.argtypes = [P]
    u.LoadIconW.restype = P
    u.LoadIconW.argtypes = [P, P]
    u.DestroyIcon.argtypes = [P]
    u.DestroyIcon.restype = I
    u.GetDC.restype = P
    u.ReleaseDC.argtypes = [P, P]
    u.CreateIconIndirect.restype = P
    u.CreateIconIndirect.argtypes = [P]

    g.CreateCompatibleBitmap.restype = P
    g.CreateCompatibleBitmap.argtypes = [P, I, I]
    g.CreateBitmap.restype = P
    g.CreateBitmap.argtypes = [I, I, U, U, P]
    g.SetDIBits.argtypes = [P, P, U, U, P, P, U]
    g.DeleteObject.argtypes = [P]
    g.DeleteObject.restype = I

    # 关键: Shell_NotifyIconW 位于 shell32.dll, 不在 user32.dll
    s.Shell_NotifyIconW.restype = I
    s.Shell_NotifyIconW.argtypes = [U, P]
    k.GetModuleHandleW.restype = P
    k.GetLastError.restype = U


def make_hicon(rgb):
    """用 ctypes 生成一个纯色圆形 HICON。失败返回 0。"""
    try:
        _init_win32()
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32
        hinst = kernel32.GetModuleHandleW(None)
        w = h = 32
        buf = bytearray(w * h * 4)
        cx = cy = w / 2.0
        rad = w / 2.0 - 2
        for y in range(h):
            for x in range(w):
                dx = x - cx + 0.5
                dy = cy - y - 0.5
                ins = (dx * dx + dy * dy) <= rad * rad
                off = (y * w + x) * 4
                if ins:
                    buf[off] = rgb[2]
                    buf[off + 1] = rgb[1]
                    buf[off + 2] = rgb[0]
                    buf[off + 3] = 255
                else:
                    buf[off + 3] = 0

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", ctypes.c_ulong), ("biWidth", ctypes.c_long),
                        ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_ushort),
                        ("biBitCount", ctypes.c_ushort), ("biCompression", ctypes.c_ulong),
                        ("biSizeImage", ctypes.c_ulong), ("biXPelsPerMeter", ctypes.c_long),
                        ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", ctypes.c_ulong),
                        ("biClrImportant", ctypes.c_ulong)]

        class BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", ctypes.c_ulong * 1)]

        class ICONINFO(ctypes.Structure):
            # fIcon 在 Win32 中是 BOOL(4 字节), 用 c_bool(1 字节) 会导致结构体布局错位
            _fields_ = [("fIcon", ctypes.c_int), ("xHotspot", ctypes.c_ulong),
                        ("yHotspot", ctypes.c_ulong), ("hbmMask", ctypes.c_void_p),
                        ("hbmColor", ctypes.c_void_p)]

        hdc = user32.GetDC(0)
        hbmColor = gdi32.CreateCompatibleBitmap(hdc, w, h)
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0
        gdi32.SetDIBits(hdc, hbmColor, 0, h, ctypes.cast(ctypes.create_string_buffer(bytes(buf)), ctypes.c_void_p),
                        ctypes.byref(bmi), 0)
        # 掩码: 单色全 0 = 完全不透明
        mask_bytes = ((w + 15) // 16) * 2 * h
        hbmMask = gdi32.CreateBitmap(w, h, 1, 1, ctypes.create_string_buffer(mask_bytes))
        ii = ICONINFO()
        ii.fIcon = True
        ii.hbmMask = hbmMask
        ii.hbmColor = hbmColor
        hicon = user32.CreateIconIndirect(ctypes.byref(ii))
        gdi32.DeleteObject(hbmColor)
        gdi32.DeleteObject(hbmMask)
        user32.ReleaseDC(0, hdc)
        return hicon
    except Exception:
        return 0


class TrayApp:
    WM_SHELL = 0x0400 + 1  # WM_USER + 1
    MSG_OPEN, MSG_ENABLE, MSG_DISABLE, MSG_FIX, MSG_EXIT = 1, 2, 3, 4, 5
    CLASS_NAME = "WarpSplitTray"
    UID = 1
    NIM_ADD, NIM_MODIFY, NIM_DELETE = 0x0, 0x1, 0x2
    NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4

    def __init__(self, url):
        _init_win32()
        self.url = url
        self.hwnd = 0
        self.hicon = 0
        self.hinst = ctypes.windll.kernel32.GetModuleHandleW(None)
        self.wndproc = None
        self._tip = "Cloudflare WARP 智能分流 (未启用)"
        self._nid_cls = self._make_nid_class()

    @staticmethod
    def _make_nid_class():
        class NOTIFYICONDATAW(ctypes.Structure):
            # 仅声明到 szTip, cbSize 自动等于 NOTIFYICONDATAW_V1_SIZE(=296), 为系统认可的合法尺寸
            _fields_ = [("cbSize", ctypes.c_uint32), ("hWnd", ctypes.c_void_p),
                        ("uID", ctypes.c_uint32), ("uFlags", ctypes.c_uint32),
                        ("uCallbackMessage", ctypes.c_uint32), ("hIcon", ctypes.c_void_p),
                        ("szTip", ctypes.c_wchar * 128)]
        return NOTIFYICONDATAW

    def _nid(self, flags, tip=None):
        N = self._nid_cls
        nid = N()
        nid.cbSize = ctypes.sizeof(N)
        nid.hWnd = self.hwnd
        nid.uID = self.UID
        nid.uFlags = flags
        nid.uCallbackMessage = self.WM_SHELL
        nid.hIcon = self.hicon
        if tip is not None:
            nid.szTip = tip[:127]
        return nid

    def create(self):
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        WM_DESTROY = 0x0002
        WM_COMMAND = 0x0111

        # LRESULT 是 LONG_PTR(64 位下 8 字节), 用 c_long 会截断 DefWindowProcW 的返回值
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_void_p,
                                     ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t)

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == self.WM_SHELL:
                    event = lparam & 0xFFFF
                    if event == 0x0202:      # WM_LBUTTONUP  单击 -> 打开面板
                        self._open()
                    elif event == 0x0203:    # WM_LBUTTONDBLCLK 双击 -> 打开面板
                        self._open()
                    elif event == 0x0205:    # WM_RBUTTONUP  右键 -> 菜单
                        self._show_menu()
                    return 0
                if msg == WM_COMMAND:
                    self._menu(wparam & 0xFFFF)
                    return 0
                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
            except Exception as e:
                log("托盘消息处理异常: " + str(e), logging.DEBUG)
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self.wndproc = WNDPROC(wndproc)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC),
                        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                        ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
                        ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
                        ("lpszMenuName", ctypes.c_wchar_p), ("lpszClassName", ctypes.c_wchar_p)]

        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = self.wndproc
        wc.hInstance = self.hinst
        # 关键修复: 直接赋 Python str, ctypes 自动转成 c_wchar_p
        # (原先传 create_unicode_buffer 得到的 c_wchar_Array, 类型不兼容会抛 TypeError)
        wc.lpszClassName = self.CLASS_NAME
        wc.lpszMenuName = None
        if not user32.RegisterClassW(ctypes.byref(wc)):
            err = kernel32.GetLastError()
            if err != 1410:  # ERROR_CLASS_ALREADY_EXISTS: 同一进程重复注册, 可继续
                log(f"托盘: RegisterClassW 失败 (GetLastError={err})", logging.WARNING)
                return False

        # HWND_MESSAGE: 创建纯消息窗口(不可见), 更轻量
        hwnd_message = ctypes.c_void_p(-3)
        self.hwnd = user32.CreateWindowExW(0, self.CLASS_NAME, self.CLASS_NAME, 0,
                                           0, 0, 0, 0, hwnd_message, 0, self.hinst, 0)
        if not self.hwnd:
            log(f"托盘: CreateWindowExW 失败 (GetLastError={kernel32.GetLastError()})",
                logging.WARNING)
            return False
        return self._register_icon()

    def _register_icon(self):
        user32 = ctypes.windll.user32
        if not self.hicon:
            self.hicon = make_hicon((239, 68, 68))
        if not self.hicon:
            self.hicon = user32.LoadIconW(0, 32516)  # IDI_INFORMATION 兜底
        nid = self._nid(self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP, self._tip)
        shell32 = ctypes.windll.shell32
        if not shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid)):
            log("托盘: Shell_NotifyIconW(NIM_ADD) 失败", logging.WARNING)
            return False
        return True

    def update(self, connected, enabled):
        if not self.hwnd:
            return
        user32 = ctypes.windll.user32
        try:
            if state.get("running"):
                color, tip = (245, 158, 11), "Cloudflare WARP 智能分流 (操作中...)"
            elif enabled and connected:
                color, tip = (34, 197, 94), "Cloudflare WARP 智能分流 (分流中)"
            elif enabled:
                color, tip = (245, 158, 11), "Cloudflare WARP 智能分流 (已启用/重连中)"
            else:
                color, tip = (239, 68, 68), "Cloudflare WARP 智能分流 (未启用)"
            # 仅状态真正变化时才重建图标, 避免每 5 秒无谓销毁/创建
            if tip != self._tip:
                self._tip = tip
                new_icon = make_hicon(color)
                if new_icon:
                    if self.hicon:
                        user32.DestroyIcon(self.hicon)
                    self.hicon = new_icon
            nid = self._nid(self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP, self._tip)
            ctypes.windll.shell32.Shell_NotifyIconW(self.NIM_MODIFY, ctypes.byref(nid))
        except Exception as e:
            log("托盘 update 异常: " + str(e), logging.DEBUG)

    def _open(self):
        # 单击会先于双击触发, 做 1.2s 防抖, 避免一次双击打开两个标签页
        now = time.time()
        if now - getattr(self, "_last_open", 0) < 1.2:
            return
        self._last_open = now
        try:
            ok = webbrowser.open(self.url)
            if not ok:
                log("托盘: 未能自动打开浏览器, 请手动访问 " + self.url, logging.WARNING)
        except Exception as e:
            log("托盘打开面板失败: " + str(e), logging.WARNING)

    def _show_menu(self):
        user32 = ctypes.windll.user32
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        MF_STRING, MF_SEPARATOR = 0x0, 0x800
        user32.AppendMenuW(menu, MF_STRING, self.MSG_OPEN, "打开控制台")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, "")
        user32.AppendMenuW(menu, MF_STRING, self.MSG_ENABLE, "启用分流")
        user32.AppendMenuW(menu, MF_STRING, self.MSG_DISABLE, "停用分流")
        user32.AppendMenuW(menu, MF_STRING, self.MSG_FIX, "修复 IPv6")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, "")
        user32.AppendMenuW(menu, MF_STRING, self.MSG_EXIT, "退出")
        pos = ctypes.wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pos))
        user32.SetForegroundWindow(self.hwnd)
        # 左键对齐 + 不通知父窗口
        user32.TrackPopupMenu(menu, 0x0000 | 0x0002, pos.x, pos.y, 0, self.hwnd, 0)
        # 发送空消息, 修复 "菜单失去焦点后不消失" 的经典问题
        user32.PostMessageW(self.hwnd, 0, 0, 0)
        user32.DestroyMenu(menu)

    def _menu(self, cmd):
        if cmd == self.MSG_OPEN:
            self._open()
        elif cmd == self.MSG_ENABLE:
            if not state["enabled"]:
                threading.Thread(target=enable_split, daemon=True).start()
        elif cmd == self.MSG_DISABLE:
            if state["enabled"]:
                threading.Thread(target=disable_split, daemon=True).start()
        elif cmd == self.MSG_FIX:
            fix_ipv6()
        elif cmd == self.MSG_EXIT:
            self.quit()

    def quit(self):
        # 正确移除图标: 必须用与 NIM_ADD 一致的 hWnd/uID 结构体
        try:
            user32 = ctypes.windll.user32
            ctypes.windll.shell32.Shell_NotifyIconW(self.NIM_DELETE,
                                                    ctypes.byref(self._nid(0)))
            if self.hicon:
                user32.DestroyIcon(self.hicon)
                self.hicon = 0
        except Exception:
            pass
        EXIT_EVENT.set()
        try:
            server.shutdown()
        except Exception:
            pass
        os._exit(0)

    def run(self):
        try:
            if not self.create():
                log("托盘图标初始化失败 (可忽略, Web 控制台仍可用)", logging.WARNING)
                return
            log("托盘图标已启动: 双击打开控制台, 右键查看菜单")
            user32 = ctypes.windll.user32
            msg = ctypes.wintypes.MSG()
            while True:
                r = user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
                if r <= 0:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as e:
            # 托盘任何异常都不应影响 Web 控制台
            log("托盘线程异常: " + str(e), logging.WARNING)
        finally:
            try:
                ctypes.windll.shell32.Shell_NotifyIconW(self.NIM_DELETE,
                                                        ctypes.byref(self._nid(0)))
            except Exception:
                pass


# ====================== Web 服务 ======================
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            try:
                data = open(asset_path("index.html"), "rb").read()
                self._send(200, data, "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        elif p == "/api/ping":
            self._json({"ok": True, "port": PORT})
        elif p == "/api/status":
            try:
                self._json(get_status())
            except Exception as e:
                self._json({"error": str(e)})
        elif p == "/api/log":
            with log_lock:
                lines = list(log_lines)
            self._json({"log": lines})
        elif p == "/api/selftest":
            try:
                self._json(self_test())
            except Exception as e:
                self._json({"verdict": "ERROR", "msg": str(e)})
        elif p == "/api/metrics":
            with metrics_lock:
                self._json({
                    "latency_cn": metrics["latency_cn"],
                    "latency_intl": metrics["latency_intl"],
                    "dl_speed_mbps": metrics["dl_speed_mbps"],
                    "egress_ip": metrics["egress_ip"],
                    "uptime_s": metrics["uptime_s"],
                    "history": list(metrics_history),
                })
        elif p == "/api/rules":
            avail = []
            for name in settings.get("active_lists", []):
                avail.append({"name": name, "active": True, "count": len(read_list_file(os.path.join(APP_DIR, name)))})
            if os.path.isdir(RULES_DIR):
                for fn in os.listdir(RULES_DIR):
                    if fn.endswith(".txt"):
                        rel = "rules/" + fn
                        if rel not in settings["active_lists"]:
                            avail.append({"name": rel, "active": False,
                                          "count": len(read_list_file(os.path.join(RULES_DIR, fn)))})
            self._json({"lists": avail})
        elif p == "/api/zerotrust":
            self._json(detect_zerotrust())
        elif p == "/api/autostart":
            self._json({"enabled": autostart_enabled()})
        elif p == "/favicon.ico":
            self._send(204, b"")
        else:
            self._send(404, json.dumps({"error": "not found"}, ensure_ascii=False))

    def do_POST(self):
        p = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {}

        if p == "/api/enable":
            threading.Thread(target=enable_split, daemon=True).start()
            self._json({"ok": True, "msg": "已开始启用分流"})
        elif p == "/api/disable":
            threading.Thread(target=disable_split, daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/restore":
            threading.Thread(target=restore, daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/refresh":
            threading.Thread(target=refresh_list, daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/fix_ipv6":
            ok, out = fix_ipv6()
            self._json({"ok": ok, "msg": out})
        elif p == "/api/settings":
            for k in ("theme", "auto_reconnect", "auto_update", "metrics_speed", "tray"):
                if k in payload:
                    settings[k] = payload[k]
            save_settings()
            self._json({"ok": True, "settings": settings})
        elif p == "/api/autostart/enable":
            ok, out = register_autostart()
            self._json({"ok": ok, "msg": out})
        elif p == "/api/autostart/disable":
            ok, out = unregister_autostart()
            self._json({"ok": ok, "msg": out})
        elif p == "/api/rules/import":
            ok, out = import_rule_list(payload.get("name", ""), payload.get("source", "text"), payload.get("value", ""))
            self._json({"ok": ok, "msg": out})
        elif p == "/api/rules/delete":
            ok, out = delete_rule_list(payload.get("name", ""))
            self._json({"ok": ok, "msg": out})
        elif p == "/api/rules/toggle":
            name = payload.get("name", "")
            active = payload.get("active", True)
            if name:
                if active and name not in settings["active_lists"]:
                    settings["active_lists"].append(name)
                elif not active and name in settings["active_lists"]:
                    settings["active_lists"].remove(name)
                save_settings()
            self._json({"ok": True})
        else:
            self._send(404, json.dumps({"error": "not found"}, ensure_ascii=False))

    def log_message(self, *a):
        pass


server = None


# ====================== 提权 ======================
# 提权重启时附加此标记。若带标记启动后仍非管理员, 说明 UAC 被禁用或弹窗
# 被拒绝, 此时必须停止重试——否则会陷入「启动 -> 检测非管理员 -> 再启动」
# 的死循环, 表现为不停弹出/闪烁控制台窗口。
ELEVATED_FLAG = "--elevated"
NO_BROWSER_FLAG = "--no-browser"

_shell_execute = ctypes.windll.shell32.ShellExecuteW
_shell_execute.restype = ctypes.wintypes.HINSTANCE
_shell_execute.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR,
                           ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
                           ctypes.wintypes.LPCWSTR, ctypes.c_int]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def run_as_admin():
    """以管理员权限重启自身。返回 True 表示提权请求已成功发出。

    必须校验 ShellExecute 返回值: 返回值 <= 32 代表失败(UAC 弹窗被取消、
    UAC 被组策略禁用等)。若不加判断, 主流程会误以为已提权而直接退出,
    而子进程又因仍是普通权限再次走提权分支, 形成无限重启。
    """
    args = [a for a in sys.argv[1:] if a != ELEVATED_FLAG]
    # 注意: ShellExecuteW 的 lpFile 已经是程序自身路径, lpParameters 里
    # 只能放参数。若再拼一次 exe 路径, 实际命令行会变成
    # `程序.exe "程序.exe" --elevated`, 多出一个位置参数。
    params = " ".join(['"%s"' % a for a in args] + [ELEVATED_FLAG])
    try:
        r = _shell_execute(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        log("提权异常: " + str(e), logging.ERROR)
        return False

    if r is None or int(r) <= 32:
        log(f"提权失败 (ShellExecute 返回 {r})。通常是 UAC 弹窗被取消, "
            f"或系统禁用了 UAC。请右键程序 →「以管理员身份运行」。",
            logging.ERROR)
        return False
    return True


# ====================== 主函数 ======================
def main():
    global server
    ensure_data_files()
    load_settings()
    load_state()

    url = "http://127.0.0.1:%d/" % PORT

    # 单实例: 端口已被占用说明已有实例在运行。此时不再启动第二个进程,
    # 直接打开现有控制台即可 —— 否则每次双击都会多一个进程, 多个进程
    # 抢同一端口会让页面连不上, 或连到已卡死的旧实例上。
    if port_in_use(PORT):
        log(f"端口 {PORT} 已有实例在运行, 直接打开控制台")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        sys.exit(0)

    if not is_admin():
        if ELEVATED_FLAG in sys.argv:
            # 已经提权重启过一次, 却仍不是管理员 —— 继续重试只会导致
            # 无限弹窗。这里明确报错并退出, 由用户手动以管理员运行。
            log("提权后仍非管理员权限。可能系统禁用了 UAC(账户控制), "
                "或提权请求被安全软件拦截。", logging.ERROR)
            alert("提权后仍非管理员权限。\n\n"
                  "可能原因: 系统禁用了 UAC(用户账户控制), 或提权请求被安全软件拦截。\n\n"
                  "请右键本程序 →「以管理员身份运行」; 或在 Windows「用户账户控制设置」"
                  "中把 UAC 调回默认级别。")
            pause()
            sys.exit(1)

        log("当前非管理员, 尝试提权...")
        if run_as_admin():
            sys.exit(0)
        alert("无法获取管理员权限。\n\n"
              "本工具需要管理员权限才能修改 WARP 隧道规则。\n"
              "请右键本程序 →「以管理员身份运行」。")
        pause()
        sys.exit(1)

    tray_mode = settings.get("tray", True) and "--no-tray" not in sys.argv

    log("Cloudflare WARP 智能分流控制台 启动")
    log(f"监听 http://127.0.0.1:{PORT}/  (工作目录: {APP_DIR})")
    if MAX_RANGES > 0:
        log(f"[测试模式] 仅注入前 {MAX_RANGES} 条规则")

    # 启动后台守护线程
    threading.Thread(target=metrics_loop, daemon=True).start()
    threading.Thread(target=reconnect_loop, daemon=True).start()
    threading.Thread(target=autoupdate_loop, daemon=True).start()
    threading.Thread(target=egress_loop, daemon=True).start()

    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as e:
        log(f"无法在端口 {PORT} 启动服务: {e}（可能已有实例在运行，端口被占用）", logging.ERROR)
        alert(f"无法在端口 {PORT} 启动服务。\n\n"
              "可能是已有实例正在运行，请先在任务管理器结束\n"
              "WARP-Split-Console.exe 后重试。\n\n"
              f"错误信息: {e}")
        pause()
        sys.exit(1)

    # 服务已就绪 —— 自动打开控制台。
    # 打包后是窗口程序(无控制台), 不主动打开的话双击 exe 将毫无反馈,
    # 看起来就像「点了没反应」。
    if NO_BROWSER_FLAG not in sys.argv:
        try:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    # 托盘 (独立线程, 失败不影响 Web 服务)
    tray = None
    if tray_mode:
        tray = TrayApp(url)
        threading.Thread(target=tray.run, daemon=True).start()

    # 周期性更新托盘图标
    def tray_updater():
        while not EXIT_EVENT.is_set():
            EXIT_EVENT.wait(5)
            if tray and tray.hwnd:
                try:
                    st = get_status()
                    tray.update(st.get("connected", False), st.get("enabled", False))
                except Exception:
                    pass

    if tray:
        threading.Thread(target=tray_updater, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到退出信号")
    finally:
        EXIT_EVENT.set()
        server.shutdown()
        save_state()


if __name__ == "__main__":
    main()
