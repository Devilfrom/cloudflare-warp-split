#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
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
  - 启用: disconnect -> mode warp -> 写入中国 IP 到 WARP 排除列表 -> connect
          (注入在断开状态下完成, 用户全程无感; 规则齐了才连, 不会"一注入就断网")
  - 注入: 优先"配置直写" —— 停 CloudflareWARP 服务 -> 原子改写
          C:\ProgramData\Cloudflare\settings.json 的 excluded_ips -> 起服务。
          实测 5400+ 条 0.007 秒写入并生效(逐条 warp-cli 要 400 秒以上)。
          直写不可用时自动回退逐条 add-range, 功能不受影响。
  - 停用: 仅 disconnect, 保留排除规则 -> 再次启用可秒级完成
  - 还原: 清空 CLI 排除 + 断开 (紧急回到干净状态)
  - 状态持久化到 state.json / settings.json, 异常自动回滚
"""

import os
import sys
import re
import json
import atexit
import time
import struct
import shutil
import socket
import select
import hashlib
import random
import threading
import subprocess
from socketserver import ThreadingUDPServer, BaseRequestHandler

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
from logging.handlers import TimedRotatingFileHandler
import webbrowser
import ctypes
import ctypes.wintypes  # 必须显式导入: MSG/POINT 等类型在此子模块, 仅 import ctypes 不会加载
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, urlsplit
from concurrent.futures import ThreadPoolExecutor

# ====================== 配置 ======================
# PyInstaller 打包后 __file__ 指向临时解压目录(_MEIxxx), 会在进程退出后被删除。
# 因此区分两个目录:
#   RES_DIR  - 只读资源目录(内置的 index.html / china_cidr.txt 初始副本)
#   APP_DIR  - 可写数据目录(china_cidr.txt / settings.json / state.json / 日志)
#             打包后取 exe 所在目录, 保证配置能持久化。
IS_FROZEN = getattr(sys, "frozen", False)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 面板资源版本(与 CHANGELOG / Release 同步, 发新版时改这里)。
# index.html 头部也带同名标记, ensure_data_files() 靠它判断要不要
# 自动更新 exe 旁边的旧面板副本。
PANEL_VERSION = "1.4.4"

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


def _exe_fingerprint():
    """当前 exe 的构建指纹(mtime+size)。

    用于识别"端口那头的实例是不是这个 exe 启动的":
    换了新版本 exe 但旧进程还在跑时, 双击新 exe 走单实例分支只会打开
    旧实例的控制台(经典陷阱), 有了指纹就能检测出来并提示用户。
    """
    try:
        st = os.stat(sys.executable)
        return "%d:%d" % (int(st.st_mtime), st.st_size)
    except Exception:
        return ""


def console_url():
    """打开控制台用的 URL —— 带当前 exe 的构建指纹。

    为什么需要: 更新 exe 后双击启动, 若浏览器里已经有一个控制台标签页
    (哪怕它是几小时前加载的旧面板), 浏览器只会聚焦那个旧标签页, 不会
    重新加载页面 —— 而旧版面板代码没有版本自检逻辑, 用户看到的就是
    "重启了却没更新"(v1.4.1/1.4.2 都没堵住这条, 因为挡的是"打开"这个
    动作本身)。URL 带上指纹后, 每个 exe 版本对应不同的 URL, 浏览器必然
    新建标签页并拉取最新面板, 从机制上杜绝"焦点旧标签页"。
    """
    base = "http://127.0.0.1:%d/" % PORT
    fp = _exe_fingerprint()
    return (base + "?_b=" + fp.replace(":", "-")) if fp else base


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
    """打包模式下，把内置资源首次复制到 exe 同级目录，保证可持久化。

    index.html(面板)特殊处理 —— 做**版本比对自动更新**:
      只复制"不存在"的副本会导致换新 exe 后面板永远不更新(exe 内置新版,
      旁边旧文件原封不动, 面板看起来"没升级")。现在比对版本标记:
      旧版/无标记 -> 备份旧文件为 index.user-<ver>.html 后覆盖;
      已是同版本或更新 -> 不动(尊重用户本地版本)。
    china_cidr 等是数据文件(用户可能刷新过), 保持"不存在才复制"。
    """
    if not IS_FROZEN:
        return
    for name in ("china_cidr.txt", "china_cidr_lite.txt"):
        dst = os.path.join(APP_DIR, name)
        src = os.path.join(RES_DIR, name)
        if not os.path.isfile(dst) and os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass
    _update_panel()


def _ver_tuple(s):
    """'1.10.0' -> (1,10,0); 解析失败返回 (0,0,0)。"""
    try:
        parts = [int(x) for x in re.findall(r"\d+", s or "")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except Exception:
        return (0, 0, 0)


def _panel_ver(path):
    """读取面板文件头部的版本标记 <!-- warp-split-res vX.Y.Z -->。"""
    try:
        with open(path, "rb") as f:
            head = f.read(2048).decode("utf-8", "ignore")
        m = re.search(r"warp-split-res\s+v([\d.]+)", head)
        return m.group(1) if m else None
    except Exception:
        return None


_PANEL_VER_CACHE = {"ver": None, "ts": 0.0}


def panel_version():
    """当前生效的面板版本(asset_path 指向的那份), 5s 缓存。"""
    now = time.time()
    if now - _PANEL_VER_CACHE["ts"] < 5:
        return _PANEL_VER_CACHE["ver"]
    ver = _panel_ver(asset_path("index.html")) or PANEL_VERSION
    _PANEL_VER_CACHE["ver"] = ver
    _PANEL_VER_CACHE["ts"] = now
    return ver


def _update_panel():
    """面板自动更新: APP_DIR 副本版本低于内置版本时, 备份旧版并覆盖。"""
    src = os.path.join(RES_DIR, "index.html")
    dst = os.path.join(APP_DIR, "index.html")
    if not os.path.isfile(src):
        return
    built_ver = _panel_ver(src) or PANEL_VERSION
    cur_ver = _panel_ver(dst) if os.path.isfile(dst) else None
    if cur_ver and _ver_tuple(cur_ver) >= _ver_tuple(built_ver):
        return                                   # 已是同版本或更新, 不动
    if os.path.isfile(dst):
        # 备份用户当前版本(可能是自己改过的), 只保留最近一份
        try:
            bak = os.path.join(APP_DIR, "index.user-%s.html" % (cur_ver or "old"))
            shutil.copy2(dst, bak)
        except Exception:
            pass
    try:
        shutil.copy2(src, dst)
        log("面板已自动更新: %s -> %s" % (cur_ver or "无", built_ver))
    except Exception as e:
        log("面板更新失败: %s" % e)


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
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org",
    "https://myip.ipip.net",
    "https://ipinfo.io/ip",
]
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=25000000"
AUTOSTART_TASK = "CloudflareWARP-Split"

# 日志保留天数(按天轮转, 超出自动删除)
LOG_KEEP_DAYS = int(os.environ.get("WARP_SPLIT_LOG_DAYS", "30"))

# ====================== 必须直连的保留网段 ======================
# APNIC 只分发公网地址段, 因此 china_cidr.txt 里不会包含任何 RFC1918
# 私有地址。若不在注入时显式补上, 局域网设备(NAS / 路由器后台 / 投屏 /
# 打印机 / 远程桌面)理论上可能被 WARP 的 TUN 接口接管而失联。
# 实测 WARP 客户端自身会保留 LAN, 但换版本或叠加 Zero Trust 策略后
# 该行为不受我们控制 —— 显式排除更稳妥。
ALWAYS_DIRECT = [
    "10.0.0.0/8",        # 私有 A 类
    "172.16.0.0/12",     # 私有 B 类
    "192.168.0.0/16",    # 私有 C 类
    "127.0.0.0/8",       # 回环
    "169.254.0.0/16",    # 链路本地(APIPA)
    "100.64.0.0/10",     # 运营商级 NAT (CGNAT)
    "224.0.0.0/4",       # 组播
]
_ALWAYS_DIRECT_SET = set(ALWAYS_DIRECT)

# ====================== 全局状态 ======================
state = {
    "enabled": False,
    "running": False,
    "action": None,
    "progress": {"total": 0, "done": 0, "phase": "空闲"},
    "error": None,
    "reconnecting": False,
    "zerotrust_locked": False,
    "auto_restored": False,   # 是否因自愈失败而自动还原过(供控制台提示)
    "armed": False,           # 本次会话是否已确认分流状态(冷启动保护, 见 reconnect_loop)
    "resume_pending": False,  # 上次启用了但本次未自动恢复(供控制台提示)
    "route_active": None,     # 当前实际生效的分路: "tun" / "proxy" / None
    "bridge_up": False,       # 本地分流桥是否在监听
    "sysproxy_on": False,     # 是否已写入 Windows 系统代理
    "dns_proxy": False,       # 本地智能 DNS 分流是否在接管网卡 DNS
    "net_down": False,        # 网络保障看门狗: 当前是否探测到上不了网
    "rescue": None,           # 最近一次自动/手动急救的详情(供控制台展示)
    "guard_paused": False,    # 是否因网络保障而自动暂停了分流(需用户手动恢复)
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
    "auto_heal": True,
    "auto_update": False,
    "auto_resume": False,     # 启动时自动恢复上次的分流状态(默认关, 避免"它自己又跑了")
    "metrics_speed": True,
    "tray": True,
    "active_lists": ["china_cidr.txt"],
    # ---- Proxy 分路 (不开 TUN 的第二条路) ----
    "route_mode": "tun",          # "tun" = 全局 TUN 分流; "proxy" = SOCKS5 分路
    "proxy_port": 40000,          # WARP 原生 SOCKS5 上行端口
    "bridge_port": 7890,          # 本地智能分流 HTTP 桥端口
    "system_proxy": False,        # 是否把分流桥写进 Windows 系统代理(默认关)
    "_sysproxy_backup": None,     # 系统代理原值备份, 用于精确还原
    # ---- 智能 DNS 分流(决定国内站能否跑满带宽, 默认开) ----
    "smart_dns": True,            # 用本地 DNS 代理按域名分流解析
    # ---- 网络保障(底线: 任何时候都要能上网) ----
    "net_guard": True,            # 程序运行时的网络看门狗: 连续探测失败就自动退让
    "net_watchdog": True,         # 系统级兜底任务: 程序没运行时也能兜住 DNS 残留
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

# 网络体检结果缓存(30s): 体检要跑 5-12s, 防止用户连点或前端重试导致
# 重复发起 tracert/DoH 探测。
audit_cache = {"data": None, "ts": 0}
audit_lock = threading.Lock()

# ====================== 日志 ======================
# 按天轮转 + 自动清理: 守护线程长年运行会持续写日志, 单文件会无限增长,
# 既占磁盘也让排查困难。这里按 UTC 午夜切分, 超过 LOG_KEEP_DAYS 天的
# 历史文件自动删除。
def prune_logs(keep_days=LOG_KEEP_DAYS):
    """删除过期的轮转日志文件(以及残留的 0 字节文件)。"""
    try:
        import glob
        cutoff = time.time() - keep_days * 86400
        for p in glob.glob(LOG_FILE + ".*"):
            try:
                if os.path.getsize(p) == 0 or os.path.getmtime(p) < cutoff:
                    os.remove(p)
            except Exception:
                pass
    except Exception:
        pass


logger = logging.getLogger("warp_split")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
_fh = TimedRotatingFileHandler(LOG_FILE, when="midnight", interval=1,
                               backupCount=LOG_KEEP_DAYS, encoding="utf-8")
_fh.suffix = "%Y-%m-%d"
_fh.setFormatter(_fmt)
logger.addHandler(_fh)
prune_logs()


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


# ====================== WARP 配置直写: 秒级注入 ======================
# 【为什么需要】
# `warp-cli tunnel ip add-range` 的每条请求都由 daemon 串行处理, 实测
# 74ms/条 —— 5440 条约 400 秒, 5433 条实测耗时 8 分 36 秒。更糟的是旧的
# 流程是「先连上 WARP 再逐条注入」, 这 8 分钟里隧道已经建立但排除规则
# 几乎是空的, 于是所有流量(含国内流量)被灌进隧道, 表现为「注入时网络
# 全断」。
#
# 【解决办法】
# WARP 把排除列表以明文 JSON 存在
#     C:\ProgramData\Cloudflare\settings.json  ->  excluded_ips
# 里。只要在「服务停止」状态下原子改写该文件, 再启动服务, daemon 就会
# 按新配置加载。实测写入 5463 条耗时 0.007 秒, 启动服务后 daemon 立即
# 报告全部规则已生效。
#
# 配合「先注入后连接」的顺序 (注入期间 WARP 处于断开状态, 网络是纯直连),
# 用户在整个启用过程中完全感知不到网络中断, 启用从 8 分钟降到数秒。
#
# 【安全边界】
#   - 只替换标签为 "CLI exclude" 的条目, daemon 自带的默认排除
#     (标签为 null 的 22 条: Apple 服务 / 组播 / 链路本地 / 保留地址)
#     原样保留, 不碰其它任何字段。
#   - 改写前自动备份到 warp_settings.backup.json, 写入失败会回滚。
#   - 任何一步失败都返回 False, 调用方自动回退到逐条 CLI 注入, 绝不影响
#     功能正确性, 只是慢一点。
WARP_CONF = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                         "Cloudflare", "settings.json")
WARP_SVC = "CloudflareWARP"
CLI_EXCLUDE_LABEL = "CLI exclude"
# 需要新增的规则超过这个数量才走"停服务直写"(服务重启本身有约 8 秒开销),
# 少量增量走 CLI 更快。
FAST_WRITE_MIN = int(os.environ.get("WARP_SPLIT_FAST_MIN", "120"))
_fast_write_lock = threading.Lock()


def _cmd(args, timeout=30):
    """运行系统命令, 返回 (ok, 输出)。"""
    try:
        r = _run(args, capture_output=True, text=True, timeout=timeout, errors="ignore")
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return False, str(e)


def warp_conf_path():
    return os.environ.get("WARP_SPLIT_CONF") or WARP_CONF


def read_warp_conf():
    """读取 WARP 配置。返回 (dict, err)。"""
    p = warp_conf_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        return None, f"读取 {p} 失败: {e}"


def read_conf_excludes():
    """返回 (内置默认条目列表, CLI 排除CIDR列表)。解析失败返回 (None, None)。"""
    d, err = read_warp_conf()
    if d is None or not isinstance(d.get("excluded_ips"), list):
        return None, None
    builtin, cli = [], []
    for e in d["excluded_ips"]:
        if not isinstance(e, (list, tuple)) or len(e) < 1:
            continue
        if len(e) > 1 and e[1] == CLI_EXCLUDE_LABEL:
            cli.append(e[0])
        else:
            builtin.append(list(e))
    return builtin, cli


def svc_ctl(action, timeout=90):
    """启停 CloudflareWARP 服务。先试 net, 再退回 sc。"""
    verb = "stop" if action in ("stop", "down") else "start"
    ok, out = _cmd(["net", verb, WARP_SVC], timeout=timeout)
    if not ok:
        ok2, out2 = _cmd(["sc", verb, WARP_SVC], timeout=timeout)
        if ok2:
            return True, out2
        return False, (out or out2)
    return True, out


def wait_daemon_ready(timeout=40):
    """等待 daemon 初始化完成 (服务起来后 warp-cli 需要几秒才能应答)。"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        ok, out = warp(["status"], timeout=8)
        if ok and any(k in out for k in ("Connected", "Disconnected", "Connecting",
                                         "Reconnecting", "Disconnecting")):
            return True
        time.sleep(1.0)
    return False


def write_excludes_fast(desired, phase_cb=None):
    """秒级全量写入排除列表: 停服务 -> 原子改写 settings.json -> 起服务。

    成功返回 (True, 说明文字); 失败返回 (False, 原因) 由调用方回退到逐条注入。
    """
    if not _IS_WIN:
        return False, "非 Windows 环境"
    with _fast_write_lock:
        cfg = warp_conf_path()
        if not os.path.exists(cfg):
            return False, f"未找到 WARP 配置文件: {cfg}"

        wanted = list(dict.fromkeys(desired))
        if phase_cb:
            phase_cb(f"准备写入 {len(wanted)} 条规则...")

        # 1) 先断开, 避免 daemon 在改写瞬间还带着旧规则跑
        warp(["disconnect"], timeout=20)

        # 2) 备份 (每次覆盖上次的备份, 只保留一份最近可回滚点)
        bak = os.path.join(APP_DIR, "warp_settings.backup.json")
        try:
            shutil.copy2(cfg, bak)
        except Exception as e:
            log(f"备份 WARP 配置失败(继续): {e}", logging.WARNING)

        # 3) 停服务 —— 必须停, 否则 daemon 会用内存态把我们的写入覆盖回去
        #    (实测: 运行中改写文件, daemon 完全无视)
        ok, out = svc_ctl("stop")
        if not ok:
            return False, "停止 CloudflareWARP 服务失败: " + (out or "")[:140]
        time.sleep(2)

        # 4) 原子改写: 保留 daemon 自己写的其它字段, 只换 excluded_ips
        try:
            d, err = read_warp_conf()
            if d is None:
                d = {}
            builtin, _old = read_conf_excludes()
            if builtin is None:
                builtin = []
            d["excluded_ips"] = builtin + [[c, CLI_EXCLUDE_LABEL] for c in wanted]
            tmp = cfg + ".warp_split_tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
            os.replace(tmp, cfg)
        except Exception as e:
            svc_ctl("start")          # 无论如何都要把服务拉起来, 不能把用户晾在断网状态
            return False, f"写入 WARP 配置失败: {e}"

        # 5) 起服务并等就绪
        ok, out = svc_ctl("start")
        if not ok:
            return False, "启动 CloudflareWARP 服务失败: " + (out or "")[:140]
        if not wait_daemon_ready():
            return False, "CloudflareWARP 服务启动后无响应"

        log(f"已通过配置直写一次性写入 {len(wanted)} 条排除规则 "
            f"(保留内置默认 {len(builtin)} 条)")
        return True, f"已一次性写入 {len(wanted)} 条规则"


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


_RANGES_CACHE = {"key": None, "val": []}


def read_active_ranges(force=False):
    """读取所有"激活"的规则列表 (默认 china_cidr.txt + 自定义导入列表)。

    返回的最前面总是 ALWAYS_DIRECT(私有网段等必须直连的保留地址),
    因此本函数的返回值 = 期望被 daemon 排除的完整网段集合。

    为什么要缓存: 控制台每 1.5 秒轮询一次 /api/status, 而它要显示规则总数。
    不缓存的话每 1.5 秒就要把 5440 行重新读一遍、解析一遍再去重 —— 纯浪费。
    缓存 key 取「激活列表名 + 每个文件的 mtime/size」, 所以列表换了、文件更新了
    (点『更新中国IP列表』) 都会自动失效, 不需要手动清理。
    """
    names = [n for n in settings.get("active_lists", ["china_cidr.txt"]) if n]
    key_parts = []
    for name in names:
        p = name if os.path.isabs(name) else os.path.join(APP_DIR, name)
        try:
            st = os.stat(p)
            key_parts.append((name, int(st.st_mtime), st.st_size))
        except OSError:
            key_parts.append((name, 0, 0))
    key = tuple(key_parts)
    if not force and _RANGES_CACHE["key"] == key and _RANGES_CACHE["val"]:
        return _RANGES_CACHE["val"]

    ranges = list(ALWAYS_DIRECT)
    for name in names:
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
    _RANGES_CACHE["key"] = key
    _RANGES_CACHE["val"] = uniq
    return uniq


_egress_cache = {"ts": 0.0, "ip": "", "colo": "", "loc": ""}


def get_egress_ip(ttl=25):
    """获取当前出口 IP。带 TTL 缓存 —— 前端轮询 /api/status 会频繁调用它,
    每次都发三个 HTTPS 请求(最坏 9 秒)会显著拖慢响应。"""
    now = time.time()
    if _egress_cache["ip"] and (now - _egress_cache["ts"]) < ttl:
        return _egress_cache["ip"]
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    res = "获取失败"
    colo, loc = "", ""
    for url in EGRESS_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                data = resp.read().decode("utf-8", "ignore").strip()
                import re
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", data)
                if m:
                    res = m.group(1)
                    # trace 接口还会返回 colo=XXX / loc=XX, 顺手解析 —— 出口
                    # 落在哪个 Cloudflare 边缘节点对「分流到哪去了」很直观,
                    # 而且这是同一个响应, 不增加任何请求成本。
                    mc = re.search(r"^colo=([A-Za-z0-9]+)", data, re.M)
                    if mc:
                        colo = mc.group(1).upper()
                    ml = re.search(r"^loc=([A-Za-z]{2})", data, re.M)
                    if ml:
                        loc = ml.group(1).upper()
                    break
        except Exception:
            continue
    if res != "获取失败":
        _egress_cache["ts"] = now
        _egress_cache["ip"] = res
        _egress_cache["colo"] = colo
        _egress_cache["loc"] = loc
    return res


def get_egress_colo():
    """当前出口的 Cloudflare 边缘节点代号(如 LAX), 与 IP 同源同缓存。"""
    return _egress_cache.get("colo", "")


def get_egress_loc():
    """出口所在国家/地区代码(如 US / HK / SG), 用于出口可视化。"""
    return _egress_cache.get("loc", "")


def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"enabled": state["enabled"],
                       "route_active": state.get("route_active"),
                       # 运行实例的构建指纹: 供"双击新 exe 却发现端口被占"时
                       # 判断那头是不是旧实例(见 main() 单实例分支)
                       "proc_build": _exe_fingerprint()},
                      f, ensure_ascii=False, indent=2)
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
    """从 state.json 恢复 enabled 标志。

    注意: 这里恢复的只是「上次会话的状态」, 不等于当前事实。是否允许自动
    重连/自动注入由 reconcile_state_on_startup() 在 daemon 就绪后判定,
    期间 state["armed"] 保持 False (见 reconnect_loop)。
    """
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                state["enabled"] = bool(d.get("enabled", False))
    except Exception:
        pass
    state["armed"] = False
    state["resume_pending"] = False


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


def is_private_ip(ip):
    """是否私有/保留地址(判断目的走的是本地网关直连还是隧道)。"""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


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


# ====================== DNS over HTTPS ======================
# 系统 DNS 可能被污染, 或运营商返回伪造的 AAAA 记录(导致 happy eyeballs
# 卡住)。自检时用 DoH 交叉验证, 能区分"分流没生效"和"DNS 被做了手脚"。
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://doh.pub/dns-query",
]
# 用于 DNS 一致性检查的国内域名(必然是大陆 IP)
DNS_CHECK_DOMAIN = "www.baidu.com"

_cn_nets_cache = {"mtime": None, "nets": []}


def cn_nets():
    """加载并缓存大陆网段(已聚合排序), 供 IP 归属二分查找。"""
    try:
        mtime = os.path.getmtime(CHINA_LIST)
    except Exception:
        mtime = None
    c = _cn_nets_cache
    if c["nets"] and c["mtime"] == mtime:
        return c["nets"]
    nets = []
    try:
        with open(CHINA_LIST, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except Exception:
                    continue
        nets = list(ipaddress.collapse_addresses(nets))
    except Exception:
        nets = []
    c["nets"] = nets
    c["mtime"] = mtime
    return nets


def is_cn_ip(ip):
    """判断 IPv4 是否属于中国大陆地址段(二分查找)。"""
    nets = cn_nets()
    if not nets:
        return False
    try:
        a = int(ipaddress.IPv4Address(ip))
    except Exception:
        return False
    lo, hi = 0, len(nets) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        n = nets[mid]
        if int(n.network_address) <= a <= int(n.broadcast_address):
            return True
        if a < int(n.network_address):
            hi = mid - 1
        else:
            lo = mid + 1
    return False


def doh_resolve(hostname, timeout=4.0):
    """用 DoH 解析域名, 只取 A 记录(IPv4 优先, 绕开伪造 AAAA)。失败返回 []。"""
    import urllib.request
    import urllib.parse
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    for ep in DOH_ENDPOINTS:
        try:
            url = ep + "?" + urllib.parse.urlencode({"name": hostname, "type": "A"})
            req = urllib.request.Request(url, headers={
                "accept": "application/dns-json",
                "User-Agent": "Mozilla/5.0",
            })
            with opener.open(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            ips = []
            for ans in data.get("Answer", []):
                if ans.get("type") != 1:      # 1 = A
                    continue
                v = (ans.get("data") or "").strip()
                try:
                    ipaddress.IPv4Address(v)
                    ips.append(v)
                except Exception:
                    continue
            if ips:
                return ips
        except Exception:
            continue
    return []


def check_dns():
    """对比系统解析与 DoH 解析, 判断是否存在 DNS 污染。"""
    res = {"domain": DNS_CHECK_DOMAIN, "system": [], "doh": [], "verdict": "unknown",
           "msg": ""}
    try:
        infos = socket.getaddrinfo(DNS_CHECK_DOMAIN, 443, socket.AF_INET)
        res["system"] = sorted({i[4][0] for i in infos})
    except Exception as e:
        res["msg"] = "系统解析失败: " + str(e)
    res["doh"] = doh_resolve(DNS_CHECK_DOMAIN)
    if not res["system"]:
        res["verdict"] = "unknown"
        return res

    sys_cn = [ip for ip in res["system"] if is_cn_ip(ip)]
    doh_cn = [ip for ip in res["doh"] if is_cn_ip(ip)]

    if len(sys_cn) == len(res["system"]):
        res["verdict"] = "ok"
        res["msg"] = "系统解析结果全部落在大陆网段内, 未发现污染"
    elif sys_cn:
        res["verdict"] = "mixed"
        res["msg"] = (f"系统解析混合返回 {len(sys_cn)} 个大陆节点与 "
                      f"{len(res['system']) - len(sys_cn)} 个境外节点, 属正常(CDN 多节点), "
                      "不影响分流判定")
    elif doh_cn:
        # 系统完全拿不到大陆地址、DoH 却能拿到 -> 强烈的污染特征
        res["verdict"] = "polluted"
        res["msg"] = (f"系统 DNS 把 {DNS_CHECK_DOMAIN} 全部解析到境外地址 "
                      f"({', '.join(res['system'])}), 而 DoH 能解析出大陆地址 "
                      f"({', '.join(doh_cn)}) —— 疑似 DNS 污染或被代理接管。"
                      "延迟探测使用固定 IP, 因此不影响分流, 但建议检查 DNS 设置。")
    else:
        res["verdict"] = "overseas"
        res["msg"] = ("系统与 DoH 的解析结果均为境外地址。可能是该域名使用境外 CDN, "
                      "也可能是 DoH 出口在境外(Cloudflare DoH 常返回 103.235.x.x 香港节点)。")
    return res


# ====================== IP / DNS 污染检测 ======================
# GFW 伪造 DNS 响应时下发的"黑洞 IP"——历次实测与公开研究整理的常见网段
# (The Great DNS Wall of China / gfw.report 等)。命中这些网段, 说明拿到的
# 不是目标网站的真实地址, 而是被塞过来的假 IP(连过去要么超时要么被嗅探)。
# 注意: 这是启发式佐证, 主判据是"系统 / DoH / 上游"三通道分歧。
POISON_NETS = [ipaddress.ip_network(n) for n in [
    "4.36.66.178/32", "8.7.198.45/32", "14.102.249.18/32",
    "31.13.92.0/24",                       # 拿 Facebook 的 IP 冒充 Google 等
    "37.61.224.0/20",                      # 37.61.229.25 等
    "46.82.170.0/23", "46.82.174.0/24",
    "59.24.3.173/32", "64.33.88.161/32", "64.33.99.47/32",
    "65.49.2.10/32", "67.19.159.0/24", "72.14.205.99/32",
    "78.16.49.0/24", "93.46.8.0/24",
    "111.175.220.0/24", "111.175.221.0/24",
    "159.106.121.0/24", "203.161.9.0/24",
    "211.98.70.0/24", "211.98.71.0/24",
    "216.234.179.186/32", "243.185.187.0/24",
    "120.203.249.18/32", "1.202.3.198/32",
    "106.186.123.146/32", "174.142.79.0/24",
]]


def is_poison_ip(ip):
    """是否是已知的 DNS 伪造响应 IP(黑洞地址)。"""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(a in n for n in POISON_NETS)


def _parse_dns_pkt(data):
    """解析 DNS 响应报文, 返回 (A记录IP列表, TTL列表, rcode)。只认 A 记录。"""
    import struct as _s
    ips, ttls = [], []
    rcode = -1
    try:
        qd, an = _s.unpack(">HH", data[4:8])
        rcode = data[3] & 0x0F
        off = 12
        for _ in range(qd):                    # 跳过 question 区
            while off < len(data) and data[off] != 0:
                off += 1 + data[off]
            off += 5
        for _ in range(an):                    # 逐条解析 answer
            if off >= len(data):
                break
            if data[off] >= 0xC0:              # 域名压缩指针
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += 1 + data[off]
                off += 1
            if off + 10 > len(data):
                break
            rtype, _cls, ttl, rdlen = _s.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:      # 1 = A
                ips.append(socket.inet_ntoa(rdata))
                ttls.append(ttl)
    except Exception:
        pass
    return ips, ttls, rcode


def raw_dns_query(server, hostname, timeout=3.0):
    """直向 server:53 发 UDP DNS 查询 —— 绕过系统解析器, 也绕过 WARP DNS。

    这是污染检测的关键一招: WARP 连着的时候系统解析走 127.0.2.2(永远干净),
    只有直查路由器/运营商 DNS 才能看到真实网络有没有被做手脚。
    返回 (ips, ttls, rcode, 耗时ms); 失败时 ips 为空、rcode=-1。
    """
    import struct as _s
    try:
        qname = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore")
                         for p in hostname.split(".") if p) + b"\x00"
    except Exception:
        return [], [], -1, -1
    pkt = (_s.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
           + qname + _s.pack(">HH", 1, 1))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.time()
    try:
        sock.sendto(pkt, (server, 53))
        data, _addr = sock.recvfrom(4096)
    except Exception:
        return [], [], -1, -1
    finally:
        try:
            sock.close()
        except Exception:
            pass
    ms = int((time.time() - t0) * 1000)
    ips, ttls, rcode = _parse_dns_pkt(data)
    return ips, ttls, rcode, ms


def resolve_a_limited(hostname, timeout=2.5):
    """限定时间内用系统解析器拿 A 记录列表(排序去重)。

    getaddrinfo 不受 socket 超时控制(DNS 卡死时能挂几十秒), 所以丢进线程
    用 join 限时 —— 与 net_ok() 同一套路, 超时返回 []。
    """
    box = {}

    def f():
        try:
            infos = socket.getaddrinfo(hostname, 443, socket.AF_INET,
                                       proto=socket.IPPROTO_TCP)
            box["ips"] = sorted({i[4][0] for i in infos})
        except Exception:
            box["ips"] = []

    t = threading.Thread(target=f, daemon=True)
    t.start()
    t.join(timeout)
    return box.get("ips") or []


# 污染检测探测域名: 境外(墙内最常被伪造响应) + 国内对照(理应拿大陆 IP)
POLLUTION_DOMAINS = [
    ("www.google.com", "Google"),
    ("www.youtube.com", "YouTube"),
    ("www.facebook.com", "Facebook"),
    ("www.wikipedia.org", "Wikipedia"),
]
POLLUTION_CONTROL = [("www.baidu.com", "百度(对照)")]


def check_pollution():
    """多域名 DNS/IP 污染检测(只读, 不改任何配置)。

    三条通道交叉对比, 每个域名都问一遍:
      系统 —— 跟随网卡 DNS(WARP 连着时就是 WARP DNS, 理应永远干净)
      DoH  —— cloudflare-dns.com 境外基准(经隧道出境, 无污染)
      上游 —— 直查路由器/运营商 DNS(绕过 WARP, 看真实网络干不干净)

    判定优先级: 系统命中伪造 IP > 上游命中伪造 IP > 与 DoH 分歧 > 干净。
    这样即使 WARP 开着(系统永远干净), 也能揭示"上游本来有多脏"。
    """
    upstream = get_gateway() or "119.29.29.29"
    items, stats = [], {"clean": 0, "polluted": 0, "upstream": 0,
                        "mismatch": 0, "unknown": 0}
    for dom, label in POLLUTION_DOMAINS + POLLUTION_CONTROL:
        is_ctl = any(dom == d for d, _ in POLLUTION_CONTROL)
        sys_ips = resolve_a_limited(dom)
        doh_ips = doh_resolve(dom, timeout=4.0)
        up_ips, up_ttls, rcode, up_ms = raw_dns_query(upstream, dom)
        sys_poison = next((ip for ip in sys_ips if is_poison_ip(ip)), "")
        up_poison = next((ip for ip in up_ips if is_poison_ip(ip)), "")

        if is_ctl:
            # 国内对照域名: 系统能拿到大陆 IP 即正常
            cn = [ip for ip in sys_ips if is_cn_ip(ip)]
            if sys_ips and len(cn) == len(sys_ips):
                status = "clean"
            elif sys_ips:
                status = "mismatch"      # 国内域名解析出境外 IP, 可疑
            else:
                status = "unknown"
        elif sys_poison:
            status = "polluted"          # 系统解析直接被伪造(严重)
        elif up_poison:
            status = "upstream"          # 上游命中伪造 IP, 但系统/DoH 干净
        elif up_ips and doh_ips and not (set(up_ips) & set(doh_ips)):
            status = "mismatch"          # 上游与干净基准分歧(伪造/劫持)
        elif doh_ips and sys_ips and not (set(sys_ips) & set(doh_ips)):
            status = "mismatch"          # 系统与基准分歧
        elif not up_ips and rcode == 3 and doh_ips:
            status = "mismatch"          # 上游 NXDOMAIN, DoH 却有结果
        elif not up_ips and not doh_ips:
            status = "unknown"           # 上游与 DoH 都没结果, 无法判断
        else:
            status = "clean"
        stats[status] = stats.get(status, 0) + 1

        ttl_txt = ("TTL %ss" % min(up_ttls)) if up_ttls else ""
        items.append({
            "domain": dom, "label": label, "status": status,
            "system": sys_ips, "doh": doh_ips, "upstream": up_ips,
            "upstream_server": upstream, "up_ms": up_ms, "ttl": ttl_txt,
            "rcode": rcode, "poison_ip": sys_poison or up_poison,
        })

    if stats.get("polluted"):
        verdict, summary = "bad", "系统 DNS 解析被伪造 —— 有域名拿到了假 IP"
    elif stats.get("upstream") or stats.get("mismatch"):
        verdict, summary = ("warn",
                            "上游 DNS 有污染迹象, 但系统解析干净(WARP DNS 正在保护)")
    elif stats.get("clean") and not stats.get("unknown"):
        verdict, summary = "clean", "所有探测域名解析一致, 未发现污染"
    else:
        verdict, summary = "unknown", "多数域名无法获取基准, 判断依据不足"
    return {"verdict": verdict, "summary": summary, "items": items,
            "stats": stats, "upstream": upstream}


LINK_TARGETS = [
    ("www.baidu.com", 443, "国内站点 · 应直连"),
    ("cloudflare-dns.com", 443, "Cloudflare · 应走 WARP"),
    ("1.1.1.1", 443, "WARP 任播入口"),
]


def check_links():
    """TCP 握手探测(只读): 验证国内直连与境外隧道两条路都通, 并量握手耗时。"""
    items = []
    for host, port, label in LINK_TARGETS:
        ips = resolve_a_limited(host, 2.0)
        ip = ips[0] if ips else host
        t0 = time.time()
        ok = False
        try:
            s = socket.create_connection((ip, port), timeout=3)
            ok = True
            s.close()
        except Exception:
            ok = False
        items.append({"target": "%s:%d" % (host, port), "label": label,
                      "ip": ip, "ok": ok, "ms": int((time.time() - t0) * 1000)})
    return items


def network_audit():
    """一键网络体检(只读): 污染检测 + 出口归属 + 链路质量 + 分流链路。

    与「分流自检」互补 —— 自检回答"分流有没有生效", 体检回答"网络干不干净、
    通不通、有没有被做手脚"。全部只读, 不碰任何配置; tracert/DoH/原始 DNS
    都是轻量探测。WARP 状态与出口信息直接复用 topology_snapshot 的缓存,
    不额外起 warp-cli 子进程。
    """
    t0 = time.time()
    groups, score = [], 100

    # ---- 1. DNS/IP 污染检测 ----
    pol = check_pollution()
    for it in pol["items"]:
        if it["status"] == "polluted":
            score -= 30
        elif it["status"] in ("upstream", "mismatch"):
            score -= 8
    score = max(score, 0)
    groups.append({"id": "pollution", "name": "DNS / IP 污染检测",
                   "verdict": pol["verdict"], "summary": pol["summary"],
                   "items": pol["items"], "upstream": pol["upstream"]})

    # ---- 2. 出口与归属(复用拓扑缓存, 零子进程) ----
    snap = topology_snapshot()
    w, e = snap["warp"], snap["engine"]
    egress = w.get("egress_ip") or ""
    via_warp = is_cloudflare_ip(egress)
    items = [
        {"name": "公网出口 IP", "ok": bool(egress),
         "detail": (egress or "获取失败") + (" · Cloudflare(WARP)" if via_warp
                                            else " · 非 Cloudflare")},
        {"name": "边缘节点 colo", "ok": bool(w.get("colo")),
         "detail": w.get("colo") or "—"},
        {"name": "出口归属地", "ok": bool(w.get("loc")),
         "detail": w.get("loc") or "—"},
        {"name": "WARP 连接状态", "ok": bool(w.get("connected")),
         "detail": "已连接" if w.get("connected") else "未连接(体检按当前状态进行)"},
        {"name": "已注入规则", "ok": (e.get("rules") or 0) > 0,
         "detail": "%d 条" % (e.get("rules") or 0)},
    ]
    if not w.get("connected"):
        score -= 5                      # 没连 WARP 不算故障, 轻微提示
    eg_warn = [i for i in items if not i["ok"] and i["name"] != "WARP 连接状态"]
    groups.append({"id": "egress", "name": "出口与归属",
                   "verdict": "warn" if eg_warn else "ok", "summary": "",
                   "items": items})

    # ---- 3. 链路质量 ----
    links = check_links()
    fail = 0
    for it in links:
        it["status"] = "ok" if it["ok"] else "fail"
        if not it["ok"]:
            fail += 1
            score -= 15
        elif it["ms"] > 400:            # 握手过慢, 疑似绕路
            it["status"] = "slow"
            score -= 5
    groups.append({"id": "links", "name": "链路质量(TCP 握手)",
                   "verdict": "bad" if fail == len(links) else
                              ("warn" if fail or any(i["status"] == "slow" for i in links) else "ok"),
                   "summary": "%d/%d 可达" % (len(links) - fail, len(links)),
                   "items": links})

    # ---- 4. 分流链路(WARP 未连接时跳过, 不算故障) ----
    routes = []
    if w.get("connected"):
        cn_hop = first_hop("1.0.1.1")
        fx_hop = first_hop("8.8.8.8")
        lan_hop = first_hop("192.168.1.1")
        cn_ok = bool(cn_hop) and is_private_ip(cn_hop)
        fx_ok = bool(fx_hop) and is_cloudflare_ip(fx_hop)
        lan_ok = bool(lan_hop) and is_private_ip(lan_hop)
        routes = [
            {"name": "国内 IP 1.0.1.1", "ok": cn_ok,
             "detail": "首跳 " + (cn_hop or "无") + (" · 本地网关直连" if cn_ok else " · 未直连 ⚠")},
            {"name": "境外 IP 8.8.8.8", "ok": fx_ok,
             "detail": "首跳 " + (fx_hop or "无") + (" · 走 WARP 隧道" if fx_ok else " · 未走 WARP ⚠")},
            {"name": "局域网 192.168.1.1", "ok": lan_ok,
             "detail": "首跳 " + (lan_hop or "无") + (" · 可达" if lan_ok else " · 不可达 ⚠")},
        ]
        for r in routes:
            if not r["ok"]:
                score -= 10
        groups.append({"id": "routes", "name": "分流链路",
                       "verdict": "ok" if all(r["ok"] for r in routes) else "warn",
                       "summary": "", "items": routes})
    else:
        groups.append({"id": "routes", "name": "分流链路",
                       "verdict": "skip",
                       "summary": "WARP 未连接, 跳过(启用分流后可复查)",
                       "items": []})

    score = max(0, min(100, score))
    verdict = "healthy" if score >= 90 else ("warn" if score >= 60 else "bad")
    return {"ts": time.time(), "duration_ms": int((time.time() - t0) * 1000),
            "score": score, "verdict": verdict, "groups": groups,
            "pollution": pol}


def self_test():
    """只读自检: 验证分流是否真正生效 (不改变任何配置)。"""
    egress = get_egress_ip()
    ok, out = warp(["status"])
    connected = "Connected" in out
    ok2, listout = warp(["tunnel", "ip", "list"])
    cli_count = listout.count("(CLI exclude)")

    cn_ip = "1.0.1.1"          # 在 china_cidr.txt 首段 (1.0.1.0/24) 内
    cn_hop = first_hop(cn_ip)
    cn_direct = bool(cn_hop) and is_private_ip(cn_hop)

    fx_ip = "8.8.8.8"          # 不在国内列表 -> 应走 WARP
    fx_hop = first_hop(fx_ip)
    fx_via_warp = bool(fx_hop) and is_cloudflare_ip(fx_hop)

    is_cf = is_cloudflare_ip(egress)

    # 私有网段是否已被排除(局域网设备可达性)
    lan_hop = first_hop("192.168.1.1")
    lan_ok = bool(lan_hop) and is_private_ip(lan_hop)

    # DNS 一致性(区分"分流没生效"与"DNS 被污染")
    dns = check_dns()

    verdict = connected and is_cf and cli_count > 0 and cn_direct
    return {
        "verdict": "PASS" if verdict else "FAIL",
        "connected": connected,
        "egress_ip": egress,
        "egress_via_warp": is_cf,
        "cli_exclude_count": cli_count,
        "china_test": {"ip": cn_ip, "first_hop": cn_hop, "direct": cn_direct},
        "foreign_test": {"ip": fx_ip, "first_hop": fx_hop, "via_warp": fx_via_warp},
        "reserved_total": len(ALWAYS_DIRECT),
        "lan_test": {"probe": "192.168.1.1", "first_hop": lan_hop, "reachable": lan_ok,
                     "reserved_excluded": sorted(set(get_cli_excludes()) & _ALWAYS_DIRECT_SET)},
        "dns": dns,
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
def connect_warp(max_attempts=4, update_phase=True, mode=None):
    """连接 WARP, 带『断重连 + 服务重启』兜底。返回 (connected, last_out)。

    mode 为 None 时按当前分路模式决定(warp / proxy)。重启服务兜底那一步
    必须显式带上 mode —— 写死 "warp" 会在 Proxy 分路下把模式悄悄改回去。
    """
    if mode is None:
        mode = "proxy" if settings.get("route_mode", "tun") == "proxy" else "warp"
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
        warp(["mode", mode], timeout=20)
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


# ====================== Proxy 分路 (不开 TUN) ======================
# net-warp 那类方案拒用 TUN 的理由是 RDP: TUN 接管系统默认路由, 隧道一抖
# 远程桌面就断在门外。我们不必像它那样自己写一个 Go 分流桥 —— 本机
# warp-cli (2026.6.x) 原生支持:
#     warp-cli mode proxy          # 建隧道供 SOCKS5 使用, 不创建 TUN 适配器
#     warp-cli proxy port <port>   # 指定 SOCKS5 监听端口 (127.0.0.1:<port>)
# 实测(见 tools/test_proxy_mode.py): 切到 proxy 模式后 CloudflareWARP 适配器
# 根本不存在、WARP 接口路由 0 条, 裸直连 trace 显示 warp=off —— 系统路由一行未改。
#
# 缺的那半是「分流」: 裸 SOCKS5 不分流, 配了代理的国内站也要绕地球一圈。
# 所以再叠一层本地 HTTP 桥: 目标域名经 DoH 解析后用 is_cn_ip() 判定,
# 国内直连、国外走 WARP SOCKS5。纯标准库, 无需 Go / 无需编译。
PROXY_PORT_DEFAULT = 40000     # WARP 原生 SOCKS5 上行端口
BRIDGE_PORT_DEFAULT = 7890     # 本地智能分流 HTTP 桥端口
SYS_PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# 明确的国内域名后缀: 省掉一次 DoH 往返(其余域名仍走 DoH + IP 判定, 更准)
CN_DOMAIN_SUFFIX = (
    ".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn",
    ".ac.cn", ".mil.cn", ".公司", ".中国", ".网络",
)

_HOP_HEADERS = {"connection", "proxy-connection", "keep-alive",
                "proxy-authenticate", "proxy-authorization", "te",
                "trailer", "transfer-encoding", "upgrade"}

_RESOLVE_CACHE = {}
_RESOLVE_TTL = 300          # DoH 结果缓存 5 分钟
_bridge_lock = threading.Lock()
_bridge_server = None
bridge_stats = {"direct": 0, "proxy": 0, "errors": 0, "started_at": None,
                "last_target": "", "last_way": ""}


def _is_ip_literal(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _system_a(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def _resolve_cached(host):
    """解析域名, 结果缓存 5 分钟。**系统 DNS 优先, DoH 只作兜底。**

    这里刻意不像 net-warp 那样强制走 DoH —— 它必须 DoH, 因为它的桥要自己
    拿着解析出的 IP 去连国外站, 拿到被污染的 IP 就白搭。而我们:
      - 判定为「走代理」时, 是把**域名**交给 SOCKS5 远端解析的(见
        _upstream_for), 本地解析结果根本不参与连接, 污染与否不影响结果;
      - 判定为「直连」时连的是国内站, 本来就没有污染问题。
    所以本地解析只用来做「国内外」判定, 用最快的那个即可。

    实测: 系统解析 0.17s; DoH 0.5s(走 WARP 时) ~ 8s(Proxy 分路下系统
    未走 WARP 时)。首包延迟差了 40 倍, 没有理由为用不上的准确性买单。
    """
    now = time.time()
    ent = _RESOLVE_CACHE.get(host)
    if ent and now - ent[0] < _RESOLVE_TTL:
        return ent[1]
    ips = _system_a(host)
    if not ips:
        ips = doh_resolve(host, timeout=2.5)
    _RESOLVE_CACHE[host] = (now, ips)
    return ips


def route_of(host):
    """判定一个目标该走『直连』还是『WARP 代理』。返回 "direct" / "proxy"。

    判定依据是 IP: 域名先用 DoH 解析(带缓存), 解析出的 IP **全部**落在国内
    或私有段才直连, 否则走代理。之所以用「全部」而不是「任一」:
       - 判错成 direct 的代价是被墙站点直接打不开(失败);
       - 判错成 proxy 的代价只是国内站绕一圈(变慢, 但仍能用)。
    宁可慢, 不可不可用。
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return "direct"
    if host == "localhost" or host.endswith(".local") or host.endswith(".arpa"):
        return "direct"
    if _is_ip_literal(host):
        return "direct" if (is_private_ip(host) or is_cn_ip(host)) else "proxy"
    for suf in CN_DOMAIN_SUFFIX:
        if host == suf.lstrip(".") or host.endswith(suf):
            return "direct"
    ips = _resolve_cached(host)
    if ips and all(is_private_ip(i) or is_cn_ip(i) for i in ips):
        return "direct"
    return "proxy"


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("连接被对端关闭")
        buf += chunk
    return buf


def socks5_connect(host, port, proxy_host="127.0.0.1", proxy_port=None, timeout=15):
    """完成 SOCKS5 握手并返回已连通到 host:port 的 socket。

    只用到 CONNECT(0x01) + 域名类型(0x03), 不需要认证 —— WARP 的本地
    SOCKS5 只监听 127.0.0.1, 本身不要求鉴权。UDP associate 不实现:
    QUIC / 游戏加速请用 TUN 路线。
    """
    pp = int(proxy_port or settings.get("proxy_port", PROXY_PORT_DEFAULT))
    s = socket.create_connection((proxy_host, pp), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")                 # 版本5, 1个方法, 无认证
        greet = _recv_exact(s, 2)
        if greet[0] != 0x05 or greet[1] != 0x00:
            raise IOError("SOCKS5 协商被拒: %s" % greet.hex())
        h = host.encode("idna")
        if len(h) > 255:
            raise IOError("域名过长")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
        rep = _recv_exact(s, 4)
        if rep[1] != 0x00:
            raise IOError("SOCKS5 CONNECT 失败, 代码 %d" % rep[1])
        atyp = rep[3]
        if atyp == 0x01:
            _recv_exact(s, 6)
        elif atyp == 0x03:
            _recv_exact(s, 1 + _recv_exact(s, 1)[0] + 2)
        elif atyp == 0x04:
            _recv_exact(s, 18)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


def _pump(a, b, timeout=600):
    """在两个 socket 之间双向搬运字节, 任一端断开即结束。"""
    socks = [a, b]
    try:
        while True:
            r, _, e = select.select(socks, [], socks, timeout)
            if e or not r:
                return
            for s in r:
                try:
                    data = s.recv(65536)
                except Exception:
                    return
                if not data:
                    return
                try:
                    (b if s is a else a).sendall(data)
                except Exception:
                    return
    finally:
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


def _upstream_for(host, port):
    """按分流判定建立上游连接: 国内/私有直连, 国外走 WARP SOCKS5。"""
    way = route_of(host)
    try:
        if way == "proxy":
            # 走代理时把域名交给远端解析(SOCKS5 的 ATYP=0x03), 既避免本地
            # DNS 污染, 也让 DoH 拿不到的域名仍有机会解析成功。
            up = socks5_connect(host, port)
        else:
            # 直连时直接用刚才判定用的那份 IP, 不再走一次 getaddrinfo。
            # 这一点很关键: 系统解析可能优先返回 AAAA, 而很多国内站的 IPv6
            # 根本不通, 于是每次请求都要等 IPv6 超时再退回 IPv4 —— 实测
            # 国内站经桥访问会因此慢到 4 秒级, 而裸直连只要 0.2 秒。
            cands = ([host] if _is_ip_literal(host)
                     else (_resolve_cached(host) or [host]))
            up = None
            last = None
            for ip in cands[:3]:
                try:
                    up = socket.create_connection((ip, port), timeout=8)
                    break
                except Exception as e:
                    last = e
            if up is None:
                raise last or IOError("无可用的直连地址")
    except Exception as e:
        bridge_stats["errors"] += 1
        raise IOError("%s 连接失败(%s): %s" % (host, way, e))
    bridge_stats[way] = bridge_stats.get(way, 0) + 1
    bridge_stats["last_target"] = host
    bridge_stats["last_way"] = way
    return up, way


class BridgeHandler(BaseHTTPRequestHandler):
    """本地智能分流 HTTP 代理。同时支持 CONNECT(HTTPS 隧道) 与明文 HTTP 转发。"""

    protocol_version = "HTTP/1.1"
    server_version = "WARP-Split-Bridge"
    sys_version = ""

    def log_message(self, *a):
        pass

    # ---------- HTTPS: CONNECT 隧道 ----------
    def do_CONNECT(self):
        host, _, pstr = self.path.rpartition(":")
        try:
            port = int(pstr or 443)
        except Exception:
            port = 443
        try:
            up, _way = _upstream_for(host, port)
        except Exception as e:
            bridge_stats["errors"] += 1
            self.send_error(502, str(e)[:120])
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        _pump(self.connection, up)

    # ---------- 明文 HTTP 转发 ----------
    def _relay(self):
        parts = urlsplit(self.path)
        host = parts.hostname or ""
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except Exception:
            port = 80
        if not host:
            self.send_error(400, "缺少目标主机")
            return
        try:
            up, _way = _upstream_for(host, port)
        except Exception as e:
            bridge_stats["errors"] += 1
            self.send_error(502, str(e)[:120])
            return
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        lines = ["%s %s HTTP/1.1" % (self.command, target),
                 "Host: %s" % parts.netloc]
        for k, v in self.headers.items():
            if k.lower() in _HOP_HEADERS or k.lower() == "host":
                continue
            lines.append("%s: %s" % (k, v))
        try:
            up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace"))
            clen = self.headers.get("Content-Length")
            if clen:
                try:
                    up.sendall(self.rfile.read(int(clen)))
                except Exception:
                    pass
        except Exception as e:
            bridge_stats["errors"] += 1
            try:
                up.close()
            except Exception:
                pass
            self.send_error(502, str(e)[:120])
            return
        self.close_connection = True
        _pump(self.connection, up)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _relay
    do_OPTIONS = do_PATCH = do_TRACE = _relay


def bridge_port():
    return int(settings.get("bridge_port", BRIDGE_PORT_DEFAULT))


def start_bridge():
    """启动本地分流桥。已启动则先停再起(端口变了也能生效)。"""
    global _bridge_server
    stop_bridge()
    port = bridge_port()
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), BridgeHandler)
    except Exception as e:
        log("分流桥启动失败 (端口 %d): %s" % (port, e), logging.ERROR)
        return False, "分流桥端口 %d 启动失败: %s" % (port, e)
    srv.daemon_threads = True
    _bridge_server = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    bridge_stats["started_at"] = time.time()
    with state_lock:
        state["bridge_up"] = True
    log("本地分流桥已启动: 127.0.0.1:%d (国内直连 / 国外走 WARP SOCKS5 %d)"
        % (port, settings.get("proxy_port", PROXY_PORT_DEFAULT)))
    return True, "分流桥已监听 127.0.0.1:%d" % port


def stop_bridge():
    global _bridge_server
    if _bridge_server is None:
        with state_lock:
            state["bridge_up"] = False
        return
    try:
        _bridge_server.shutdown()
    except Exception:
        pass
    try:
        _bridge_server.server_close()
    except Exception:
        pass
    _bridge_server = None
    with state_lock:
        state["bridge_up"] = False
    log("本地分流桥已停止")


# ---------------------- Windows 系统代理 (可选开关) ----------------------
def get_system_proxy():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SYS_PROXY_KEY, 0, winreg.KEY_READ)
        try:
            enable = winreg.QueryValueEx(k, "ProxyEnable")[0]
            server = winreg.QueryValueEx(k, "ProxyServer")[0]
        finally:
            winreg.CloseKey(k)
        return bool(enable), str(server or "")
    except Exception:
        return False, ""


def set_system_proxy(on, port=None):
    """写/还原 HKCU 的 Internet Settings。首次写入前备份原值以便精确还原。

    ProxyOverride 里保留局域网段: 即便开了系统代理, 访问 192.168.x / 10.x
    也不该绕代理 —— 这是 Proxy 分路"局域网零影响"承诺的一部分。
    """
    import winreg
    port = int(port or bridge_port())
    bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;" \
             "172.2*;172.30.*;172.31.*;192.168.*;::1;169.254.*"
    try:
        if on:
            if not settings.get("_sysproxy_backup"):
                en, sv = get_system_proxy()
                settings["_sysproxy_backup"] = {"enable": en, "server": sv}
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SYS_PROXY_KEY,
                               0, winreg.KEY_WRITE)
            try:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ,
                                  "127.0.0.1:%d" % port)
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass)
            finally:
                winreg.CloseKey(k)
        else:
            bak = settings.get("_sysproxy_backup") or {"enable": False, "server": ""}
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SYS_PROXY_KEY,
                               0, winreg.KEY_WRITE)
            try:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD,
                                  1 if bak.get("enable") else 0)
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ,
                                  bak.get("server", ""))
            finally:
                winreg.CloseKey(k)
            settings["_sysproxy_backup"] = None
        try:    # 通知系统刷新代理设置, 否则部分进程要等很久才生效
            ctypes.windll.wininet.InternetSetOptionW(0, 39, None, 0)  # SETTINGS_CHANGED
            ctypes.windll.wininet.InternetSetOptionW(0, 37, None, 0)  # REFRESH
        except Exception:
            pass
        with state_lock:
            state["sysproxy_on"] = bool(on)
        log("系统代理已" + ("设置为 127.0.0.1:%d (局域网已绕过)" % port if on else "还原"))
        return True
    except Exception as e:
        log("设置系统代理失败: " + str(e), logging.ERROR)
        return False


def enable_proxy_route():
    """启用 Proxy 分路: 不创建 TUN、不改系统路由, 只给『配了代理的应用』加速。"""
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "enable"
        state["progress"] = {"total": 0, "done": 0, "phase": "正在切换到 Proxy 分路..."}
    log("开始启用 Proxy 分路 (mode proxy, 不开 TUN, 不改系统路由)...")
    try:
        pp = int(settings.get("proxy_port", PROXY_PORT_DEFAULT))
        warp(["disconnect"], timeout=20)
        time.sleep(1)
        ok, out = warp(["proxy", "port", str(pp)], timeout=20)
        if not ok:
            log("设置 SOCKS5 端口失败: " + out[:120], logging.WARNING)
        else:
            log("WARP SOCKS5 端口已设为 %d" % pp)
        ok, out = warp(["mode", "proxy"], timeout=20)
        if not ok:
            log("设置 mode proxy 返回: " + out[:120], logging.WARNING)

        connected, last_out = connect_warp(update_phase=True, mode="proxy")
        if not connected:
            raise RuntimeError("WARP proxy 模式未能连接。最后状态: " + last_out[:160])

        # 等 SOCKS5 端口起来(daemon 建隧道后才监听)
        up = False
        for _ in range(30):
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect(("127.0.0.1", pp))
                up = True
            except Exception:
                time.sleep(0.5)
            finally:
                s.close()
            if up:
                break
        if not up:
            raise RuntimeError("WARP 已连接但 127.0.0.1:%d 未监听, SOCKS5 不可用" % pp)
        log("WARP proxy 模式已连接, SOCKS5 127.0.0.1:%d 可用" % pp)

        ok, msg = start_bridge()
        if not ok:
            raise RuntimeError(msg)
        if settings.get("system_proxy"):
            set_system_proxy(True)

        with state_lock:
            state["enabled"] = True
            state["route_active"] = "proxy"
            state["armed"] = True
            state["auto_restored"] = False
            state["progress"] = {"total": 0, "done": 0, "phase": "Proxy 分路已启用"}
        save_state()
        log("Proxy 分路启用完成: 系统路由未改动, 分流桥 127.0.0.1:%d"
            % bridge_port())
    except Exception as e:
        log("启用 Proxy 分路失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
        stop_bridge()
        try:
            warp(["disconnect"], timeout=20)
        except Exception:
            pass
        with state_lock:
            state["enabled"] = False
            state["route_active"] = None
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


def disable_proxy_route():
    """停用 Proxy 分路: 还原系统代理 -> 停桥 -> 断开 WARP。"""
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "disable"
        state["progress"] = {"total": 0, "done": 0, "phase": "正在关闭 Proxy 分路..."}
    log("开始停用 Proxy 分路...")
    try:
        if state.get("sysproxy_on"):
            set_system_proxy(False)
        stop_bridge()
        warp(["disconnect"], timeout=20)
        with state_lock:
            state["enabled"] = False
            state["armed"] = False
            state["route_active"] = None
            state["bridge_up"] = False
            state["progress"] = {"total": 0, "done": 0, "phase": "已停用，网络恢复正常"}
        save_state()
        log("Proxy 分路已停用，网络恢复默认")
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


# ====================== 智能 DNS 分流代理 ======================
# 为什么必须有这一段(这是「开启分流后千兆跑不满」的真正元凶):
#
#   WARP 在 TUN(mode warp)下会把物理网卡的 DNS 强制改成 127.0.2.2 / 127.0.2.3
#   —— 那是它自己的 DNS 代理, 查询经隧道送到 Cloudflare 再出去。它只排除了
#   IP, 从不排除 DNS。于是:
#       国内 CDN 的智能 DNS 看到的是「来自境外的查询」, 返回境外/次优节点 IP;
#       这些 IP 不在中国规则库里, 于是流量也一并走隧道 —— 国内站绕地球一圈。
#
#   实测(本机): baidu.com 被解析到 103.235.46.x, taobao.com 到 155.102.176.x,
#   腾讯云镜像到新加坡 101.33.x / 43.159.x; 建连 RTT 从 14.7ms 劣化到 521ms。
#   TCP 吞吐上限 ≈ 窗口/RTT, Windows 默认窗口下 500ms RTT 单流根本跑不满千兆。
#
#   而 warp-cli 的 dns 子命令只有 fallback/families/gateway-id, 没有「自定义
#   DNS 服务器」的口子, 官方在 TUN 模式下不给改。所以只能自己接管:
#
#   监听 127.0.0.1:53(WARP 只占 127.0.2.2/.3, 这个地址是空的), 把网卡 DNS
#   指向它; 对国内域名用国内 DNS 解析(拿到国内 CDN 节点, 走直连), 其余交给
#   WARP DNS(保证被污染/境外域名仍能正确解析)。

DNS_CN = os.environ.get("WARP_SPLIT_DNS_CN", "223.5.5.5")     # 阿里 DNS
DNS_CN_FALLBACK = "119.29.29.29"                              # 腾讯 DNS
# 「境外」分支的上游。**绝不能填 127.0.2.2(WARP 自带 DNS 代理)** —— 会死循环:
#   我们的代理问 127.0.2.2 查 google.com
#     -> WARP 发现 "com" 命中 fallback 后缀, 把查询转回 127.0.0.1(我们)
#     -> 我们再问 127.0.2.2 -> ...
#   实测表现为 3.5s 超时、只能退回国内结果(被污染)。
# 用公网 DNS 则没有这个问题: 1.1.1.1 会经 WARP 隧道出境, 拿到的正是
# "从境外访问"的视角, 与 WARP 原生 DNS 一致, 且实测 169ms、未被劫持。
DNS_WARP = os.environ.get("WARP_SPLIT_DNS_INTL", "1.1.1.1")
DNS_WARP_FALLBACK = os.environ.get("WARP_SPLIT_DNS_INTL2", "8.8.8.8")
DNS_LISTEN_ADDR = "127.0.0.1"
DNS_LISTEN_PORT = 53
_DNS_CACHE = {}                 # question 摘要 -> (时间戳, 响应报文)
_DNS_CACHE_TTL = 120
_DNS_SERVER = None
_DNS_LOCK = threading.Lock()
dns_stats = {"cn": 0, "warp": 0, "fallback": 0, "errors": 0}

# ---- 把这些后缀交给本地智能 DNS 解析 ----
# WARP 的「fallback domains」机制: 命中后缀的域名, 其 DNS 查询不进隧道,
# 而是转给 fallback 服务器(见 `warp-cli dns default-fallbacks`)。
#
# 【实测结论, 与直觉相反, 别踩坑】
# 1) fallback 服务器默认**不是** 127.0.0.1, 而是网卡 DHCP 学来的地址
#    (本机是路由器 192.168.33.1:53)。所以光加后缀是不够的 —— 查询会转给
#    路由器 DNS, 国内域名确实能拿国内节点, 但境外域名会被 ISP 污染
#    (实测 google.com 被解析成 31.13.92.37, 那是 Facebook 的段)。
# 2) 改网卡 DNS **争不过** WARP: CloudflareWARP 适配器 metric 更低, 系统
#     DNS 客户端永远优先它的 127.0.2.2(实测把 metric 调到 50 也无效)。
# 3) 但 **fallback 服务器会跟随网卡 DNS** —— 而且只在网卡 DNS 是**单条目**
#    时才跟随(实测写两条 127.0.0.1+223.5.5.5 会退回路由器)。所以正确姿势是:
#        a. 先在 127.0.0.1:53 起本地智能 DNS
#        b. 把网卡 DNS 设为**单条** 127.0.0.1
#        c. 再加后缀
#    这样 WARP 的 default-fallbacks 就变成 127.0.0.1:53, 命中后缀的域名
#    正式转交我们的代理, 国内拿国内节点、境外拿干净的 WARP 结果, 零污染。
# 4) 风险与兜底: 代理一死, 命中后缀的域名就解析不了(后缀覆盖 com/net/org
#    等, 影响面很大)。所以 dns_guard_loop 每轮都会核对「代理活着 且
#    default-fallbacks 是 127.0.0.1」, 一旦救不回来就**立刻把网卡 DNS
#    还原成 DHCP**, 退化成 WARP 原生行为, 绝不让用户断网。
DNS_FALLBACK_SUFFIXES = (
    # 国内常用
    "cn", "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn", "ac.cn",
    "com", "net", "org", "edu", "gov",
    # 国际常见后缀: 多数是境外站, 但一样交给本地代理按 IP 归属判定更准 ——
    # 判成国内就拿国内节点, 判成境外照旧走 WARP DNS, 不会解析错。
    "io", "co", "app", "dev", "xyz", "top", "club", "vip", "shop",
    "info", "biz", "me", "tv", "cc", "online", "site", "tech", "ai",
    "cloud", "wiki", "name", "pro", "work", "life", "world", "space",
)

# 改 DNS 时要跳过的网卡: WARP 自己的隧道、企业 VPN 虚拟网卡(本机有深信服
# aTrust VNIC)、各类虚拟化网卡。改它们的 DNS 没有意义, 还可能破坏业务网络。
_NIC_SKIP_RE = r"WARP|Cloudflare|TAP|Virtual|Sangfor|aTrust|VPN|Hyper-V|VMware|VirtualBox|Loopback|Teredo|isatap"


def _dns_parse_question(data):
    """取出 DNS 查询报文里的 (qname, qtype)。失败返回 (None, 0)。"""
    try:
        i = 12
        labels = []
        while i < len(data):
            ln = data[i]
            if ln == 0:
                i += 1
                break
            labels.append(data[i + 1:i + 1 + ln].decode("latin-1"))
            i += 1 + ln
        qtype = struct.unpack("!H", data[i:i + 2])[0]
        return ".".join(labels).lower().rstrip("."), qtype
    except Exception:
        return None, 0


def _dns_extract_ips(resp, want_type):
    """从 DNS 应答里提取 A(1) / AAAA(28) 记录的 IP 列表。"""
    ips = []
    try:
        if not resp or len(resp) < 12:
            return ips
        qd, an = struct.unpack("!HH", resp[4:8])
        i = 12
        for _ in range(qd):                      # 跳过问题区
            while i < len(resp) and resp[i] != 0:
                i += 1 + resp[i]
            i += 5
        for _ in range(an):                      # 遍历应答区
            if i >= len(resp):
                break
            if resp[i] & 0xC0 == 0xC0:           # 压缩指针
                i += 2
            else:
                while i < len(resp) and resp[i] != 0:
                    i += 1 + resp[i]
                i += 1
            if i + 10 > len(resp):
                break
            rtype, _cls, _ttl, rdl = struct.unpack("!HHIH", resp[i:i + 10])
            i += 10
            rd = resp[i:i + rdl]
            i += rdl
            if rtype == want_type:
                try:
                    if want_type == 1 and rdl == 4:
                        ips.append(socket.inet_ntoa(rd))
                    elif want_type == 28 and rdl == 16:
                        ips.append(socket.inet_ntop(socket.AF_INET6, rd))
                except Exception:
                    pass
    except Exception:
        pass
    return ips


def _dns_forward(data, upstream, timeout=3.0):
    """把原始查询报文转发给上游 DNS, 返回响应报文或 None。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(data, (upstream, 53))
        resp, _ = s.recvfrom(4096)
        s.close()
        return resp
    except Exception:
        return None


_DNS_ROUTE_CACHE = {}       # (qname, qtype) -> (时间戳, "cn" | "warp")
_DNS_ROUTE_TTL = 600        # 记住某个域名该问谁, 避免每次都问两边


def _dns_resolve_once(data):
    """分流判定: 国内域名用国内 DNS(拿国内 CDN 节点), 境外域名交给 WARP DNS。

    「解析出的 IP 全部在国内才认定国内」的道理与分流桥一致: 判错成国内=
    站点打不开(失败), 判错成 WARP=只是慢一点, 宁可慢不可不可用。

    性能: 首次见到的域名并行问两边(总耗时取较慢的那个, 而非两者之和);
    判定结果记住 10 分钟, 之后只问该问的那一个 —— 国内域名约 17ms。
    """
    qname, qtype = _dns_parse_question(data)
    now = time.time()
    ck = (qname, qtype)
    way = None
    ent = _DNS_ROUTE_CACHE.get(ck)
    if ent and now - ent[0] < _DNS_ROUTE_TTL:
        way = ent[1]

    if way == "cn":
        r = _dns_forward(data, DNS_CN, timeout=2.5)
        if r:
            dns_stats["cn"] += 1
            return r
        way = None
    elif way == "warp":
        r = _dns_forward(data, DNS_WARP, timeout=3.5)
        if not r:
            r = _dns_forward(data, DNS_WARP_FALLBACK, timeout=3.0)
        if r:
            dns_stats["warp"] += 1
            return r
        way = None

    # 首次见到这个域名 -> 并行问两边
    res = {}

    def _ask(key, up, to):
        res[key] = _dns_forward(data, up, timeout=to)

    t1 = threading.Thread(target=_ask, args=("cn", DNS_CN, 2.5))
    t2 = threading.Thread(target=_ask, args=("warp", DNS_WARP, 3.5))
    t1.start()
    t2.start()
    t1.join()                       # 先拿国内的结果做判定
    resp_cn = res.get("cn")
    if qtype == 1 and resp_cn:
        ips = _dns_extract_ips(resp_cn, 1)
        if ips and all(is_cn_ip(i) or is_private_ip(i) for i in ips):
            _DNS_ROUTE_CACHE[ck] = (time.time(), "cn")
            dns_stats["cn"] += 1
            return resp_cn
    t2.join()
    resp_w = res.get("warp")
    if not resp_w:
        resp_w = _dns_forward(data, DNS_WARP_FALLBACK, timeout=3.0)
    if resp_w:
        _DNS_ROUTE_CACHE[ck] = (time.time(), "warp")
        dns_stats["warp"] += 1
        return resp_w
    if resp_cn:
        dns_stats["fallback"] += 1
        return resp_cn
    return None


class _DNSRequestHandler(BaseRequestHandler):
    """UDP DNS 处理器。任何异常都必须吞掉并返回兜底应答 —— 这个服务挂了
    等于本机断网, 绝不能因为一个畸形报文把线程打死。"""

    def handle(self):
        try:
            data, sock = self.request
            if not data or len(data) < 12:
                return
            key = hashlib.md5(data[12:]).digest()
            now = time.time()
            ent = _DNS_CACHE.get(key)
            if ent and now - ent[0] < _DNS_CACHE_TTL:
                resp = bytearray(ent[1])
                resp[0:2] = data[0:2]        # 换回本次的事务 ID
                sock.sendto(bytes(resp), self.client_address)
                return
            resp = _dns_resolve_once(data)
            if resp:
                _DNS_CACHE[key] = (now, resp)
                resp = bytearray(resp)
                resp[0:2] = data[0:2]
                sock.sendto(bytes(resp), self.client_address)
        except Exception:
            dns_stats["errors"] += 1


def start_smart_dns():
    """启动本地 DNS 分流代理(127.0.0.1:53)。返回 (ok, msg)。"""
    global _DNS_SERVER
    with _DNS_LOCK:
        if _DNS_SERVER is not None:
            return True, "已在运行"
        try:
            srv = ThreadingUDPServer((DNS_LISTEN_ADDR, DNS_LISTEN_PORT),
                                     _DNSRequestHandler)
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            _DNS_SERVER = srv
            log("智能 DNS 分流已启动: %s:%d (国内 %s / 境外 %s)" %
                (DNS_LISTEN_ADDR, DNS_LISTEN_PORT, DNS_CN, DNS_WARP))
            return True, "started"
        except Exception as e:
            log("智能 DNS 启动失败: " + str(e), logging.WARNING)
            return False, str(e)


def stop_smart_dns():
    """停掉本地 DNS 分流代理。"""
    global _DNS_SERVER
    with _DNS_LOCK:
        if _DNS_SERVER is None:
            return
        try:
            _DNS_SERVER.shutdown()
            _DNS_SERVER.server_close()
        except Exception:
            pass
        _DNS_SERVER = None
        log("智能 DNS 分流已停止")


def _ps(body, timeout=40):
    """跑一段 PowerShell 并取回 stdout。

    【中文 Windows 的坑, 踩过一次】PowerShell 的输出编码跟随控制台代码页,
    中文系统上是 GBK(936)。网卡名恰恰是中文("以太网"), 用 text=True 让
    Python 按 UTF-8 解会直接抛 UnicodeDecodeError, stdout 变 None ——
    表现为"枚举不到网卡", 极难排查。这里在命令前强制把输出编码设成 UTF-8,
    并用 errors='replace' 兜底, 保证任何代码页下都能拿到东西。
    """
    prefix = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
              "$OutputEncoding=[System.Text.Encoding]::UTF8; ")
    try:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  prefix + body], capture_output=True, timeout=timeout)
        out = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
        return r.returncode, out
    except Exception as e:
        return -1, str(e)


def _nic_indexes():
    """需要改 DNS 的物理网卡 ifIndex 列表(排除 WARP/VPN/虚拟网卡)。

    返回**数字**而不是网卡名: 一是彻底绕开中文编码问题, 二是
    Set-DnsClientServerAddress / netsh 都认 ifIndex, 更稳。
    """
    body = ("Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and "
            "$_.InterfaceDescription -notmatch '%s' } | "
            "ForEach-Object { $_.ifIndex }" % _NIC_SKIP_RE)
    rc, out = _ps(body, timeout=30)
    idx = []
    for x in out.splitlines():
        x = x.strip()
        if x.isdigit():
            idx.append(int(x))
    return idx


def apply_nic_dns(servers):
    """把物理网卡的 DNS 设为给定列表(排除 WARP/企业VPN/虚拟网卡)。
    传入空列表表示还原为 DHCP 自动获取。返回 (ok, msg)。

    三个坑(都实测过):
      - 中文 Windows 上 PowerShell 输出是 GBK, 按 UTF-8 解会抛异常、stdout
        变 None, 表现为"枚举不到网卡"。所以只取数字 ifIndex(见 _ps/_nic_indexes)。
      - 还原时 `Set-DnsClientServerAddress -ServerAddresses @()` 是**无效的**,
        注册表里的静态 NameServer 会原样留着 —— 表现为「程序退出了但网卡
        还指向 127.0.0.1, 而代理已死」, 用户直接断网。这个 bug 我踩过一次。
        这里用 -ResetServerAddresses, 并在之后**复查注册表**, 没清干净就
        再用 netsh 兜底一次。
      - WARP 只在网卡 DNS 是**单条目**时才把它学成 fallback 服务器,
        所以调用方要传一个元素的列表(不要塞备用 DNS, 那样会失效)。
    """
    if not _IS_WIN:
        return False, "仅支持 Windows"
    idxs = _nic_indexes()
    if not idxs:
        return False, "未找到物理网卡"
    errs = []
    for idx in idxs:
        try:
            if servers:
                arg = ",".join("'%s'" % s for s in servers)
                body = ("Set-DnsClientServerAddress -InterfaceIndex %d "
                        "-ServerAddresses @(%s)" % (idx, arg))
            else:
                body = ("Set-DnsClientServerAddress -InterfaceIndex %d "
                        "-ResetServerAddresses" % idx)
            rc, out = _ps(body, timeout=40)
            if rc != 0:
                errs.append("idx%s: %s" % (idx, out.strip()[:80]))
        except Exception as e:
            errs.append("idx%s: %s" % (idx, str(e)[:80]))
    if not servers and not errs:
        # 复查: 静态 DNS 是否真被清掉
        if _static_dns_left():
            _reset_dns_via_netsh()
            if _static_dns_left():
                errs.append("还原后仍残留静态 DNS")
    if errs:
        return False, "; ".join(errs)
    return True, "ok"


def _static_dns_left():
    """注册表里是否还留着我们可能写过的静态 DNS(127.0.0.1)。"""
    rc, out = _ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
                  "Services\\Tcpip\\Parameters\\Interfaces\\*' -Name NameServer "
                  "-ErrorAction SilentlyContinue | Where-Object { $_.NameServer } | "
                  "ForEach-Object { $_.NameServer }", timeout=30)
    return "127.0.0.1" in (out or "")


def _reset_dns_via_netsh():
    """netsh 兜底还原网卡 DNS(实测有效, PowerShell 那条路有时会留残留)。"""
    rc, out = _ps("Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
                  "ForEach-Object { $_.Name }", timeout=30)
    for nm in (out or "").splitlines():
        nm = nm.strip()
        if not nm:
            continue
        try:
            _run(["netsh", "interface", "ipv4", "delete", "dnsservers", nm, "all"],
                 capture_output=True, timeout=40)
        except Exception:
            pass


def setup_smart_dns(wait_ready=True, rounds=8):
    """装配智能 DNS 分流。返回 (ok, msg)。

    顺序很关键 —— 先把代理跑起来, 再把网卡 DNS 指过去, 最后加后缀。
    反过来的话会有一小段「网卡指向 127.0.0.1 但没有监听」的窗口, 表现为
    所有解析卡一下; 实测在这个窗口里 WARP 连握手都会卡在 happy eyeballs。

    装完还要等它真正生效: 改网卡 DNS 属于「网络配置变化」, WARP 有时会以
    "Settings Changed" 为由把隧道短暂断掉, 而 `dns default-fallbacks` 只在
    连着时才有值。所以这里轮询等待, 发现断了就重连(排除规则还在配置里,
    重连是秒级的), 直到 fallback 服务器变成 127.0.0.1。
    """
    if not _IS_WIN:
        return False, "仅支持 Windows"
    ok, msg = start_smart_dns()
    if not ok:
        # 代理起不来就别动网卡 —— 否则等于自断 DNS
        return False, "本地 DNS 代理未启动: " + msg
    ok2, msg2 = apply_nic_dns([DNS_LISTEN_ADDR])
    if not ok2:
        stop_smart_dns()
        return False, "网卡 DNS 改写失败: " + msg2
    n = apply_dns_fallbacks()
    if n == 0:
        teardown_smart_dns()
        return False, "WARP 未能接受 fallback 后缀"

    if wait_ready:
        for _ in range(rounds):
            time.sleep(3)
            okc, out = warp(["status"], timeout=12)
            if "Connected" not in (out or ""):
                # 被我们的改动弄断了 —— 重连一次再验
                connect_warp(max_attempts=2, update_phase=False)
                continue
            if DNS_LISTEN_ADDR in dns_fallback_server():
                return True, "已接管 (代理 + 网卡 DNS + %d 条后缀)" % n
        # 没等到: 后缀已经写进去了, 先按"部分生效"返回, 剩下的交给
        # dns_guard_loop 每 30 秒继续修。不在这里判失败, 否则会把刚建好的
        # 隧道又拆掉, 反而更糟。
        return True, "已接管但 WARP 尚未确认 fallback 服务器(守卫线程会继续修)"

    return True, "已接管 (代理 + 网卡 DNS + %d 条后缀)" % n
    return True, "已接管 (代理 + 网卡 DNS + %d 条后缀)" % n


def teardown_smart_dns():
    """拆卸智能 DNS 分流, 顺序与装配相反: 先撤后缀, 再停代理, 最后还原网卡。

    「先撤后缀」很重要: 后缀还在但代理已停的话, 命中后缀的域名会解析失败。
    """
    reset_dns_fallbacks()
    stop_smart_dns()
    apply_nic_dns([])


def toggle_smart_dns(on):
    """在程序运行中切换智能 DNS 开关(供 /api/settings 用)。

    为什么不能在请求线程里直接干完就完事: 无论是装配还是拆卸, 都会动
    `dns fallback` 列表, 而 WARP 把这个当「设置变更」—— 隧道会被断掉
    (实测确认)。分流还开着的话必须再连回来, 否则用户点一下开关就断网了。
    排除规则还在配置里, 重连是秒级的。
    """
    try:
        if on:
            ok, msg = setup_smart_dns(wait_ready=False)
            with state_lock:
                state["dns_proxy"] = ok
            log("智能 DNS 已开启: " + msg if ok else
                "智能 DNS 开启失败: " + msg, logging.INFO if ok else logging.WARNING)
        else:
            teardown_smart_dns()
            with state_lock:
                state["dns_proxy"] = False
            log("智能 DNS 已关闭, 已还原网卡 DNS")
        # 分流开着就把隧道接回来
        if state.get("enabled") and settings.get("route_mode", "tun") == "tun":
            ok, out = warp(["status"], timeout=12)
            if "Connected" not in (out or ""):
                connect_warp(max_attempts=3, update_phase=False)
                log("切换智能 DNS 后已重新连接 WARP")
    except Exception as e:
        log("切换智能 DNS 失败: " + str(e), logging.WARNING)


def dns_fallback_server():
    """读取 WARP 当前的 fallback 服务器, 用于守卫校验。返回字符串或 ''。"""
    try:
        ok, out = warp(["dns", "default-fallbacks"], timeout=15)
        return (out or "").strip() if ok else ""
    except Exception:
        return ""


_FB_SERVER_CACHE = {"ts": 0, "val": ""}


def _cached_fallback_server():
    """同 read_nic_dns 的理由: /api/status 每 1.5 秒一次, 不能每次真去问。"""
    now = time.time()
    if now - _FB_SERVER_CACHE["ts"] < 15:
        return _FB_SERVER_CACHE["val"]
    _FB_SERVER_CACHE["ts"] = now
    _FB_SERVER_CACHE["val"] = dns_fallback_server().replace("\n", " ")
    return _FB_SERVER_CACHE["val"]


def _atexit_restore_dns():
    """进程退出兜底: 撤掉智能 DNS 接管。

    网卡 DNS 指向 127.0.0.1 而本进程已死 = 53 端口无人监听 = 命中后缀的
    域名全部解析失败。这是本功能最严重的失败模式, 所以专门用 atexit 兜一层。
    """
    try:
        if _DNS_SERVER is not None:
            teardown_smart_dns()
            log("atexit: 已还原网卡 DNS 与 WARP fallback")
    except Exception:
        pass


_NIC_DNS_CACHE = {"ts": 0, "val": []}
_NIC_DNS_TTL = 20


def read_nic_dns(force=False):
    """读取当前物理网卡的 DNS, 用于展示与守卫校验。

    带 20 秒缓存 —— 控制台每 1.5 秒就会拉一次 /api/status, 而每次真读都要
    起一个 PowerShell 进程(实测 1-2 秒), 不缓存等于持续 fork 进程。

    历史教训(重大): 曾经为了"一次 PS 顺带取网关"把 Get-NetRoute 耦合进来,
    而 Get-NetRoute 在这台机器上每次必挂满 timeout —— read_nic_dns 卡 20s,
    又因为它在 /api/status 里是持着 state_lock 调的, 导致前端 1.5s 轮询全部
    堆积、面板数据全「—」。**只查 DNS, 别的一概不碰**; 网关走 get_gateway()。
    """
    if not _IS_WIN:
        return []
    now = time.time()
    if not force and now - _NIC_DNS_CACHE["ts"] < _NIC_DNS_TTL:
        return _NIC_DNS_CACHE["val"]
    try:
        body = ("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
                "ForEach-Object { $_.ServerAddresses -join ',' }")
        _rc, out = _ps(body, timeout=8)
        if _rc != 0:
            # PowerShell 失败(超时/被拦): 绝不能把错误信息当成 DNS 值缓存,
            # 否则面板会展示一串 Command 报错文本。按空处理, 下次再试。
            _NIC_DNS_CACHE["ts"] = now
            _NIC_DNS_CACHE["val"] = []
            return []
        val = []
        for ln in (out or "").splitlines():
            ln = ln.strip()
            if ln:
                val.append(ln)
    except Exception:
        val = []
    _NIC_DNS_CACHE["ts"] = now
    _NIC_DNS_CACHE["val"] = val
    return val


_GATEWAY_CACHE = {"ts": 0.0, "val": ""}
_GATEWAY_TTL = 60


def get_gateway():
    """默认网关地址(带 60s 缓存)。出口可视化用。

    用 `netsh interface ipv4 show route`(原生 exe, 不经 PowerShell 管线,
    实测 0.7s)解析默认路由。**不用 Get-NetRoute** —— 那台机器上它每次必挂
    满 timeout(见 read_nic_dns 的教训), 曾把 /api/status 拖死 20s。

    解析: 找前缀恰为 0.0.0.0/0 的行, 取跃点数最小的那条的网关列。
    netsh 在中文系统输出可能是 GBK 也可能 UTF-8, 但网关列是 ASCII,
    所以解码用 ignore 即可, split 不受影响。
    """
    if not _IS_WIN:
        return ""
    now = time.time()
    if _GATEWAY_CACHE["val"] and now - _GATEWAY_CACHE["ts"] < _GATEWAY_TTL:
        return _GATEWAY_CACHE["val"]
    gw = ""
    try:
        r = _run(["netsh", "interface", "ipv4", "show", "route"],
                 capture_output=True, timeout=8)
        out = (r.stdout or b"").decode("utf-8", "ignore")
        best = None
        for ln in out.splitlines():
            f = ln.split()
            if len(f) < 6 or f[3] != "0.0.0.0/0":
                continue
            try:
                metric = int(f[2])
            except ValueError:
                continue
            cand = f[-1]
            if not (cand and cand[0].isdigit() and cand.count(".") == 3):
                continue          # "在链路上"或接口名, 不是 IP
            if best is None or metric < best[0]:
                best = (metric, cand)
        if best:
            gw = best[1]
    except Exception:
        gw = ""
    _GATEWAY_CACHE["val"] = gw
    _GATEWAY_CACHE["ts"] = now
    return gw


def apply_dns_fallbacks():
    """把常见域名后缀写进 WARP 的 DNS fallback, 让这些域名的解析转交本地
    智能 DNS。返回成功写入的条数。"""
    n = 0
    for suf in DNS_FALLBACK_SUFFIXES:
        try:
            ok, _out = warp(["dns", "fallback", "add", suf], timeout=15)
            if ok:
                n += 1
        except Exception:
            pass
    if n:
        log("已把 %d 个域名后缀交给本地智能 DNS 解析" % n)
    return n


def reset_dns_fallbacks():
    """还原 WARP 的 DNS fallback 到默认(只留 lan/home/internal 等)。"""
    try:
        ok, out = warp(["dns", "fallback", "reset"], timeout=20)
        if ok:
            log("已还原 WARP 的 DNS fallback 列表")
        return ok
    except Exception:
        return False


def dns_guard_loop():
    """DNS 守卫 + 故障安全网。只在「已启用 + 智能 DNS + TUN 分路」时动作。

    每轮核对三件事, 任一不满足就修; 修不好就**整体撤退**(还原网卡 DNS),
    退化成 WARP 原生行为 —— 宁可不分流, 也不能让用户断网:
      1. 本地代理是否还活着
      2. WARP 的 fallback 服务器是否仍是 127.0.0.1(重连后可能被改回路由器)
      3. fallback 后缀是否还在
    WARP 没连着的时候不做任何事(连着才谈得上分流)。
    """
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(30)
        try:
            if not settings.get("smart_dns", True):
                continue
            if time.time() < net_state.get("suppress_dns_until", 0):
                continue    # 网络保障刚判定智能 DNS 有害, 冷却期内别再装回来
            if not state["enabled"] or state["running"]:
                continue
            if settings.get("route_mode", "tun") != "tun":
                continue      # Proxy 分路不改系统 DNS, 无需守卫
            ok, out = warp(["status"], timeout=12)
            if "Connected" not in (out or ""):
                continue

            need = []
            if _DNS_SERVER is None:
                need.append("代理已停止")
            if DNS_LISTEN_ADDR not in dns_fallback_server():
                need.append("fallback 服务器已漂移")
            ok2, fl = warp(["dns", "fallback", "list"], timeout=15)
            if not ok2 or "com" not in (fl or ""):
                need.append("后缀已丢失")
            if not need:
                continue

            log("智能 DNS 状态异常(%s), 尝试恢复..." % "、".join(need),
                logging.WARNING)
            ok3, msg3 = setup_smart_dns()
            if ok3:
                log("智能 DNS 已恢复: " + msg3)
            else:
                # 救不回来 —— 立刻整体撤退, 保证网络可用
                teardown_smart_dns()
                with state_lock:
                    state["dns_proxy"] = False
                log("智能 DNS 无法恢复(%s), 已整体还原为 WARP 原生 DNS "
                    "以保证网络可用" % msg3, logging.ERROR)
        except Exception as e:
            log("dns guard err: " + str(e), logging.WARNING)


# ====================== 网络保障: 底线是「任何时候都要能上网」 ======================
# 分流是锦上添花, 上网才是刚需。前面所有功能都在「网络可用」这个前提上叠,
# 而 DNS 接管、WARP 隧道、排除规则任何一环出岔子都可能把前提弄丢。
# 这一层不关心分流是否启用 —— 它只关心一件事: 现在能不能上网? 不能就逐级
# 退让, 直到能为止。
NET_PROBES = ("www.baidu.com", "www.qq.com", "one.one.one.one")
GUARD_TASK = "CloudflareWARP-Split-Guard"
net_state = {
    "ok": True, "detail": "", "ts": 0.0, "streak": 0, "last_action": "",
    "cooldown_until": 0.0,      # 刚救过一次, 冷却期内不再动(避免与自愈/重连打架)
    "suppress_dns_until": 0.0,  # 判定"智能 DNS 有害"后, 冷却期内别再把它装回来
}


def _resolve_ok(host, timeout=2.5):
    """在限定时间内解析 host。getaddrinfo 不受 socket 超时控制(卡住能卡几十秒),
    所以丢进线程里用 join 限时, 超时即判失败。"""
    box = {}
    def f():
        try:
            box["ok"] = bool(socket.getaddrinfo(host, 443,
                                                proto=socket.IPPROTO_TCP))
        except Exception:
            box["ok"] = False
    t = threading.Thread(target=f, daemon=True)
    t.start()
    t.join(timeout)
    return bool(box.get("ok"))


def net_ok(timeout=2.5):
    """能否上网。只判 DNS 是否能拿到 A 记录 —— 解析不通后面的连接必然不通,
    解析通了基本就能用, 探测成本极低(不发真实流量)。三个域名任一成功即可,
    避免单站点故障被误判成断网。返回 (ok, detail)。"""
    for host in NET_PROBES:
        if _resolve_ok(host, timeout):
            return True, host
    return False, "解析 %s 均失败" % " / ".join(NET_PROBES)


def rescue_network(reason="", force=False):
    """网络急救: 逐级退让, 每一步之后复查, 通了就停。返回 (ok, detail)。

    force=True 表示用户手动触发(按钮/托盘), 无视冷却强制执行。
    自动触发时遵守 5 分钟跨进程冷却 —— 见下面那段说明。

    退让顺序按「代价从小到大、可能性从高到低」排:
      L0 还原网卡 DNS(清掉 127.0.0.1 残留) + 撤掉 WARP fallback 后缀
         —— 覆盖 90% 的场景: 进程被硬杀后 daemon 还把查询转给死掉的本地代理
      L1 断开 WARP 隧道 —— 回到纯直连。排除规则留在配置里, 断开后本就不生效,
         所以这一步零副作用, 再次启用也是秒级的
      L2 强制 netsh 清空网卡 DNS 再试 —— 到这一步基本说明不是我们造成的
         (例如运营商/路由器问题), 如实记录并提示
    """
    ok, detail = net_ok()
    if ok:
        return True, "网络正常 (%s)" % detail
    # 跨进程冷却: 计划任务拉起的 --guard 每次都是全新进程, 内存里的冷却变量
    # 每次都归零 —— 网络真的断着的时候它会每 5 分钟做一遍全套退让(含断开
    # WARP), 把 state.json 反复改。所以冷却判据放在持久化的 state 里,
    # 主进程和巡检进程都遵守。手动触发(force)不受此限。
    last = state.get("rescue") or {}
    if not force and last.get("ts") and time.time() - last["ts"] < 300:
        return False, ("5 分钟内已急救过一次(上次结果: %s), 本次跳过 —— "
                       "反复拆网络只会让情况更乱" % (last.get("detail") or "未知"))

    log("网络不可用(%s)%s, 开始急救..." % (detail, (" 触发原因: " + reason) if reason else ""),
        logging.WARNING)
    # 一旦进入退让就上两个冷却, 防止几个守护线程互相拆台、来回震荡:
    #   cooldown      5 分钟内 net_guard 不再重复动网络
    #   suppress_dns  10 分钟内 dns_guard 别把刚判定有害的智能 DNS 再装回来
    net_state["cooldown_until"] = time.time() + 300
    net_state["suppress_dns_until"] = time.time() + 600
    steps = []

    # ---- L0: 撤掉我们动过的 DNS ----
    try:
        reset_dns_fallbacks()
        apply_nic_dns([])
        steps.append("已还原网卡 DNS 并撤掉 fallback 后缀")
    except Exception as e:
        steps.append("L0 失败: %s" % e)
    time.sleep(1.5)
    ok, detail = net_ok()
    if ok:
        _record_rescue(reason, "L0", steps, True, detail)
        return True, "L0 还原 DNS 后恢复 (%s)" % detail

    # ---- L1: 断开隧道回到直连 ----
    try:
        warp(["disconnect"], timeout=20)
        # 关键: 断开的同时必须摘掉"允许自动重连"的旗标。否则 reconnect_loop
        # 会在 15 秒后把隧道拉回来 —— 我们正是因为"分流状态下网络不可用"
        # 才断开的, 拉回去等于把刚救回来的网络又拖进同一个坑, 而且用户
        # 看起来就是"我明明关了它又自己开了"。
        # 保障层只做减法: 它永远不会主动启用分流, 恢复与否交给用户决定。
        with state_lock:
            state["armed"] = False
            was_on = state["enabled"]
            if was_on:
                state["enabled"] = False
                state["route_active"] = None
                state["guard_paused"] = True
        if was_on:
            save_state()
            log("为保障网络已暂停分流 —— 不会自动重开, 请确认网络正常后手动启用",
                logging.WARNING)
        steps.append("已断开 WARP 隧道(回到直连)")
    except Exception as e:
        steps.append("L1 失败: %s" % e)
    time.sleep(2)
    ok, detail = net_ok()
    if ok:
        _record_rescue(reason, "L1", steps, True, detail)
        return True, "L1 断开 WARP 后恢复直连 (%s)" % detail

    # ---- L2: 强制清空 DNS 再试 ----
    try:
        _reset_dns_via_netsh()
        apply_nic_dns([])
        steps.append("已用 netsh 强制清空网卡 DNS")
    except Exception as e:
        steps.append("L2 失败: %s" % e)
    time.sleep(2)
    ok, detail = net_ok()
    _record_rescue(reason, "L2", steps, ok, detail)
    if ok:
        return True, "L2 强制清空 DNS 后恢复 (%s)" % detail
    return False, ("三层急救均未恢复: %s —— 请检查路由器/运营商线路" % detail
                   + " (" + "; ".join(steps) + ")")


def _record_rescue(reason, level, steps, ok, detail):
    with state_lock:
        state["rescue"] = {
            "ts": time.time(),
            "reason": reason,
            "level": level,
            "steps": steps,
            "ok": bool(ok),
            "detail": detail,
        }
        net_state["last_action"] = ("%s 急救%s: %s" %
                                    (level, "成功" if ok else "未恢复", detail))


def ensure_net_ok(context=""):
    """操作失败后的收尾检查: 确认网络真的可用, 不通就走分级急救。

    启用/停用任何一步失败都可能留下「DNS 接管已写入、隧道却没连上」这类
    半吊子状态 —— 用户看到的是"启用失败", 实际后果是"网也上不了"。
    失败提示和"能上网"是两件事, 这里把后者兜住。
    """
    time.sleep(2)
    ok, detail = net_ok()
    if ok:
        return True
    log("操作后网络不可用(%s), 触发保障..." % (context or detail), logging.WARNING)
    ok2, msg2 = rescue_network(context or detail)
    log("保障结果: " + msg2, logging.INFO if ok2 else logging.ERROR)
    return ok2


def net_guard_loop():
    """网络保障看门狗 —— 与「分流是否启用」无关, 全程在跑。

    分流未启用时也要跑: 用户关了程序、程序崩了、或者残留没清干净, 都可能
    让本机 DNS 挂掉, 而这时没有任何其他线程会去管(自愈线程只在启用后动作,
    DNS 守卫只在智能 DNS 开着时动作)。这里是最后一道网。

    判定用「连续两次失败」(约 40 秒)而不是一次: 单次的解析失败太常见
    (瞬时抖动、DNS 服务器换手), 一次就动手会把正常网络反复拆掉。
    """
    time.sleep(20)          # 启动/重连期间网络在变, 先让它稳定
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(20)
        try:
            if state["running"]:
                continue    # 正在启用/停用/还原, 网络正在变化, 不打扰

            # Proxy 分路: 桥停了但系统代理还指着它 = 所有应用"代理错误"上不了网。
            # 先试着把桥拉起来; 拉不起来就撤掉系统代理, 退回直连。
            if state.get("sysproxy_on") and not port_in_use(
                    int(settings.get("bridge_port", 7890))):
                log("分流桥已停止但系统代理仍指向它, 正在恢复...", logging.WARNING)
                ok_b, msg_b = start_bridge()
                if ok_b:
                    log("分流桥已恢复: " + msg_b)
                else:
                    set_system_proxy(False)
                    with state_lock:
                        state["sysproxy_on"] = False
                    log("分流桥恢复失败, 已撤掉系统代理以保证正常上网: " + msg_b,
                        logging.ERROR)

            ok, detail = net_ok()
            net_state["ok"] = ok
            net_state["detail"] = detail
            net_state["ts"] = time.time()
            if ok:
                if net_state["streak"]:
                    log("网络已恢复正常 (%s)" % detail)
                    with state_lock:
                        state["net_down"] = False
                net_state["streak"] = 0
                continue
            net_state["streak"] += 1
            with state_lock:
                state["net_down"] = True
            if net_state["streak"] < 2:
                log("网络探测失败 1 次 (%s), 下轮复查" % detail, logging.WARNING)
                continue
            if not settings.get("net_guard", True):
                continue    # 用户关掉了自动保障
            if time.time() < net_state.get("cooldown_until", 0):
                continue    # 刚救过一次, 冷却期内不再动
            ok2, msg2 = rescue_network(detail)
            net_state["streak"] = 0
            log("自动保障结果: " + msg2, logging.INFO if ok2 else logging.ERROR)
        except Exception as e:
            log("net guard err: " + str(e), logging.WARNING)


def watchdog_enabled():
    """系统级兜底计划任务是否已注册。缓存 5 分钟, 别每次 /api/status 都跑 schtasks
    (它每 1.5 秒被轮询一次, 而起一个子进程去问计划任务是纯浪费)。"""
    now = time.time()
    if now - _WD_CACHE["ts"] < 300:
        return _WD_CACHE["val"]
    _WD_CACHE["ts"] = now
    if not _IS_WIN:
        _WD_CACHE["val"] = False
        return False
    try:
        r = _run(["schtasks", "/query", "/tn", GUARD_TASK, "/fo", "LIST"],
                 capture_output=True, timeout=20)
        _WD_CACHE["val"] = (r.returncode == 0)
    except Exception:
        _WD_CACHE["val"] = False
    return _WD_CACHE["val"]


_WD_CACHE = {"ts": 0, "val": False}


def register_watchdog(minutes=5):
    """注册系统级兜底任务: 每 N 分钟跑一次 `exe --guard`。

    为什么需要它: 主程序没运行(或刚被硬杀)时, 上面那个 net_guard_loop 根本
    不存在 —— 而恰恰是这时候最容易留下 DNS 残留。计划任务由系统拉起, 不依赖
    我们的进程存活, 是真正的最后一道防线。
    """
    if not _IS_WIN:
        return False, "仅支持 Windows"
    exe = sys.executable if getattr(sys, "frozen", False) else None
    if not exe:
        return False, "源码模式不注册(打包后的 exe 才需要)"
    tr = '"%s" --guard' % exe
    try:
        r = _run(["schtasks", "/create", "/tn", GUARD_TASK, "/tr", tr,
                  "/sc", "minute", "/mo", str(minutes), "/rl", "highest", "/f"],
                 capture_output=True, timeout=40)
        _WD_CACHE["ts"] = 0
        if r.returncode == 0:
            log("已注册系统级网络兜底任务(每 %d 分钟检查一次, 不依赖本程序运行)" % minutes)
            return True, "ok"
        return False, ((r.stderr or r.stdout or b"").decode("utf-8", "ignore").strip()[:200])
    except Exception as e:
        return False, str(e)


def unregister_watchdog():
    if not _IS_WIN:
        return False, "仅支持 Windows"
    try:
        r = _run(["schtasks", "/delete", "/tn", GUARD_TASK, "/f"],
                 capture_output=True, timeout=30)
        _WD_CACHE["ts"] = 0
        return (r.returncode == 0), "ok" if r.returncode == 0 else "未找到该任务"
    except Exception as e:
        return False, str(e)


def run_guard_once():
    """一次性网络兜底(计划任务每 5 分钟调一次, 无界面、不启服务)。

    只做一件事: 上不了网就按分级退让救回来。正常情况一轮解析就返回, 耗时毫秒级。

    正常时故意不写日志: 它每 5 分钟被系统拉起一次, 一天 288 次, 全写进去
    日志里就全是"网络正常", 真正有用的异常行反而被淹没了。
    """
    try:
        ok, detail = net_ok()
        if ok:
            return 0
        log("[guard] 检测到网络不可用 (%s), 开始急救" % detail, logging.WARNING)
        ok2, msg2 = rescue_network("计划任务巡检")
        log("[guard] 急救结果: " + msg2, logging.INFO if ok2 else logging.ERROR)
        return 0 if ok2 else 1
    except Exception as e:
        log("[guard] 巡检异常: " + str(e), logging.WARNING)
        return 1


# ====================== 出口可视化数据 ======================
_LOCAL_IP_CACHE = {"ts": 0.0, "val": ""}


def _cached_local_ip(ttl=300):
    """本机内网 IP。解析一次管 5 分钟 —— gethostbyname 虽然大概率走 hosts
    文件, 但极端情况下会走 DNS 查询, 可视化接口不该冒这个阻塞风险。"""
    now = time.time()
    if now - _LOCAL_IP_CACHE["ts"] < ttl:
        return _LOCAL_IP_CACHE["val"]
    ip = ""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = ""
    _LOCAL_IP_CACHE["ts"] = now
    _LOCAL_IP_CACHE["val"] = ip
    return ip


def topology_snapshot():
    """出口拓扑快照: 本机 -> 分流引擎 -> 国内直连 / WARP 隧道。

    **只读内存里的缓存**, 不新起任何子进程、不发任何网络请求 —— 面板上这个
    组件是纯展示, 不能因为它拖慢 /api/status 或给 warp-cli 添负担
    (分流性能优先)。数据新鲜度由各缓存自己的 TTL 决定(10-30 秒)。
    """
    with state_lock:
        st = dict(state)
    with metrics_lock:
        mt = dict(metrics)
    fb = _cached_fallback_server().replace("\n", " ").strip()
    if fb.lower().startswith("default fallbacks:"):
        fb = fb.split(":", 1)[1].strip()
    ds = dns_stats
    bs = bridge_stats
    try:
        local_ip = _cached_local_ip()
    except Exception:
        local_ip = ""
    total_dns = (ds.get("cn", 0) or 0) + (ds.get("warp", 0) or 0)
    return {
        "ts": time.time(),
        "local": {
            "ip": local_ip,
            "gateway": get_gateway(),
            "nic_dns": read_nic_dns(),
            "dns_proxy": bool(st.get("dns_proxy")),
        },
        "engine": {
            "route_mode": settings.get("route_mode", "tun"),
            "route_active": st.get("route_active"),
            "rules": _cached_cli_count(),
            "dns_suffixes": len(DNS_FALLBACK_SUFFIXES) if settings.get("smart_dns", True) else 0,
            "fallback": fb,
            "mode": _cached_mode(),
        },
        "direct": {
            "label": "国内直连",
            "latency": mt.get("latency_cn"),
            "queries": ds.get("cn", 0) or 0,
        },
        "warp": {
            "label": "WARP 隧道",
            "connected": bool(st.get("enabled")),
            "egress_ip": mt.get("egress_ip", ""),
            "colo": get_egress_colo(),
            "loc": get_egress_loc(),
            "latency": mt.get("latency_intl"),
            "queries": ds.get("warp", 0) or 0,
            "socks": "127.0.0.1:%d" % int(settings.get("proxy_port", 40000)),
            "bridge": ("127.0.0.1:%d" % int(settings.get("bridge_port", 7890))
                       if st.get("bridge_up") else ""),
        },
        "traffic": {
            "dl_mbps": mt.get("dl_speed_mbps"),
            "uptime_s": mt.get("uptime_s", 0) or 0,
            "bridge_direct": bs.get("direct", 0) or 0,
            "bridge_proxy": bs.get("proxy", 0) or 0,
            "bridge_errors": bs.get("errors", 0) or 0,
            "dns_errors": ds.get("errors", 0) or 0,
            "dns_total": total_dns,
            "net_ok": bool(net_state.get("ok")),
            "net_detail": net_state.get("detail", ""),
        },
    }


# ====================== 核心操作 ======================
def enable_split():
    """按当前分路模式启用。route_mode=proxy 时走 Proxy 分路(不开 TUN)。"""
    if settings.get("route_mode", "tun") == "proxy":
        return enable_proxy_route()
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

        all_ranges = read_active_ranges()
        if MAX_RANGES > 0:
            all_ranges = all_ranges[:MAX_RANGES]
        if not all_ranges:
            raise RuntimeError("规则列表为空，请点击『更新中国IP列表』或导入规则")

        # ---- 顺序是关键: 先把排除规则全部写好, 最后一步才连上 WARP ----
        # 旧流程是「先 connect 再逐条注入」, 5440 条要 8 分钟以上; 这期间隧道
        # 已建立但排除列表几乎是空的, 国内流量全被灌进隧道 -> 用户看到的就是
        # 「一注入就断网」。现在把注入放在断开状态做, 此时网络是纯直连,
        # 用户在启用过程中完全无感; 规则齐了再连接, 一步到位。
        warp(["disconnect"], timeout=20)
        time.sleep(1)

        ok, out = warp(["mode", "warp"], timeout=20)
        if not ok:
            log("设置 mode warp 返回: " + out, logging.WARNING)
        else:
            log("mode warp 设置完成")

        with state_lock:
            state["progress"] = {"total": 0, "done": 0, "phase": "正在写入分流规则..."}
        ok_sync, msg = sync_excludes(all_ranges, prune=False, phase_cb=_set_phase)
        if not ok_sync:
            raise RuntimeError("分流规则写入失败: " + msg)
        log("规则就绪 -> " + msg)

        # ---- 在连接之前把 DNS 分流装好 ----
        # 顺序有讲究: `dns fallback add` 属于「设置变更」, WARP 收到会把隧道
        # 以 "Settings Changed" 为由断掉(实测确认)。所以趁现在还断着把后缀
        # 和网卡 DNS 都写好, 再 connect —— 一次连上即可, 不用连了又断再连。
        # 实测: 断开状态下 38 条后缀照样能写进去, 连上后 3 秒 fallback 服务器
        # 就变成 127.0.0.1。
        if settings.get("smart_dns", True):
            with state_lock:
                state["progress"] = {"total": 0, "done": 0,
                                     "phase": "正在接管 DNS 解析..."}
            ok_dns, msg_dns = setup_smart_dns(wait_ready=False)
            with state_lock:
                state["dns_proxy"] = ok_dns
            if ok_dns:
                log("智能 DNS 已装配: " + msg_dns)
            else:
                log("智能 DNS 装配失败(保持 WARP 原 DNS): " + msg_dns,
                    logging.WARNING)

        if op_stop.is_set():
            raise RuntimeError("用户取消了操作")

        connected, last_out = connect_warp(update_phase=True)
        if not connected:
            raise RuntimeError(
                "WARP 未能连接。最后状态: " + last_out[:160] +
                " | 常见原因: 到 Cloudflare WARP 端点(162.159.x.x:443)的握手被网络阻断, 或 IPv6 探测(happy eyeballs)卡住。"
                "建议: 多试 1-2 次; 或在『网络适配器 -> CloudflareWARP -> 属性』取消 IPv6 勾选后重试; 确认 WARP 账号可用。"
            )
        log("WARP 已连接, 分流规则已生效")
        total = len(all_ranges)

        with state_lock:
            state["enabled"] = True
            state["armed"] = True            # 本次会话已确认, 允许后续自动重连
            state["resume_pending"] = False
            state["route_active"] = "tun"
            state["auto_restored"] = False   # 手动重新启用后清除自愈还原提示
            state["guard_paused"] = False    # 用户确认网络后手动恢复, 清掉保障暂停标记
            state["progress"] = {"total": total, "done": total, "phase": "分流已启用"}
        save_state()
        log(f"分流启用完成: {total} 条规则已就位, daemon 现有排除 "
            f"{len(get_cli_excludes())} 条")

        # 连上之后只需**确认** DNS 分流真正生效(装配已在连接前做完)。
        # fallback 服务器是 WARP 连着时才有的概念, 所以这一步必须在 connect 之后;
        # 通常 3 秒内就会出现 127.0.0.1, 等不到也没关系 —— dns_guard_loop 会
        # 每 30 秒继续修, 这里不因此判失败(否则会把刚建好的隧道又拆掉)。
        if settings.get("smart_dns", True) and state.get("dns_proxy"):
            for _ in range(8):
                time.sleep(3)
                if DNS_LISTEN_ADDR in dns_fallback_server():
                    log("智能 DNS 已生效: 国内域名走国内 DNS 拿国内 CDN 节点, "
                        "境外域名走 " + DNS_WARP + " (经隧道, 无污染)")
                    break
            else:
                log("智能 DNS 尚未被 WARP 确认为 fallback 服务器, "
                    "守卫线程会继续修复", logging.WARNING)
    except Exception as e:
        log("启用失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
        try:
            # 只断开, 不清规则 —— 规则留着, 用户重试时可以直接秒级启用;
            # (旧代码在这里做 tunnel ip reset, 导致每次失败重试都要重注 8 分钟)
            warp(["disconnect"], timeout=20)
        except Exception:
            pass
        with state_lock:
            state["enabled"] = False
            state["dns_proxy"] = False
        if settings.get("smart_dns", True):
            teardown_smart_dns()
        # 启用失败本身不是最坏结果, "失败之后还上不了网"才是。收尾确认一次。
        threading.Thread(target=ensure_net_ok,
                         args=("启用分流失败",), daemon=True).start()
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


def disable_split():
    """停用分流: 断开隧道, 网络恢复纯直连。

    当前是 Proxy 分路时交给 disable_proxy_route() —— 它还得多做两件事:
    停掉本地分流桥、还原可能写过Windows 系统代理。

    刻意不再做 `tunnel ip reset`:
      - 排除规则只在隧道建立时才起作用, 断开后它们完全不影响直连网络;
      - 保留规则后「再次启用」可以秒级完成, 而不是重新注入 8 分钟;
      - 这正是「每次重启都要重新注入、启动特别慢」的根因之一。
    想彻底清空规则请用「一键还原」(它会 reset)。
    """
    if state.get("route_active") == "proxy" or state.get("bridge_up"):
        return disable_proxy_route()
    with state_lock:
        if state["running"]:
            return
        state["running"] = True
        state["action"] = "disable"
        state["progress"] = {"total": 0, "done": 0, "phase": "正在关闭分流..."}
    log("开始停用分流...")
    try:
        # 先撤 DNS 接管再断开, 顺序反了会有一小段「查询转给本地但代理已停」
        teardown_smart_dns()
        with state_lock:
            state["dns_proxy"] = False
        warp(["disconnect"], timeout=20)
        with state_lock:
            state["enabled"] = False
            state["armed"] = False
            state["route_active"] = None
            state["progress"] = {"total": 0, "done": 0, "phase": "已停用，网络恢复正常"}
        save_state()
        log("分流已停用，网络恢复直连 (排除规则已保留, 再次启用可秒级完成)")
        # 停用的目的就是回到干净能上网的状态 —— 异步确认一次真的通了。
        # 注意 ensure_net_ok 只会继续退让(还原 DNS / 断开 WARP), 绝不会把
        # 分流再打开, 所以这里不用担心"关了又自己开"。
        threading.Thread(target=ensure_net_ok,
                         args=("停用分流后",), daemon=True).start()
    except Exception as e:
        log("停用失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
        # 停用失败可能停在「隧道还连着、DNS 还被接管」的中间态, 兜一次
        threading.Thread(target=ensure_net_ok,
                         args=("停用分流失败",), daemon=True).start()
    finally:
        with state_lock:
            state["running"] = False
            state["action"] = None


def switch_route(new_mode):
    """在 TUN 全局 / Proxy 分路之间切换。

    已启用时先按旧模式完整停用(Proxy 要停桥+撤系统代理), 再按新模式启用,
    避免留下「模式是 proxy 但 TUN 规则还在」这类半吊子状态。
    """
    new_mode = "proxy" if new_mode == "proxy" else "tun"
    old = settings.get("route_mode", "tun")
    if new_mode == old:
        return
    log("切换分路: %s -> %s" % (old, new_mode))
    settings["route_mode"] = new_mode
    save_settings()
    with state_lock:
        was_on = state["enabled"] and state.get("armed")
    if was_on:
        disable_split()
        enable_split()


def restore():
    """一键还原 (紧急): 终止正在进行的操作, 强制断开, 清空自定义排除, 回到干净状态。

    Proxy 分路下额外还原两件事: 停掉本地分流桥、撤掉写过的 Windows 系统代理,
    并把 warp-cli 的模式切回 warp —— 否则下次启用 TUN 路线时模式还停在 proxy。
    """
    log("执行一键还原...")
    op_stop.set()
    for _ in range(100):
        with state_lock:
            if not state["running"]:
                break
        time.sleep(0.2)
    op_stop.clear()
    if state.get("sysproxy_on"):
        try:
            set_system_proxy(False)
        except Exception:
            pass
    stop_bridge()
    teardown_smart_dns()       # 停代理 + 撤后缀 + 还原网卡 DNS
    try:
        warp(["disconnect"], timeout=20)
        warp(["mode", "warp"], timeout=20)
    except Exception:
        pass
    # 优先用配置直写把 CLI 排除清空 —— 秒级完成, 且保留 daemon 自带的默认
    # 排除(Apple 服务/组播等); 直写不可用时回退到官方 reset。
    ok, msg = write_excludes_fast([])
    if not ok:
        log("配置直写清空失败, 回退 tunnel ip reset: " + msg, logging.WARNING)
        try:
            warp(["tunnel", "ip", "reset"], timeout=30)
        except Exception:
            pass
    with state_lock:
        state["enabled"] = False
        state["armed"] = False
        state["resume_pending"] = False
        state["error"] = None
        state["reconnecting"] = False
        state["dns_proxy"] = False
        state["route_active"] = None
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
        read_active_ranges(force=True)   # 文件刚重写, 强制刷新缓存
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
        refresh_list_data()
        ok, msg = sync_excludes(read_active_ranges(), prune=True, phase_cb=_set_phase)
        log("后台自动更新规则: " + msg, logging.INFO if ok else logging.WARNING)
    except Exception as e:
        log("后台自动更新规则失败: " + str(e), logging.WARNING)


def _set_phase(text):
    with state_lock:
        state["progress"]["phase"] = text


def sync_excludes(desired, prune=False, phase_cb=None, quiet=False):
    """把 daemon 的 CLI 排除列表同步成 desired。返回 (ok, 说明文字)。

    - 增量: 只补差的、只删多的, 已经存在的规则一条都不重复注入。
    - 大数据量走"配置直写"(停服务改写 -> 起服务, 秒级); 小增量走逐条 CLI。
    - 完成后回查 daemon 校验, 不会"以为成功了其实没生效"。

    prune=False 时只增不删 (用于启用分流: 保留多余规则无害, 且能避免
    每次启用都产生写放大)。
    """
    want = list(dict.fromkeys(desired))
    current = get_cli_excludes()
    want_set = set(want)

    to_add = [c for c in want if c not in current]
    to_del = [c for c in current if c not in want_set] if prune else []

    if not to_add and not to_del:
        return True, f"规则已是最新(daemon 现有 {len(current)} 条), 无需注入"

    target = want if prune else list(dict.fromkeys(list(current) + want))

    mode = "skip"
    if len(to_add) >= FAST_WRITE_MIN or len(to_del) >= FAST_WRITE_MIN:
        if phase_cb:
            phase_cb(f"正在写入 {len(target)} 条规则...")
        ok, msg = write_excludes_fast(target, phase_cb=phase_cb)
        if ok:
            mode = "fast"
        else:
            log(f"配置直写不可用, 回退逐条注入: {msg}", logging.WARNING)
            mode = "cli"
    else:
        mode = "cli"

    if mode == "cli":
        fails = []

        def add_one(c):
            if op_stop.is_set():
                return
            is_reserved = c in _ALWAYS_DIRECT_SET
            for _ in range(2):
                ok1, out = warp(["tunnel", "ip", "add-range", c], timeout=20)
                if ok1 or "already" in out.lower():
                    return
                low = out.lower()
                if any(k in low for k in ["not allowed", "not permitted", "policy",
                                          "organization", "managed by", "team", "locked"]):
                    if is_reserved:
                        return
                    with state_lock:
                        state["zerotrust_locked"] = True
                    log("检测到 Zero Trust 策略锁定 split-tunnel: " + out[:120], logging.ERROR)
                    return
                time.sleep(0.3)
            fails.append(c)

        if to_add:
            if phase_cb:
                phase_cb(f"注入 {len(to_add)} 条新增规则...")
            with state_lock:
                state["progress"] = {"total": len(to_add), "done": 0,
                                     "phase": f"注入 {len(to_add)} 条新增规则..."}
            done = [0]

            def add_counted(c):
                add_one(c)
                done[0] += 1
                if done[0] % 50 == 0 or done[0] == len(to_add):
                    with state_lock:
                        state["progress"]["done"] = done[0]

            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                list(ex.map(add_counted, to_add))

        if to_del:
            if phase_cb:
                phase_cb(f"移除 {len(to_del)} 条失效规则...")
            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                list(ex.map(lambda c: warp(["tunnel", "ip", "remove-range", c], timeout=15),
                            to_del))

    # ---- 回查校验, 不轻信返回码 ----
    actual = get_cli_excludes()
    missing = [c for c in want if c not in actual]
    if missing:
        ratio = len(missing) / max(len(want), 1)
        if ratio > 0.02:
            return False, (f"校验失败: {len(missing)}/{len(want)} 条规则未生效"
                           f"({ratio:.1%})。首个缺失: {missing[0]}。"
                           "可能原因: Zero Trust 策略限制 / daemon 异常 / 规则数超限。")
        log(f"校验: {len(missing)} 条未生效(占比 {ratio:.1%}, 已放行)", logging.WARNING)

    parts = []
    if to_add:
        parts.append(f"新增 {len(to_add)}")
    if to_del:
        parts.append(f"移除 {len(to_del)}")
    how = "配置直写" if mode == "fast" else ("逐条注入" if mode == "cli" else "无需写入")
    summary = "/".join(parts) or "无变化"
    return True, f"{how}: {summary}, daemon 现有 {len(actual)} 条"


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
            if not state["enabled"] or state["running"]:
                continue
            # 冷启动保护 (解决「我都退出程序了, 它怎么又自己启动了」):
            # state.enabled 是从 state.json 读出来的「上次会话的状态」, 新进程
            # 刚起来时它天然为 True。若不加区分就自动重连+注入, 用户会觉得
            # 程序在背着他自己动网络。只有本次会话确认过状态(armed)才允许
            # 自动重连; armed 在「用户手动启用成功」或「启动校对时发现 daemon
            # 确实已在连接状态」时才置位。
            if not state.get("armed"):
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
                # Proxy 分路没有 TUN, excluded_ips 对它毫无意义 —— 别白跑。
                if state.get("route_active") == "proxy" or \
                        settings.get("route_mode", "tun") == "proxy":
                    log("WARP 已自动重连 (Proxy 分路无需同步排除规则)")
                    continue
                # 只补差集。旧代码在这里对 5440 条做串行 add-range, 一旦触发
                # 就是十几分钟, 而且是在隧道已经连上的状态下做 —— 用户直接断网。
                try:
                    ok2, msg = sync_excludes(read_active_ranges(), prune=False,
                                             phase_cb=_set_phase)
                    log("WARP 已自动重连; 规则同步: " + msg,
                        logging.INFO if ok2 else logging.WARNING)
                except Exception as e:
                    log("重连后同步规则失败: " + str(e), logging.WARNING)
            else:
                log("自动重连失败: " + last[:120], logging.ERROR)
        except Exception as e:
            log("reconnect loop err: " + str(e), logging.WARNING)


def cleanup_dns_residue_on_startup():
    """清理「上次进程被硬杀」留下的智能 DNS 残留。

    atexit 挡不住 taskkill -f / 崩溃 / 断电。残留的完整链条(实测踩过):
      1. 智能 DNS 接管时把网卡静态 DNS 写成 127.0.0.1;
      2. 进程被硬杀, 网卡 DNS 和 daemon 学到的 fallback(127.0.0.1:53)
         都来不及还原;
      3. WARP 仍连着(Always On), 本机 53 端口却已无人监听 -> daemon 把
         所有 DNS 查询转发到死地址, 实测 182 条查询 100% Other Error;
      4. 浏览器靠缓存苟活(页面能开、上传能跑), 但任何新建连接都要新解析
         —— 表现为测速网站「下载 0.00 Mbps」, 且越用越卡。

    注意 WARP 连着时网卡显示值永远是 127.0.2.2/.3(daemon 自己覆写的),
    所以判定要看两处: 注册表静态 NameServer, 以及 daemon 的 fallback。
    用户若自己在 127.0.0.1:53 跑了别的 DNS(端口在听), fallback 那条
    判定不成立, 不会误伤。
    """
    if not _IS_WIN:
        return
    try:
        stale_nic = _static_dns_left()
        stale_fb = False
        if not stale_nic:
            fb = dns_fallback_server()
            stale_fb = "127.0.0.1" in fb and not port_in_use(53, "127.0.0.1")
        if not (stale_nic or stale_fb):
            return
        if _DNS_SERVER is not None or state.get("dns_proxy"):
            return  # 智能 DNS 已由本进程接管, 不是残留
        log("检测到上次异常退出留下的 DNS 残留(网卡静态 DNS 或 WARP fallback "
            "仍指向 127.0.0.1:53), 正在还原...", logging.WARNING)
        apply_nic_dns([])
        ok, out = warp(["status"], timeout=15)
        if "Connected" in (out or ""):
            # daemon 的 fallback 只在 connect 时重新从网卡学习, 必须重连一次
            warp(["disconnect"], timeout=15)
            time.sleep(1.5)
            connect_warp(max_attempts=3, update_phase=False)
            log("已还原网卡 DNS 并重连 WARP (fallback 重新学习为路由器/DHCP)")
        else:
            log("已还原网卡 DNS (WARP 当前未连接, 下次连接会自动学习新 fallback)")
    except Exception as e:
        log("DNS 残留清理失败: " + str(e), logging.WARNING)


def reconcile_state_on_startup():
    """启动后校对「上次留下的 enabled 标志」与「daemon 的真实状态」。

    这是「退出程序后它自己又启动」的另一半答案: 旧版把 state.json 里的
    enabled=true 当成当前事实, 于是新进程一起来就自动重连 WARP、自动注入
    规则, 用户看起来就是「我没点它, 它自己动了」。

    新的判定:
      - daemon 确实处于连接状态 -> 说明分流本来就在生效, 认定为已启用;
      - daemon 未连接 -> 不擅自动手。默认只提示, 由用户点开关恢复
        (规则已留在 daemon 里, 恢复是秒级的); 只有用户显式打开
        『启动时自动恢复』才会自动执行。
    """
    time.sleep(6)
    # 先清残留再谈恢复: 硬杀留下的 127.0.0.1 残留不清掉, 后面所有
    # 判定与自愈都会在一个「DNS 全挂」的地基上空转。
    cleanup_dns_residue_on_startup()
    try:
        ok, out = warp(["status"], timeout=15)
        connected = "Connected" in out
        n = len(get_cli_excludes())
        if not state["enabled"]:
            return
        if connected:
            with state_lock:
                state["armed"] = True
                state["route_active"] = settings.get("route_mode", "tun")
            # Proxy 分路: 进程重启后分流桥没了, 必须重新拉起来, 否则
            # "已启用" 但 7890 没人监听, 配了代理的应用全部超时。
            if state["route_active"] == "proxy" and not state["bridge_up"]:
                ok2, msg = start_bridge()
                log("Proxy 分路: 重启后自动恢复分流桥 -> " + msg,
                    logging.INFO if ok2 else logging.ERROR)
            # TUN 分路: 进程重启后本地 DNS 代理没了, 但网卡 DNS 还指着
            # 127.0.0.1 —— 这个空档期本机是「DNS 全挂」状态, 必须立刻补上。
            if state["route_active"] == "tun" and settings.get("smart_dns", True):
                ok3, msg3 = setup_smart_dns()
                with state_lock:
                    state["dns_proxy"] = ok3
                if ok3:
                    log("TUN 分路: 重启后自动恢复智能 DNS (" + msg3 + ")")
                else:
                    # 恢复失败必须把网卡 DNS 还原干净, 否则会留下「指向
                    # 127.0.0.1 但无监听」的断网隐患
                    log("TUN 分路: 智能 DNS 恢复失败(" + msg3 +
                        "), 已整体还原", logging.WARNING)
                    teardown_smart_dns()
            log(f"已确认上次的分流仍在生效 (WARP 已连接, daemon 排除规则 {n} 条)")
            return
        if settings.get("auto_resume", False):
            with state_lock:
                state["armed"] = True
            log("按『启动时自动恢复』设置, 正在恢复上次的分流状态...")
            threading.Thread(target=enable_split, daemon=True).start()
            return
        with state_lock:
            state["enabled"] = False
            state["resume_pending"] = True
            state["progress"] = {"total": 0, "done": 0,
                                 "phase": "上次的分流未自动恢复, 点开关即可秒级恢复"}
        save_state()
        log(f"上次会话启用了分流, 但当前 WARP 未连接 —— 已暂停自动恢复, "
            f"等你手动确认 (daemon 中已保留 {n} 条规则, 恢复约 1 秒)")
    except Exception as e:
        log("启动状态校对失败: " + str(e), logging.WARNING)


# ====================== 可用性优先: 自动自愈 ======================
# 借鉴 net-warp「直连失败自动回退隧道」的取舍哲学: 分流判定出错时,
# 宁可放弃加速也不能断网。这里做成三级:
#   1) 采样连续失败 -> 自动重连 WARP 并重新注入规则
#   2) 自愈反复无效 -> 自动还原为直连(保可用, 放弃加速)
#   3) 每一步都写日志, 控制台可见, 不做静默操作
heal = {
    "fail_streak": 0,      # 连续采样失败次数
    "attempts": 0,         # 本轮已自愈次数
    "last_ts": 0.0,        # 上次自愈时间(冷却用)
    "last_action": "",     # 最近一次自愈结果(给控制台展示)
    "active": False,       # 正在自愈中
}
heal_lock = threading.Lock()
HEAL_FAIL_THRESHOLD = int(os.environ.get("WARP_SPLIT_HEAL_FAILS", "4"))  # 约 12 秒
HEAL_COOLDOWN = 90        # 两次自愈之间的最小间隔(秒)
HEAL_MAX_ATTEMPTS = 3     # 连续自愈超过该次数仍无效 -> 自动还原


def reconnect_and_reinject():
    """重连 WARP 并同步分流规则(只补差集)。成功返回 True。"""
    try:
        connected, last = connect_warp(max_attempts=3, update_phase=False)
        if not connected:
            log("自愈重连失败: " + last[:140], logging.WARNING)
            return False
        ranges = read_active_ranges()
        if MAX_RANGES > 0:
            ranges = ranges[:MAX_RANGES]
        if not ranges:
            return True
        ok, msg = sync_excludes(ranges, prune=False, phase_cb=_set_phase)
        log("自愈规则同步: " + msg, logging.INFO if ok else logging.WARNING)
        return ok
    except Exception as e:
        log("自愈重连异常: " + str(e), logging.WARNING)
        return False


def self_heal_loop():
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(3)
        try:
            if not settings.get("auto_heal", True):
                continue
            # Proxy 分路下系统流量本就全部直连, "国际流量没走隧道" 是设计如此
            # 而非故障 —— 自愈判定会把它误判成失效并触发还原。这条路由
            # reconnect_loop 保活就够, 不参与自愈。
            if state.get("route_active") == "proxy":
                with heal_lock:
                    heal["fail_streak"] = 0
                    heal["attempts"] = 0
                continue
            if not state["enabled"] or state["running"] or state["reconnecting"]:
                with heal_lock:
                    heal["fail_streak"] = 0
                    heal["attempts"] = 0
                continue
            with heal_lock:
                streak = heal["fail_streak"]
                if streak < HEAL_FAIL_THRESHOLD:
                    continue
                now = time.time()
                if now - heal["last_ts"] < HEAL_COOLDOWN:
                    continue
                heal["last_ts"] = now
                heal["active"] = True
                heal["attempts"] += 1
                attempts = heal["attempts"]
                heal["fail_streak"] = 0

            log(f"连续 {streak} 次采样失败, 触发自动自愈(第 {attempts} 次)...", logging.WARNING)

            if attempts > HEAL_MAX_ATTEMPTS:
                log("自愈反复无效, 判定分流当前不可用 —— 自动还原为直连以保证网络可用",
                    logging.ERROR)
                with heal_lock:
                    heal["last_action"] = "已自动还原为直连"
                    heal["attempts"] = 0
                    heal["active"] = False
                with state_lock:
                    state["auto_restored"] = True
                restore()
                continue

            ok = reconnect_and_reinject()
            with heal_lock:
                heal["last_action"] = "重连并重新注入成功" if ok else "自愈尝试失败"
                if ok:
                    heal["attempts"] = 0
                heal["active"] = False
            log("自动自愈" + ("成功, 分流已恢复" if ok else "失败, 将在冷却后重试"),
                logging.INFO if ok else logging.WARNING)
        except Exception as e:
            log("自愈线程异常: " + str(e), logging.WARNING)
            with heal_lock:
                heal["active"] = False


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
        try:
            ip = get_egress_ip(ttl=0)   # 本循环自行控制刷新节奏
            with metrics_lock:
                metrics["egress_ip"] = ip
        except Exception:
            pass
        EXIT_EVENT.wait(30)


def metrics_loop():
    intl_url = "https://www.cloudflare.com/cdn-cgi/trace"
    while not EXIT_EVENT.is_set():
        EXIT_EVENT.wait(3)
        try:
            lat_cn = probe_latency(CN_PROBES)
            lat_intl = probe_latency(INTL_PROBES, http_fallback=intl_url)
            # 可用性监测: 分流启用时国内外探测同时全部失败 => 疑似隧道/路由异常,
            # 累加失败计数交给 self_heal_loop 处理(仅计数, 不在此阻塞)。
            with heal_lock:
                if state["enabled"] and lat_cn is None and lat_intl is None:
                    heal["fail_streak"] += 1
                else:
                    heal["fail_streak"] = 0
            with metrics_lock:
                metrics["latency_cn"] = lat_cn
                metrics["latency_intl"] = lat_intl
                # 在线时长: 只在 metrics_loop 里更新过一次就忘了 —— 之前
                # metrics["uptime_s"] 永远是 0, 面板上「在线时长」一直显示
                # 「—」。这里按当前 WARP 连接状态实时推算。
                if metrics["connected_since"]:
                    metrics["uptime_s"] = int(time.time() - metrics["connected_since"])
                else:
                    metrics["uptime_s"] = 0
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
# /api/status 每 1.5 秒被前端轮询一次, 而每个 warp-cli 调用都要新起一个进程。
# 其中 `tunnel ip list` 会把 5440 条规则全打出来(最慢), `settings` 次之。
# 这两项变化频率极低, 用短 TTL 缓存掉能显著降低轮询开销。
_SLOW_CACHE = {"mode": ("unknown", 0), "cli_count": (0, 0), "ts": 0}


def _cached_mode(ttl=10):
    ts = _SLOW_CACHE["mode"][1]
    if time.time() - ts < ttl:
        return _SLOW_CACHE["mode"][0]
    mode = "unknown"
    try:
        ok2, setout = warp(["settings"], timeout=10)
        for ln in setout.splitlines():
            if "Mode:" in ln:
                m = ln.split("Mode:")[-1].strip()
                if m:
                    mode = m
                    break
    except Exception:
        pass
    _SLOW_CACHE["mode"] = (mode, time.time())
    return mode


def _cached_cli_count(ttl=15):
    ts = _SLOW_CACHE["cli_count"][1]
    if time.time() - ts < ttl:
        return _SLOW_CACHE["cli_count"][0]
    n = 0
    try:
        ok3, listout = warp(["tunnel", "ip", "list"], timeout=15)
        n = listout.count("(CLI exclude)")
    except Exception:
        pass
    _SLOW_CACHE["cli_count"] = (n, time.time())
    return n


def get_status():
    ok, out = warp(["status"], timeout=10)
    connected = "Connected" in out
    mode = _cached_mode()
    cli_count = _cached_cli_count()
    egress = get_egress_ip()
    # 这三个调用可能起 PowerShell / schtasks / warp-cli 子进程(缓存过期时),
    # 必须放在 state_lock 之外 —— 在锁内卡 20 秒会冻结所有守护线程和
    # /api/status 轮询(真实事故: Get-NetRoute 挂死把面板打成全「—」)。
    guard_task = watchdog_enabled() if _IS_WIN else False
    nic_dns = read_nic_dns() if _IS_WIN else []
    dns_fallback = _cached_fallback_server()
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
            "reserved_total": len(ALWAYS_DIRECT),
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
            "auto_heal": settings.get("auto_heal", True),
            "auto_resume": settings.get("auto_resume", False),
            "resume_pending": state.get("resume_pending", False),
            "fast_write": os.path.exists(warp_conf_path()),
            "heal": dict(heal),
            "auto_restored": state.get("auto_restored", False),
            "auto_update": settings.get("auto_update", False),
            "metrics_speed": settings.get("metrics_speed", True),
            "tray": settings.get("tray", True),
            "theme": settings.get("theme", "dark"),
            "active_lists": list(settings.get("active_lists", ["china_cidr.txt"])),
            "route_mode": settings.get("route_mode", "tun"),
            "route_active": state.get("route_active"),
            "bridge_up": state.get("bridge_up", False),
            # 面板资源版本: 前端轮询时比对, 发现磁盘上的面板比当前打开的
            # 页面新(换了 exe / 面板自动更新过)就提示刷新, 解决"重启了
            # 但浏览器标签页不刷新, 看着像没更新"的体感问题。
            "panel_ver": panel_version(),
            "bridge_port": int(settings.get("bridge_port", 7890)),
            "proxy_port": int(settings.get("proxy_port", 40000)),
            "system_proxy": settings.get("system_proxy", False),
            "sysproxy_on": state.get("sysproxy_on", False),
            "smart_dns": settings.get("smart_dns", True),
            "dns_proxy": state.get("dns_proxy", False),
            "dns_stats": dict(dns_stats),
            "net_ok": net_state["ok"],
            "net_detail": net_state["detail"],
            "net_down": state.get("net_down", False),
            "rescue": state.get("rescue"),
            "net_guard": settings.get("net_guard", True),
            "guard_paused": state.get("guard_paused", False),
            "guard_task": guard_task,
            "nic_dns": nic_dns,
            "dns_fallback": dns_fallback,
            "bridge_stats": dict(bridge_stats),
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
    MSG_OPEN, MSG_ENABLE, MSG_DISABLE, MSG_FIX, MSG_RESCUE, MSG_EXIT = 1, 2, 3, 4, 5, 6
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
            ok = webbrowser.open(console_url())
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
        user32.AppendMenuW(menu, MF_STRING, self.MSG_RESCUE, "网络急救")
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
        elif cmd == self.MSG_RESCUE:
            def _r():
                ok, msg = rescue_network("托盘菜单手动触发", force=True)
                log("网络急救: " + msg, logging.INFO if ok else logging.ERROR)
            threading.Thread(target=_r, daemon=True).start()
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
        elif p == "/api/topology":
            # 出口拓扑快照: 纯读缓存, 零子进程零请求, 面板可视化用。
            # 注意不要在这里调任何 warp-cli —— 那是 /api/status 的职责。
            try:
                self._json(topology_snapshot())
            except Exception as e:
                self._json({"error": str(e)})
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
        elif p == "/api/rescue":
            # 手动「网络急救」。放后台线程: 分级退让最多要几十秒。
            def _rescue():
                ok, msg = rescue_network("用户手动触发", force=True)
                log("手动网络急救: " + msg, logging.INFO if ok else logging.ERROR)
            threading.Thread(target=_rescue, daemon=True).start()
            self._json({"ok": True, "msg": "已开始网络急救"})
        elif p == "/api/guard-task":
            on = bool(payload.get("on", True))
            settings["net_watchdog"] = on
            save_settings()
            ok, out = register_watchdog(5) if on else unregister_watchdog()
            self._json({"ok": ok, "msg": out})
        elif p == "/api/audit":
            # 一键网络体检(只读): 污染检测 + 出口归属 + 链路质量 + 分流链路。
            # 全程约 5-12s(tracert/DoH/原始DNS探测), 同步返回(ThreadingHTTPServer
            # 每请求独立线程, 不阻塞面板轮询); 结果缓存 30s 防连点重复探测。
            try:
                now = time.time()
                with audit_lock:
                    if audit_cache.get("data") and now - audit_cache.get("ts", 0) < 30:
                        self._json(audit_cache["data"])
                        return
                data = network_audit()
                with audit_lock:
                    audit_cache["data"] = data
                    audit_cache["ts"] = now
                self._json(data)
            except Exception as e:
                self._json({"verdict": "ERROR", "msg": str(e),
                            "groups": [], "score": 0})
        elif p == "/api/refresh":
            threading.Thread(target=refresh_list, daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/fix_ipv6":
            ok, out = fix_ipv6()
            self._json({"ok": ok, "msg": out})
        elif p == "/api/settings":
            for k in ("theme", "auto_reconnect", "auto_heal", "auto_update",
                      "auto_resume", "metrics_speed", "tray",
                      "proxy_port", "bridge_port", "system_proxy",
                      "smart_dns", "net_guard"):
                if k in payload:
                    settings[k] = payload[k]
            save_settings()
            # 端口变了要重启分流桥才生效
            if state.get("bridge_up") and ("bridge_port" in payload or "proxy_port" in payload):
                threading.Thread(target=start_bridge, daemon=True).start()
            # 智能 DNS 开关即时生效(仅在 TUN 分流已启用时有意义)
            if "smart_dns" in payload:
                # 放后台线程: 装配/拆卸会触发 WARP 断线并需要重连, 不能卡住请求
                threading.Thread(target=toggle_smart_dns,
                                 args=(bool(payload["smart_dns"]),),
                                 daemon=True).start()
            self._json({"ok": True, "settings": settings})
        elif p == "/api/route":
            mode = payload.get("mode", "tun")
            threading.Thread(target=switch_route, args=(mode,), daemon=True).start()
            self._json({"ok": True, "msg": "正在切换到 " + mode})
        elif p == "/api/system-proxy":
            on = bool(payload.get("on", False))
            settings["system_proxy"] = on
            save_settings()
            if state.get("route_active") == "proxy" or state.get("bridge_up"):
                ok = set_system_proxy(on)
            else:
                ok = True   # 分路没起, 只记偏好; 下次启用 proxy 时自动带上
            self._json({"ok": ok, "on": on})
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
    # 先读"上一个实例"的构建指纹, 再落自己的。顺序至关重要:
    # save_state() 写的是当前进程的指纹, 若先 save 后读, 单实例分支
    # 比对的就是"自己 vs 自己", 永远相等, 旧实例提示成了死代码
    # (v1.4.1 引入该提示时埋下的 bug, 直到 v1.4.4 才被发现)。
    prev_build = None
    try:
        if os.path.isfile(STATE_FILE):
            with open(STATE_FILE, encoding="utf-8") as f:
                prev_build = json.load(f).get("proc_build")
    except Exception:
        pass
    # 落一次构建指纹: 之后任何人(包括下次双击的自己)都能从 state.json
    # 看出"端口那头的实例是不是这个 exe 启的"。
    save_state()

    # 一次性巡检模式: 计划任务每 5 分钟拉起一次, 不启服务、不出界面。
    # 必须在单实例检测之前处理 —— 否则主程序在跑时巡检会被端口占用分支
    # 直接 exit(0) 掉, 而恰恰这时候它的价值最低(有看门狗), 反过来主程序
    # 不在时它才最该跑。
    if "--guard" in sys.argv:
        sys.exit(run_guard_once())

    url = "http://127.0.0.1:%d/" % PORT

    # 单实例: 端口已被占用说明已有实例在运行。此时不再启动第二个进程,
    # 直接打开现有控制台即可 —— 否则每次双击都会多一个进程, 多个进程
    # 抢同一端口会让页面连不上, 或连到已卡死的旧实例上。
    if port_in_use(PORT):
        log(f"端口 {PORT} 已有实例在运行, 直接打开控制台")
        # 检测运行中的实例是不是"另一个 exe"启的(经典陷阱: 换了新版 exe,
        # 旧版进程还在后台跑, 双击新 exe 只会打开旧实例的控制台, 用户会
        # 以为"重启了却没更新")。指纹对得上 = 同版本, 静默打开即可。
        try:
            my_fp = _exe_fingerprint()
            # 用 main() 开头读到的 prev_build(保存前的旧值) —— 绝不能
            # 在这里重读 state.json, 那已经是自己刚写的新指纹了
            if my_fp and prev_build != my_fp:
                log("运行中的实例构建指纹与当前 exe 不同(疑似旧实例未退出)", logging.WARNING)
                alert("检测到已有实例在运行, 但它可能不是当前这个 exe 启动的。\n\n"
                      "常见原因: 你更新了新版本的 exe, 但旧版本进程还在后台运行。"
                      "此时双击新 exe 只会打开旧实例的控制台, 新功能不会生效。\n\n"
                      "解决办法: 右键托盘图标 →「退出」, 然后再双击本程序。")
        except Exception:
            pass
        try:
            webbrowser.open(console_url())
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
    if os.path.exists(warp_conf_path()):
        log(f"已启用秒级注入通道 (配置直写: {warp_conf_path()})")
    else:
        log(f"未找到 WARP 配置 {warp_conf_path()}, 将使用逐条注入(较慢)", logging.WARNING)

    # 兜底: 任何方式的退出(含未捕获异常)都必须撤掉 DNS 接管。
    # 否则网卡 DNS 会一直指向 127.0.0.1 而 53 端口无人监听 —— 用户直接断网。
    # atexit 挡不住 taskkill -f, 但能覆盖绝大多数正常/异常退出路径。
    atexit.register(_atexit_restore_dns)

    # 启动后台守护线程
    threading.Thread(target=metrics_loop, daemon=True).start()
    threading.Thread(target=reconnect_loop, daemon=True).start()
    threading.Thread(target=self_heal_loop, daemon=True).start()
    threading.Thread(target=autoupdate_loop, daemon=True).start()
    threading.Thread(target=egress_loop, daemon=True).start()
    threading.Thread(target=dns_guard_loop, daemon=True).start()
    # 网络保障看门狗: 与分流是否启用无关, 全程在跑
    threading.Thread(target=net_guard_loop, daemon=True).start()
    # 校对上次留下的 enabled 标志, 避免"一启动就自己动网络"
    threading.Thread(target=reconcile_state_on_startup, daemon=True).start()

    # 系统级兜底: 本程序没运行时(被硬杀 / 没启动)由计划任务兜住 DNS 残留。
    # 注册失败不致命(看门狗还在), 只记日志, 不打断启动。
    if settings.get("net_watchdog", True) and _IS_WIN:
        if not watchdog_enabled():
            def _reg():
                ok, msg = register_watchdog(5)
                if not ok:
                    log("系统级网络兜底任务注册失败: " + msg, logging.WARNING)
            threading.Thread(target=_reg, daemon=True).start()

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
            threading.Timer(0.8, lambda: webbrowser.open(console_url())).start()
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
        # 退出前必须撤掉 DNS 接管。不撤的话网卡 DNS 会一直指向 127.0.0.1,
        # 而本进程已死、53 端口没人监听 —— 命中后缀的域名全部解析失败,
        # 表现就是"能上微信但打不开网页"。这个后果比不分流严重得多,
        # 所以这里无条件检查一次(不只看 dns_proxy 标志位)。
        if state.get("dns_proxy") or _DNS_SERVER is not None:
            teardown_smart_dns()
            log("退出前已还原网卡 DNS 与 WARP fallback 设置")
        server.shutdown()
        save_state()


if __name__ == "__main__":
    main()
