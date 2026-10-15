#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare WARP 智能分流控制台 —— 后端
=========================================
功能:
  - 国际流量走 Cloudflare WARP 出口 (warp 全隧道)
  - 国内 (中国大陆) 流量直连 (通过 WARP split-tunnel 排除规则)
  - 可视化控制台 (index.html) + 一键开关 / 一键还原
  - 自动以管理员身份运行 (修改路由需要权限)

技术要点:
  - 仅依赖 Python 标准库
  - 启用: disconnect -> mode warp -> connect -> 并发注入 china_cidr.txt 中的中国 IP 到 WARP 排除列表
  - 停用/还原: disconnect + tunnel ip reset (瞬间清空自定义排除, 比逐条删除快得多)
  - 状态持久化到 state.json, 异常自动回滚
"""

import os
import sys
import json
import time
import threading
import subprocess
import logging
import webbrowser
import ctypes
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ====================== 配置 ======================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WARP_CLI_CANDIDATES = [
    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"D:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
]
CHINA_LIST = os.path.join(APP_DIR, "china_cidr.txt")
STATE_FILE = os.path.join(APP_DIR, "state.json")
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

# ====================== 全局状态 ======================
state = {
    "enabled": False,
    "running": False,
    "action": None,
    "progress": {"total": 0, "done": 0, "phase": "空闲"},
    "added_ranges": [],
    "error": None,
}
state_lock = threading.Lock()
op_stop = threading.Event()
log_lines = []
log_lock = threading.Lock()

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
    # PATH 中查找
    try:
        r = subprocess.run(["where", "warp-cli"], capture_output=True, text=True, timeout=10)
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
        r = subprocess.run([cli] + args, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "命令超时"
    except Exception as e:
        return False, str(e)


def restart_warp_service():
    """重启 CloudflareWARP 服务, 用于清除卡死的 daemon 状态 (happy eyeballs 卡住时兜底)。"""
    try:
        subprocess.run(["net", "stop", "CloudflareWARP"], capture_output=True, text=True, timeout=30)
        time.sleep(3)
        subprocess.run(["net", "start", "CloudflareWARP"], capture_output=True, text=True, timeout=30)
        time.sleep(5)
        return True
    except Exception as e:
        log("重启 CloudflareWARP 服务失败: " + str(e), logging.WARNING)
        return False


def read_china_list():
    if not os.path.exists(CHINA_LIST):
        return []
    out = []
    try:
        with open(CHINA_LIST, "r", encoding="utf-8") as f:
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


def get_egress_ip():
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for url in EGRESS_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                data = resp.read().decode("utf-8", "ignore").strip()
                # 有的服务返回 "当前 IP：1.2.3.4 来自..."
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
        r = subprocess.run(["tracert", "-d", "-h", "2", "-w", "700", host],
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
    """禁用 CloudflareWARP 虚拟适配器的 IPv6, 解决 WARP 连接卡在 happy eyeballs 的问题。
    可逆: 再次调用 set interface <idx> enabled 即可恢复。"""
    import re
    try:
        r = subprocess.run(["netsh", "interface", "ipv6", "show", "interfaces"],
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
        res = subprocess.run(["netsh", "interface", "ipv6", "set", "interface", idx, "disabled"],
                             capture_output=True, text=True, timeout=20, errors="ignore")
        if res.returncode != 0:
            return False, (res.stdout + res.stderr).strip() or "netsh 返回非零"
        return True, "已禁用 CloudflareWARP 适配器 IPv6 (若仍连不上可再点一次本按钮恢复)"
    except Exception as e:
        return False, str(e)



def load_state():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                state["enabled"] = bool(d.get("enabled", False))
                state["added_ranges"] = d.get("added_ranges", [])
    except Exception:
        pass


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

        # 1) 确保断开, 避免模式切换冲突
        warp(["disconnect"], timeout=20)
        time.sleep(2)

        # 2) 设置为全隧道模式
        ok, out = warp(["mode", "warp"], timeout=20)
        if not ok:
            log("设置 mode warp 返回: " + out, logging.WARNING)
        else:
            log("mode warp 设置完成")

        # 3) 连接 WARP (happy eyeballs 偶发卡住, 采用『断重连 + 服务重启』兜底)
        with state_lock:
            state["progress"] = {"total": 0, "done": 0, "phase": "正在连接 WARP 隧道..."}
        connected = False
        last_out = ""
        max_attempts = 4
        for attempt in range(1, max_attempts + 1):
            if op_stop.is_set():
                raise RuntimeError("用户取消了操作")
            with state_lock:
                state["progress"] = {"total": 0, "done": 0,
                                     "phase": f"正在连接 WARP 隧道 (第 {attempt}/{max_attempts} 次尝试)..."}
            log(f"尝试连接 WARP (第 {attempt}/{max_attempts} 次)...")
            warp(["disconnect"], timeout=20)
            time.sleep(2)
            ok, out = warp(["--accept-tos", "connect"], timeout=30)
            log("connect: " + out)
            # 轮询连接状态 (单次尝试最多等 ~36s)
            for _ in range(18):
                if op_stop.is_set():
                    raise RuntimeError("用户取消了操作")
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
        # 兜底: 重启 CloudflareWARP 服务后最后再试一次
        if not connected:
            log("常规重试未连上, 尝试重启 CloudflareWARP 服务...", logging.WARNING)
            if restart_warp_service():
                warp(["mode", "warp"], timeout=20)
                time.sleep(1)
            warp(["disconnect"], timeout=20)
            time.sleep(2)
            warp(["--accept-tos", "connect"], timeout=30)
            for _ in range(18):
                if op_stop.is_set():
                    raise RuntimeError("用户取消了操作")
                ok, out = warp(["status"], timeout=10)
                last_out = out
                with state_lock:
                    state["warp_status"] = out.replace("\n", " ")
                if "Connected" in out:
                    connected = True
                    break
                time.sleep(2)
        if not connected:
            raise RuntimeError(
                "WARP 未能连接。最后状态: " + last_out[:160] +
                " | 常见原因: 到 Cloudflare WARP 端点(162.159.x.x:443)的握手被网络阻断, 或 IPv6 探测(happy eyeballs)卡住。"
                "建议: 多试 1-2 次; 或在『网络适配器 -> CloudflareWARP -> 属性』取消 IPv6 勾选后重试; 确认 WARP 账号可用。"
            )
        log("WARP 已连接")

        # 4) 读取国内网段并并发注入排除列表
        ranges = read_china_list()
        if MAX_RANGES > 0:
            ranges = ranges[:MAX_RANGES]
        total = len(ranges)
        if total == 0:
            raise RuntimeError("china_cidr.txt 为空，请点击『更新中国IP列表』")
        log(f"准备注入 {total} 条中国 IP 规则 (并发 {WORKERS})")
        with state_lock:
            state["progress"] = {"total": total, "done": 0, "phase": "注入中国IP分流规则..."}

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
            state["added_ranges"] = added
            state["enabled"] = True
            state["progress"] = {"total": total, "done": total, "phase": "分流已启用"}
        save_state()
        log(f"分流启用完成: 成功注入 {len(added)}/{total} 条中国IP规则 (其余已存在或被跳过)")
    except Exception as e:
        log("启用失败: " + str(e), logging.ERROR)
        with state_lock:
            state["error"] = str(e)
        # 自动回滚
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
            state["added_ranges"] = []
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
    # 等待当前操作结束
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
        state["added_ranges"] = []
        state["error"] = None
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
        # 启用完成后即使 daemon 状态短暂显示 Connecting，也视为已连接(分流已生效)
        if state["enabled"] and not connected and "Disconnected" not in out and "Failure" not in out:
            connected = True
        st = {
            "warp_status": out.strip(),
            "connected": connected,
            "mode": mode,
            "cli_exclude_count": cli_count,
            "list_total": len(read_china_list()),
            "egress_ip": egress,
            "enabled": state["enabled"],
            "running": state["running"],
            "action": state["action"],
            "progress": dict(state["progress"]),
            "error": state["error"],
            "warp_cli": find_warp_cli() or "",
            "max_ranges_test": MAX_RANGES,
        }
    return st


# ====================== Web 服务 ======================
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            try:
                data = open(os.path.join(APP_DIR, "index.html"), "rb").read()
                self._send(200, data, "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        elif p == "/api/ping":
            self._send(200, json.dumps({"ok": True, "port": PORT}))
        elif p == "/api/status":
            try:
                self._send(200, json.dumps(get_status(), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"error": str(e)}, ensure_ascii=False))
        elif p == "/api/log":
            with log_lock:
                lines = list(log_lines)
            self._send(200, json.dumps({"log": lines}, ensure_ascii=False))
        elif p == "/api/selftest":
            try:
                self._send(200, json.dumps(self_test(), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"verdict": "ERROR", "msg": str(e)}, ensure_ascii=False))
        elif p == "/favicon.ico":
            self._send(204, b"")
        else:
            self._send(404, json.dumps({"error": "not found"}, ensure_ascii=False))

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/enable":
            threading.Thread(target=enable_split, daemon=True).start()
            self._send(200, json.dumps({"ok": True, "msg": "已开始启用分流"}))
        elif p == "/api/disable":
            threading.Thread(target=disable_split, daemon=True).start()
            self._send(200, json.dumps({"ok": True}))
        elif p == "/api/restore":
            threading.Thread(target=restore, daemon=True).start()
            self._send(200, json.dumps({"ok": True}))
        elif p == "/api/refresh":
            threading.Thread(target=refresh_list, daemon=True).start()
            self._send(200, json.dumps({"ok": True}))
        elif p == "/api/fix_ipv6":
            ok, out = fix_ipv6()
            self._send(200, json.dumps({"ok": ok, "msg": out}, ensure_ascii=False))
        else:
            self._send(404, json.dumps({"error": "not found"}, ensure_ascii=False))

    def log_message(self, *a):
        pass


# ====================== 提权 ======================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return True


def run_as_admin():
    try:
        params = " ".join([repr(a) for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        log("提权失败: " + str(e), logging.ERROR)


# ====================== 主函数 ======================
def main():
    load_state()
    if not is_admin():
        log("当前非管理员, 尝试提权...")
        run_as_admin()
        sys.exit(0)

    log("Cloudflare WARP 智能分流控制台 启动")
    log(f"监听 http://127.0.0.1:{PORT}/  (工作目录: {APP_DIR})")
    if MAX_RANGES > 0:
        log(f"[测试模式] 仅注入前 {MAX_RANGES} 条规则")

    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as e:
        log(f"无法在端口 {PORT} 启动服务: {e}（可能已有实例在运行，端口被占用）", logging.ERROR)
        input("按回车退出...")
        sys.exit(1)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到退出信号")
    finally:
        server.shutdown()
        save_state()


if __name__ == "__main__":
    main()
