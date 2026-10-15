# -*- coding: utf-8 -*-
"""端到端: 智能 DNS 分流是否随启用/停用正确接管与还原。

流程:
  1. 启动后端(8777)
  2. 停用 -> 验证 DNS 还原为 DHCP
  3. 启用 -> 验证 DNS 代理接管、网卡 DNS 指向 127.0.0.1
  4. 系统解析国内/境外域名, 验证判定正确
  5. 再次停用 -> 验证还原

用法: python tools/test_e2e_dns.py
"""
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8777"
ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def api(path, obj=None, timeout=25):
    url = BASE + path
    data = json.dumps(obj).encode() if obj is not None else b""
    req = urllib.request.Request(url, data=data, method="POST" if obj is not None else "GET",
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())


def sys_resolve(host):
    """走系统 DNS 解析(会经过网卡 DNS, 即我们可能接管后的那个)。"""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception as e:
        return ["ERR:%s" % str(e)[:40]]


def wait_idle(max_s=180):
    t0 = time.time()
    while time.time() - t0 < max_s:
        try:
            st = api("/api/status")
        except Exception:
            time.sleep(1)
            continue
        if not st.get("running"):
            return st
        time.sleep(1)
    return api("/api/status")


def kill_8777():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$c = Get-NetTCPConnection -LocalPort 8777 -State Listen -ErrorAction SilentlyContinue; "
             "if ($c) { $c | Select-Object -ExpandProperty OwningProcess -Unique | "
             "ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue; "
             "Write-Output \"killed $_\" } } else { Write-Output 'none' }"],
            capture_output=True, text=True, timeout=40)
        print("  清理 8777: " + (out.stdout.strip() or "none"))
    except Exception as e:
        print("  清理失败: %s" % e)


def main():
    print("=" * 74)
    print("端到端: 智能 DNS 分流的接管与还原")
    print("=" * 74)

    print("\n[0] 清理可能占用 8777 的旧实例")
    kill_8777()
    time.sleep(2)

    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    p = subprocess.Popen([PY, str(ROOT / "warp_split.py"), "--no-browser"],
                         cwd=str(ROOT), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         startupinfo=si, creationflags=0x08000000)
    print("  后端已启动 pid=%d" % p.pid)
    time.sleep(12)

    try:
        st = api("/api/status")
        print("\n[1] 初始状态")
        print("    enabled=%s  route_active=%s  dns_proxy=%s" %
              (st.get("enabled"), st.get("route_active"), st.get("dns_proxy")))
        print("    网卡 DNS: %s" % (st.get("nic_dns") or "-"))
        print("    baidu -> %s" % sys_resolve("www.baidu.com")[:3])

        print("\n[2] 停用分流 —— 应还原网卡 DNS 为 DHCP")
        api("/api/disable", {})
        st = wait_idle()
        print("    enabled=%s  dns_proxy=%s" % (st.get("enabled"), st.get("dns_proxy")))
        print("    网卡 DNS: %s" % (st.get("nic_dns") or "-"))

        print("\n[3] 启用分流 —— 应接管 DNS")
        api("/api/enable", {})
        st = wait_idle()
        print("    enabled=%s  dns_proxy=%s" % (st.get("enabled"), st.get("dns_proxy")))
        print("    网卡 DNS: %s" % (st.get("nic_dns") or "-"))
        print("    DNS 统计: %s" % st.get("dns_stats"))

        print("\n[4] 系统解析验证 (走本机网卡 DNS, 即智能 DNS)")
        sys.path.insert(0, str(ROOT))
        import warp_split as W
        # 必须清掉 Windows DNS 缓存, 否则读到的是开启前留下的旧结果
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", "Clear-DnsClientCache"],
                       capture_output=True, timeout=40)
        print("    (已清空 Windows DNS 缓存)")
        st0 = api("/api/status")
        d0 = dict(st0.get("dns_stats") or {})
        for h in ["www.baidu.com", "www.taobao.com", "mirrors.aliyun.com",
                  "www.google.com", "github.com"]:
            ips = sys_resolve(h)
            cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
            kind = "国内" if (cn and cn == len(ips)) else "境外"
            print("    %-24s %s   %s (%d/%d)" %
                  (h, ",".join(ips[:2]), kind, cn, len(ips)))
        st1 = api("/api/status")
        d1 = dict(st1.get("dns_stats") or {})
        print("    代理收到: 国内 %d->%d, 境外 %d->%d  (增长说明查询确实走了本地代理)" %
              (d0.get("cn", 0), d1.get("cn", 0), d0.get("warp", 0), d1.get("warp", 0)))

        print("\n[5] 再次停用 —— 应干净还原")
        api("/api/disable", {})
        st = wait_idle()
        print("    enabled=%s  dns_proxy=%s" % (st.get("enabled"), st.get("dns_proxy")))
        print("    网卡 DNS: %s" % (st.get("nic_dns") or "-"))

        print("\n[6] 恢复到启用状态, 交还给你")
        api("/api/enable", {})
        st = wait_idle()
        print("    enabled=%s  dns_proxy=%s  route_active=%s" %
              (st.get("enabled"), st.get("dns_proxy"), st.get("route_active")))
        print("    网卡 DNS: %s" % (st.get("nic_dns") or "-"))
        print("    排除规则: %s 条" % st.get("cli_exclude_count"))
        print("    baidu -> %s" % sys_resolve("www.baidu.com")[:2])
    finally:
        p.terminate()
        try:
            p.wait(timeout=15)
        except Exception:
            p.kill()
        print("\n后端已结束")
    print("=" * 74)


if __name__ == "__main__":
    main()
