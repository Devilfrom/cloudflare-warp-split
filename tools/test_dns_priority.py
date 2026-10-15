# -*- coding: utf-8 -*-
"""验证: WARP 接口 metric 低于物理网卡时, Windows 会优先用它的 127.0.2.2,
导致本地智能 DNS 白接管。试验调高 WARP 接口 metric 是否能把优先级抢回来。
"""
import socket
import subprocess
import sys
import time

sys.path.insert(0, ".")
import warp_split as W


def ps(cmd):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, text=True, timeout=60)
    return (r.stdout or "").strip(), (r.stderr or "").strip()


def flush():
    ps("Clear-DnsClientCache")


def resolve(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception as e:
        return ["ERR"]


def metrics():
    out, _ = ps("Get-NetIPInterface -AddressFamily IPv4 | "
                "Where-Object { $_.ConnectionState -eq 'Connected' } | "
                "ForEach-Object { $_.InterfaceAlias + '=' + $_.InterfaceMetric }")
    return out.replace("\n", "  ")


def main():
    print("=" * 72)
    print("DNS 查询优先级实验")
    print("=" * 72)

    ok, msg = W.start_smart_dns()
    print("\n[1] 启动本地智能 DNS: %s (%s)" % (ok, msg))
    ok2, msg2 = W.apply_nic_dns([W.DNS_LISTEN_ADDR, W.DNS_CN])
    print("    网卡 DNS 改写: %s (%s)" % (ok2, msg2))
    time.sleep(1)

    print("\n[2] 当前接口 metric")
    print("    " + metrics())

    print("\n[3] 改 metric 前 —— 解析国内域名")
    flush()
    before = dict(W.dns_stats)
    ips = resolve("www.baidu.com")
    print("    www.baidu.com -> %s" % ips[:3])
    print("    代理统计: %s -> %s" % (before, dict(W.dns_stats)))

    # 调高 WARP 接口的 metric, 降低它的 DNS 查询优先级
    print("\n[4] 把 CloudflareWARP 接口 metric 调到 50 (低于物理网卡优先级)")
    out, err = ps("Set-NetIPInterface -InterfaceAlias 'CloudflareWARP' "
                  "-InterfaceMetric 50; Get-NetIPInterface -InterfaceAlias "
                  "'CloudflareWARP' -AddressFamily IPv4 | "
                  "ForEach-Object { $_.InterfaceMetric }")
    print("    新 metric: " + (out or err)[:80])

    print("\n[5] 改 metric 后 —— 重新解析")
    flush()
    before = dict(W.dns_stats)
    ips = resolve("www.baidu.com")
    print("    www.baidu.com -> %s" % ips[:3])
    cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
    print("    判定: %s (%d/%d 在国内)" % ("国内 ✓" if cn == len(ips) else "境外 ✗",
                                           cn, len(ips)))
    print("    代理统计: %s -> %s" % (before, dict(W.dns_stats)))

    print("\n[6] 境外域名仍然要能解析")
    flush()
    for h in ["www.google.com", "github.com"]:
        print("    %-20s -> %s" % (h, resolve(h)[:2]))

    W.stop_smart_dns()
    W.apply_nic_dns([])
    print("\n已清理(停代理 + 还原网卡 DNS)")
    print("=" * 72)


if __name__ == "__main__":
    main()
