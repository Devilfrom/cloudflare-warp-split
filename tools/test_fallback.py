# -*- coding: utf-8 -*-
"""验证 WARP 官方的 dns fallback 机制: 把域名后缀加进 fallback 后, WARP 会把
这些域名的 DNS 查询转给 fallback 服务器(默认含 127.0.0.1:53, 也就是我们的
本地智能 DNS), 而不是走自己的隧道出口。
"""
import socket
import subprocess
import sys
import time

sys.path.insert(0, ".")
import warp_split as W


def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                           "-Command", cmd], capture_output=True, text=True,
                          timeout=60).stdout.strip()


def flush():
    ps("Clear-DnsClientCache")


def res(h):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)})
    except Exception:
        return ["ERR"]


def main():
    print("=" * 72)
    print("WARP dns fallback 机制验证")
    print("=" * 72)

    print("\n[1] 启动本地智能 DNS(127.0.0.1:53)")
    print("    " + str(W.start_smart_dns()))
    time.sleep(1)

    print("\n[2] 基线: 未加 fallback 时")
    flush()
    for h in ["www.baidu.com", "www.taobao.com"]:
        ips = res(h)
        cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
        print("    %-18s %-44s %s (%d/%d)" % (h, ",".join(ips[:2]),
              "国内" if cn == len(ips) else "境外", cn, len(ips)))

    print("\n[3] 加入 fallback 后缀")
    for d in ["baidu.com", "taobao.com", "aliyun.com", "tencent.com"]:
        ok, out = W.warp(["dns", "fallback", "add", d], timeout=20)
        print("    add %-14s ok=%s %s" % (d, ok, (out or "").strip()[:30]))
    time.sleep(2)

    print("\n[4] 加 fallback 后重新解析")
    flush()
    for h in ["www.baidu.com", "www.taobao.com", "mirrors.aliyun.com",
              "mirrors.cloud.tencent.com", "www.google.com"]:
        ips = res(h)
        cn = sum(1 for i in ips if i[:3].isdigit() and W.is_cn_ip(i))
        tag = "国内 OK" if cn == len(ips) else ("境外(应然)" if cn == 0 else "混合")
        print("    %-28s %-40s %s (%d/%d)" % (h, ",".join(ips[:2]), tag, cn, len(ips)))
    print("    代理统计: " + str(dict(W.dns_stats)))

    print("\n[5] 清理测试条目")
    for d in ["baidu.com", "taobao.com", "aliyun.com", "tencent.com"]:
        W.warp(["dns", "fallback", "remove", d], timeout=20)
    print("    已移除")
    W.stop_smart_dns()
    print("=" * 72)


if __name__ == "__main__":
    main()
