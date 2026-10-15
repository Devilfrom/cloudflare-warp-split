#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从已安装 Cloudflare WARP 的安卓手机中导出完整安装包。

背景
----
Google Play 分发的 WARP 是 App Bundle(AAB) 格式，安装到手机后会被拆成
多个 APK：
    base.apk                - 代码与资源
    split_config.<abi>.apk  - 各 CPU 架构的 native .so(boringtun)
    split_config.<lang>.apk - 各语言资源
    split_config.<dpi>.apk  - 各分辨率资源

只拿 base.apk 是**无法正常运行**的：WARP 的 WireGuard 实现 boringtun 是
Rust 编译的 native 库，位于 ABI split 中，缺少它 App 能装但建不了隧道。

用法
----
1. 手机开启「开发者选项 -> USB 调试」，用数据线连电脑，信任本机
2. 运行: python tools/export_android_app.py
3. 产物在 dist/android/ 下：
     - 多个 .apk（可用 adb install-multiple 安装）
     - Cloudflare-WARP-<版本>.apkm（可用 SAI / APKMirror Installer 安装）

可选参数
--------
  --pkg <包名>      默认 com.cloudflare.app
  --adb <路径>      adb 可执行文件路径
  --out <目录>      输出目录，默认 dist/android
  --universal       若找到已合并的 universal apk 则优先导出（部分机型有）
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

DEFAULT_PKG = "com.cloudflare.app"


def find_adb(user_adb=None):
    """定位 adb 可执行文件。"""
    if user_adb:
        if os.path.isfile(user_adb):
            return user_adb
        raise SystemExit(f"[x] 指定的 adb 不存在: {user_adb}")

    p = shutil.which("adb")
    if p:
        return p

    # 常见安装位置
    candidates = [
        r"D:\IT\platform-tools\adb.exe",
        r"C:\platform-tools\adb.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expanduser(r"~\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    raise SystemExit(
        "[x] 未找到 adb。请先安装 Android platform-tools，或用 --adb 指定路径。\n"
        "    下载: https://developer.android.com/tools/releases/platform-tools"
    )


def run(cmd, timeout=60):
    """执行命令并解码输出（兼容 Windows GBK 控制台）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return 1, "", "命令不存在"
    dec = lambda b: b.decode("utf-8", "replace") or b.decode("gbk", "replace")
    return r.returncode, dec(r.stdout), dec(r.stderr)


def check_device(adb):
    """确认只有一台设备在线。"""
    rc, out, err = run([adb, "devices"])
    if rc != 0:
        raise SystemExit(f"[x] adb devices 执行失败: {err}")

    lines = [
        l.strip() for l in out.splitlines()[1:]
        if l.strip() and not l.strip().startswith("*")
    ]
    devs = [l for l in lines if "\tdevice" in l or " device" in l]
    unauthorized = [l for l in lines if "unauthorized" in l]
    offline = [l for l in lines if "offline" in l]

    if unauthorized:
        raise SystemExit(
            "[x] 手机未授权 USB 调试。请解锁屏幕，在弹出的"
            "「允许 USB 调试吗？」对话框点「允许」。"
        )
    if offline:
        raise SystemExit("[x] 设备 offline，请重新插拔数据线。")
    if not devs:
        raise SystemExit(
            "[x] 未检测到设备。请确认：\n"
            "    1) 开发者选项 -> USB 调试 已开启\n"
            "    2) 数据线支持传输（非纯充电线）\n"
            "    3) 手机已解锁并信任此电脑"
        )
    return devs[0].split("\t")[0]


def get_apk_paths(adb, serial, pkg):
    """获取该包名所有 APK 在手机上的路径。"""
    rc, out, err = run([adb, "-s", serial, "shell", "pm", "path", pkg])
    if rc != 0 or "package:" not in out:
        raise SystemExit(
            f"[x] 未在手机上找到 {pkg}。\n"
            f"    请先在手机安装 Cloudflare WARP(1.1.1.1) 并登录一次。\n"
            f"    adb 输出: {out or err}"
        )
    return [l.strip().replace("package:", "") for l in out.splitlines() if "package:" in l]


def get_version(adb, serial, pkg):
    """读取版本名/版本号，用于文件命名。"""
    rc, out, err = run([adb, "-s", serial, "shell", "dumpsys", "package", pkg])
    name, code = "", ""
    if rc == 0:
        m = re.search(r"versionName=([^\s]+)", out)
        if m:
            name = m.group(1)
        m = re.search(r"versionCode=(\d+)", out)
        if m:
            code = m.group(1)
    return name or "unknown", code or "0"


def pull_icon(adb, serial, pkg, out_dir):
    """尽力抓取应用图标，供 .apkm 识别；失败不影响主流程。"""
    rc, out, _ = run([adb, "-s", serial, "shell", "pm", "path", pkg])
    base = None
    for l in out.splitlines():
        if l.strip().endswith("base.apk"):
            base = l.strip().replace("package:", "")
    if not base:
        return None

    tmp = "/sdcard/.warp_export_tmp"
    try:
        # 用 aapt 不可靠，改为直接从 apk 里挑最大图标资源
        local_tmp = os.path.join(out_dir, "_base_tmp.apk")
        run([adb, "-s", serial, "pull", base, local_tmp], timeout=180)
        if not os.path.isfile(local_tmp):
            return None

        best = None
        with zipfile.ZipFile(local_tmp) as z:
            for i in z.infolist():
                n = i.filename
                if re.match(r"res/drawable[^/]*/ic_launcher.*\.(png|webp)$", n) or \
                   re.match(r"res/mipmap[^/]*/ic_launcher\.png$", n):
                    if best is None or i.file_size > best.file_size:
                        best = i
            if best:
                dst = os.path.join(out_dir, "icon.png")
                with z.open(best) as src, open(dst, "wb") as f:
                    f.write(src.read())
                os.remove(local_tmp)
                return dst
        os.remove(local_tmp)
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description="从手机导出 Cloudflare WARP 完整安装包")
    ap.add_argument("--pkg", default=DEFAULT_PKG, help="WARP 包名, 默认 com.cloudflare.app")
    ap.add_argument("--adb", default=None, help="adb 路径")
    ap.add_argument("--out", default=None, help="输出目录, 默认 dist/android")
    ap.add_argument("--no-apkm", action="store_true", help="只导出 apk, 不打包成 .apkm")
    args = ap.parse_args()

    adb = find_adb(args.adb)
    print(f"[i] adb: {adb}")

    serial = check_device(adb)
    print(f"[i] 设备: {serial}")

    paths = get_apk_paths(adb, serial, args.pkg)
    print(f"[i] 发现 {len(paths)} 个分包:")

    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = args.out or os.path.join(app_dir, "dist", "android")
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    pulled = []
    for p in paths:
        fname = os.path.basename(p)
        dst = os.path.join(out_dir, fname)
        print(f"    拉取 {fname} ...", end=" ", flush=True)
        rc, out, err = run([adb, "-s", serial, "pull", p, dst], timeout=300)
        if rc == 0 and os.path.isfile(dst):
            size = os.path.getsize(dst) / 1048576
            print(f"OK ({size:.2f} MB)")
            pulled.append(dst)
        else:
            print(f"失败 ({err.strip()[:60]})")

    if not pulled:
        raise SystemExit("[x] 没有任何文件导出成功。")

    # 校验：若没有 ABI split，提醒用户这份包可能不完整
    abi_splits = [f for f in pulled if re.search(r"split_config\.(arm|x86)", os.path.basename(f))]
    has_lib = False
    for f in pulled:
        try:
            with zipfile.ZipFile(f) as z:
                if any(n.startswith("lib/") and n.endswith(".so") for n in z.namelist()):
                    has_lib = True
                    break
        except Exception:
            pass

    print()
    if has_lib:
        print("[OK] 检测到 native .so 库，这份安装包是完整的。")
    elif abi_splits:
        print("[!] 有 ABI 分包但未在已拉取文件中找到 .so，请确认导出完整性。")
    else:
        print("[!] 警告: 未发现任何 ABI 分包 / native 库。")
        print("    这份包很可能是残缺的 base.apk，装在手机上无法建立 WARP 隧道。")
        print("    请确认手机上 WARP 是完整安装（而不是只恢复了基础包）。")

    ver_name, ver_code = get_version(adb, serial, args.pkg)
    print(f"[i] 版本: {ver_name} (versionCode {ver_code})")

    total = sum(os.path.getsize(f) for f in pulled) / 1048576
    print(f"[i] 合计: {len(pulled)} 个文件, {total:.2f} MB")
    print(f"[i] 输出目录: {out_dir}")

    # 写出安装说明
    if abi_splits or has_lib:
        note = (
            "安装方式 A(SAI,推荐):\n"
            "  1. 手机安装 SAI (Split APKs Installer, Google Play / F-Droid)\n"
            "  2. 把 Cloudflare-WARP-*.apkm 传到手机\n"
            "  3. 打开 SAI -> 选择该文件 -> 安装\n\n"
            "安装方式 B(adb,需电脑):\n"
            f"  adb install-multiple {' '.join(os.path.basename(f) for f in pulled)}\n"
        )
    else:
        note = "当前导出不完整，请先确认手机上的 WARP 为完整安装后重新导出。\n"
    with open(os.path.join(out_dir, "安装说明.txt"), "w", encoding="utf-8") as f:
        f.write(f"Cloudflare WARP {ver_name}\n包名: {args.pkg}\n导出时间: {__import__('datetime').datetime.now():%Y-%m-%d %H:%M}\n\n{note}")

    # 打包 .apkm
    if not args.no_apkm and len(pulled) > 1:
        apkm = os.path.join(out_dir, f"Cloudflare-WARP-{ver_name}.apkm")
        icon = pull_icon(adb, serial, args.pkg, out_dir)
        with zipfile.ZipFile(apkm, "w", zipfile.ZIP_DEFLATED) as z:
            for f in pulled:
                z.write(f, os.path.basename(f))
            if icon and os.path.isfile(icon):
                z.write(icon, "icon.png")
                os.remove(icon)
            z.writestr("meta.json", json.dumps({
                "package": args.pkg,
                "version_name": ver_name,
                "version_code": int(ver_code) if ver_code.isdigit() else 0,
                "split_count": len(pulled),
            }, ensure_ascii=False, indent=2))
        print(f"[OK] 已打包: {os.path.basename(apkm)} ({os.path.getsize(apkm)/1048576:.2f} MB)")

    print("\n[完成] 把 dist/android 下的文件上传到 GitHub Release 即可。")


if __name__ == "__main__":
    main()
