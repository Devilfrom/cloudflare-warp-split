#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反复采样 cmd.exe / conhost.exe 进程, 找出谁在不断新建控制台窗口。

纯 ctypes + CreateToolhelp32Snapshot, 不依赖 wmic(新版 Windows 已移除)。

用法: python tools/watch_cmd.py [采样次数] [间隔秒]
"""

import ctypes
import ctypes.wintypes as wt
import sys
import time
from collections import Counter

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = -1
MAX_PATH = 260

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL


def snapshot():
    h = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h == INVALID_HANDLE_VALUE:
        return {}
    out = {}
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(h, ctypes.byref(pe)):
            while True:
                out[pe.th32ProcessID] = (pe.szExeFile, pe.th32ParentProcessID)
                if not kernel32.Process32NextW(h, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(h)
    return out


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0

    seen = {}          # pid -> (name, ppid, first_seen, last_seen)
    for i in range(n):
        t = time.strftime("%H:%M:%S")
        procs = snapshot()
        for pid, (name, ppid) in procs.items():
            if name.lower() in ("cmd.exe", "conhost.exe", "powershell.exe"):
                if pid in seen:
                    seen[pid][3] = t
                else:
                    seen[pid] = [name, ppid, t, t]
        time.sleep(gap)

    print(f"=== 采样 {n} 次 (间隔 {gap}s) ===")
    print(f"捕获到 {len(seen)} 个控制台相关进程\n")

    # 统计每个父进程 spawn 了多少个 cmd
    ppid_counter = Counter()
    for pid, (name, ppid, first, last) in seen.items():
        if name.lower() == "cmd.exe":
            ppid_counter[ppid] += 1

    allp = snapshot()
    for pid, (name, ppid, first, last) in sorted(seen.items(), key=lambda x: x[0]):
        pname = allp.get(ppid, ("?", 0))[0]
        print(f"PID {pid:>6}  {name:<16} 父={ppid:>6}({pname:<20}) 首见={first} 末见={last}")

    print("\n=== 各父进程 spawn 的 cmd.exe 数量 ===")
    for ppid, cnt in ppid_counter.most_common():
        pname = allp.get(ppid, ("?", 0))[0]
        flag = "  <== 疑似循环源" if cnt >= 3 else ""
        print(f"  父进程 {ppid:>6} ({pname:<24}) 共 {cnt} 个{flag}")


if __name__ == "__main__":
    main()
