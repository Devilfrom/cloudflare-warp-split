#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Cloudflare WARP.exe 的 PE 资源中导出图标，合并成一个多尺寸 warp.ico。

不使用 EnumResourceNames(回调在嵌入环境易崩)，改为纯 struct 手工解析
PE 资源目录树，保留原始尺寸(含 256x256 PNG 图标)。

用法: python tools/make_icon.py
"""

import os
import struct
import sys

RT_ICON = 3
RT_GROUP_ICON = 14

SRC = r"C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe"
DST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "warp.ico")


class PE:
    """最小化的 PE 资源读取器。"""

    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("不是有效的 PE 文件")

        coff = e_lfanew + 4
        (_, self.nsec, _, _, _, self.opt_size, _) = struct.unpack_from("<HHIIIHH", d, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        self.is64 = magic == 0x20B

        dd = opt + (112 if self.is64 else 96)     # Data Directory 起始
        rva, _size = struct.unpack_from("<II", d, dd + 2 * 8)   # index 2 = Resource
        self.res_rva = rva

        sec = opt + self.opt_size
        self.sections = []
        for i in range(self.nsec):
            s = sec + i * 40
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, s + 8)
            self.sections.append((vaddr, max(vsize, rsize), raddr))

    def rva2off(self, rva):
        for vaddr, vsize, raddr in self.sections:
            if vaddr <= rva < vaddr + vsize:
                return raddr + (rva - vaddr)
        return None

    def _entries(self, off):
        """返回目录项列表: [(id, is_dir, rel_off), ...]

        注意: rel_off 是**相对于资源目录基址**的偏移(PE 规范), 不是相对于
        当前目录的文件偏移。
        """
        nnames, nids = struct.unpack_from("<HH", self.data, off + 12)
        out = []
        for i in range(nnames + nids):
            e = off + 16 + i * 8
            name_or_id, data_off = struct.unpack_from("<II", self.data, e)
            out.append((name_or_id, bool(data_off & 0x80000000),
                        data_off & 0x7FFFFFFF))
        return out

    def find_all(self, rtype):
        """查找某类型下所有叶子: {name_id: (rva, size)}"""
        base = self.rva2off(self.res_rva)
        if base is None:
            return {}
        result = {}
        for tid, tdir, trel in self._entries(base):
            if not tdir or tid != rtype:
                continue
            for nid, ndir, nrel in self._entries(base + trel):
                if not ndir:
                    continue
                for _lid, ldir, lrel in self._entries(base + nrel):
                    if ldir:
                        continue
                    rva, size, _cp, _res = struct.unpack_from(
                        "<IIII", self.data, base + lrel)
                    result[nid] = (rva, size)
        return result

    def read(self, rva, size):
        off = self.rva2off(rva)
        if off is None:
            return None
        return self.data[off:off + size]


def export_icon(path=SRC, dst=DST):
    pe = PE(path)
    icons = pe.find_all(RT_ICON)
    groups = pe.find_all(RT_GROUP_ICON)
    if not icons or not groups:
        return None

    # 取第一个图标组
    grva, gsize = next(iter(groups.values()))
    gdata = pe.read(grva, gsize)

    _res, _typ, count = struct.unpack("<HHH", gdata[:6])
    entries, off = [], 6
    for _ in range(count):
        bW, bH, _c, _r, planes, bits, nbytes, nId = struct.unpack_from(
            "<BBBBHHIH", gdata, off)
        entries.append({"w": bW or 256, "h": bH or 256, "planes": planes,
                        "bits": bits, "bytes": nbytes, "id": nId})
        off += 14

    entries.sort(key=lambda e: (-e["w"], -e["bits"]))

    blobs = []
    for e in entries:
        if e["id"] not in icons:
            continue
        rva, _sz = icons[e["id"]]
        d = pe.read(rva, e["bytes"])
        if d:
            # 判断是 PNG(Vista+ 256图标) 还是 BMP(DIB)
            is_png = d[:8] == b"\x89PNG\r\n\x1a\n"
            blobs.append((e, d, is_png))

    if not blobs:
        return None

    icondir = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    dirents, datas = b"", b""
    for e, d, is_png in blobs:
        # ICO 条目宽高: 256 记为 0
        bw = 0 if e["w"] >= 256 else e["w"]
        bh = 0 if e["h"] >= 256 else e["h"]
        if is_png:
            # PNG 条目: BITMAPINFOHEADER 的宽高直接是尺寸(单倍, 无 AND mask)
            dirents += struct.pack("<BBBBHHII", bw, bh, 0, 0,
                                   e["planes"], e["bits"], len(d), offset)
        else:
            dirents += struct.pack("<BBBBHHII", bw, bh, 0, 0,
                                   e["planes"], e["bits"], len(d), offset)
        datas += d
        offset += len(d)

    with open(dst, "wb") as f:
        f.write(icondir + dirents + datas)

    return dst


if __name__ == "__main__":
    if not os.path.isfile(SRC):
        sys.exit(f"[x] 未找到 {SRC}")
    out = export_icon()
    if out:
        print(f"[OK] 图标已导出: {out}  ({os.path.getsize(out)/1024:.1f} KB)")
    else:
        sys.exit("[x] 图标导出失败")
