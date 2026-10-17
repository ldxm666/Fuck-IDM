#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract-idm-installer.py —— 从 IDM 官方安装包里"只提取、不安装"地取出 IDMan.exe。

IDM 的安装包是一个小 PE（自解压壳）+ 尾部 overlay，overlay 是一串连续的 zlib 流，
每条对应一个要落地的文件。本脚本按流边界顺序解压，把里面所有 PE 文件（MZ...PE）存出来。

用法：
    python extract-idm-installer.py <安装包路径> <输出目录>
"""
import os
import sys
import zlib
import hashlib

PE_MAGIC = b"MZ"


def pe_size(buf, off=0):
    """从 MZ 头算出整个 PE 映像的长度（含 overlay 之前的节表数据）。"""
    if buf[off:off + 2] != b"MZ":
        return None
    import struct
    e = struct.unpack_from("<I", buf, off + 0x3C)[0]
    if buf[off + e:off + e + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", buf, off + e + 6)[0]
    optsz = struct.unpack_from("<H", buf, off + e + 20)[0]
    so = off + e + 24 + optsz
    end = 0
    for i in range(nsec):
        o = so + i * 40
        rs, ra = struct.unpack_from("<II", buf, o + 16)
        end = max(end, ra + rs)
    return end


def iter_zlib_streams(d, start):
    """顺序切分 overlay 里的 zlib 流，yield (偏移, 压缩长度, 解压数据)。"""
    pos = start
    while pos < len(d) - 2:
        if d[pos] != 0x78 or d[pos + 1] not in (0x01, 0x9C, 0xDA):
            # 重新对齐到下一个可能的 zlib 头
            nxt = -1
            for c in (0x01, 0x9C, 0xDA):
                k = d.find(bytes([0x78, c]), pos + 1)
                if k >= 0 and (nxt < 0 or k < nxt):
                    nxt = k
            if nxt < 0:
                return
            pos = nxt
            continue
        o = zlib.decompressobj()
        try:
            out = o.decompress(d[pos:])
        except Exception:
            pos += 1
            continue
        consumed = (len(d) - pos) - len(o.unused_data)
        if consumed <= 0:
            pos += 1
            continue
        yield pos, consumed, out
        pos += consumed


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], sys.argv[2]
    d = open(src, "rb").read()
    os.makedirs(outdir, exist_ok=True)

    # overlay 起点：最后一个节的 raw 末尾
    import struct
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    so = e + 24 + optsz
    overlay = 0
    for i in range(nsec):
        o = so + i * 40
        rs, ra = struct.unpack_from("<II", d, o + 16)
        overlay = max(overlay, ra + rs)
    print("installer : %s" % src)
    print("size      : %d" % len(d))
    print("sha256    : %s" % hashlib.sha256(d).hexdigest())
    print("overlay   : 0x%X" % overlay)

    n = 0
    saved = []
    for off, clen, data in iter_zlib_streams(d, overlay):
        n += 1
        # 找出这条流里所有 PE 映像
        p = 0
        while True:
            j = data.find(PE_MAGIC, p)
            if j < 0:
                break
            sz = pe_size(data, j)
            if sz and sz <= len(data) - j and sz > 0x1000:
                blob = data[j:j + sz]
                # 取 PE 里的版本资源名做文件名提示
                name = "entry%03d_off%X.exe" % (n, j)
                fp = os.path.join(outdir, name)
                open(fp, "wb").write(blob)
                sha = hashlib.sha256(blob).hexdigest()
                saved.append((fp, len(blob), sha))
                print("  [+] stream#%d @0x%X  %s  %d bytes  sha256=%s"
                      % (n, off, name, len(blob), sha))
                p = j + sz
            else:
                p = j + 2
        if n % 25 == 0:
            print("  ... %d streams scanned" % n)

    print("\ntotal zlib streams: %d" % n)
    print("PE files extracted: %d" % len(saved))
    for fp, ln, sha in saved:
        print("  %s  %d  %s" % (fp, ln, sha))
    return 0


if __name__ == "__main__":
    sys.exit(main())
