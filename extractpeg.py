"""
PEG 文件解包工具 (zstd压缩)
用法: python extractpeg.py <输出目录> <peg文件路径>
依赖: pip install zstandard

Author: Deneo
"""

import sys
import os
import struct
import hashlib
import zlib

try:
    import zstandard as zstd
except ImportError:
    print("[错误] 请先安装 zstandard: pip install zstandard")
    sys.exit(1)


def read_wstring(data, offset):
    """读取 UTF-16-LE 宽字符串，返回 (字符串, 新偏移)"""
    name_len = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    byte_len = name_len * 2  # UTF-16-LE: 每个字符2字节
    name = data[offset:offset + byte_len].decode('utf-16-le')
    offset += byte_len
    return name, offset


def extract_peg(peg_path, output_dir):
    with open(peg_path, 'rb') as f:
        data = f.read()

    offset = 0

    # ========== 1. 解析文件头 (magic: 1984) ==========
    magic = data[offset:offset + 4]
    if magic != b'1984':
        print(f"[错误] 文件头 magic 不匹配: {magic!r}, 期望: b'1984'")
        return
    offset += 4

    uncompressed_total_size = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    print(f"[文件头] 声明解压总大小: {uncompressed_total_size} 字节 ({uncompressed_total_size / 1024 / 1024:.2f} MB)")

    # 6字节数据:
    # 0x0C-0x0D: 未知 (01 00)
    # 0x0E-0x0F: PEG文件总数 (10 00 = 16个, 0-15)
    # 0x10-0x11: 当前PEG文件编号
    header_flags = data[offset:offset + 6]
    offset += 6
    unknown_flag = struct.unpack_from('<H', header_flags, 0)[0]
    total_pegs = struct.unpack_from('<H', header_flags, 2)[0]
    peg_number = struct.unpack_from('<H', header_flags, 4)[0]
    print(f"[文件头] 未知标志: {unknown_flag}, PEG总数: {total_pegs}, 当前编号: {peg_number}")

    file_size = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    print(f"[文件头] 文件大小: {file_size} 字节 ({file_size / 1024 / 1024:.2f} MB)")

    # ========== 2. 初始化 zstd 解压器 ==========
    dctx = zstd.ZstdDecompressor()

    # ========== 3. 解析目录和文件条目 ==========
    file_count = 0
    error_count = 0
    total_compressed = 0
    total_uncompressed = 0

    while offset < len(data):
        if offset + 4 > len(data):
            break

        entry_magic = data[offset:offset + 4]
        offset += 4

        # ---------- 目录项 (magic: 1982) ----------
        if entry_magic == b'1982':
            dir_path, offset = read_wstring(data, offset)
            full_dir = os.path.join(output_dir, dir_path.lstrip('\\').lstrip('/'))
            os.makedirs(full_dir, exist_ok=True)
            print(f"[目录] {dir_path}")

        # ---------- 文件项 (magic: 1989) ----------
        elif entry_magic == b'1989':
            compressed_size = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

            uncompressed_size = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

            file_hash = data[offset:offset + 12]
            offset += 12

            try:
                file_path, offset = read_wstring(data, offset)
            except UnicodeDecodeError:
                print(f"[错误] 解码文件名失败 @ offset 0x{offset:X}")
                print(f"  原始数据: {data[offset:offset+32].hex()}")
                break

            # 读取压缩数据
            compressed_data = data[offset:offset + compressed_size]
            offset += compressed_size

            # zstd 流式解压
            try:
                reader = dctx.stream_reader(compressed_data)
                chunks = []
                while True:
                    chunk = reader.read(256 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                decompressed_data = b''.join(chunks)
            except zstd.ZstdError as e:
                print(f"[错误] 解压失败: {file_path} - {e}")
                error_count += 1
                continue

            # 校验大小
            if len(decompressed_data) != uncompressed_size:
                print(f"[警告] 大小不匹配: {file_path} (期望 {uncompressed_size}, 实际 {len(decompressed_data)})")

            # 校验哈希
            stored_crc = struct.unpack_from('<I', file_hash, 0)[0]
            actual_crc = zlib.crc32(decompressed_data) & 0xFFFFFFFF
            
            # 解析 FILETIME
            filetime_raw = struct.unpack_from('<Q', file_hash, 4)[0]
            # FILETIME 转 Unix 时间戳
            FILETIME_EPOCH_DIFF = 116444736000000000  # 1601-1970 之间的100纳秒数
            if filetime_raw > FILETIME_EPOCH_DIFF:
                unix_ts = (filetime_raw - FILETIME_EPOCH_DIFF) / 10000000
                from datetime import datetime
                dt = datetime.fromtimestamp(unix_ts)
                time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            else:
                time_str = "N/A"
            
            if stored_crc != actual_crc:
                print(f"[警告] CRC32不匹配: {file_path}")
                print(f"  存储CRC32: 0x{stored_crc:08X}")
                print(f"  实际CRC32: 0x{actual_crc:08X}")
            else:
                print(f"[文件] {file_path} ({compressed_size} -> {len(decompressed_data)} 字节, CRC32: 0x{stored_crc:08X}, 时间: {time_str})")

            # 写入文件
            full_path = os.path.join(output_dir, file_path.lstrip('\\').lstrip('/'))
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'wb') as out_f:
                out_f.write(decompressed_data)

            file_count += 1
            total_compressed += compressed_size
            total_uncompressed += len(decompressed_data)

        # ---------- 遇到未知 magic 则停止 ----------
        else:
            print(f"[信息] 遇到未知 magic: {entry_magic!r} @ offset 0x{offset - 4:X}, 解析结束")
            break

    print(f"\n[完成] 共解压 {file_count} 个文件, {error_count} 个错误")
    print(f"[统计] 压缩数据总大小: {total_compressed} 字节 ({total_compressed / 1024 / 1024:.2f} MB)")
    print(f"[统计] 解压数据总大小: {total_uncompressed} 字节 ({total_uncompressed / 1024 / 1024:.2f} MB)")
    print(f"[统计] 文件头声明解压大小: {uncompressed_total_size} 字节 ({uncompressed_total_size / 1024 / 1024:.2f} MB)")
    print(f"[统计] 文件实际大小: {len(data)} 字节 ({len(data) / 1024 / 1024:.2f} MB)")
    print(f"[统计] 文件头声明文件大小: {file_size} 字节 ({file_size / 1024 / 1024:.2f} MB)")


def main():
    if len(sys.argv) != 3:
        print("用法: python extractpeg.py <输出目录> <peg文件路径>")
        print("示例: python extractpeg.py extracted MapleStoryM_2.430.6284_Live_1717.peg00")
        sys.exit(1)

    output_dir = sys.argv[1]
    peg_path = sys.argv[2]

    if not os.path.isfile(peg_path):
        print(f"[错误] 文件不存在: {peg_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    print(f"[开始] 解包 {peg_path} -> {output_dir}")
    extract_peg(peg_path, output_dir)


if __name__ == '__main__':
    main()
