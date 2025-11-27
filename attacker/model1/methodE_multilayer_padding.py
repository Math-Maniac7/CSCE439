#!/usr/bin/env python3
"""
Method E - Multi-layer Padding with Entropy Balancing

Technique:
1. Apply multiple layers of padding with different patterns
2. Balance entropy (mix high and low entropy regions)
3. Add metadata mutations
4. Create complex byte distribution patterns

Evasion rationale:
- Multi-layer padding creates complex byte distributions
- Entropy balancing confuses entropy-based detection
- Multiple patterns dilute signature matches
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path


METHOD_NAME = "methodE_multilayer_padding"
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


def modify_pe_metadata(pe_path: Path) -> bool:
    """Modify PE metadata"""
    try:
        import pefile
        pe = pefile.PE(str(pe_path))
        
        # Randomize timestamp
        pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
        
        # Zero checksum
        pe.OPTIONAL_HEADER.CheckSum = 0
        
        pe.write(str(pe_path))
        pe.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def add_multilayer_padding(file_path: Path) -> None:
    """Add multi-layer padding with entropy balancing"""
    data = file_path.read_bytes()
    
    # Layer 1: Low entropy (repetitive patterns)
    layer1 = bytearray()
    layer1.extend(b"\x00" * 200000)  # Null padding
    layer1.extend(b"Microsoft\x00" * 5000)  # Repetitive strings
    layer1.extend(b"Windows\x00" * 5000)
    
    # Layer 2: Medium entropy (mixed patterns)
    layer2 = bytearray()
    patterns = [
        b"Microsoft Corporation\x00",
        b"Windows Operating System\x00",
        b"Copyright (C) 2024\x00",
        b"Version 10.0\x00",
    ]
    for _ in range(10000):
        layer2.extend(random.choice(patterns))
    
    # Layer 3: Higher entropy (more random, but still structured)
    layer3 = bytearray()
    for _ in range(50000):
        # Create structured but varied patterns
        prefix = random.choice([b"MS", b"WIN", b"SYS", b"LIB"])
        suffix = bytes([random.randint(32, 126) for _ in range(8)])
        layer3.extend(prefix + suffix + b"\x00")
    
    # Combine layers
    total_size = random.randint(1_000_000, 2_000_000)
    overlay = bytearray()
    
    # Mix layers in proportion
    layer1_size = total_size // 3
    layer2_size = total_size // 3
    layer3_size = total_size - layer1_size - layer2_size
    
    overlay.extend(layer1[:layer1_size])
    overlay.extend(layer2[:layer2_size])
    overlay.extend(layer3[:layer3_size])
    
    # Fill remaining with nulls if needed
    if len(overlay) < total_size:
        overlay.extend(b"\x00" * (total_size - len(overlay)))
    
    final_data = data + bytes(overlay[:total_size])
    file_path.write_bytes(final_data)
    print(f"      ✓ Added {total_size:,} bytes multi-layer padding")


def multilayer_padding_transform(src: Path, dst: Path) -> None:
    """Apply multi-layer padding"""
    print(f"    -> Multi-layer padding for {src.name}")
    
    # Copy file
    shutil.copy2(src, dst)
    
    # Try to modify PE metadata
    if modify_pe_metadata(dst):
        print("      ✓ Modified PE metadata")
    
    # Always add multi-layer padding
    add_multilayer_padding(dst)


def process_files(input_dir: Path, output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = collect_inputs(input_dir)
    rows = []
    success = 0
    fail = 0

    print(f"Found {len(files)} files")
    for idx, src in enumerate(files, 1):
        print(f"[{idx}/{len(files)}] {src.name}")
        dst = output_dir / src.name
        base_sha = sha256_of(src)
        start = time.time()

        try:
            multilayer_padding_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "multilayer_padding",
                }
            )
            success += 1
        except Exception as exc:
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": "",
                    "status": "FAIL",
                    "duration_sec": "0.000",
                    "notes": f"error: {str(exc)[:120]}",
                }
            )
            fail += 1

    report_file = output_dir / "compare_report.csv"
    with report_file.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "filename",
                "baseline_sha256",
                "output_sha256",
                "status",
                "duration_sec",
                "notes",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    sha_file = output_dir / "sha256sums.txt"
    with sha_file.open("w") as handle:
        for row in rows:
            if row["status"] == "OK":
                handle.write(f'{row["output_sha256"]}  {output_dir / row["filename"]}\n')

    print("\nSummary")
    print("-------")
    print(f"Success: {success} | Fail: {fail} | Total: {len(files)}")
    print(f"Outputs:\n - {report_file}\n - {sha_file}")


def run_pipeline(archive_path: Path, work_root: Path, output_zip: Path) -> None:
    input_dir = work_root / "input"
    output_dir = work_root / "output"
    extract_dataset(archive_path, input_dir)
    process_files(input_dir, output_dir)
    compress_outputs(output_dir, output_zip)
    print(f"\nPackaging complete -> {output_zip}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Method E: Multi-layer Padding with Entropy Balancing"
    )
    parser.add_argument(
        "--archive",
        default=str(DEFAULT_ARCHIVE),
        help="Path to the zipped dataset",
    )
    parser.add_argument(
        "--work-root",
        default=str(DEFAULT_WORK_ROOT),
        help="Working directory",
    )
    parser.add_argument(
        "--output-zip",
        default=str(DEFAULT_OUTPUT_ZIP),
        help="Output zip file",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    run_pipeline(
        Path(args.archive).expanduser().resolve(),
        Path(args.work_root).expanduser().resolve(),
        Path(args.output_zip).expanduser().resolve(),
    )


if __name__ == "__main__":
    main()

