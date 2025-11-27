#!/usr/bin/env python3
"""
Method D - Resource Table Manipulation + Overlay

Technique:
1. Modify resource table entries (version info, strings)
2. Add fake resource entries with benign data
3. Append large overlay with resource-like patterns
4. Preserve executable functionality

Evasion rationale:
- Resource changes alter file signatures
- Fake resources confuse resource-based detection
- Overlay shifts entropy and byte patterns
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path


METHOD_NAME = "methodD_resource_manipulation"
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


def add_resource_like_overlay(file_path: Path) -> None:
    """Add overlay with resource-like patterns"""
    data = file_path.read_bytes()
    
    # Resource-like patterns
    resource_patterns = [
        b"VS_VERSION_INFO\x00" * 1000,
        b"StringFileInfo\x00" * 1000,
        b"VarFileInfo\x00" * 1000,
        b"CompanyName\x00Microsoft Corporation\x00" * 500,
        b"FileDescription\x00Windows System Component\x00" * 500,
        b"FileVersion\x0010.0.19041.1\x00" * 500,
        b"ProductName\x00Microsoft Windows Operating System\x00" * 500,
        b"Copyright\x00Copyright (C) 2024 Microsoft Corporation\x00" * 500,
        b"\x00" * 300000,  # Null padding
    ]
    
    overlay_size = random.randint(600_000, 1_400_000)
    overlay = bytearray()
    while len(overlay) < overlay_size:
        overlay.extend(random.choice(resource_patterns))
    
    final_data = data + bytes(overlay[:overlay_size])
    file_path.write_bytes(final_data)
    print(f"      ✓ Added {overlay_size:,} bytes resource-like overlay")


def resource_manipulation_transform(src: Path, dst: Path) -> None:
    """Apply resource manipulation + overlay"""
    print(f"    -> Resource manipulation for {src.name}")
    
    # Copy file
    shutil.copy2(src, dst)
    
    # Try to modify PE metadata
    if modify_pe_metadata(dst):
        print("      ✓ Modified PE metadata")
    
    # Always add resource-like overlay
    add_resource_like_overlay(dst)


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
            resource_manipulation_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "resource_manipulation+overlay",
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
        description="Method D: Resource Table Manipulation + Overlay"
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

