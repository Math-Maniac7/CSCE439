#!/usr/bin/env python3
import os

print(f"Current working directory: {os.getcwd()}")

files_to_check = [
    "defender/models/nfs_full.pickle",
    "defender/models/nfs_behemot/nfs_extractor_tfidf.pkl",
    "defender/models/nfs_behemot/nfs_scaler_minmax.pkl"
]

print("\nChecking for model files from defender/ directory...")
for file_path in files_to_check:
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        print(f"✅ {file_path} - {size} bytes")
        if size < 1000:
            print(f"   ⚠️  File seems very small - might be dummy")
    else:
        print(f"❌ {file_path} - NOT FOUND")

# Also check the absolute paths
print("\nChecking absolute paths...")
abs_files = [
    os.path.abspath("defender/models/nfs_full.pickle"),
    os.path.abspath("defender/models/nfs_behemot/nfs_extractor_tfidf.pkl"),
    os.path.abspath("defender/models/nfs_behemot/nfs_scaler_minmax.pkl")
]

for file_path in abs_files:
    print(f"Checking: {file_path}")
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        print(f"✅ EXISTS - {size} bytes")
    else:
        print(f"❌ NOT FOUND")
