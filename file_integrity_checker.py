import hashlib
import os
import json
import argparse

# File to store original hashes
HASH_DB = "file_hashes.json"

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def store_hash(file_path):
    hash_value = calculate_hash(file_path)
    if not hash_value:
        print(f"[!] File not found: {file_path}")
        return

    if os.path.exists(HASH_DB):
        with open(HASH_DB, "r") as db:
            hashes = json.load(db)
    else:
        hashes = {}

    hashes[file_path] = hash_value

    with open(HASH_DB, "w") as db:
        json.dump(hashes, db, indent=4)
    
    print(f"[+] Hash stored for: {file_path}")

def check_integrity(file_path):
    current_hash = calculate_hash(file_path)
    if not current_hash:
        print(f"[!] File not found: {file_path}")
        return

    try:
        with open(HASH_DB, "r") as db:
            hashes = json.load(db)
    except FileNotFoundError:
        print("[!] Hash database not found. Run store mode first.")
        return

    original_hash = hashes.get(file_path)

    if not original_hash:
        print(f"[!] No stored hash for: {file_path}")
        return

    if current_hash == original_hash:
        print(f"[✓] File integrity verified: {file_path}")
    else:
        print(f"[✗] File has been modified: {file_path}")

# CLI setup
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("mode", choices=["store", "check"], help="Mode: store or check")
    parser.add_argument("file", help="Path to file")
    args = parser.parse_args()

    if args.mode == "store":
        store_hash(args.file)
    elif args.mode == "check":
        check_integrity(args.file)
