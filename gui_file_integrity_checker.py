import hashlib
import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

# === File Hash Logic ===
HASH_DB = "file_hashes.json"
LOG_FILE = "log.txt"

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
        return "[!] File not found!", "error"

    if os.path.exists(HASH_DB):
        with open(HASH_DB, "r") as db:
            hashes = json.load(db)
    else:
        hashes = {}

    hashes[file_path] = hash_value

    with open(HASH_DB, "w") as db:
        json.dump(hashes, db, indent=4)
    
    return f"[+] Hash stored for: {file_path}", "info"

def check_integrity(file_path):
    current_hash = calculate_hash(file_path)
    if not current_hash:
        return "[!] File not found!", "error"

    try:
        with open(HASH_DB, "r") as db:
            hashes = json.load(db)
    except FileNotFoundError:
        return "[!] No stored hash database found!", "error"

    original_hash = hashes.get(file_path)

    if not original_hash:
        return f"[!] No stored hash for: {file_path}", "error"

    if current_hash == original_hash:
        return f"[✓] File integrity verified: {file_path}", "success"
    else:
        return f"[✗] File has been modified: {file_path}", "warning"

def list_hashes():
    if not os.path.exists(HASH_DB):
        return "[!] No stored hashes found.", "error"
    
    with open(HASH_DB, "r") as db:
        hashes = json.load(db)

    if not hashes:
        return "[!] Hash database is empty.", "error"

    output = "[*] Stored File Hashes:\n"
    for file, hash_val in hashes.items():
        output += f"• {file} → {hash_val}\n"
    
    return output.strip(), "info"

def reset_hash_db():
    if os.path.exists(HASH_DB):
        os.remove(HASH_DB)
        return "[✔] Hash database reset successfully.", "success"
    else:
        return "[!] No hash database found to delete.", "error"

# === GUI Functions ===
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def show_output(message, status):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    colors = {
        "success": "#00FF7F",
        "warning": "#FF4C4C",
        "error": "#FF4C4C",
        "info": "#00FFD1"
    }
    output_box.config(state='normal')
    output_box.insert(tk.END, timestamp + message + "\n", status)
    output_box.tag_config(status, foreground=colors.get(status, "#E0E0E0"))
    output_box.config(state='disabled')
    output_box.see(tk.END)

def store_action():
    file_path = entry.get()
    result, status = store_hash(file_path)
    show_output(result, status)

def check_action():
    file_path = entry.get()
    result, status = check_integrity(file_path)
    show_output(result, status)

def list_action():
    result, status = list_hashes()
    show_output(result, status)

def reset_action():
    confirm = messagebox.askyesno("Confirm Reset", "Are you sure you want to delete all stored hashes?")
    if confirm:
        result, status = reset_hash_db()
        show_output(result, status)

def export_log():
    try:
        content = output_box.get("1.0", tk.END).strip()
        with open(LOG_FILE, "w", encoding="utf-8") as log:
            log.write(content)
        show_output(f"[✓] Log exported to {LOG_FILE}", "success")
    except Exception as e:
        show_output(f"[!] Failed to export log: {e}", "error")


# === Main GUI ===
root = tk.Tk()
root.title("🛡️ File Integrity Checker")
root.geometry("780x540")
root.configure(bg="#0F1117")

# === Widgets ===
label = tk.Label(root, text="Select File to Monitor:", fg="#E0E0E0", bg="#0F1117", font=("Segoe UI", 12))
label.pack(pady=10)

entry = tk.Entry(root, width=60, font=("Consolas", 11), bg="#1A1D24", fg="#00FFD1", insertbackground="#00FFD1")
entry.pack(pady=5)

browse_btn = tk.Button(root, text="📁 Browse", command=browse_file,
                       bg="#00FFD1", fg="#0F1117", font=("Segoe UI", 10), activebackground="#00BFA6")
browse_btn.pack(pady=5)

btn_frame = tk.Frame(root, bg="#0F1117")
btn_frame.pack(pady=10)

store_btn = tk.Button(btn_frame, text="💾 Store Hash", command=store_action,
                      bg="#00FFD1", fg="#0F1117", width=15, font=("Segoe UI", 10), activebackground="#00BFA6")
store_btn.grid(row=0, column=0, padx=8)

check_btn = tk.Button(btn_frame, text="🔍 Check Integrity", command=check_action,
                      bg="#00FFD1", fg="#0F1117", width=15, font=("Segoe UI", 10), activebackground="#00BFA6")
check_btn.grid(row=0, column=1, padx=8)

list_btn = tk.Button(btn_frame, text="📄 View Hash List", command=list_action,
                     bg="#00FFD1", fg="#0F1117", width=15, font=("Segoe UI", 10), activebackground="#00BFA6")
list_btn.grid(row=0, column=2, padx=8)

reset_btn = tk.Button(btn_frame, text="🧹 Reset DB", command=reset_action,
                      bg="#FF4C4C", fg="#FFFFFF", width=15, font=("Segoe UI", 10), activebackground="#D13636")
reset_btn.grid(row=0, column=3, padx=8)

export_btn = tk.Button(root, text="📝 Export Log", command=export_log,
                       bg="#00FFD1", fg="#0F1117", font=("Segoe UI", 10), activebackground="#00BFA6")
export_btn.pack(pady=5)

output_box = tk.Text(root, height=15, width=95, bg="#1A1D24", fg="#E0E0E0",
                     font=("Consolas", 10), state='disabled', wrap='word')
output_box.pack(pady=10)

root.mainloop()
