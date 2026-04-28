import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
import os
import json
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
import secrets

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLOR_BG = "#0a0e17"
COLOR_ACCENT = "#00ffcc"     
COLOR_BUTTON = "#1e3a8a"
COLOR_BUTTON_HOVER = "#3b82f6"
COLOR_HEADER = "#1e40af"
COLOR_DANGER = "#b91c1c"

STORAGE_FOLDER = "storage"
USERS_FILE = "users.json"
ATTACK_LOG = "attack_logs.txt"

if not os.path.exists(STORAGE_FOLDER):
    os.makedirs(STORAGE_FOLDER)

ph = PasswordHasher()

def log_attack(username, reason):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(ATTACK_LOG, 'a') as f:
        f.write(f"[{timestamp}] User: {username} | Reason: {reason}\n")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def derive_key(password: str, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    key, salt = derive_key(password)
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(salt + iv + ciphertext)
    hmac_tag = h.finalize()

    encrypted_data = salt + iv + hmac_tag + ciphertext
    filename = os.path.basename(file_path)
    enc_path = os.path.join(STORAGE_FOLDER, f"{filename}.enc")

    with open(enc_path, 'wb') as f:
        f.write(encrypted_data)
    return enc_path

def decrypt_file(enc_filename: str, password: str):
    enc_path = os.path.join(STORAGE_FOLDER, enc_filename)
    with open(enc_path, 'rb') as f:
        data = f.read()

    salt = data[0:16]
    iv = data[16:32]
    hmac_tag = data[32:64]
    ciphertext = data[64:]

    key, _ = derive_key(password, salt)

    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(salt + iv + ciphertext)
    try:
        h.verify(hmac_tag)
    except Exception:
        messagebox.showerror("Attack Detected", "File integrity check FAILED!\nPossible tampering detected!")
        return None

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    original = unpadder.update(padded) + unpadder.finalize()

    original_name = enc_filename.replace('.enc', '')
    out_path = os.path.join(STORAGE_FOLDER, f"decrypted_{original_name}")

    with open(out_path, 'wb') as f:
        f.write(original)
    return out_path

class SecureXApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureX : File Security & Attack Detection System")
        self.geometry("1020x680")
        self.configure(fg_color=COLOR_BG)

        self.current_user = None
        self.current_password = None

        self.show_login_screen()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_window()

        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="#111827")
        frame.pack(pady=90, padx=140, fill="both", expand=True)

        ctk.CTkLabel(frame, text="SecureX", font=ctk.CTkFont(size=48, weight="bold"), text_color=COLOR_ACCENT).pack(pady=(50, 10))
        ctk.CTkLabel(frame, text="File Security & Attack Detection System", font=ctk.CTkFont(size=18), text_color="#94a3b8").pack(pady=8)

        self.username_entry = ctk.CTkEntry(frame, placeholder_text="Username", width=340, height=50, font=ctk.CTkFont(size=15))
        self.username_entry.pack(pady=20)

        self.password_entry = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=340, height=50, font=ctk.CTkFont(size=15))
        self.password_entry.pack(pady=10)

        ctk.CTkButton(frame, text="LOGIN", width=340, height=55, font=ctk.CTkFont(size=16, weight="bold"),
                      fg_color=COLOR_BUTTON, hover_color=COLOR_BUTTON_HOVER, command=self.login).pack(pady=25)

        ctk.CTkButton(frame, text="Register New User", width=340, height=45, fg_color="transparent", 
                      border_width=2, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT, command=self.show_register_screen).pack()

    def show_register_screen(self):
        self.clear_window()
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="#111827")
        frame.pack(pady=90, padx=140, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Create Account", font=ctk.CTkFont(size=32, weight="bold"), text_color=COLOR_ACCENT).pack(pady=40)

        self.reg_username = ctk.CTkEntry(frame, placeholder_text="Username", width=340, height=50)
        self.reg_username.pack(pady=15)

        self.reg_password = ctk.CTkEntry(frame, placeholder_text="Password (min 8 characters)", show="*", width=340, height=50)
        self.reg_password.pack(pady=15)

        ctk.CTkButton(frame, text="REGISTER", width=340, height=55, command=self.register).pack(pady=30)
        ctk.CTkButton(frame, text="Back to Login", width=340, fg_color="transparent", command=self.show_login_screen).pack()

    def register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()

        if not username or len(password) < 8:
            messagebox.showerror("Error", "Username and password (min 8 chars) required!")
            return

        users = load_users()
        if username in users:
            messagebox.showerror("Error", "Username already exists!")
            return

        users[username] = {
            "password_hash": ph.hash(password),
            "failed_attempts": 0,
            "lock_until": 0
        }
        save_users(users)
        messagebox.showinfo("Success", f"User '{username}' registered successfully!")
        self.show_login_screen()

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        users = load_users()
        if username not in users:
            messagebox.showerror("Error", "Invalid username!")
            log_attack(username, "Invalid username attempt")
            return

        user = users[username]
        if user.get("lock_until", 0) > time.time():
            remaining = int(user["lock_until"] - time.time())
            messagebox.showerror("Account Locked", f"Account is locked!\nTry again in {remaining} seconds.")
            return

        try:
            ph.verify(user["password_hash"], password)
            user["failed_attempts"] = 0
            user["lock_until"] = 0
            save_users(users)

            self.current_user = username
            self.current_password = password
            messagebox.showinfo("Welcome", f"Login successful!\nWelcome back, {username}")
            self.show_dashboard()

        except VerifyMismatchError:
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            save_users(users)

            if user["failed_attempts"] >= 5:
                user["lock_until"] = time.time() + 300
                save_users(users)
                messagebox.showerror("Locked", "Too many failed attempts!\nAccount locked for 5 minutes.")
                log_attack(username, "Brute force attack - Account locked")
            else:
                messagebox.showerror("Error", f"Wrong password! {5 - user['failed_attempts']} attempts remaining.")
                log_attack(username, f"Wrong password attempt ({user['failed_attempts']}/5)")

    def show_dashboard(self):
        self.clear_window()

        # Header
        header = ctk.CTkFrame(self, height=100, fg_color=COLOR_HEADER)
        header.pack(fill="x")
        ctk.CTkLabel(header, text="SecureX", font=ctk.CTkFont(size=28, weight="bold"), text_color=COLOR_ACCENT).pack(side="left", padx=40, pady=25)
        ctk.CTkLabel(header, text=f"Logged in as: {self.current_user}", font=ctk.CTkFont(size=16), text_color="white").pack(side="right", padx=40, pady=25)

        # Main Buttons Frame
        main_frame = ctk.CTkFrame(self, fg_color="#111827", corner_radius=15)
        main_frame.pack(pady=50, padx=80, fill="both", expand=True)

        buttons = [
            ("📤  Upload & Encrypt File", self.upload_file),
            ("📋  List Secured Files", self.list_files),
            ("📥  Download & Decrypt File", self.download_file),
            ("🗑️  Delete File", self.delete_file),
            ("⚠️  View Attack Logs", self.view_logs),
        ]

        for text, command in buttons:
            ctk.CTkButton(main_frame, text=text, width=420, height=60, font=ctk.CTkFont(size=16),
                          fg_color=COLOR_BUTTON, hover_color=COLOR_BUTTON_HOVER, command=command).pack(pady=14)

        ctk.CTkButton(main_frame, text="Logout", width=420, height=50, fg_color=COLOR_DANGER,
                      hover_color="#ef4444", font=ctk.CTkFont(size=16), command=self.logout).pack(pady=25)

    def upload_file(self):
        filepath = filedialog.askopenfilename(title="Select file to secure")
        if not filepath:
            return
        try:
            encrypt_file(filepath, self.current_password)
            messagebox.showinfo("Success", "File successfully encrypted and secured!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def list_files(self):
        files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
        if not files:
            messagebox.showinfo("No Files", "No secured files found.")
            return
        text = "\n".join([f"• {f}" for f in files])
        messagebox.showinfo("Secured Files", f"Total Files: {len(files)}\n\n{text}")

    def download_file(self):
        files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
        if not files:
            messagebox.showinfo("Info", "No files available to download.")
            return

        choice = simpledialog.askstring("Download", "Enter file number to download:\n\n" + 
                                       "\n".join([f"{i+1}. {f}" for i, f in enumerate(files)]))
        if not choice:
            return
        try:
            idx = int(choice) - 1
            selected = files[idx]
            result = decrypt_file(selected, self.current_password)
            if result:
                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as:\n{result}")
        except:
            messagebox.showerror("Error", "Invalid selection!")

    def delete_file(self):
        files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
        if not files:
            messagebox.showinfo("Info", "No files to delete.")
            return

        choice = simpledialog.askstring("Delete", "Enter file number to delete:\n\n" + 
                                       "\n".join([f"{i+1}. {f}" for i, f in enumerate(files)]))
        if not choice:
            return
        try:
            idx = int(choice) - 1
            selected = files[idx]
            if messagebox.askyesno("Confirm Delete", f"Delete {selected} permanently?"):
                os.remove(os.path.join(STORAGE_FOLDER, selected))
                messagebox.showinfo("Success", "File deleted successfully.")
        except:
            messagebox.showerror("Error", "Invalid selection!")

    def view_logs(self):
        if not os.path.exists(ATTACK_LOG):
            messagebox.showinfo("Attack Logs", "No attack logs recorded yet.")
            return
        with open(ATTACK_LOG, 'r') as f:
            logs = f.read().strip()
        if logs:
            messagebox.showinfo("Attack Logs", logs)
        else:
            messagebox.showinfo("Attack Logs", "No attacks detected yet.")

    def logout(self):
        self.current_user = None
        self.current_password = None
        self.show_login_screen()

if __name__ == "__main__":
    app = SecureXApp()
    app.mainloop()