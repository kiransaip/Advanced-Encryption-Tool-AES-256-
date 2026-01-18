import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

backend = default_backend()

# ---------- KEY DERIVATION ----------
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # AES-256
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

# ---------- ENCRYPT ----------
def encrypt_file(file_path, password):
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)

    with open(file_path, "rb") as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(salt + iv + encrypted)

    return encrypted_file

# ---------- DECRYPT ----------
def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    decrypted_file = file_path.replace(".enc", ".dec")
    with open(decrypted_file, "wb") as f:
        f.write(data)

    return decrypted_file

# ---------- GUI ----------
def select_file():
    path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, path)

def encrypt_action():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not password:
        messagebox.showerror("Error", "Select file and enter password")
        return

    try:
        output = encrypt_file(file_path, password)
        messagebox.showinfo("Success", f"Encrypted File:\n{output}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not password:
        messagebox.showerror("Error", "Select file and enter password")
        return

    try:
        output = decrypt_file(file_path, password)
        messagebox.showinfo("Success", f"Decrypted File:\n{output}")
    except Exception:
        messagebox.showerror("Error", "Wrong password or corrupted file")

# ---------- WINDOW ----------
root = tk.Tk()
root.title("Advanced AES-256 Encryption Tool")
root.geometry("450x250")
root.resizable(False, False)

tk.Label(root, text="File:", font=("Arial", 10)).pack(pady=5)
file_entry = tk.Entry(root, width=50)
file_entry.pack()
tk.Button(root, text="Browse", command=select_file).pack(pady=5)

tk.Label(root, text="Password:", font=("Arial", 10)).pack(pady=5)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

tk.Button(root, text="Encrypt", width=15, command=encrypt_action).pack(pady=10)
tk.Button(root, text="Decrypt", width=15, command=decrypt_action).pack()

root.mainloop()
