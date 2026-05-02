from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from crypto_utils import (
    AuthenticationError,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    tamper_payload,
)

BASE_DIR = Path(__file__).resolve().parent
VAULT_DIR = BASE_DIR / "vault_data"
VAULT_DIR.mkdir(exist_ok=True)


class SecureVaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureVault - Secure Messaging / Vault")
        self.root.geometry("1180x760")
        self.root.minsize(1050, 700)
        self._configure_style()
        self._build_ui()
        self.refresh_file_list()

    def _configure_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        bg = "#f5f7fb"
        card = "#ffffff"
        primary = "#204ecf"
        text = "#172033"
        self.root.configure(bg=bg)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=card, relief="flat")
        style.configure("TLabel", background=bg, foreground=text, font=("Arial", 11))
        style.configure("Heading.TLabel", background=bg, foreground=text, font=("Arial", 22, "bold"))
        style.configure("Sub.TLabel", background=bg, foreground="#4f5d73", font=("Arial", 11))
        style.configure("Section.TLabel", background=card, foreground=text, font=("Arial", 13, "bold"))
        style.configure("TButton", font=("Arial", 11), padding=8)
        style.map("Accent.TButton", background=[("!disabled", primary)], foreground=[("!disabled", "white")])
        style.configure("Accent.TButton", background=primary, foreground="white")
        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 10), font=("Arial", 11, "bold"))

    def _card(self, parent):
        frame = ttk.Frame(parent, style="Card.TFrame", padding=16)
        frame.configure(relief="solid")
        return frame

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 16))
        ttk.Label(header, text="SecureVault", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local AES-based secure messaging and file vault with key handling, attack demo, and functional testing.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        self.message_tab = ttk.Frame(self.notebook, padding=10)
        self.file_tab = ttk.Frame(self.notebook, padding=10)
        self.attack_tab = ttk.Frame(self.notebook, padding=10)
        self.about_tab = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.message_tab, text="Message Vault")
        self.notebook.add(self.file_tab, text="File Vault")
        self.notebook.add(self.attack_tab, text="Attack Demo")
        self.notebook.add(self.about_tab, text="Project Notes")

        self._build_message_tab()
        self._build_file_tab()
        self._build_attack_tab()
        self._build_about_tab()

    def _build_message_tab(self):
        layout = ttk.Frame(self.message_tab)
        layout.pack(fill="both", expand=True)
        left = self._card(layout)
        right = self._card(layout)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left, text="Encrypt Message", style="Section.TLabel").pack(anchor="w")
        ttk.Label(left, text="Plaintext").pack(anchor="w", pady=(12, 4))
        self.plaintext_box = tk.Text(left, height=18, wrap="word", font=("Consolas", 11))
        self.plaintext_box.pack(fill="both", expand=True)
        ttk.Label(left, text="Password").pack(anchor="w", pady=(12, 4))
        self.msg_password = ttk.Entry(left, show="*", width=32)
        self.msg_password.pack(anchor="w")
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Encrypt Message", style="Accent.TButton", command=self.encrypt_message).pack(side="left")
        ttk.Button(btns, text="Load Sample", command=self.load_sample_message).pack(side="left", padx=8)
        ttk.Button(btns, text="Clear", command=lambda: self.plaintext_box.delete("1.0", "end")).pack(side="left")

        ttk.Label(right, text="Ciphertext / Decryption", style="Section.TLabel").pack(anchor="w")
        ttk.Label(right, text="Encrypted JSON payload").pack(anchor="w", pady=(12, 4))
        self.cipher_box = tk.Text(right, height=18, wrap="word", font=("Consolas", 10))
        self.cipher_box.pack(fill="both", expand=True)
        ttk.Label(right, text="Password for Decryption").pack(anchor="w", pady=(12, 4))
        self.decrypt_password = ttk.Entry(right, show="*", width=32)
        self.decrypt_password.pack(anchor="w")
        decrypt_btns = ttk.Frame(right)
        decrypt_btns.pack(fill="x", pady=(12, 0))
        ttk.Button(decrypt_btns, text="Decrypt Message", style="Accent.TButton", command=self.decrypt_message).pack(side="left")
        ttk.Button(decrypt_btns, text="Copy to Attack Demo", command=self.copy_to_attack_demo).pack(side="left", padx=8)
        self.msg_status = ttk.Label(right, text="Ready.")
        self.msg_status.pack(anchor="w", pady=(12, 0))

    def _build_file_tab(self):
        layout = ttk.Frame(self.file_tab)
        layout.pack(fill="both", expand=True)
        left = self._card(layout)
        right = self._card(layout)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left, text="Encrypt Local File", style="Section.TLabel").pack(anchor="w")
        self.file_path_var = tk.StringVar(value="No file selected.")
        ttk.Label(left, textvariable=self.file_path_var, wraplength=420).pack(anchor="w", pady=(12, 8))
        ttk.Button(left, text="Choose File", command=self.choose_file).pack(anchor="w")
        ttk.Label(left, text="Password").pack(anchor="w", pady=(14, 4))
        self.file_password = ttk.Entry(left, show="*", width=32)
        self.file_password.pack(anchor="w")
        ttk.Button(left, text="Encrypt and Save to Vault", style="Accent.TButton", command=self.encrypt_selected_file).pack(anchor="w", pady=(12, 10))
        ttk.Label(left, text="Vault output folder: vault_data/").pack(anchor="w")
        self.file_status = ttk.Label(left, text="Ready.")
        self.file_status.pack(anchor="w", pady=(12, 0))

        ttk.Label(right, text="Decrypt File from Vault", style="Section.TLabel").pack(anchor="w")
        self.file_list = tk.Listbox(right, height=16, font=("Consolas", 11))
        self.file_list.pack(fill="both", expand=True, pady=(12, 10))
        ttk.Button(right, text="Refresh Vault List", command=self.refresh_file_list).pack(anchor="w")
        ttk.Label(right, text="Password").pack(anchor="w", pady=(12, 4))
        self.file_decrypt_password = ttk.Entry(right, show="*", width=32)
        self.file_decrypt_password.pack(anchor="w")
        ttk.Button(right, text="Decrypt Selected File", style="Accent.TButton", command=self.decrypt_selected_file).pack(anchor="w", pady=(12, 0))

    def _build_attack_tab(self):
        layout = ttk.Frame(self.attack_tab)
        layout.pack(fill="both", expand=True)
        left = self._card(layout)
        right = self._card(layout)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left, text="Attack Input", style="Section.TLabel").pack(anchor="w")
        ttk.Label(left, text="Ciphertext JSON payload").pack(anchor="w", pady=(12, 4))
        self.attack_payload = tk.Text(left, height=20, wrap="word", font=("Consolas", 10))
        self.attack_payload.pack(fill="both", expand=True)
        ttk.Label(left, text="Password to test").pack(anchor="w", pady=(12, 4))
        self.attack_password = ttk.Entry(left, show="*", width=32)
        self.attack_password.pack(anchor="w")
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Try Decrypt", style="Accent.TButton", command=self.try_attack_decrypt).pack(side="left")
        ttk.Button(btns, text="Tamper Payload", command=self.make_tampered_payload).pack(side="left", padx=8)
        ttk.Button(btns, text="Load Demo Payload", command=self.load_demo_attack_payload).pack(side="left")

        ttk.Label(right, text="Attack Result", style="Section.TLabel").pack(anchor="w")
        self.attack_result = tk.Text(right, height=20, wrap="word", font=("Consolas", 11))
        self.attack_result.pack(fill="both", expand=True, pady=(12, 0))
        self.attack_result.insert(
            "1.0",
            "Wrong password or modified ciphertext should fail.\n\nThis demonstrates that plaintext is not revealed without the correct secret.",
        )
        self.attack_result.configure(state="disabled")

    def _build_about_tab(self):
        card = self._card(self.about_tab)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="Project Notes", style="Section.TLabel").pack(anchor="w")
        text = tk.Text(card, wrap="word", font=("Arial", 11), height=26)
        text.pack(fill="both", expand=True, pady=(12, 0))
        text.insert(
            "1.0",
            "1. GUI is local and uses Tkinter.\n"
            "2. Messages and files are encrypted locally.\n"
            "3. Key handling uses PBKDF2-HMAC-SHA256 with a random salt.\n"
            "4. AES-256 encrypts the content before it is stored.\n"
            "5. Attack demo shows failed decryption when the password is wrong or ciphertext is modified.\n"
            "6. Use local/test data only, as requested in the project guideline.\n"
            "7. For class demo: show message encryption, file encryption, wrong-password failure, and successful file recovery."
        )
        text.configure(state="disabled")

    def load_sample_message(self):
        sample = (
            "Meeting code: 320-SAFE\n"
            "Temporary OTP: 481982\n"
            "Reminder: use test data only for the class demonstration."
        )
        self.plaintext_box.delete("1.0", "end")
        self.plaintext_box.insert("1.0", sample)

    def encrypt_message(self):
        plaintext = self.plaintext_box.get("1.0", "end").strip()
        password = self.msg_password.get().strip()
        if not plaintext or not password:
            messagebox.showerror("Missing data", "Enter both plaintext and password.")
            return
        payload = encrypt_text(plaintext, password)
        self.cipher_box.delete("1.0", "end")
        self.cipher_box.insert("1.0", payload)
        self.msg_status.config(text="Message encrypted successfully.")

    def decrypt_message(self):
        payload = self.cipher_box.get("1.0", "end").strip()
        password = self.decrypt_password.get().strip()
        if not payload or not password:
            messagebox.showerror("Missing data", "Provide ciphertext and password.")
            return
        try:
            plaintext = decrypt_text(payload, password)
        except (AuthenticationError, json.JSONDecodeError, KeyError, ValueError) as exc:
            messagebox.showerror("Decryption failed", str(exc))
            self.msg_status.config(text="Decryption failed.")
            return
        self.plaintext_box.delete("1.0", "end")
        self.plaintext_box.insert("1.0", plaintext)
        self.msg_status.config(text="Message decrypted successfully.")

    def copy_to_attack_demo(self):
        payload = self.cipher_box.get("1.0", "end").strip()
        if not payload:
            messagebox.showerror("No data", "Encrypt a message first.")
            return
        self.attack_payload.delete("1.0", "end")
        self.attack_payload.insert("1.0", payload)
        self.attack_password.delete(0, "end")
        self.attack_password.insert(0, self.decrypt_password.get() or self.msg_password.get())
        messagebox.showinfo("Copied", "Ciphertext was copied to the Attack Demo tab.")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Choose a local test file")
        if path:
            self.file_path_var.set(path)

    def encrypt_selected_file(self):
        source = self.file_path_var.get()
        password = self.file_password.get().strip()
        if source == "No file selected." or not password:
            messagebox.showerror("Missing data", "Choose a file and enter a password.")
            return
        source_path = Path(source)
        output_path = VAULT_DIR / f"{source_path.stem}.svault"
        encrypt_file(source_path, output_path, password)
        self.file_status.config(text=f"Encrypted file saved: {output_path.name}")
        self.refresh_file_list()

    def refresh_file_list(self):
        self.file_list.delete(0, "end")
        for item in sorted(VAULT_DIR.glob("*.svault")):
            self.file_list.insert("end", item.name)

    def decrypt_selected_file(self):
        selection = self.file_list.curselection()
        password = self.file_decrypt_password.get().strip()
        if not selection or not password:
            messagebox.showerror("Missing data", "Select a vault file and enter a password.")
            return
        selected = self.file_list.get(selection[0])
        output_dir = filedialog.askdirectory(title="Choose output folder")
        if not output_dir:
            return
        try:
            restored_path = decrypt_file(VAULT_DIR / selected, output_dir, password)
        except Exception as exc:
            messagebox.showerror("Decryption failed", str(exc))
            return
        messagebox.showinfo("Success", f"Recovered file: {restored_path.name}")

    def load_demo_attack_payload(self):
        demo_payload = encrypt_text("This message should stay protected.", "Demo@123")
        self.attack_payload.delete("1.0", "end")
        self.attack_payload.insert("1.0", demo_payload)
        self.attack_password.delete(0, "end")
        self.attack_password.insert(0, "WrongPass")
        self._set_attack_text("Demo payload loaded. Now try decrypting with the wrong password first.")

    def try_attack_decrypt(self):
        payload = self.attack_payload.get("1.0", "end").strip()
        password = self.attack_password.get().strip()
        if not payload or not password:
            messagebox.showerror("Missing data", "Provide payload and password.")
            return
        try:
            plaintext = decrypt_text(payload, password)
        except Exception as exc:
            self._set_attack_text(
                "Attack attempt failed as expected.\n\n"
                f"Reason: {exc}\n\n"
                "Conclusion: without the correct password, the attacker cannot recover the original message."
            )
            return
        self._set_attack_text(
            "Decryption succeeded.\n\n"
            f"Recovered plaintext: {plaintext}\n\n"
            "Use this only to demonstrate that the correct secret is required."
        )

    def make_tampered_payload(self):
        payload = self.attack_payload.get("1.0", "end").strip()
        if not payload:
            messagebox.showerror("No data", "Load or copy a payload first.")
            return
        try:
            modified = tamper_payload(payload)
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            return
        self.attack_payload.delete("1.0", "end")
        self.attack_payload.insert("1.0", modified)
        self._set_attack_text("Payload was modified. The next decryption attempt should fail.")

    def _set_attack_text(self, text: str):
        self.attack_result.configure(state="normal")
        self.attack_result.delete("1.0", "end")
        self.attack_result.insert("1.0", text)
        self.attack_result.configure(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVaultApp(root)
    root.mainloop()
