import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken

# Store the secret key beside this Python file.
KEY_FILE = Path(__file__).resolve().parent / "secret.key"


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Encryption & SHA-256 Tool")
        self.root.geometry("750x650")
        self.root.minsize(600, 500)

        self.cipher = None
        self.load_or_create_key()

        ttk.Label(
            root,
            text="Encryption, Decryption & SHA-256",
            font=("Arial", 17, "bold")
        ).pack(pady=15)

        ttk.Label(
            root,
            text="Enter text or paste encrypted JSON below:"
        ).pack(anchor="w", padx=20)

        self.input_text = tk.Text(root, height=7, wrap="word")
        self.input_text.pack(fill="x", padx=20, pady=8)

        buttons = ttk.Frame(root)
        buttons.pack(pady=8)

        ttk.Button(
            buttons, text="Encrypt + SHA-256",
            command=self.encrypt_text
        ).grid(row=0, column=0, padx=5, pady=5)

        ttk.Button(
            buttons, text="Decrypt + Verify",
            command=self.decrypt_text
        ).grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(
            buttons, text="SHA-256 Only",
            command=self.hash_text
        ).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(
            buttons, text="Clear",
            command=self.clear_text
        ).grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(root, text="Output:").pack(
            anchor="w", padx=20, pady=(10, 0)
        )

        self.output_text = tk.Text(root, height=12, wrap="word")
        self.output_text.pack(
            fill="both", expand=True, padx=20, pady=8
        )

        bottom = ttk.Frame(root)
        bottom.pack(pady=8)

        ttk.Button(
            bottom, text="Copy Output",
            command=self.copy_output
        ).pack(side="left", padx=5)

        ttk.Button(
            bottom, text="Save Output",
            command=self.save_output
        ).pack(side="left", padx=5)

        self.status = ttk.Label(root, text="Ready")
        self.status.pack(pady=(0, 10))

    def load_or_create_key(self):
        """Load the existing key or create one on first launch."""
        try:
            if KEY_FILE.exists():
                key = KEY_FILE.read_bytes()
                self.cipher = Fernet(key)
            else:
                key = Fernet.generate_key()
                KEY_FILE.write_bytes(key)
                self.cipher = Fernet(key)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "Key Error",
                f"Could not load or create the key:\n{error}"
            )

    @staticmethod
    def calculate_sha256(text):
        """Return the SHA-256 hexadecimal digest of text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get_input(self):
        return self.input_text.get("1.0", "end-1c").strip()

    def show_output(self, result, status):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", result)
        self.status.config(text=status)

    def encrypt_text(self):
        text = self.get_input()

        if not text:
            messagebox.showwarning(
                "Missing Text", "Enter text to encrypt."
            )
            return

        if self.cipher is None:
            messagebox.showerror(
                "Key Error", "Encryption key is not available."
            )
            return

        try:
            # Calculate SHA-256 of original plaintext.
            original_hash = self.calculate_sha256(text)

            # Encrypt plaintext using Fernet.
            encrypted = self.cipher.encrypt(
                text.encode("utf-8")
            ).decode("ascii")

            # Package ciphertext and hash together.
            package = {
                "ciphertext": encrypted,
                "sha256": original_hash
            }

            output = json.dumps(package, indent=4)

            self.show_output(
                output,
                "Encryption complete | SHA-256 generated."
            )

        except Exception as error:
            messagebox.showerror("Encryption Error", str(error))

    def decrypt_text(self):
        encrypted_input = self.get_input()

        if not encrypted_input:
            messagebox.showwarning(
                "Missing Text", "Paste encrypted JSON to decrypt."
            )
            return

        if self.cipher is None:
            messagebox.showerror(
                "Key Error", "Encryption key is not available."
            )
            return

        try:
            # Read ciphertext and its original hash.
            package = json.loads(encrypted_input)
            encrypted = package["ciphertext"]
            original_hash = package["sha256"]

            # Decrypt ciphertext.
            decrypted = self.cipher.decrypt(
                encrypted.encode("ascii")
            ).decode("utf-8")

            # Calculate SHA-256 of decrypted plaintext.
            decrypted_hash = self.calculate_sha256(decrypted)

            # Compare the computed hash with the stored hash.
            verified = decrypted_hash == original_hash

            output = (
                f"Decrypted Text:\n{decrypted}\n\n"
                f"Original SHA-256:\n{original_hash}\n\n"
                f"Decrypted Text SHA-256:\n{decrypted_hash}\n\n"
                f"Hash Verification: "
                f"{'PASSED' if verified else 'FAILED'}"
            )

            self.show_output(
                output,
                "Decryption complete | Hash verification "
                + ("passed." if verified else "failed.")
            )

        except (InvalidToken, ValueError, UnicodeError, KeyError, TypeError):
            messagebox.showerror(
                "Decryption Failed",
                "Invalid ciphertext, wrong key, or invalid input format."
            )

    def hash_text(self):
        text = self.get_input()

        if not text:
            messagebox.showwarning(
                "Missing Text", "Enter text to hash."
            )
            return

        digest = self.calculate_sha256(text)

        self.show_output(
            f"Input Text:\n{text}\n\nSHA-256 Hash:\n{digest}",
            "SHA-256 hash generated."
        )

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status.config(text="Ready")

    def copy_output(self):
        result = self.output_text.get("1.0", "end-1c")

        if not result:
            messagebox.showwarning(
                "Empty Output", "Nothing to copy."
            )
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self.status.config(text="Output copied to clipboard.")

    def save_output(self):
        result = self.output_text.get("1.0", "end-1c")

        if not result:
            messagebox.showwarning(
                "Empty Output", "Nothing to save."
            )
            return

        filename = filedialog.asksaveasfilename(
            title="Save Output",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )

        if filename:
            try:
                Path(filename).write_text(
                    result, encoding="utf-8"
                )
                self.status.config(
                    text="Output saved successfully."
                )
            except OSError as error:
                messagebox.showerror("Save Error", str(error))


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
    