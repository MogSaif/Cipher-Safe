import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from typing import List

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSafe")
        self.root.geometry("500x400")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat")
        self.style.configure("TLabel", padding=6)
        
        # Create UI elements
        self.create_widgets()
        
    def create_widgets(self):
        # File selection
        ttk.Label(self.root, text="Select File:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.file_entry = ttk.Entry(self.root, width=40)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Password input
        ttk.Label(self.root, text="Password:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.password_entry = ttk.Entry(self.root, show="*", width=40)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Confirm Password
        ttk.Label(self.root, text="Confirm Password:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.confirm_password_entry = ttk.Entry(self.root, show="*", width=40)
        self.confirm_password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Action buttons
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_file).pack(side="left", padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=4, column=0, columnspan=3, pady=10)
        
        # Status text
        self.status_text = tk.Text(self.root, height=8, width=60, state="disabled")
        self.status_text.grid(row=5, column=0, columnspan=3, padx=10, pady=5)
        
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
            
    def log_status(self, message):
        self.status_text.config(state="normal")
        self.status_text.insert("end", message + "\n")
        self.status_text.see("end")
        self.status_text.config(state="disabled")
    
    def clear_progress(self):
        self.progress["value"] = 0
        self.root.update_idletasks()
        
    def update_progress(self, value):
        self.progress["value"] = value
        self.root.update_idletasks()
        
    def get_key(self, password, salt):
        return scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)
    
    def encrypt_file(self):
        input_file = self.file_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not self.validate_inputs(input_file, password, confirm_password):
            return
            
        try:
            output_file = input_file + ".enc"
            salt = get_random_bytes(16)
            key = self.get_key(password.encode(), salt)
            cipher = AES.new(key, AES.MODE_GCM)
            
            filesize = os.path.getsize(input_file)
            chunk_size = 64 * 1024  # 64KB chunks
            
            with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
                # Write salt and nonce
                fout.write(salt)
                fout.write(cipher.nonce)
                
                bytes_processed = 0
                while True:
                    chunk = fin.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    encrypted_chunk = cipher.encrypt(chunk)
                    fout.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    self.update_progress((bytes_processed / filesize) * 100)
                    
                # Write MAC tag
                fout.write(cipher.digest())
                
            # Delete the original file after encryption
            os.remove(input_file)
            
            self.log_status("Encryption successful!")
            self.log_status(f"Encrypted file saved as: {output_file}")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            self.log_status(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            
    def decrypt_file(self):
        input_file = self.file_entry.get()
        password = self.password_entry.get()
        
        if not input_file.endswith(".enc"):
            messagebox.showwarning("Warning", "File does not appear to be encrypted (.enc extension expected)")
            return
            
        try:
            output_file = input_file[:-4]
            filesize = os.path.getsize(input_file)
            chunk_size = 64 * 1024  # 64KB chunks
            
            self.log_status(f"Decrypting {os.path.basename(input_file)}...")
            self.clear_progress()
            
            with open(input_file, "rb") as fin:
                salt = fin.read(16)
                nonce = fin.read(16)
                key = self.get_key(password.encode(), salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                # Calculate total data length (excluding salt, nonce and tag)
                actual_size = filesize - 16 - 16 - 16
                bytes_processed = 0
                
                with open(output_file, "wb") as fout:
                    while True:
                        chunk = fin.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        
                        # Handle the last chunk containing the tag
                        if fin.tell() == filesize:
                            tag = chunk[-16:]
                            chunk = chunk[:-16]
                            decrypted_chunk = cipher.decrypt(chunk)
                            fout.write(decrypted_chunk)
                            cipher.verify(tag)
                        else:
                            decrypted_chunk = cipher.decrypt(chunk)
                            fout.write(decrypted_chunk)
                
                bytes_processed += len(chunk)
                self.update_progress((bytes_processed / filesize) * 100)

            self.log_status("Decryption successful!")
            self.log_status(f"Decrypted file saved as: {output_file}")
            messagebox.showinfo("Success", "File decrypted successfully!")

            # Delete the original encrypted file after decryption
            os.remove(input_file)
            
        except Exception as e:
            self.log_status(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            if os.path.exists(output_file):
                os.remove(output_file)
            
                
    def validate_inputs(self, input_file, password, confirm_password):
        if not input_file:
            messagebox.showwarning("Warning", "Please select a file")
            return False
        if not os.path.exists(input_file):
            messagebox.showwarning("Warning", "Selected file does not exist")
            return False
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return False
        if password != confirm_password:
            messagebox.showwarning("Warning", "Passwords do not match")
            return False
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
