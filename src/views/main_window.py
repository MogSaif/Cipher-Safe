import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont

# Import from the same package
from ..utils.crypto_service import CryptoService

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSafe - Secure File Encryption")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Set application icon and style
        self.setup_styles()
        
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_font = tkfont.Font(size=24, weight="bold")
        ttk.Label(
            header_frame,
            text="CipherSafe",
            font=title_font,
            foreground="#2c3e50"
        ).pack(side=tk.LEFT)
        
        # Main content
        self.create_file_section()
        self.create_password_section()
        self.create_action_buttons()
        self.create_progress_section()
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(10, 5)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
        
        # Center the window
        self.center_window()
    
    def setup_styles(self):
        """Configure ttk styles for a modern look."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure(
            'TFrame',
            background='#f5f6fa'
        )
        
        style.configure(
            'TLabel',
            background='#f5f6fa',
            font=('Segoe UI', 10)
        )
        
        style.configure(
            'TButton',
            font=('Segoe UI', 10),
            padding=8
        )
        
        style.map(
            'TButton',
            background=[
                ('active', '#3498db'),
                ('!disabled', '#2980b9')
            ],
            foreground=[
                ('!disabled', 'white')
            ]
        )
        
        style.configure(
            'TEntry',
            padding=8,
            fieldbackground='white'
        )
        
        style.configure(
            'TProgressbar',
            thickness=10,
            troughcolor='#dcdde1',
            background='#2ecc71',
            lightcolor='#2ecc71',
            darkcolor='#27ae60',
            bordercolor='#27ae60'
        )
    
    def create_file_section(self):
        """Create the file selection section."""
        frame = ttk.LabelFrame(
            self.main_frame,
            text=" File ",
            padding=(15, 10)
        )
        frame.pack(fill=tk.X, pady=(0, 15))
        
        # File entry and browse button
        self.file_var = tk.StringVar()
        
        file_entry = ttk.Entry(
            frame,
            textvariable=self.file_var,
            font=('Segoe UI', 10)
        )
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = ttk.Button(
            frame,
            text="Browse...",
            command=self.browse_file,
            style='TButton'
        )
        browse_btn.pack(side=tk.RIGHT)
    
    def create_password_section(self):
        """Create the password input section."""
        frame = ttk.LabelFrame(
            self.main_frame,
            text=" Security ",
            padding=(15, 10)
        )
        frame.pack(fill=tk.X, pady=(0, 15))
        
        # Password field
        ttk.Label(
            frame,
            text="Password:",
            font=('Segoe UI', 10)
        ).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            frame,
            textvariable=self.password_var,
            show="•",
            font=('Segoe UI', 10)
        )
        password_entry.grid(row=0, column=1, sticky=tk.EW, padx=(5, 0), pady=(0, 5))
        
        # Confirm password field
        ttk.Label(
            frame,
            text="Confirm Password:",
            font=('Segoe UI', 10)
        ).grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        self.confirm_password_var = tk.StringVar()
        confirm_entry = ttk.Entry(
            frame,
            textvariable=self.confirm_password_var,
            show="•",
            font=('Segoe UI', 10)
        )
        confirm_entry.grid(row=1, column=1, sticky=tk.EW, padx=(5, 0), pady=(5, 0))
        
        # Configure grid weights
        frame.columnconfigure(1, weight=1)
    
    def create_action_buttons(self):
        """Create the action buttons section."""
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Encrypt button
        self.encrypt_btn = ttk.Button(
            btn_frame,
            text="Encrypt File",
            command=self.encrypt_file,
            style='Accent.TButton'
        )
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Decrypt button
        self.decrypt_btn = ttk.Button(
            btn_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            style='Accent.TButton'
        )
        self.decrypt_btn.pack(side=tk.LEFT)
        
        # Clear button
        clear_btn = ttk.Button(
            btn_frame,
            text="Clear",
            command=self.clear_fields
        )
        clear_btn.pack(side=tk.RIGHT)
    
    def create_progress_section(self):
        """Create the progress section."""
        frame = ttk.Frame(self.main_frame)
        frame.pack(fill=tk.X, pady=(20, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(
            frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(
            frame,
            text="0%",
            anchor=tk.CENTER
        )
        self.progress_label.pack(pady=(5, 0))
    
    def browse_file(self):
        """Open file dialog to select a file."""
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("All files", "*.*"),
                ("Encrypted files", "*.enc"),
                ("Documents", "*.txt *.doc *.docx *.pdf"),
                ("Images", "*.jpg *.jpeg *.png *.gif"),
                ("Videos", "*.mp4 *.avi *.mov")
            ]
        )
        
        if file_path:
            self.file_var.set(file_path)
            
            # Auto-detect if file is encrypted
            if file_path.lower().endswith('.enc'):
                self.decrypt_btn.state(['!disabled'])
                self.encrypt_btn.state(['disabled'])
            else:
                self.encrypt_btn.state(['!disabled'])
                self.decrypt_btn.state(['disabled'])
    
    def encrypt_file(self):
        """Encrypt the selected file."""
        if not self.validate_inputs():
            return
            
        input_file = self.file_var.get()
        password = self.password_var.get()
        
        def update_progress(percent):
            self.progress_var.set(percent)
            self.progress_label.config(text=f"{percent}%")
            self.root.update_idletasks()
        
        try:
            self.set_ui_state(False)
            self.update_status("Encrypting file...")
            
            success = CryptoService.encrypt_file(
                input_file,
                password,
                callback=update_progress
            )
            
            if success:
                messagebox.showinfo(
                    "Success",
                    f"File encrypted successfully!\n\n"
                    f"Original: {input_file}\n"
                    f"Encrypted: {input_file}.enc"
                )
                self.clear_fields()
            else:
                messagebox.showerror("Error", "Failed to encrypt file.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            
        finally:
            self.set_ui_state(True)
            self.update_status("Ready")
    
    def decrypt_file(self):
        """Decrypt the selected file."""
        if not self.validate_inputs():
            return
            
        input_file = self.file_var.get()
        password = self.password_var.get()
        
        def update_progress(percent):
            self.progress_var.set(percent)
            self.progress_label.config(text=f"{percent}%")
            self.root.update_idletasks()
        
        try:
            self.set_ui_state(False)
            self.update_status("Decrypting file...")
            
            success = CryptoService.decrypt_file(
                input_file,
                password,
                callback=update_progress
            )
            
            if success:
                output_file = input_file[:-4]  # Remove .enc extension
                messagebox.showinfo(
                    "Success",
                    f"File decrypted successfully!\n\n"
                    f"Encrypted: {input_file}\n"
                    f"Decrypted: {output_file}"
                )
                self.clear_fields()
            else:
                messagebox.showerror("Error", "Failed to decrypt file. Invalid password?")
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            
        finally:
            self.set_ui_state(True)
            self.update_status("Ready")
    
    def validate_inputs(self):
        """Validate user inputs."""
        file_path = self.file_var.get()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file.")
            return False
            
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "The selected file does not exist.")
            return False
            
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return False
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return False
            
        return True
    
    def clear_fields(self):
        """Clear all input fields."""
        self.file_var.set("")
        self.password_var.set("")
        self.confirm_password_var.set("")
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.encrypt_btn.state(['!disabled'])
        self.decrypt_btn.state(['!disabled'])
    
    def set_ui_state(self, enabled):
        """Enable or disable UI elements."""
        state = 'normal' if enabled else 'disabled'
        
        for widget in [
            self.encrypt_btn,
            self.decrypt_btn
        ]:
            widget.state(['!disabled' if enabled else 'disabled'])
    
    def update_status(self, message):
        """Update the status bar."""
        self.status_var.set(f"Status: {message}")
    
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
