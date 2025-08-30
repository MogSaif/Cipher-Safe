import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import os
import platform
import subprocess

class TOTPSetupDialog:
    def __init__(self, parent, totp_service):
        self.parent = parent
        self.totp_service = totp_service
        self.secret = None
        self.setup_completed = False
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Setup Two-Factor Authentication")
        self.dialog.geometry("500x700")  # Made taller
        self.dialog.resizable(True, True)  # Allow resizing
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.center_dialog()
        
        # Create scrollable frame
        self.create_scrollable_frame()
        
        # Create UI
        self.create_widgets()
        
        # Setup TOTP
        self.setup_totp()
    
    def center_dialog(self):
        """Center the dialog on parent window."""
        self.dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (500 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (700 // 2)
        self.dialog.geometry(f"500x700+{x}+{y}")
    
    def create_scrollable_frame(self):
        """Create a scrollable frame for the content."""
        # Create canvas and scrollbar
        canvas = tk.Canvas(self.dialog, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dialog, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind("<MouseWheel>", _on_mousewheel)  # Windows
        canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))  # Linux
        canvas.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))   # Linux
    
    def create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.scrollable_frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Setup Two-Factor Authentication",
            font=("Segoe UI", 14, "bold")
        )
        title_label.pack(pady=(0, 15))
        
        # Instructions
        instructions = (
            "1. Install Google Authenticator on your phone\n"
            "2. Scan the QR code below with the app\n"
            "3. Enter the 6-digit code to verify setup"
        )
        
        instruction_label = ttk.Label(
            main_frame,
            text=instructions,
            font=("Segoe UI", 9),
            justify=tk.LEFT
        )
        instruction_label.pack(pady=(0, 15), anchor=tk.W)
        
        # QR Code frame
        self.qr_frame = ttk.LabelFrame(
            main_frame,
            text=" QR Code ",
            padding=(10, 10)
        )
        self.qr_frame.pack(pady=(0, 15))
        
        # QR Code label (will be populated later)
        self.qr_label = ttk.Label(self.qr_frame, text="Generating QR Code...")
        self.qr_label.pack()
        
        # Manual entry frame - more compact
        manual_frame = ttk.LabelFrame(
            main_frame,
            text=" Manual Entry ",
            padding=(10, 5)
        )
        manual_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(
            manual_frame,
            text="Secret Key:",
            font=("Segoe UI", 8, "bold")
        ).pack(anchor=tk.W)
        
        self.secret_var = tk.StringVar()
        secret_entry = ttk.Entry(
            manual_frame,
            textvariable=self.secret_var,
            state="readonly",
            font=("Courier", 8)
        )
        secret_entry.pack(fill=tk.X, pady=(2, 5))
        
        copy_btn = ttk.Button(
            manual_frame,
            text="Copy Secret",
            command=self.copy_secret
        )
        copy_btn.pack()
        
        # Verification frame - HIGHLIGHTED
        verify_frame = ttk.LabelFrame(
            main_frame,
            text=" VERIFY SETUP - ENTER CODE HERE ",
            padding=(15, 10)
        )
        verify_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Make verification section more prominent
        ttk.Label(
            verify_frame,
            text="Enter the 6-digit code from your authenticator app:",
            font=("Segoe UI", 10, "bold"),
            foreground="#2980b9"
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Code entry with larger font
        code_frame = ttk.Frame(verify_frame)
        code_frame.pack(pady=(0, 10))
        
        self.code_var = tk.StringVar()
        code_entry = ttk.Entry(
            code_frame,
            textvariable=self.code_var,
            font=("Courier", 16),  # Larger font
            width=8,
            justify=tk.CENTER
        )
        code_entry.pack()
        code_entry.bind('<Return>', lambda e: self.verify_setup())
        
        # Add validation to only allow digits
        def validate_code(char):
            return char.isdigit() and len(self.code_var.get()) < 6
        
        vcmd = (self.dialog.register(validate_code), '%S')
        code_entry.config(validate='key', validatecommand=vcmd)
        
        # Buttons - more prominent
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.verify_btn = ttk.Button(
            button_frame,
            text="✓ Verify & Complete Setup",
            command=self.verify_setup
        )
        self.verify_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        cancel_btn = ttk.Button(
            button_frame,
            text="✗ Cancel",
            command=self.cancel_setup
        )
        cancel_btn.pack(side=tk.RIGHT)
        
        # Status label for feedback
        self.status_label = ttk.Label(
            main_frame,
            text="Scan the QR code and enter the code above",
            font=("Segoe UI", 9),
            foreground="#7f8c8d"
        )
        self.status_label.pack(pady=(10, 0))
        
        # Focus on code entry
        code_entry.focus()
    
    def setup_totp(self):
        """Setup TOTP and generate QR code."""
        success, message, qr_path, secret = self.totp_service.setup_totp()
        
        if success and qr_path and os.path.exists(qr_path):
            self.secret = secret
            self.secret_var.set(secret)
            
            try:
                # Load and display QR code - smaller size for better fit
                img = Image.open(qr_path)
                img = img.resize((200, 200), Image.Resampling.LANCZOS)  # Smaller QR code
                photo = ImageTk.PhotoImage(img)
                
                self.qr_label.configure(image=photo, text="")
                self.qr_label.image = photo  # Keep a reference
                
                self.status_label.config(
                    text="✓ QR Code generated! Scan it and enter the code above.",
                    foreground="#27ae60"
                )
                
            except Exception as e:
                self.qr_label.configure(text=f"Error loading QR code: {e}")
                messagebox.showerror("Error", f"Failed to display QR code: {e}")
        else:
            self.qr_label.configure(text="Failed to generate QR code")
            self.status_label.config(
                text="❌ Failed to generate QR code",
                foreground="#e74c3c"
            )
            messagebox.showerror("Error", f"Failed to setup TOTP: {message}")
    
    def copy_secret(self):
        """Copy secret key to clipboard."""
        try:
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(self.secret_var.get())
            self.status_label.config(
                text="✓ Secret key copied to clipboard!",
                foreground="#27ae60"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy secret: {e}")
    
    def verify_setup(self):
        """Verify the TOTP setup."""
        code = self.code_var.get().strip()
        
        if not code:
            self.status_label.config(
                text="❌ Please enter the 6-digit code",
                foreground="#e74c3c"
            )
            return
        
        if len(code) != 6 or not code.isdigit():
            self.status_label.config(
                text="❌ Please enter a valid 6-digit code",
                foreground="#e74c3c"
            )
            return
        
        self.status_label.config(
            text="⏳ Verifying code...",
            foreground="#3498db"
        )
        self.verify_btn.config(state="disabled")
        self.dialog.update()
        
        if self.totp_service.verify_totp_code(code, self.secret):
            # Save the secret permanently
            if self.totp_service.save_secret(self.secret):
                self.setup_completed = True
                self.status_label.config(
                    text="✅ Setup completed successfully!",
                    foreground="#27ae60"
                )
                messagebox.showinfo(
                    "Success",
                    "Two-Factor Authentication has been successfully enabled!\n\n"
                    "From now on, you'll need to enter a code from your "
                    "authenticator app when encrypting or decrypting files."
                )
                self.dialog.destroy()
            else:
                self.status_label.config(
                    text="❌ Failed to save configuration",
                    foreground="#e74c3c"
                )
                messagebox.showerror("Error", "Failed to save TOTP configuration.")
        else:
            self.status_label.config(
                text="❌ Incorrect code. Try again with a new code.",
                foreground="#e74c3c"
            )
            self.code_var.set("")  # Clear the input
            messagebox.showerror(
                "Verification Failed",
                "The code you entered is incorrect. Please try again.\n\n"
                "Make sure your phone's time is synchronized and try a new code."
            )
        
        self.verify_btn.config(state="normal")
    
    def cancel_setup(self):
        """Cancel TOTP setup."""
        result = messagebox.askyesno(
            "Cancel Setup",
            "Are you sure you want to cancel the Two-Factor Authentication setup?"
        )
        
        if result:
            # Clean up generated files
            if os.path.exists("totp_qr_code.png"):
                os.remove("totp_qr_code.png")
            self.dialog.destroy()
    
    def get_result(self):
        """Return whether setup was completed."""
        return self.setup_completed


class TOTPVerificationDialog:
    def __init__(self, parent, totp_service, operation="operation"):
        self.parent = parent
        self.totp_service = totp_service
        self.operation = operation
        self.verification_successful = False
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Two-Factor Authentication")
        self.dialog.geometry("450x250")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.center_dialog()
        
        # Create UI
        self.create_widgets()
    
    def center_dialog(self):
        """Center the dialog on parent window."""
        self.dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (450 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (250 // 2)
        self.dialog.geometry(f"450x250+{x}+{y}")
    
    def create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon and title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(
            title_frame,
            text="🔐",
            font=("Segoe UI", 28)
        ).pack(side=tk.LEFT)
        
        ttk.Label(
            title_frame,
            text="Two-Factor Authentication Required",
            font=("Segoe UI", 13, "bold")
        ).pack(side=tk.LEFT, padx=(15, 0))
        
        # Instructions
        ttk.Label(
            main_frame,
            text=f"Enter the 6-digit code from your authenticator app to {self.operation}:",
            font=("Segoe UI", 11)
        ).pack(pady=(0, 20))
        
        # Code entry with better styling
        code_frame = ttk.Frame(main_frame)
        code_frame.pack(pady=(0, 25))
        
        self.code_var = tk.StringVar()
        code_entry = ttk.Entry(
            code_frame,
            textvariable=self.code_var,
            font=("Courier", 18),
            width=8,
            justify=tk.CENTER
        )
        code_entry.pack()
        code_entry.bind('<Return>', lambda e: self.verify_code())
        
        # Add validation to only allow digits
        def validate_code(char):
            return char.isdigit() and len(self.code_var.get()) < 6
        
        vcmd = (self.dialog.register(validate_code), '%S')
        code_entry.config(validate='key', validatecommand=vcmd)
        
        # Focus on entry
        code_entry.focus()
        
        # Status label
        self.status_label = ttk.Label(
            main_frame,
            text="Enter the current code from your authenticator app",
            font=("Segoe UI", 9),
            foreground="#7f8c8d"
        )
        self.status_label.pack(pady=(10, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        self.verify_btn = ttk.Button(
            button_frame,
            text="✓ Verify",
            command=self.verify_code
        )
        self.verify_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        cancel_btn = ttk.Button(
            button_frame,
            text="✗ Cancel",
            command=self.cancel_verification
        )
        cancel_btn.pack(side=tk.RIGHT)
    
    def verify_code(self):
        """Verify the entered TOTP code."""
        code = self.code_var.get().strip()
        
        if not code:
            self.status_label.config(
                text="❌ Please enter the 6-digit code",
                foreground="#e74c3c"
            )
            return
        
        if len(code) != 6 or not code.isdigit():
            self.status_label.config(
                text="❌ Please enter a valid 6-digit code",
                foreground="#e74c3c"
            )
            return
        
        self.status_label.config(
            text="⏳ Verifying code...",
            foreground="#3498db"
        )
        self.verify_btn.config(state="disabled")
        self.dialog.update()
        
        if self.totp_service.verify_totp_code(code):
            self.verification_successful = True
            self.status_label.config(
                text="✅ Verification successful!",
                foreground="#27ae60"
            )
            self.dialog.after(500, self.dialog.destroy)  # Brief delay to show success
        else:
            self.status_label.config(
                text="❌ Incorrect code. Try again with a new code.",
                foreground="#e74c3c"
            )
            self.code_var.set("")  # Clear the input
            messagebox.showerror(
                "Verification Failed",
                "The code you entered is incorrect. Please try again.\n\n"
                "Make sure your phone's time is synchronized and try a new code."
            )
            self.verify_btn.config(state="normal")
    
    def cancel_verification(self):
        """Cancel verification."""
        self.dialog.destroy()
    
    def get_result(self):
        """Return whether verification was successful."""
        return self.verification_successful