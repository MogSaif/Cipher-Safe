import pyotp
import qrcode
import os
import json
from io import BytesIO
from PIL import Image
import tkinter as tk
from tkinter import messagebox

class TOTPService:
    def __init__(self):
        self.config_file = "totp_config.json"
        self.app_name = "CipherSafe"
        self.issuer = "CipherSafe File Encryption"
    
    def generate_secret(self):
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    def save_secret(self, secret, user_email="user@ciphersafe.local"):
        """Save the TOTP secret to local config file."""
        config = {
            "secret": secret,
            "user_email": user_email,
            "issuer": self.issuer,
            "app_name": self.app_name
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving TOTP config: {e}")
            return False
    
    def load_secret(self):
        """Load the TOTP secret from local config file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                return config.get("secret"), config.get("user_email", "user@ciphersafe.local")
            return None, None
        except Exception as e:
            print(f"Error loading TOTP config: {e}")
            return None, None
    
    def generate_qr_code(self, secret, user_email="user@ciphersafe.local"):
        """Generate QR code for Google Authenticator setup."""
        try:
            # Create TOTP URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user_email,
                issuer_name=self.issuer
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create QR code image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save QR code image
            qr_path = "totp_qr_code.png"
            img.save(qr_path)
            
            return qr_path, provisioning_uri
            
        except Exception as e:
            print(f"Error generating QR code: {e}")
            return None, None
    
    def verify_totp_code(self, code, secret=None):
        """Verify a TOTP code."""
        try:
            if secret is None:
                secret, _ = self.load_secret()
                if secret is None:
                    return False
            
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=1)  # Allow 30 seconds window
            
        except Exception as e:
            print(f"Error verifying TOTP code: {e}")
            return False
    
    def get_current_totp(self, secret=None):
        """Get current TOTP code (for testing purposes)."""
        try:
            if secret is None:
                secret, _ = self.load_secret()
                if secret is None:
                    return None
            
            totp = pyotp.TOTP(secret)
            return totp.now()
            
        except Exception as e:
            print(f"Error getting current TOTP: {e}")
            return None
    
    def is_totp_enabled(self):
        """Check if TOTP is already enabled."""
        secret, _ = self.load_secret()
        return secret is not None
    
    def setup_totp(self, user_email="user@ciphersafe.local"):
        """Complete TOTP setup process."""
        try:
            # Generate new secret
            secret = self.generate_secret()
            
            # Generate QR code
            qr_path, provisioning_uri = self.generate_qr_code(secret, user_email)
            
            if qr_path is None:
                return False, "Failed to generate QR code", None, None
            
            return True, "QR code generated successfully", qr_path, secret
            
        except Exception as e:
            print(f"Error setting up TOTP: {e}")
            return False, f"Setup failed: {e}", None, None
    
    def disable_totp(self):
        """Disable TOTP by removing the config file."""
        try:
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
            
            # Remove QR code file if it exists
            if os.path.exists("totp_qr_code.png"):
                os.remove("totp_qr_code.png")
            
            return True
        except Exception as e:
            print(f"Error disabling TOTP: {e}")
            return False