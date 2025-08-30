from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import os

class CryptoService:
    SALT_SIZE = 16  # 128 bits
    KEY_SIZE = 32    # 256 bits for AES-256
    NONCE_SIZE = 12   # 96 bits for GCM
    TAG_SIZE = 16     # 128 bits for GCM
    OUTPUT_FOLDER_NAME = "CipherSafe_Output"
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive a secure key from a password and salt."""
        return scrypt(
            password.encode('utf-8'),
            salt=salt,
            key_len=CryptoService.KEY_SIZE,
            N=2**20,  # CPU/memory cost parameter
            r=8,      # Block size parameter
            p=1       # Parallelization parameter
        )
    
    @staticmethod
    def create_output_folder(base_path: str) -> str:
        """Create output folder in the same directory as the input file."""
        folder_path = os.path.join(base_path, CryptoService.OUTPUT_FOLDER_NAME)
        
        # Create the folder if it doesn't exist
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            
        return folder_path
    
    @staticmethod
    def get_output_path(input_file: str, operation: str) -> str:
        """
        Generate output path in the dedicated output folder.
        
        Args:
            input_file: Path to the input file
            operation: 'encrypt' or 'decrypt'
        
        Returns:
            Full path to the output file
        """
        # Get the directory containing the input file
        input_dir = os.path.dirname(input_file)
        input_filename = os.path.basename(input_file)
        
        # Create output folder
        output_folder = CryptoService.create_output_folder(input_dir)
        
        if operation == 'encrypt':
            # Add .enc extension
            output_filename = input_filename + '.enc'
        else:  # decrypt
            # Remove .enc extension
            if input_filename.endswith('.enc'):
                output_filename = input_filename[:-4]
            else:
                output_filename = input_filename + '_decrypted'
        
        return os.path.join(output_folder, output_filename)
    
    @staticmethod
    def encrypt_file(input_file: str, password: str, callback=None) -> tuple[bool, str]:
        """
        Encrypt a file using AES-GCM.
        
        Returns:
            tuple: (success: bool, output_path: str)
        """
        try:
            salt = get_random_bytes(CryptoService.SALT_SIZE)
            key = CryptoService.derive_key(password, salt)
            nonce = get_random_bytes(CryptoService.NONCE_SIZE)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Generate output path in dedicated folder
            output_file = CryptoService.get_output_path(input_file, 'encrypt')
            total_size = os.path.getsize(input_file)
            processed = 0
            
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                # Write salt and nonce to output file
                f_out.write(salt)
                f_out.write(nonce)
                
                # Encrypt file in chunks
                while True:
                    chunk = f_in.read(64 * 1024)  # 64KB chunks
                    if not chunk:
                        break
                        
                    # Only encrypt if there's data left
                    if len(chunk) % 16 != 0:
                        # Pad the last chunk if needed
                        chunk += b' ' * (16 - len(chunk) % 16)
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    f_out.write(encrypted_chunk)
                    
                    # Update progress
                    processed += len(chunk)
                    if callback:
                        progress = min(int((processed / total_size) * 100), 100)
                        callback(progress)
                
                # Get and write the authentication tag
                tag = cipher.digest()
                f_out.write(tag)
                
            return True, output_file
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False, ""
    
    @staticmethod
    def decrypt_file(input_file: str, password: str, callback=None) -> tuple[bool, str]:
        """
        Decrypt a file using AES-GCM.
        
        Returns:
            tuple: (success: bool, output_path: str)
        """
        try:
            if not input_file.endswith('.enc'):
                raise ValueError("File must have .enc extension")
            
            # Generate output path in dedicated folder
            output_file = CryptoService.get_output_path(input_file, 'decrypt')
                
            with open(input_file, 'rb') as f:
                # Read salt and nonce
                salt = f.read(CryptoService.SALT_SIZE)
                nonce = f.read(CryptoService.NONCE_SIZE)
                
                # Get file size and calculate data size (excluding salt, nonce, and tag)
                f.seek(0, 2)
                file_size = f.tell()
                data_size = file_size - CryptoService.SALT_SIZE - CryptoService.NONCE_SIZE - CryptoService.TAG_SIZE
                f.seek(CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE)
                
                # Derive key
                key = CryptoService.derive_key(password, salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                with open(output_file, 'wb') as f_out:
                    processed = 0
                    chunk_size = 64 * 1024  # 64KB chunks
                    
                    while processed < data_size:
                        chunk = f.read(min(chunk_size, data_size - processed))
                        if not chunk:
                            break
                            
                        decrypted_chunk = cipher.decrypt(chunk)
                        f_out.write(decrypted_chunk)
                        processed += len(chunk)
                        
                        # Update progress
                        if callback:
                            progress = min(int((processed / data_size) * 100), 100)
                            callback(progress)
                    
                    # Verify the authentication tag
                    tag = f.read(CryptoService.TAG_SIZE)
                    try:
                        cipher.verify(tag)
                    except ValueError:
                        f_out.close()
                        if os.path.exists(output_file):
                            os.remove(output_file)
                        raise ValueError("Invalid password or corrupted file")
                        
            return True, output_file
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False, ""