from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import logging

# Constants
AES_KEY_SIZE = 32  # 256-bit
IV_SIZE = 16       # 128-bit
SALT_SIZE = 16
RSA_KEY_SIZE = 2048
PBKDF2_ITERATIONS = 100000

def generate_aes_key(password=None, salt=None):
    """Generate a random 256-bit (32-byte) AES key or derive from password."""
    if password:
        if not salt:
            salt = os.urandom(SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode()), salt
    return os.urandom(AES_KEY_SIZE), None

def encrypt_aes(data, key, iv):
    """Encrypt data using AES-256-CBC."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted_data, key, iv):
    """Decrypt data using AES-256-CBC."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def generate_rsa_keys(private_key_path, public_key_path):
    """Generate RSA keys and save them as PEM files."""
    if os.path.exists(private_key_path) or os.path.exists(public_key_path):
        raise FileExistsError("Key files already exist")
    
    key = RSA.generate(RSA_KEY_SIZE)
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(key.export_key(format="PEM"))
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(key.publickey().export_key(format="PEM"))

def encrypt_rsa(data, public_key):
    """Encrypt data using RSA-OAEP."""
    if len(data) > 190:  # RSA 2048 can encrypt up to 190 bytes
        raise ValueError("Data too large for RSA encryption")
    
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def decrypt_rsa(encrypted_data, private_key):
    """Decrypt data using RSA-OAEP."""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_data)

def encrypt_file(file_path, public_key_path, output_path, password=None):
    """Encrypt a file using hybrid encryption (RSA+AES)."""
    # Validate inputs
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found: {public_key_path}")
    if os.path.exists(output_path):
        raise FileExistsError(f"Output file already exists: {output_path}")
    
    # Read public key
    with open(public_key_path, "rb") as key_file:
        public_key = key_file.read()
    
    # Read file data
    with open(file_path, "rb") as file:
        data = file.read()
    
    # Generate AES key and IV
    aes_key, salt = generate_aes_key(password)
    iv = os.urandom(IV_SIZE)
    
    # Encrypt data with AES
    encrypted_data = encrypt_aes(data, aes_key, iv)
    
    # Encrypt AES key with RSA
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)
    
    # Write encrypted file
    with open(output_path, "wb") as file:
        if password:  # Only write salt if password was used
            file.write(salt)
        file.write(encrypted_aes_key)
        file.write(iv)
        file.write(encrypted_data)

def decrypt_file(file_path, private_key_path, output_path, password=None):
    """Decrypt a file using hybrid encryption (RSA+AES)."""
    # Validate inputs
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Encrypted file not found: {file_path}")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    if os.path.exists(output_path):
        raise FileExistsError(f"Output file already exists: {output_path}")
    
    # Read private key
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()
    
    # Read encrypted file
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    
    # Extract components
    offset = 0
    salt = None
    if password:
        salt = encrypted_data[:SALT_SIZE]
        offset = SALT_SIZE
    
    encrypted_aes_key = encrypted_data[offset:offset+256]  # RSA 2048 produces 256-byte ciphertext
    offset += 256
    iv = encrypted_data[offset:offset+IV_SIZE]
    offset += IV_SIZE
    encrypted_data = encrypted_data[offset:]
    
    # Decrypt AES key
    aes_key = decrypt_rsa(encrypted_aes_key, private_key)
    
    # If password was used, derive key from password
    if password:
        aes_key, _ = generate_aes_key(password, salt)
    
    # Decrypt data
    decrypted_data = decrypt_aes(encrypted_data, aes_key, iv)
    
    # Write decrypted file
    with open(output_path, "wb") as file:
        file.write(decrypted_data)

def batch_encrypt_files(input_paths, public_key_path, output_folder, password=None):
    """Encrypt multiple files at once."""
    results = []
    
    # Read public key once for all files
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found: {public_key_path}")
    
    with open(public_key_path, "rb") as key_file:
        public_key = key_file.read()
    
    # Process each file
    for input_path in input_paths:
        try:
            if not os.path.exists(input_path):
                results.append({
                    'status': 'error',
                    'file': os.path.basename(input_path),
                    'message': 'File not found'
                })
                continue
            
            filename = os.path.basename(input_path)
            output_path = os.path.join(output_folder, f"{filename}.enc")
            
            if os.path.exists(output_path):
                results.append({
                    'status': 'error',
                    'file': filename,
                    'message': 'Output file already exists'
                })
                continue
            
            # Encrypt the file
            encrypt_file(input_path, public_key_path, output_path, password)
            
            results.append({
                'status': 'success',
                'file': filename,
                'encrypted_file': f"{filename}.enc",
                'message': 'File encrypted successfully'
            })
            
        except Exception as e:
            results.append({
                'status': 'error',
                'file': os.path.basename(input_path),
                'message': str(e)
            })
            logging.error(f"Error encrypting file {input_path}: {e}")
    
    return results

def batch_decrypt_files(input_paths, private_key_path, output_folder, password=None):
    """Decrypt multiple files at once."""
    results = []
    
    # Read private key once for all files
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()
    
    # Process each file
    for input_path in input_paths:
        try:
            if not os.path.exists(input_path):
                results.append({
                    'status': 'error',
                    'file': os.path.basename(input_path),
                    'message': 'File not found'
                })
                continue
            
            filename = os.path.basename(input_path)
            if not filename.endswith('.enc'):
                results.append({
                    'status': 'error',
                    'file': filename,
                    'message': 'File is not encrypted'
                })
                continue
            
            original_filename = filename[:-4]  # Remove .enc extension
            output_path = os.path.join(output_folder, original_filename)
            
            if os.path.exists(output_path):
                results.append({
                    'status': 'error',
                    'file': filename,
                    'message': 'Output file already exists'
                })
                continue
            
            # Decrypt the file
            decrypt_file(input_path, private_key_path, output_path, password)
            
            results.append({
                'status': 'success',
                'file': filename,
                'decrypted_file': original_filename,
                'message': 'File decrypted successfully'
            })
            
        except Exception as e:
            results.append({
                'status': 'error',
                'file': os.path.basename(input_path),
                'message': str(e)
            })
            logging.error(f"Error decrypting file {input_path}: {e}")
    
    return results