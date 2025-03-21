from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# AES-256 Encryption and Decryption
def generate_aes_key(password=None, salt=None):
    """Generate a random 256-bit (32-byte) AES key or derive from password."""
    if password:
        if not salt:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode()), salt
    return os.urandom(32), None

def encrypt_aes(data, key, iv):
    """Encrypt data using AES-256."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted_data, key, iv):
    """Decrypt data using AES-256."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# RSA Encryption and Decryption
def generate_rsa_keys(private_key_path, public_key_path):
    """Generate RSA keys and save them as PEM files."""
    key = RSA.generate(2048)
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(key.export_key(format="PEM"))
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(key.publickey().export_key(format="PEM"))

def encrypt_rsa(data, public_key):
    """Encrypt data using RSA."""
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def decrypt_rsa(encrypted_data, private_key):
    """Decrypt data using RSA."""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_data)

# File Encryption and Decryption
def encrypt_file(file_path, public_key_path, output_path, password=None):
    """Encrypt a file using hybrid encryption."""
    with open(public_key_path, "rb") as key_file:
        public_key = key_file.read()
    
    with open(file_path, "rb") as file:
        data = file.read()
    
    # Generate AES key
    aes_key, salt = generate_aes_key(password)
    iv = os.urandom(16)
    
    # Encrypt data with AES
    encrypted_data = encrypt_aes(data, aes_key, iv)
    
    # Encrypt AES key with RSA
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)
    
    # Save salt (if used) + encrypted AES key + IV + encrypted data
    with open(output_path, "wb") as file:
        if salt:
            file.write(salt)
        file.write(encrypted_aes_key + iv + encrypted_data)

def decrypt_file(file_path, private_key_path, output_path, password=None):
    """Decrypt a file using hybrid encryption."""
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()
    
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    
    # Extract salt (if used), encrypted AES key, IV, and encrypted data
    salt = None
    if password:
        salt = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
    encrypted_aes_key = encrypted_data[:256]
    iv = encrypted_data[256:272]
    encrypted_data = encrypted_data[272:]
    
    # Decrypt AES key with RSA
    aes_key = decrypt_rsa(encrypted_aes_key, private_key)
    
    # Derive AES key if password is provided
    if password:
        aes_key, _ = generate_aes_key(password, salt)
    
    # Decrypt data with AES
    decrypted_data = decrypt_aes(encrypted_data, aes_key, iv)
    
    # Save decrypted data
    with open(output_path, "wb") as file:
        file.write(decrypted_data)