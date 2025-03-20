from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# AES-256 Encryption and Decryption
def generate_aes_key():
    """Generate a random 256-bit (32-byte) AES key."""
    return os.urandom(32)

def encrypt_aes(data, key):
    """Encrypt data using AES-256."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(encrypted_data, key):
    """Decrypt data using AES-256."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

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
def encrypt_file(file_path, public_key_path, output_path):
    """Encrypt a file using hybrid encryption."""
    with open(public_key_path, "rb") as key_file:
        public_key = key_file.read()
    
    with open(file_path, "rb") as file:
        data = file.read()
    
    encrypted_data = encrypt_aes(data, generate_aes_key())
    with open(output_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_path, private_key_path, output_path):
    """Decrypt a file using hybrid encryption."""
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()
    
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    
    decrypted_data = decrypt_aes(encrypted_data, generate_aes_key())
    with open(output_path, "wb") as file:
        file.write(decrypted_data)