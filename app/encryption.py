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
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + ciphertext (IV is needed for decryption)
    return iv + ciphertext

def decrypt_aes(encrypted_data, key):
    """Decrypt data using AES-256."""
    # Extract IV (first 16 bytes) and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Decryption failed: Invalid padding bytes.") from e

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
    
    # Generate a random AES key
    aes_key = generate_aes_key()
    
    # Encrypt the data with AES
    encrypted_data = encrypt_aes(data, aes_key)
    
    # Encrypt the AES key with RSA
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)
    
    # Save the encrypted AES key + encrypted data
    with open(output_path, "wb") as file:
        file.write(encrypted_aes_key + encrypted_data)

def decrypt_file(file_path, private_key_path, output_path):
    """Decrypt a file using hybrid encryption."""
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()
    
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    
    # Extract the encrypted AES key (first 256 bytes) and encrypted data
    encrypted_aes_key = encrypted_data[:256]
    encrypted_data = encrypted_data[256:]
    
    # Decrypt the AES key with RSA
    try:
        aes_key = decrypt_rsa(encrypted_aes_key, private_key)
    except ValueError as e:
        raise ValueError("Failed to decrypt AES key: " + str(e))
    
    # Decrypt the data with AES
    try:
        decrypted_data = decrypt_aes(encrypted_data, aes_key)
    except ValueError as e:
        raise ValueError("Failed to decrypt file data: " + str(e))
    
    # Save the decrypted data
    with open(output_path, "wb") as file:
        file.write(decrypted_data)