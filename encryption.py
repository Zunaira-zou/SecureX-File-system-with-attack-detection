import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
import secrets

STORAGE_FOLDER = 'storage'

def derive_key(password: str, salt: bytes = None) -> tuple:
    #Derive AES-256 key from password using PBKDF2(Password-Based Key Derivation Function 2)
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 256-bit key
        salt=salt,
        iterations=100000,  # Strong
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt 

def encrypt_file(file_path: str, password: str) -> str:
    #Encrypt file with AES-256 + HMAC (Multi-Layer)
    if not os.path.exists(file_path):
        print("File not found!")
        return None
    
    # Read original file data
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Derive aes key from password
    key, salt = derive_key(password)
    
    # Generate random IV 
    iv = secrets.token_bytes(16)
    
    # AES-256-CBC Encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Create HMAC(SHA 256) for integrity (Layer 3)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(salt + iv + ciphertext)
    hmac_tag = h.finalize() 
    
    # Combine everything: salt + iv + hmac + ciphertext
    encrypted_data = salt + iv + hmac_tag + ciphertext
    
    # Save as .enc file in storage folder
    filename = os.path.basename(file_path)
    encrypted_filename = f"{filename}.enc"
    encrypted_path = os.path.join(STORAGE_FOLDER, encrypted_filename)
    
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"File encrypted and saved as: {encrypted_filename}")
    return encrypted_path

def decrypt_file(encrypted_filename: str, password: str) -> str:
    #Decrypt file + verify integrity (Attack Detection)
    encrypted_path = os.path.join(STORAGE_FOLDER, encrypted_filename)
    
    if not os.path.exists(encrypted_path):
        print(" Encrypted file not found!")
        return None
    
    # Read encrypted data
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract components
    salt = encrypted_data[0:16]
    iv = encrypted_data[16:32]
    hmac_tag = encrypted_data[32:64]
    ciphertext = encrypted_data[64:]
    
    # Derive key
    key, _ = derive_key(password, salt)
    
    # Verify HMAC (Integrity Check - Attack Detection)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(salt + iv + ciphertext)
    
    try:
        h.verify(hmac_tag)
    except Exception:
        print("CRITICAL: File integrity check FAILED! Possible tampering detected!")
        return None  # Block decryption if tampered
    
    # Decrypt AES 256 CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Save decrypted file (remove .enc extension)
    original_name = encrypted_filename.replace('.enc', '')
    decrypted_path = os.path.join(STORAGE_FOLDER, f"decrypted_{original_name}")
    
    with open(decrypted_path, 'wb') as f:
        f.write(data)
    
    print(f"File decrypted successfully: decrypted_{original_name}")
    return decrypted_path

# For independent testing
if __name__ == "__main__":
    print(" Encryption Module ")
    pass
