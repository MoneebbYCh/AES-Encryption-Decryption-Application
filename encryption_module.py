# encryption_module.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import os

class AESCipher:
    def __init__(self, password):
        # Derive a 32-byte key using scrypt
        self.key = scrypt(password.encode(), salt=b'salt_', key_len=32, N=2**14, r=8, p=1)

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            data = file.read()

        # AES encryption in GCM mode with a new IV each time
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Store the IV, tag, and ciphertext
        return cipher.nonce + tag + ciphertext

    def decrypt_file(self, encrypted_data):
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

    def save_encrypted_file(self, file_path, encrypted_data):
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    def load_encrypted_file(self, file_path):
        with open(file_path, 'rb') as file:
            return file.read()
