from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import os

class AESCipher:
    def __init__(self, password):
        # Derive a 32-byte key using scrypt
        self.key = scrypt(password.encode(), salt=b'salt_', key_len=32, N=2**14, r=8, p=1)

    def encrypt_file(self, file_path, mode="AES-GCM"):
        with open(file_path, 'rb') as file:
            data = file.read()

        if mode == "AES-GCM":
            cipher = AES.new(self.key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return mode.encode() + b"|" + cipher.nonce + tag + ciphertext
        elif mode == "AES-CBC":
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            # Pad data to be a multiple of AES block size
            padded_data = self._pad(data)
            ciphertext = cipher.encrypt(padded_data)
            return mode.encode() + b"|" + iv + ciphertext
        else:
            raise ValueError("Unsupported encryption mode.")

    def decrypt_file(self, encrypted_data):
        mode, encrypted_data = encrypted_data.split(b"|", 1)
        mode = mode.decode()

        if mode == "AES-GCM":
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        elif mode == "AES-CBC":
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            padded_data = cipher.decrypt(ciphertext)
            return self._unpad(padded_data)
        else:
            raise ValueError("Unsupported encryption mode.")

    def save_encrypted_file(self, file_path, encrypted_data):
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    def load_encrypted_file(self, file_path):
        with open(file_path, 'rb') as file:
            return file.read()

    @staticmethod
    def _pad(data):
        # PKCS7 padding
        padding_length = AES.block_size - len(data) % AES.block_size
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def _unpad(data):
        # Remove PKCS7 padding
        padding_length = data[-1]
        if padding_length > AES.block_size or padding_length <= 0:
            raise ValueError("Invalid padding.")
        return data[:-padding_length]
