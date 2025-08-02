from cryptography.fernet import Fernet
import os

def generate_key():
    return Fernet.generate_key()

def encrypt_pdf(input_path, output_path, key):
    fernet = Fernet(key)
    with open(input_path, 'rb') as f_in:
        encrypted = fernet.encrypt(f_in.read())
    with open(output_path, 'wb') as f_out:
        f_out.write(encrypted)

def decrypt_pdf(input_path, output_path, key):
    fernet = Fernet(key)
    with open(input_path, 'rb') as f_in:
        decrypted = fernet.decrypt(f_in.read())
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted)
