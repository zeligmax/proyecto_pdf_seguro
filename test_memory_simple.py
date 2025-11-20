#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.append('app')

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager

# Inicializar
config = SecureConfig()
auth = UserAuthManager(config)
pdf_manager = PDFSecureManager(config, auth)

# Descifrar en memoria
encrypted_file = Path('Assets/TECH.enc')
user_key = '6e265fa36c8f3bfdcba367678abf52ced6066b89eb1200832b193e5c6f0226ca'

print("Descifrando en memoria...")
pdf_bytes, filename = pdf_manager.decrypt_pdf_to_memory(encrypted_file, user_key)

print(f"OK - Descifrado exitoso")
print(f"Nombre: {filename}")
print(f"Tamano: {len(pdf_bytes)} bytes")
print(f"NO guardado en disco")
print(f"Es PDF valido: {pdf_bytes.startswith(b'%PDF')}")
