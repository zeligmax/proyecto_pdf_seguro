#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test del visualizador de PDF en memoria
"""

import sys
from pathlib import Path

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar directorio app al path
sys.path.append(str(Path(__file__).parent / "app"))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager

def test_view_memory():
    print("=" * 60)
    print("TEST: Descifrado en Memoria (Sin guardar en disco)")
    print("=" * 60)

    # Inicializar sistema
    print("\n1. Inicializando sistema...")
    try:
        config = SecureConfig()
        auth_manager = UserAuthManager(config)
        pdf_manager = PDFSecureManager(config, auth_manager)
        print("   ✅ Sistema inicializado")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return

    # Cargar archivo cifrado
    encrypted_file = Path("Assets/TECH.enc")
    if not encrypted_file.exists():
        print(f"\n❌ Archivo no encontrado: {encrypted_file}")
        return

    print(f"\n2. Archivo cifrado: {encrypted_file}")

    # Obtener información del archivo
    try:
        info = pdf_manager.get_file_info(encrypted_file)
        print(f"   📄 Nombre original: {info['filename']}")
        print(f"   👥 Usuarios autorizados: {', '.join(info['authorized_users'])}")
        print(f"   📦 Tamaño: {info['size']:,} bytes")
    except Exception as e:
        print(f"   ⚠️ No se pudo obtener info: {e}")

    # Pedir clave al usuario
    print("\n3. Introduce la clave de usuario:")
    user_key = input("   Clave: ").strip()

    if not user_key:
        print("   ❌ Clave vacía")
        return

    # Descifrar en memoria
    print("\n4. Descifrando en memoria...")
    try:
        pdf_bytes, original_filename = pdf_manager.decrypt_pdf_to_memory(encrypted_file, user_key)
        print(f"   ✅ PDF descifrado en memoria")
        print(f"   📄 Nombre original: {original_filename}")
        print(f"   📦 Tamaño descifrado: {len(pdf_bytes):,} bytes")
        print(f"   🔒 Archivo NO guardado en disco")

        # Verificar que es un PDF válido
        if pdf_bytes.startswith(b'%PDF'):
            print(f"   ✅ Formato PDF válido")
        else:
            print(f"   ⚠️ Advertencia: El archivo no parece ser un PDF")

        print("\n" + "=" * 60)
        print("✅ TEST EXITOSO: Descifrado en memoria funciona correctamente")
        print("=" * 60)

    except Exception as e:
        print(f"   ❌ Error: {e}")
        print("\n" + "=" * 60)
        print("❌ TEST FALLIDO")
        print("=" * 60)

if __name__ == "__main__":
    test_view_memory()
