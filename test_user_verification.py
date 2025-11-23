#!/usr/bin/env python3
"""
Test de verificación de usuario del sistema
"""

import sys
from pathlib import Path
import getpass

# Agregar directorio app al path
sys.path.append(str(Path(__file__).parent / "app"))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import FileSecureManager

def test_user_verification():
    print("=" * 60)
    print("TEST: Verificación de Usuario del Sistema")
    print("=" * 60)

    # 1. Detectar usuario actual
    try:
        current_user = getpass.getuser()
    except:
        import os
        try:
            current_user = os.getlogin()
        except:
            current_user = "Unknown"

    print(f"\n1. Usuario actual del sistema: {current_user}")

    # 2. Inicializar sistema
    print("\n2. Inicializando sistema...")
    try:
        config = SecureConfig()
        auth_manager = UserAuthManager(config)
        pdf_manager = FileSecureManager(config, auth_manager)
        print("   OK - Sistema inicializado")
    except Exception as e:
        print(f"   ERROR: {e}")
        return

    # 3. Verificar archivo cifrado
    encrypted_file = Path("Assets/TECH.enc")
    if not encrypted_file.exists():
        print(f"\n   ERROR: No se encontró {encrypted_file}")
        return

    print(f"\n3. Archivo a descifrar: {encrypted_file}")

    # 4. Obtener info del archivo
    try:
        info = pdf_manager.get_file_info(encrypted_file)
        print(f"   Usuarios autorizados: {info['authorized_users']}")
    except Exception as e:
        print(f"   WARNING: No se pudo obtener info: {e}")

    # 5. Intentar descifrar
    print("\n4. Introduce la clave de usuario:")
    user_key = input("   Clave: ").strip()

    if not user_key:
        print("   ERROR: Clave vacía")
        return

    print(f"\n5. Intentando descifrar...")
    print(f"   Usuario del sistema: {current_user}")
    print(f"   Verificando autorizacion...")

    try:
        # Intentar descifrar en memoria
        pdf_bytes, filename = pdf_manager.decrypt_pdf_to_memory(encrypted_file, user_key)
        print(f"\n   OK - Descifrado exitoso!")
        print(f"   Archivo: {filename}")
        print(f"   Tamaño: {len(pdf_bytes):,} bytes")
        print(f"\n   La clave pertenece a un usuario autorizado")
        print(f"   Y el usuario del sistema coincide con el autorizado")

    except ValueError as e:
        error_msg = str(e)
        print(f"\n   ERROR: {error_msg}")

        if "Usuario del sistema no coincide" in error_msg:
            print(f"\n   CAUSA: El usuario '{current_user}' no coincide con el usuario")
            print(f"          autorizado para esa clave.")
            print(f"\n   SOLUCION: Debes estar logueado como el usuario correcto")
            print(f"             para descifrar este archivo.")
        elif "Clave de usuario no autorizada" in error_msg:
            print(f"\n   CAUSA: La clave no es válida para este archivo.")
        else:
            print(f"\n   CAUSA: Error desconocido")

    except Exception as e:
        print(f"\n   ERROR inesperado: {type(e).__name__}: {e}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_user_verification()
