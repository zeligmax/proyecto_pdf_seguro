#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Descifrado Directo - Sin validación de sistema
Usa la clave que está dentro del archivo .enc
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent / 'app'))

from cryptography.fernet import Fernet
from config import SecureConfig


def descifrar_archivo(archivo_enc, clave_usuario, archivo_salida=None):
    """Descifra un archivo usando la clave directa"""
    print("=" * 70)
    print("🔓 DESCIFRADO DIRECTO")
    print("=" * 70)

    # 1. Verificar archivo
    if not Path(archivo_enc).exists():
        print(f"❌ El archivo no existe: {archivo_enc}")
        return

    print(f"\n📄 Archivo: {Path(archivo_enc).name}")
    print(f"🔑 Usando clave: {clave_usuario[:40]}...")

    try:
        # 2. Cargar archivo cifrado
        print("\n📂 Cargando archivo cifrado...")
        with open(archivo_enc, 'r', encoding='utf-8') as f:
            secure_data = json.load(f)

        # 3. Verificar que la clave está en el archivo
        user_keys = secure_data.get('user_keys', {})

        clave_encontrada = False
        usuario_autorizado = None

        for username, stored_key in user_keys.items():
            if stored_key.strip() == clave_usuario.strip():
                clave_encontrada = True
                usuario_autorizado = username
                break

        if not clave_encontrada:
            print(f"\n❌ La clave no está autorizada para este archivo")
            print(f"\n🔑 Claves válidas en el archivo:")
            for username, key in user_keys.items():
                print(f"  👤 {username}: {key}")
            return

        print(f"✅ Clave válida para usuario: {usuario_autorizado}")

        # 4. Obtener clave maestra
        print("\n🔐 Obteniendo clave maestra...")
        config = SecureConfig()
        master_fernet = Fernet(config.get_master_key())

        # 5. Descifrar clave del PDF
        print("🔓 Descifrando clave del PDF...")
        encrypted_pdf_key = bytes.fromhex(secure_data['encrypted_pdf_key'])
        pdf_key = master_fernet.decrypt(encrypted_pdf_key)

        # 6. Descifrar PDF
        print("📄 Descifrando contenido del PDF...")
        pdf_fernet = Fernet(pdf_key)
        encrypted_pdf = bytes.fromhex(secure_data['encrypted_pdf'])
        decrypted_pdf = pdf_fernet.decrypt(encrypted_pdf)

        # 7. Determinar nombre de salida
        if not archivo_salida:
            original_name = secure_data['metadata']['original_filename']
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archivo_salida = Path(archivo_enc).parent / f"decrypted_{timestamp}_{original_name}"

        # 8. Guardar PDF descifrado
        print(f"💾 Guardando archivo descifrado...")
        with open(archivo_salida, 'wb') as f:
            f.write(decrypted_pdf)

        print(f"\n✅ ¡DESCIFRADO EXITOSO!")
        print(f"📂 Archivo guardado en: {archivo_salida}")
        print(f"📊 Tamaño: {len(decrypted_pdf):,} bytes")
        print("\n" + "=" * 70)

    except Exception as e:
        print(f"\n❌ Error durante el descifrado: {str(e)}")
        import traceback
        traceback.print_exc()


def main():
    print("\n" + "=" * 70)
    print(" " * 20 + "🔓 DESCIFRADOR DIRECTO")
    print(" " * 15 + "Descifra sin validación de sistema")
    print("=" * 70)

    # Solicitar datos
    archivo_enc = input("\n📄 Ruta del archivo cifrado (.enc): ").strip()

    if not archivo_enc:
        print("❌ Debe especificar un archivo")
        return

    if not Path(archivo_enc).exists():
        print(f"❌ El archivo no existe: {archivo_enc}")
        return

    # Mostrar la clave que está en el archivo
    try:
        with open(archivo_enc, 'r', encoding='utf-8') as f:
            data = json.load(f)

        user_keys = data.get('user_keys', {})
        if user_keys:
            print(f"\n🔑 Claves disponibles en el archivo:")
            for username, key in user_keys.items():
                print(f"  👤 {username}: {key}")
    except:
        pass

    clave = input("\n🔑 Clave de usuario: ").strip()

    if not clave:
        print("❌ Debe proporcionar una clave")
        return

    archivo_salida = input("💾 Archivo de salida (Enter para auto): ").strip()
    if not archivo_salida:
        archivo_salida = None

    descifrar_archivo(archivo_enc, clave, archivo_salida)


if __name__ == '__main__':
    main()
