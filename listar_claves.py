#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para listar todas las claves registradas
"""

import sys
import os
from pathlib import Path
from datetime import datetime

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent / 'app'))

from config import SecureConfig
from user_auth import UserAuthManager


def main():
    print("=" * 70)
    print("🔑 LISTADO DE CLAVES DE USUARIO REGISTRADAS")
    print("=" * 70)

    config = SecureConfig()
    auth_manager = UserAuthManager(config)

    all_keys = auth_manager.load_user_keys()

    if not all_keys:
        print("\nℹ️  No hay claves registradas en el sistema")
        return

    print(f"\n📊 Total de claves: {len(all_keys)}\n")

    for i, (key_id, key_data) in enumerate(all_keys.items(), 1):
        username = key_data.get('username', 'Unknown')
        pdf_path = key_data.get('pdf_path', 'Unknown')
        pdf_name = Path(pdf_path).name if pdf_path != 'Unknown' else 'Unknown'
        created = key_data.get('created', 'Unknown')
        expires = key_data.get('expires', 'Unknown')
        access_count = key_data.get('access_count', 0)

        # Verificar si expiró
        try:
            expire_date = datetime.fromisoformat(expires)
            is_expired = datetime.now() > expire_date
            status = "❌ EXPIRADA" if is_expired else "✅ VÁLIDA"
        except:
            status = "⚠️ DESCONOCIDO"

        print(f"{'=' * 70}")
        print(f"Clave #{i}")
        print(f"{'=' * 70}")
        print(f"👤 Usuario: {username}")
        print(f"📄 Archivo: {pdf_name}")
        print(f"📂 Ruta: {pdf_path}")
        print(f"🔑 Clave completa: {key_id}")
        print(f"📅 Creada: {created}")
        print(f"⏰ Expira: {expires}")
        print(f"📊 Accesos: {access_count}")
        print(f"🎯 Estado: {status}")
        print()

    print("=" * 70)
    print("💡 Para usar una clave, cópiala completa (sin espacios al final)")
    print("=" * 70)


if __name__ == '__main__':
    main()
