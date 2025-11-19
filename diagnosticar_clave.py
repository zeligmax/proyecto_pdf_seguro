#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Diagnóstico de Claves
Ayuda a diagnosticar problemas con claves de usuario y archivos cifrados
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
from pdf_utils_v2 import PDFSecureManager


def diagnosticar_archivo(archivo_enc):
    """Diagnostica un archivo cifrado"""
    print("=" * 70)
    print("🔍 DIAGNÓSTICO DE ARCHIVO CIFRADO")
    print("=" * 70)

    try:
        config = SecureConfig()
        auth_manager = UserAuthManager(config)
        pdf_manager = PDFSecureManager(config, auth_manager)

        # Verificar que el archivo existe
        if not Path(archivo_enc).exists():
            print(f"❌ El archivo no existe: {archivo_enc}")
            return

        print(f"\n📄 Archivo: {Path(archivo_enc).name}")
        print(f"📂 Ruta completa: {Path(archivo_enc).absolute()}")

        # Obtener información del archivo
        print("\n📊 Información del archivo cifrado:")
        print("-" * 70)

        info = pdf_manager.get_file_info(archivo_enc)

        print(f"  Nombre original: {info['filename']}")
        print(f"  Tamaño: {info['size']:,} bytes")
        print(f"  Cifrado el: {info['encrypted_on']}")
        print(f"  Método: {info['encryption_method']}")
        print(f"  Versión: {info['version']}")

        print(f"\n👥 Usuarios autorizados ({len(info['authorized_users'])}):")
        for user in info['authorized_users']:
            print(f"  • {user}")

        # Verificar claves de usuario
        print(f"\n🔑 Estado de claves de usuario:")
        print("-" * 70)

        if info['user_keys_info']:
            for key_info in info['user_keys_info']:
                print(f"\n  👤 Usuario: {key_info['username']}")
                print(f"     Creada: {key_info['created']}")
                print(f"     Expira: {key_info['expires']}")
                print(f"     Accesos: {key_info['access_count']}")
                if key_info['last_access']:
                    print(f"     Último acceso: {key_info['last_access']}")
        else:
            print("  ⚠️  No hay claves de usuario registradas para este archivo")
            print("\n  💡 PROBLEMA IDENTIFICADO:")
            print("     El archivo fue cifrado pero no se registraron las claves de usuario.")
            print("     Esto puede ocurrir si:")
            print("     1. El archivo fue cifrado con una versión anterior del sistema")
            print("     2. Se eliminó el registro de claves manualmente")
            print("     3. Hubo un error durante el cifrado")

        # Buscar todas las claves en el sistema
        print(f"\n🔎 Buscando claves en el sistema...")
        print("-" * 70)

        all_keys = auth_manager.load_user_keys()

        if not all_keys:
            print("  ℹ️  No hay claves registradas en el sistema")
        else:
            print(f"  ✓ Total de claves registradas: {len(all_keys)}")

            # Buscar claves relacionadas con este archivo
            archivo_path = str(Path(archivo_enc).absolute())
            claves_relacionadas = []

            for key_id, key_data in all_keys.items():
                pdf_path = key_data.get('pdf_path', '')
                if archivo_path in pdf_path or Path(archivo_enc).name in pdf_path:
                    claves_relacionadas.append((key_id, key_data))

            if claves_relacionadas:
                print(f"\n  🎯 Claves encontradas para este archivo ({len(claves_relacionadas)}):")
                for key_id, key_data in claves_relacionadas:
                    username = key_data.get('username', 'Unknown')
                    expires = key_data.get('expires', 'Unknown')

                    # Verificar si expiró
                    try:
                        expire_date = datetime.fromisoformat(expires)
                        is_expired = datetime.now() > expire_date
                        status = "❌ EXPIRADA" if is_expired else "✅ VÁLIDA"
                    except:
                        status = "⚠️ DESCONOCIDO"

                    print(f"\n     Clave: {key_id[:40]}...")
                    print(f"     Usuario: {username}")
                    print(f"     Estado: {status}")
                    print(f"     Expira: {expires}")
            else:
                print("  ⚠️  No se encontraron claves asociadas a este archivo")

                # Mostrar primeras 3 claves disponibles
                print(f"\n  📋 Claves disponibles en el sistema (primeras 3):")
                for i, (key_id, key_data) in enumerate(list(all_keys.items())[:3], 1):
                    username = key_data.get('username', 'Unknown')
                    pdf_name = Path(key_data.get('pdf_path', '')).name
                    print(f"\n     {i}. Usuario: {username}")
                    print(f"        Archivo: {pdf_name}")
                    print(f"        Clave: {key_id[:40]}...")

        # Recomendaciones
        print("\n" + "=" * 70)
        print("💡 RECOMENDACIONES")
        print("=" * 70)

        if not info['user_keys_info']:
            print("\n⚠️  El archivo no tiene claves de usuario registradas.")
            print("\n✅ SOLUCIONES POSIBLES:")
            print("\n1. Si tienes el PDF original sin cifrar:")
            print("   • Vuelve a cifrarlo usando la opción '1. Cifrar PDF'")
            print("   • Guarda las claves que se generen")
            print("\n2. Si cifraste este archivo recientemente:")
            print("   • Verifica que guardaste la clave que se generó al cifrarlo")
            print("   • Las claves se muestran una sola vez después del cifrado")
            print("\n3. Revisa el archivo de logs para ver cuándo se cifró:")
            print("   • Usa la opción '6. Ver logs de acceso' del menú principal")
        else:
            print("\n✅ El archivo tiene claves registradas.")
            print("   Verifica que estás usando la clave correcta y que no haya expirado.")

        print("\n" + "=" * 70)

    except Exception as e:
        print(f"\n❌ Error durante el diagnóstico: {str(e)}")
        import traceback
        traceback.print_exc()


def main():
    if len(sys.argv) < 2:
        print("Uso: python diagnosticar_clave.py <archivo.enc>")
        print("\nEjemplo:")
        print('  python diagnosticar_clave.py "Assets/TECH.enc"')
        sys.exit(1)

    archivo = sys.argv[1]
    diagnosticar_archivo(archivo)


if __name__ == '__main__':
    main()
