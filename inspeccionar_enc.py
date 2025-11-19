#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para inspeccionar la estructura de un archivo .enc
"""

import sys
import os
import json
from pathlib import Path

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')


def inspeccionar_archivo(archivo_enc):
    """Inspecciona un archivo .enc y muestra su estructura"""
    print("=" * 70)
    print("🔍 INSPECCIÓN DE ARCHIVO CIFRADO")
    print("=" * 70)

    if not Path(archivo_enc).exists():
        print(f"❌ El archivo no existe: {archivo_enc}")
        return

    print(f"\n📄 Archivo: {Path(archivo_enc).name}")
    print(f"📂 Ruta: {Path(archivo_enc).absolute()}")
    print(f"📊 Tamaño: {Path(archivo_enc).stat().st_size:,} bytes")

    try:
        with open(archivo_enc, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print("\n📋 Estructura del archivo:")
        print("-" * 70)

        # Mostrar todas las claves principales
        print(f"\n🔑 Claves principales en el archivo:")
        for key in data.keys():
            print(f"  • {key}")

        # Información básica
        print(f"\n📊 Metadatos:")
        if 'filename' in data:
            print(f"  Nombre original: {data['filename']}")
        if 'size' in data:
            print(f"  Tamaño original: {data['size']:,} bytes")
        if 'encrypted_on' in data:
            print(f"  Cifrado el: {data['encrypted_on']}")
        if 'version' in data:
            print(f"  Versión: {data['version']}")
        if 'encryption_method' in data:
            print(f"  Método: {data['encryption_method']}")

        # Usuarios autorizados
        if 'authorized_users' in data:
            print(f"\n👥 Usuarios autorizados ({len(data['authorized_users'])}):")
            for user in data['authorized_users']:
                print(f"  • {user}")

        # Claves de usuario
        if 'user_keys' in data:
            user_keys = data['user_keys']
            print(f"\n🔐 Claves de usuario en el archivo ({len(user_keys)}):")
            if user_keys:
                for username, key in user_keys.items():
                    print(f"  👤 {username}: {key[:50]}..." if len(key) > 50 else f"  👤 {username}: {key}")
            else:
                print("  ⚠️  El diccionario de claves está vacío")
                print("\n  💡 PROBLEMA: El archivo no tiene claves registradas dentro del .enc")
                print("     Esto significa que las claves se generaron pero no se guardaron")
                print("     en el archivo cifrado durante el proceso de cifrado.")
        else:
            print(f"\n⚠️  El archivo NO tiene el campo 'user_keys'")

        # Datos cifrados
        if 'encrypted_pdf_key' in data:
            print(f"\n🔒 Clave del PDF cifrada: {data['encrypted_pdf_key'][:50]}...")

        if 'encrypted_data' in data:
            enc_data = data['encrypted_data']
            print(f"\n📦 Datos cifrados: {len(enc_data):,} caracteres")

        print("\n" + "=" * 70)
        print("💡 ANÁLISIS")
        print("=" * 70)

        if 'user_keys' not in data or not data.get('user_keys'):
            print("\n❌ PROBLEMA DETECTADO:")
            print("   El archivo no contiene claves de usuario en su interior.")
            print("\n🔍 CAUSA POSIBLE:")
            print("   1. El archivo fue cifrado con una versión anterior del código")
            print("   2. Hubo un error durante el cifrado que no guardó las claves")
            print("   3. El archivo fue modificado manualmente")
            print("\n✅ SOLUCIÓN:")
            print("   1. Si tienes el PDF original (sin cifrar):")
            print("      → Vuelve a cifrarlo con la opción '1. Cifrar PDF'")
            print("      → El nuevo .enc tendrá las claves guardadas correctamente")
            print("\n   2. Si no tienes el PDF original:")
            print("      → Lamentablemente, el archivo no es descifrable")
            print("      → Las claves generadas no están asociadas al archivo")
        else:
            print("\n✅ El archivo tiene claves registradas correctamente")
            print("   Verifica que estás usando una de las claves mostradas arriba")

    except json.JSONDecodeError as e:
        print(f"\n❌ Error: El archivo no es un JSON válido")
        print(f"   Detalles: {str(e)}")
    except Exception as e:
        print(f"\n❌ Error al inspeccionar: {str(e)}")
        import traceback
        traceback.print_exc()


def main():
    if len(sys.argv) < 2:
        print("Uso: python inspeccionar_enc.py <archivo.enc>")
        print("\nEjemplo:")
        print('  python inspeccionar_enc.py "Assets/TECH.enc"')
        sys.exit(1)

    archivo = sys.argv[1]
    inspeccionar_archivo(archivo)


if __name__ == '__main__':
    main()
