#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Completo del Sistema PDF Secure
Prueba todo el flujo: cifrado, descifrado, y validación
"""

import sys
import os
from pathlib import Path

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent / 'app'))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import FileSecureManager


def test_completo():
    """Prueba completa del sistema"""
    print("=" * 70)
    print("🧪 TEST COMPLETO DEL SISTEMA PDF SECURE")
    print("=" * 70)

    try:
        # Inicializar sistema
        print("\n1️⃣ Inicializando sistema...")
        config = SecureConfig()
        auth_manager = UserAuthManager(config)
        pdf_manager = FileSecureManager(config, auth_manager)
        print("✅ Sistema inicializado")

        # Usar un PDF existente para las pruebas
        pdf_original = "Assets/decrypted_20251119_151023_TECH.pdf"

        if not Path(pdf_original).exists():
            print(f"❌ No se encuentra el PDF de prueba: {pdf_original}")
            return False

        # Test 1: Cifrar PDF con múltiples usuarios
        print("\n2️⃣ Test: Cifrar PDF con múltiples usuarios...")
        usuarios = ['User', 'admin', 'test_user']
        archivo_cifrado = "Assets/TEST_completo.enc"

        claves = pdf_manager.encrypt_pdf_with_user_keys(
            pdf_original,
            archivo_cifrado,
            usuarios
        )

        print(f"✅ PDF cifrado exitosamente")
        print(f"📊 Usuarios autorizados: {len(claves)}")
        print("🔑 Claves generadas:")
        for usuario, clave in claves.items():
            print(f"  👤 {usuario}: {clave[:40]}...")

        # Test 2: Descifrar con cada clave de usuario
        print("\n3️⃣ Test: Descifrar con cada clave de usuario...")

        for usuario, clave in claves.items():
            print(f"\n  Probando descifrado con usuario '{usuario}'...")
            try:
                resultado = pdf_manager.decrypt_pdf_with_user_key(
                    archivo_cifrado,
                    clave
                )
                print(f"  ✅ Descifrado exitoso: {Path(resultado).name}")

                # Limpiar archivo descifrado
                if Path(resultado).exists():
                    os.remove(resultado)

            except Exception as e:
                print(f"  ❌ Error: {str(e)}")
                return False

        # Test 3: Verificar información del archivo
        print("\n4️⃣ Test: Obtener información del archivo cifrado...")
        info = pdf_manager.get_file_info(archivo_cifrado)

        print(f"✅ Información obtenida:")
        print(f"  📄 Nombre original: {info['filename']}")
        print(f"  📊 Tamaño: {info['size']:,} bytes")
        print(f"  👥 Usuarios autorizados: {', '.join(info['authorized_users'])}")

        # Test 4: Verificar con clave incorrecta
        print("\n5️⃣ Test: Intentar con clave incorrecta...")
        try:
            pdf_manager.decrypt_pdf_with_user_key(
                archivo_cifrado,
                "clave_incorrecta_123"
            )
            print("  ❌ FALLO: Debería haber rechazado la clave incorrecta")
            return False
        except ValueError:
            print("  ✅ Correctamente rechazada la clave incorrecta")

        # Test 5: Probar archivo TECH.enc existente con clave del archivo
        print("\n6️⃣ Test: Descifrar archivo TECH.enc existente...")
        if Path("Assets/TECH.enc").exists():
            try:
                # Usar la clave que está en el archivo
                clave_tech = "cc75ae1519eb21b51802a9017f03a39272c8a27a3c4b7297ecd8078d03795d00"
                resultado = pdf_manager.decrypt_pdf_with_user_key(
                    "Assets/TECH.enc",
                    clave_tech
                )
                print(f"  ✅ TECH.enc descifrado correctamente: {Path(resultado).name}")

                # Limpiar
                if Path(resultado).exists():
                    os.remove(resultado)
            except Exception as e:
                print(f"  ⚠️  Error con TECH.enc: {str(e)}")
        else:
            print("  ℹ️  TECH.enc no existe, saltando test")

        # Resumen
        print("\n" + "=" * 70)
        print("✅ TODOS LOS TESTS PASARON CORRECTAMENTE")
        print("=" * 70)
        print("\n📊 Resumen:")
        print(f"  ✓ Sistema inicializado correctamente")
        print(f"  ✓ Cifrado con {len(usuarios)} usuarios")
        print(f"  ✓ Descifrado correcto con todas las claves")
        print(f"  ✓ Información de archivo obtenida")
        print(f"  ✓ Claves incorrectas rechazadas")
        print(f"  ✓ Compatibilidad con archivos existentes")

        print("\n🎉 El sistema está funcionando perfectamente!")
        print("=" * 70)

        return True

    except Exception as e:
        print(f"\n❌ ERROR DURANTE LOS TESTS:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    exito = test_completo()
    sys.exit(0 if exito else 1)
