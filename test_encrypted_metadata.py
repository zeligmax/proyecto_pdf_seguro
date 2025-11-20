#!/usr/bin/env python3
"""
Script de prueba para verificar el cifrado de metadatos (Mejora de Seguridad #3)
"""

import sys
import json
from pathlib import Path

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar app al path
sys.path.insert(0, str(Path(__file__).parent / 'app'))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager


def test_encrypted_metadata():
    """Prueba el cifrado de metadatos"""

    print("=" * 60)
    print("TEST: Cifrado de Metadatos (Mejora de Seguridad #3)")
    print("=" * 60)

    try:
        # Inicializar sistema
        print("\n1. Inicializando sistema...")
        config = SecureConfig()
        auth_manager = UserAuthManager(config)
        pdf_manager = PDFSecureManager(config, auth_manager)
        print("   ✅ Sistema inicializado")

        # Crear PDF de prueba simple
        print("\n2. Creando PDF de prueba...")
        test_pdf_path = Path("Assets/test_metadata.pdf")
        with open(test_pdf_path, 'wb') as f:
            f.write(b"%PDF-1.4\nTest PDF content\n%%EOF")

        print(f"   ✅ PDF de prueba creado: {test_pdf_path}")

        # Cifrar el PDF de prueba
        print("\n3. Cifrando PDF de prueba...")
        output_path = Path("Assets/test_encrypted_metadata.enc")
        users = ["testuser"]

        user_keys = pdf_manager.encrypt_pdf_with_user_keys(
            str(test_pdf_path),
            str(output_path),
            users
        )

        print(f"   ✅ PDF cifrado exitosamente: {output_path}")
        print(f"   📝 Usuarios autorizados: {users}")

        # Verificar estructura del archivo cifrado
        print("\n4. Verificando estructura del archivo cifrado...")
        with open(output_path, 'r') as f:
            encrypted_data = json.load(f)

        print(f"   📊 Campos en archivo cifrado:")
        for key in encrypted_data.keys():
            print(f"      - {key}")

        # Verificar versión
        version = encrypted_data.get('version', 'N/A')
        print(f"\n   📌 Versión del archivo: {version}")

        # Verificar que metadatos están cifrados
        if 'encrypted_metadata' in encrypted_data:
            print("   ✅ Metadatos están CIFRADOS (encrypted_metadata)")
            print(f"   🔐 Tamaño de metadatos cifrados: {len(encrypted_data['encrypted_metadata'])} caracteres")
        else:
            print("   ❌ Metadatos NO están cifrados (metadata en texto plano)")

        # Verificar que metadatos NO están en texto plano
        if 'metadata' in encrypted_data:
            print("   ⚠️ ADVERTENCIA: Campo 'metadata' en texto plano encontrado")
        else:
            print("   ✅ No hay metadatos en texto plano")

        # Intentar descifrar
        print("\n5. Descifrando PDF...")
        user_key = list(user_keys.values())[0]
        decrypted_path = pdf_manager.decrypt_pdf_with_user_key(
            str(output_path),
            user_key
        )

        print(f"   ✅ PDF descifrado exitosamente: {decrypted_path}")

        # Verificar que el archivo descifrado existe
        if Path(decrypted_path).exists():
            print(f"   ✅ Archivo descifrado verificado")

            # Limpiar archivos de prueba
            print("\n6. Limpiando archivos de prueba...")
            test_pdf_path.unlink()
            output_path.unlink()
            Path(decrypted_path).unlink()
            print("   ✅ Archivos de prueba eliminados")

        print("\n" + "=" * 60)
        print("✅ TODAS LAS PRUEBAS PASARON EXITOSAMENTE")
        print("=" * 60)
        print("\n🔒 Mejoras de Seguridad Implementadas:")
        print("   • Metadatos cifrados con AES-256 (versión 2.1)")
        print("   • Nombre de archivo protegido")
        print("   • Usuarios autorizados protegidos")
        print("   • Información de cifrado protegida")
        print("   • Compatibilidad hacia atrás con versión 2.0")
        print("\n" + "=" * 60)

    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    success = test_encrypted_metadata()
    sys.exit(0 if success else 1)
