#!/usr/bin/env python3
"""
Descifrador Simple para PDF Secure v2.0
Usa este script si la GUI o CLI no funcionan correctamente
"""

import os
import sys
import json
from pathlib import Path
from cryptography.fernet import Fernet

def descifrar_pdf(archivo_enc, clave_usuario):
    """
    Descifra un archivo PDF usando la clave de usuario
    
    Args:
        archivo_enc: Ruta del archivo .enc
        clave_usuario: Clave de usuario (la cadena larga que te dieron)
    
    Returns:
        Ruta del archivo descifrado o None si falla
    """
    
    print(f"🔓 Descifrando: {Path(archivo_enc).name}")
    print("-" * 50)
    
    # 1. Verificar clave maestra
    print("1️⃣ Verificando clave maestra...")
    master_key = os.getenv('PDF_SECURE_MASTER_KEY')
    if not master_key:
        print("❌ ERROR: PDF_SECURE_MASTER_KEY no configurada")
        print("   Ejecuta: $env:PDF_SECURE_MASTER_KEY = 'tu_clave'")
        return None
    
    try:
        master_fernet = Fernet(master_key.encode())
        print("   ✅ Clave maestra válida")
    except Exception as e:
        print(f"   ❌ ERROR: Clave maestra inválida: {e}")
        return None
    
    # 2. Cargar archivo cifrado
    print("\n2️⃣ Cargando archivo cifrado...")
    try:
        with open(archivo_enc, 'r', encoding='utf-8') as f:
            secure_data = json.load(f)
        print("   ✅ Archivo cargado")
    except FileNotFoundError:
        print(f"   ❌ ERROR: Archivo no encontrado: {archivo_enc}")
        return None
    except json.JSONDecodeError:
        print("   ❌ ERROR: Archivo corrupto o no es un archivo cifrado válido")
        return None
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return None
    
    # 3. Verificar clave de usuario
    print("\n3️⃣ Verificando clave de usuario...")
    user_keys = secure_data.get('user_keys', {})
    
    usuario_encontrado = None
    for username, stored_key in user_keys.items():
        if stored_key == clave_usuario:
            usuario_encontrado = username
            break
    
    if not usuario_encontrado:
        print("   ❌ ERROR: Clave de usuario no válida para este archivo")
        print("\n   👥 Usuarios autorizados:")
        for username in user_keys.keys():
            print(f"      - {username}")
        return None
    
    print(f"   ✅ Clave válida para usuario: {usuario_encontrado}")
    
    # 4. Descifrar clave del PDF
    print("\n4️⃣ Descifrando clave del PDF...")
    try:
        encrypted_pdf_key = bytes.fromhex(secure_data['encrypted_pdf_key'])
        pdf_key = master_fernet.decrypt(encrypted_pdf_key)
        print("   ✅ Clave del PDF descifrada")
    except Exception as e:
        print(f"   ❌ ERROR: No se pudo descifrar la clave del PDF: {e}")
        return None
    
    # 5. Descifrar PDF
    print("\n5️⃣ Descifrando contenido del PDF...")
    try:
        pdf_fernet = Fernet(pdf_key)
        encrypted_pdf = bytes.fromhex(secure_data['encrypted_pdf'])
        decrypted_pdf = pdf_fernet.decrypt(encrypted_pdf)
        print(f"   ✅ PDF descifrado ({len(decrypted_pdf):,} bytes)")
    except Exception as e:
        print(f"   ❌ ERROR: No se pudo descifrar el PDF: {e}")
        return None
    
    # 6. Guardar archivo descifrado
    print("\n6️⃣ Guardando archivo descifrado...")
    
    # Determinar nombre de salida
    original_name = secure_data.get('metadata', {}).get('original_filename', 'documento.pdf')
    output_dir = Path(archivo_enc).parent
    
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = output_dir / f"decrypted_{timestamp}_{original_name}"
    
    try:
        with open(output_path, 'wb') as f:
            f.write(decrypted_pdf)
        print(f"   ✅ Archivo guardado: {output_path}")
    except Exception as e:
        print(f"   ❌ ERROR: No se pudo guardar el archivo: {e}")
        return None
    
    print("\n" + "=" * 50)
    print("✅ ¡DESCIFRADO EXITOSO!")
    print(f"📄 Archivo: {output_path}")
    print("=" * 50)
    
    return str(output_path)


def main():
    """Función principal - modo interactivo"""
    
    print("=" * 60)
    print("🔓 PDF SECURE v2.0 - DESCIFRADOR SIMPLE")
    print("=" * 60)
    print()
    
    # Solicitar archivo
    print("📁 Ingresa la ruta del archivo cifrado (.enc)")
    print("   Puedes arrastrar el archivo a la terminal")
    archivo_enc = input("\n📄 Archivo: ").strip()
    
    # Limpiar comillas si las tiene (por drag & drop)
    archivo_enc = archivo_enc.strip('"').strip("'")
    
    if not archivo_enc:
        print("❌ No se especificó ningún archivo")
        return
    
    if not Path(archivo_enc).exists():
        print(f"❌ ERROR: El archivo no existe")
        print(f"   Ruta: {archivo_enc}")
        return
    
    print()
    
    # Solicitar clave
    print("🔑 Ingresa la clave de usuario")
    print("   (la cadena larga que se generó al cifrar)")
    clave = input("\n🔑 Clave: ").strip()
    
    if not clave:
        print("❌ No se especificó ninguna clave")
        return
    
    print()
    print("=" * 60)
    
    # Descifrar
    resultado = descifrar_pdf(archivo_enc, clave)
    
    if resultado:
        print("\n✨ Puedes abrir el archivo descifrado con cualquier lector de PDF")
        
        # Preguntar si quiere abrir el archivo
        print("\n¿Quieres abrir el archivo ahora? (s/n)")
        respuesta = input("➡️  ").strip().lower()
        
        if respuesta in ['s', 'si', 'sí', 'y', 'yes']:
            try:
                import subprocess
                import platform
                
                if platform.system() == 'Windows':
                    os.startfile(resultado)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.run(['open', resultado])
                else:  # Linux
                    subprocess.run(['xdg-open', resultado])
                
                print("✅ Archivo abierto")
            except Exception as e:
                print(f"⚠️  No se pudo abrir automáticamente: {e}")
                print(f"   Abre manualmente: {resultado}")
    else:
        print("\n❌ No se pudo descifrar el archivo")
        print("\n💡 Posibles soluciones:")
        print("   1. Verifica que la clave sea correcta (copia/pega completa)")
        print("   2. Asegúrate que la clave maestra sea la misma")
        print("   3. Ejecuta diagnostico.py para más detalles")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Operación cancelada")
    except Exception as e:
        print(f"\n❌ ERROR INESPERADO: {e}")
        import traceback
        traceback.print_exc()