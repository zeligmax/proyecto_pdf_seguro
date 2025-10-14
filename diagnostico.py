#!/usr/bin/env python3
"""
Script de Diagnóstico para PDF Secure v2.0
Ayuda a identificar problemas de cifrado/descifrado
"""

import os
import json
import sys
from pathlib import Path

def print_separator(title=""):
    print("\n" + "=" * 60)
    if title:
        print(f" {title}")
        print("=" * 60)

def check_environment():
    """Verifica el entorno y configuración"""
    print_separator("1. VERIFICACIÓN DE ENTORNO")
    
    # Verificar Python
    print(f"✓ Python: {sys.version.split()[0]}")
    
    # Verificar clave maestra
    master_key = os.getenv('PDF_SECURE_MASTER_KEY')
    if master_key:
        print(f"✓ Clave Maestra: Configurada ({len(master_key)} caracteres)")
    else:
        print("✗ Clave Maestra: NO CONFIGURADA")
        print("  ERROR CRÍTICO: Debes configurar PDF_SECURE_MASTER_KEY")
        return False
    
    # Verificar cryptography
    try:
        from cryptography.fernet import Fernet
        print("✓ Cryptography: Instalado")
    except ImportError:
        print("✗ Cryptography: NO INSTALADO")
        print("  Ejecuta: pip install cryptography")
        return False
    
    return True

def check_config_directory():
    """Verifica el directorio de configuración"""
    print_separator("2. DIRECTORIO DE CONFIGURACIÓN")
    
    config_dir = Path.home() / '.pdf_secure'
    print(f"📁 Ubicación: {config_dir}")
    
    if config_dir.exists():
        print("✓ Directorio existe")
        
        # Listar archivos
        files = list(config_dir.glob('*'))
        print(f"\n📄 Archivos encontrados ({len(files)}):")
        for f in files:
            size = f.stat().st_size
            print(f"  - {f.name} ({size} bytes)")
    else:
        print("✗ Directorio NO existe")
        print("  Creando...")
        config_dir.mkdir(exist_ok=True)
        print("✓ Directorio creado")
    
    return config_dir

def check_user_keys(config_dir):
    """Verifica las claves de usuario almacenadas"""
    print_separator("3. CLAVES DE USUARIO")
    
    user_keys_file = config_dir / 'user_keys.json'
    
    if not user_keys_file.exists():
        print("✗ Archivo user_keys.json NO existe")
        print("  Esto es normal si aún no has cifrado ningún archivo")
        return {}
    
    try:
        with open(user_keys_file, 'r') as f:
            user_keys = json.load(f)
        
        print(f"✓ Archivo cargado correctamente")
        print(f"📊 Total de claves almacenadas: {len(user_keys)}")
        
        if len(user_keys) == 0:
            print("⚠️  No hay claves almacenadas")
            return {}
        
        print("\n🔑 Claves encontradas:")
        for key_id, key_data in user_keys.items():
            print(f"\n  ID: {key_id}")
            print(f"  👤 Usuario: {key_data.get('username', 'Unknown')}")
            print(f"  📄 Archivo: {Path(key_data.get('pdf_path', '')).name}")
            print(f"  🔑 Clave: {key_data.get('user_key', '')[:20]}...")
            print(f"  📅 Creada: {key_data.get('created', 'Unknown')}")
            print(f"  ⏰ Expira: {key_data.get('expires', 'Unknown')}")
            print(f"  📊 Accesos: {key_data.get('access_count', 0)}")
        
        return user_keys
    
    except json.JSONDecodeError as e:
        print(f"✗ Error al leer archivo: {e}")
        print("  El archivo puede estar corrupto")
        return {}
    except Exception as e:
        print(f"✗ Error inesperado: {e}")
        return {}

def analyze_encrypted_file(file_path):
    """Analiza un archivo cifrado"""
    print_separator("4. ANÁLISIS DE ARCHIVO CIFRADO")
    
    if not file_path:
        print("⚠️  No se especificó archivo para analizar")
        return
    
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"✗ Archivo NO existe: {file_path}")
        return
    
    print(f"📄 Archivo: {file_path.name}")
    print(f"📊 Tamaño: {file_path.stat().st_size:,} bytes")
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        print("✓ Formato JSON válido")
        
        # Verificar estructura
        required_keys = ['encrypted_pdf', 'encrypted_pdf_key', 'user_keys', 'metadata']
        missing_keys = [k for k in required_keys if k not in data]
        
        if missing_keys:
            print(f"✗ Faltan campos: {', '.join(missing_keys)}")
            return
        
        print("✓ Estructura correcta")
        
        # Información del archivo
        metadata = data.get('metadata', {})
        print(f"\n📋 Metadatos:")
        print(f"  Archivo original: {metadata.get('original_filename', 'Unknown')}")
        print(f"  Tamaño original: {metadata.get('original_size', 0):,} bytes")
        print(f"  Cifrado el: {metadata.get('encrypted_on', 'Unknown')}")
        print(f"  Método: {metadata.get('encryption_method', 'Unknown')}")
        print(f"  Versión: {metadata.get('version', 'Unknown')}")
        
        # Usuarios autorizados
        user_keys = data.get('user_keys', {})
        print(f"\n👥 Usuarios autorizados ({len(user_keys)}):")
        for username, user_key in user_keys.items():
            print(f"  - {username}: {user_key[:20]}...")
        
        return data
    
    except json.JSONDecodeError as e:
        print(f"✗ Error al leer archivo: NO es un JSON válido")
        print(f"  El archivo puede estar corrupto o no ser un archivo cifrado")
    except Exception as e:
        print(f"✗ Error inesperado: {e}")

def test_decrypt(encrypted_file, user_key, config_dir):
    """Prueba el descifrado paso a paso"""
    print_separator("5. PRUEBA DE DESCIFRADO")
    
    if not encrypted_file or not user_key:
        print("⚠️  Necesitas especificar archivo y clave para probar descifrado")
        return
    
    encrypted_file = Path(encrypted_file)
    
    if not encrypted_file.exists():
        print(f"✗ Archivo NO existe: {encrypted_file}")
        return
    
    print(f"📄 Archivo: {encrypted_file.name}")
    print(f"🔑 Clave proporcionada: {user_key[:20]}...")
    
    # Paso 1: Cargar archivo cifrado
    print("\n📥 Paso 1: Cargando archivo cifrado...")
    try:
        with open(encrypted_file, 'r') as f:
            secure_data = json.load(f)
        print("  ✓ Archivo cargado")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return
    
    # Paso 2: Verificar clave en archivo
    print("\n🔍 Paso 2: Verificando clave en archivo...")
    user_keys_in_file = secure_data.get('user_keys', {})
    
    found = False
    for username, stored_key in user_keys_in_file.items():
        if stored_key == user_key:
            print(f"  ✓ Clave encontrada para usuario: {username}")
            found = True
            break
    
    if not found:
        print("  ✗ Clave NO encontrada en el archivo")
        print("\n  🔍 Claves válidas para este archivo:")
        for username, stored_key in user_keys_in_file.items():
            print(f"    - Usuario: {username}")
            print(f"      Clave: {stored_key[:20]}...")
            print(f"      ¿Coincide?: {stored_key == user_key}")
        return
    
    # Paso 3: Buscar en base de datos de claves
    print("\n📚 Paso 3: Verificando en base de datos...")
    user_keys_file = config_dir / 'user_keys.json'
    
    if not user_keys_file.exists():
        print("  ✗ Base de datos de claves NO existe")
        print("  Esto puede pasar si cifraste en otra máquina")
        return
    
    try:
        with open(user_keys_file, 'r') as f:
            db_keys = json.load(f)
        
        found_in_db = False
        for key_id, key_data in db_keys.items():
            if key_data.get('user_key') == user_key:
                print(f"  ✓ Clave encontrada en base de datos")
                print(f"    Usuario: {key_data.get('username')}")
                print(f"    Archivo: {Path(key_data.get('pdf_path', '')).name}")
                
                # Verificar expiración
                from datetime import datetime
                try:
                    expires = datetime.fromisoformat(key_data['expires'])
                    if datetime.now() > expires:
                        print(f"  ✗ ERROR: La clave EXPIRÓ el {expires.strftime('%Y-%m-%d')}")
                        return
                    else:
                        print(f"  ✓ Clave válida hasta: {expires.strftime('%Y-%m-%d')}")
                except:
                    pass
                
                found_in_db = True
                break
        
        if not found_in_db:
            print("  ⚠️  Clave NO encontrada en base de datos")
            print("  Pero puede funcionar si coincide con el archivo")
    
    except Exception as e:
        print(f"  ⚠️  Error al leer base de datos: {e}")
    
    # Paso 4: Verificar clave maestra
    print("\n🔐 Paso 4: Verificando clave maestra...")
    master_key = os.getenv('PDF_SECURE_MASTER_KEY')
    if not master_key:
        print("  ✗ ERROR CRÍTICO: Clave maestra NO configurada")
        return
    
    try:
        from cryptography.fernet import Fernet
        master_fernet = Fernet(master_key.encode())
        print("  ✓ Clave maestra válida")
    except Exception as e:
        print(f"  ✗ ERROR: Clave maestra inválida: {e}")
        return
    
    # Paso 5: Intentar descifrar
    print("\n🔓 Paso 5: Intentando descifrar...")
    try:
        # Descifrar clave del PDF
        encrypted_pdf_key = bytes.fromhex(secure_data['encrypted_pdf_key'])
        pdf_key = master_fernet.decrypt(encrypted_pdf_key)
        print("  ✓ Clave del PDF descifrada")
        
        # Descifrar PDF
        pdf_fernet = Fernet(pdf_key)
        encrypted_pdf = bytes.fromhex(secure_data['encrypted_pdf'])
        decrypted_pdf = pdf_fernet.decrypt(encrypted_pdf)
        print("  ✓ PDF descifrado correctamente")
        
        print(f"\n✅ ÉXITO: El archivo se puede descifrar")
        print(f"   Tamaño del PDF descifrado: {len(decrypted_pdf):,} bytes")
        
    except Exception as e:
        print(f"  ✗ ERROR al descifrar: {e}")
        print(f"\n  Tipo de error: {type(e).__name__}")
        
        if "Invalid" in str(e):
            print("\n  💡 Posibles causas:")
            print("     1. La clave maestra cambió desde que se cifró")
            print("     2. El archivo está corrupto")
            print("     3. La clave de usuario no es correcta")

def main():
    """Función principal del diagnóstico"""
    print("🔍 PDF SECURE v2.0 - HERRAMIENTA DE DIAGNÓSTICO")
    
    # 1. Verificar entorno
    if not check_environment():
        print("\n❌ El entorno NO está configurado correctamente")
        print("   Configura la clave maestra antes de continuar")
        return
    
    # 2. Verificar directorio
    config_dir = check_config_directory()
    
    # 3. Ver claves almacenadas
    user_keys = check_user_keys(config_dir)
    
    # 4. Preguntar por archivo a analizar
    print_separator("ANÁLISIS DE ARCHIVO ESPECÍFICO")
    print("\n¿Quieres analizar un archivo cifrado específico?")
    print("Ingresa la ruta completa del archivo .enc (o presiona Enter para salir)")
    
    encrypted_file = input("\n📄 Archivo cifrado: ").strip()
    
    if encrypted_file:
        # Analizar archivo
        file_data = analyze_encrypted_file(encrypted_file)
        
        if file_data:
            # Preguntar por clave para probar descifrado
            print("\n¿Quieres probar descifrar este archivo?")
            print("Ingresa la clave de usuario (o presiona Enter para salir)")
            
            user_key = input("\n🔑 Clave: ").strip()
            
            if user_key:
                test_decrypt(encrypted_file, user_key, config_dir)
    
    print_separator("DIAGNÓSTICO COMPLETADO")
    print("\n💡 Si tienes problemas:")
    print("   1. Verifica que la clave maestra sea la misma que cuando cifraste")
    print("   2. Asegúrate de copiar la clave completa (sin espacios)")
    print("   3. Verifica que la clave no haya expirado")
    print("   4. Revisa los logs en ~/.pdf_secure/access_log.json")

if __name__ == "__main__":
    main()