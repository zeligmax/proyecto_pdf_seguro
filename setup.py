#!/usr/bin/env python3
"""
Setup script para PDF Secure v2.0
Configura el entorno e instala dependencias
"""

import os
import sys
import subprocess
from pathlib import Path
from cryptography.fernet import Fernet

def print_banner():
    """Muestra el banner de instalación"""
    print("=" * 60)
    print("🔧 PDF SECURE v2.0 - CONFIGURACIÓN INICIAL")
    print("=" * 60)
    print()

def check_python_version():
    """Verifica la versión de Python"""
    print("🐍 Verificando versión de Python...")
    if sys.version_info < (3, 8):
        print("❌ Error: Se requiere Python 3.8 o superior")
        print(f"   Versión actual: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} - Compatible")
    return True

def install_dependencies():
    """Instala las dependencias requeridas"""
    print("\n📦 Instalando dependencias...")
    
    try:
        # Verificar si pip está disponible
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
        print("✅ pip disponible")
    except subprocess.CalledProcessError:
        print("❌ Error: pip no está disponible")
        return False
    
    # Instalar cryptography
    try:
        print("🔧 Instalando cryptography...")
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography>=41.0.0"], 
                      check=True)
        print("✅ cryptography instalado")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error al instalar cryptography: {e}")
        return False
    
    return True

def setup_master_key():
    """Configura la clave maestra"""
    print("\n🔑 Configurando clave maestra...")
    
    # Verificar si ya existe
    if os.getenv('PDF_SECURE_MASTER_KEY'):
        print("✅ Clave maestra ya configurada en variables de entorno")
        return True
    
    # Generar nueva clave
    try:
        master_key = Fernet.generate_key().decode()
        print("🔑 Clave maestra generada exitosamente")
        
        # Mostrar instrucciones
        print("\n📋 IMPORTANTE - CONFIGURACIÓN DE CLAVE MAESTRA:")
        print("=" * 50)
        print("Para usar PDF Secure, debes configurar la siguiente variable de entorno:\n")
        
        print("🐧 Linux/macOS:")
        print(f"export PDF_SECURE_MASTER_KEY='{master_key}'")
        print("# Para hacer permanente, agregar al ~/.bashrc o ~/.zshrc")
        print(f"echo 'export PDF_SECURE_MASTER_KEY=\"{master_key}\"' >> ~/.bashrc")
        
        print("\n🪟 Windows (PowerShell):")
        print(f"$env:PDF_SECURE_MASTER_KEY='{master_key}'")
        print("# Para hacer permanente:")
        print(f"[Environment]::SetEnvironmentVariable('PDF_SECURE_MASTER_KEY', '{master_key}', 'User')")
        
        print("\n🪟 Windows (CMD):")
        print(f"set PDF_SECURE_MASTER_KEY={master_key}")
        
        print("\n⚠️  GUARDA ESTA CLAVE DE FORMA SEGURA")
        print("   Si la pierdes, no podrás descifrar archivos existentes!")
        
        # Guardar en archivo temporal para referencia
        key_file = Path.cwd() / "master_key_backup.txt"
        with open(key_file, 'w') as f:
            f.write(f"PDF Secure v2.0 - Clave Maestra\n")
            f.write(f"Generada el: {__import__('datetime').datetime.now()}\n")
            f.write(f"CLAVE: {master_key}\n\n")
            f.write("IMPORTANTE:\n")
            f.write("- Guarda esta clave en un lugar seguro\n")
            f.write("- Configúrala como variable de entorno\n")
            f.write("- Elimina este archivo después de configurarla\n")
        
        print(f"\n💾 Clave de respaldo guardada en: {key_file}")
        print("   (Elimina este archivo después de configurar la variable de entorno)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error al generar clave maestra: {e}")
        return False

def create_directory_structure():
    """Crea la estructura de directorios"""
    print("\n📁 Creando estructura de directorios...")
    
    config_dir = Path.home() / '.pdf_secure'
    try:
        config_dir.mkdir(exist_ok=True)
        print(f"✅ Directorio de configuración: {config_dir}")
        
        # Crear archivos de configuración iniciales si no existen
        files_to_create = [
            (config_dir / 'ip_whitelist.json', '[]'),
            (config_dir / 'user_keys.json', '{}'),
            (config_dir / 'access_log.json', '[]')
        ]
        
        for file_path, default_content in files_to_create:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    f.write(default_content)
                print(f"✅ Creado: {file_path.name}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error al crear directorios: {e}")
        return False

def verify_installation():
    """Verifica que la instalación sea correcta"""
    print("\n🔍 Verificando instalación...")
    
    # Verificar imports
    try:
        from cryptography.fernet import Fernet
        print("✅ Cryptography importado correctamente")
    except ImportError as e:
        print(f"❌ Error al importar cryptography: {e}")
        return False
    
    # Verificar estructura de archivos
    required_files = [
        'app/config.py',
        'app/user_auth.py', 
        'app/pdf_utils_v2.py',
        'app/ip_check.py',
        'app/main.py',
        'app/app_gui.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print("⚠️  Archivos faltantes:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("   Asegúrate de tener todos los archivos del proyecto")
    else:
        print("✅ Todos los archivos necesarios están presentes")
    
    return len(missing_files) == 0

def show_usage_instructions():
    """Muestra instrucciones de uso"""
    print("\n📖 INSTRUCCIONES DE USO:")
    print("=" * 40)
    print()
    print("1️⃣  Configura la variable de entorno (ver arriba)")
    print()
    print("2️⃣  Ejecutar interfaz gráfica:")
    print("   python app/app_gui.py")
    print()
    print("3️⃣  Ejecutar interfaz de línea de comandos:")
    print("   python app/main.py")
    print()
    print("4️⃣  Estructura de archivos:")
    print("   📁 ~/.pdf_secure/        # Configuración")
    print("   📄 archivo.pdf          # PDF original")
    print("   🔒 archivo.enc          # PDF cifrado")
   🔑 claves_usuario.txt   # Claves generadas
    
    print()
    print("📋 FLUJO DE TRABAJO:")
    print("=" * 30)
    print("1. Cifrar PDF → genera claves para usuarios")
    print("2. Compartir claves de forma segura")
    print("3. Usuarios usan sus claves para descifrar")
    print("4. El sistema registra todos los accesos")
    print()
    print("⚠️  RECORDATORIOS DE SEGURIDAD:")
    print("• Nunca compartas las claves por email/chat")
    print("• Haz backup de ~/.pdf_secure/ regularmente")
    print("• Revisa los logs de acceso periódicamente")
    print("• Las claves expiran automáticamente")

def main():
    """Función principal de configuración"""
    print_banner()
    
    # Verificar Python
    if not check_python_version():
        return False
    
    # Instalar dependencias
    if not install_dependencies():
        print("\n❌ Error en la instalación de dependencias")
        return False
    
    # Configurar clave maestra
    if not setup_master_key():
        print("\n❌ Error en la configuración de clave maestra")
        return False
    
    # Crear directorios
    if not create_directory_structure():
        print("\n❌ Error al crear estructura de directorios")
        return False
    
    # Verificar instalación
    if not verify_installation():
        print("\n⚠️  Instalación incompleta, revisa los archivos faltantes")
    
    # Mostrar instrucciones
    show_usage_instructions()
    
    print("\n" + "=" * 60)
    print("🎉 CONFIGURACIÓN COMPLETADA")
    print("=" * 60)
    print("✅ PDF Secure v2.0 está listo para usar")
    print("🔑 No olvides configurar la variable de entorno")
    print("📚 Consulta la documentación para más detalles")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)