#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDF Secure CLI - Version 2.0
Interfaz de línea de comandos para el sistema de PDFs seguros con autenticación por usuario.
"""

import os
import sys
from pathlib import Path

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager
from ip_check import IPChecker
from api_manager import get_api_manager

class PDFSecureCLI:
    def __init__(self):
        try:
            self.config = SecureConfig()
            self.auth_manager = UserAuthManager(self.config)
            self.pdf_manager = PDFSecureManager(self.config, self.auth_manager)
            self.ip_checker = IPChecker(self.config)
        except ValueError as e:
            print(f"❌ Error de configuración: {e}")
            print("\nPara configurar la clave maestra, ejecuta:")
            print("export PDF_SECURE_MASTER_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')")
            sys.exit(1)
    
    def show_banner(self):
        """Muestra el banner de la aplicación"""
        print("\n" + "="*60)
        print("📄 PDF SECURE v2.0 - Sistema de PDFs Seguros")
        print("🔐 Con autenticación por usuario y trazabilidad completa")
        print("="*60)
        
        # Mostrar información del sistema
        network_info = self.ip_checker.get_network_info()
        print(f"🖥️  Sistema: {network_info['hostname']} ({network_info['local_ip']})")
        
        # Mostrar estado de whitelist
        whitelist = self.config.load_ip_whitelist()
        if whitelist:
            print(f"✅ IPs autorizadas: {len(whitelist)}")
        else:
            print("⚠️  Sin whitelist de IPs configurada")
        
        print()
    
    def show_main_menu(self):
        """Muestra el menú principal"""
        print("🔧 MENÚ PRINCIPAL")
        print("-" * 30)
        print("1. 🔒 Cifrar PDF")
        print("2. 🔓 Descifrar PDF")
        print("3. 📋 Ver información de archivo")
        print("4. 👥 Gestionar usuarios")
        print("5. 🌐 Gestionar IPs autorizadas")
        print("6. 📊 Ver logs de acceso")
        print("7. 🧹 Mantenimiento")
        print("8. 🔍 Gestionar API de Usuarios")
        print("9. ❓ Ayuda")
        print("0. 🚪 Salir")
        print("-" * 30)
    
    def encrypt_pdf_interactive(self):
        """Proceso interactivo de cifrado de PDF"""
        print("\n🔒 CIFRAR PDF")
        print("-" * 30)
        
        # Solicitar archivo PDF
        pdf_path = input("📄 Ruta del archivo PDF: ").strip()
        if not pdf_path:
            print("❌ Debe especificar un archivo PDF")
            return
        
        if not Path(pdf_path).exists():
            print(f"❌ El archivo no existe: {pdf_path}")
            return
        
        # Solicitar archivo de salida
        default_output = str(Path(pdf_path).with_suffix('.enc'))
        output_path = input(f"💾 Archivo de salida [{default_output}]: ").strip()
        if not output_path:
            output_path = default_output
        
        # Solicitar usuarios autorizados
        print("\n👥 Usuarios autorizados (separados por comas):")
        users_input = input("Usuarios: ").strip()
        if not users_input:
            print("❌ Debe especificar al menos un usuario")
            return
        
        authorized_users = [u.strip() for u in users_input.split(',') if u.strip()]
        
        try:
            print(f"\n🔄 Cifrando '{Path(pdf_path).name}'...")
            user_keys = self.pdf_manager.encrypt_pdf_with_user_keys(
                pdf_path, output_path, authorized_users
            )
            
            print(f"✅ PDF cifrado exitosamente: {output_path}")
            print("\n🔑 CLAVES DE USUARIO GENERADAS:")
            print("-" * 50)
            for username, key in user_keys.items():
                print(f"👤 {username}")
                print(f"   Clave: {key}")
                print()
            
            print("⚠️  IMPORTANTE: Guarda estas claves de forma segura.")
            print("   Cada usuario necesita su clave para acceder al PDF.")
            
        except Exception as e:
            print(f"❌ Error al cifrar: {str(e)}")
    
    def decrypt_pdf_interactive(self):
        """Proceso interactivo de descifrado de PDF"""
        print("\n🔓 DESCIFRAR PDF")
        print("-" * 30)

        # Mostrar usuario actual del sistema
        import getpass
        try:
            current_user = getpass.getuser()
        except:
            import os
            try:
                current_user = os.getlogin()
            except:
                current_user = "Unknown"

        print(f"\n👤 Usuario del sistema: {current_user}")
        print("ℹ️  Solo podrás descifrar archivos autorizados para este usuario")
        print()

        # Solicitar archivo cifrado
        encrypted_path = input("🔒 Ruta del archivo cifrado (.enc): ").strip()
        if not encrypted_path:
            print("❌ Debe especificar un archivo cifrado")
            return
        
        if not Path(encrypted_path).exists():
            print(f"❌ El archivo no existe: {encrypted_path}")
            return
        
        # Solicitar clave de usuario
        user_key = input("🔑 Clave de usuario: ").strip()
        if not user_key:
            print("❌ Debe proporcionar la clave de usuario")
            return
        
        # Solicitar archivo de salida (opcional)
        output_path = input("💾 Archivo de salida (opcional): ").strip()
        if not output_path:
            output_path = None
        
        try:
            print(f"\n🔄 Descifrando '{Path(encrypted_path).name}'...")
            
            # Verificar autorización IP si aplica
            ip_auth, ip_info = self.ip_checker.is_ip_authorized()
            if not ip_auth:
                print(f"❌ {ip_info['reason']}")
                print(f"   Tu IP: {ip_info['ip']}")
                return
            
            # Descifrar archivo
            decrypted_path = self.pdf_manager.decrypt_pdf_with_user_key(
                encrypted_path, user_key, output_path
            )
            
            print(f"✅ PDF descifrado exitosamente: {decrypted_path}")
            
        except Exception as e:
            print(f"❌ Error al descifrar: {str(e)}")
    
    def show_file_info(self):
        """Muestra información sobre un archivo cifrado"""
        print("\n📋 INFORMACIÓN DE ARCHIVO")
        print("-" * 30)
        
        encrypted_path = input("🔒 Ruta del archivo cifrado: ").strip()
        if not encrypted_path or not Path(encrypted_path).exists():
            print("❌ Archivo no válido o no existe")
            return
        
        try:
            info = self.pdf_manager.get_file_info(encrypted_path)
            
            print(f"\n📄 Archivo: {info['filename']}")
            print(f"📊 Tamaño original: {info['size']:,} bytes")
            print(f"🕐 Cifrado el: {info['encrypted_on']}")
            print(f"🔐 Método: {info['encryption_method']}")
            print(f"📦 Versión: {info['version']}")
            
            print(f"\n👥 Usuarios autorizados ({len(info['authorized_users'])}):")
            for user in info['authorized_users']:
                print(f"   • {user}")
            
            if info['user_keys_info']:
                print(f"\n🔑 Estado de claves:")
                for key_info in info['user_keys_info']:
                    print(f"   👤 {key_info['username']}")
                    print(f"      Creada: {key_info['created']}")
                    print(f"      Expira: {key_info['expires']}")
                    print(f"      Accesos: {key_info['access_count']}")
                    if key_info['last_access']:
                        print(f"      Último acceso: {key_info['last_access']}")
                    print()
            
        except Exception as e:
            print(f"❌ Error al obtener información: {str(e)}")
    
    def manage_users(self):
        """Gestión de usuarios y claves"""
        while True:
            print("\n👥 GESTIÓN DE USUARIOS")
            print("-" * 30)
            print("1. 📋 Listar claves activas")
            print("2. ❌ Revocar clave específica")
            print("3. ⏰ Extender expiración de clave")
            print("4. 🧹 Limpiar claves expiradas")
            print("5. 🔙 Volver al menú principal")
            
            choice = input("\nSelecciona opción: ").strip()
            
            if choice == "1":
                self.list_active_keys()
            elif choice == "2":
                self.revoke_user_key()
            elif choice == "3":
                self.extend_key_expiration()
            elif choice == "4":
                self.cleanup_expired_keys()
            elif choice == "5":
                break
            else:
                print("❌ Opción no válida")
    
    def list_active_keys(self):
        """Lista todas las claves activas"""
        print("\n📋 CLAVES ACTIVAS")
        print("-" * 40)
        
        user_keys = self.auth_manager.load_user_keys()
        active_keys = []
        
        for key_id, key_data in user_keys.items():
            from datetime import datetime
            try:
                expires = datetime.fromisoformat(key_data['expires'])
                if datetime.now() <= expires:
                    active_keys.append((key_id, key_data))
            except (ValueError, KeyError):
                continue
        
        if not active_keys:
            print("ℹ️  No hay claves activas")
            return
        
        for i, (key_id, key_data) in enumerate(active_keys, 1):
            print(f"{i}. 👤 {key_data.get('username', 'Unknown')}")
            print(f"   📄 Archivo: {Path(key_data.get('pdf_path', '')).name}")
            print(f"   🔑 ID: {key_id[:16]}...")
            print(f"   📅 Expira: {key_data.get('expires')}")
            print(f"   📊 Accesos: {key_data.get('access_count', 0)}")
            print()
    
    def revoke_user_key(self):
        """Revoca una clave específica"""
        print("\n❌ REVOCAR CLAVE")
        print("-" * 30)
        
        user_key = input("🔑 Clave de usuario a revocar: ").strip()
        if not user_key:
            return
        
        if self.auth_manager.revoke_user_key(user_key):
            print("✅ Clave revocada exitosamente")
        else:
            print("❌ Clave no encontrada")
    
    def extend_key_expiration(self):
        """Extiende la expiración de una clave"""
        print("\n⏰ EXTENDER EXPIRACIÓN")
        print("-" * 30)
        
        user_key = input("🔑 Clave de usuario: ").strip()
        if not user_key:
            return
        
        days = input("📅 Días adicionales [30]: ").strip()
        try:
            days = int(days) if days else 30
        except ValueError:
            print("❌ Número de días no válido")
            return
        
        if self.auth_manager.extend_key_expiration(user_key, days):
            print(f"✅ Expiración extendida por {days} días")
        else:
            print("❌ Clave no encontrada")
    
    def cleanup_expired_keys(self):
        """Limpia claves expiradas"""
        print("\n🧹 LIMPIEZA DE CLAVES EXPIRADAS")
        print("-" * 30)
        
        cleaned = self.auth_manager.cleanup_expired_keys()
        if cleaned > 0:
            print(f"✅ Se eliminaron {cleaned} claves expiradas")
        else:
            print("ℹ️  No se encontraron claves expiradas")
    
    def manage_ips(self):
        """Gestión de IPs autorizadas"""
        while True:
            print("\n🌐 GESTIÓN DE IPs")
            print("-" * 30)
            print("1. 📋 Ver IPs autorizadas")
            print("2. ➕ Agregar IP")
            print("3. ❌ Eliminar IP")
            print("4. ℹ️  Información de red")
            print("5. 🔙 Volver al menú principal")
            
            choice = input("\nSelecciona opción: ").strip()
            
            if choice == "1":
                self.list_authorized_ips()
            elif choice == "2":
                self.add_authorized_ip()
            elif choice == "3":
                self.remove_authorized_ip()
            elif choice == "4":
                self.show_network_info()
            elif choice == "5":
                break
            else:
                print("❌ Opción no válida")
    
    def list_authorized_ips(self):
        """Lista IPs autorizadas"""
        print("\n📋 IPs AUTORIZADAS")
        print("-" * 40)
        
        whitelist = self.config.load_ip_whitelist()
        if not whitelist:
            print("ℹ️  No hay IPs configuradas en la whitelist")
            return
        
        for i, entry in enumerate(whitelist, 1):
            print(f"{i}. 🌐 {entry['ip']}")
            if entry.get('description'):
                print(f"   📝 {entry['description']}")
            print(f"   📅 Agregada: {entry.get('added', 'Unknown')}")
            print(f"   📊 Accesos: {entry.get('access_count', 0)}")
            if entry.get('last_access'):
                print(f"   🕐 Último acceso: {entry['last_access']}")
            print()
    
    def add_authorized_ip(self):
        """Agregar IP autorizada"""
        print("\n➕ AGREGAR IP")
        print("-" * 30)
        
        # Mostrar IP actual
        current_ip = self.ip_checker.get_local_ip()
        print(f"💡 Tu IP actual: {current_ip}")
        
        ip = input("🌐 IP a autorizar: ").strip()
        if not ip:
            return
        
        # Validar formato
        valid, msg = self.ip_checker.validate_ip_format(ip)
        if not valid:
            print(f"❌ {msg}")
            return
        
        description = input("📝 Descripción (opcional): ").strip()
        
        try:
            self.config.add_ip_to_whitelist(ip, description)
            print(f"✅ IP {ip} agregada exitosamente")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def remove_authorized_ip(self):
        """Eliminar IP autorizada"""
        print("\n❌ ELIMINAR IP")
        print("-" * 30)
        
        ip = input("🌐 IP a eliminar: ").strip()
        if not ip:
            return
        
        try:
            self.config.remove_ip_from_whitelist(ip)
            print(f"✅ IP {ip} eliminada exitosamente")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def show_network_info(self):
        """Muestra información de red"""
        print("\nℹ️  INFORMACIÓN DE RED")
        print("-" * 40)
        
        network_info = self.ip_checker.get_network_info()
        
        print(f"🖥️  Hostname: {network_info['hostname']}")
        print(f"🌐 IP local: {network_info['local_ip']}")
        print(f"🏠 Es privada: {'Sí' if network_info['is_private'] else 'No'}")
        print(f"🔄 Es localhost: {'Sí' if network_info['is_localhost'] else 'No'}")
        
        # Información adicional de IP
        ip_info = self.ip_checker.get_ip_subnet_info(network_info['local_ip'])
        if 'network' in ip_info:
            print(f"🌐 Red: {ip_info['network']}")
            print(f"🔢 Versión IP: {ip_info['version']}")
    
    def show_access_logs(self):
        """Muestra logs de acceso"""
        print("\n📊 LOGS DE ACCESO")
        print("-" * 40)
        
        try:
            limit = input("📊 Número de entradas [50]: ").strip()
            limit = int(limit) if limit else 50
        except ValueError:
            limit = 50
        
        logs = self.pdf_manager.get_access_logs(limit)
        
        if not logs:
            print("ℹ️  No hay logs disponibles")
            return
        
        for log in logs[-20:]:  # Mostrar últimos 20
            timestamp = log.get('timestamp', 'Unknown')[:19]  # Solo fecha y hora
            action = log.get('action', 'Unknown')
            status = log.get('status', 'Unknown')
            username = log.get('username', 'Unknown')
            ip = log.get('ip', 'Unknown')
            
            # Iconos por acción/estado
            if action == 'ENCRYPT':
                icon = "🔒"
            elif status == 'SUCCESS':
                icon = "✅"
            elif 'FAILED' in status or 'UNAUTHORIZED' in status:
                icon = "❌"
            else:
                icon = "📄"
            
            print(f"{icon} {timestamp} | {action}")
            if username != 'Unknown':
                print(f"    👤 Usuario: {username}")
            if status != 'Unknown':
                print(f"    📊 Estado: {status}")
            print(f"    🌐 IP: {ip}")
            
            if log.get('pdf_path'):
                pdf_name = Path(log['pdf_path']).name
                print(f"    📄 Archivo: {pdf_name}")
            print()
    
    def show_maintenance_menu(self):
        """Menú de mantenimiento"""
        while True:
            print("\n🧹 MANTENIMIENTO")
            print("-" * 30)
            print("1. 🧹 Limpiar claves expiradas")
            print("2. 📊 Estadísticas del sistema")
            print("3. 🔄 Verificar configuración")
            print("4. 📁 Mostrar rutas de configuración")
            print("5. 🔙 Volver al menú principal")
            
            choice = input("\nSelecciona opción: ").strip()
            
            if choice == "1":
                self.cleanup_expired_keys()
            elif choice == "2":
                self.show_system_stats()
            elif choice == "3":
                self.verify_configuration()
            elif choice == "4":
                self.show_config_paths()
            elif choice == "5":
                break
            else:
                print("❌ Opción no válida")
    
    def show_system_stats(self):
        """Muestra estadísticas del sistema"""
        print("\n📊 ESTADÍSTICAS DEL SISTEMA")
        print("-" * 40)
        
        # Estadísticas de claves
        user_keys = self.auth_manager.load_user_keys()
        active_keys = 0
        expired_keys = 0
        
        from datetime import datetime
        for key_data in user_keys.values():
            try:
                expires = datetime.fromisoformat(key_data['expires'])
                if datetime.now() <= expires:
                    active_keys += 1
                else:
                    expired_keys += 1
            except (ValueError, KeyError):
                expired_keys += 1
        
        print(f"🔑 Claves activas: {active_keys}")
        print(f"⏰ Claves expiradas: {expired_keys}")
        print(f"📊 Total de claves: {len(user_keys)}")
        
        # Estadísticas de IPs
        whitelist = self.config.load_ip_whitelist()
        print(f"🌐 IPs autorizadas: {len(whitelist)}")
        
        # Estadísticas de logs
        logs = self.pdf_manager.get_access_logs(1000)
        successful_decrypts = len([l for l in logs if l.get('status') == 'SUCCESS'])
        failed_attempts = len([l for l in logs if 'FAILED' in l.get('status', '') or 'UNAUTHORIZED' in l.get('status', '')])
        
        print(f"✅ Descifraciones exitosas: {successful_decrypts}")
        print(f"❌ Intentos fallidos: {failed_attempts}")
        print(f"📄 Total de eventos: {len(logs)}")
    
    def verify_configuration(self):
        """Verifica la configuración del sistema"""
        print("\n🔄 VERIFICACIÓN DE CONFIGURACIÓN")
        print("-" * 40)
        
        try:
            # Verificar clave maestra
            self.config.get_master_key()
            print("✅ Clave maestra configurada")
        except ValueError:
            print("❌ Clave maestra no configurada")
        
        # Verificar directorios
        if self.config.config_dir.exists():
            print(f"✅ Directorio de configuración: {self.config.config_dir}")
        else:
            print(f"❌ Directorio de configuración no existe")
        
        # Verificar archivos de configuración
        files_to_check = [
            (self.config.whitelist_file, "Whitelist de IPs"),
            (self.config.user_keys_file, "Claves de usuario"),
            (self.config.access_log_file, "Logs de acceso")
        ]
        
        for file_path, description in files_to_check:
            if file_path.exists():
                print(f"✅ {description}: {file_path}")
            else:
                print(f"ℹ️  {description}: No existe (se creará cuando sea necesario)")
    
    def show_config_paths(self):
        """Muestra las rutas de configuración"""
        print("\n📁 RUTAS DE CONFIGURACIÓN")
        print("-" * 40)
        print(f"📁 Directorio base: {self.config.config_dir}")
        print(f"🌐 Whitelist IPs: {self.config.whitelist_file}")
        print(f"🔑 Claves usuarios: {self.config.user_keys_file}")
        print(f"📊 Logs acceso: {self.config.access_log_file}")
    
    def manage_api(self):
        """Gestión de la API de Usuarios"""
        api_manager = get_api_manager()

        while True:
            print("\n🔍 GESTIÓN DE API DE USUARIOS")
            print("-" * 40)

            # Mostrar estado actual
            status = api_manager.get_status()
            if status['running']:
                print(f"📡 Estado: ✅ EJECUTÁNDOSE")
                print(f"🌐 URL: {status['url']}")
                if status.get('healthy'):
                    print(f"❤️  Salud: ✅ Saludable")
                    if 'version' in status:
                        print(f"📦 Versión: {status['version']}")
            else:
                print(f"📡 Estado: ⭕ DETENIDA")

            print("\n" + "-" * 40)
            print("1. ▶️  Iniciar API")
            print("2. ⏹️  Detener API")
            print("3. 🔄 Ver estado")
            print("4. 🌐 Abrir en navegador")
            print("5. 👥 Listar usuarios del sistema")
            print("6. 🔙 Volver al menú principal")

            choice = input("\nSelecciona opción: ").strip()

            if choice == "1":
                print("\n▶️  Iniciando API...")
                success, message = api_manager.start(in_thread=True)
                if success:
                    print(f"✅ {message}")
                    print(f"💡 Accede a la API en: {api_manager.base_url}")
                else:
                    print(f"❌ {message}")

            elif choice == "2":
                print("\n⏹️  Deteniendo API...")
                success, message = api_manager.stop()
                if success:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")

            elif choice == "3":
                print("\n🔄 Actualizando estado...")
                # El estado ya se muestra al principio del bucle

            elif choice == "4":
                print("\n🌐 Abriendo navegador...")
                success, message = api_manager.open_browser()
                if success:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")

            elif choice == "5":
                print("\n👥 USUARIOS DEL SISTEMA")
                print("-" * 40)
                users_data = api_manager.get_users(format_type='simple')

                if users_data and users_data.get('success'):
                    users = users_data.get('users', [])
                    print(f"Total de usuarios: {len(users)}\n")
                    for i, user in enumerate(users, 1):
                        print(f"  {i}. {user}")
                else:
                    print("❌ No se pudo obtener la lista de usuarios")
                    print("💡 Asegúrate de que la API esté ejecutándose")

            elif choice == "6":
                break
            else:
                print("❌ Opción no válida")

    def show_help(self):
        """Muestra ayuda"""
        print("\n❓ AYUDA")
        print("=" * 50)
        print("""
📖 CÓMO USAR PDF SECURE v2.0

🔒 CIFRADO:
1. Selecciona un archivo PDF para cifrar
2. Especifica usuarios autorizados (separados por comas)
3. El sistema genera claves únicas para cada usuario
4. Guarda las claves de forma segura

🔓 DESCIFRADO:
1. Proporciona el archivo cifrado (.enc)
2. Introduce tu clave de usuario personalizada
3. El sistema verifica tu autorización
4. Si todo es correcto, descifra el PDF

👥 GESTIÓN DE USUARIOS:
- Cada usuario tiene una clave única por archivo
- Las claves expiran automáticamente (30 días por defecto)
- Se registra cada acceso para auditoría

🌐 CONTROL DE IPs:
- Solo IPs autorizadas pueden descifrar archivos
- Se usa únicamente la IP local (no internet)
- Evita problemas con VPNs y IPs dinámicas

🔧 CONFIGURACIÓN:
- Variable de entorno: PDF_SECURE_MASTER_KEY
- Archivos en: ~/.pdf_secure/
- Logs automáticos de todas las operaciones

⚠️  IMPORTANTE:
- NO pierdas las claves de usuario
- NO compartas las claves por canales inseguros
- Haz respaldos de ~/.pdf_secure/ regularmente
        """)
    
    def run(self):
        """Ejecuta el CLI principal"""
        try:
            self.show_banner()
            
            while True:
                self.show_main_menu()
                choice = input("Selecciona una opción: ").strip()
                
                if choice == "1":
                    self.encrypt_pdf_interactive()
                elif choice == "2":
                    self.decrypt_pdf_interactive()
                elif choice == "3":
                    self.show_file_info()
                elif choice == "4":
                    self.manage_users()
                elif choice == "5":
                    self.manage_ips()
                elif choice == "6":
                    self.show_access_logs()
                elif choice == "7":
                    self.show_maintenance_menu()
                elif choice == "8":
                    self.manage_api()
                elif choice == "9":
                    self.show_help()
                elif choice == "0":
                    print("\n👋 ¡Hasta luego!")
                    break
                else:
                    print("❌ Opción no válida. Intenta de nuevo.")
                
                input("\n⏸️  Presiona Enter para continuar...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Saliendo...")
        except Exception as e:
            print(f"\n❌ Error inesperado: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    """Función principal"""
    cli = PDFSecureCLI()
    cli.run()

if __name__ == "__main__":
    main()