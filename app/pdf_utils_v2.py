#!/usr/bin/env python3
"""
pdf_utils_v2.py - Sistema de Cifrado Mejorado para PDF Secure v2.0

Este módulo maneja el cifrado y descifrado de PDFs con:
- Claves únicas por PDF
- Claves únicas por usuario
- Cifrado multicapa (AES-256)
- Trazabilidad completa
"""

import os
import json
import socket
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime


class FileSecureManager:
    """
    Gestor de cifrado/descifrado de archivos con autenticación por usuario
    Soporta múltiples formatos: PDF, DOCX, XLSX, TXT, PBIP, PBIX
    """
    
    def __init__(self, config, auth_manager):
        """
        Inicializa el gestor de PDFs seguros

        Args:
            config: Instancia de SecureConfig
            auth_manager: Instancia de UserAuthManager
        """
        self.config = config
        self.auth_manager = auth_manager
        self.master_fernet = Fernet(config.get_master_key())

    def _decrypt_metadata(self, secure_data):
        """
        Descifra metadatos del archivo cifrado con compatibilidad hacia atrás

        Args:
            secure_data: Diccionario con datos del archivo cifrado

        Returns:
            dict: Metadatos descifrados
        """
        # Detectar versión del archivo
        version = secure_data.get('version', '2.0')

        if version >= '2.1':
            # Versión 2.1+: metadatos cifrados
            try:
                encrypted_metadata = bytes.fromhex(secure_data['encrypted_metadata'])
                decrypted_metadata_bytes = self.master_fernet.decrypt(encrypted_metadata)
                metadata = json.loads(decrypted_metadata_bytes.decode('utf-8'))
                return metadata
            except Exception as e:
                raise ValueError(f"Error al descifrar metadatos: {str(e)}")
        else:
            # Versión 2.0: metadatos en texto plano (compatibilidad)
            return secure_data.get('metadata', {})

    def encrypt_pdf_with_user_keys(self, pdf_path, output_path, authorized_users):
        """
        Cifra PDF con claves únicas por usuario
        
        Args:
            pdf_path: Ruta del PDF original
            output_path: Ruta del archivo cifrado
            authorized_users: Lista de usernames autorizados
            
        Returns:
            dict: Diccionario con las claves de usuario generadas
        """
        
        if not Path(pdf_path).exists():
            raise FileNotFoundError(f"El archivo PDF no existe: {pdf_path}")
        
        if not authorized_users:
            raise ValueError("Debe especificar al menos un usuario autorizado")
        
        # 1. Generar clave única para este PDF
        pdf_key = Fernet.generate_key()
        pdf_fernet = Fernet(pdf_key)
        
        # 2. Cifrar el PDF con la clave única
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()
        
        encrypted_pdf = pdf_fernet.encrypt(pdf_data)
        
        # 3. Generar claves de usuario para este PDF
        user_keys = {}
        user_key_entries = {}
        
        for username in authorized_users:
            user_key_data = self.auth_manager.generate_user_key(username, str(pdf_path))
            user_key_id = f"{username}_{Path(pdf_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            user_keys[user_key_id] = user_key_data
            user_key_entries[username] = user_key_data['user_key']
        
        # 4. Cifrar la clave del PDF con la clave maestra
        encrypted_pdf_key = self.master_fernet.encrypt(pdf_key)

        # 5. Crear metadatos (NUEVO: se cifrarán para mayor seguridad)
        file_extension = Path(pdf_path).suffix.lower()  # .pdf, .docx, .xlsx, etc.
        metadata = {
            'original_filename': Path(pdf_path).name,
            'file_type': file_extension,  # NUEVO: tipo de archivo original
            'original_size': len(pdf_data),
            'encrypted_on': datetime.now().isoformat(),
            'authorized_users': authorized_users,
            'encryption_method': 'Fernet/AES256',
            'version': '2.2'  # Nueva versión con soporte multi-formato
        }

        # 6. Cifrar metadatos con la clave maestra (NUEVO: Mejora de Seguridad #3)
        metadata_json = json.dumps(metadata)
        encrypted_metadata = self.master_fernet.encrypt(metadata_json.encode('utf-8'))

        # 7. Crear estructura del archivo cifrado
        secure_data = {
            'version': '2.2',  # Versión actualizada con soporte multi-formato
            'encrypted_file': encrypted_pdf.hex(),  # Ahora soporta cualquier archivo
            'encrypted_file_key': encrypted_pdf_key.hex(),
            'user_keys': user_key_entries,
            'encrypted_metadata': encrypted_metadata.hex(),  # Metadatos cifrados
            # Mantener compatibilidad con v2.1
            'encrypted_pdf': encrypted_pdf.hex(),
            'encrypted_pdf_key': encrypted_pdf_key.hex()
        }

        # 8. Guardar archivo cifrado
        with open(output_path, 'w') as f:
            json.dump(secure_data, f, indent=2)

        # 9. Guardar claves de usuario
        existing_keys = self.auth_manager.load_user_keys()
        existing_keys.update(user_keys)
        self.auth_manager.save_user_keys(existing_keys)

        # 10. Log de cifrado
        self._log_encryption(authorized_users, pdf_path, output_path)

        return user_key_entries
    
    def decrypt_pdf_with_user_key(self, encrypted_path, user_key, output_path=None):
        """
        Descifra PDF usando clave de usuario - VERSIÓN MEJORADA
        
        Args:
            encrypted_path: Ruta del archivo cifrado
            user_key: Clave del usuario (se limpia automáticamente)
            output_path: Ruta de salida (opcional)
            
        Returns:
            str: Ruta del archivo descifrado
        """
        
        # Limpiar la clave de espacios al inicio/final
        user_key = user_key.strip()
        
        if not Path(encrypted_path).exists():
            raise FileNotFoundError(f"El archivo cifrado no existe: {encrypted_path}")
        
        # 1. Cargar archivo cifrado
        try:
            with open(encrypted_path, 'r', encoding='utf-8') as f:
                secure_data = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("El archivo cifrado está corrupto o no es válido")
        except Exception as e:
            raise ValueError(f"Error al cargar archivo: {str(e)}")
        
        # 2. Verificar que la clave de usuario está autorizada Y que el usuario del sistema coincide
        user_authorized = False
        authorized_username = None
        current_system_user = self._get_current_system_user()

        user_keys_in_file = secure_data.get('user_keys', {})

        for username, stored_key in user_keys_in_file.items():
            # Limpiar también la clave almacenada
            stored_key_clean = stored_key.strip()

            if stored_key_clean == user_key:
                user_authorized = True
                authorized_username = username
                break

        if not user_authorized:
            # Mensaje de error más informativo
            error_msg = f"Clave de usuario no autorizada para este archivo.\n"
            error_msg += f"Usuarios autorizados: {', '.join(user_keys_in_file.keys())}"

            self._log_access(None, encrypted_path, "UNAUTHORIZED_KEY")
            raise ValueError(error_msg)

        # 2.5. Verificar que el usuario del sistema coincide con el usuario autorizado
        if current_system_user.lower() != authorized_username.lower():
            error_msg = f"Usuario del sistema no coincide.\n"
            error_msg += f"Usuario actual del sistema: {current_system_user}\n"
            error_msg += f"Usuario autorizado para esta clave: {authorized_username}\n"
            error_msg += f"Debes estar logueado como '{authorized_username}' para descifrar este archivo."

            self._log_access(current_system_user, encrypted_path, "USER_MISMATCH")
            raise ValueError(error_msg)
        
        # 3. Verificar IP local si está habilitada la whitelist
        local_ip = self._get_local_ip()
        whitelist = self.config.load_ip_whitelist()

        if whitelist and not self.config.is_ip_whitelisted(local_ip):
            self._log_access(authorized_username, encrypted_path, "IP_NOT_WHITELISTED")
            raise ValueError(f"IP {local_ip} no está autorizada para acceder a este archivo")

        # 4. Autenticar usuario y registrar acceso (opcional)
        # Intentar autenticar, pero si falla solo por no estar en el sistema, continuar
        auth_result, message = self.auth_manager.authenticate_user(user_key, encrypted_path)

        # Si la autenticación falla por razones distintas a "no encontrado", rechazar
        if not auth_result:
            # Si la clave ya fue validada en el archivo, permitir continuar
            # Solo fallar si es por expiración o corrupción
            if "expirada" in message.lower() or "corruptos" in message.lower():
                self._log_access(authorized_username, encrypted_path, "AUTH_FAILED")
                raise ValueError(f"Autenticación fallida: {message}")
            # Si es porque no está registrada en el sistema, continuar (ya validamos en el archivo)
        
        # 5. Descifrar clave del archivo (compatible con v2.0, v2.1, v2.2)
        try:
            # Intentar con v2.2 primero (encrypted_file_key), sino v2.0/v2.1 (encrypted_pdf_key)
            if 'encrypted_file_key' in secure_data:
                encrypted_file_key = bytes.fromhex(secure_data['encrypted_file_key'])
            else:
                encrypted_file_key = bytes.fromhex(secure_data['encrypted_pdf_key'])

            file_key = self.master_fernet.decrypt(encrypted_file_key)
        except Exception as e:
            self._log_access(authorized_username, encrypted_path, "DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar la clave del archivo: {str(e)}")

        # 6. Descifrar archivo (compatible con v2.0, v2.1, v2.2)
        try:
            file_fernet = Fernet(file_key)
            # Intentar con v2.2 primero (encrypted_file), sino v2.0/v2.1 (encrypted_pdf)
            if 'encrypted_file' in secure_data:
                encrypted_data = bytes.fromhex(secure_data['encrypted_file'])
            else:
                encrypted_data = bytes.fromhex(secure_data['encrypted_pdf'])

            decrypted_file = file_fernet.decrypt(encrypted_data)
        except Exception as e:
            self._log_access(authorized_username, encrypted_path, "FILE_DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar el archivo: {str(e)}")
        
        # 7. Descifrar metadatos (NUEVO: soporta metadatos cifrados en v2.1+)
        metadata = self._decrypt_metadata(secure_data)

        # 8. Determinar ruta de salida
        if not output_path:
            original_name = metadata['original_filename']
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(encrypted_path).parent / f"decrypted_{timestamp}_{original_name}"

        # 9. Guardar archivo descifrado
        try:
            with open(output_path, 'wb') as f:
                f.write(decrypted_file)
        except Exception as e:
            raise ValueError(f"Error al guardar archivo: {str(e)}")

        # 10. Log del acceso exitoso
        self._log_access(authorized_username, encrypted_path, "SUCCESS")

        # 11. Actualizar contador de acceso IP
        if whitelist:
            self.config.increment_ip_access_count(local_ip)

        return str(output_path)

    def decrypt_pdf_to_memory(self, encrypted_path, user_key):
        """
        Descifra PDF en memoria sin guardarlo en disco (para visualización)

        Args:
            encrypted_path: Ruta del archivo cifrado
            user_key: Clave del usuario (se limpia automáticamente)

        Returns:
            tuple: (bytes del PDF descifrado, nombre original del archivo)
        """

        # Limpiar la clave de espacios al inicio/final
        user_key = user_key.strip()

        if not Path(encrypted_path).exists():
            raise FileNotFoundError(f"El archivo cifrado no existe: {encrypted_path}")

        # 1. Cargar archivo cifrado
        try:
            with open(encrypted_path, 'r', encoding='utf-8') as f:
                secure_data = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("El archivo cifrado está corrupto o no es válido")
        except Exception as e:
            raise ValueError(f"Error al cargar archivo: {str(e)}")

        # 2. Verificar que la clave de usuario está autorizada Y que el usuario del sistema coincide
        user_authorized = False
        authorized_username = None
        current_system_user = self._get_current_system_user()

        user_keys_in_file = secure_data.get('user_keys', {})

        for username, stored_key in user_keys_in_file.items():
            # Limpiar también la clave almacenada
            stored_key_clean = stored_key.strip()

            if stored_key_clean == user_key:
                user_authorized = True
                authorized_username = username
                break

        if not user_authorized:
            # Mensaje de error más informativo
            error_msg = f"Clave de usuario no autorizada para este archivo.\n"
            error_msg += f"Usuarios autorizados: {', '.join(user_keys_in_file.keys())}"

            self._log_view(None, encrypted_path, "UNAUTHORIZED_KEY")
            raise ValueError(error_msg)

        # 2.5. Verificar que el usuario del sistema coincide con el usuario autorizado
        if current_system_user.lower() != authorized_username.lower():
            error_msg = f"Usuario del sistema no coincide.\n"
            error_msg += f"Usuario actual del sistema: {current_system_user}\n"
            error_msg += f"Usuario autorizado para esta clave: {authorized_username}\n"
            error_msg += f"Debes estar logueado como '{authorized_username}' para descifrar este archivo."

            self._log_view(current_system_user, encrypted_path, "USER_MISMATCH")
            raise ValueError(error_msg)

        # 3. Verificar IP local si está habilitada la whitelist
        local_ip = self._get_local_ip()
        whitelist = self.config.load_ip_whitelist()

        if whitelist and not self.config.is_ip_whitelisted(local_ip):
            self._log_view(authorized_username, encrypted_path, "IP_NOT_WHITELISTED")
            raise ValueError(f"IP {local_ip} no está autorizada para acceder a este archivo")

        # 4. Autenticar usuario (opcional)
        auth_result, message = self.auth_manager.authenticate_user(user_key, encrypted_path)

        if not auth_result:
            if "expirada" in message.lower() or "corruptos" in message.lower():
                self._log_view(authorized_username, encrypted_path, "AUTH_FAILED")
                raise ValueError(f"Autenticación fallida: {message}")

        # 5. Descifrar clave del archivo (compatible con v2.0, v2.1, v2.2)
        try:
            # Intentar con v2.2 primero (encrypted_file_key), sino v2.0/v2.1 (encrypted_pdf_key)
            if 'encrypted_file_key' in secure_data:
                encrypted_file_key = bytes.fromhex(secure_data['encrypted_file_key'])
            else:
                encrypted_file_key = bytes.fromhex(secure_data['encrypted_pdf_key'])

            file_key = self.master_fernet.decrypt(encrypted_file_key)
        except Exception as e:
            self._log_view(authorized_username, encrypted_path, "DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar la clave del archivo: {str(e)}")

        # 6. Descifrar archivo en memoria (compatible con v2.0, v2.1, v2.2)
        try:
            file_fernet = Fernet(file_key)
            # Intentar con v2.2 primero (encrypted_file), sino v2.0/v2.1 (encrypted_pdf)
            if 'encrypted_file' in secure_data:
                encrypted_data = bytes.fromhex(secure_data['encrypted_file'])
            else:
                encrypted_data = bytes.fromhex(secure_data['encrypted_pdf'])

            decrypted_file = file_fernet.decrypt(encrypted_data)
        except Exception as e:
            self._log_view(authorized_username, encrypted_path, "FILE_DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar el archivo: {str(e)}")

        # 7. Descifrar metadatos
        metadata = self._decrypt_metadata(secure_data)

        # 8. Log del acceso exitoso (VIEW en lugar de DECRYPT)
        self._log_view(authorized_username, encrypted_path, "SUCCESS")

        # 9. Actualizar contador de acceso IP
        if whitelist:
            self.config.increment_ip_access_count(local_ip)

        # 10. Retornar bytes del archivo y nombre original
        original_filename = metadata.get('original_filename', 'documento')
        file_type = metadata.get('file_type', '.dat')  # Tipo de archivo para visualizador
        return decrypted_file, original_filename, file_type

    def get_file_info(self, encrypted_path):
        """
        Obtiene información sobre un archivo cifrado sin descifrarlo
        
        Args:
            encrypted_path: Ruta del archivo cifrado
            
        Returns:
            dict: Información del archivo
        """
        if not Path(encrypted_path).exists():
            raise FileNotFoundError(f"El archivo no existe: {encrypted_path}")
        
        try:
            with open(encrypted_path, 'r') as f:
                secure_data = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("El archivo no es un PDF cifrado válido")

        # Descifrar metadatos (soporta v2.1+ con metadatos cifrados)
        metadata = self._decrypt_metadata(secure_data)
        user_keys = secure_data.get('user_keys', {})
        
        # Obtener información de las claves de usuario
        user_info = []
        for username in user_keys.keys():
            keys_data = self.auth_manager.list_user_keys_for_pdf(encrypted_path)
            user_key_info = next((k for k in keys_data if k['username'] == username), None)
            if user_key_info:
                user_info.append(user_key_info)
        
        return {
            'filename': metadata.get('original_filename', 'Unknown'),
            'size': metadata.get('original_size', 0),
            'encrypted_on': metadata.get('encrypted_on'),
            'authorized_users': metadata.get('authorized_users', []),
            'encryption_method': metadata.get('encryption_method', 'Unknown'),
            'version': metadata.get('version', '1.0'),
            'user_keys_info': user_info
        }
    
    def _log_encryption(self, users, original_path, encrypted_path):
        """Registra operaciones de cifrado"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': 'ENCRYPT',
            'original_file': str(original_path),
            'encrypted_file': str(encrypted_path),
            'authorized_users': users,
            'ip': self._get_local_ip()
        }
        
        self._write_log_entry(log_entry)
    
    def _log_access(self, username, pdf_path, status):
        """Registra accesos al sistema"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': 'DECRYPT_ATTEMPT',
            'username': username if username else 'Unknown',
            'pdf_path': str(pdf_path),
            'status': status,
            'ip': self._get_local_ip()
        }

        self._write_log_entry(log_entry)

    def _log_view(self, username, pdf_path, status):
        """Registra visualizaciones en memoria (sin descifrado completo)"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': 'VIEW_ATTEMPT',
            'username': username if username else 'Unknown',
            'pdf_path': str(pdf_path),
            'status': status,
            'ip': self._get_local_ip()
        }

        self._write_log_entry(log_entry)
    
    def _write_log_entry(self, entry):
        """Escribe entrada en el log"""
        log_file = self.config.access_log_file
        
        # Cargar log existente
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
        else:
            logs = []
        
        logs.append(entry)
        
        # Mantener solo últimos 1000 registros
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def _get_local_ip(self):
        """Obtiene IP local solamente"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def _get_current_system_user(self):
        """Obtiene el nombre de usuario actual del sistema"""
        try:
            return getpass.getuser()
        except Exception:
            try:
                return os.getlogin()
            except Exception:
                return "Unknown"

    def get_access_logs(self, limit=100):
        """
        Obtiene los últimos logs de acceso
        
        Args:
            limit (int): Número máximo de registros a retornar
            
        Returns:
            list: Lista de logs (máximo 'limit' entradas)
        """
        log_file = self.config.access_log_file
        
        if not log_file.exists():
            return []
        
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            return []
        except Exception:
            return []
        
        # Retornar los últimos 'limit' registros
        return logs[-limit:] if len(logs) > limit else logs


# Ejemplo de uso
if __name__ == "__main__":
    """
    Ejemplo de uso del módulo de cifrado
    """
    print("📄 PDF Secure - Sistema de Cifrado v2.0")
    print("=" * 50)
    print("\nEste módulo requiere ser usado junto con:")
    print("  - config.py (configuración)")
    print("  - user_auth.py (autenticación)")
    print("\nEjecuta app_gui.py o main.py para usar el sistema completo.")