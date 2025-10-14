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
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime


class PDFSecureManager:
    """
    Gestor de cifrado/descifrado de PDFs con autenticación por usuario
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
        
        # 5. Crear estructura del archivo cifrado
        secure_data = {
            'encrypted_pdf': encrypted_pdf.hex(),
            'encrypted_pdf_key': encrypted_pdf_key.hex(),
            'user_keys': user_key_entries,
            'metadata': {
                'original_filename': Path(pdf_path).name,
                'original_size': len(pdf_data),
                'encrypted_on': datetime.now().isoformat(),
                'authorized_users': authorized_users,
                'encryption_method': 'Fernet/AES256',
                'version': '2.0'
            }
        }
        
        # 6. Guardar archivo cifrado
        with open(output_path, 'w') as f:
            json.dump(secure_data, f, indent=2)
        
        # 7. Guardar claves de usuario
        existing_keys = self.auth_manager.load_user_keys()
        existing_keys.update(user_keys)
        self.auth_manager.save_user_keys(existing_keys)
        
        # 8. Log de cifrado
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
        
        # 2. Verificar que la clave de usuario está autorizada
        user_authorized = False
        authorized_username = None
        
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
        
        # 3. Verificar IP local si está habilitada la whitelist
        local_ip = self._get_local_ip()
        whitelist = self.config.load_ip_whitelist()
        
        if whitelist and not self.config.is_ip_whitelisted(local_ip):
            self._log_access(authorized_username, encrypted_path, "IP_NOT_WHITELISTED")
            raise ValueError(f"IP {local_ip} no está autorizada para acceder a este archivo")
        
        # 4. Autenticar usuario y registrar acceso
        auth_result, message = self.auth_manager.authenticate_user(user_key, encrypted_path)
        if not auth_result:
            self._log_access(authorized_username, encrypted_path, "AUTH_FAILED")
            raise ValueError(f"Autenticación fallida: {message}")
        
        # 5. Descifrar clave del PDF
        try:
            encrypted_pdf_key = bytes.fromhex(secure_data['encrypted_pdf_key'])
            pdf_key = self.master_fernet.decrypt(encrypted_pdf_key)
        except Exception as e:
            self._log_access(authorized_username, encrypted_path, "DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar la clave del PDF: {str(e)}")
        
        # 6. Descifrar PDF
        try:
            pdf_fernet = Fernet(pdf_key)
            encrypted_pdf = bytes.fromhex(secure_data['encrypted_pdf'])
            decrypted_pdf = pdf_fernet.decrypt(encrypted_pdf)
        except Exception as e:
            self._log_access(authorized_username, encrypted_path, "PDF_DECRYPTION_FAILED")
            raise ValueError(f"Error al descifrar el PDF: {str(e)}")
        
        # 7. Determinar ruta de salida
        if not output_path:
            original_name = secure_data['metadata']['original_filename']
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(encrypted_path).parent / f"decrypted_{timestamp}_{original_name}"
        
        # 8. Guardar PDF descifrado
        try:
            with open(output_path, 'wb') as f:
                f.write(decrypted_pdf)
        except Exception as e:
            raise ValueError(f"Error al guardar archivo: {str(e)}")
        
        # 9. Log del acceso exitoso
        self._log_access(authorized_username, encrypted_path, "SUCCESS")
        
        # 10. Actualizar contador de acceso IP
        if whitelist:
            self.config.increment_ip_access_count(local_ip)
        
        return str(output_path)
    
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
        
        metadata = secure_data.get('metadata', {})
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