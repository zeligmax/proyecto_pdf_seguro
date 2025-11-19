#!/usr/bin/env python3
"""
user_auth.py - Sistema de Autenticación de Usuarios para PDF Secure v2.0

Este módulo maneja:
- Generación de claves únicas por usuario
- Autenticación y validación
- Gestión del ciclo de vida de claves (expiración, revocación)
- Trazabilidad de accesos
"""

import json
import hashlib
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime, timedelta


class UserAuthManager:
    """
    Gestor de autenticación de usuarios con claves derivadas
    """
    
    def __init__(self, config):
        """
        Inicializa el gestor de autenticación
        
        Args:
            config: Instancia de SecureConfig
        """
        self.config = config
        self.user_keys_file = config.user_keys_file
    
    def generate_user_key(self, username, pdf_path):
        """
        Genera clave única para usuario y PDF específico
        
        Args:
            username: Nombre del usuario
            pdf_path: Ruta del PDF para el cual se genera la clave
            
        Returns:
            dict: Datos de la clave generada
        """
        # Salt único por usuario y archivo
        salt = secrets.token_hex(16)
        user_pdf_combo = f"{username}:{pdf_path}:{salt}:{datetime.now().isoformat()}"
        
        # Hash del combo para crear clave derivada (PBKDF2 con 100k iteraciones)
        user_hash = hashlib.pbkdf2_hmac('sha256', 
                                       user_pdf_combo.encode(), 
                                       salt.encode(), 
                                       100000)
        
        return {
            'user_key': user_hash.hex(),
            'salt': salt,
            'pdf_path': str(pdf_path),
            'username': username,
            'created': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(days=30)).isoformat(),
            'access_count': 0,
            'last_access': None
        }
    
    def save_user_keys(self, user_keys):
        """
        Guarda las claves de usuario de forma segura
        
        Args:
            user_keys: Diccionario con las claves de usuario
        """
        with open(self.user_keys_file, 'w') as f:
            json.dump(user_keys, f, indent=2)
    
    def load_user_keys(self):
        """
        Carga las claves de usuario
        
        Returns:
            dict: Diccionario con las claves de usuario
        """
        if not self.user_keys_file.exists():
            return {}
        
        try:
            with open(self.user_keys_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
        except Exception:
            return {}
    
    def authenticate_user(self, user_key, pdf_path):
        """
        Autentica usuario y devuelve información

        Args:
            user_key: Clave del usuario
            pdf_path: Ruta del PDF que intenta acceder (puede ser .pdf o .enc)

        Returns:
            tuple: (datos_clave, mensaje) o (None, mensaje_error)
        """
        user_keys = self.load_user_keys()

        # Normalizar la ruta para comparación (quitar extensión y normalizar path)
        from pathlib import Path
        pdf_path_normalized = str(Path(pdf_path).absolute()).lower()
        # Quitar extensión .enc si existe para comparar con .pdf
        if pdf_path_normalized.endswith('.enc'):
            pdf_path_base = pdf_path_normalized[:-4]  # Quitar .enc
        else:
            pdf_path_base = pdf_path_normalized.rsplit('.', 1)[0] if '.' in pdf_path_normalized else pdf_path_normalized

        for key_id, key_data in user_keys.items():
            if key_data.get('user_key') == user_key:
                # Normalizar la ruta almacenada
                stored_path = str(Path(key_data.get('pdf_path', '')).absolute()).lower()
                stored_path_base = stored_path.rsplit('.', 1)[0] if '.' in stored_path else stored_path

                # Comparar sin extensión para que .pdf y .enc coincidan
                if stored_path_base == pdf_path_base:
                    # Verificar expiración
                    try:
                        expires = datetime.fromisoformat(key_data['expires'])
                        if datetime.now() > expires:
                            return None, "Clave expirada"
                    except (ValueError, KeyError):
                        return None, "Datos de clave corruptos"

                    # Registrar acceso
                    key_data['last_access'] = datetime.now().isoformat()
                    key_data['access_count'] = key_data.get('access_count', 0) + 1

                    self.save_user_keys(user_keys)

                    return key_data, "Autenticado correctamente"

        return None, "Clave no válida o no autorizada para este archivo"
    
    def revoke_user_key(self, user_key):
        """
        Revoca una clave de usuario específica
        
        Args:
            user_key: Clave del usuario a revocar
            
        Returns:
            bool: True si se revocó correctamente, False si no se encontró
        """
        user_keys = self.load_user_keys()
        
        # Buscar y eliminar la clave
        key_found = False
        for key_id, key_data in list(user_keys.items()):
            if key_data.get('user_key') == user_key:
                del user_keys[key_id]
                key_found = True
                break
        
        if key_found:
            self.save_user_keys(user_keys)
            return True
        
        return False
    
    def revoke_user_keys_by_username(self, username):
        """
        Revoca todas las claves de un usuario específico
        
        Args:
            username: Nombre del usuario
            
        Returns:
            int: Número de claves revocadas
        """
        user_keys = self.load_user_keys()
        
        # Filtrar claves que NO pertenecen a este usuario
        keys_to_keep = {}
        revoked_count = 0
        
        for key_id, key_data in user_keys.items():
            if key_data.get('username') != username:
                keys_to_keep[key_id] = key_data
            else:
                revoked_count += 1
        
        self.save_user_keys(keys_to_keep)
        return revoked_count
    
    def cleanup_expired_keys(self):
        """
        Elimina claves expiradas
        
        Returns:
            int: Número de claves eliminadas
        """
        user_keys = self.load_user_keys()
        cleaned_keys = {}
        
        for key_id, key_data in user_keys.items():
            try:
                expires = datetime.fromisoformat(key_data['expires'])
                if datetime.now() <= expires:
                    cleaned_keys[key_id] = key_data
            except (ValueError, KeyError):
                # Skip corrupted entries
                continue
        
        removed_count = len(user_keys) - len(cleaned_keys)
        
        if removed_count > 0:
            self.save_user_keys(cleaned_keys)
        
        return removed_count
    
    def list_user_keys_for_pdf(self, pdf_path):
        """
        Lista todas las claves activas para un PDF específico
        
        Args:
            pdf_path: Ruta del PDF
            
        Returns:
            list: Lista de claves activas para ese PDF
        """
        user_keys = self.load_user_keys()
        pdf_keys = []
        
        for key_id, key_data in user_keys.items():
            if key_data.get('pdf_path') == str(pdf_path):
                # Verificar si no está expirada
                try:
                    expires = datetime.fromisoformat(key_data['expires'])
                    if datetime.now() <= expires:
                        pdf_keys.append({
                            'key_id': key_id,
                            'username': key_data.get('username'),
                            'created': key_data.get('created'),
                            'expires': key_data.get('expires'),
                            'access_count': key_data.get('access_count', 0),
                            'last_access': key_data.get('last_access')
                        })
                except (ValueError, KeyError):
                    continue
        
        return pdf_keys
    
    def extend_key_expiration(self, user_key, days=30):
        """
        Extiende la expiración de una clave
        
        Args:
            user_key: Clave del usuario
            days: Días adicionales de validez
            
        Returns:
            bool: True si se extendió correctamente
        """
        user_keys = self.load_user_keys()
        
        for key_id, key_data in user_keys.items():
            if key_data.get('user_key') == user_key:
                new_expires = datetime.now() + timedelta(days=days)
                key_data['expires'] = new_expires.isoformat()
                key_data['extended'] = datetime.now().isoformat()
                key_data['extended_days'] = days
                
                self.save_user_keys(user_keys)
                return True
        
        return False
    
    def get_user_key_info(self, user_key):
        """
        Obtiene información detallada de una clave específica
        
        Args:
            user_key: Clave del usuario
            
        Returns:
            dict: Información de la clave o None si no existe
        """
        user_keys = self.load_user_keys()
        
        for key_id, key_data in user_keys.items():
            if key_data.get('user_key') == user_key:
                return {
                    'key_id': key_id,
                    'username': key_data.get('username'),
                    'pdf_path': key_data.get('pdf_path'),
                    'created': key_data.get('created'),
                    'expires': key_data.get('expires'),
                    'access_count': key_data.get('access_count', 0),
                    'last_access': key_data.get('last_access'),
                    'is_expired': self._is_expired(key_data)
                }
        
        return None
    
    def get_all_active_users(self):
        """
        Obtiene lista de todos los usuarios con claves activas
        
        Returns:
            set: Conjunto de nombres de usuario únicos
        """
        user_keys = self.load_user_keys()
        active_users = set()
        
        for key_data in user_keys.values():
            if not self._is_expired(key_data):
                username = key_data.get('username')
                if username:
                    active_users.add(username)
        
        return active_users
    
    def get_statistics(self):
        """
        Obtiene estadísticas del sistema de autenticación
        
        Returns:
            dict: Estadísticas generales
        """
        user_keys = self.load_user_keys()
        
        total = len(user_keys)
        active = 0
        expired = 0
        total_accesses = 0
        
        for key_data in user_keys.values():
            if self._is_expired(key_data):
                expired += 1
            else:
                active += 1
            
            total_accesses += key_data.get('access_count', 0)
        
        return {
            'total_keys': total,
            'active_keys': active,
            'expired_keys': expired,
            'total_accesses': total_accesses,
            'unique_users': len(self.get_all_active_users())
        }
    
    def _is_expired(self, key_data):
        """
        Verifica si una clave está expirada
        
        Args:
            key_data: Datos de la clave
            
        Returns:
            bool: True si está expirada
        """
        try:
            expires = datetime.fromisoformat(key_data['expires'])
            return datetime.now() > expires
        except (ValueError, KeyError):
            return True


# Ejemplo de uso
if __name__ == "__main__":
    """
    Ejemplo de uso del módulo de autenticación
    """
    print("🔐 PDF Secure - Sistema de Autenticación v2.0")
    print("=" * 50)
    print("\nEste módulo requiere ser usado junto con:")
    print("  - config.py (configuración)")
    print("\nEjecuta app_gui.py o main.py para usar el sistema completo.")