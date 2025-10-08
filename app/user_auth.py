import json
import hashlib
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

class UserAuthManager:
    def __init__(self, config):
        self.config = config
        self.user_keys_file = config.user_keys_file
        
    def generate_user_key(self, username, pdf_path):
        """Genera clave única para usuario y PDF específico"""
        # Salt único por usuario y archivo
        salt = secrets.token_hex(16)
        user_pdf_combo = f"{username}:{pdf_path}:{salt}"
        
        # Hash del combo para crear clave derivada
        user_hash = hashlib.pbkdf2_hmac('sha256', 
                                       user_pdf_combo.encode(), 
                                       salt.encode(), 
                                       100000)  # 100k iteraciones
        
        return {
            'user_key': user_hash.hex(),
            'salt': salt,
            'pdf_path': pdf_path,
            'username': username,
            'created': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(days=30)).isoformat()
        }
    
    def save_user_keys(self, user_keys):
        """Guarda las claves de usuario de forma segura"""
        with open(self.user_keys_file, 'w') as f:
            json.dump(user_keys, f, indent=2)
    
    def load_user_keys(self):
        """Carga las claves de usuario"""
        if not self.user_keys_file.exists():
            return {}
        
        with open(self.user_keys_file, 'r') as f:
            return json.load(f)
    
    def authenticate_user(self, user_key, pdf_path):
        """Autentica usuario y devuelve información"""
        user_keys = self.load_user_keys()
        
        for key_id, key_data in user_keys.items():
            if (key_data['user_key'] == user_key and 
                key_data['pdf_path'] == pdf_path):
                
                # Verificar expiración
                expires = datetime.fromisoformat(key_data['expires'])
                if datetime.now() > expires:
                    return None, "Clave expirada"
                
                # Registrar acceso
                key_data['last_access'] = datetime.now().isoformat()
                key_data['access_count'] = key_data.get('access_count', 0) + 1
                
                self.save_user_keys(user_keys)
                
                return key_data, "Autenticado correctamente"
        
        return None, "Clave no válida"