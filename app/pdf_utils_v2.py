import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime

class PDFSecureManager:
    def __init__(self, config, auth_manager):
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
        """
        
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
                'encrypted_on': datetime.now().isoformat(),
                'authorized_users': authorized_users,
                'encryption_method': 'Fernet/AES256'
            }
        }
        
        # 6. Guardar archivo cifrado
        with open(output_path, 'w') as f:
            json.dump(secure_data, f)
        
        # 7. Guardar claves de usuario
        existing_keys = self.auth_manager.load_user_keys()
        existing_keys.update(user_keys)
        self.auth_manager.save_user_keys(existing_keys)
        
        return user_key_entries
    
    def decrypt_pdf_with_user_key(self, encrypted_path, user_key, output_path=None):
        """
        Descifra PDF usando clave de usuario
        
        Args:
            encrypted_path: Ruta del archivo cifrado
            user_key: Clave del usuario
            output_path: Ruta de salida (opcional)
        """
        
        # 1. Cargar archivo cifrado
        with open(encrypted_path, 'r') as f:
            secure_data = json.load(f)
        
        # 2. Verificar que la clave de usuario está autorizada
        user_authorized = False
        for username, stored_key in secure_data['user_keys'].items():
            if stored_key == user_key:
                user_authorized = True
                break
        
        if not user_authorized:
            raise ValueError("Clave de usuario no autorizada para este PDF")
        
        # 3. Autenticar usuario y registrar acceso
        auth_result, message = self.auth_manager.authenticate_user(user_key, encrypted_path)
        if not auth_result:
            raise ValueError(f"Autenticación fallida: {message}")
        
        # 4. Descifrar clave del PDF
        encrypted_pdf_key = bytes.fromhex(secure_data['encrypted_pdf_key'])
        pdf_key = self.master_fernet.decrypt(encrypted_pdf_key)
        
        # 5. Descifrar PDF
        pdf_fernet = Fernet(pdf_key)
        encrypted_pdf = bytes.fromhex(secure_data['encrypted_pdf'])
        decrypted_pdf = pdf_fernet.decrypt(encrypted_pdf)
        
        # 6. Determinar ruta de salida
        if not output_path:
            original_name = secure_data['metadata']['original_filename']
            output_path = Path(encrypted_path).parent / f"decrypted_{original_name}"
        
        # 7. Guardar PDF descifrado
        with open(output_path, 'wb') as f:
            f.write(decrypted_pdf)
        
        # 8. Log del acceso
        self._log_access(auth_result['username'], encrypted_path, "SUCCESS")
        
        return str(output_path)
    
    def _log_access(self, username, pdf_path, status):
        """Registra accesos al sistema"""
        log_file = self.config.config_dir / 'access_log.json'
        
        access_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'pdf_path': str(pdf_path),
            'status': status,
            'ip': self._get_local_ip()  # Solo IP local
        }
        
        # Cargar log existente
        if log_file.exists():
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(access_entry)
        
        # Mantener solo últimos 1000 registros
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def _get_local_ip(self):
        """Obtiene IP local solamente"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"