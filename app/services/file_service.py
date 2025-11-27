#!/usr/bin/env python3
"""
File Service v3.2
Servicio de cifrado/descifrado de archivos integrado con RBAC y auditoría
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from cryptography.fernet import Fernet

from app.models.file import SecureFile, FileAccess
from app.models.user import User
from app.services.audit_service import AuditService


class FileService:
    """Servicio para gestión de archivos cifrados"""

    def __init__(self, session, current_user: User):
        """
        Initialize file service

        Args:
            session: SQLAlchemy session
            current_user: Usuario actual autenticado
        """
        self.session = session
        self.current_user = current_user
        self.audit_service = AuditService(session)

        # Obtener clave maestra desde variable de entorno
        master_key = os.getenv('PDF_SECURE_MASTER_KEY')
        if not master_key:
            raise ValueError("PDF_SECURE_MASTER_KEY environment variable not set")

        self.master_fernet = Fernet(master_key.encode() if isinstance(master_key, str) else master_key)

        # Directorio para archivos cifrados
        self.storage_dir = Path.home() / '.pdf_secure' / 'encrypted_files'
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def encrypt_file(
        self,
        file_path: str,
        authorized_usernames: List[str],
        output_path: Optional[str] = None,
        description: Optional[str] = None
    ) -> Tuple[SecureFile, Dict[str, str]]:
        """
        Cifra un archivo y lo registra en la base de datos

        Args:
            file_path: Ruta del archivo original
            authorized_usernames: Lista de usernames autorizados
            output_path: Ruta de salida opcional
            description: Descripción del archivo

        Returns:
            Tuple de (SecureFile, dict de claves de usuario)
        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # 1. Leer archivo original
            with open(file_path, 'rb') as f:
                file_data = f.read()

            original_size = len(file_data)
            file_hash = hashlib.sha256(file_data).hexdigest()

            # 2. Generar clave única para este archivo
            file_key = Fernet.generate_key()
            file_fernet = Fernet(file_key)

            # 3. Cifrar el archivo
            encrypted_data = file_fernet.encrypt(file_data)
            encrypted_size = len(encrypted_data)

            # 4. Generar claves de usuario
            user_keys = {}
            file_accesses = []

            for username in authorized_usernames:
                user = self.session.query(User).filter_by(
                    username=username,
                    organization_id=self.current_user.organization_id
                ).first()

                if not user:
                    raise ValueError(f"User '{username}' not found in organization")

                # Generar clave única para este usuario + archivo
                user_key = Fernet.generate_key().decode('utf-8')
                user_keys[username] = user_key

            # 5. Cifrar la clave del archivo con la clave maestra
            encrypted_file_key = self.master_fernet.encrypt(file_key)

            # 6. Determinar ruta de salida
            if not output_path:
                encrypted_filename = f"{file_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.encrypted"
                output_path = self.storage_dir / encrypted_filename
            else:
                output_path = Path(output_path)

            # 7. Crear estructura del archivo cifrado
            secure_data = {
                'encrypted_data': encrypted_data.hex(),
                'encrypted_file_key': encrypted_file_key.hex(),
                'user_keys': user_keys,
                'metadata': {
                    'original_filename': file_path.name,
                    'encrypted_on': datetime.utcnow().isoformat(),
                    'encrypted_by': self.current_user.username,
                    'authorized_users': authorized_usernames,
                    'encryption_algorithm': 'Fernet/AES256',
                    'file_hash': file_hash
                }
            }

            # 8. Guardar archivo cifrado
            with open(output_path, 'w') as f:
                json.dump(secure_data, f)

            # 9. Crear registro en base de datos
            secure_file = SecureFile(
                organization_id=self.current_user.organization_id,
                department_id=self.current_user.department_id,
                original_filename=file_path.name,
                encrypted_filename=output_path.name,
                file_path=str(output_path),
                file_extension=file_path.suffix,
                original_size=original_size,
                encrypted_size=encrypted_size,
                file_hash=file_hash,
                encryption_algorithm='Fernet/AES256',
                encryption_key_id=encrypted_file_key.hex()[:64],
                is_metadata_encrypted=True,
                description=description,
                uploaded_by=self.current_user.id,
                is_active=True
            )

            self.session.add(secure_file)
            self.session.flush()  # Para obtener el ID

            # 10. Crear registros de acceso para usuarios autorizados
            for username in authorized_usernames:
                user = self.session.query(User).filter_by(
                    username=username,
                    organization_id=self.current_user.organization_id
                ).first()

                file_access = FileAccess(
                    file_id=secure_file.id,
                    user_id=user.id,
                    access_type='read',
                    granted_by=self.current_user.id,
                    granted_at=datetime.utcnow(),
                    is_active=True
                )
                file_accesses.append(file_access)
                self.session.add(file_access)

            self.session.commit()

            # 11. Registrar en auditoría
            self.audit_service.log_action(
                user_id=self.current_user.id,
                action='file.encrypt',
                resource_type='SecureFile',
                resource_id=secure_file.id,
                status='success',
                details=f"Encrypted file '{file_path.name}' for {len(authorized_usernames)} users",
                ip_address='127.0.0.1'
            )

            return secure_file, user_keys

        except Exception as e:
            self.session.rollback()

            # Registrar error en auditoría
            self.audit_service.log_action(
                user_id=self.current_user.id,
                action='file.encrypt',
                resource_type='SecureFile',
                status='error',
                details=f"Failed to encrypt '{file_path}': {str(e)}",
                ip_address='127.0.0.1'
            )

            raise

    def decrypt_file(
        self,
        encrypted_path: str,
        user_key: str,
        output_path: Optional[str] = None,
        read_only: bool = False
    ) -> str:
        """
        Descifra un archivo usando clave de usuario

        Args:
            encrypted_path: Ruta del archivo cifrado
            user_key: Clave del usuario
            output_path: Ruta de salida opcional
            read_only: Si True, retorna datos sin guardar archivo

        Returns:
            Ruta del archivo descifrado o datos en memoria
        """
        try:
            encrypted_path = Path(encrypted_path)

            # 1. Cargar archivo cifrado
            with open(encrypted_path, 'r') as f:
                secure_data = json.load(f)

            # 2. Verificar que la clave de usuario está autorizada
            user_authorized = False
            authorized_username = None

            for username, stored_key in secure_data['user_keys'].items():
                if stored_key == user_key:
                    user_authorized = True
                    authorized_username = username
                    break

            if not user_authorized:
                raise ValueError("User key not authorized for this file")

            # 3. Buscar archivo en base de datos
            secure_file = self.session.query(SecureFile).filter_by(
                encrypted_filename=encrypted_path.name,
                organization_id=self.current_user.organization_id
            ).first()

            if not secure_file:
                raise ValueError("File not found in database")

            # 4. Verificar permisos de acceso
            file_access = self.session.query(FileAccess).filter_by(
                file_id=secure_file.id,
                user_id=self.current_user.id,
                is_active=True
            ).first()

            if not file_access:
                raise ValueError("User does not have access to this file")

            # 5. Descifrar clave del archivo
            encrypted_file_key = bytes.fromhex(secure_data['encrypted_file_key'])
            file_key = self.master_fernet.decrypt(encrypted_file_key)

            # 6. Descifrar archivo
            file_fernet = Fernet(file_key)
            encrypted_data = bytes.fromhex(secure_data['encrypted_data'])
            decrypted_data = file_fernet.decrypt(encrypted_data)

            # 7. Actualizar último acceso
            file_access.last_accessed = datetime.utcnow()
            file_access.access_count = (file_access.access_count or 0) + 1

            # 8. Registrar en auditoría
            self.audit_service.log_action(
                user_id=self.current_user.id,
                action='file.decrypt',
                resource_type='SecureFile',
                resource_id=secure_file.id,
                status='success',
                details=f"Decrypted file '{secure_file.original_filename}' (read_only={read_only})",
                ip_address='127.0.0.1'
            )

            self.session.commit()

            # 9. Si es solo lectura, retornar datos
            if read_only:
                return decrypted_data

            # 10. Determinar ruta de salida y guardar
            if not output_path:
                original_name = secure_data['metadata']['original_filename']
                output_path = encrypted_path.parent / f"decrypted_{original_name}"
            else:
                output_path = Path(output_path)

            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            return str(output_path)

        except Exception as e:
            self.session.rollback()

            # Registrar error en auditoría
            self.audit_service.log_action(
                user_id=self.current_user.id,
                action='file.decrypt',
                resource_type='SecureFile',
                status='error',
                details=f"Failed to decrypt '{encrypted_path}': {str(e)}",
                ip_address='127.0.0.1'
            )

            raise

    def list_user_files(self) -> List[SecureFile]:
        """
        Lista archivos accesibles por el usuario actual

        Returns:
            Lista de SecureFile
        """
        # Obtener IDs de archivos con acceso
        file_accesses = self.session.query(FileAccess).filter_by(
            user_id=self.current_user.id,
            is_active=True
        ).all()

        file_ids = [fa.file_id for fa in file_accesses]

        # Obtener archivos
        files = self.session.query(SecureFile).filter(
            SecureFile.id.in_(file_ids),
            SecureFile.is_active == True
        ).order_by(SecureFile.created_at.desc()).all()

        return files

    def revoke_access(self, file_id: str, user_id: str) -> bool:
        """
        Revoca acceso de un usuario a un archivo

        Args:
            file_id: ID del archivo
            user_id: ID del usuario

        Returns:
            True si se revocó exitosamente
        """
        try:
            file_access = self.session.query(FileAccess).filter_by(
                file_id=file_id,
                user_id=user_id,
                is_active=True
            ).first()

            if not file_access:
                raise ValueError("Access not found")

            file_access.is_active = False
            file_access.revoked_by = self.current_user.id
            file_access.revoked_at = datetime.utcnow()

            self.session.commit()

            # Registrar en auditoría
            self.audit_service.log_action(
                user_id=self.current_user.id,
                action='file.revoke_access',
                resource_type='FileAccess',
                resource_id=file_access.id,
                status='success',
                details=f"Revoked access for user {user_id} to file {file_id}",
                ip_address='127.0.0.1'
            )

            return True

        except Exception as e:
            self.session.rollback()
            raise
