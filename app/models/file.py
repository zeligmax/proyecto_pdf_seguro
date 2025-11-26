#!/usr/bin/env python3
"""
file.py - Secure File Model for File Secure v3.2
File management with access control
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, BigInteger, Text, Table
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import json

from app.core.database import Base


class SecureFile(Base):
    """
    Modelo de Archivo Cifrado
    Gestiona archivos cifrados con control de acceso granular
    """
    __tablename__ = 'secure_files'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    department_id = Column(String(36), ForeignKey('departments.id', ondelete='SET NULL'), nullable=True, index=True)

    # Información del archivo
    original_filename = Column(String(512), nullable=False)
    encrypted_filename = Column(String(512), nullable=False, unique=True)
    file_path = Column(String(1024), nullable=False)  # Ruta física del archivo
    file_extension = Column(String(20), nullable=True, index=True)

    # Tamaño del archivo
    original_size = Column(BigInteger, nullable=True)  # Bytes
    encrypted_size = Column(BigInteger, nullable=True)  # Bytes

    # Hash para verificación de integridad
    file_hash = Column(String(64), nullable=True)  # SHA-256
    checksum = Column(String(32), nullable=True)  # MD5

    # Cifrado
    encryption_algorithm = Column(String(100), default="AES-256-GCM", nullable=False)
    encryption_key_id = Column(String(255), nullable=True)  # Referencia a la clave usada
    is_metadata_encrypted = Column(Boolean, default=True, nullable=False)

    # Control de versiones
    version = Column(Integer, default=1, nullable=False)
    parent_file_id = Column(String(36), ForeignKey('secure_files.id', ondelete='SET NULL'), nullable=True)

    # Propietario
    owner_id = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    created_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Metadatos adicionales
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)  # JSON array
    custom_metadata = Column(Text, nullable=True)  # JSON

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)  # Soft delete

    # Estadísticas de acceso
    access_count = Column(Integer, default=0, nullable=False)
    last_accessed = Column(DateTime, nullable=True)
    download_count = Column(Integer, default=0, nullable=False)

    # Fechas
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    # Retención
    retention_until = Column(DateTime, nullable=True)  # Fecha de expiración

    # Relaciones
    organization = relationship("Organization", back_populates="files")
    department = relationship("Department", back_populates="files")
    owner = relationship("User", foreign_keys=[owner_id])
    creator = relationship("User", foreign_keys=[created_by])
    versions = relationship("SecureFile", backref="parent_file", remote_side=[id])
    accesses = relationship("FileAccess", back_populates="file", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<SecureFile(id={self.id}, filename={self.original_filename})>"

    def get_tags(self):
        """Obtiene las etiquetas como lista"""
        if self.tags:
            try:
                return json.loads(self.tags)
            except json.JSONDecodeError:
                return []
        return []

    def set_tags(self, tags_list):
        """Establece las etiquetas desde una lista"""
        self.tags = json.dumps(tags_list)

    def get_custom_metadata(self):
        """Obtiene los metadatos personalizados como diccionario"""
        if self.custom_metadata:
            try:
                return json.loads(self.custom_metadata)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_custom_metadata(self, metadata_dict):
        """Establece los metadatos personalizados desde un diccionario"""
        self.custom_metadata = json.dumps(metadata_dict)

    def increment_access_count(self):
        """Incrementa el contador de accesos"""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()

    def increment_download_count(self):
        """Incrementa el contador de descargas"""
        self.download_count += 1

    def soft_delete(self):
        """Marca el archivo como eliminado (soft delete)"""
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = datetime.utcnow()

    def restore(self):
        """Restaura un archivo eliminado"""
        self.is_deleted = False
        self.is_active = True
        self.deleted_at = None

    def to_dict(self, include_accesses=False):
        data = {
            'id': self.id,
            'organization_id': self.organization_id,
            'department_id': self.department_id,
            'original_filename': self.original_filename,
            'encrypted_filename': self.encrypted_filename,
            'file_extension': self.file_extension,
            'original_size': self.original_size,
            'encrypted_size': self.encrypted_size,
            'encryption_algorithm': self.encryption_algorithm,
            'version': self.version,
            'owner_id': self.owner_id,
            'created_by': self.created_by,
            'description': self.description,
            'tags': self.get_tags(),
            'is_active': self.is_active,
            'is_deleted': self.is_deleted,
            'access_count': self.access_count,
            'download_count': self.download_count,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'retention_until': self.retention_until.isoformat() if self.retention_until else None
        }

        if include_accesses:
            data['accesses'] = [access.to_dict() for access in self.accesses]

        return data


class FileAccess(Base):
    """
    Modelo de Acceso a Archivos
    Registro de usuarios autorizados para acceder a archivos específicos
    """
    __tablename__ = 'file_accesses'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String(36), ForeignKey('secure_files.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Clave de usuario para este archivo
    user_key = Column(String(512), nullable=False)
    user_salt = Column(String(64), nullable=True)

    # Permisos específicos para este acceso
    can_decrypt = Column(Boolean, default=True, nullable=False)
    can_download = Column(Boolean, default=True, nullable=False)
    can_share = Column(Boolean, default=False, nullable=False)
    can_delete = Column(Boolean, default=False, nullable=False)

    # Expiración del acceso
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    granted_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Estadísticas
    access_count = Column(Integer, default=0, nullable=False)
    last_access = Column(DateTime, nullable=True)

    # Relaciones
    file = relationship("SecureFile", back_populates="accesses")
    user = relationship("User", foreign_keys=[user_id], back_populates="file_accesses")
    granter = relationship("User", foreign_keys=[granted_by])
    revoker = relationship("User", foreign_keys=[revoked_by])

    def __repr__(self):
        return f"<FileAccess(file_id={self.file_id}, user_id={self.user_id})>"

    def is_valid(self):
        """Verifica si el acceso es válido actualmente"""
        if not self.is_active or self.is_revoked:
            return False

        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False

        return True

    def revoke(self, revoked_by_user_id: str = None):
        """Revoca el acceso"""
        self.is_revoked = True
        self.is_active = False
        self.revoked_at = datetime.utcnow()
        self.revoked_by = revoked_by_user_id

    def increment_access(self):
        """Incrementa el contador de accesos"""
        self.access_count += 1
        self.last_access = datetime.utcnow()

    def to_dict(self):
        return {
            'id': self.id,
            'file_id': self.file_id,
            'user_id': self.user_id,
            'can_decrypt': self.can_decrypt,
            'can_download': self.can_download,
            'can_share': self.can_share,
            'can_delete': self.can_delete,
            'granted_at': self.granted_at.isoformat() if self.granted_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'granted_by': self.granted_by,
            'is_active': self.is_active,
            'is_revoked': self.is_revoked,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'access_count': self.access_count,
            'last_access': self.last_access.isoformat() if self.last_access else None,
            'is_valid': self.is_valid()
        }
