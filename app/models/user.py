#!/usr/bin/env python3
"""
user.py - User Model for File Secure v3.2
Enhanced user model with RBAC support
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import hashlib
import secrets

from app.core.database import Base


class User(Base):
    """
    Modelo de Usuario v3.2
    Soporta multi-tenancy, roles, y autenticación mejorada
    """
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    department_id = Column(String(36), ForeignKey('departments.id', ondelete='SET NULL'), nullable=True, index=True)

    # Credenciales
    username = Column(String(255), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=True, index=True)
    password_hash = Column(String(255), nullable=True)  # Nullable para usuarios externos
    password_salt = Column(String(64), nullable=True)

    # Información personal
    full_name = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    avatar_url = Column(String(512), nullable=True)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)  # SuperAdmin
    is_locked = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # Seguridad
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(32), nullable=True)
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, nullable=True)
    password_must_change = Column(Boolean, default=False, nullable=False)

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(String(36), nullable=True)

    # Settings personalizados
    preferences = Column(Text, nullable=True)  # JSON

    # Relaciones
    organization = relationship("Organization", back_populates="users")
    department = relationship("Department", back_populates="users")
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    file_accesses = relationship("FileAccess", foreign_keys="[FileAccess.user_id]", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, org={self.organization_id})>"

    def set_password(self, password: str):
        """
        Hashea y almacena la contraseña de forma segura

        Args:
            password: Contraseña en texto plano
        """
        # Generar salt único
        self.password_salt = secrets.token_hex(32)

        # Hash con PBKDF2
        self.password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self.password_salt.encode('utf-8'),
            100000
        ).hex()

        self.last_password_change = datetime.utcnow()

    def check_password(self, password: str) -> bool:
        """
        Verifica si la contraseña es correcta

        Args:
            password: Contraseña a verificar

        Returns:
            bool: True si la contraseña es correcta
        """
        if not self.password_hash or not self.password_salt:
            return False

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self.password_salt.encode('utf-8'),
            100000
        ).hex()

        return password_hash == self.password_hash

    def has_permission(self, permission_name: str) -> bool:
        """
        Verifica si el usuario tiene un permiso específico

        Args:
            permission_name: Nombre del permiso (ej: "file.decrypt")

        Returns:
            bool: True si tiene el permiso
        """
        if self.is_admin:
            return True  # SuperAdmin tiene todos los permisos

        for role in self.roles:
            if not role.is_active:
                continue
            for permission in role.permissions:
                if permission.name == permission_name or permission.name == "*":
                    return True

        return False

    def has_role(self, role_name: str) -> bool:
        """
        Verifica si el usuario tiene un rol específico

        Args:
            role_name: Nombre del rol

        Returns:
            bool: True si tiene el rol
        """
        return any(role.name == role_name and role.is_active for role in self.roles)

    def to_dict(self, include_sensitive=False):
        """Convierte el objeto a diccionario"""
        data = {
            'id': self.id,
            'organization_id': self.organization_id,
            'department_id': self.department_id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'display_name': self.display_name,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'is_locked': self.is_locked,
            'mfa_enabled': self.mfa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'roles': [role.name for role in self.roles]
        }

        if include_sensitive:
            data['failed_login_attempts'] = self.failed_login_attempts
            data['locked_until'] = self.locked_until.isoformat() if self.locked_until else None

        return data
