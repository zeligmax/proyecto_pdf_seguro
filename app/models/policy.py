#!/usr/bin/env python3
"""
policy.py - Policy Model for File Secure v3.2
Configurable security policies per organization
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import json

from app.core.database import Base


class Policy(Base):
    """
    Modelo de Política
    Políticas de seguridad configurables por organización/departamento
    """
    __tablename__ = 'policies'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    department_id = Column(String(36), ForeignKey('departments.id', ondelete='CASCADE'), nullable=True, index=True)

    # Identificación
    name = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Tipo de política
    policy_type = Column(String(100), nullable=False, index=True)  # password, session, file, encryption, access, audit

    # Configuración en JSON
    config = Column(Text, nullable=False)  # JSON con los parámetros de la política

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)

    # Prioridad (para resolución de conflictos)
    priority = Column(Integer, default=0, nullable=False)

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(String(36), nullable=True)

    # Fechas de vigencia (opcional)
    effective_from = Column(DateTime, nullable=True)
    effective_until = Column(DateTime, nullable=True)

    # Relaciones
    organization = relationship("Organization", back_populates="policies")
    department = relationship("Department", foreign_keys=[department_id])

    def __repr__(self):
        return f"<Policy(id={self.id}, name={self.name}, type={self.policy_type})>"

    def get_config(self):
        """Obtiene la configuración parseada como diccionario"""
        if self.config:
            return json.loads(self.config)
        return {}

    def set_config(self, config_dict):
        """Establece la configuración desde un diccionario"""
        self.config = json.dumps(config_dict)

    def is_effective(self):
        """Verifica si la política está vigente"""
        now = datetime.utcnow()

        if not self.is_active:
            return False

        if self.effective_from and now < self.effective_from:
            return False

        if self.effective_until and now > self.effective_until:
            return False

        return True

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'department_id': self.department_id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'policy_type': self.policy_type,
            'config': self.get_config(),
            'is_active': self.is_active,
            'is_default': self.is_default,
            'priority': self.priority,
            'effective_from': self.effective_from.isoformat() if self.effective_from else None,
            'effective_until': self.effective_until.isoformat() if self.effective_until else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


# Plantillas de políticas predeterminadas
DEFAULT_POLICIES = {
    "password_policy": {
        "display_name": "Default Password Policy",
        "description": "Política de contraseñas seguras",
        "config": {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "expiration_days": 90,
            "history_count": 5,
            "max_failed_attempts": 3,
            "lockout_duration_minutes": 30
        }
    },
    "session_policy": {
        "display_name": "Default Session Policy",
        "description": "Política de sesiones de usuario",
        "config": {
            "timeout_minutes": 30,
            "max_concurrent_sessions": 3,
            "require_mfa": False,
            "ip_whitelist_required": False,
            "remember_device_days": 30
        }
    },
    "file_policy": {
        "display_name": "Default File Policy",
        "description": "Política de gestión de archivos",
        "config": {
            "max_file_size_mb": 100,
            "allowed_extensions": [".pdf", ".docx", ".xlsx", ".txt", ".pbip", ".pbix"],
            "retention_days": 365,
            "auto_delete_after_days": None,
            "require_approval_for_sharing": False,
            "watermark_required": False,
            "prevent_download": False
        }
    },
    "encryption_policy": {
        "display_name": "Default Encryption Policy",
        "description": "Política de cifrado de archivos",
        "config": {
            "algorithm": "AES-256-GCM",
            "key_rotation_days": 90,
            "require_user_keys": True,
            "min_authorized_users": 1,
            "max_authorized_users": 50,
            "encrypt_metadata": True
        }
    },
    "access_policy": {
        "display_name": "Default Access Policy",
        "description": "Política de control de acceso",
        "config": {
            "max_failed_attempts": 3,
            "lockout_duration_minutes": 30,
            "require_ip_whitelist": False,
            "allowed_hours": "00:00-23:59",
            "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "require_2fa_for_sensitive": False
        }
    },
    "audit_policy": {
        "display_name": "Default Audit Policy",
        "description": "Política de auditoría y logs",
        "config": {
            "log_retention_days": 730,
            "alert_on_critical": True,
            "alert_email": None,
            "export_format": "json",
            "log_level": "info",
            "track_file_downloads": True,
            "track_failed_access": True
        }
    }
}
