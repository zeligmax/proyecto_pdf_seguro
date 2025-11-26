#!/usr/bin/env python3
"""
audit_log.py - Audit Log Model for File Secure v3.2
Centralized audit logging system
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import json

from app.core.database import Base


class AuditLog(Base):
    """
    Modelo de Log de Auditoría
    Sistema centralizado de auditoría con búsqueda optimizada
    """
    __tablename__ = 'audit_logs'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Timestamp (indexado para consultas por rango de fechas)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Contexto organizacional
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)
    department_id = Column(String(36), ForeignKey('departments.id', ondelete='SET NULL'), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)

    # Acción realizada
    action = Column(String(255), nullable=False, index=True)  # ej: "file.decrypt", "user.create"
    resource_type = Column(String(100), nullable=True, index=True)  # ej: "file", "user", "policy"
    resource_id = Column(String(255), nullable=True, index=True)  # ID del recurso afectado
    resource_name = Column(String(512), nullable=True)  # Nombre del recurso

    # Resultado
    status = Column(String(50), nullable=False, index=True)  # success, failure, denied
    severity = Column(String(50), nullable=False, index=True)  # info, warning, error, critical

    # Información de red
    ip_address = Column(String(45), nullable=True, index=True)  # IPv4 o IPv6
    user_agent = Column(String(512), nullable=True)

    # Detalles adicionales en JSON
    meta_data = Column(Text, nullable=True)  # JSON con detalles específicos
    error_message = Column(Text, nullable=True)  # Mensaje de error si aplica

    # Geolocalización (opcional)
    country = Column(String(2), nullable=True)
    city = Column(String(255), nullable=True)

    # Relaciones
    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action={self.action}, status={self.status})>"

    def get_metadata(self):
        """Obtiene los metadatos parseados como diccionario"""
        if self.meta_data:
            try:
                return json.loads(self.meta_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_metadata(self, metadata_dict):
        """Establece los metadatos desde un diccionario"""
        self.meta_data = json.dumps(metadata_dict)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'organization_id': self.organization_id,
            'department_id': self.department_id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'resource_name': self.resource_name,
            'status': self.status,
            'severity': self.severity,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'metadata': self.get_metadata(),
            'error_message': self.error_message,
            'country': self.country,
            'city': self.city
        }

    @classmethod
    def log_action(cls, session, action: str, user_id: str = None, organization_id: str = None,
                   resource_type: str = None, resource_id: str = None, resource_name: str = None,
                   status: str = "success", severity: str = "info", ip_address: str = None,
                   metadata: dict = None, error_message: str = None):
        """
        Método helper para crear un log de auditoría

        Args:
            session: Sesión de SQLAlchemy
            action: Acción realizada
            user_id: ID del usuario
            organization_id: ID de la organización
            resource_type: Tipo de recurso
            resource_id: ID del recurso
            resource_name: Nombre del recurso
            status: Estado (success, failure, denied)
            severity: Severidad (info, warning, error, critical)
            ip_address: Dirección IP
            metadata: Metadatos adicionales (dict)
            error_message: Mensaje de error
        """
        log = cls(
            action=action,
            user_id=user_id,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            status=status,
            severity=severity,
            ip_address=ip_address,
            error_message=error_message
        )

        if metadata:
            log.set_metadata(metadata)

        session.add(log)
        return log


# Índices compuestos para optimizar consultas comunes
Index('idx_audit_org_timestamp', AuditLog.organization_id, AuditLog.timestamp)
Index('idx_audit_user_timestamp', AuditLog.user_id, AuditLog.timestamp)
Index('idx_audit_action_status', AuditLog.action, AuditLog.status)
Index('idx_audit_severity_timestamp', AuditLog.severity, AuditLog.timestamp)


# Acciones predefinidas del sistema
AUDIT_ACTIONS = {
    # Authentication
    "auth.login": "User Login",
    "auth.logout": "User Logout",
    "auth.failed_login": "Failed Login Attempt",
    "auth.password_change": "Password Changed",
    "auth.password_reset": "Password Reset",
    "auth.mfa_enabled": "MFA Enabled",
    "auth.mfa_disabled": "MFA Disabled",

    # User management
    "user.create": "User Created",
    "user.update": "User Updated",
    "user.delete": "User Deleted",
    "user.activate": "User Activated",
    "user.deactivate": "User Deactivated",
    "user.lock": "User Locked",
    "user.unlock": "User Unlocked",
    "user.role_assigned": "Role Assigned to User",
    "user.role_removed": "Role Removed from User",

    # File operations
    "file.encrypt": "File Encrypted",
    "file.decrypt": "File Decrypted",
    "file.delete": "File Deleted",
    "file.share": "File Shared",
    "file.download": "File Downloaded",
    "file.access_denied": "File Access Denied",

    # Organization management
    "org.create": "Organization Created",
    "org.update": "Organization Updated",
    "org.delete": "Organization Deleted",

    # Department management
    "dept.create": "Department Created",
    "dept.update": "Department Updated",
    "dept.delete": "Department Deleted",

    # Policy management
    "policy.create": "Policy Created",
    "policy.update": "Policy Updated",
    "policy.delete": "Policy Deleted",
    "policy.activated": "Policy Activated",
    "policy.deactivated": "Policy Deactivated",

    # Role management
    "role.create": "Role Created",
    "role.update": "Role Updated",
    "role.delete": "Role Deleted",
    "role.permission_added": "Permission Added to Role",
    "role.permission_removed": "Permission Removed from Role",

    # System events
    "system.startup": "System Started",
    "system.shutdown": "System Shutdown",
    "system.config_change": "Configuration Changed",
    "system.backup": "System Backup",
    "system.restore": "System Restore",

    # Security events
    "security.ip_blocked": "IP Address Blocked",
    "security.suspicious_activity": "Suspicious Activity Detected",
    "security.policy_violation": "Security Policy Violation",
}
