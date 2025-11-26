#!/usr/bin/env python3
"""
organization.py - Organization Model for File Secure v3.2
Multi-tenancy support
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.core.database import Base


class Organization(Base):
    """
    Modelo de Organización
    Soporta multi-tenancy - cada empresa puede tener múltiples organizaciones
    """
    __tablename__ = 'organizations'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)

    # Configuración específica
    settings = Column(Text, nullable=True)  # JSON con configuración específica

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(String(36), nullable=True)

    # Relaciones
    departments = relationship("Department", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization")
    files = relationship("SecureFile", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")

    def __repr__(self):
        return f"<Organization(id={self.id}, name={self.name})>"

    def to_dict(self):
        """Convierte el objeto a diccionario"""
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
