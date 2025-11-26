#!/usr/bin/env python3
"""
department.py - Department Model for File Secure v3.2
Departments within organizations
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.core.database import Base


class Department(Base):
    """
    Modelo de Departamento
    Cada organización puede tener múltiples departamentos
    """
    __tablename__ = 'departments'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    name = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Jerarquía (opcional - departamento padre)
    parent_id = Column(String(36), ForeignKey('departments.id', ondelete='SET NULL'), nullable=True)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)

    # Configuración específica
    settings = Column(Text, nullable=True)  # JSON

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relaciones
    organization = relationship("Organization", back_populates="departments")
    parent = relationship("Department", remote_side=[id], backref="subdepartments")
    users = relationship("User", back_populates="department")
    files = relationship("SecureFile", back_populates="department")

    def __repr__(self):
        return f"<Department(id={self.id}, name={self.name}, org={self.organization_id})>"

    def to_dict(self):
        """Convierte el objeto a diccionario"""
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'parent_id': self.parent_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
