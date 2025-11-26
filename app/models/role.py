#!/usr/bin/env python3
"""
role.py - Role and Permission Models for File Secure v3.2
RBAC (Role-Based Access Control) implementation
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Table, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.core.database import Base


# Tabla de asociación Many-to-Many: Users <-> Roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('role_id', String(36), ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow),
    Column('assigned_by', String(36), nullable=True)
)


# Tabla de asociación Many-to-Many: Roles <-> Permissions
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', String(36), ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', String(36), ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow)
)


class Permission(Base):
    """
    Modelo de Permiso
    Permisos granulares del sistema
    """
    __tablename__ = 'permissions'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Identificador del permiso (ej: "file.decrypt", "user.create")
    name = Column(String(255), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Categoría del permiso (ej: "file", "user", "policy")
    category = Column(String(100), nullable=False, index=True)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)
    is_system = Column(Boolean, default=False, nullable=False)  # Permisos del sistema (no editables)

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relaciones
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

    def __repr__(self):
        return f"<Permission(name={self.name})>"

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'category': self.category,
            'is_active': self.is_active,
            'is_system': self.is_system
        }


class Role(Base):
    """
    Modelo de Rol
    Roles con permisos asociados
    """
    __tablename__ = 'roles'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)

    # Identificador del rol
    name = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Tipo de rol
    is_system = Column(Boolean, default=False, nullable=False)  # Roles predefinidos del sistema
    is_custom = Column(Boolean, default=False, nullable=False)  # Roles personalizados por empresa

    # Prioridad (para resolución de conflictos)
    priority = Column(Integer, default=0, nullable=False)

    # Estado
    is_active = Column(Boolean, default=True, nullable=False)

    # Metadatos
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(String(36), nullable=True)

    # Relaciones
    organization = relationship("Organization", foreign_keys=[organization_id])
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")

    def __repr__(self):
        return f"<Role(name={self.name}, org={self.organization_id})>"

    def add_permission(self, permission: Permission):
        """Añade un permiso a este rol"""
        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission: Permission):
        """Elimina un permiso de este rol"""
        if permission in self.permissions:
            self.permissions.remove(permission)

    def has_permission(self, permission_name: str) -> bool:
        """Verifica si este rol tiene un permiso específico"""
        return any(p.name == permission_name or p.name == "*"
                   for p in self.permissions if p.is_active)

    def to_dict(self, include_permissions=False):
        data = {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'is_system': self.is_system,
            'is_custom': self.is_custom,
            'priority': self.priority,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_count': len(self.users)
        }

        if include_permissions:
            data['permissions'] = [p.to_dict() for p in self.permissions]

        return data


# Permisos predefinidos del sistema
SYSTEM_PERMISSIONS = [
    # File permissions
    ("file.encrypt", "Encrypt Files", "Permite cifrar archivos", "file"),
    ("file.decrypt", "Decrypt Files", "Permite descifrar archivos", "file"),
    ("file.delete", "Delete Files", "Permite eliminar archivos", "file"),
    ("file.share", "Share Files", "Permite compartir archivos con otros usuarios", "file"),
    ("file.view", "View Files", "Permite ver archivos", "file"),
    ("file.download", "Download Files", "Permite descargar archivos", "file"),

    # User permissions
    ("user.create", "Create Users", "Permite crear usuarios", "user"),
    ("user.edit", "Edit Users", "Permite editar usuarios", "user"),
    ("user.delete", "Delete Users", "Permite eliminar usuarios", "user"),
    ("user.view", "View Users", "Permite ver usuarios", "user"),
    ("user.assign_roles", "Assign Roles", "Permite asignar roles a usuarios", "user"),

    # Organization permissions
    ("org.create", "Create Organizations", "Permite crear organizaciones", "organization"),
    ("org.edit", "Edit Organizations", "Permite editar organizaciones", "organization"),
    ("org.delete", "Delete Organizations", "Permite eliminar organizaciones", "organization"),
    ("org.view", "View Organizations", "Permite ver organizaciones", "organization"),

    # Department permissions
    ("dept.create", "Create Departments", "Permite crear departamentos", "department"),
    ("dept.edit", "Edit Departments", "Permite editar departamentos", "department"),
    ("dept.delete", "Delete Departments", "Permite eliminar departamentos", "department"),
    ("dept.view", "View Departments", "Permite ver departamentos", "department"),

    # Policy permissions
    ("policy.create", "Create Policies", "Permite crear políticas", "policy"),
    ("policy.edit", "Edit Policies", "Permite editar políticas", "policy"),
    ("policy.delete", "Delete Policies", "Permite eliminar políticas", "policy"),
    ("policy.view", "View Policies", "Permite ver políticas", "policy"),

    # Audit permissions
    ("audit.view", "View Audit Logs", "Permite ver logs de auditoría", "audit"),
    ("audit.export", "Export Reports", "Permite exportar reportes", "audit"),

    # Role permissions
    ("role.create", "Create Roles", "Permite crear roles personalizados", "role"),
    ("role.edit", "Edit Roles", "Permite editar roles", "role"),
    ("role.delete", "Delete Roles", "Permite eliminar roles", "role"),
    ("role.view", "View Roles", "Permite ver roles", "role"),

    # Dashboard permissions
    ("dashboard.view", "View Dashboard", "Permite ver el dashboard ejecutivo", "dashboard"),
    ("dashboard.export", "Export Dashboard", "Permite exportar datos del dashboard", "dashboard"),

    # Wildcard (SuperAdmin only)
    ("*", "All Permissions", "Acceso completo a todas las funcionalidades", "system"),
]


# Roles predefinidos del sistema
SYSTEM_ROLES = {
    "SuperAdmin": {
        "display_name": "Super Administrator",
        "description": "Administrador con acceso completo al sistema",
        "permissions": ["*"],
        "priority": 100,
        "is_system": True
    },
    "OrgAdmin": {
        "display_name": "Organization Administrator",
        "description": "Administrador de una organización específica",
        "permissions": [
            "user.create", "user.edit", "user.delete", "user.view", "user.assign_roles",
            "dept.create", "dept.edit", "dept.delete", "dept.view",
            "file.encrypt", "file.decrypt", "file.delete", "file.share", "file.view", "file.download",
            "policy.create", "policy.edit", "policy.delete", "policy.view",
            "audit.view", "audit.export",
            "role.view", "dashboard.view", "dashboard.export"
        ],
        "priority": 80,
        "is_system": True
    },
    "DepartmentManager": {
        "display_name": "Department Manager",
        "description": "Gerente de departamento con permisos limitados",
        "permissions": [
            "user.view",
            "dept.view",
            "file.encrypt", "file.decrypt", "file.share", "file.view", "file.download",
            "policy.view",
            "audit.view",
            "dashboard.view"
        ],
        "priority": 60,
        "is_system": True
    },
    "Editor": {
        "display_name": "Editor",
        "description": "Usuario con permisos de edición de archivos",
        "permissions": [
            "file.encrypt", "file.decrypt", "file.view", "file.download",
            "user.view", "dept.view"
        ],
        "priority": 40,
        "is_system": True
    },
    "Viewer": {
        "display_name": "Viewer",
        "description": "Usuario con permisos solo de lectura",
        "permissions": [
            "file.decrypt", "file.view", "file.download"
        ],
        "priority": 20,
        "is_system": True
    },
    "Auditor": {
        "display_name": "Auditor",
        "description": "Auditor con acceso solo a logs y reportes",
        "permissions": [
            "audit.view", "audit.export",
            "dashboard.view", "dashboard.export",
            "user.view", "dept.view", "org.view"
        ],
        "priority": 50,
        "is_system": True
    }
}
