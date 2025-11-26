#!/usr/bin/env python3
"""
rbac_service.py - RBAC Service for File Secure v3.2
Role-Based Access Control implementation
"""

from typing import List, Optional
from sqlalchemy.orm import Session

from app.models import User, Role, Permission, Organization, AuditLog


class RBACService:
    """
    Servicio de control de acceso basado en roles (RBAC)
    """

    def __init__(self, db_session: Session):
        """
        Inicializa el servicio RBAC

        Args:
            db_session: Sesión de base de datos SQLAlchemy
        """
        self.db = db_session

    def user_has_permission(self, user_id: str, permission_name: str) -> bool:
        """
        Verifica si un usuario tiene un permiso específico

        Args:
            user_id: ID del usuario
            permission_name: Nombre del permiso (ej: "file.decrypt")

        Returns:
            bool: True si tiene el permiso
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        return user.has_permission(permission_name)

    def user_has_role(self, user_id: str, role_name: str) -> bool:
        """
        Verifica si un usuario tiene un rol específico

        Args:
            user_id: ID del usuario
            role_name: Nombre del rol

        Returns:
            bool: True si tiene el rol
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        return user.has_role(role_name)

    def assign_role_to_user(self, user_id: str, role_id: str, assigned_by: str = None) -> bool:
        """
        Asigna un rol a un usuario

        Args:
            user_id: ID del usuario
            role_id: ID del rol
            assigned_by: ID del usuario que asigna

        Returns:
            bool: True si se asignó exitosamente
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        role = self.db.query(Role).filter_by(id=role_id).first()

        if not user or not role:
            return False

        # Verificar si ya tiene el rol
        if role in user.roles:
            return True  # Ya lo tiene

        # Asignar rol
        user.roles.append(role)

        # Log
        AuditLog.log_action(
            self.db,
            action="user.role_assigned",
            user_id=assigned_by,
            organization_id=user.organization_id,
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            status="success",
            severity="info",
            metadata={
                "role_id": role.id,
                "role_name": role.name,
                "target_user": user.username
            }
        )

        self.db.commit()
        return True

    def remove_role_from_user(self, user_id: str, role_id: str, removed_by: str = None) -> bool:
        """
        Remueve un rol de un usuario

        Args:
            user_id: ID del usuario
            role_id: ID del rol
            removed_by: ID del usuario que remueve

        Returns:
            bool: True si se removió exitosamente
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        role = self.db.query(Role).filter_by(id=role_id).first()

        if not user or not role:
            return False

        # Verificar si tiene el rol
        if role not in user.roles:
            return True  # Ya no lo tiene

        # Remover rol
        user.roles.remove(role)

        # Log
        AuditLog.log_action(
            self.db,
            action="user.role_removed",
            user_id=removed_by,
            organization_id=user.organization_id,
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            status="success",
            severity="info",
            metadata={
                "role_id": role.id,
                "role_name": role.name,
                "target_user": user.username
            }
        )

        self.db.commit()
        return True

    def get_user_permissions(self, user_id: str) -> List[str]:
        """
        Obtiene todos los permisos de un usuario

        Args:
            user_id: ID del usuario

        Returns:
            list: Lista de nombres de permisos
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return []

        if user.is_admin:
            return ["*"]  # SuperAdmin tiene todos los permisos

        permissions = set()
        for role in user.roles:
            if not role.is_active:
                continue
            for permission in role.permissions:
                if permission.is_active:
                    permissions.add(permission.name)

        return list(permissions)

    def get_user_roles(self, user_id: str) -> List[dict]:
        """
        Obtiene todos los roles de un usuario

        Args:
            user_id: ID del usuario

        Returns:
            list: Lista de roles (dicts)
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return []

        return [role.to_dict() for role in user.roles if role.is_active]

    def create_custom_role(self, organization_id: str, name: str, display_name: str,
                          description: str, permission_ids: List[str],
                          created_by: str = None) -> Optional[Role]:
        """
        Crea un rol personalizado para una organización

        Args:
            organization_id: ID de la organización
            name: Nombre del rol (único en la org)
            display_name: Nombre para mostrar
            description: Descripción del rol
            permission_ids: Lista de IDs de permisos
            created_by: ID del usuario creador

        Returns:
            Role: Rol creado o None si falla
        """
        # Verificar que no exista
        existing = self.db.query(Role).filter_by(
            organization_id=organization_id,
            name=name
        ).first()

        if existing:
            return None

        # Crear rol
        role = Role(
            organization_id=organization_id,
            name=name,
            display_name=display_name,
            description=description,
            is_custom=True,
            is_system=False,
            is_active=True,
            created_by=created_by
        )

        # Asignar permisos
        for perm_id in permission_ids:
            permission = self.db.query(Permission).filter_by(id=perm_id).first()
            if permission and permission.is_active:
                role.permissions.append(permission)

        self.db.add(role)

        # Log
        AuditLog.log_action(
            self.db,
            action="role.create",
            user_id=created_by,
            organization_id=organization_id,
            resource_type="role",
            resource_id=role.id,
            resource_name=role.name,
            status="success",
            severity="info",
            metadata={
                "is_custom": True,
                "permissions_count": len(role.permissions)
            }
        )

        self.db.commit()
        return role

    def update_role_permissions(self, role_id: str, permission_ids: List[str],
                               updated_by: str = None) -> bool:
        """
        Actualiza los permisos de un rol

        Args:
            role_id: ID del rol
            permission_ids: Lista de IDs de permisos
            updated_by: ID del usuario que actualiza

        Returns:
            bool: True si se actualizó exitosamente
        """
        role = self.db.query(Role).filter_by(id=role_id).first()
        if not role:
            return False

        # No permitir modificar roles del sistema
        if role.is_system and not role.is_custom:
            return False

        # Limpiar permisos actuales
        role.permissions.clear()

        # Asignar nuevos permisos
        for perm_id in permission_ids:
            permission = self.db.query(Permission).filter_by(id=perm_id).first()
            if permission and permission.is_active:
                role.permissions.append(permission)

        # Log
        AuditLog.log_action(
            self.db,
            action="role.update",
            user_id=updated_by,
            organization_id=role.organization_id,
            resource_type="role",
            resource_id=role.id,
            resource_name=role.name,
            status="success",
            severity="info",
            metadata={
                "permissions_count": len(role.permissions)
            }
        )

        self.db.commit()
        return True

    def delete_custom_role(self, role_id: str, deleted_by: str = None) -> bool:
        """
        Elimina un rol personalizado

        Args:
            role_id: ID del rol
            deleted_by: ID del usuario que elimina

        Returns:
            bool: True si se eliminó exitosamente
        """
        role = self.db.query(Role).filter_by(id=role_id).first()
        if not role:
            return False

        # Solo permitir eliminar roles personalizados
        if not role.is_custom or role.is_system:
            return False

        # Log
        AuditLog.log_action(
            self.db,
            action="role.delete",
            user_id=deleted_by,
            organization_id=role.organization_id,
            resource_type="role",
            resource_id=role.id,
            resource_name=role.name,
            status="success",
            severity="info"
        )

        self.db.delete(role)
        self.db.commit()
        return True

    def get_available_permissions(self, category: str = None) -> List[dict]:
        """
        Obtiene los permisos disponibles

        Args:
            category: Categoría de permisos (opcional)

        Returns:
            list: Lista de permisos
        """
        query = self.db.query(Permission).filter_by(is_active=True)

        if category:
            query = query.filter_by(category=category)

        return [perm.to_dict() for perm in query.all()]

    def check_organization_access(self, user_id: str, organization_id: str) -> bool:
        """
        Verifica si un usuario tiene acceso a una organización

        Args:
            user_id: ID del usuario
            organization_id: ID de la organización

        Returns:
            bool: True si tiene acceso
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        # SuperAdmin tiene acceso a todo
        if user.is_admin:
            return True

        # Usuario debe pertenecer a la organización
        return user.organization_id == organization_id

    def check_department_access(self, user_id: str, department_id: str) -> bool:
        """
        Verifica si un usuario tiene acceso a un departamento

        Args:
            user_id: ID del usuario
            department_id: ID del departamento

        Returns:
            bool: True si tiene acceso
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        # SuperAdmin o OrgAdmin tienen acceso a todos los departamentos de su org
        if user.is_admin or user.has_role("OrgAdmin"):
            return True

        # Usuario debe pertenecer al departamento
        return user.department_id == department_id

    def get_roles_by_organization(self, organization_id: str, include_system: bool = True) -> List[dict]:
        """
        Obtiene los roles de una organización

        Args:
            organization_id: ID de la organización
            include_system: Incluir roles del sistema

        Returns:
            list: Lista de roles
        """
        query = self.db.query(Role).filter_by(
            organization_id=organization_id,
            is_active=True
        )

        if not include_system:
            query = query.filter_by(is_system=False)

        return [role.to_dict(include_permissions=True) for role in query.all()]
