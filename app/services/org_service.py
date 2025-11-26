#!/usr/bin/env python3
"""
org_service.py - Organization Service for File Secure v3.2
Manages organizations and departments
"""

from typing import List, Optional
from sqlalchemy.orm import Session

from app.models import Organization, Department, User, AuditLog


class OrganizationService:
    """
    Servicio de gestión de organizaciones y departamentos
    """

    def __init__(self, db_session: Session):
        """
        Inicializa el servicio de organizaciones

        Args:
            db_session: Sesión de base de datos SQLAlchemy
        """
        self.db = db_session

    # ==================== ORGANIZACIONES ====================

    def create_organization(self, name: str, display_name: str, description: str = None,
                           created_by: str = None) -> Optional[Organization]:
        """
        Crea una nueva organización

        Args:
            name: Nombre único de la organización
            display_name: Nombre para mostrar
            description: Descripción
            created_by: ID del usuario creador

        Returns:
            Organization: Organización creada o None si falla
        """
        # Verificar que no exista
        existing = self.db.query(Organization).filter_by(name=name).first()
        if existing:
            return None

        org = Organization(
            name=name,
            display_name=display_name,
            description=description,
            is_active=True,
            created_by=created_by
        )

        self.db.add(org)

        # Log
        AuditLog.log_action(
            self.db,
            action="org.create",
            user_id=created_by,
            resource_type="organization",
            resource_id=org.id,
            resource_name=org.name,
            status="success",
            severity="info"
        )

        self.db.commit()
        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        """
        Obtiene una organización por ID

        Args:
            org_id: ID de la organización

        Returns:
            Organization: Organización o None
        """
        return self.db.query(Organization).filter_by(id=org_id).first()

    def get_organization_by_name(self, name: str) -> Optional[Organization]:
        """
        Obtiene una organización por nombre

        Args:
            name: Nombre de la organización

        Returns:
            Organization: Organización o None
        """
        return self.db.query(Organization).filter_by(name=name).first()

    def list_organizations(self, active_only: bool = True) -> List[dict]:
        """
        Lista todas las organizaciones

        Args:
            active_only: Solo organizaciones activas

        Returns:
            list: Lista de organizaciones
        """
        query = self.db.query(Organization)
        if active_only:
            query = query.filter_by(is_active=True)

        return [org.to_dict() for org in query.all()]

    def update_organization(self, org_id: str, display_name: str = None, description: str = None,
                          is_active: bool = None, updated_by: str = None) -> bool:
        """
        Actualiza una organización

        Args:
            org_id: ID de la organización
            display_name: Nuevo nombre para mostrar
            description: Nueva descripción
            is_active: Nuevo estado
            updated_by: ID del usuario que actualiza

        Returns:
            bool: True si se actualizó exitosamente
        """
        org = self.db.query(Organization).filter_by(id=org_id).first()
        if not org:
            return False

        changes = {}
        if display_name is not None:
            changes['display_name'] = display_name
            org.display_name = display_name
        if description is not None:
            changes['description'] = description
            org.description = description
        if is_active is not None:
            changes['is_active'] = is_active
            org.is_active = is_active

        # Log
        AuditLog.log_action(
            self.db,
            action="org.update",
            user_id=updated_by,
            resource_type="organization",
            resource_id=org.id,
            resource_name=org.name,
            status="success",
            severity="info",
            metadata=changes
        )

        self.db.commit()
        return True

    def delete_organization(self, org_id: str, deleted_by: str = None) -> bool:
        """
        Elimina una organización (y todos sus datos asociados)

        Args:
            org_id: ID de la organización
            deleted_by: ID del usuario que elimina

        Returns:
            bool: True si se eliminó exitosamente
        """
        org = self.db.query(Organization).filter_by(id=org_id).first()
        if not org:
            return False

        # Log antes de eliminar
        AuditLog.log_action(
            self.db,
            action="org.delete",
            user_id=deleted_by,
            resource_type="organization",
            resource_id=org.id,
            resource_name=org.name,
            status="success",
            severity="warning"
        )

        self.db.delete(org)
        self.db.commit()
        return True

    def get_organization_stats(self, org_id: str) -> dict:
        """
        Obtiene estadísticas de una organización

        Args:
            org_id: ID de la organización

        Returns:
            dict: Estadísticas
        """
        org = self.db.query(Organization).filter_by(id=org_id).first()
        if not org:
            return {}

        users_count = self.db.query(User).filter_by(organization_id=org_id, is_active=True).count()
        departments_count = self.db.query(Department).filter_by(organization_id=org_id, is_active=True).count()

        return {
            'id': org.id,
            'name': org.name,
            'display_name': org.display_name,
            'users_count': users_count,
            'departments_count': departments_count,
            'created_at': org.created_at.isoformat() if org.created_at else None
        }

    # ==================== DEPARTAMENTOS ====================

    def create_department(self, organization_id: str, name: str, display_name: str,
                         description: str = None, parent_id: str = None,
                         created_by: str = None) -> Optional[Department]:
        """
        Crea un nuevo departamento

        Args:
            organization_id: ID de la organización
            name: Nombre del departamento
            display_name: Nombre para mostrar
            description: Descripción
            parent_id: ID del departamento padre (opcional)
            created_by: ID del usuario creador

        Returns:
            Department: Departamento creado o None si falla
        """
        # Verificar que la organización exista
        org = self.db.query(Organization).filter_by(id=organization_id).first()
        if not org:
            return None

        # Verificar que no exista un departamento con el mismo nombre en la org
        existing = self.db.query(Department).filter_by(
            organization_id=organization_id,
            name=name
        ).first()
        if existing:
            return None

        dept = Department(
            organization_id=organization_id,
            name=name,
            display_name=display_name,
            description=description,
            parent_id=parent_id,
            is_active=True
        )

        self.db.add(dept)

        # Log
        AuditLog.log_action(
            self.db,
            action="dept.create",
            user_id=created_by,
            organization_id=organization_id,
            resource_type="department",
            resource_id=dept.id,
            resource_name=dept.name,
            status="success",
            severity="info"
        )

        self.db.commit()
        return dept

    def get_department(self, dept_id: str) -> Optional[Department]:
        """
        Obtiene un departamento por ID

        Args:
            dept_id: ID del departamento

        Returns:
            Department: Departamento o None
        """
        return self.db.query(Department).filter_by(id=dept_id).first()

    def list_departments(self, organization_id: str, active_only: bool = True) -> List[dict]:
        """
        Lista los departamentos de una organización

        Args:
            organization_id: ID de la organización
            active_only: Solo departamentos activos

        Returns:
            list: Lista de departamentos
        """
        query = self.db.query(Department).filter_by(organization_id=organization_id)
        if active_only:
            query = query.filter_by(is_active=True)

        return [dept.to_dict() for dept in query.all()]

    def update_department(self, dept_id: str, display_name: str = None, description: str = None,
                         parent_id: str = None, is_active: bool = None,
                         updated_by: str = None) -> bool:
        """
        Actualiza un departamento

        Args:
            dept_id: ID del departamento
            display_name: Nuevo nombre para mostrar
            description: Nueva descripción
            parent_id: Nuevo ID del padre
            is_active: Nuevo estado
            updated_by: ID del usuario que actualiza

        Returns:
            bool: True si se actualizó exitosamente
        """
        dept = self.db.query(Department).filter_by(id=dept_id).first()
        if not dept:
            return False

        changes = {}
        if display_name is not None:
            changes['display_name'] = display_name
            dept.display_name = display_name
        if description is not None:
            changes['description'] = description
            dept.description = description
        if parent_id is not None:
            changes['parent_id'] = parent_id
            dept.parent_id = parent_id
        if is_active is not None:
            changes['is_active'] = is_active
            dept.is_active = is_active

        # Log
        AuditLog.log_action(
            self.db,
            action="dept.update",
            user_id=updated_by,
            organization_id=dept.organization_id,
            resource_type="department",
            resource_id=dept.id,
            resource_name=dept.name,
            status="success",
            severity="info",
            metadata=changes
        )

        self.db.commit()
        return True

    def delete_department(self, dept_id: str, deleted_by: str = None) -> bool:
        """
        Elimina un departamento

        Args:
            dept_id: ID del departamento
            deleted_by: ID del usuario que elimina

        Returns:
            bool: True si se eliminó exitosamente
        """
        dept = self.db.query(Department).filter_by(id=dept_id).first()
        if not dept:
            return False

        # Log
        AuditLog.log_action(
            self.db,
            action="dept.delete",
            user_id=deleted_by,
            organization_id=dept.organization_id,
            resource_type="department",
            resource_id=dept.id,
            resource_name=dept.name,
            status="success",
            severity="warning"
        )

        self.db.delete(dept)
        self.db.commit()
        return True

    def get_department_tree(self, organization_id: str) -> List[dict]:
        """
        Obtiene el árbol jerárquico de departamentos

        Args:
            organization_id: ID de la organización

        Returns:
            list: Árbol de departamentos
        """
        # Obtener todos los departamentos activos
        departments = self.db.query(Department).filter_by(
            organization_id=organization_id,
            is_active=True
        ).all()

        # Crear diccionario para acceso rápido
        dept_dict = {dept.id: dept.to_dict() for dept in departments}

        # Construir árbol
        tree = []
        for dept in departments:
            if dept.parent_id is None:
                # Es un departamento raíz
                dept_data = dept_dict[dept.id]
                dept_data['children'] = self._get_children(dept.id, dept_dict, departments)
                tree.append(dept_data)

        return tree

    def _get_children(self, parent_id: str, dept_dict: dict, all_departments: list) -> list:
        """Helper para construir árbol de departamentos recursivamente"""
        children = []
        for dept in all_departments:
            if dept.parent_id == parent_id:
                dept_data = dept_dict[dept.id]
                dept_data['children'] = self._get_children(dept.id, dept_dict, all_departments)
                children.append(dept_data)
        return children

    def get_department_users_count(self, dept_id: str) -> int:
        """
        Obtiene el número de usuarios en un departamento

        Args:
            dept_id: ID del departamento

        Returns:
            int: Número de usuarios
        """
        return self.db.query(User).filter_by(
            department_id=dept_id,
            is_active=True
        ).count()
