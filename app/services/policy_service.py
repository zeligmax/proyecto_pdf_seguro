#!/usr/bin/env python3
"""
policy_service.py - Policy Service for File Secure v3.2
Manages security policies
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

from app.models import Policy, Organization, AuditLog


class PolicyService:
    """
    Servicio de gestión de políticas de seguridad
    """

    def __init__(self, db_session: Session):
        """
        Inicializa el servicio de políticas

        Args:
            db_session: Sesión de base de datos SQLAlchemy
        """
        self.db = db_session

    def create_policy(self, organization_id: str, name: str, display_name: str,
                     policy_type: str, config: Dict[str, Any], description: str = None,
                     department_id: str = None, priority: int = 0, is_default: bool = False,
                     created_by: str = None) -> Optional[Policy]:
        """
        Crea una nueva política

        Args:
            organization_id: ID de la organización
            name: Nombre de la política
            display_name: Nombre para mostrar
            policy_type: Tipo de política (password, session, file, etc.)
            config: Configuración de la política (dict)
            description: Descripción
            department_id: ID del departamento (opcional)
            priority: Prioridad de la política
            is_default: Si es la política por defecto
            created_by: ID del usuario creador

        Returns:
            Policy: Política creada o None si falla
        """
        # Verificar que la organización exista
        org = self.db.query(Organization).filter_by(id=organization_id).first()
        if not org:
            return None

        # Verificar que no exista otra con el mismo nombre
        existing = self.db.query(Policy).filter_by(
            organization_id=organization_id,
            name=name
        ).first()
        if existing:
            return None

        policy = Policy(
            organization_id=organization_id,
            department_id=department_id,
            name=name,
            display_name=display_name,
            description=description,
            policy_type=policy_type,
            priority=priority,
            is_default=is_default,
            is_active=True,
            created_by=created_by
        )
        policy.set_config(config)

        self.db.add(policy)

        # Log
        AuditLog.log_action(
            self.db,
            action="policy.create",
            user_id=created_by,
            organization_id=organization_id,
            department_id=department_id,
            resource_type="policy",
            resource_id=policy.id,
            resource_name=policy.name,
            status="success",
            severity="info",
            metadata={
                "policy_type": policy_type,
                "is_default": is_default
            }
        )

        self.db.commit()
        return policy

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """
        Obtiene una política por ID

        Args:
            policy_id: ID de la política

        Returns:
            Policy: Política o None
        """
        return self.db.query(Policy).filter_by(id=policy_id).first()

    def get_policy_by_name(self, organization_id: str, name: str) -> Optional[Policy]:
        """
        Obtiene una política por nombre

        Args:
            organization_id: ID de la organización
            name: Nombre de la política

        Returns:
            Policy: Política o None
        """
        return self.db.query(Policy).filter_by(
            organization_id=organization_id,
            name=name
        ).first()

    def list_policies(self, organization_id: str, policy_type: str = None,
                     active_only: bool = True, department_id: str = None) -> List[dict]:
        """
        Lista las políticas de una organización

        Args:
            organization_id: ID de la organización
            policy_type: Tipo de política (opcional)
            active_only: Solo políticas activas
            department_id: Filtrar por departamento (opcional)

        Returns:
            list: Lista de políticas
        """
        query = self.db.query(Policy).filter_by(organization_id=organization_id)

        if policy_type:
            query = query.filter_by(policy_type=policy_type)

        if active_only:
            query = query.filter_by(is_active=True)

        if department_id:
            query = query.filter_by(department_id=department_id)

        # Ordenar por prioridad
        query = query.order_by(Policy.priority.desc())

        return [policy.to_dict() for policy in query.all()]

    def update_policy(self, policy_id: str, display_name: str = None, description: str = None,
                     config: Dict[str, Any] = None, priority: int = None, is_active: bool = None,
                     updated_by: str = None) -> bool:
        """
        Actualiza una política

        Args:
            policy_id: ID de la política
            display_name: Nuevo nombre para mostrar
            description: Nueva descripción
            config: Nueva configuración
            priority: Nueva prioridad
            is_active: Nuevo estado
            updated_by: ID del usuario que actualiza

        Returns:
            bool: True si se actualizó exitosamente
        """
        policy = self.db.query(Policy).filter_by(id=policy_id).first()
        if not policy:
            return False

        changes = {}
        if display_name is not None:
            changes['display_name'] = display_name
            policy.display_name = display_name
        if description is not None:
            changes['description'] = description
            policy.description = description
        if config is not None:
            changes['config'] = config
            policy.set_config(config)
        if priority is not None:
            changes['priority'] = priority
            policy.priority = priority
        if is_active is not None:
            changes['is_active'] = is_active
            policy.is_active = is_active

        # Log
        AuditLog.log_action(
            self.db,
            action="policy.update",
            user_id=updated_by,
            organization_id=policy.organization_id,
            resource_type="policy",
            resource_id=policy.id,
            resource_name=policy.name,
            status="success",
            severity="info",
            metadata=changes
        )

        self.db.commit()
        return True

    def delete_policy(self, policy_id: str, deleted_by: str = None) -> bool:
        """
        Elimina una política

        Args:
            policy_id: ID de la política
            deleted_by: ID del usuario que elimina

        Returns:
            bool: True si se eliminó exitosamente
        """
        policy = self.db.query(Policy).filter_by(id=policy_id).first()
        if not policy:
            return False

        # Log
        AuditLog.log_action(
            self.db,
            action="policy.delete",
            user_id=deleted_by,
            organization_id=policy.organization_id,
            resource_type="policy",
            resource_id=policy.id,
            resource_name=policy.name,
            status="success",
            severity="warning"
        )

        self.db.delete(policy)
        self.db.commit()
        return True

    def get_effective_policy(self, organization_id: str, policy_type: str,
                            department_id: str = None) -> Optional[Policy]:
        """
        Obtiene la política efectiva para un contexto específico

        Resuelve conflictos usando prioridad:
        1. Política de departamento (si existe)
        2. Política de organización con mayor prioridad
        3. Política por defecto

        Args:
            organization_id: ID de la organización
            policy_type: Tipo de política
            department_id: ID del departamento (opcional)

        Returns:
            Policy: Política efectiva o None
        """
        # Buscar política de departamento si se especifica
        if department_id:
            dept_policy = self.db.query(Policy).filter_by(
                organization_id=organization_id,
                department_id=department_id,
                policy_type=policy_type,
                is_active=True
            ).order_by(Policy.priority.desc()).first()

            if dept_policy and dept_policy.is_effective():
                return dept_policy

        # Buscar política de organización
        org_policy = self.db.query(Policy).filter_by(
            organization_id=organization_id,
            department_id=None,  # Solo org-level
            policy_type=policy_type,
            is_active=True
        ).order_by(Policy.priority.desc()).first()

        if org_policy and org_policy.is_effective():
            return org_policy

        return None

    def get_policy_config(self, organization_id: str, policy_type: str,
                         department_id: str = None) -> Dict[str, Any]:
        """
        Obtiene la configuración efectiva de una política

        Args:
            organization_id: ID de la organización
            policy_type: Tipo de política
            department_id: ID del departamento (opcional)

        Returns:
            dict: Configuración de la política
        """
        policy = self.get_effective_policy(organization_id, policy_type, department_id)
        if policy:
            return policy.get_config()
        return {}

    def validate_against_policy(self, organization_id: str, policy_type: str,
                               data: Dict[str, Any], department_id: str = None) -> tuple:
        """
        Valida datos contra una política

        Args:
            organization_id: ID de la organización
            policy_type: Tipo de política
            data: Datos a validar
            department_id: ID del departamento (opcional)

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        policy_config = self.get_policy_config(organization_id, policy_type, department_id)
        if not policy_config:
            return True, []  # Sin política, todo válido

        errors = []

        # Validación según tipo de política
        if policy_type == "password_policy":
            errors.extend(self._validate_password_policy(data, policy_config))
        elif policy_type == "file_policy":
            errors.extend(self._validate_file_policy(data, policy_config))
        elif policy_type == "session_policy":
            errors.extend(self._validate_session_policy(data, policy_config))
        elif policy_type == "access_policy":
            errors.extend(self._validate_access_policy(data, policy_config))

        return len(errors) == 0, errors

    def _validate_password_policy(self, data: dict, config: dict) -> list:
        """Valida contraseña contra política"""
        errors = []
        password = data.get('password', '')

        if len(password) < config.get('min_length', 12):
            errors.append(f"Password must be at least {config.get('min_length')} characters")

        if config.get('require_uppercase', True) and not any(c.isupper() for c in password):
            errors.append("Password must contain uppercase letters")

        if config.get('require_lowercase', True) and not any(c.islower() for c in password):
            errors.append("Password must contain lowercase letters")

        if config.get('require_numbers', True) and not any(c.isdigit() for c in password):
            errors.append("Password must contain numbers")

        if config.get('require_special', True):
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain special characters")

        return errors

    def _validate_file_policy(self, data: dict, config: dict) -> list:
        """Valida archivo contra política"""
        errors = []

        file_size_mb = data.get('file_size_mb', 0)
        max_size = config.get('max_file_size_mb', 100)
        if file_size_mb > max_size:
            errors.append(f"File size exceeds maximum of {max_size}MB")

        file_extension = data.get('file_extension', '').lower()
        allowed_extensions = config.get('allowed_extensions', [])
        if allowed_extensions and file_extension not in allowed_extensions:
            errors.append(f"File type {file_extension} is not allowed")

        return errors

    def _validate_session_policy(self, data: dict, config: dict) -> list:
        """Valida sesión contra política"""
        errors = []
        # Implementar validaciones de sesión según necesidad
        return errors

    def _validate_access_policy(self, data: dict, config: dict) -> list:
        """Valida acceso contra política"""
        errors = []

        # Validar IP whitelist si es requerido
        if config.get('require_ip_whitelist', False):
            ip = data.get('ip_address')
            # Aquí iría la lógica de validación de IP
            pass

        return errors

    def activate_policy(self, policy_id: str, activated_by: str = None) -> bool:
        """Activa una política"""
        return self.update_policy(policy_id, is_active=True, updated_by=activated_by)

    def deactivate_policy(self, policy_id: str, deactivated_by: str = None) -> bool:
        """Desactiva una política"""
        return self.update_policy(policy_id, is_active=False, updated_by=deactivated_by)
