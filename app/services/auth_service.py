#!/usr/bin/env python3
"""
auth_service.py - Authentication Service for File Secure v3.2
Handles user authentication, JWT tokens, and session management
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from jwt.exceptions import InvalidTokenError

from app.models import User, AuditLog
from app.core.config import get_config_manager


class AuthenticationService:
    """
    Servicio de autenticación con JWT
    """

    def __init__(self, db_session):
        """
        Inicializa el servicio de autenticación

        Args:
            db_session: Sesión de base de datos SQLAlchemy
        """
        self.db = db_session
        self.config = get_config_manager().config

    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Optional[Dict[str, Any]]:
        """
        Autentica un usuario con username y password

        Args:
            username: Nombre de usuario
            password: Contraseña
            ip_address: IP del cliente (opcional)

        Returns:
            dict: Datos del usuario y token JWT si es exitoso, None si falla
        """
        # Buscar usuario
        user = self.db.query(User).filter_by(username=username).first()

        if not user:
            # Log failed attempt
            AuditLog.log_action(
                self.db,
                action="auth.failed_login",
                status="failure",
                severity="warning",
                ip_address=ip_address,
                metadata={"username": username, "reason": "user_not_found"}
            )
            return None

        # Verificar si está bloqueado
        if user.is_locked:
            if user.locked_until and datetime.utcnow() < user.locked_until:
                # Aún está bloqueado
                AuditLog.log_action(
                    self.db,
                    action="auth.failed_login",
                    user_id=user.id,
                    organization_id=user.organization_id,
                    status="failure",
                    severity="warning",
                    ip_address=ip_address,
                    metadata={"reason": "account_locked"}
                )
                return None
            else:
                # Desbloquear automáticamente
                user.is_locked = False
                user.locked_until = None
                user.failed_login_attempts = 0

        # Verificar si está activo
        if not user.is_active:
            AuditLog.log_action(
                self.db,
                action="auth.failed_login",
                user_id=user.id,
                organization_id=user.organization_id,
                status="failure",
                severity="warning",
                ip_address=ip_address,
                metadata={"reason": "account_inactive"}
            )
            return None

        # Verificar contraseña
        if not user.check_password(password):
            # Incrementar intentos fallidos
            user.failed_login_attempts += 1

            # Bloquear si supera el máximo
            max_attempts = self.config.security.max_failed_attempts
            if user.failed_login_attempts >= max_attempts:
                user.is_locked = True
                lockout_duration = timedelta(minutes=self.config.security.lockout_duration_minutes)
                user.locked_until = datetime.utcnow() + lockout_duration

                AuditLog.log_action(
                    self.db,
                    action="auth.failed_login",
                    user_id=user.id,
                    organization_id=user.organization_id,
                    status="failure",
                    severity="error",
                    ip_address=ip_address,
                    metadata={
                        "reason": "invalid_password",
                        "failed_attempts": user.failed_login_attempts,
                        "account_locked": True
                    }
                )
            else:
                AuditLog.log_action(
                    self.db,
                    action="auth.failed_login",
                    user_id=user.id,
                    organization_id=user.organization_id,
                    status="failure",
                    severity="warning",
                    ip_address=ip_address,
                    metadata={
                        "reason": "invalid_password",
                        "failed_attempts": user.failed_login_attempts
                    }
                )

            self.db.commit()
            return None

        # Autenticación exitosa
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        self.db.commit()

        # Generar token JWT
        token = self.generate_token(user)

        # Log successful login
        AuditLog.log_action(
            self.db,
            action="auth.login",
            user_id=user.id,
            organization_id=user.organization_id,
            status="success",
            severity="info",
            ip_address=ip_address,
            metadata={"login_time": datetime.utcnow().isoformat()}
        )

        return {
            'user': user.to_dict(),
            'token': token,
            'expires_in': self.config.security.jwt_expiration_minutes * 60  # seconds
        }

    def generate_token(self, user: User) -> str:
        """
        Genera un token JWT para el usuario

        Args:
            user: Usuario

        Returns:
            str: Token JWT
        """
        expiration = datetime.utcnow() + timedelta(minutes=self.config.security.jwt_expiration_minutes)

        payload = {
            'user_id': user.id,
            'username': user.username,
            'organization_id': user.organization_id,
            'department_id': user.department_id,
            'is_admin': user.is_admin,
            'roles': [role.name for role in user.roles],
            'exp': expiration,
            'iat': datetime.utcnow()
        }

        token = jwt.encode(
            payload,
            self.config.security.secret_key,
            algorithm=self.config.security.jwt_algorithm
        )

        return token

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifica y decodifica un token JWT

        Args:
            token: Token JWT

        Returns:
            dict: Payload del token si es válido, None si no
        """
        try:
            payload = jwt.decode(
                token,
                self.config.security.secret_key,
                algorithms=[self.config.security.jwt_algorithm]
            )
            return payload
        except InvalidTokenError:
            return None

    def logout_user(self, user_id: str, ip_address: str = None):
        """
        Registra el logout de un usuario

        Args:
            user_id: ID del usuario
            ip_address: IP del cliente
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if user:
            AuditLog.log_action(
                self.db,
                action="auth.logout",
                user_id=user.id,
                organization_id=user.organization_id,
                status="success",
                severity="info",
                ip_address=ip_address,
                metadata={"logout_time": datetime.utcnow().isoformat()}
            )
            self.db.commit()

    def change_password(self, user_id: str, old_password: str, new_password: str, ip_address: str = None) -> bool:
        """
        Cambia la contraseña de un usuario

        Args:
            user_id: ID del usuario
            old_password: Contraseña actual
            new_password: Nueva contraseña
            ip_address: IP del cliente

        Returns:
            bool: True si se cambió exitosamente
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        # Verificar contraseña actual
        if not user.check_password(old_password):
            AuditLog.log_action(
                self.db,
                action="auth.password_change",
                user_id=user.id,
                organization_id=user.organization_id,
                status="failure",
                severity="warning",
                ip_address=ip_address,
                metadata={"reason": "invalid_old_password"}
            )
            self.db.commit()
            return False

        # Establecer nueva contraseña
        user.set_password(new_password)
        user.password_must_change = False

        AuditLog.log_action(
            self.db,
            action="auth.password_change",
            user_id=user.id,
            organization_id=user.organization_id,
            status="success",
            severity="info",
            ip_address=ip_address
        )

        self.db.commit()
        return True

    def reset_password(self, username: str, new_password: str, admin_user_id: str = None) -> bool:
        """
        Resetea la contraseña de un usuario (admin only)

        Args:
            username: Nombre de usuario
            new_password: Nueva contraseña
            admin_user_id: ID del admin que hace el reset

        Returns:
            bool: True si se reseteó exitosamente
        """
        user = self.db.query(User).filter_by(username=username).first()
        if not user:
            return False

        user.set_password(new_password)
        user.password_must_change = True  # Forzar cambio en siguiente login
        user.failed_login_attempts = 0
        user.is_locked = False
        user.locked_until = None

        AuditLog.log_action(
            self.db,
            action="auth.password_reset",
            user_id=user.id,
            organization_id=user.organization_id,
            status="success",
            severity="info",
            metadata={
                "reset_by": admin_user_id,
                "must_change": True
            }
        )

        self.db.commit()
        return True

    def unlock_user(self, user_id: str, admin_user_id: str = None) -> bool:
        """
        Desbloquea un usuario bloqueado

        Args:
            user_id: ID del usuario a desbloquear
            admin_user_id: ID del admin que desbloquea

        Returns:
            bool: True si se desbloqueó exitosamente
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return False

        user.is_locked = False
        user.locked_until = None
        user.failed_login_attempts = 0

        AuditLog.log_action(
            self.db,
            action="user.unlock",
            user_id=user.id,
            organization_id=user.organization_id,
            status="success",
            severity="info",
            metadata={"unlocked_by": admin_user_id}
        )

        self.db.commit()
        return True

    def get_user_by_token(self, token: str) -> Optional[User]:
        """
        Obtiene el usuario a partir de un token JWT

        Args:
            token: Token JWT

        Returns:
            User: Usuario si el token es válido, None si no
        """
        payload = self.verify_token(token)
        if not payload:
            return None

        user = self.db.query(User).filter_by(id=payload['user_id']).first()
        return user if user and user.is_active else None
