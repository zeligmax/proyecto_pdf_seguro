#!/usr/bin/env python3
"""
auth.py - Authentication Middleware for File Secure v3.2
JWT token validation and user context
"""

from functools import wraps
from flask import request, jsonify, g
from typing import Optional, Callable

from app.core.database import get_db_manager
from app.services import AuthenticationService


def get_token_from_header() -> Optional[str]:
    """
    Extrae el token JWT del header Authorization

    Returns:
        str: Token o None
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None

    # Formato: "Bearer <token>"
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    return parts[1]


def require_auth(f: Callable) -> Callable:
    """
    Decorator que requiere autenticación JWT

    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            user = g.current_user
            return {'message': f'Hello {user.username}'}
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_header()

        if not token:
            return jsonify({'error': 'No token provided'}), 401

        # Obtener sesión de BD
        db_manager = get_db_manager()
        db = next(db_manager.get_db())

        try:
            auth_service = AuthenticationService(db)

            # Verificar token
            user = auth_service.get_user_by_token(token)
            if not user:
                return jsonify({'error': 'Invalid or expired token'}), 401

            # Guardar usuario en contexto de Flask
            g.current_user = user
            g.db = db

            # Ejecutar función decorada
            return f(*args, **kwargs)

        finally:
            db.close()

    return decorated_function


def require_permission(permission_name: str) -> Callable:
    """
    Decorator que requiere un permiso específico

    Args:
        permission_name: Nombre del permiso requerido

    Usage:
        @app.route('/admin/users')
        @require_auth
        @require_permission('user.create')
        def create_user():
            return {'message': 'User created'}
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # require_auth debe ejecutarse primero
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401

            user = g.current_user

            # Verificar permiso
            if not user.has_permission(permission_name):
                return jsonify({
                    'error': 'Permission denied',
                    'required_permission': permission_name
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def require_role(role_name: str) -> Callable:
    """
    Decorator que requiere un rol específico

    Args:
        role_name: Nombre del rol requerido

    Usage:
        @app.route('/admin/settings')
        @require_auth
        @require_role('OrgAdmin')
        def admin_settings():
            return {'message': 'Admin settings'}
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # require_auth debe ejecutarse primero
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401

            user = g.current_user

            # Verificar rol
            if not user.has_role(role_name) and not user.is_admin:
                return jsonify({
                    'error': 'Role required',
                    'required_role': role_name
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def optional_auth(f: Callable) -> Callable:
    """
    Decorator que permite autenticación opcional

    Si hay token válido, se añade el usuario a g.current_user
    Si no hay token o es inválido, continúa sin usuario

    Usage:
        @app.route('/public')
        @optional_auth
        def public_route():
            user = getattr(g, 'current_user', None)
            if user:
                return {'message': f'Hello {user.username}'}
            return {'message': 'Hello anonymous'}
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_header()

        if token:
            db_manager = get_db_manager()
            db = next(db_manager.get_db())

            try:
                auth_service = AuthenticationService(db)
                user = auth_service.get_user_by_token(token)

                if user:
                    g.current_user = user
                    g.db = db

            except Exception:
                # Ignorar errores en auth opcional
                pass

        return f(*args, **kwargs)

    return decorated_function
