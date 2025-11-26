#!/usr/bin/env python3
"""
auth.py - Authentication Endpoints for File Secure v3.2
Login, logout, password management
"""

from flask import Blueprint, request, jsonify, g
from app.core.database import get_db_manager
from app.services import AuthenticationService
from app.api.middleware.auth import require_auth

bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


@bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and generate JWT token

    Request Body:
        {
            "username": "user@example.com",
            "password": "password123"
        }

    Returns:
        {
            "user": {...},
            "token": "jwt_token",
            "expires_in": 3600
        }
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    # Get client IP
    ip_address = request.remote_addr

    # Authenticate
    db_manager = get_db_manager()
    db = next(db_manager.get_db())

    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(username, password, ip_address)

        if not result:
            return jsonify({'error': 'Invalid credentials'}), 401

        return jsonify(result), 200

    finally:
        db.close()


@bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """
    Logout current user

    Requires: JWT token in Authorization header

    Returns:
        {
            "message": "Logged out successfully"
        }
    """
    user = g.current_user
    ip_address = request.remote_addr

    auth_service = AuthenticationService(g.db)
    auth_service.logout_user(user.id, ip_address)

    return jsonify({'message': 'Logged out successfully'}), 200


@bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """
    Get current authenticated user

    Requires: JWT token in Authorization header

    Returns:
        {
            "user": {...}
        }
    """
    user = g.current_user
    return jsonify({'user': user.to_dict()}), 200


@bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """
    Change current user's password

    Request Body:
        {
            "old_password": "old123",
            "new_password": "new456"
        }

    Returns:
        {
            "message": "Password changed successfully"
        }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'error': 'Both old and new passwords required'}), 400

    user = g.current_user
    ip_address = request.remote_addr

    auth_service = AuthenticationService(g.db)
    success = auth_service.change_password(
        user.id,
        old_password,
        new_password,
        ip_address
    )

    if not success:
        return jsonify({'error': 'Invalid old password'}), 400

    return jsonify({'message': 'Password changed successfully'}), 200


@bp.route('/reset-password', methods=['POST'])
@require_auth
def reset_password():
    """
    Reset user password (admin only)

    Request Body:
        {
            "username": "user@example.com",
            "new_password": "temp123"
        }

    Returns:
        {
            "message": "Password reset successfully"
        }
    """
    user = g.current_user

    # Only admins can reset passwords
    if not user.has_permission('user.edit'):
        return jsonify({'error': 'Permission denied'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username')
    new_password = data.get('new_password')

    if not username or not new_password:
        return jsonify({'error': 'Username and new password required'}), 400

    auth_service = AuthenticationService(g.db)
    success = auth_service.reset_password(username, new_password, user.id)

    if not success:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'message': 'Password reset successfully',
        'note': 'User must change password on next login'
    }), 200


@bp.route('/unlock-user', methods=['POST'])
@require_auth
def unlock_user():
    """
    Unlock a locked user account (admin only)

    Request Body:
        {
            "user_id": "user_uuid"
        }

    Returns:
        {
            "message": "User unlocked successfully"
        }
    """
    user = g.current_user

    # Only admins can unlock users
    if not user.has_permission('user.edit'):
        return jsonify({'error': 'Permission denied'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400

    auth_service = AuthenticationService(g.db)
    success = auth_service.unlock_user(user_id, user.id)

    if not success:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'message': 'User unlocked successfully'}), 200


@bp.route('/verify-token', methods=['GET'])
def verify_token():
    """
    Verify if a JWT token is valid

    Requires: JWT token in Authorization header

    Returns:
        {
            "valid": true,
            "user_id": "uuid",
            "expires_at": "2024-01-01T00:00:00"
        }
    """
    from app.api.middleware.auth import get_token_from_header

    token = get_token_from_header()
    if not token:
        return jsonify({'valid': False, 'error': 'No token provided'}), 401

    db_manager = get_db_manager()
    db = next(db_manager.get_db())

    try:
        auth_service = AuthenticationService(db)
        payload = auth_service.verify_token(token)

        if not payload:
            return jsonify({'valid': False, 'error': 'Invalid token'}), 401

        return jsonify({
            'valid': True,
            'user_id': payload.get('user_id'),
            'username': payload.get('username'),
            'organization_id': payload.get('organization_id'),
            'roles': payload.get('roles', []),
            'expires_at': payload.get('exp')
        }), 200

    finally:
        db.close()
