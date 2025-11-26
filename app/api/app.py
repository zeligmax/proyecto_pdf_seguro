#!/usr/bin/env python3
"""
app.py - Main Flask API Application for File Secure v3.2
REST API with JWT authentication
"""

from flask import Flask, jsonify
from flask_cors import CORS

from app.core.database import init_db
from app.core.config import get_config_manager

# Import blueprints
from app.api.v1 import auth


def create_app(config_file=None):
    """
    Factory function to create Flask app

    Args:
        config_file: Path to configuration file (optional)

    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__)

    # Load configuration
    config_manager = get_config_manager(config_file)
    app.config['SECRET_KEY'] = config_manager.config.security.secret_key
    app.config['JSON_SORT_KEYS'] = False

    # Enable CORS
    CORS(app)

    # Initialize database
    init_db(config_manager.config.database.url)

    # Register blueprints
    app.register_blueprint(auth.bp)

    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint"""
        from app.core.database import get_db_manager

        db_health = get_db_manager().health_check()

        return jsonify({
            'status': 'healthy',
            'version': '3.2',
            'database': db_health
        }), 200

    # API info endpoint
    @app.route('/api/v1', methods=['GET'])
    def api_info():
        """API information endpoint"""
        return jsonify({
            'name': 'File Secure API',
            'version': '3.2',
            'description': 'Enterprise file encryption and management API',
            'endpoints': {
                'auth': {
                    'POST /api/v1/auth/login': 'Authenticate user',
                    'POST /api/v1/auth/logout': 'Logout user',
                    'GET /api/v1/auth/me': 'Get current user',
                    'POST /api/v1/auth/change-password': 'Change password',
                    'POST /api/v1/auth/reset-password': 'Reset user password (admin)',
                    'POST /api/v1/auth/unlock-user': 'Unlock user account (admin)',
                    'GET /api/v1/auth/verify-token': 'Verify JWT token'
                }
            },
            'documentation': '/api/v1/docs'
        }), 200

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Permission denied'}), 403

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Authentication required'}), 401

    return app


# For development
if __name__ == '__main__':
    app = create_app()
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
