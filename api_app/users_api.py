#!/usr/bin/env python3
"""
Users API - API REST para detección de usuarios del sistema
API web que expone información de usuarios del sistema operativo
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from system_users import SystemUsersDetector
from datetime import datetime
import json
from typing import Dict, List
import os


# Crear aplicación Flask
app = Flask(__name__)
CORS(app)  # Habilitar CORS para permitir requests desde otros dominios

# Crear instancia del detector
detector = SystemUsersDetector()

# Configuración
API_VERSION = "1.0.0"
API_TITLE = "System Users Detection API"


# ==================== RUTAS DE LA API ====================

@app.route('/')
def index():
    """Ruta raíz - Información de la API"""
    return jsonify({
        'api': API_TITLE,
        'version': API_VERSION,
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'endpoints': {
            'GET /': 'Información de la API',
            'GET /api/system': 'Información del sistema',
            'GET /api/users': 'Lista de todos los usuarios',
            'GET /api/users/current': 'Información del usuario actual',
            'GET /api/users/logged': 'Usuarios conectados actualmente',
            'GET /api/users/<username>': 'Información de un usuario específico',
            'GET /api/users/<username>/groups': 'Grupos de un usuario',
            'GET /api/report': 'Reporte completo del sistema',
            'GET /api/health': 'Estado de salud de la API'
        },
        'documentation': '/api/docs'
    })


@app.route('/api/docs')
def documentation():
    """Documentación de la API"""
    return jsonify({
        'title': API_TITLE,
        'version': API_VERSION,
        'description': 'API para detectar y listar usuarios del sistema operativo (Windows/Linux/macOS)',
        'base_url': request.host_url,
        'endpoints': [
            {
                'path': '/api/system',
                'method': 'GET',
                'description': 'Obtiene información general del sistema operativo',
                'response_example': {
                    'os': 'Windows',
                    'hostname': 'DESKTOP-ABC123',
                    'platform': 'Windows-10-10.0.19041-SP0'
                }
            },
            {
                'path': '/api/users',
                'method': 'GET',
                'description': 'Lista todos los usuarios del sistema',
                'query_params': {
                    'filter': 'human|system|all (default: all)',
                    'format': 'json|simple (default: json)'
                },
                'response_example': [
                    {
                        'username': 'user1',
                        'full_name': 'Usuario Uno',
                        'home_directory': '/home/user1'
                    }
                ]
            },
            {
                'path': '/api/users/current',
                'method': 'GET',
                'description': 'Obtiene información del usuario que ejecuta la API',
                'response_example': {
                    'username': 'current_user',
                    'home_directory': '/home/current_user',
                    'is_admin': False
                }
            },
            {
                'path': '/api/users/logged',
                'method': 'GET',
                'description': 'Lista usuarios actualmente conectados al sistema',
                'response_example': [
                    {
                        'username': 'user1',
                        'session_name': 'console',
                        'state': 'active'
                    }
                ]
            },
            {
                'path': '/api/users/<username>',
                'method': 'GET',
                'description': 'Obtiene información de un usuario específico',
                'response_example': {
                    'username': 'user1',
                    'exists': True,
                    'details': {}
                }
            },
            {
                'path': '/api/users/<username>/groups',
                'method': 'GET',
                'description': 'Lista los grupos a los que pertenece un usuario',
                'response_example': {
                    'username': 'user1',
                    'groups': ['sudo', 'users', 'docker']
                }
            },
            {
                'path': '/api/report',
                'method': 'GET',
                'description': 'Genera un reporte completo con toda la información',
                'response_example': {
                    'system_info': {},
                    'current_user': {},
                    'all_users': [],
                    'logged_in_users': []
                }
            },
            {
                'path': '/api/health',
                'method': 'GET',
                'description': 'Verifica el estado de salud de la API',
                'response_example': {
                    'status': 'healthy',
                    'uptime': '1h 30m',
                    'checks': {}
                }
            }
        ]
    })


@app.route('/api/system')
def get_system_info():
    """Obtiene información del sistema"""
    try:
        system_info = detector.get_system_info()
        return jsonify({
            'success': True,
            'data': system_info
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/users')
def get_all_users():
    """Obtiene lista de todos los usuarios"""
    try:
        all_users = detector.get_all_users()

        # Parámetro de filtro
        filter_type = request.args.get('filter', 'all').lower()
        format_type = request.args.get('format', 'json').lower()

        # Filtrar usuarios
        if filter_type == 'human':
            # Solo usuarios humanos (no del sistema)
            if detector.os_type == 'Linux':
                all_users = [u for u in all_users if not u.get('is_system_user', False)]
            elif detector.os_type == 'Darwin':  # macOS
                all_users = [u for u in all_users if not u.get('is_system_user', False)]
        elif filter_type == 'system':
            # Solo usuarios del sistema
            if detector.os_type == 'Linux':
                all_users = [u for u in all_users if u.get('is_system_user', False)]
            elif detector.os_type == 'Darwin':  # macOS
                all_users = [u for u in all_users if u.get('is_system_user', False)]

        # Formato de respuesta
        if format_type == 'simple':
            # Solo nombres de usuario
            usernames = [u.get('username') for u in all_users if 'username' in u]
            return jsonify({
                'success': True,
                'count': len(usernames),
                'users': usernames
            })
        else:
            # Respuesta completa
            return jsonify({
                'success': True,
                'count': len(all_users),
                'filter': filter_type,
                'data': all_users
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/users/current')
def get_current_user():
    """Obtiene información del usuario actual"""
    try:
        current_user = detector.get_current_user()
        return jsonify({
            'success': True,
            'data': current_user
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/users/logged')
def get_logged_users():
    """Obtiene usuarios actualmente conectados"""
    try:
        logged_users = detector.get_logged_in_users()
        return jsonify({
            'success': True,
            'count': len(logged_users),
            'data': logged_users
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/users/<username>')
def get_user_info(username):
    """Obtiene información de un usuario específico"""
    try:
        all_users = detector.get_all_users()

        # Buscar el usuario
        user_found = None
        for user in all_users:
            if user.get('username') == username:
                user_found = user
                break

        if user_found:
            return jsonify({
                'success': True,
                'exists': True,
                'data': user_found
            })
        else:
            return jsonify({
                'success': True,
                'exists': False,
                'message': f'Usuario "{username}" no encontrado'
            }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/users/<username>/groups')
def get_user_groups(username):
    """Obtiene los grupos de un usuario"""
    try:
        groups = detector.get_user_groups(username)
        return jsonify({
            'success': True,
            'username': username,
            'count': len(groups),
            'groups': groups
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/report')
def get_complete_report():
    """Genera un reporte completo"""
    try:
        report = detector.get_complete_report()
        return jsonify({
            'success': True,
            'generated_at': datetime.now().isoformat(),
            'data': report
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/health')
def health_check():
    """Verifica el estado de salud de la API"""
    try:
        # Verificar que el detector funciona
        sys_info = detector.get_system_info()

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': API_VERSION,
            'checks': {
                'detector': 'ok',
                'os_detection': sys_info.get('os', 'unknown'),
                'endpoints': 'available'
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


# ==================== MANEJO DE ERRORES ====================

@app.errorhandler(404)
def not_found(error):
    """Manejo de errores 404"""
    return jsonify({
        'success': False,
        'error': 'Endpoint no encontrado',
        'message': 'La ruta solicitada no existe',
        'available_endpoints': list(app.url_map.iter_rules())
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500"""
    return jsonify({
        'success': False,
        'error': 'Error interno del servidor',
        'message': str(error)
    }), 500


# ==================== EJECUCIÓN ====================

def run_api(host='0.0.0.0', port=5000, debug=False):
    """Ejecuta el servidor de la API"""
    print("=" * 60)
    print(f"🚀 {API_TITLE} v{API_VERSION}")
    print("=" * 60)
    print(f"📡 Servidor: http://{host}:{port}")
    print(f"📋 Documentación: http://{host}:{port}/api/docs")
    print(f"🔍 Sistema detectado: {detector.os_type}")
    print("=" * 60)
    print("\n💡 Endpoints disponibles:")
    print(f"  GET http://{host}:{port}/api/system")
    print(f"  GET http://{host}:{port}/api/users")
    print(f"  GET http://{host}:{port}/api/users/current")
    print(f"  GET http://{host}:{port}/api/users/logged")
    print(f"  GET http://{host}:{port}/api/report")
    print(f"  GET http://{host}:{port}/api/health")
    print("\n⏸️  Presiona Ctrl+C para detener el servidor\n")

    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='API de Detección de Usuarios del Sistema')
    parser.add_argument('--host', default='0.0.0.0', help='Host del servidor (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Puerto del servidor (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Modo debug')

    args = parser.parse_args()

    run_api(host=args.host, port=args.port, debug=args.debug)
