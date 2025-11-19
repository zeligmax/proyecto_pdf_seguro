"""
API App - Sistema de Detección de Usuarios
Paquete que contiene la API REST para detectar usuarios del sistema
"""

__version__ = '1.0.0'
__author__ = 'PDF Secure Team'

from .system_users import SystemUsersDetector
from .users_api import app

__all__ = ['SystemUsersDetector', 'app']
