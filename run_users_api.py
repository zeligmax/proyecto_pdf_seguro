#!/usr/bin/env python3
"""
Script de ejecución para la API de Detección de Usuarios
Ejecuta el servidor de la API de manera independiente
"""

import sys
from pathlib import Path

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent / 'app'))

from users_api import run_api

if __name__ == '__main__':
    # Ejecutar la API
    # Por defecto en http://0.0.0.0:5000
    # Puedes cambiar el puerto si 5000 está ocupado
    run_api(
        host='0.0.0.0',  # Escucha en todas las interfaces
        port=5000,        # Puerto
        debug=True        # Modo debug para desarrollo (cambiar a False en producción)
    )
