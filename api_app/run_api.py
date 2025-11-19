#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de ejecución para la API de Detección de Usuarios
Ejecuta el servidor de la API desde la carpeta api_app
"""

import sys
from pathlib import Path

# Agregar el directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

from users_api import run_api

if __name__ == '__main__':
    # Ejecutar la API
    # Por defecto en http://0.0.0.0:5000
    run_api(
        host='0.0.0.0',  # Escucha en todas las interfaces
        port=5000,        # Puerto
        debug=True        # Modo debug para desarrollo
    )
