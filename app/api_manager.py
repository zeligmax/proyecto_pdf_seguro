#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Manager - Gestor de la API de Detección de Usuarios
Permite iniciar, detener y monitorear la API desde main.py y app_gui.py
"""

import sys
import threading
import subprocess
import time
import requests
from pathlib import Path


class APIManager:
    """Gestor de la API de Usuarios"""

    def __init__(self, host='0.0.0.0', port=5000):
        """
        Inicializa el gestor de API

        Args:
            host: Host del servidor (default: 0.0.0.0)
            port: Puerto del servidor (default: 5000)
        """
        self.host = host
        self.port = port
        self.process = None
        self.thread = None
        self.running = False
        self.base_url = f"http://localhost:{port}"

    def start(self, in_thread=True):
        """
        Inicia el servidor de la API

        Args:
            in_thread: Si True, ejecuta en un hilo separado (recomendado para GUI)
                      Si False, ejecuta en un proceso separado (recomendado para CLI)

        Returns:
            tuple: (success: bool, message: str)
        """
        if self.is_running():
            return False, "La API ya está ejecutándose"

        try:
            if in_thread:
                # Ejecutar en hilo (para GUI)
                self.thread = threading.Thread(target=self._run_api_thread, daemon=True)
                self.thread.start()
            else:
                # Ejecutar en proceso separado (para CLI)
                self._run_api_process()

            # Verificar que se inició correctamente con reintentos
            max_retries = 10
            for i in range(max_retries):
                time.sleep(1)  # Esperar 1 segundo entre intentos
                if self._check_health():
                    self.running = True
                    return True, f"API iniciada en {self.base_url}"

            # Si no respondió después de todos los reintentos
            self.running = False
            return False, "La API no responde después de iniciar (timeout 10s)"

        except Exception as e:
            return False, f"Error al iniciar API: {str(e)}"

    def _run_api_thread(self):
        """Ejecuta la API en el hilo actual"""
        try:
            # Agregar api_app al path
            api_app_path = Path(__file__).parent.parent / 'api_app'
            sys.path.insert(0, str(api_app_path))

            from users_api import app

            # Ejecutar servidor Flask
            app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            print(f"Error en hilo de API: {str(e)}")
            self.running = False

    def _run_api_process(self):
        """Ejecuta la API en un proceso separado"""
        try:
            # Ruta al script de ejecución
            run_script = Path(__file__).parent.parent / 'run_users_api.py'

            # Iniciar proceso
            self.process = subprocess.Popen(
                [sys.executable, str(run_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
            )

        except Exception as e:
            print(f"Error al iniciar proceso de API: {str(e)}")
            self.running = False

    def stop(self):
        """
        Detiene el servidor de la API

        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.is_running():
            return False, "La API no está ejecutándose"

        try:
            # Detener proceso si existe
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)
                self.process = None

            # Marcar como detenido
            self.running = False

            # Esperar un poco
            time.sleep(1)

            return True, "API detenida correctamente"

        except Exception as e:
            return False, f"Error al detener API: {str(e)}"

    def is_running(self):
        """
        Verifica si la API está ejecutándose

        Returns:
            bool: True si está ejecutándose, False si no
        """
        # Verificar flag interno
        if not self.running and not self.process:
            return False

        # Verificar haciendo request
        return self._check_health()

    def _check_health(self):
        """
        Verifica la salud de la API

        Returns:
            bool: True si responde correctamente, False si no
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/health",
                timeout=2
            )
            return response.status_code == 200
        except:
            return False

    def get_status(self):
        """
        Obtiene el estado completo de la API

        Returns:
            dict: Información del estado
        """
        is_running = self.is_running()

        status = {
            'running': is_running,
            'url': self.base_url if is_running else None,
            'host': self.host,
            'port': self.port,
        }

        if is_running:
            try:
                response = requests.get(f"{self.base_url}/api/health", timeout=2)
                if response.status_code == 200:
                    health_data = response.json()
                    status['version'] = health_data.get('version', 'Unknown')
                    status['healthy'] = True
            except:
                status['healthy'] = False

        return status

    def get_users(self, filter_type='all', format_type='json'):
        """
        Obtiene usuarios del sistema a través de la API

        Args:
            filter_type: 'all', 'human', 'system'
            format_type: 'json', 'simple'

        Returns:
            dict: Datos de usuarios o None si hay error
        """
        if not self.is_running():
            return None

        try:
            response = requests.get(
                f"{self.base_url}/api/users",
                params={'filter': filter_type, 'format': format_type},
                timeout=5
            )

            if response.status_code == 200:
                return response.json()
            return None

        except Exception as e:
            print(f"Error obteniendo usuarios: {str(e)}")
            return None

    def open_browser(self):
        """
        Abre el navegador web en la URL de la API

        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.is_running():
            return False, "La API no está ejecutándose"

        try:
            import webbrowser
            webbrowser.open(self.base_url)
            return True, f"Navegador abierto en {self.base_url}"
        except Exception as e:
            return False, f"Error al abrir navegador: {str(e)}"


# Instancia global para compartir entre módulos
_api_manager_instance = None


def get_api_manager(host='0.0.0.0', port=5000):
    """
    Obtiene o crea la instancia global del gestor de API

    Args:
        host: Host del servidor
        port: Puerto del servidor

    Returns:
        APIManager: Instancia del gestor
    """
    global _api_manager_instance

    if _api_manager_instance is None:
        _api_manager_instance = APIManager(host=host, port=port)

    return _api_manager_instance
