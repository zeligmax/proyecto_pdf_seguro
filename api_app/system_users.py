#!/usr/bin/env python3
"""
System Users Detection - Detección de usuarios del sistema
Módulo para detectar y listar usuarios del sistema operativo (Windows/Linux/macOS)
"""

import os
import sys
import platform
import subprocess
from typing import List, Dict, Optional
from datetime import datetime


class SystemUsersDetector:
    """Clase para detectar usuarios del sistema operativo"""

    def __init__(self):
        self.os_type = platform.system()
        self.os_version = platform.version()
        self.hostname = platform.node()

    def get_system_info(self) -> Dict:
        """Obtiene información general del sistema"""
        return {
            'os': self.os_type,
            'os_version': self.os_version,
            'hostname': self.hostname,
            'platform': platform.platform(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'timestamp': datetime.now().isoformat()
        }

    def get_current_user(self) -> Dict:
        """Obtiene información del usuario actual"""
        import getpass

        current_user = getpass.getuser()

        return {
            'username': current_user,
            'home_directory': os.path.expanduser('~'),
            'effective_uid': os.getuid() if hasattr(os, 'getuid') else None,
            'is_admin': self._is_admin()
        }

    def _is_admin(self) -> bool:
        """Verifica si el usuario actual tiene privilegios de administrador"""
        try:
            if self.os_type == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Unix-like systems
                return os.getuid() == 0
        except Exception:
            return False

    def get_all_users(self) -> List[Dict]:
        """
        Obtiene lista de todos los usuarios del sistema
        Funciona en Windows, Linux y macOS
        """
        if self.os_type == 'Windows':
            return self._get_windows_users()
        elif self.os_type == 'Linux':
            return self._get_linux_users()
        elif self.os_type == 'Darwin':  # macOS
            return self._get_macos_users()
        else:
            return [{'error': f'Sistema operativo no soportado: {self.os_type}'}]

    def _get_windows_users(self) -> List[Dict]:
        """Obtiene usuarios en Windows"""
        users = []

        try:
            # Método 1: Usando WMI (más completo)
            try:
                import wmi
                c = wmi.WMI()

                for user in c.Win32_UserAccount():
                    users.append({
                        'username': user.Name,
                        'full_name': user.FullName or '',
                        'description': user.Description or '',
                        'disabled': user.Disabled,
                        'local_account': user.LocalAccount,
                        'sid': user.SID,
                        'account_type': user.AccountType,
                        'domain': user.Domain,
                        'status': user.Status
                    })
            except ImportError:
                # Método 2: Usando comando net user (fallback)
                result = subprocess.run(
                    ['net', 'user'],
                    capture_output=True,
                    text=True,
                    encoding='cp850'  # Codificación para Windows
                )

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    in_user_section = False

                    for line in lines:
                        if '----' in line:
                            in_user_section = True
                            continue

                        if in_user_section and line.strip():
                            # Extraer usuarios de la línea
                            user_names = line.split()
                            for username in user_names:
                                if username and not username.startswith('Se completó'):
                                    users.append({
                                        'username': username,
                                        'full_name': '',
                                        'description': '',
                                        'method': 'net_user'
                                    })

        except Exception as e:
            users.append({'error': f'Error obteniendo usuarios de Windows: {str(e)}'})

        return users

    def _get_linux_users(self) -> List[Dict]:
        """Obtiene usuarios en Linux"""
        users = []

        try:
            # Leer el archivo /etc/passwd
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            uid = int(parts[2])
                            gid = int(parts[3])
                            full_name = parts[4].split(',')[0]  # GECOS field
                            home_dir = parts[5]
                            shell = parts[6]

                            # Filtrar usuarios del sistema (UID < 1000) opcionalmente
                            # Aquí incluimos todos, pero se puede filtrar
                            users.append({
                                'username': username,
                                'uid': uid,
                                'gid': gid,
                                'full_name': full_name,
                                'home_directory': home_dir,
                                'shell': shell,
                                'is_system_user': uid < 1000,
                                'has_login_shell': not shell.endswith('nologin') and not shell.endswith('false')
                            })

        except Exception as e:
            users.append({'error': f'Error obteniendo usuarios de Linux: {str(e)}'})

        return users

    def _get_macos_users(self) -> List[Dict]:
        """Obtiene usuarios en macOS"""
        users = []

        try:
            # Método 1: Usando dscl (Directory Service Command Line)
            result = subprocess.run(
                ['dscl', '.', '-list', '/Users'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                usernames = result.stdout.strip().split('\n')

                for username in usernames:
                    if username.strip():
                        # Obtener información adicional del usuario
                        user_info = self._get_macos_user_info(username.strip())
                        users.append(user_info)

        except Exception as e:
            users.append({'error': f'Error obteniendo usuarios de macOS: {str(e)}'})

        return users

    def _get_macos_user_info(self, username: str) -> Dict:
        """Obtiene información detallada de un usuario en macOS"""
        try:
            # Obtener UID
            uid_result = subprocess.run(
                ['dscl', '.', '-read', f'/Users/{username}', 'UniqueID'],
                capture_output=True,
                text=True
            )
            uid = uid_result.stdout.split(':')[1].strip() if ':' in uid_result.stdout else None

            # Obtener nombre real
            real_name_result = subprocess.run(
                ['dscl', '.', '-read', f'/Users/{username}', 'RealName'],
                capture_output=True,
                text=True
            )
            real_name_lines = real_name_result.stdout.split('\n')
            real_name = real_name_lines[1].strip() if len(real_name_lines) > 1 else ''

            # Obtener home directory
            home_result = subprocess.run(
                ['dscl', '.', '-read', f'/Users/{username}', 'NFSHomeDirectory'],
                capture_output=True,
                text=True
            )
            home_dir = home_result.stdout.split(':')[1].strip() if ':' in home_result.stdout else None

            # Obtener shell
            shell_result = subprocess.run(
                ['dscl', '.', '-read', f'/Users/{username}', 'UserShell'],
                capture_output=True,
                text=True
            )
            shell = shell_result.stdout.split(':')[1].strip() if ':' in shell_result.stdout else None

            return {
                'username': username,
                'uid': int(uid) if uid and uid.isdigit() else None,
                'real_name': real_name,
                'home_directory': home_dir,
                'shell': shell,
                'is_system_user': int(uid) < 500 if uid and uid.isdigit() else False
            }

        except Exception as e:
            return {
                'username': username,
                'error': f'Error obteniendo detalles: {str(e)}'
            }

    def get_logged_in_users(self) -> List[Dict]:
        """Obtiene lista de usuarios actualmente conectados"""
        logged_users = []

        try:
            if self.os_type == 'Windows':
                # Usar comando query user en Windows
                result = subprocess.run(
                    ['query', 'user'],
                    capture_output=True,
                    text=True,
                    encoding='cp850'
                )

                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                logged_users.append({
                                    'username': parts[0].replace('>', ''),
                                    'session_name': parts[1] if len(parts) > 1 else '',
                                    'state': 'active'
                                })
            else:
                # Unix-like: usar comando who
                result = subprocess.run(
                    ['who'],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                logged_users.append({
                                    'username': parts[0],
                                    'terminal': parts[1],
                                    'login_time': ' '.join(parts[2:5]) if len(parts) >= 5 else ''
                                })

        except Exception as e:
            logged_users.append({'error': f'Error obteniendo usuarios conectados: {str(e)}'})

        return logged_users

    def get_user_groups(self, username: Optional[str] = None) -> List[str]:
        """Obtiene los grupos a los que pertenece un usuario"""
        try:
            if username is None:
                import getpass
                username = getpass.getuser()

            if self.os_type == 'Windows':
                result = subprocess.run(
                    ['net', 'user', username],
                    capture_output=True,
                    text=True,
                    encoding='cp850'
                )

                if result.returncode == 0:
                    # Parsear la salida para extraer grupos
                    groups = []
                    in_local_groups = False
                    in_global_groups = False

                    for line in result.stdout.split('\n'):
                        # Filtrar mensajes del sistema
                        if ('Se ha completado' in line or
                            'The command completed' in line or
                            'successfully' in line.lower()):
                            break

                        # Detectar sección de grupos locales
                        if 'Miembros del grupo local' in line or 'Local Group Memberships' in line:
                            in_local_groups = True
                            in_global_groups = False
                            # Extraer grupos de la misma línea si los hay (formato: "Miembros del grupo local *Grupo1 *Grupo2")
                            if '*' in line:
                                group_parts = line.split('*')[1:]  # Tomar todo después del primer *
                                for part in group_parts:
                                    group_name = part.strip().split()[0] if part.strip() else ''
                                    if group_name and group_name not in ['Ninguno', 'None']:
                                        groups.append(group_name)
                            continue

                        # Detectar sección de grupos globales
                        if 'Miembros del grupo global' in line or 'Global Group memberships' in line:
                            in_local_groups = False
                            in_global_groups = True
                            # Extraer grupos de la misma línea
                            if '*' in line:
                                group_parts = line.split('*')[1:]
                                for part in group_parts:
                                    group_name = part.strip().split()[0] if part.strip() else ''
                                    if group_name and group_name not in ['Ninguno', 'None']:
                                        groups.append(group_name)
                            continue

                        # Procesar líneas de continuación con grupos
                        if (in_local_groups or in_global_groups) and '*' in line:
                            group_parts = line.split('*')[1:]
                            for part in group_parts:
                                group_name = part.strip().split()[0] if part.strip() else ''
                                if group_name and group_name not in ['Ninguno', 'None']:
                                    groups.append(group_name)

                    return groups
            else:
                # Unix-like: usar comando groups
                result = subprocess.run(
                    ['groups', username],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    groups_line = result.stdout.strip()
                    # Formato: "username : group1 group2 group3"
                    if ':' in groups_line:
                        groups = groups_line.split(':')[1].strip().split()
                    else:
                        groups = groups_line.split()[1:]  # Skip username

                    return groups

        except Exception as e:
            return [f'Error: {str(e)}']

        return []

    def get_complete_report(self) -> Dict:
        """Genera un reporte completo del sistema y usuarios"""
        return {
            'system_info': self.get_system_info(),
            'current_user': self.get_current_user(),
            'all_users': self.get_all_users(),
            'logged_in_users': self.get_logged_in_users(),
            'current_user_groups': self.get_user_groups()
        }


def main():
    """Función de prueba"""
    print("🔍 Sistema de Detección de Usuarios")
    print("=" * 50)

    detector = SystemUsersDetector()

    # Información del sistema
    print("\n📊 INFORMACIÓN DEL SISTEMA:")
    sys_info = detector.get_system_info()
    for key, value in sys_info.items():
        print(f"  {key}: {value}")

    # Usuario actual
    print("\n👤 USUARIO ACTUAL:")
    current = detector.get_current_user()
    for key, value in current.items():
        print(f"  {key}: {value}")

    # Todos los usuarios
    print("\n👥 TODOS LOS USUARIOS:")
    all_users = detector.get_all_users()
    for i, user in enumerate(all_users, 1):
        print(f"\n  Usuario {i}:")
        for key, value in user.items():
            print(f"    {key}: {value}")

    # Usuarios conectados
    print("\n🟢 USUARIOS CONECTADOS:")
    logged = detector.get_logged_in_users()
    for user in logged:
        print(f"  {user}")

    # Grupos del usuario actual
    print("\n🔐 GRUPOS DEL USUARIO ACTUAL:")
    groups = detector.get_user_groups()
    for group in groups:
        print(f"  - {group}")


if __name__ == "__main__":
    main()
