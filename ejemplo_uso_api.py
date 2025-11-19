#!/usr/bin/env python3
"""
Ejemplo de Uso de la API de Detección de Usuarios
Script de demostración que muestra cómo consumir la API desde Python
"""

import requests
import json
from typing import List, Dict

# Configuración de la API
API_BASE_URL = "http://localhost:5000"


class UsersAPIClient:
    """Cliente para la API de Detección de Usuarios"""

    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip('/')

    def _make_request(self, endpoint: str) -> Dict:
        """Realiza una petición GET a la API"""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def get_system_info(self) -> Dict:
        """Obtiene información del sistema"""
        return self._make_request('/api/system')

    def get_all_users(self, filter_type: str = 'all', format_type: str = 'json') -> Dict:
        """
        Obtiene lista de usuarios

        Args:
            filter_type: 'all', 'human', 'system'
            format_type: 'json', 'simple'
        """
        return self._make_request(f'/api/users?filter={filter_type}&format={format_type}')

    def get_current_user(self) -> Dict:
        """Obtiene información del usuario actual"""
        return self._make_request('/api/users/current')

    def get_logged_users(self) -> Dict:
        """Obtiene usuarios conectados"""
        return self._make_request('/api/users/logged')

    def get_user_info(self, username: str) -> Dict:
        """Obtiene información de un usuario específico"""
        return self._make_request(f'/api/users/{username}')

    def get_user_groups(self, username: str) -> Dict:
        """Obtiene grupos de un usuario"""
        return self._make_request(f'/api/users/{username}/groups')

    def get_complete_report(self) -> Dict:
        """Obtiene reporte completo"""
        return self._make_request('/api/report')

    def check_health(self) -> Dict:
        """Verifica el estado de la API"""
        return self._make_request('/api/health')

    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe en el sistema"""
        result = self.get_user_info(username)
        return result.get('success', False) and result.get('exists', False)

    def validate_users(self, usernames: List[str]) -> tuple:
        """
        Valida una lista de usuarios

        Returns:
            tuple: (usuarios_validos, usuarios_invalidos)
        """
        valid = []
        invalid = []

        for username in usernames:
            if self.user_exists(username):
                valid.append(username)
            else:
                invalid.append(username)

        return valid, invalid


def demo_basic_usage():
    """Demostración de uso básico"""
    print("=" * 60)
    print("🔍 DEMO: Uso Básico de la API de Detección de Usuarios")
    print("=" * 60)

    # Crear cliente
    client = UsersAPIClient()

    # 1. Verificar estado de la API
    print("\n1️⃣ Verificando estado de la API...")
    health = client.check_health()
    if health.get('status') == 'healthy':
        print(f"   ✅ API funcionando correctamente")
        print(f"   📊 Versión: {health.get('version')}")
        print(f"   🖥️  Sistema: {health['checks'].get('os_detection')}")
    else:
        print("   ❌ API no disponible")
        return

    # 2. Obtener información del sistema
    print("\n2️⃣ Información del Sistema:")
    sys_info = client.get_system_info()
    if sys_info.get('success'):
        data = sys_info['data']
        print(f"   🖥️  OS: {data['os']} {data['os_version']}")
        print(f"   💻 Hostname: {data['hostname']}")
        print(f"   🔧 Arquitectura: {data['architecture']}")
    else:
        print(f"   ❌ Error: {sys_info.get('error')}")

    # 3. Obtener usuario actual
    print("\n3️⃣ Usuario Actual:")
    current = client.get_current_user()
    if current.get('success'):
        data = current['data']
        print(f"   👤 Usuario: {data['username']}")
        print(f"   🏠 Home: {data['home_directory']}")
        print(f"   🔐 Admin: {'Sí' if data['is_admin'] else 'No'}")
    else:
        print(f"   ❌ Error: {current.get('error')}")

    # 4. Listar todos los usuarios (formato simple)
    print("\n4️⃣ Todos los Usuarios del Sistema:")
    users = client.get_all_users(format_type='simple')
    if users.get('success'):
        print(f"   Total: {users['count']} usuarios")
        for i, username in enumerate(users['users'][:10], 1):  # Mostrar primeros 10
            print(f"   {i}. {username}")
        if users['count'] > 10:
            print(f"   ... y {users['count'] - 10} más")
    else:
        print(f"   ❌ Error: {users.get('error')}")

    # 5. Usuarios conectados
    print("\n5️⃣ Usuarios Conectados Actualmente:")
    logged = client.get_logged_users()
    if logged.get('success'):
        if logged['count'] > 0:
            for user in logged['data']:
                username = user.get('username')
                session = user.get('session_name', user.get('terminal', ''))
                print(f"   🟢 {username} ({session})")
        else:
            print("   ℹ️  No hay usuarios conectados")
    else:
        print(f"   ❌ Error: {logged.get('error')}")


def demo_user_validation():
    """Demostración de validación de usuarios"""
    print("\n" + "=" * 60)
    print("🔎 DEMO: Validación de Usuarios")
    print("=" * 60)

    client = UsersAPIClient()

    # Obtener lista de usuarios reales
    users_response = client.get_all_users(format_type='simple')
    if not users_response.get('success'):
        print("❌ No se pudo obtener la lista de usuarios")
        return

    real_users = users_response['users'][:3] if users_response['users'] else []

    # Crear lista mixta (usuarios reales + usuarios ficticios)
    test_users = real_users + ['usuario_inexistente1', 'usuario_inexistente2']

    print(f"\n📋 Validando usuarios: {', '.join(test_users)}")

    # Validar usuarios
    valid, invalid = client.validate_users(test_users)

    print(f"\n✅ Usuarios válidos ({len(valid)}):")
    for user in valid:
        print(f"   ✓ {user}")

    print(f"\n❌ Usuarios inválidos ({len(invalid)}):")
    for user in invalid:
        print(f"   ✗ {user}")


def demo_user_details():
    """Demostración de detalles de usuario"""
    print("\n" + "=" * 60)
    print("👤 DEMO: Detalles de Usuario")
    print("=" * 60)

    client = UsersAPIClient()

    # Obtener usuario actual
    current = client.get_current_user()
    if not current.get('success'):
        print("❌ No se pudo obtener el usuario actual")
        return

    username = current['data']['username']

    print(f"\n🔍 Obteniendo detalles de: {username}")

    # Información del usuario
    user_info = client.get_user_info(username)
    if user_info.get('success') and user_info.get('exists'):
        print(f"\n📊 Información:")
        data = user_info['data']
        for key, value in data.items():
            if key != 'error':
                print(f"   {key}: {value}")
    else:
        print("   ℹ️  Información limitada disponible")

    # Grupos del usuario
    groups = client.get_user_groups(username)
    if groups.get('success'):
        print(f"\n🔐 Grupos ({groups['count']}):")
        for group in groups['groups']:
            print(f"   • {group}")
    else:
        print(f"   ❌ Error obteniendo grupos: {groups.get('error')}")


def demo_integration_example():
    """Ejemplo de integración con el sistema PDF Secure"""
    print("\n" + "=" * 60)
    print("🔗 DEMO: Integración con PDF Secure")
    print("=" * 60)

    client = UsersAPIClient()

    # Simular la selección de usuarios para cifrar un PDF
    print("\n📄 Escenario: Cifrar un PDF para usuarios específicos")

    # Obtener usuarios disponibles
    users_response = client.get_all_users(filter_type='human', format_type='simple')

    if users_response.get('success'):
        available_users = users_response['users']
        print(f"\n👥 Usuarios disponibles en el sistema ({len(available_users)}):")
        for i, user in enumerate(available_users[:5], 1):
            print(f"   {i}. {user}")

        # Simular selección de usuarios
        if len(available_users) >= 2:
            selected_users = available_users[:2]
        else:
            selected_users = available_users

        # Agregar un usuario que no existe para demostrar validación
        selected_users.append('usuario_ficticio')

        print(f"\n📝 Usuarios seleccionados para el PDF:")
        for user in selected_users:
            print(f"   • {user}")

        # Validar usuarios antes de cifrar
        print("\n🔍 Validando usuarios antes de cifrar...")
        valid, invalid = client.validate_users(selected_users)

        if invalid:
            print(f"\n⚠️  ADVERTENCIA: Los siguientes usuarios no existen:")
            for user in invalid:
                print(f"   ✗ {user}")
            print("\n❓ ¿Deseas continuar solo con usuarios válidos?")

        if valid:
            print(f"\n✅ Usuarios válidos que recibirán acceso al PDF:")
            for user in valid:
                print(f"   ✓ {user}")

            print(f"\n💡 En este punto, el sistema procedería a:")
            print(f"   1. Cifrar el PDF")
            print(f"   2. Generar claves para: {', '.join(valid)}")
            print(f"   3. Registrar en logs la operación")
        else:
            print("\n❌ No hay usuarios válidos. No se puede cifrar el PDF.")

    else:
        print("❌ Error obteniendo usuarios del sistema")


def main():
    """Función principal"""
    print("\n" + "=" * 70)
    print(" " * 15 + "🔍 API DE DETECCIÓN DE USUARIOS")
    print(" " * 20 + "Ejemplos de Uso")
    print("=" * 70)

    try:
        # Verificar que la API está disponible
        client = UsersAPIClient()
        health = client.check_health()

        if health.get('status') != 'healthy':
            print("\n❌ ERROR: La API no está disponible")
            print("\n💡 Asegúrate de que el servidor esté ejecutándose:")
            print("   python run_users_api.py")
            return

        # Ejecutar demos
        demo_basic_usage()
        demo_user_validation()
        demo_user_details()
        demo_integration_example()

        print("\n" + "=" * 70)
        print("✅ Demos completadas exitosamente")
        print("=" * 70)
        print("\n📖 Para más información, consulta: API_USERS_GUIDE.md")

    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: No se puede conectar a la API")
        print("\n💡 Asegúrate de que el servidor esté ejecutándose:")
        print("   python run_users_api.py")
        print(f"\n🌐 URL de la API: {API_BASE_URL}")

    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
