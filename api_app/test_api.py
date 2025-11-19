#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Prueba Rápida - API de Detección de Usuarios
Ejecuta pruebas básicas para verificar que la API funciona correctamente
"""

import sys
import os
from pathlib import Path

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

from system_users import SystemUsersDetector


def test_system_detection():
    """Prueba la detección del sistema"""
    print("=" * 60)
    print("🧪 TEST 1: Detección del Sistema Operativo")
    print("=" * 60)

    detector = SystemUsersDetector()

    print(f"✓ Sistema detectado: {detector.os_type}")
    print(f"✓ Versión: {detector.os_version}")
    print(f"✓ Hostname: {detector.hostname}")

    assert detector.os_type in ['Windows', 'Linux', 'Darwin'], "Sistema no soportado"
    print("\n✅ Test 1 PASADO\n")


def test_system_info():
    """Prueba la obtención de información del sistema"""
    print("=" * 60)
    print("🧪 TEST 2: Información del Sistema")
    print("=" * 60)

    detector = SystemUsersDetector()
    info = detector.get_system_info()

    required_keys = ['os', 'hostname', 'platform', 'timestamp']

    for key in required_keys:
        assert key in info, f"Clave faltante: {key}"
        print(f"✓ {key}: {info[key]}")

    print("\n✅ Test 2 PASADO\n")


def test_current_user():
    """Prueba la obtención del usuario actual"""
    print("=" * 60)
    print("🧪 TEST 3: Usuario Actual")
    print("=" * 60)

    detector = SystemUsersDetector()
    user = detector.get_current_user()

    assert 'username' in user, "No se pudo obtener username"
    assert 'home_directory' in user, "No se pudo obtener home_directory"

    print(f"✓ Usuario: {user['username']}")
    print(f"✓ Home: {user['home_directory']}")
    print(f"✓ Admin: {user.get('is_admin', 'N/A')}")

    print("\n✅ Test 3 PASADO\n")


def test_all_users():
    """Prueba la obtención de todos los usuarios"""
    print("=" * 60)
    print("🧪 TEST 4: Lista de Todos los Usuarios")
    print("=" * 60)

    detector = SystemUsersDetector()
    users = detector.get_all_users()

    assert isinstance(users, list), "Debe retornar una lista"
    assert len(users) > 0, "Debe haber al menos un usuario"

    print(f"✓ Total de usuarios encontrados: {len(users)}")

    # Mostrar primeros 3 usuarios
    print("\nPrimeros usuarios:")
    for i, user in enumerate(users[:3], 1):
        username = user.get('username', 'Unknown')
        print(f"  {i}. {username}")

    print("\n✅ Test 4 PASADO\n")


def test_logged_users():
    """Prueba la obtención de usuarios conectados"""
    print("=" * 60)
    print("🧪 TEST 5: Usuarios Conectados")
    print("=" * 60)

    detector = SystemUsersDetector()
    logged = detector.get_logged_in_users()

    assert isinstance(logged, list), "Debe retornar una lista"

    if len(logged) > 0:
        print(f"✓ Usuarios conectados: {len(logged)}")
        for user in logged:
            username = user.get('username', 'Unknown')
            print(f"  • {username}")
    else:
        print("ℹ️  No hay usuarios conectados detectados (puede ser normal)")

    print("\n✅ Test 5 PASADO\n")


def test_user_groups():
    """Prueba la obtención de grupos del usuario actual"""
    print("=" * 60)
    print("🧪 TEST 6: Grupos del Usuario Actual")
    print("=" * 60)

    detector = SystemUsersDetector()
    groups = detector.get_user_groups()

    assert isinstance(groups, list), "Debe retornar una lista"

    if len(groups) > 0 and not any('Error' in str(g) for g in groups):
        print(f"✓ Total de grupos: {len(groups)}")
        print("\nGrupos:")
        for group in groups[:5]:  # Mostrar primeros 5
            print(f"  • {group}")
        if len(groups) > 5:
            print(f"  ... y {len(groups) - 5} más")
    else:
        print("⚠️  No se pudieron obtener grupos (puede ser normal según permisos)")

    print("\n✅ Test 6 PASADO\n")


def test_complete_report():
    """Prueba el reporte completo"""
    print("=" * 60)
    print("🧪 TEST 7: Reporte Completo")
    print("=" * 60)

    detector = SystemUsersDetector()
    report = detector.get_complete_report()

    required_sections = ['system_info', 'current_user', 'all_users', 'logged_in_users']

    for section in required_sections:
        assert section in report, f"Sección faltante: {section}"
        print(f"✓ {section}: OK")

    print("\n✅ Test 7 PASADO\n")


def run_all_tests():
    """Ejecuta todos los tests"""
    print("\n" + "=" * 60)
    print(" " * 15 + "🔬 SUITE DE PRUEBAS")
    print(" " * 10 + "API de Detección de Usuarios")
    print("=" * 60 + "\n")

    tests = [
        test_system_detection,
        test_system_info,
        test_current_user,
        test_all_users,
        test_logged_users,
        test_user_groups,
        test_complete_report
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"❌ TEST FALLIDO: {e}\n")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR INESPERADO: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1

    # Resumen
    print("=" * 60)
    print("📊 RESUMEN DE PRUEBAS")
    print("=" * 60)
    print(f"✅ Pasados: {passed}/{len(tests)}")
    print(f"❌ Fallidos: {failed}/{len(tests)}")

    if failed == 0:
        print("\n🎉 ¡TODOS LOS TESTS PASARON!")
        print("\n✅ La API está lista para usar. Ejecuta:")
        print("   python run_users_api.py")
    else:
        print(f"\n⚠️  {failed} test(s) fallaron. Revisa los errores arriba.")

    print("=" * 60 + "\n")

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
