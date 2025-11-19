#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script simple para saber qué usuario eres
"""

import sys
import os
from pathlib import Path

# Configurar encoding para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent / 'app'))

from system_users import SystemUsersDetector

def main():
    print("=" * 60)
    print("👤 ¿QUIÉN SOY YO?")
    print("=" * 60)

    detector = SystemUsersDetector()

    # Obtener información del usuario actual
    current_user = detector.get_current_user()

    print(f"\n📋 Información de tu usuario:\n")
    print(f"  👤 Nombre de usuario: {current_user['username']}")
    print(f"  🏠 Directorio home: {current_user['home_directory']}")
    print(f"  🔐 ¿Eres administrador?: {'Sí ✅' if current_user['is_admin'] else 'No ❌'}")

    if current_user.get('effective_uid') is not None:
        print(f"  🆔 UID: {current_user['effective_uid']}")

    # Obtener grupos del usuario
    print(f"\n👥 Tus grupos:\n")
    groups = detector.get_user_groups()

    if groups and not any('Error' in str(g) for g in groups):
        for i, group in enumerate(groups, 1):
            print(f"  {i}. {group}")
    else:
        print("  ℹ️  No se pudieron obtener los grupos")

    # Información del sistema
    print(f"\n🖥️  Información del sistema:\n")
    sys_info = detector.get_system_info()
    print(f"  💻 Sistema operativo: {sys_info['os']}")
    print(f"  🏷️  Hostname: {sys_info['hostname']}")
    print(f"  🔧 Plataforma: {sys_info['platform']}")

    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()
