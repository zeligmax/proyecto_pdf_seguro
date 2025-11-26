#!/usr/bin/env python3
"""
init_data.py - Initialize File Secure v3.2 with default data
Creates system permissions, roles, default organization, and admin user
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.database import get_db_manager
from app.core.config import get_config_manager
from app.models import (
    Organization, Department, User, Role, Permission,
    Policy, SYSTEM_PERMISSIONS, SYSTEM_ROLES, DEFAULT_POLICIES
)


def init_permissions(session):
    """Crea los permisos del sistema"""
    print("Creating system permissions...")

    created_count = 0
    for perm_name, display_name, description, category in SYSTEM_PERMISSIONS:
        # Verificar si ya existe
        existing = session.query(Permission).filter_by(name=perm_name).first()
        if existing:
            print(f"  ⏭️  Permission '{perm_name}' already exists")
            continue

        permission = Permission(
            name=perm_name,
            display_name=display_name,
            description=description,
            category=category,
            is_system=True,
            is_active=True
        )
        session.add(permission)
        created_count += 1
        print(f"  ✅ Created permission: {perm_name}")

    session.commit()
    print(f"✅ Created {created_count} permissions\n")
    return created_count


def init_roles(session, org_id=None):
    """Crea los roles del sistema"""
    print("Creating system roles...")

    created_count = 0
    for role_name, role_config in SYSTEM_ROLES.items():
        # Verificar si ya existe
        existing = session.query(Role).filter_by(
            name=role_name,
            organization_id=org_id
        ).first()

        if existing:
            print(f"  ⏭️  Role '{role_name}' already exists")
            continue

        role = Role(
            organization_id=org_id,
            name=role_name,
            display_name=role_config['display_name'],
            description=role_config['description'],
            is_system=role_config['is_system'],
            priority=role_config['priority'],
            is_active=True
        )

        # Asignar permisos
        for perm_name in role_config['permissions']:
            permission = session.query(Permission).filter_by(name=perm_name).first()
            if permission:
                role.permissions.append(permission)

        session.add(role)
        created_count += 1
        print(f"  ✅ Created role: {role_name} ({len(role_config['permissions'])} permissions)")

    session.commit()
    print(f"✅ Created {created_count} roles\n")
    return created_count


def init_default_organization(session):
    """Crea la organización por defecto"""
    print("Creating default organization...")

    # Verificar si ya existe
    org = session.query(Organization).filter_by(name="default").first()
    if org:
        print("  ⏭️  Default organization already exists")
        return org

    org = Organization(
        name="default",
        display_name="Default Organization",
        description="Default organization for File Secure v3.2",
        is_active=True
    )

    session.add(org)
    session.commit()
    print(f"✅ Created organization: {org.display_name} (ID: {org.id})\n")
    return org


def init_default_department(session, org_id):
    """Crea el departamento por defecto"""
    print("Creating default department...")

    # Verificar si ya existe
    dept = session.query(Department).filter_by(
        organization_id=org_id,
        name="general"
    ).first()

    if dept:
        print("  ⏭️  Default department already exists")
        return dept

    dept = Department(
        organization_id=org_id,
        name="general",
        display_name="General",
        description="Default department",
        is_active=True
    )

    session.add(dept)
    session.commit()
    print(f"✅ Created department: {dept.display_name} (ID: {dept.id})\n")
    return dept


def init_default_policies(session, org_id):
    """Crea las políticas por defecto"""
    print("Creating default policies...")

    created_count = 0
    for policy_type, policy_config in DEFAULT_POLICIES.items():
        # Verificar si ya existe
        existing = session.query(Policy).filter_by(
            organization_id=org_id,
            name=policy_type
        ).first()

        if existing:
            print(f"  ⏭️  Policy '{policy_type}' already exists")
            continue

        policy = Policy(
            organization_id=org_id,
            name=policy_type,
            display_name=policy_config['display_name'],
            description=policy_config['description'],
            policy_type=policy_type,
            is_default=True,
            is_active=True,
            priority=100
        )
        policy.set_config(policy_config['config'])

        session.add(policy)
        created_count += 1
        print(f"  ✅ Created policy: {policy_type}")

    session.commit()
    print(f"✅ Created {created_count} policies\n")
    return created_count


def init_admin_user(session, org_id, dept_id):
    """Crea el usuario administrador por defecto"""
    print("Creating admin user...")

    # Verificar si ya existe
    admin = session.query(User).filter_by(username="admin").first()
    if admin:
        print("  ⏭️  Admin user already exists")
        print(f"     Username: {admin.username}")
        print(f"     Email: {admin.email}")
        return admin

    # Crear admin
    admin = User(
        organization_id=org_id,
        department_id=dept_id,
        username="admin",
        email="admin@filesecure.local",
        full_name="System Administrator",
        display_name="Admin",
        is_active=True,
        is_admin=True  # SuperAdmin
    )

    # Establecer contraseña
    default_password = os.getenv('FILESECURE_ADMIN_PASSWORD', 'Admin@123456')
    admin.set_password(default_password)

    # Asignar rol SuperAdmin
    superadmin_role = session.query(Role).filter_by(name="SuperAdmin").first()
    if superadmin_role:
        admin.roles.append(superadmin_role)

    session.add(admin)
    session.commit()

    print(f"✅ Created admin user:")
    print(f"   Username: {admin.username}")
    print(f"   Email: {admin.email}")
    print(f"   Password: {default_password}")
    print(f"   ⚠️  IMPORTANT: Change the default password immediately!\n")

    return admin


def main():
    """Main initialization function"""
    print("=" * 60)
    print("FILE SECURE v3.2 - System Initialization")
    print("=" * 60)
    print()

    # Inicializar configuración
    config_manager = get_config_manager()

    # Inicializar base de datos
    db_manager = get_db_manager(config_manager.config.database.url)

    # Crear tablas
    print("Creating database tables...")
    db_manager.create_all_tables()
    print("✅ Database tables created\n")

    # Obtener sesión
    with db_manager.get_session() as session:
        # 1. Crear permisos
        init_permissions(session)

        # 2. Crear organización por defecto
        org = init_default_organization(session)

        # 3. Crear roles
        init_roles(session, org.id)

        # 4. Crear departamento por defecto
        dept = init_default_department(session, org.id)

        # 5. Crear políticas por defecto
        init_default_policies(session, org.id)

        # 6. Crear usuario admin
        admin = init_admin_user(session, org.id, dept.id)

        # Guardar valores para el resumen (antes de cerrar la sesión)
        org_name = org.display_name
        dept_name = dept.display_name
        admin_username = admin.username

    print("=" * 60)
    print("✅ System initialized successfully!")
    print("=" * 60)
    print()
    print("📊 Summary:")
    print(f"  - Organization: {org_name}")
    print(f"  - Department: {dept_name}")
    print(f"  - Admin User: {admin_username}")
    print(f"  - Database: {config_manager.config.database.url}")
    print()
    print("🚀 You can now start the application:")
    print("   python run_app.py")
    print()


if __name__ == "__main__":
    main()
