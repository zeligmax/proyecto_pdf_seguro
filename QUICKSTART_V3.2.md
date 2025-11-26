# 🚀 File Secure v3.2 Enterprise - Quick Start Guide

## 📋 Requisitos Previos

- Python 3.8+
- PostgreSQL 12+ (opcional, puede usar SQLite)
- Redis (opcional, para producción)

---

## ⚡ Instalación Rápida

### 1. Clonar o Descargar el Proyecto

```bash
cd FileSecureManager
```

### 2. Crear Entorno Virtual

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate
```

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

---

## 🗄️ Configuración de Base de Datos

### Opción A: SQLite (Desarrollo/Pruebas)

**No requiere configuración adicional** - Se usa automáticamente si no se configura PostgreSQL.

Ubicación: `~/.pdf_secure/filesecure_v3.db`

### Opción B: PostgreSQL (Producción)

#### 1. Instalar PostgreSQL

```bash
# Opción 1: Docker (recomendado)
cd docker
docker-compose up -d postgres

# Opción 2: Instalación local
# Descarga desde: https://www.postgresql.org/download/
```

#### 2. Crear Base de Datos

```sql
CREATE DATABASE filesecure_v3;
CREATE USER filesecure WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE filesecure_v3 TO filesecure;
```

#### 3. Configurar Variable de Entorno

**Windows (PowerShell):**
```powershell
$env:FILESECURE_DATABASE_URL = "postgresql://filesecure:your_password@localhost:5432/filesecure_v3"
```

**Linux/Mac:**
```bash
export FILESECURE_DATABASE_URL="postgresql://filesecure:your_password@localhost:5432/filesecure_v3"
```

O crear archivo `.env`:
```bash
cp docker/.env.example .env
# Editar .env con tus credenciales
```

---

## 🔑 Generar Clave Maestra

```bash
# Windows (PowerShell)
$key = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:PDF_SECURE_MASTER_KEY = $key
$env:FILESECURE_SECRET_KEY = $key

# Linux/Mac
export PDF_SECURE_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY
```

---

## 🎯 Inicializar el Sistema

### 1. Crear Tablas e Insertar Datos Iniciales

```bash
python -m app.scripts.init_data
```

Esto crea:
- ✅ Todas las tablas de la base de datos
- ✅ Permisos del sistema (30+)
- ✅ Roles predefinidos (SuperAdmin, OrgAdmin, DepartmentManager, Editor, Viewer, Auditor)
- ✅ Organización por defecto
- ✅ Departamento por defecto
- ✅ Políticas de seguridad por defecto
- ✅ Usuario administrador

**Credenciales del admin:**
```
Username: admin
Password: Admin@123456
Email: admin@filesecure.local
```

⚠️ **IMPORTANTE:** Cambiar la contraseña inmediatamente después del primer login.

---

## 🖥️ Ejecutar la Aplicación

### Opción 1: GUI de Escritorio (Tkinter)

```bash
# Windows
start_desktop.bat

# O manualmente
python run_app.py
```

La GUI se ejecuta con la interfaz v3.2 Enterprise.

### Opción 2: API REST

```bash
python run_api_v32.py
```

Acceder a:
- Health Check: http://localhost:5000/health
- API Info: http://localhost:5000/api/v1
- Swagger Docs: http://localhost:5000/api/v1/docs (próximamente)

### Opción 3: Dashboard Web (próximamente)

```bash
python -m app.dashboard.app
```

---

## 📡 Probar la API

### 1. Login

```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@123456"
  }'
```

Respuesta:
```json
{
  "user": {
    "id": "...",
    "username": "admin",
    "email": "admin@filesecure.local",
    "is_admin": true,
    "roles": ["SuperAdmin"]
  },
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 3600
}
```

### 2. Obtener Usuario Actual

```bash
curl http://localhost:5000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 3. Cambiar Contraseña

```bash
curl -X POST http://localhost:5000/api/v1/auth/change-password \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "Admin@123456",
    "new_password": "NewSecurePass@2024"
  }'
```

---

## 🏢 Crear Organizaciones y Usuarios

### Usando Python (próximamente via API):

```python
from app.core.database import get_db_manager
from app.services import OrganizationService, RBACService
from app.models import User

db_manager = get_db_manager()
with db_manager.get_session() as session:
    # Crear servicio de organización
    org_service = OrganizationService(session)

    # Crear nueva organización
    org = org_service.create_organization(
        name="finance",
        display_name="Finance Department",
        description="Financial operations",
        created_by="admin_user_id"
    )

    # Crear departamento
    dept = org_service.create_department(
        organization_id=org.id,
        name="accounting",
        display_name="Accounting",
        created_by="admin_user_id"
    )

    # Crear usuario
    user = User(
        organization_id=org.id,
        department_id=dept.id,
        username="john.doe",
        email="john@finance.com",
        full_name="John Doe"
    )
    user.set_password("SecurePass@123")
    session.add(user)

    # Asignar rol
    rbac_service = RBACService(session)
    role = session.query(Role).filter_by(name="Editor").first()
    rbac_service.assign_role_to_user(user.id, role.id)
```

---

## 🔐 Características v3.2

### Multi-Tenancy
- ✅ Organizaciones aisladas
- ✅ Departamentos jerárquicos
- ✅ Usuarios por organización

### RBAC Completo
- ✅ 6 roles predefinidos
- ✅ 30+ permisos granulares
- ✅ Roles personalizados por empresa

### Auditoría Centralizada
- ✅ Logs de todas las acciones
- ✅ Búsqueda y filtrado avanzado
- ✅ Exportación de reportes

### Políticas Configurables
- ✅ Políticas de contraseñas
- ✅ Políticas de sesión
- ✅ Políticas de archivos
- ✅ Políticas de cifrado
- ✅ Políticas de acceso
- ✅ Políticas de auditoría

---

## 🐳 Docker Deployment

### 1. Usar Docker Compose

```bash
cd docker
docker-compose up -d
```

Esto inicia:
- PostgreSQL (puerto 5432)
- Redis (puerto 6379)
- Elasticsearch (puerto 9200) - opcional
- pgAdmin (puerto 5050) - opcional

### 2. Configurar Variables

```bash
cp .env.example .env
# Editar .env con valores de producción
```

### 3. Inicializar Base de Datos

```bash
docker-compose exec postgres psql -U filesecure -d filesecure_v3 -f /docker-entrypoint-initdb.d/init-db.sql
```

---

## 🛠️ Comandos Útiles

### Ver Estado de la Base de Datos

```bash
python -c "
from app.core.database import get_db_manager
db = get_db_manager()
print(db.health_check())
"
```

### Limpiar Base de Datos

```bash
python -c "
from app.core.database import get_db_manager
db = get_db_manager()
# ⚠️ CUIDADO: Elimina todas las tablas
db.drop_all_tables()
"
```

### Ver Logs de Auditoría

```bash
python -c "
from app.core.database import get_db_manager
from app.services import AuditService

db_manager = get_db_manager()
with db_manager.get_session() as session:
    audit_service = AuditService(session)
    logs = audit_service.get_logs(limit=10)
    for log in logs:
        print(f'{log["timestamp"]}: {log["action"]} - {log["status"]}')
"
```

---

## 🔍 Troubleshooting

### Error: "PDF_SECURE_MASTER_KEY no encontrada"

**Solución:** Configurar la variable de entorno antes de ejecutar.

```bash
# Windows PowerShell
$env:PDF_SECURE_MASTER_KEY = "your_key_here"

# Linux/Mac
export PDF_SECURE_MASTER_KEY="your_key_here"
```

### Error: "Database connection failed"

**Solución:** Verificar que PostgreSQL esté corriendo y las credenciales sean correctas.

```bash
# Probar conexión
psql -U filesecure -d filesecure_v3 -h localhost
```

### Error: "Module not found"

**Solución:** Instalar todas las dependencias.

```bash
pip install -r requirements.txt
```

---

## 📚 Próximos Pasos

1. ✅ Cambiar contraseña del admin
2. ✅ Crear tu organización
3. ✅ Configurar políticas de seguridad
4. ✅ Crear usuarios y asignar roles
5. ✅ Comenzar a cifrar archivos
6. ✅ Revisar logs de auditoría

---

## 🆘 Soporte

- GitHub Issues: https://github.com/your-repo/FileSecureManager/issues
- Documentación completa: README.md
- API Documentation: http://localhost:5000/api/v1

---

**¡Disfruta de File Secure v3.2 Enterprise Edition!** 🎉
