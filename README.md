# 📁 File Secure v3.2 Enterprise - Guía Completa

> Sistema empresarial de cifrado de archivos con multi-tenancy, RBAC completo, auditoría centralizada y políticas configurables.
> **Soporta múltiples formatos**: PDF, DOCX, XLSX, TXT, PBIP, PBIX

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-enterprise-brightgreen.svg)]()
[![Database](https://img.shields.io/badge/database-PostgreSQL%20%7C%20SQLite-blue)]()
[![API](https://img.shields.io/badge/API-REST%20v1-orange)]()

---

## 🚀 Quick Start

**Para empezar rápido con v3.2, consulta**: [QUICKSTART_V3.2.md](QUICKSTART_V3.2.md)

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Generar clave maestra
export PDF_SECURE_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY

# 3. Inicializar base de datos (SQLite por defecto)
python -m app.scripts.init_data

# 4. Ejecutar aplicación
python run_app.py
# O ejecutar API REST
python run_api_v32.py
```

**Credenciales por defecto**: `admin` / `Admin@123456` (cambiar inmediatamente)

---

## 📖 **Tabla de Contenidos**

1. [¿Qué es File Secure?](#-qué-es-file-secure)
2. [🆕 Novedades v3.2 Enterprise](#-novedades-v32-enterprise)
3. [Características Principales](#-características-principales)
4. [🏢 Multi-Tenancy y RBAC](#-multi-tenancy-y-rbac)
5. [📁 Soporte Multi-formato](#-soporte-multi-formato-desde-v31)
6. [🔌 REST API v1](#-rest-api-v1)
7. [Requisitos del Sistema](#-requisitos-del-sistema)
8. [Instalación Paso a Paso](#-instalación-paso-a-paso)
9. [Configuración Inicial](#-configuración-inicial)
10. [Cómo Usar el Programa](#-cómo-usar-el-programa)
11. [Ejemplos Prácticos](#-ejemplos-prácticos)
12. [Preguntas Frecuentes](#-preguntas-frecuentes)
13. [Solución de Problemas](#-solución-de-problemas)
14. [Seguridad y Buenas Prácticas](#-seguridad-y-buenas-prácticas)
15. [Migración desde v3.1](#-migración-desde-v31)

---

## 🤔 **¿Qué es PDF Secure?**

File Secure es un **sistema empresarial de cifrado de archivos** con arquitectura multi-tenant que permite a las organizaciones **proteger cualquier tipo de archivo** (PDF, DOCX, XLSX, TXT, PBIP, PBIX, y más) con control de acceso basado en roles, auditoría centralizada y políticas de seguridad configurables.

### **¿Cómo funciona?**

1. **La organización cifra** archivos y asigna permisos según roles
2. El sistema **gestiona usuarios, departamentos y organizaciones**
3. **Control de acceso granular** con 30+ permisos y 6 roles predefinidos
4. El sistema **audita todas las acciones** en una base de datos centralizada
5. **Políticas configurables** de contraseñas, sesiones, archivos, cifrado y acceso

### **¿Por qué usar v3.2 Enterprise?**

✅ **Multi-tenancy**: Múltiples organizaciones aisladas en un solo sistema
✅ **RBAC completo**: 6 roles predefinidos + roles personalizados por empresa
✅ **Auditoría centralizada**: Logs de todas las acciones con búsqueda avanzada
✅ **Políticas configurables**: 6 tipos de políticas ajustables por organización
✅ **PostgreSQL**: Base de datos empresarial con alta disponibilidad
✅ **REST API**: Integración con otros sistemas vía JWT
✅ **Dashboard ejecutivo**: Métricas y estadísticas en tiempo real
✅ **Docker deployment**: Despliegue fácil con contenedores
✅ **Soporte multi-formato**: PDF, DOCX, XLSX, TXT, PBIP, PBIX

---

## 🆕 **Novedades v3.2 Enterprise**

### **Arquitectura Empresarial Completa**

File Secure v3.2 introduce una **transformación completa** hacia una arquitectura empresarial:

#### **1. Multi-Tenancy**
- ✅ **Organizaciones aisladas**: Cada empresa tiene sus propios datos
- ✅ **Departamentos jerárquicos**: Estructura organizacional completa
- ✅ **Usuarios por organización**: Gestión centralizada de identidades
- ✅ **Datos separados**: Aislamiento completo entre organizaciones

#### **2. RBAC (Control de Acceso Basado en Roles)**
- ✅ **6 roles predefinidos**:
  - **SuperAdmin**: Acceso total al sistema
  - **OrgAdmin**: Administrador de organización
  - **DepartmentManager**: Gestor de departamento
  - **Editor**: Crear y editar archivos
  - **Viewer**: Solo lectura
  - **Auditor**: Acceso a logs y reportes
- ✅ **30+ permisos granulares**: `file.*`, `user.*`, `org.*`, `dept.*`, `policy.*`, `audit.*`, `role.*`, `dashboard.*`
- ✅ **Roles personalizados**: Cada organización puede crear sus propios roles

#### **3. Auditoría Centralizada**
- ✅ **Logs de todas las acciones**: Login, logout, cifrado, descifrado, cambios de usuarios, políticas
- ✅ **Búsqueda avanzada**: Por acción, usuario, fecha, severidad, estado
- ✅ **Exportación de reportes**: CSV, JSON
- ✅ **Estadísticas**: Accesos por día, usuarios más activos, archivos más accedidos
- ✅ **Niveles de severidad**: info, warning, error, critical

#### **4. Políticas Configurables**
- ✅ **6 tipos de políticas**:
  - **password_policy**: Requisitos de contraseñas (longitud, caracteres, expiración)
  - **session_policy**: Duración de sesión, concurrencia, timeout
  - **file_policy**: Tamaño máximo, formatos permitidos, expiración
  - **encryption_policy**: Algoritmos, rotación de claves
  - **access_policy**: Restricciones de IP, horarios, intentos fallidos
  - **audit_policy**: Retención de logs, niveles mínimos
- ✅ **Por organización**: Cada empresa define sus políticas
- ✅ **Por departamento**: Políticas específicas con herencia
- ✅ **Prioridad**: Sistema de prioridades para resolver conflictos

#### **5. PostgreSQL + SQLite**
- ✅ **PostgreSQL**: Producción con alta disponibilidad
- ✅ **SQLite**: Desarrollo y pruebas (fallback automático)
- ✅ **Migraciones**: Alembic para gestión de esquemas
- ✅ **Connection pooling**: Alto rendimiento con múltiples conexiones

#### **6. REST API v1 con JWT**
- ✅ **Autenticación JWT**: Tokens seguros con expiración
- ✅ **Endpoints**:
  - `POST /api/v1/auth/login` - Login con JWT
  - `GET /api/v1/auth/me` - Usuario actual
  - `POST /api/v1/auth/change-password` - Cambiar contraseña
  - `POST /api/v1/auth/reset-password` - Reset de contraseña (admin)
  - `POST /api/v1/auth/unlock-user` - Desbloquear usuario
- ✅ **Decoradores**: `@require_auth`, `@require_permission`, `@require_role`
- ✅ **CORS**: Integración con frontends externos

#### **7. Dashboard Ejecutivo (Tkinter)**
- ✅ **KPIs en tiempo real**: Total de usuarios, archivos, accesos hoy, intentos fallidos
- ✅ **Gráficos de tendencias**: Accesos por día (ASCII charts)
- ✅ **Actividad reciente**: Últimas acciones del sistema
- ✅ **Alertas de seguridad**: Intentos fallidos, políticas violadas

#### **8. Docker Deployment**
- ✅ **docker-compose.yml**: PostgreSQL, Redis, Elasticsearch
- ✅ **Variables de entorno**: Configuración externalizada
- ✅ **pgAdmin**: Interfaz web para PostgreSQL
- ✅ **Escalabilidad horizontal**: Ready for Kubernetes

#### **9. Migración de Datos**
- ✅ **Script automático**: `app/scripts/migrate_v31_to_v32.py`
- ✅ **Preserva**: Claves de usuario, logs de acceso, IP whitelist
- ✅ **Crea**: Organización/departamento por defecto
- ✅ **Compatible**: Los archivos cifrados v3.1 funcionan en v3.2

---

## ✨ **Características Principales**

### **Características Empresariales (v3.2)**
- 🏢 **Multi-Tenancy**: Organizaciones y departamentos aislados
- 👥 **RBAC Completo**: 6 roles predefinidos + 30+ permisos granulares
- 📊 **Auditoría Centralizada**: PostgreSQL con búsqueda avanzada y exportación
- ⚙️ **Políticas Configurables**: 6 tipos de políticas por organización/departamento
- 🔌 **REST API v1**: JWT authentication + decoradores de permisos
- 📈 **Dashboard Ejecutivo**: KPIs, tendencias y alertas en tiempo real
- 🐳 **Docker Ready**: docker-compose con PostgreSQL, Redis, Elasticsearch
- 🔄 **Migración Automática**: Script de migración desde v3.1

### **Características de Seguridad**
- 🔐 **Cifrado AES-256**: Nivel militar de seguridad (metadatos cifrados)
- 🔑 **Verificación de Usuario**: Usuario del sistema debe coincidir con autorizado
- 🌐 **Control de IP**: Whitelist opcional + políticas de acceso por IP
- ⏰ **Expiración de Claves**: Configurable por política
- 🔒 **Bloqueo de Cuentas**: Después de N intentos fallidos (configurable)
- 📝 **Logs Inmutables**: Auditoría completa de todas las acciones
- 🔐 **Password Policies**: Complejidad, expiración, historial

### **Características Funcionales**
- 📁 **Soporte Multi-formato**: PDF, DOCX, XLSX, TXT, PBIP, PBIX, y más
- 👁️ **Visualizadores en Memoria**: Ver archivos sin guardarlos en disco
  - PDF: Renderizado completo con PyMuPDF
  - Texto: Archivos .txt, .md, .log, .csv
  - Imágenes: .jpg, .png, .gif, .bmp, .webp
  - Office: Información de archivos .docx, .xlsx, .pptx
- 🖥️ **Dos Interfaces**: GUI Tkinter moderna + REST API
- 🗄️ **Bases de Datos**: PostgreSQL (producción) + SQLite (desarrollo)
- 🔍 **Búsqueda Avanzada**: Filtros por usuario, acción, fecha, severidad

---

## 🏢 **Multi-Tenancy y RBAC**

### **Arquitectura Multi-Tenant**

File Secure v3.2 soporta **múltiples organizaciones** dentro de un solo sistema:

```
Sistema File Secure
├── Organización A (Acme Corp)
│   ├── Departamento Finanzas
│   │   ├── Usuario: Juan (OrgAdmin)
│   │   └── Usuario: María (Editor)
│   ├── Departamento IT
│   │   ├── Usuario: Carlos (DepartmentManager)
│   │   └── Usuario: Ana (Viewer)
│   └── Políticas específicas de Acme Corp
│
├── Organización B (Tech Solutions)
│   ├── Departamento Ventas
│   │   └── Usuario: Luis (Editor)
│   ├── Departamento Soporte
│   │   └── Usuario: Elena (Auditor)
│   └── Políticas específicas de Tech Solutions
│
└── SuperAdmin (admin)
    └── Gestiona todas las organizaciones
```

### **Roles Predefinidos**

| Rol | Prioridad | Descripción | Permisos Clave |
|-----|-----------|-------------|----------------|
| **SuperAdmin** | 100 | Control total del sistema | `*` (todos los permisos) |
| **OrgAdmin** | 80 | Administrador de organización | Gestionar usuarios, departamentos, políticas de su org |
| **DepartmentManager** | 60 | Gestor de departamento | Gestionar usuarios de su departamento, ver métricas |
| **Editor** | 40 | Editor de archivos | Crear, editar, cifrar, descifrar archivos |
| **Viewer** | 20 | Solo lectura | Ver archivos, ver dashboard (sin editar) |
| **Auditor** | 50 | Auditor de seguridad | Acceso completo a logs, reportes, estadísticas |

### **Permisos Granulares**

El sistema incluye **30+ permisos** organizados por categoría:

**Archivos** (`file.*`):
- `file.create` - Crear archivos
- `file.read` - Leer archivos
- `file.update` - Actualizar archivos
- `file.delete` - Eliminar archivos
- `file.encrypt` - Cifrar archivos
- `file.decrypt` - Descifrar archivos
- `file.share` - Compartir acceso a archivos

**Usuarios** (`user.*`):
- `user.create` - Crear usuarios
- `user.read` - Ver usuarios
- `user.update` - Actualizar usuarios
- `user.delete` - Eliminar usuarios
- `user.change_password` - Cambiar contraseñas
- `user.reset_password` - Resetear contraseñas (admin)
- `user.unlock` - Desbloquear cuentas

**Organizaciones** (`org.*`):
- `org.create` - Crear organizaciones (solo SuperAdmin)
- `org.read` - Ver organizaciones
- `org.update` - Actualizar organizaciones
- `org.delete` - Eliminar organizaciones

**Departamentos** (`dept.*`):
- `dept.create` - Crear departamentos
- `dept.read` - Ver departamentos
- `dept.update` - Actualizar departamentos
- `dept.delete` - Eliminar departamentos

**Políticas** (`policy.*`):
- `policy.create` - Crear políticas
- `policy.read` - Ver políticas
- `policy.update` - Actualizar políticas
- `policy.delete` - Eliminar políticas

**Auditoría** (`audit.*`):
- `audit.read` - Ver logs de auditoría
- `audit.export` - Exportar logs
- `audit.delete` - Eliminar logs antiguos

**Roles** (`role.*`):
- `role.create` - Crear roles personalizados
- `role.read` - Ver roles
- `role.update` - Actualizar roles
- `role.assign` - Asignar roles a usuarios

**Dashboard** (`dashboard.*`):
- `dashboard.view` - Ver dashboard
- `dashboard.stats` - Ver estadísticas

### **Roles Personalizados**

Cada organización puede crear **roles personalizados**:

```python
# Ejemplo: Crear rol "Contador" para departamento de Finanzas
{
  "name": "Contador",
  "organization_id": "acme-corp-id",
  "permissions": [
    "file.read",
    "file.decrypt",
    "audit.read",
    "dashboard.view"
  ],
  "priority": 45
}
```

---

## 🔌 **REST API v1**

File Secure v3.2 incluye una **API REST completa** con autenticación JWT.

### **Inicio Rápido**

```bash
# 1. Iniciar API
python run_api_v32.py

# 2. La API corre en http://localhost:5000
# 3. Documentación: http://localhost:5000/api/v1/docs (próximamente)
```

### **Autenticación**

**Login y obtención de token JWT:**

```bash
# Login
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@123456"
  }'

# Respuesta:
{
  "user": {
    "id": "...",
    "username": "admin",
    "email": "admin@filesecure.local",
    "roles": ["SuperAdmin"]
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

**Usar el token en requests:**

```bash
# Obtener información del usuario actual
curl http://localhost:5000/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### **Endpoints Disponibles**

#### **Autenticación** (`/api/v1/auth`)

| Método | Endpoint | Descripción | Requiere Auth |
|--------|----------|-------------|---------------|
| POST | `/login` | Login con usuario/contraseña | No |
| POST | `/logout` | Logout (invalida token) | Sí |
| GET | `/me` | Información del usuario actual | Sí |
| POST | `/change-password` | Cambiar contraseña | Sí |
| POST | `/reset-password` | Resetear contraseña (admin) | Sí + `user.reset_password` |
| POST | `/unlock-user` | Desbloquear cuenta | Sí + `user.unlock` |

### **Decoradores de Seguridad**

La API implementa decoradores para control de acceso:

```python
from app.api.middleware.auth import require_auth, require_permission, require_role

# Requiere autenticación
@app.route('/api/v1/files')
@require_auth
def list_files():
    user = g.current_user
    # ...

# Requiere permiso específico
@app.route('/api/v1/users', methods=['POST'])
@require_auth
@require_permission('user.create')
def create_user():
    # ...

# Requiere rol específico
@app.route('/api/v1/admin/stats')
@require_auth
@require_role('OrgAdmin')
def admin_stats():
    # ...
```

### **Códigos de Error**

| Código | Descripción |
|--------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (datos inválidos) |
| 401 | Unauthorized (sin token o token inválido) |
| 403 | Forbidden (sin permisos) |
| 404 | Not Found |
| 423 | Locked (cuenta bloqueada) |
| 500 | Internal Server Error |

---

## 📁 **Soporte Multi-formato (Desde v3.1)**

File Secure es un sistema completo de cifrado de archivos que soporta múltiples formatos, no solo PDFs.

### **Formatos Soportados:**

| Formato | Extensión | Visualización en Memoria |
|---------|-----------|-------------------------|
| PDF | `.pdf` | ✅ Renderizado completo |
| Word | `.docx` | ℹ️ Información del archivo |
| Excel | `.xlsx` | ℹ️ Información del archivo |
| Texto | `.txt` | ✅ Editor de texto |
| Power BI Project | `.pbip` | ℹ️ Información del archivo |
| Power BI Report | `.pbix` | ℹ️ Información del archivo |
| Markdown | `.md` | ✅ Editor de texto |
| CSV | `.csv` | ✅ Editor de texto |
| Imágenes | `.jpg, .png, .gif, .bmp, .webp` | ✅ Visor de imágenes |

### **¿Cómo funciona?**

1. **Cifrado**: El sistema detecta automáticamente el tipo de archivo y lo almacena en los metadatos cifrados
2. **Descifrado**: Al descifrar, el sistema identifica el formato original y lo restaura
3. **Visualización**: Según el tipo de archivo, se muestra con el visualizador apropiado
4. **Compatibilidad**: Los archivos cifrados con v2.0 y v2.1 siguen siendo compatibles

### **Ventajas:**

✅ **Un solo sistema** para todos tus documentos confidenciales
✅ **Mismo nivel de seguridad** (AES-256) para todos los formatos
✅ **Mismas capacidades** de control de acceso y auditoría
✅ **Visualización segura** sin necesidad de guardar en disco

---


## 💻 **Requisitos del Sistema**

### **Software Necesario**

#### **Requisitos Básicos (Obligatorios)**
- **Python 3.8 o superior** ([Descargar aquí](https://www.python.org/downloads/))
- **pip** (gestor de paquetes de Python, viene con Python)
- **Sistema Operativo**: Windows 10/11, macOS 10.14+, Linux (cualquier distribución)

#### **Base de Datos (Elegir una)**
- **SQLite**: Incluido en Python (para desarrollo/pruebas)
- **PostgreSQL 12+**: Recomendado para producción ([Descargar](https://www.postgresql.org/download/))
  - O usar Docker (ver sección Docker)

#### **Opcional (Producción/Enterprise)**
- **Docker y Docker Compose**: Para deployment con PostgreSQL, Redis, Elasticsearch
- **Redis 6+**: Para caché y sesiones (opcional)
- **Elasticsearch 8+**: Para logs centralizados (opcional)

### **¿Cómo verifico si tengo Python?**

**Windows:**
```cmd
python --version
```

**macOS/Linux:**
```bash
python3 --version
```

Si ves algo como `Python 3.8.10` o superior, ¡estás listo! ✅

Si no tienes Python instalado, [descárgalo aquí](https://www.python.org/downloads/) e instálalo.

### **Verificar PostgreSQL (Opcional)**

Si vas a usar PostgreSQL en lugar de SQLite:

```bash
# Verificar instalación
psql --version

# O usar Docker
docker --version
```

---

## 📥 **Instalación Paso a Paso**

### **Opción 1: Instalación Rápida (SQLite)**

**Para desarrollo o evaluación rápida:**

```bash
# 1. Clonar repositorio
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar variables de entorno
export PDF_SECURE_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY

# 4. Inicializar base de datos SQLite
python -m app.scripts.init_data

# 5. Ejecutar aplicación
python run_app.py
```

### **Opción 2: Instalación con Docker (Recomendado para Producción)**

**Para deployment empresarial con PostgreSQL:**

```bash
# 1. Clonar repositorio
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro

# 2. Configurar variables de entorno
cp docker/.env.example docker/.env
# Editar docker/.env con tus configuraciones

# 3. Iniciar servicios con Docker Compose
cd docker
docker-compose up -d

# 4. Verificar servicios
docker-compose ps
# Deberías ver: postgres, redis, elasticsearch, pgadmin

# 5. Instalar dependencias Python (en host)
cd ..
pip install -r requirements.txt

# 6. Configurar variables de entorno para la app
export DATABASE_URL="postgresql://filesecure:SecurePass2025@localhost:5432/filesecure_v3"
export REDIS_URL="redis://localhost:6379/0"
export PDF_SECURE_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY

# 7. Inicializar base de datos PostgreSQL
python -m app.scripts.init_data

# 8. Ejecutar API
python run_api_v32.py
```

**Acceder a servicios:**
- **API**: http://localhost:5000
- **pgAdmin**: http://localhost:5050 (admin@filesecure.local / admin)
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **Elasticsearch**: localhost:9200

### **Opción 3: Instalación Manual Detallada**

#### **Paso 1: Descargar el Proyecto**

**Usando Git:**
```bash
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro
```

**Descarga Manual:**
1. Ve a: https://github.com/zeligmax/proyecto_pdf_seguro
2. Click en **"Code"** → **"Download ZIP"**
3. Descomprime y abre terminal en la carpeta

#### **Paso 2: Verificar Estructura**

Tu proyecto debe tener esta estructura:

```
FileSecureManager/
├── app/
│   ├── api/              # API REST v1
│   ├── core/             # Database y config
│   ├── models/           # Modelos SQLAlchemy
│   ├── services/         # Lógica de negocio
│   ├── gui/              # Widgets Tkinter
│   ├── dashboard/        # Dashboard ejecutivo
│   └── scripts/          # Scripts de inicialización
├── docker/               # Docker Compose
├── migrations/           # Migraciones Alembic
├── requirements.txt
├── run_api_v32.py
└── README.md
```

#### **Paso 3: Instalar Dependencias**

```bash
# Opción A: Todas las dependencias (recomendado)
pip install -r requirements.txt

# Opción B: Solo dependencias básicas
pip install cryptography sqlalchemy psycopg2-binary flask pyjwt pyyaml
```

**Dependencias principales instaladas:**
- cryptography: Cifrado AES-256
- sqlalchemy: ORM para base de datos
- psycopg2-binary: Driver PostgreSQL
- flask: API REST
- pyjwt: Autenticación JWT
- pyyaml: Configuración
- PyMuPDF, Pillow: Visualizadores
- marshmallow: Serialización
- redis: Caché (opcional)

✅ ¡Listo! Ya tienes todo instalado.

---

## 🔧 **Configuración Inicial**

### **Paso 1: Variables de Entorno**

File Secure v3.2 requiere dos variables de entorno principales:

#### **En Windows (PowerShell):**

```powershell
# 1. Generar claves
$key = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. Configurar variables (¡GUARDA ESTAS CLAVES EN UN LUGAR SEGURO!)
$env:PDF_SECURE_MASTER_KEY = $key
$env:FILESECURE_SECRET_KEY = $key

# 3. Configurar base de datos (SQLite por defecto)
# Para SQLite (desarrollo):
$env:DATABASE_URL = "sqlite:///./filesecure_v32.db"

# Para PostgreSQL (producción):
# $env:DATABASE_URL = "postgresql://user:password@localhost:5432/filesecure_v3"

# 4. Verificar
echo $env:PDF_SECURE_MASTER_KEY
echo $env:DATABASE_URL
```

#### **En macOS/Linux (Terminal):**

```bash
# 1. Generar y configurar claves
export PDF_SECURE_MASTER_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY

# 2. Configurar base de datos
# Para SQLite (desarrollo):
export DATABASE_URL="sqlite:///./filesecure_v32.db"

# Para PostgreSQL (producción):
# export DATABASE_URL="postgresql://user:password@localhost:5432/filesecure_v3"

# 3. Verificar
echo $PDF_SECURE_MASTER_KEY
echo $DATABASE_URL
```

**Variables disponibles:**
- `PDF_SECURE_MASTER_KEY`: Clave maestra para cifrado (obligatoria)
- `FILESECURE_SECRET_KEY`: Clave para JWT (obligatoria, puede ser igual a PDF_SECURE_MASTER_KEY)
- `DATABASE_URL`: URL de conexión a base de datos (default: SQLite)
- `REDIS_URL`: URL de Redis (opcional, default: redis://localhost:6379/0)
- `LOG_LEVEL`: Nivel de logging (default: INFO)

### **Paso 2: Configuración Permanente (Recomendado)**

#### **Windows:**
```powershell
# PowerShell como Administrador
[Environment]::SetEnvironmentVariable('PDF_SECURE_MASTER_KEY', 'tu_clave_aqui', 'User')
[Environment]::SetEnvironmentVariable('FILESECURE_SECRET_KEY', 'tu_clave_aqui', 'User')
[Environment]::SetEnvironmentVariable('DATABASE_URL', 'sqlite:///./filesecure_v32.db', 'User')
```

#### **macOS/Linux:**
```bash
# Agregar a ~/.bashrc o ~/.zshrc
echo 'export PDF_SECURE_MASTER_KEY="tu_clave_aqui"' >> ~/.bashrc
echo 'export FILESECURE_SECRET_KEY="tu_clave_aqui"' >> ~/.bashrc
echo 'export DATABASE_URL="sqlite:///./filesecure_v32.db"' >> ~/.bashrc

# Recargar configuración
source ~/.bashrc
```

### **Paso 3: Inicializar Base de Datos**

Después de configurar las variables de entorno:

```bash
# Inicializar con datos por defecto
python -m app.scripts.init_data
```

Este script crea:
- ✅ 30+ permisos del sistema
- ✅ 6 roles predefinidos (SuperAdmin, OrgAdmin, DepartmentManager, Editor, Viewer, Auditor)
- ✅ Organización por defecto: "Default Organization"
- ✅ Departamento por defecto: "General"
- ✅ Usuario admin: `admin` / `Admin@123456` (⚠️ **CAMBIAR INMEDIATAMENTE**)
- ✅ Políticas por defecto (password, session, file, encryption, access, audit)

### **Paso 4: Verificar Instalación**

```bash
# Verificar base de datos
python -c "from app.core.database import DatabaseManager; db = DatabaseManager(); print('✅ Database OK' if db.check_health() else '❌ Database Error')"

# O ejecutar la aplicación
python run_app.py
```

Si todo está correcto, verás la GUI de File Secure v3.2 Enterprise.

### **Paso 5: Primer Login**

**Credenciales por defecto:**
- **Usuario**: `admin`
- **Contraseña**: `Admin@123456`

⚠️ **IMPORTANTE**: Cambia la contraseña inmediatamente después del primer login.

```bash
# Cambiar contraseña vía CLI (próximamente)
# O usar la GUI: Pestaña "Usuarios" → Seleccionar admin → "Cambiar Contraseña"
```

---

## 🎮 **Cómo Usar el Programa**

### **Opción 1: Interfaz Gráfica (GUI) - Para Principiantes**

La interfaz gráfica es la forma más fácil de usar el programa.

#### **Abrir la GUI:**

**Windows:**
```cmd
python app\app_gui.py
```

**macOS/Linux:**
```bash
python3 app/app_gui.py
```

Se abrirá una ventana con pestañas:

![GUI Screenshot](https://via.placeholder.com/800x400?text=PDF+Secure+GUI)

#### **Las Pestañas:**

1. **🔒 Cifrar PDF**: Para proteger tus archivos
2. **🔓 Descifrar PDF**: Para abrir archivos protegidos
3. **👥 Usuarios**: Gestionar claves de usuario
4. **🌐 IPs**: Configurar qué dispositivos pueden acceder
5. **📊 Logs**: Ver quién accedió a qué archivos
6. **ℹ️ Info**: Estadísticas e información del sistema

---

### **Opción 2: Línea de Comandos (CLI) - Para Usuarios Avanzados**

Si prefieres usar comandos en la terminal:

**Windows:**
```cmd
python app\main.py
```

**macOS/Linux:**
```bash
python3 app/main.py
```

Verás un menú interactivo:

```
🔧 MENÚ PRINCIPAL
------------------------------
1. 🔒 Cifrar PDF
2. 🔓 Descifrar PDF
3. 📋 Ver información de archivo
4. 👥 Gestionar usuarios
5. 🌐 Gestionar IPs autorizadas
6. 📊 Ver logs de acceso
7. 🧹 Mantenimiento
8. ❓ Ayuda
9. 🚪 Salir
```

Simplemente escribe el número de la opción que quieres y presiona Enter.

---

## 📚 **Ejemplos Prácticos**

### **Ejemplo 1: Proteger un PDF para 3 Personas**

#### **Usando la GUI:**

1. **Abre la GUI**: `python3 app/app_gui.py`

2. **Ve a la pestaña "🔒 Cifrar PDF"**

3. **Selecciona tu PDF:**
   - Click en "Examinar"
   - Busca y selecciona tu archivo (ej: `contrato_secreto.pdf`)

4. **El archivo de salida se autocompleta** (ej: `contrato_secreto.enc`)

5. **Ingresa los usuarios autorizados:**
   ```
   juan, maria, carlos
   ```

6. **Click en "🔒 Cifrar PDF"**

7. **¡Aparecen las claves!** En la parte inferior verás:
   ```
   🔑 CLAVES DE USUARIO GENERADAS:
   ==================================================
   
   👤 juan
   🔑 Clave: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
   
   👤 maria
   🔑 Clave: z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0
   
   👤 carlos
   🔑 Clave: m3n4o5p6q7r8s9t0a1b2c3d4e5f6g7h8i9j0k1l2
   ```

8. **¡MUY IMPORTANTE!** 
   - Click en "📋 Copiar Claves"
   - Pega las claves en un archivo de texto
   - Guarda el archivo de forma segura
   - Envía a cada persona su clave por un canal seguro (NO por email)

#### **Usando el CLI:**

```bash
# 1. Ejecuta el programa
python3 app/main.py

# 2. Selecciona opción 1
Selecciona una opción: 1

# 3. Sigue las instrucciones:
📄 Ruta del archivo PDF: /home/usuario/documentos/contrato_secreto.pdf
💾 Archivo de salida [/home/usuario/documentos/contrato_secreto.enc]: 
👥 Usuarios autorizados (separados por comas):
Usuarios: juan, maria, carlos

# 4. El programa genera las claves automáticamente
🔄 Cifrando 'contrato_secreto.pdf'...
✅ PDF cifrado exitosamente: contrato_secreto.enc

🔑 CLAVES DE USUARIO GENERADAS:
--------------------------------------------------
👤 juan
   Clave: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0

👤 maria
   Clave: z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0

👤 carlos
   Clave: m3n4o5p6q7r8s9t0a1b2c3d4e5f6g7h8i9j0k1l2

⚠️  IMPORTANTE: Guarda estas claves de forma segura.
   Cada usuario necesita su clave para acceder al PDF.
```

---

### **Ejemplo 2: Abrir un PDF Protegido**

Imagina que María recibió el archivo `contrato_secreto.enc` y su clave.

#### **Usando la GUI:**

1. **Abre la GUI**: `python3 app/app_gui.py`

2. **Ve a la pestaña "🔓 Descifrar PDF"**

3. **Selecciona el archivo cifrado:**
   - Click en "Examinar"
   - Busca `contrato_secreto.enc`

4. **Ingresa tu clave:**
   ```
   z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0
   ```
   
5. **(Opcional) Marca "Mostrar clave"** para verificar que la escribiste bien

6. **Click en "🔓 Descifrar PDF"**

7. **¡Listo!** El PDF descifrado aparece en la misma carpeta con un nombre como:
   ```
   decrypted_20250115_143022_contrato_secreto.pdf
   ```

#### **Usando el CLI:**

```bash
# 1. Ejecuta el programa
python3 app/main.py

# 2. Selecciona opción 2
Selecciona una opción: 2

# 3. Ingresa los datos:
🔒 Ruta del archivo cifrado (.enc): contrato_secreto.enc
🔑 Clave de usuario: z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0
💾 Archivo de salida (opcional): 

# 4. ¡El archivo se descifra!
🔄 Descifrando 'contrato_secreto.enc'...
✅ PDF descifrado exitosamente: decrypted_20250115_143022_contrato_secreto.pdf
```

---

### **Ejemplo 3: Restringir Acceso por IP (Opcional)**

Si quieres que solo ciertos dispositivos puedan descifrar archivos:

#### **Usando la GUI:**

1. **Ve a la pestaña "🌐 IPs"**

2. **Verás tu IP actual** en la parte superior

3. **Para agregar tu IP actual:**
   - Click en "➕ IP Actual" (se llena automáticamente)
   - Ingresa descripción: `Mi laptop personal`
   - Click en "➕ Agregar IP"

4. **Para agregar otra IP:**
   - Escribe la IP manualmente: `192.168.1.105`
   - Descripción: `PC de la oficina`
   - Click en "➕ Agregar IP"

5. **Para eliminar una IP:**
   - Selecciona la IP en la lista
   - Click en "❌ Eliminar"

---

## ❓ **Preguntas Frecuentes**

### **¿Qué pasa si pierdo las claves de usuario?**

❌ **No se pueden recuperar**. Las claves se generan una sola vez y no se almacenan en ningún lugar accesible. Por eso es **MUY IMPORTANTE** guardarlas de forma segura.

**Solución preventiva**: Siempre guarda las claves en un gestor de contraseñas o documento cifrado.

---

### **¿Qué pasa si pierdo la clave maestra?**

❌ **No podrás descifrar ningún archivo existente**. La clave maestra es la base de todo el sistema de cifrado.

**Solución preventiva**: 
1. Guarda tu clave maestra en un lugar seguro (gestor de contraseñas, USB cifrado)
2. Haz backups de la carpeta `~/.pdf_secure/`

---

### **¿Puedo usar el mismo archivo cifrado en diferentes computadoras?**

✅ **Sí**, siempre que:
1. Tengas la clave de usuario correcta
2. La clave maestra sea la misma en ambas computadoras
3. Si usas whitelist de IPs, la IP de la otra computadora esté autorizada

---

### **¿Las claves expiran?**

✅ **Sí**, por defecto expiran después de **30 días** desde su creación.

**Para extender la expiración:**
- **GUI**: Pestaña "👥 Usuarios" → Selecciona la clave → Click en "⏰ Extender"
- **CLI**: Menú principal → Opción 4 → Opción 3

---

### **¿Puedo revocar el acceso a un usuario?**

✅ **Sí**, en cualquier momento.

**Para revocar:**
- **GUI**: Pestaña "👥 Usuarios" → Selecciona la clave → Click en "❌ Revocar"
- **CLI**: Menú principal → Opción 4 → Opción 2

Una vez revocada, esa clave ya no funcionará para descifrar archivos.

---

### **¿Es seguro compartir el archivo .enc por email?**

✅ **Sí**, el archivo `.enc` está cifrado con AES-256 (nivel militar). Sin la clave de usuario correcta, es imposible descifrarlo.

⚠️ **PERO**: Nunca envíes la clave por el mismo canal que el archivo. Usa canales diferentes:
- Archivo `.enc` → Email
- Clave → WhatsApp, Signal, o en persona

---

### **¿Puedo ver quién accedió a mis archivos?**

✅ **Sí**, el sistema registra todo.

**Para ver los logs:**
- **GUI**: Pestaña "📊 Logs"
- **CLI**: Menú principal → Opción 6

Verás información como:
- Usuario que accedió
- Fecha y hora
- Archivo accedido
- IP desde donde se accedió
- Si el acceso fue exitoso o fallido

---

## 🐛 **Solución de Problemas**

### **Problema: "PDF_SECURE_MASTER_KEY no encontrada"**

**Causa**: No configuraste la clave maestra.

**Solución**:
```bash
# macOS/Linux:
export PDF_SECURE_MASTER_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# Windows (PowerShell):
$key = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:PDF_SECURE_MASTER_KEY = $key
```

---

### **Problema: "No module named 'cryptography'"**

**Causa**: No instalaste las dependencias.

**Solución**:
```bash
pip install cryptography
# o
pip3 install cryptography
```

---

### **Problema: "Tkinter no está disponible" (Linux)**

**Causa**: Linux no incluye tkinter por defecto.

**Solución**:
```bash
# Ubuntu/Debian:
sudo apt-get install python3-tk

# Fedora/RHEL:
sudo dnf install python3-tkinter

# Arch Linux:
sudo pacman -S tk
```

Luego vuelve a ejecutar la GUI.

---

### **Problema: La GUI no abre o se cierra inmediatamente**

**Causa posible 1**: Error en algún archivo de código.

**Solución**: Usa el CLI en su lugar:
```bash
python3 app/main.py
```

**Causa posible 2**: Problema con tkinter.

**Solución**: Verifica que tkinter funciona:
```bash
python3 -m tkinter
```
Debería abrir una ventana de prueba.

---

### **Problema: "Clave de usuario no válida"**

**Causas posibles**:
1. La clave está mal escrita (revisa mayúsculas, espacios)
2. La clave fue revocada
3. La clave expiró
4. El archivo cifrado está corrupto

**Solución**:
1. Verifica que copiaste la clave completa (sin espacios al inicio/final)
2. En la GUI, marca "Mostrar clave" para verificar
3. Contacta a quien cifró el archivo para verificar el estado de la clave

---

### **Problema: "IP no autorizada"**

**Causa**: Tu IP no está en la whitelist.

**Solución**:
1. Verifica tu IP actual: Ve a la pestaña "🌐 IPs" en la GUI
2. Agrega tu IP a la whitelist
3. O pide al administrador que agregue tu IP

---

## 🔒 **Seguridad y Buenas Prácticas**

### **✅ Recomendaciones de Seguridad**

1. **Gestión de Claves**:
   - ✅ Usa un gestor de contraseñas (LastPass, 1Password, Bitwarden)
   - ✅ Nunca compartas claves por email o chat
   - ✅ Cambia claves periódicamente (cada 30-60 días)
   - ❌ No escribas claves en papeles o archivos de texto sin cifrar

2. **Backups**:
   - ✅ Haz backup regular de `~/.pdf_secure/`
   - ✅ Guarda tu clave maestra en un lugar seguro
   - ✅ Documenta qué usuarios tienen acceso a qué archivos

3. **Monitoreo**:
   - ✅ Revisa los logs semanalmente
   - ✅ Investiga intentos de acceso fallidos
   - ✅ Limpia claves expiradas regularmente

4. **Control de Acceso**:
   - ✅ Usa whitelist de IPs cuando sea posible
   - ✅ Revoca acceso inmediatamente cuando sea necesario
   - ✅ Usa descripciones claras para cada IP autorizada

---

### **⚠️ Limitaciones Conocidas**

1. **Trazabilidad post-descifrado**: Una vez que alguien descifra el PDF, puede copiarlo sin restricciones. El PDF descifrado no tiene protección adicional.

2. **Dependencia de clave maestra**: Si pierdes la clave maestra, pierdes acceso a TODOS los archivos cifrados.

3. **IP local únicamente**: El control de IP solo funciona en red local, no identifica dispositivos específicos de forma única.

---

## 📞 **Soporte y Contacto**

### **¿Necesitas Ayuda?**

1. **Revisa este README** primero (especialmente la sección de Problemas)
2. **Consulta la ayuda integrada**: 
   - GUI: Pestaña "ℹ️ Info"
   - CLI: Opción 8 (Ayuda)
3. **Issues en GitHub**: [github.com/zeligmax/proyecto_pdf_seguro/issues](https://github.com/zeligmax/proyecto_pdf_seguro/issues)

---

## 🤝 **Contribuir**

¿Quieres mejorar PDF Secure? ¡Las contribuciones son bienvenidas!

1. Fork del repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

---

---

## 🔄 **Migración desde v3.1**

### **¿Tengo que migrar?**

Si ya usabas File Secure v3.1, tienes dos opciones:

1. **Migración automática**: Importa tus datos de v3.1 a v3.2
2. **Empezar de cero**: Usa v3.2 sin migrar datos antiguos

### **Proceso de Migración Automática**

File Secure v3.2 incluye un **script de migración automática** que:

✅ **Preserva**:
- Claves de usuario existentes
- Logs de acceso históricos
- Whitelist de IPs
- Configuración del sistema

✅ **Crea**:
- Organización "Default Organization"
- Departamento "General"
- Políticas por defecto
- Usuario admin con rol SuperAdmin

✅ **Convierte**:
- Claves de usuario → FileAccess entries
- Logs v3.1 → AuditLog entries
- IPs autorizadas → Políticas de acceso

#### **Pasos para Migrar:**

```bash
# 1. Hacer backup de tu instalación v3.1
cp -r ~/.pdf_secure ~/.pdf_secure_backup

# 2. Instalar v3.2
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro
pip install -r requirements.txt

# 3. Configurar variables de entorno (igual que en v3.1)
export PDF_SECURE_MASTER_KEY="tu_clave_maestra_v31"  # ⚠️ USAR LA MISMA CLAVE
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY
export DATABASE_URL="sqlite:///./filesecure_v32.db"

# 4. Ejecutar script de migración
python -m app.scripts.migrate_v31_to_v32

# 5. Verificar migración
python run_app.py
```

**Salida esperada del script:**

```
🔄 Migrando datos de File Secure v3.1 a v3.2...
==================================================
📂 Directorio v3.1: /home/usuario/.pdf_secure

✅ Organización creada: Default Organization
✅ Departamento creado: General
✅ Migrados 15 claves de usuario
✅ Migradas 8 IPs autorizadas
✅ Migrados 234 logs de acceso
✅ Creadas 6 políticas por defecto

📊 RESUMEN DE MIGRACIÓN:
==================================================
👥 Usuarios migrados: 15
📝 Logs migrados: 234
🌐 IPs migradas: 8
✅ Estado: EXITOSO
```

### **Compatibilidad de Archivos Cifrados**

**¿Los archivos .enc de v3.1 funcionan en v3.2?**

✅ **Sí, completamente compatibles**. Los archivos cifrados con v3.1 pueden descifrarse en v3.2 sin cambios.

**Requisitos:**
- Usar la **misma clave maestra** en v3.2
- Las claves de usuario deben estar migradas
- El usuario debe existir en v3.2

### **Cambios que debes conocer**

#### **Cambios en la Base de Datos**
- v3.1: Archivos JSON en `~/.pdf_secure/`
- v3.2: Base de datos SQLite o PostgreSQL

#### **Nuevas Características en GUI**
- **Login con usuario/contraseña**: Ahora la GUI requiere autenticación
- **Selector de organización**: Si tienes múltiples organizaciones
- **Dashboard ejecutivo**: Nueva pestaña con métricas
- **Gestión de roles**: Asignar permisos a usuarios

#### **Cambios en CLI**
- El CLI de v3.1 sigue funcionando igual
- Nuevos comandos para RBAC y organizaciones

### **Solución de Problemas en Migración**

#### **Problema: "No se encontró directorio v3.1"**

```bash
# Verifica que existe ~/.pdf_secure/
ls -la ~/.pdf_secure/

# Si no existe, no tienes datos v3.1 para migrar
# Puedes empezar de cero con:
python -m app.scripts.init_data
```

#### **Problema: "Clave maestra no coincide"**

La clave maestra de v3.2 **DEBE SER LA MISMA** que usabas en v3.1.

```bash
# Verificar tu clave v3.1 (si la guardaste)
cat ~/mis_claves_backup.txt

# Configurarla en v3.2
export PDF_SECURE_MASTER_KEY="tu_clave_original_v31"
```

#### **Problema: "Usuarios duplicados"**

Si ejecutas el script de migración múltiples veces, puede crear usuarios duplicados.

```bash
# Solución: Eliminar base de datos y volver a migrar
rm filesecure_v32.db
python -m app.scripts.migrate_v31_to_v32
```

### **Migración Selectiva (Avanzado)**

Si solo quieres migrar ciertas cosas, puedes editar el script:

```python
# app/scripts/migrate_v31_to_v32.py

migrator = DataMigrator(db_manager)

# Descomentar solo lo que quieres migrar:
migrator._migrate_user_keys(session, org_id, dept_id)  # Claves de usuario
# migrator._migrate_ip_whitelist(session)              # IPs (comentado)
# migrator._migrate_access_logs(session, org_id)       # Logs (comentado)
```

---

## 📜 **Licencia**

Este proyecto está licenciado bajo la Licencia MIT. Ver archivo [LICENSE.md](LICENSE.md) para más detalles.

---

## 👨‍💻 **Autor**

**Desarrollado por**: Zeligmax
**Versión**: 3.2 Enterprise Edition
**Fecha**: Enero 2025

### **Historial de Versiones**

#### **v3.2 Enterprise (Enero 2025)** - Transformación Empresarial
- 🏢 **Multi-Tenancy**: Organizaciones y departamentos aislados
- 👥 **RBAC Completo**: 6 roles predefinidos + 30+ permisos granulares
- 📊 **Auditoría Centralizada**: PostgreSQL con búsqueda avanzada
- ⚙️ **Políticas Configurables**: 6 tipos de políticas personalizables
- 🔌 **REST API v1**: JWT authentication + decoradores de seguridad
- 📈 **Dashboard Ejecutivo**: KPIs y métricas en tiempo real
- 🐳 **Docker Ready**: docker-compose para deployment empresarial
- 🗄️ **PostgreSQL**: Base de datos empresarial con alta disponibilidad
- 🔄 **Script de Migración**: Migración automática desde v3.1
- 🔐 **Password Policies**: Complejidad, expiración, bloqueo de cuentas

#### **v3.1 (Diciembre 2024)** - Soporte Multi-formato
- 🎯 **Renombramiento**: De "PDF Secure" a "File Secure"
- 📁 **Soporte Multi-formato**: PDF, DOCX, XLSX, TXT, PBIP, PBIX
- 👁️ **Múltiples Visualizadores**: Por tipo de archivo
- 🔄 **Compatibilidad**: Con archivos v2.x

#### **v2.1 (Noviembre 2024)** - Visualización en Memoria
- 👁️ **Visualizador en Memoria**: Ver PDFs sin guardar en disco
- 🔐 **Metadatos Cifrados**: Mayor seguridad
- 📝 **Logs Diferenciados**: VIEW_ATTEMPT vs DECRYPT_ATTEMPT
- 🔑 **Verificación de Usuario**: Clave + usuario del sistema

#### **v2.0 (Octubre 2024)** - Base Sólida
- 🔐 **Cifrado AES-256**: Seguridad de nivel militar
- 👥 **Claves por Usuario**: Sistema de permisos básico
- 📊 **Logs de Acceso**: Auditoría básica
- 🌐 **IP Whitelist**: Control de dispositivos

---

## 🙏 **Agradecimientos**

Agradecimientos especiales a todos los colaboradores y revisores técnicos que hicieron posible File Secure v3.2 Enterprise Edition, especialmente por las contribuciones en seguridad, arquitectura multi-tenant y RBAC.

---

## 🚀 **¿Listo para Empezar?**

### **Instalación Rápida (5 minutos)**

```bash
# 1. Clonar repositorio
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar variables de entorno
export PDF_SECURE_MASTER_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
export FILESECURE_SECRET_KEY=$PDF_SECURE_MASTER_KEY

# 4. Inicializar base de datos
python -m app.scripts.init_data

# 5. Ejecutar aplicación
python run_app.py

# Credenciales por defecto:
# Usuario: admin
# Contraseña: Admin@123456
```

### **Deployment con Docker (Producción)**

```bash
# 1. Configurar variables
cp docker/.env.example docker/.env
# Editar docker/.env

# 2. Iniciar servicios
cd docker && docker-compose up -d

# 3. Inicializar base de datos
export DATABASE_URL="postgresql://filesecure:SecurePass2025@localhost:5432/filesecure_v3"
python -m app.scripts.init_data

# 4. Ejecutar API
python run_api_v32.py
```

### **Migración desde v3.1**

```bash
# Si ya usabas v3.1, migra tus datos automáticamente:
python -m app.scripts.migrate_v31_to_v32
```

---

### **📚 Documentación Adicional**

- 🚀 **Quick Start**: [QUICKSTART_V3.2.md](QUICKSTART_V3.2.md)
- 🐳 **Docker Deployment**: [docker/README.md](docker/README.md)
- 🔌 **API Documentation**: Próximamente
- 🔄 **Migration Guide**: Ver sección [Migración desde v3.1](#-migración-desde-v31)

---

**💡 Recuerda**:
- Cambia la contraseña del admin inmediatamente
- Guarda tu clave maestra en un lugar seguro
- Configura políticas de seguridad para tu organización
- Revisa los logs de auditoría regularmente

---

<div align="center">

**Si este proyecto te resultó útil, ¡dale una ⭐ en GitHub!**

### **File Secure v3.2 Enterprise Edition**
*Cifrado de archivos de nivel empresarial con multi-tenancy y RBAC*

[⬆ Volver arriba](#-file-secure-v32-enterprise---guía-completa)

</div>