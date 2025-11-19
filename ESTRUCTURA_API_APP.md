# 📁 Estructura de la Carpeta API App

La carpeta **`api_app/`** contiene todos los archivos relacionados con la API de Detección de Usuarios del sistema.

---

## 🎯 Contenido de `api_app/`

```
api_app/
├── 📄 __init__.py              # Inicialización del paquete Python
├── 🔧 system_users.py          # Módulo de detección de usuarios
├── 🌐 users_api.py             # API REST con Flask
├── ▶️  run_api.py               # Script para ejecutar el servidor
├── 🧪 test_api.py              # Suite de pruebas (7 tests)
├── 👤 quien_soy.py             # Script para ver tu usuario
├── 💡 ejemplo_uso_api.py       # Ejemplos de uso de la API
├── 📚 README.md                # Documentación de la API
└── 📑 INDICE.md                # Índice detallado de archivos
```

---

## 🚀 Cómo Usar

### Opción 1: Desde la Raíz del Proyecto

```bash
# Ejecutar la API
python run_users_api.py

# O directamente
python api_app/run_api.py
```

### Opción 2: Desde Dentro de api_app

```bash
cd api_app

# Ejecutar la API
python run_api.py

# Ver tu usuario
python quien_soy.py

# Ejecutar tests
python test_api.py

# Ver ejemplos
python ejemplo_uso_api.py
```

---

## 📊 Descripción de Archivos

### Archivos Principales

#### `system_users.py` (~400 líneas)
- **Propósito:** Detectar usuarios del sistema operativo
- **Clase:** `SystemUsersDetector`
- **Soporta:** Windows, Linux, macOS
- **Métodos principales:**
  - `get_all_users()` - Lista todos los usuarios
  - `get_current_user()` - Usuario actual
  - `get_logged_in_users()` - Usuarios conectados
  - `get_user_groups()` - Grupos de un usuario
  - `get_system_info()` - Info del sistema

#### `users_api.py` (~300 líneas)
- **Propósito:** API REST con Flask
- **Framework:** Flask + Flask-CORS
- **Puerto:** 5000 (por defecto)
- **Endpoints:** 10 endpoints disponibles
- **Formato:** JSON

#### `run_api.py` (~20 líneas)
- **Propósito:** Script de ejecución del servidor
- **Configuración:**
  - Host: 0.0.0.0 (todas las interfaces)
  - Port: 5000
  - Debug: True (modo desarrollo)

### Scripts de Utilidad

#### `test_api.py` (~200 líneas)
- **Propósito:** Suite de 7 tests automáticos
- **Valida:**
  - Detección del sistema
  - Información del sistema
  - Usuario actual
  - Lista de usuarios
  - Usuarios conectados
  - Grupos de usuario
  - Reporte completo

#### `quien_soy.py` (~50 líneas)
- **Propósito:** Muestra información del usuario actual
- **Salida:**
  - Nombre de usuario
  - Directorio home
  - Si es administrador
  - Grupos del usuario
  - Info del sistema

#### `ejemplo_uso_api.py` (~150 líneas)
- **Propósito:** Ejemplos de cómo usar la API
- **Incluye:**
  - Cliente Python para la API
  - Demos de uso básico
  - Validación de usuarios
  - Detalles de usuario
  - Ejemplo de integración

### Documentación

#### `README.md`
- Guía de inicio rápido
- Lista de endpoints
- Ejemplos de uso
- Configuración
- Solución de problemas

#### `INDICE.md`
- Índice detallado de todos los archivos
- Descripción de métodos
- Flujo de ejecución
- Casos de uso
- Instrucciones de mantenimiento

---

## 🔗 Integración

### Desde el Proyecto Principal

```python
# En app/main.py o cualquier otro archivo
import sys
sys.path.insert(0, 'api_app')

from system_users import SystemUsersDetector

detector = SystemUsersDetector()
usuarios = detector.get_all_users()
```

### Como API REST

```python
import requests

# Consultar la API
response = requests.get('http://localhost:5000/api/users')
data = response.json()
```

---

## 📡 Endpoints de la API

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/` | GET | Información general |
| `/api/docs` | GET | Documentación |
| `/api/system` | GET | Info del sistema |
| `/api/users` | GET | Lista de usuarios |
| `/api/users/current` | GET | Usuario actual |
| `/api/users/logged` | GET | Usuarios conectados |
| `/api/users/<user>` | GET | Info de usuario |
| `/api/users/<user>/groups` | GET | Grupos |
| `/api/report` | GET | Reporte completo |
| `/api/health` | GET | Estado de la API |

---

## 🧪 Ejecutar Tests

### Test Completo
```bash
cd api_app
python test_api.py
```

**Salida esperada:**
```
✅ Test 1 PASADO - Detección del Sistema
✅ Test 2 PASADO - Información del Sistema
✅ Test 3 PASADO - Usuario Actual
✅ Test 4 PASADO - Lista de Usuarios
✅ Test 5 PASADO - Usuarios Conectados
✅ Test 6 PASADO - Grupos del Usuario
✅ Test 7 PASADO - Reporte Completo

🎉 ¡TODOS LOS TESTS PASARON!
```

### Verificar Tu Usuario
```bash
cd api_app
python quien_soy.py
```

---

## 📦 Dependencias

### Requeridas
```bash
pip install flask flask-cors
```

### Opcionales (Windows)
```bash
pip install pywin32  # Mejora detección en Windows
```

---

## 🔧 Configuración Personalizada

### Cambiar Puerto

**Opción 1:** Editar `run_api.py`
```python
run_api(
    host='0.0.0.0',
    port=8080,  # Cambiar aquí
    debug=True
)
```

**Opción 2:** Usar argumentos
```bash
python users_api.py --port 8080
```

### Solo Localhost
```python
run_api(
    host='127.0.0.1',  # Solo local
    port=5000,
    debug=False
)
```

---

## 🎯 Casos de Uso

### 1. Validar Usuario Antes de Cifrar

```python
from system_users import SystemUsersDetector

detector = SystemUsersDetector()
all_users = detector.get_all_users()
usernames = [u['username'] for u in all_users]

if 'john' in usernames:
    print("Usuario válido para cifrado")
```

### 2. Autocompletar en GUI

```python
import requests

response = requests.get('http://localhost:5000/api/users?format=simple')
usuarios = response.json()['users']

# Usar en tkinter, PyQt, etc.
combobox.configure(values=usuarios)
```

### 3. Monitoreo de Sesiones

```python
import requests
import time

while True:
    response = requests.get('http://localhost:5000/api/users/logged')
    logged = response.json()
    print(f"Usuarios conectados: {logged['count']}")
    time.sleep(60)
```

---

## 📝 Mantenimiento

### Actualizar API

1. Editar archivos en `api_app/`
2. Ejecutar tests: `python test_api.py`
3. Reiniciar servidor

### Agregar Nuevo Endpoint

1. Editar `users_api.py`
2. Agregar función con `@app.route()`
3. Actualizar documentación
4. Agregar test en `test_api.py`

---

## 🔐 Seguridad

⚠️ **Importante:**

- La API expone información del sistema
- **NO** exponerla públicamente sin autenticación
- Usar solo en redes locales/protegidas
- Considerar rate limiting en producción
- Implementar autenticación si es necesario

---

## 📚 Documentación Adicional

En el directorio raíz del proyecto:

- **[API_USERS_GUIDE.md](API_USERS_GUIDE.md)** - Guía completa de la API
- **[QUICKSTART_API.md](QUICKSTART_API.md)** - Inicio rápido
- **[CHANGELOG_API.md](CHANGELOG_API.md)** - Registro de cambios
- **[CORRECCIONES_APLICADAS.md](CORRECCIONES_APLICADAS.md)** - Bugs corregidos

---

## ✨ Resumen

La carpeta `api_app/` es un **módulo independiente** que contiene:

✅ **Sistema de detección** de usuarios multiplataforma
✅ **API REST** completa con Flask
✅ **10 endpoints** funcionales
✅ **Scripts de prueba** y utilidad
✅ **Documentación** completa
✅ **Ejemplos de uso** en Python

**Todo listo para usar:** `python api_app/run_api.py` 🚀
