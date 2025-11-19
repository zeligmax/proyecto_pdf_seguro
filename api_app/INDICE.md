# 📑 Índice de Archivos - API App

## 🎯 Archivos Principales

### 🔧 Módulos Core

| Archivo | Líneas | Descripción | Uso |
|---------|--------|-------------|-----|
| **`system_users.py`** | ~400 | Detecta usuarios del sistema operativo (Windows/Linux/macOS) | Importar clase `SystemUsersDetector` |
| **`users_api.py`** | ~300 | API REST con Flask, endpoints para consultar usuarios | Ejecutar servidor o importar `app` |
| **`run_api.py`** | ~20 | Script de ejecución del servidor | `python run_api.py` |
| **`__init__.py`** | ~10 | Inicialización del paquete Python | Import automático |

---

## 🧪 Scripts de Prueba

| Archivo | Propósito | Comando |
|---------|-----------|---------|
| **`test_api.py`** | Suite de 7 tests automáticos | `python test_api.py` |
| **`quien_soy.py`** | Ver información del usuario actual | `python quien_soy.py` |
| **`ejemplo_uso_api.py`** | Ejemplos de uso de la API | `python ejemplo_uso_api.py` |

---

## 📚 Documentación

| Archivo | Contenido |
|---------|-----------|
| **`README.md`** | Guía de inicio rápido y uso |
| **`INDICE.md`** | Este archivo |

---

## 🔍 Descripción Detallada

### `system_users.py`

**Clase Principal:** `SystemUsersDetector`

**Métodos Públicos:**
- `get_system_info()` - Info del sistema operativo
- `get_current_user()` - Usuario actual
- `get_all_users()` - Lista todos los usuarios
- `get_logged_in_users()` - Usuarios conectados
- `get_user_groups(username)` - Grupos de un usuario
- `get_complete_report()` - Reporte completo

**Soporta:**
- ✅ Windows (WMI + comando net user)
- ✅ Linux (lectura de /etc/passwd)
- ✅ macOS (comando dscl)

---

### `users_api.py`

**Framework:** Flask + Flask-CORS

**Endpoints Implementados:**

| Ruta | Método | Descripción |
|------|--------|-------------|
| `/` | GET | Info general de la API |
| `/api/docs` | GET | Documentación |
| `/api/system` | GET | Info del sistema |
| `/api/users` | GET | Lista de usuarios |
| `/api/users/current` | GET | Usuario actual |
| `/api/users/logged` | GET | Usuarios conectados |
| `/api/users/<username>` | GET | Info de usuario específico |
| `/api/users/<username>/groups` | GET | Grupos del usuario |
| `/api/report` | GET | Reporte completo |
| `/api/health` | GET | Estado de la API |

**Parámetros Query:**
- `filter` - all/human/system
- `format` - json/simple

---

### `run_api.py`

**Configuración por defecto:**
```python
host='0.0.0.0'    # Todas las interfaces
port=5000         # Puerto estándar
debug=True        # Modo desarrollo
```

**Personalizar:**
```bash
python users_api.py --host 127.0.0.1 --port 8080 --debug
```

---

## 📊 Tamaño de Archivos

```
system_users.py    ~400 líneas  (~15 KB)
users_api.py       ~300 líneas  (~12 KB)
test_api.py        ~200 líneas  (~8 KB)
ejemplo_uso_api.py ~150 líneas  (~6 KB)
quien_soy.py       ~50 líneas   (~2 KB)
run_api.py         ~20 líneas   (~1 KB)
```

---

## 🔄 Flujo de Ejecución

### Iniciar API

```
run_api.py
    ↓
users_api.py (importa)
    ↓
system_users.py (usa clase)
    ↓
Detecta SO y ejecuta comandos apropiados
    ↓
Retorna datos en formato JSON
```

### Cliente Hace Request

```
Cliente (curl/browser/python)
    ↓
GET /api/users
    ↓
users_api.py procesa
    ↓
Llama a SystemUsersDetector
    ↓
Retorna JSON al cliente
```

---

## 🎯 Casos de Uso

### 1. Validar Usuario Antes de Cifrar PDF

```python
from system_users import SystemUsersDetector

detector = SystemUsersDetector()
usuarios_sistema = [u['username'] for u in detector.get_all_users()]

if 'john' in usuarios_sistema:
    print("Usuario válido")
```

### 2. Obtener Lista de Usuarios para Autocompletar

```python
import requests

response = requests.get('http://localhost:5000/api/users?format=simple')
usuarios = response.json()['users']

# Usar en GUI
combobox.configure(values=usuarios)
```

### 3. Monitorear Usuarios Conectados

```python
import requests
import time

while True:
    response = requests.get('http://localhost:5000/api/users/logged')
    data = response.json()
    print(f"Usuarios conectados: {data['count']}")
    time.sleep(60)
```

---

## 🧪 Ejecutar Tests

### Test Individual

```bash
cd api_app
python test_api.py
```

### Test con Reporte

```bash
python test_api.py > test_results.txt 2>&1
```

### Ver Usuario Actual

```bash
python quien_soy.py
```

### Ejemplos Completos

```bash
python ejemplo_uso_api.py
```

---

## 🔗 Integración con Otros Módulos

### Desde el proyecto principal

```python
# En app/main.py o app/app_gui.py
import sys
sys.path.append('api_app')

from system_users import SystemUsersDetector

detector = SystemUsersDetector()
usuarios = detector.get_all_users()
```

### Como API REST

```python
import requests

# Desde cualquier parte del sistema
def obtener_usuarios():
    response = requests.get('http://localhost:5000/api/users')
    return response.json()['data']
```

---

## 📝 Dependencias

### Requeridas

```
flask>=2.3.3
flask-cors>=4.0.0
```

### Opcionales (mejoran detección en Windows)

```
pywin32  # Para WMI en Windows
```

### Instalación

```bash
pip install flask flask-cors
pip install pywin32  # Opcional, solo Windows
```

---

## 🔧 Mantenimiento

### Actualizar Versión

Editar `__init__.py`:
```python
__version__ = '1.1.0'
```

### Agregar Nuevo Endpoint

1. Editar `users_api.py`
2. Agregar ruta con `@app.route()`
3. Actualizar documentación en `/api/docs`
4. Agregar test en `test_api.py`

### Agregar Soporte para Nuevo SO

1. Editar `system_users.py`
2. Agregar método `_get_<sistema>_users()`
3. Actualizar `get_all_users()` para detectar nuevo SO
4. Agregar tests específicos

---

**📌 Nota:** Todos los scripts están configurados con encoding UTF-8 para Windows y funcionan correctamente con emojis.
