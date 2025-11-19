# 🔍 API de Detección de Usuarios del Sistema - Guía de Uso

> API REST para detectar y listar usuarios del sistema operativo (Windows/Linux/macOS)

---

## 📖 Tabla de Contenidos

1. [Introducción](#-introducción)
2. [Instalación](#-instalación)
3. [Iniciar el Servidor](#-iniciar-el-servidor)
4. [Endpoints Disponibles](#-endpoints-disponibles)
5. [Ejemplos de Uso](#-ejemplos-de-uso)
6. [Integración con el Sistema PDF Secure](#-integración-con-el-sistema-pdf-secure)
7. [Solución de Problemas](#-solución-de-problemas)

---

## 🚀 Introducción

Esta API permite detectar y obtener información sobre los usuarios del sistema operativo donde se ejecuta. Es útil para:

✅ Detectar usuarios disponibles en un servidor/ordenador
✅ Validar usuarios autorizados antes de cifrar PDFs
✅ Auditoría de usuarios del sistema
✅ Monitoreo de sesiones activas
✅ Gestión de permisos y grupos

### Características Principales

- 🖥️ **Multiplataforma**: Funciona en Windows, Linux y macOS
- 🔐 **Seguro**: Solo expone información del sistema local
- 📊 **Completo**: Incluye información de usuarios, grupos, y sesiones
- 🚀 **Rápido**: API REST con respuestas en JSON
- 📖 **Documentado**: Documentación integrada en `/api/docs`

---

## 📥 Instalación

### Paso 1: Instalar Dependencias

Las dependencias ya están incluidas en el archivo `requirements.txt` del proyecto.

**En Windows:**
```cmd
pip install flask flask-cors
```

**En macOS/Linux:**
```bash
pip3 install flask flask-cors
```

### Paso 2: Verificar Instalación

```bash
# Verificar que los archivos existen
ls app/system_users.py
ls app/users_api.py
ls run_users_api.py
```

---

## 🏃 Iniciar el Servidor

### Opción 1: Usando el Script de Ejecución (Recomendado)

**Windows:**
```cmd
python run_users_api.py
```

**macOS/Linux:**
```bash
python3 run_users_api.py
```

### Opción 2: Ejecución Directa

**Windows:**
```cmd
cd app
python users_api.py
```

**macOS/Linux:**
```bash
cd app
python3 users_api.py
```

### Opción 3: Con Parámetros Personalizados

```bash
# Cambiar puerto y host
python3 app/users_api.py --host 127.0.0.1 --port 8080

# Habilitar modo debug
python3 app/users_api.py --debug
```

### Salida Esperada

```
============================================================
🚀 System Users Detection API v1.0.0
============================================================
📡 Servidor: http://0.0.0.0:5000
📋 Documentación: http://0.0.0.0:5000/api/docs
🔍 Sistema detectado: Windows
============================================================

💡 Endpoints disponibles:
  GET http://0.0.0.0:5000/api/system
  GET http://0.0.0.0:5000/api/users
  GET http://0.0.0.0:5000/api/users/current
  GET http://0.0.0.0:5000/api/users/logged
  GET http://0.0.0.0:5000/api/report
  GET http://0.0.0.0:5000/api/health

⏸️  Presiona Ctrl+C para detener el servidor
```

---

## 📡 Endpoints Disponibles

### 1. Información de la API

**GET /** o **GET /api/docs**

Muestra información general de la API y documentación.

**Ejemplo:**
```bash
curl http://localhost:5000/
```

**Respuesta:**
```json
{
  "api": "System Users Detection API",
  "version": "1.0.0",
  "status": "running",
  "timestamp": "2025-01-19T10:30:00",
  "endpoints": {
    "GET /": "Información de la API",
    "GET /api/system": "Información del sistema",
    ...
  }
}
```

---

### 2. Información del Sistema

**GET /api/system**

Obtiene información general del sistema operativo.

**Ejemplo:**
```bash
curl http://localhost:5000/api/system
```

**Respuesta:**
```json
{
  "success": true,
  "data": {
    "os": "Windows",
    "os_version": "10.0.19041",
    "hostname": "DESKTOP-ABC123",
    "platform": "Windows-10-10.0.19041-SP0",
    "architecture": "AMD64",
    "processor": "Intel64 Family 6 Model 142 Stepping 12, GenuineIntel",
    "python_version": "3.10.5",
    "timestamp": "2025-01-19T10:30:00"
  }
}
```

---

### 3. Lista de Todos los Usuarios

**GET /api/users**

Lista todos los usuarios del sistema.

**Parámetros de consulta (query params):**
- `filter`: `all` (default), `human`, `system` - Filtra tipo de usuarios
- `format`: `json` (default), `simple` - Formato de respuesta

**Ejemplos:**

```bash
# Todos los usuarios (formato completo)
curl http://localhost:5000/api/users

# Solo usuarios humanos (no del sistema)
curl http://localhost:5000/api/users?filter=human

# Solo nombres de usuarios (formato simple)
curl http://localhost:5000/api/users?format=simple
```

**Respuesta (Windows):**
```json
{
  "success": true,
  "count": 3,
  "filter": "all",
  "data": [
    {
      "username": "Administrador",
      "full_name": "",
      "description": "Cuenta integrada para la administración del equipo",
      "disabled": false,
      "local_account": true,
      "sid": "S-1-5-21-...",
      "domain": "DESKTOP-ABC123"
    },
    {
      "username": "User",
      "full_name": "Usuario Principal",
      "description": "",
      "disabled": false,
      "local_account": true
    }
  ]
}
```

**Respuesta (Linux):**
```json
{
  "success": true,
  "count": 25,
  "data": [
    {
      "username": "root",
      "uid": 0,
      "gid": 0,
      "full_name": "root",
      "home_directory": "/root",
      "shell": "/bin/bash",
      "is_system_user": true,
      "has_login_shell": true
    },
    {
      "username": "usuario",
      "uid": 1000,
      "gid": 1000,
      "full_name": "Usuario Principal",
      "home_directory": "/home/usuario",
      "shell": "/bin/bash",
      "is_system_user": false,
      "has_login_shell": true
    }
  ]
}
```

---

### 4. Usuario Actual

**GET /api/users/current**

Obtiene información del usuario que está ejecutando la API.

**Ejemplo:**
```bash
curl http://localhost:5000/api/users/current
```

**Respuesta:**
```json
{
  "success": true,
  "data": {
    "username": "User",
    "home_directory": "C:\\Users\\User",
    "effective_uid": null,
    "is_admin": true
  }
}
```

---

### 5. Usuarios Conectados

**GET /api/users/logged**

Lista usuarios actualmente conectados al sistema.

**Ejemplo:**
```bash
curl http://localhost:5000/api/users/logged
```

**Respuesta (Windows):**
```json
{
  "success": true,
  "count": 2,
  "data": [
    {
      "username": "User",
      "session_name": "console",
      "state": "active"
    },
    {
      "username": "Admin",
      "session_name": "rdp-tcp#1",
      "state": "active"
    }
  ]
}
```

**Respuesta (Linux):**
```json
{
  "success": true,
  "count": 1,
  "data": [
    {
      "username": "usuario",
      "terminal": "pts/0",
      "login_time": "2025-01-19 10:00"
    }
  ]
}
```

---

### 6. Información de Usuario Específico

**GET /api/users/<username>**

Obtiene información detallada de un usuario específico.

**Ejemplo:**
```bash
curl http://localhost:5000/api/users/User
```

**Respuesta (si existe):**
```json
{
  "success": true,
  "exists": true,
  "data": {
    "username": "User",
    "full_name": "Usuario Principal",
    "description": "",
    "disabled": false,
    "local_account": true
  }
}
```

**Respuesta (si no existe):**
```json
{
  "success": true,
  "exists": false,
  "message": "Usuario \"UserX\" no encontrado"
}
```

---

### 7. Grupos de Usuario

**GET /api/users/<username>/groups**

Lista los grupos a los que pertenece un usuario.

**Ejemplo:**
```bash
curl http://localhost:5000/api/users/User/groups
```

**Respuesta:**
```json
{
  "success": true,
  "username": "User",
  "count": 3,
  "groups": [
    "Administradores",
    "Usuarios",
    "Usuarios de escritorio remoto"
  ]
}
```

---

### 8. Reporte Completo

**GET /api/report**

Genera un reporte completo con toda la información disponible.

**Ejemplo:**
```bash
curl http://localhost:5000/api/report
```

**Respuesta:**
```json
{
  "success": true,
  "generated_at": "2025-01-19T10:30:00",
  "data": {
    "system_info": { ... },
    "current_user": { ... },
    "all_users": [ ... ],
    "logged_in_users": [ ... ],
    "current_user_groups": [ ... ]
  }
}
```

---

### 9. Estado de Salud

**GET /api/health**

Verifica que la API está funcionando correctamente.

**Ejemplo:**
```bash
curl http://localhost:5000/api/health
```

**Respuesta:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-19T10:30:00",
  "version": "1.0.0",
  "checks": {
    "detector": "ok",
    "os_detection": "Windows",
    "endpoints": "available"
  }
}
```

---

## 🔧 Ejemplos de Uso

### Ejemplo 1: Listar Solo Usuarios Humanos en Linux

```bash
curl http://localhost:5000/api/users?filter=human
```

Esto filtra usuarios del sistema (root, daemon, etc.) y solo muestra usuarios reales.

---

### Ejemplo 2: Verificar Si un Usuario Existe

```bash
# Verificar si existe el usuario "juan"
curl http://localhost:5000/api/users/juan

# Si existe, la respuesta incluirá "exists": true
# Si no existe, recibirás un 404 con "exists": false
```

---

### Ejemplo 3: Obtener Solo Nombres de Usuarios

```bash
curl http://localhost:5000/api/users?format=simple
```

**Respuesta:**
```json
{
  "success": true,
  "count": 3,
  "users": ["Administrador", "User", "Invitado"]
}
```

---

### Ejemplo 4: Usar desde Python

```python
import requests

# Obtener todos los usuarios
response = requests.get('http://localhost:5000/api/users')
data = response.json()

if data['success']:
    print(f"Total de usuarios: {data['count']}")
    for user in data['data']:
        print(f"  - {user['username']}")
```

---

### Ejemplo 5: Usar desde JavaScript (Frontend)

```javascript
// Fetch API
fetch('http://localhost:5000/api/users')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log('Usuarios:', data.data);
    }
  });

// Axios
import axios from 'axios';

axios.get('http://localhost:5000/api/users')
  .then(response => {
    console.log('Usuarios:', response.data.data);
  });
```

---

## 🔗 Integración con el Sistema PDF Secure

### Validar Usuarios Antes de Cifrar

Puedes integrar la API con el sistema de cifrado de PDFs para validar que los usuarios existen en el sistema.

**Ejemplo de integración en Python:**

```python
import requests

def validate_users_exist(usernames):
    """Valida que los usuarios existen en el sistema"""
    valid_users = []
    invalid_users = []

    for username in usernames:
        response = requests.get(f'http://localhost:5000/api/users/{username}')
        data = response.json()

        if data.get('exists'):
            valid_users.append(username)
        else:
            invalid_users.append(username)

    return valid_users, invalid_users

# Uso
users_to_check = ['juan', 'maria', 'usuario_inexistente']
valid, invalid = validate_users_exist(users_to_check)

print(f"Usuarios válidos: {valid}")
print(f"Usuarios inválidos: {invalid}")
```

### Obtener Lista de Usuarios para Autocompletar

En la interfaz gráfica, puedes usar la API para autocompletar nombres de usuarios:

```python
import requests
import tkinter as tk
from tkinter import ttk

def get_system_users():
    """Obtiene lista de usuarios del sistema"""
    try:
        response = requests.get('http://localhost:5000/api/users?format=simple')
        data = response.json()
        if data['success']:
            return data['users']
    except:
        return []
    return []

# Crear combobox con usuarios
root = tk.Tk()
users = get_system_users()
combo = ttk.Combobox(root, values=users)
combo.pack()
root.mainloop()
```

---

## 🐛 Solución de Problemas

### Problema 1: "Address already in use"

**Causa:** El puerto 5000 ya está ocupado.

**Solución:**
```bash
# Usar otro puerto
python3 run_users_api.py --port 8080
```

---

### Problema 2: "ModuleNotFoundError: No module named 'flask'"

**Causa:** Flask no está instalado.

**Solución:**
```bash
pip install flask flask-cors
```

---

### Problema 3: Error de permisos al listar usuarios (Linux)

**Causa:** Algunos comandos requieren permisos de root.

**Solución:**
```bash
# Ejecutar con sudo (solo si es necesario)
sudo python3 run_users_api.py
```

**Nota:** La API funciona sin sudo, pero puede tener información limitada.

---

### Problema 4: CORS error al acceder desde el navegador

**Causa:** Restricciones de CORS.

**Solución:**
La API ya incluye `flask-cors`, por lo que debería funcionar. Verifica que `flask-cors` esté instalado:

```bash
pip install flask-cors
```

---

### Problema 5: Usuarios no aparecen en Windows

**Causa:** Falta el módulo `wmi` para mejor detección.

**Solución (opcional):**
```bash
pip install pywin32
```

Esto mejora la detección de usuarios en Windows, pero no es obligatorio.

---

## 📊 Casos de Uso Reales

### 1. **Panel de Administración**
Crear un dashboard web que muestre todos los usuarios del servidor y sus estados.

### 2. **Validación de Acceso**
Antes de cifrar un PDF, verificar que los usuarios autorizados existan en el sistema.

### 3. **Auditoría de Seguridad**
Monitorear qué usuarios están conectados en tiempo real.

### 4. **Automatización de Tareas**
Scripts que necesitan saber qué usuarios tienen acceso al sistema.

### 5. **Integración con Sistemas de Tickets**
Validar que los usuarios mencionados en tickets existen en el sistema.

---

## 🔒 Consideraciones de Seguridad

### ⚠️ Advertencias

1. **No exponer públicamente**: Esta API debe ejecutarse en redes locales o protegidas.
2. **Información sensible**: La API expone información del sistema que puede ser sensible.
3. **Autenticación**: Considera añadir autenticación si la usas en producción.

### ✅ Recomendaciones

1. Ejecutar solo en `localhost` (127.0.0.1) si es para uso local
2. Usar un firewall para restringir acceso
3. Implementar rate limiting para evitar abusos
4. Añadir autenticación mediante tokens o API keys

---

## 📞 Soporte

Para reportar problemas o sugerencias:
- **Issues**: [GitHub Issues](https://github.com/zeligmax/proyecto_pdf_seguro/issues)
- **Documentación del proyecto principal**: Ver [README.md](README.md)

---

## 🎯 Próximas Funcionalidades

Funcionalidades planeadas para futuras versiones:

- [ ] Autenticación con API Keys
- [ ] Rate limiting
- [ ] Caché de respuestas
- [ ] Exportación a CSV/Excel
- [ ] Websockets para actualizaciones en tiempo real
- [ ] Integración directa con la GUI de PDF Secure

---

**🚀 ¡Listo para usar! Ejecuta `python run_users_api.py` y comienza a detectar usuarios.**
