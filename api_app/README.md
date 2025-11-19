# 🔍 API de Detección de Usuarios

Carpeta que contiene la API REST para detectar usuarios del sistema operativo.

---

## 📁 Contenido de la Carpeta

### Archivos Principales

| Archivo | Descripción |
|---------|-------------|
| **`system_users.py`** | Módulo de detección de usuarios del SO |
| **`users_api.py`** | API REST con Flask |
| **`run_api.py`** | Script para ejecutar el servidor |
| **`__init__.py`** | Inicialización del paquete |

### Scripts de Ejemplo y Pruebas

| Archivo | Descripción |
|---------|-------------|
| **`ejemplo_uso_api.py`** | Ejemplos de uso de la API desde Python |
| **`test_api.py`** | Suite de pruebas del sistema de detección |
| **`quien_soy.py`** | Script simple para ver tu usuario |

---

## 🚀 Inicio Rápido

### 1. Instalar Dependencias

```bash
pip install flask flask-cors
```

### 2. Ejecutar la API

```bash
cd api_app
python run_api.py
```

O desde la raíz del proyecto:

```bash
python api_app/run_api.py
```

### 3. Acceder a la API

Abre tu navegador en: **http://localhost:5000**

---

## 📡 Endpoints Disponibles

| Endpoint | Descripción |
|----------|-------------|
| `GET /` | Información de la API |
| `GET /api/docs` | Documentación completa |
| `GET /api/system` | Info del sistema operativo |
| `GET /api/users` | Lista de usuarios |
| `GET /api/users/current` | Usuario actual |
| `GET /api/users/logged` | Usuarios conectados |
| `GET /api/users/<username>` | Info de usuario específico |
| `GET /api/users/<username>/groups` | Grupos del usuario |
| `GET /api/report` | Reporte completo |
| `GET /api/health` | Estado de la API |

---

## 💡 Ejemplos de Uso

### Desde el Navegador

```
http://localhost:5000/api/users
http://localhost:5000/api/users/current
http://localhost:5000/api/system
```

### Desde curl

```bash
# Listar usuarios
curl http://localhost:5000/api/users

# Usuario actual
curl http://localhost:5000/api/users/current

# Solo nombres (formato simple)
curl "http://localhost:5000/api/users?format=simple"

# Filtrar solo usuarios humanos
curl "http://localhost:5000/api/users?filter=human"
```

### Desde Python

```python
import requests

# Obtener todos los usuarios
response = requests.get('http://localhost:5000/api/users')
data = response.json()

if data['success']:
    print(f"Total usuarios: {data['count']}")
    for user in data['data']:
        print(f"  - {user['username']}")
```

---

## 🧪 Probar la API

### Test Básico

```bash
cd api_app
python test_api.py
```

Deberías ver:
```
✅ Test 1 PASADO
✅ Test 2 PASADO
...
🎉 ¡TODOS LOS TESTS PASARON!
```

### Ver Tu Usuario

```bash
cd api_app
python quien_soy.py
```

### Ejemplos Completos

```bash
cd api_app
python ejemplo_uso_api.py
```

---

## 🔧 Configuración Avanzada

### Cambiar Puerto

Edita `run_api.py`:

```python
run_api(
    host='0.0.0.0',
    port=8080,  # Cambiar aquí
    debug=True
)
```

O usa argumentos de línea de comandos:

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

### Producción

```python
run_api(
    host='0.0.0.0',
    port=5000,
    debug=False  # Desactivar debug en producción
)
```

---

## 📚 Documentación Completa

Ver la documentación completa en el directorio raíz:

- **[API_USERS_GUIDE.md](../API_USERS_GUIDE.md)** - Guía completa
- **[QUICKSTART_API.md](../QUICKSTART_API.md)** - Inicio rápido
- **[CHANGELOG_API.md](../CHANGELOG_API.md)** - Registro de cambios

---

## 🔐 Seguridad

⚠️ **IMPORTANTE:**

- Esta API expone información del sistema
- **NO** la expongas públicamente en internet sin autenticación
- Úsala solo en redes locales o protegidas
- Considera implementar autenticación para producción

---

## 🐛 Solución de Problemas

### Problema: "No module named 'flask'"

**Solución:**
```bash
pip install flask flask-cors
```

### Problema: "Address already in use"

**Solución:**
```bash
# Cambiar puerto
python users_api.py --port 8080
```

### Problema: Los tests fallan

**Solución:**
```bash
# Verificar permisos
# En Linux/Mac, algunos comandos pueden necesitar sudo
sudo python test_api.py
```

---

## 🎯 Integración con PDF Secure

Esta API puede integrarse con el sistema principal de PDF Secure:

1. **Validar usuarios** antes de cifrar PDFs
2. **Autocompletar** nombres de usuarios
3. **Auditoría** del sistema
4. **Verificar existencia** de usuarios

### Ejemplo de Integración

```python
import requests

# Validar que un usuario existe antes de cifrar
def validar_usuario(username):
    response = requests.get(f'http://localhost:5000/api/users/{username}')
    data = response.json()
    return data.get('exists', False)

# Uso
if validar_usuario('john'):
    print("Usuario válido, proceder con cifrado")
else:
    print("Usuario no existe en el sistema")
```

---

## 📊 Estructura del Código

```
api_app/
├── __init__.py              # Inicialización del paquete
├── system_users.py          # Clase SystemUsersDetector
├── users_api.py             # API Flask con endpoints
├── run_api.py               # Script de ejecución
├── ejemplo_uso_api.py       # Ejemplos de uso
├── test_api.py              # Suite de pruebas
├── quien_soy.py             # Script utilidad
└── README.md                # Esta documentación
```

---

## 🚀 Próximas Mejoras

- [ ] Autenticación con API Keys
- [ ] Rate limiting
- [ ] Caché de respuestas
- [ ] Websockets para actualizaciones en tiempo real
- [ ] Exportación a CSV/Excel
- [ ] Panel de control web

---

**✨ La API está lista para usar. Ejecuta `python run_api.py` y accede a http://localhost:5000**
