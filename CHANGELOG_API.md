# 📋 Changelog - API de Detección de Usuarios

## 🆕 Nueva Funcionalidad Añadida al Proyecto PDF Secure

**Fecha:** 19 de Enero de 2025
**Versión API:** 1.0.0
**Autor:** Desarrollo para integración con PDF Secure v2.0

---

## 📦 Archivos Nuevos Creados

### 1. **Módulo de Detección de Usuarios**
- **Archivo:** `app/system_users.py`
- **Descripción:** Clase `SystemUsersDetector` que detecta usuarios del sistema operativo
- **Funcionalidades:**
  - Detecta usuarios en Windows, Linux y macOS
  - Obtiene información detallada de cada usuario
  - Lista usuarios conectados actualmente
  - Obtiene grupos de usuarios
  - Genera reportes completos del sistema

### 2. **API REST**
- **Archivo:** `app/users_api.py`
- **Descripción:** API web construida con Flask
- **Endpoints:** 9 endpoints para gestión de usuarios
- **Características:**
  - CORS habilitado
  - Documentación integrada
  - Manejo de errores robusto
  - Filtros y formatos personalizables

### 3. **Script de Ejecución**
- **Archivo:** `run_users_api.py`
- **Descripción:** Script para ejecutar la API fácilmente
- **Configuración:**
  - Host: 0.0.0.0 (por defecto)
  - Puerto: 5000 (por defecto)
  - Modo debug activado

### 4. **Documentación**
- **Archivo:** `API_USERS_GUIDE.md`
- **Descripción:** Guía completa de uso de la API
- **Contenido:**
  - Instalación detallada
  - Documentación de todos los endpoints
  - Ejemplos de uso con curl, Python, JavaScript
  - Casos de uso reales
  - Solución de problemas

### 5. **Guía de Inicio Rápido**
- **Archivo:** `QUICKSTART_API.md`
- **Descripción:** Inicio rápido en 3 pasos
- **Contenido:**
  - Instalación rápida
  - Comandos esenciales
  - Tabla de endpoints

### 6. **Script de Ejemplo**
- **Archivo:** `ejemplo_uso_api.py`
- **Descripción:** Ejemplos prácticos de uso de la API
- **Demostraciones:**
  - Uso básico de la API
  - Validación de usuarios
  - Detalles de usuario
  - Integración con PDF Secure

### 7. **Este Changelog**
- **Archivo:** `CHANGELOG_API.md`
- **Descripción:** Registro de cambios y nuevas funcionalidades

---

## 🔧 Archivos Modificados

### 1. **requirements.txt**
- **Añadido:** `flask-cors>=4.0.0`
- **Añadido:** `pywin32; sys_platform == "win32"`
- **Actualizada documentación** de dependencias

### 2. **README.md**
- **Añadida sección:** "API de Detección de Usuarios"
- **Actualizada tabla de contenidos**
- **Añadidos enlaces** a la nueva documentación

---

## 📊 Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/` | Información general de la API |
| GET | `/api/docs` | Documentación de endpoints |
| GET | `/api/system` | Información del sistema operativo |
| GET | `/api/users` | Lista de todos los usuarios |
| GET | `/api/users/current` | Usuario actual |
| GET | `/api/users/logged` | Usuarios conectados |
| GET | `/api/users/<username>` | Info de usuario específico |
| GET | `/api/users/<username>/groups` | Grupos del usuario |
| GET | `/api/report` | Reporte completo |
| GET | `/api/health` | Estado de la API |

---

## 🎯 Características Implementadas

### ✅ Detección Multiplataforma
- **Windows:** Usando WMI (con pywin32) o comando `net user`
- **Linux:** Leyendo `/etc/passwd` y comandos del sistema
- **macOS:** Usando `dscl` (Directory Service Command Line)

### ✅ Información Detallada
- Nombre de usuario
- Nombre completo
- Directorio home
- Shell/Sesión
- UID/GID (Unix)
- SID (Windows)
- Estado (habilitado/deshabilitado)
- Grupos del usuario

### ✅ Funciones Adicionales
- Detectar si un usuario es administrador
- Filtrar usuarios humanos vs. del sistema
- Detectar usuarios actualmente conectados
- Validar existencia de usuarios
- Formato de respuesta personalizable (JSON completo o lista simple)

---

## 🚀 Casos de Uso

### 1. **Validación de Usuarios para Cifrado**
Antes de cifrar un PDF, validar que los usuarios autorizados existan en el sistema.

```python
from ejemplo_uso_api import UsersAPIClient

client = UsersAPIClient()
valid, invalid = client.validate_users(['user1', 'user2', 'user3'])
print(f"Válidos: {valid}")
print(f"Inválidos: {invalid}")
```

### 2. **Autocompletar en la GUI**
Usar la API para proporcionar autocompletado de usuarios en la interfaz gráfica.

```python
users = client.get_all_users(format_type='simple')['users']
# Usar 'users' en un widget de autocompletado
```

### 3. **Auditoría de Sistema**
Generar reportes de usuarios del sistema para auditoría.

```bash
curl http://localhost:5000/api/report > system_report.json
```

### 4. **Monitoreo de Sesiones**
Verificar qué usuarios están conectados en tiempo real.

```bash
curl http://localhost:5000/api/users/logged
```

---

## 📚 Documentación de Referencia

- **Guía Completa:** [API_USERS_GUIDE.md](API_USERS_GUIDE.md)
- **Inicio Rápido:** [QUICKSTART_API.md](QUICKSTART_API.md)
- **Ejemplos de Código:** [ejemplo_uso_api.py](ejemplo_uso_api.py)
- **README Principal:** [README.md](README.md)

---

## 🔐 Consideraciones de Seguridad

### ⚠️ Advertencias
1. La API expone información del sistema que puede ser sensible
2. No debe exponerse públicamente en internet sin autenticación
3. Ejecutar solo en redes confiables

### ✅ Recomendaciones
1. Usar en localhost (127.0.0.1) para uso local
2. Implementar firewall si se ejecuta en red
3. Considerar añadir autenticación para producción
4. Implementar rate limiting si se usa intensivamente

---

## 🐛 Problemas Conocidos y Limitaciones

### Windows
- **WMI:** Requiere `pywin32` para información completa (opcional)
- **Fallback:** Usa `net user` si WMI no está disponible
- **Codificación:** Maneja correctamente caracteres especiales (cp850)

### Linux
- **Permisos:** Algunas operaciones pueden requerir privilegios elevados
- **Usuarios del sistema:** Incluye usuarios técnicos (filtrable con `?filter=human`)

### macOS
- **dscl:** Comando estándar del sistema, no requiere instalación
- **Usuarios del sistema:** Incluye usuarios técnicos (filtrable con `?filter=human`)

---

## 🔄 Integración con PDF Secure

La API está diseñada para integrarse perfectamente con el sistema PDF Secure existente:

1. **Validación antes de cifrar:** Verificar que los usuarios existen
2. **Autocompletar usuarios:** En la GUI al seleccionar usuarios autorizados
3. **Auditoría:** Registrar quién está disponible en el sistema
4. **Logs:** Correlacionar accesos con usuarios del sistema

### Ejemplo de Integración

```python
# En app/pdf_utils_v2.py o app/app_gui.py
from users_api import UsersAPIClient

# Al cifrar PDF
client = UsersAPIClient()
valid_users, invalid_users = client.validate_users(authorized_users)

if invalid_users:
    print(f"⚠️ Usuarios no encontrados: {', '.join(invalid_users)}")
    # Opcionalmente, preguntar al usuario si continuar
```

---

## 📈 Próximas Mejoras Sugeridas

### Versión 1.1
- [ ] Autenticación con API Keys
- [ ] Rate limiting
- [ ] Caché de respuestas
- [ ] Logs de acceso a la API

### Versión 1.2
- [ ] Exportación a CSV/Excel
- [ ] Websockets para actualizaciones en tiempo real
- [ ] Panel de control web

### Versión 2.0
- [ ] Integración directa con la GUI de PDF Secure
- [ ] Gestión de usuarios desde la API
- [ ] Sincronización con Active Directory (Windows)
- [ ] Soporte para LDAP

---

## 🙏 Notas de Desarrollo

Esta API fue desarrollada como una extensión del sistema PDF Secure v2.0 para proporcionar capacidades de detección de usuarios del sistema operativo. La implementación es multiplataforma y está diseñada para ser fácil de usar y extender.

### Tecnologías Utilizadas
- **Python 3.8+**
- **Flask 2.3+** - Framework web
- **Flask-CORS 4.0+** - Soporte CORS
- **pywin32** - WMI en Windows (opcional)

### Principios de Diseño
- **Modularidad:** Código separado en módulos independientes
- **Multiplataforma:** Funciona en Windows, Linux y macOS
- **Extensibilidad:** Fácil de extender con nuevas funcionalidades
- **Documentación:** Completamente documentado con ejemplos

---

## 📞 Soporte

Para reportar problemas o sugerencias relacionadas con la API:
- **Issues:** [GitHub Issues](https://github.com/zeligmax/proyecto_pdf_seguro/issues)
- **Etiqueta:** Usar etiqueta "api" o "users-detection"

---

**✅ La API de Detección de Usuarios está lista para usar. ¡Ejecuta `python run_users_api.py` y comienza a detectar usuarios!**
