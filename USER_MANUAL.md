# 📘 Manual de Usuario - File Secure v3.2 Enterprise

> **Guía completa para usuarios finales**
> Aprende a proteger tus archivos con cifrado de nivel empresarial

---

## 📖 Tabla de Contenidos

1. [Bienvenido a File Secure](#-bienvenido-a-file-secure)
2. [Inicio Rápido](#-inicio-rápido)
3. [Usar la Interfaz Gráfica (GUI)](#-usar-la-interfaz-gráfica-gui)
4. [Usar la API REST](#-usar-la-api-rest)
5. [Casos de Uso Comunes](#-casos-de-uso-comunes)
6. [Roles y Permisos](#-roles-y-permisos)
7. [Preguntas Frecuentes](#-preguntas-frecuentes)
8. [Solución de Problemas](#-solución-de-problemas)

---

## 🎯 Bienvenido a File Secure

**File Secure v3.2 Enterprise** es un sistema de cifrado de archivos que te permite:

✅ **Proteger archivos confidenciales** con cifrado AES-256 (nivel militar)
✅ **Controlar quién accede** a cada archivo con permisos granulares
✅ **Auditar todas las acciones** para cumplir con normativas
✅ **Compartir de forma segura** archivos dentro de tu organización
✅ **Soportar múltiples formatos**: PDF, DOCX, XLSX, TXT, PBIP, PBIX, y más

### ¿Qué hace File Secure?

1. **Cifra tus archivos** para que nadie sin autorización pueda leerlos
2. **Gestiona permisos** para controlar quién puede descifrar cada archivo
3. **Registra todo** en un log de auditoría para seguridad y cumplimiento
4. **Permite compartir** archivos de forma segura entre usuarios autorizados

---

## 🚀 Inicio Rápido

### Tu Primer Login

Cuando abres File Secure por primera vez, verás una pantalla de login:

**Credenciales iniciales:**
- **Usuario**: `admin`
- **Contraseña**: `Admin@123456`

⚠️ **MUY IMPORTANTE**: Después de tu primer login, cambia la contraseña inmediatamente.

### Cambiar tu Contraseña (Primer Paso Obligatorio)

1. Después de hacer login, ve a la pestaña **"Usuarios"**
2. Busca tu usuario (`admin`)
3. Haz clic en **"Cambiar Contraseña"**
4. Ingresa:
   - Contraseña actual: `Admin@123456`
   - Nueva contraseña: (elige una contraseña segura)
   - Confirmar nueva contraseña
5. Haz clic en **"Guardar"**

✅ **Tu cuenta ahora es segura**

---

## 🖥️ Usar la Interfaz Gráfica (GUI)

### Iniciar la Aplicación

**En Windows:**
```powershell
# Abrir PowerShell en la carpeta del proyecto
python app/app_gui.py
```

**En macOS/Linux:**
```bash
# Abrir terminal en la carpeta del proyecto
python3 app/app_gui.py
```

### Pantalla Principal

Después de iniciar sesión, verás varias pestañas en la parte superior:

- 📊 **Dashboard**: Resumen de tu actividad
- 📁 **Archivos**: Cifrar, descifrar y gestionar archivos
- 👥 **Usuarios**: Gestionar usuarios de tu organización
- 📋 **Auditoría**: Ver logs de acciones
- ⚙️ **Configuración**: Ajustes de políticas y seguridad

---

## 📁 Trabajar con Archivos

### 1️⃣ Cifrar un Archivo

**Paso a Paso:**

1. Ve a la pestaña **"Archivos"**
2. Haz clic en el botón **"Cifrar Archivo"**
3. Se abre un cuadro de diálogo:
   - Haz clic en **"Seleccionar archivo"**
   - Navega hasta el archivo que quieres proteger
   - Selecciona el archivo (por ejemplo: `informe_financiero.pdf`)
   - Haz clic en **"Abrir"**
4. Configura las opciones:
   - **Descripción**: "Informe financiero Q4 2024"
   - **Etiquetas**: "confidencial, finanzas, 2024"
   - **Departamento**: Selecciona tu departamento
5. Haz clic en **"Cifrar"**

✅ **Resultado**: El archivo original se cifra y se guarda como `informe_financiero.pdf.enc`

**¿Qué pasó con mi archivo original?**
- El archivo original **se conserva** (no se elimina)
- Se crea un nuevo archivo cifrado con extensión `.enc`
- Solo usuarios autorizados pueden descifrar el archivo `.enc`

---

### 2️⃣ Descifrar un Archivo

**Paso a Paso:**

1. Ve a la pestaña **"Archivos"**
2. En la lista de archivos, busca el archivo que quieres descifrar
3. Selecciona el archivo (por ejemplo: `informe_financiero.pdf.enc`)
4. Haz clic en el botón **"Descifrar"**
5. Se te pedirá:
   - **Confirmar que eres el usuario autorizado**
   - **Seleccionar dónde guardar** el archivo descifrado
6. Elige la ubicación y haz clic en **"Guardar"**

✅ **Resultado**: El archivo se descifra y se guarda en la ubicación que elegiste

**Importante:**
- Solo puedes descifrar archivos para los que tienes acceso autorizado
- Cada descifrado se registra en el log de auditoría
- El archivo cifrado `.enc` permanece intacto

---

### 3️⃣ Ver un Archivo sin Descifrarlo

File Secure te permite **visualizar archivos en memoria** sin guardarlos en disco (más seguro):

**Paso a Paso:**

1. Ve a la pestaña **"Archivos"**
2. Selecciona el archivo cifrado
3. Haz clic en **"Ver en Memoria"** o **"Vista Previa"**
4. Se abre una ventana mostrando el contenido del archivo

**Tipos de archivo que puedes visualizar:**
- 📄 **PDF**: Se muestra el documento completo
- 📝 **TXT, CSV, MD**: Contenido de texto
- 🖼️ **Imágenes**: JPG, PNG, GIF, BMP
- 📊 **Office**: Información básica de DOCX, XLSX

✅ **Ventaja**: El archivo nunca se guarda en tu disco, por lo que es más seguro

---

### 4️⃣ Compartir un Archivo

**Paso a Paso para compartir acceso:**

1. Ve a la pestaña **"Archivos"**
2. Selecciona el archivo que quieres compartir
3. Haz clic en **"Compartir"** o **"Gestionar Accesos"**
4. Se abre un cuadro de diálogo:
   - **Usuario**: Selecciona el usuario con quien quieres compartir
   - **Permisos**:
     - ✅ Puede descifrar
     - ✅ Puede descargar
     - ☐ Puede compartir con otros
     - ☐ Puede eliminar
   - **Expiración**: (Opcional) Fecha de vencimiento del acceso
5. Haz clic en **"Conceder Acceso"**

✅ **Resultado**: El usuario ahora puede ver y descifrar el archivo

**Ejemplo práctico:**
```
Archivo: presupuesto_2025.xlsx.enc
Compartir con: maria.gonzalez
Permisos: Solo lectura (descifrar + descargar)
Expira: 31/12/2025
```

---

### 5️⃣ Revocar Acceso a un Archivo

Si necesitas quitar el acceso de un usuario:

1. Selecciona el archivo
2. Haz clic en **"Gestionar Accesos"**
3. En la lista de usuarios con acceso, busca el usuario
4. Haz clic en **"Revocar Acceso"** junto a su nombre
5. Confirma la acción

✅ **Resultado**: El usuario ya no puede descifrar el archivo

---

## 👥 Gestionar Usuarios

*(Solo disponible para usuarios con rol OrgAdmin, DepartmentManager o SuperAdmin)*

### Crear un Nuevo Usuario

1. Ve a la pestaña **"Usuarios"**
2. Haz clic en **"Crear Usuario"**
3. Completa el formulario:
   - **Nombre de usuario**: `juan.perez`
   - **Email**: `juan.perez@empresa.com`
   - **Nombre completo**: `Juan Pérez`
   - **Contraseña**: `Temporal@123` (el usuario debe cambiarla)
   - **Departamento**: Selecciona el departamento
   - **Rol**: Selecciona el rol apropiado
4. Haz clic en **"Crear"**

✅ **Resultado**: El nuevo usuario puede hacer login

---

### Asignar Roles a un Usuario

1. Ve a la pestaña **"Usuarios"**
2. Selecciona el usuario en la lista
3. Haz clic en **"Editar"** o **"Asignar Roles"**
4. Selecciona los roles:
   - ☐ SuperAdmin (solo si eres SuperAdmin)
   - ☐ OrgAdmin
   - ☐ DepartmentManager
   - ✅ Editor
   - ☐ Viewer
   - ☐ Auditor
5. Haz clic en **"Guardar"**

**Recomendación**: Asigna el rol mínimo necesario para cada usuario (principio de menor privilegio).

---

## 📊 Dashboard - Métricas y Estadísticas

El dashboard te muestra un resumen de la actividad:

### KPIs Principales

📈 **Total de Usuarios**: Cantidad de usuarios en tu organización
📁 **Total de Archivos**: Archivos cifrados en el sistema
👁️ **Accesos Hoy**: Número de descargas/visualizaciones hoy
⚠️ **Intentos Fallidos**: Intentos de acceso no autorizado

### Gráficos de Actividad

- **Accesos por Día**: Línea de tiempo de actividad
- **Archivos Más Accedidos**: Top 10 archivos más populares
- **Usuarios Más Activos**: Quién está usando más el sistema

### Alertas de Seguridad

⚠️ **Intentos de login fallidos**
⚠️ **Accesos denegados**
⚠️ **Políticas violadas**

---

## 📋 Auditoría - Ver Logs

*(Disponible para todos los usuarios, pero con diferentes niveles de visibilidad)*

### Ver el Log de Auditoría

1. Ve a la pestaña **"Auditoría"**
2. Verás una lista de todas las acciones registradas:
   - Timestamp
   - Usuario
   - Acción (login, cifrado, descifrado, etc.)
   - Estado (éxito, fallo, denegado)
   - Detalles

### Filtrar Logs

Puedes filtrar por:
- **Fecha**: Desde/Hasta
- **Usuario**: Selecciona un usuario específico
- **Acción**: file.encrypt, file.decrypt, auth.login, etc.
- **Estado**: success, failure, denied
- **Severidad**: info, warning, error, critical

**Ejemplo de filtro:**
```
Fecha: 01/01/2025 - 31/01/2025
Usuario: maria.gonzalez
Acción: file.decrypt
Estado: success
```

### Exportar Logs

1. Filtra los logs que necesitas
2. Haz clic en **"Exportar"**
3. Selecciona el formato:
   - CSV (para Excel)
   - JSON (para análisis técnico)
4. Guarda el archivo

---

## 🔌 Usar la API REST

Si eres desarrollador o quieres integrar File Secure con otros sistemas, puedes usar la API REST.

### Iniciar la API

```powershell
# En la carpeta del proyecto
python run_api_v32.py
```

La API estará disponible en: `http://localhost:5000`

---

### 1️⃣ Login y Obtener Token

Antes de usar cualquier endpoint, necesitas autenticarte:

**Usando curl (Terminal):**

```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "tu_contraseña_segura"
  }'
```

**Respuesta:**

```json
{
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "admin",
    "email": "admin@filesecure.local",
    "roles": ["SuperAdmin"]
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIn0.abc123...",
  "expires_in": 3600
}
```

✅ **Guarda el token**, lo necesitarás para todas las demás peticiones.

---

### 2️⃣ Obtener Información del Usuario Actual

**Usando curl:**

```bash
curl http://localhost:5000/api/v1/auth/me \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

**Respuesta:**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "admin",
  "email": "admin@filesecure.local",
  "full_name": "Administrador del Sistema",
  "organization_id": "org-123",
  "department_id": "dept-456",
  "roles": ["SuperAdmin"],
  "is_active": true,
  "last_login": "2025-01-26T10:30:00Z"
}
```

---

### 3️⃣ Cambiar Contraseña

**Usando curl:**

```bash
curl -X POST http://localhost:5000/api/v1/auth/change-password \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "contraseña_actual",
    "new_password": "nueva_contraseña_segura"
  }'
```

**Respuesta:**

```json
{
  "message": "Password changed successfully"
}
```

---

### 4️⃣ Ejemplos con Python

Si prefieres usar Python en lugar de curl:

**Instalar requests:**

```bash
pip install requests
```

**Login y obtener información del usuario:**

```python
import requests

# URL base de la API
BASE_URL = "http://localhost:5000/api/v1"

# 1. Login
response = requests.post(
    f"{BASE_URL}/auth/login",
    json={
        "username": "admin",
        "password": "tu_contraseña"
    }
)

data = response.json()
token = data["token"]
print(f"Token obtenido: {token[:20]}...")

# 2. Obtener información del usuario actual
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(f"{BASE_URL}/auth/me", headers=headers)

user_info = response.json()
print(f"Usuario: {user_info['username']}")
print(f"Email: {user_info['email']}")
print(f"Roles: {', '.join(user_info['roles'])}")

# 3. Cambiar contraseña
response = requests.post(
    f"{BASE_URL}/auth/change-password",
    headers=headers,
    json={
        "current_password": "contraseña_actual",
        "new_password": "nueva_contraseña"
    }
)

print(response.json()["message"])
```

---

### 5️⃣ Códigos de Estado HTTP

Cuando uses la API, recibirás estos códigos:

| Código | Significado | Qué hacer |
|--------|-------------|-----------|
| 200 | ✅ Success | Todo salió bien |
| 201 | ✅ Created | Recurso creado exitosamente |
| 400 | ❌ Bad Request | Revisa los datos que enviaste |
| 401 | ❌ Unauthorized | Token inválido o expirado, haz login de nuevo |
| 403 | ❌ Forbidden | No tienes permisos para esta acción |
| 404 | ❌ Not Found | El recurso no existe |
| 423 | ❌ Locked | Tu cuenta está bloqueada, contacta al admin |
| 500 | ❌ Server Error | Error del servidor, contacta soporte |

---

## 💼 Casos de Uso Comunes

### Caso 1: Proteger Documentos Financieros

**Situación**: Eres del departamento de Finanzas y necesitas compartir el presupuesto anual solo con el director.

**Pasos:**

1. Cifra el archivo `presupuesto_2025.xlsx`
2. Comparte el archivo con el usuario `director.finanzas`
3. Configura permisos: Solo lectura (descifrar + descargar)
4. Establece expiración: 31/12/2025
5. El director puede ver el archivo pero no compartirlo con otros

**Beneficios:**
- ✅ Solo el director puede ver el presupuesto
- ✅ El acceso expira automáticamente
- ✅ Todas las visualizaciones quedan registradas
- ✅ Si se filtra, el archivo cifrado es inútil sin acceso

---

### Caso 2: Auditoría de Cumplimiento

**Situación**: Necesitas demostrar quién accedió a archivos sensibles en el último mes.

**Pasos:**

1. Ve a la pestaña **"Auditoría"**
2. Filtra:
   - Fecha: Último mes
   - Acción: `file.decrypt`
   - Estado: `success`
3. Exporta el reporte en CSV
4. Abre en Excel y analiza

**Beneficios:**
- ✅ Registro completo de todos los accesos
- ✅ Cumplimiento con normativas (GDPR, SOX, etc.)
- ✅ Evidencia forense en caso de incidente
- ✅ Detección de accesos sospechosos

---

### Caso 3: Trabajo Remoto Seguro

**Situación**: Un empleado trabaja desde casa y necesita acceder a archivos confidenciales.

**Pasos:**

1. El empleado hace login desde su casa
2. File Secure registra su IP de origen
3. El empleado descifra el archivo que necesita
4. Trabaja en el archivo
5. Vuelve a cifrar el archivo modificado

**Beneficios:**
- ✅ Los archivos viajan cifrados
- ✅ Solo usuarios autorizados pueden descifrar
- ✅ Se registra desde dónde se accedió
- ✅ Políticas de IP pueden restringir ubicaciones

---

### Caso 4: Rotación de Personal

**Situación**: Un empleado renuncia y necesitas revocar su acceso a todos los archivos.

**Pasos:**

1. Ve a la pestaña **"Usuarios"**
2. Busca el usuario que renunció
3. Haz clic en **"Desactivar Usuario"**
4. Automáticamente:
   - Se revoca el acceso a todos los archivos
   - Se cierra su sesión activa
   - No puede hacer login nuevamente

**Beneficios:**
- ✅ Revocación inmediata de acceso
- ✅ No puede acceder a nada desde ese momento
- ✅ Los archivos permanecen seguros
- ✅ Cumplimiento con políticas de offboarding

---

## 🔐 Roles y Permisos

### ¿Qué puedo hacer según mi rol?

#### 👑 SuperAdmin (Administrador Total)
**Permisos:**
- ✅ TODO (acceso completo al sistema)
- ✅ Crear organizaciones
- ✅ Gestionar todos los usuarios
- ✅ Ver todos los archivos y logs
- ✅ Configurar políticas globales

**Cuándo usar:** Solo para el administrador del sistema.

---

#### 👨‍💼 OrgAdmin (Administrador de Organización)
**Permisos:**
- ✅ Gestionar usuarios de su organización
- ✅ Crear departamentos
- ✅ Configurar políticas de su organización
- ✅ Ver todos los archivos de su organización
- ✅ Asignar roles (excepto SuperAdmin)

**Cuándo usar:** Para el administrador de cada empresa/organización.

---

#### 👨‍💼 DepartmentManager (Gestor de Departamento)
**Permisos:**
- ✅ Gestionar usuarios de su departamento
- ✅ Ver archivos de su departamento
- ✅ Cifrar y descifrar archivos
- ✅ Compartir archivos
- ✅ Ver métricas de su departamento

**Cuándo usar:** Para jefes de departamento (Finanzas, IT, RRHH, etc.).

---

#### ✏️ Editor
**Permisos:**
- ✅ Cifrar archivos
- ✅ Descifrar archivos (si tiene acceso)
- ✅ Compartir archivos (si tiene acceso)
- ✅ Eliminar sus propios archivos
- ✅ Ver dashboard básico

**Cuándo usar:** Para empleados que necesitan trabajar con archivos cifrados.

---

#### 👁️ Viewer (Solo Lectura)
**Permisos:**
- ✅ Ver archivos (si tiene acceso)
- ✅ Descargar archivos (si tiene acceso)
- ✅ Ver dashboard básico
- ❌ NO puede cifrar nuevos archivos
- ❌ NO puede compartir

**Cuándo usar:** Para empleados que solo necesitan consultar información.

---

#### 🔍 Auditor
**Permisos:**
- ✅ Ver todos los logs de auditoría
- ✅ Exportar reportes
- ✅ Ver estadísticas completas
- ✅ Ver dashboard avanzado
- ❌ NO puede modificar archivos o usuarios

**Cuándo usar:** Para el equipo de seguridad/cumplimiento.

---

## ❓ Preguntas Frecuentes

### ¿Qué pasa si olvido mi contraseña?

Si olvidas tu contraseña:
1. Contacta a tu administrador de organización (OrgAdmin)
2. El administrador puede resetear tu contraseña
3. Te enviará una contraseña temporal
4. Cámbiala inmediatamente después de hacer login

**Nota:** Los SuperAdmin no pueden ver las contraseñas, solo pueden crear nuevas.

---

### ¿Puedo descifrar archivos en otro equipo?

Sí, siempre que:
- ✅ File Secure esté instalado en ese equipo
- ✅ Tengas acceso autorizado al archivo
- ✅ Inicies sesión con tu usuario
- ✅ (Opcional) La IP del equipo esté en la whitelist

El sistema verifica tu identidad antes de permitir el descifrado.

---

### ¿Qué tan seguro es el cifrado?

File Secure usa **AES-256-GCM**, el mismo estándar que:
- 🏦 La banca en línea
- 🔐 Aplicaciones de mensajería (WhatsApp, Signal)
- 🛡️ Agencias gubernamentales (NSA aprobado)

**En términos simples:** Con la tecnología actual, romper el cifrado AES-256 tomaría miles de millones de años.

---

### ¿Se puede recuperar un archivo si pierdo la clave?

**No**. Si pierdes la clave maestra del sistema:
- ❌ Los archivos cifrados **NO** se pueden recuperar
- ❌ Ni siquiera el creador del software puede descifrarlos

**Por eso es CRÍTICO:**
- 💾 Guardar la clave maestra en un lugar seguro
- 💾 Hacer backups de la clave
- 💾 Almacenar la clave fuera del sistema (USB, bóveda de contraseñas)

---

### ¿Cuántos archivos puedo cifrar?

**No hay límite teórico**, pero depende de:
- 💾 Espacio en disco
- 🗄️ Base de datos (SQLite tiene límites, PostgreSQL no)
- ⚡ Rendimiento del servidor

**Recomendaciones:**
- SQLite: Hasta 10,000 archivos
- PostgreSQL: Millones de archivos

---

### ¿Puedo cifrar archivos grandes?

Sí, File Secure puede cifrar archivos de cualquier tamaño, pero:
- ⏱️ Archivos grandes toman más tiempo
- 💾 Necesitas espacio en disco (el archivo cifrado es ~igual de grande)

**Políticas por defecto:**
- Tamaño máximo: 500 MB
- Se puede ajustar en **Configuración → Políticas → file_policy**

---

### ¿Qué pasa si alguien copia el archivo .enc?

Si alguien copia el archivo cifrado `.enc`:
- ❌ **No puede descifrarlo** sin acceso autorizado en File Secure
- ❌ **No puede romper el cifrado** (AES-256 es prácticamente irrompible)
- ✅ El archivo está **completamente protegido**

**Pero recuerda:**
- Una vez descifrado, es un archivo normal
- Protege los archivos descifrados como cualquier archivo sensible
- Mejor usa "Ver en Memoria" para no guardar archivos descifrados en disco

---

## 🔧 Solución de Problemas

### Problema: "No puedo hacer login"

**Posibles causas y soluciones:**

1. **Contraseña incorrecta**
   - Verifica que CAPS LOCK esté desactivado
   - Contacta al administrador para resetear tu contraseña

2. **Cuenta bloqueada** (después de 5 intentos fallidos)
   - Mensaje: "User account is locked"
   - Contacta al administrador para desbloquear tu cuenta

3. **Usuario desactivado**
   - Mensaje: "User is not active"
   - Contacta al administrador

4. **Base de datos no disponible**
   - Verifica que File Secure esté configurado correctamente
   - Contacta al administrador del sistema

---

### Problema: "No puedo descifrar un archivo"

**Posibles causas:**

1. **No tienes acceso autorizado**
   - Mensaje: "Access denied"
   - Solicita acceso al dueño del archivo o al administrador

2. **Tu acceso expiró**
   - El acceso tenía fecha de expiración
   - Solicita renovación de acceso

3. **Tu acceso fue revocado**
   - El dueño del archivo revocó tu acceso
   - Contacta al dueño del archivo

4. **Archivo corrupto**
   - El archivo `.enc` está dañado
   - Intenta con un backup

---

### Problema: "El archivo cifrado no abre"

**Pasos de diagnóstico:**

1. **Verifica la extensión**
   - Debe ser `.enc` (por ejemplo: `archivo.pdf.enc`)
   - No intentes abrir con doble clic

2. **Usa File Secure para descifrar**
   - No puedes abrir archivos `.enc` con programas normales
   - Debes usar File Secure → Descifrar

3. **Verifica integridad**
   - File Secure verifica el hash del archivo
   - Si está corrupto, mostrará un error

---

### Problema: "La API devuelve 401 Unauthorized"

**Causas comunes:**

1. **Token expirado**
   - Los tokens JWT expiran después de 1 hora
   - Haz login de nuevo para obtener un nuevo token

2. **Token inválido**
   - Verifica que copiaste el token completo
   - No agregues espacios al principio o final

3. **Falta el header Authorization**
   - Asegúrate de incluir: `Authorization: Bearer TU_TOKEN`

**Solución:**

```bash
# Obtener un nuevo token
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"tu_contraseña"}'
```

---

### Problema: "La API devuelve 403 Forbidden"

**Causa:**
- Tienes un token válido pero no tienes permisos para esa acción

**Solución:**
- Verifica que tu rol tenga el permiso necesario
- Contacta al administrador para que te asigne el rol correcto

**Ejemplo:**
```
Acción: Crear usuario
Permiso requerido: user.create
Tu rol actual: Viewer (no tiene este permiso)
Solución: Necesitas rol OrgAdmin o SuperAdmin
```

---

### Problema: "Error al iniciar la GUI"

**Errores comunes:**

1. **ModuleNotFoundError: No module named 'tkinter'**

   **En Windows:**
   - Reinstala Python con la opción "tcl/tk and IDLE" seleccionada

   **En Ubuntu/Debian:**
   ```bash
   sudo apt-get install python3-tk
   ```

   **En macOS:**
   ```bash
   brew install python-tk
   ```

2. **Variables de entorno no configuradas**
   - Error: "PDF_SECURE_MASTER_KEY not found"
   - Solución: Configura las variables de entorno (ver README.md)

---

## 📞 Soporte

### ¿Necesitas ayuda adicional?

**Para usuarios finales:**
- 📧 Contacta a tu administrador de organización
- 📋 Revisa el README.md para más detalles técnicos
- 🔍 Busca en los logs de auditoría para diagnóstico

**Para administradores:**
- 📖 Lee la documentación técnica en README.md
- 🐛 Reporta bugs en: https://github.com/zeligmax/proyecto_pdf_seguro/issues
- 💬 Consulta el código fuente para entender el funcionamiento interno

---

## 📝 Notas Finales

### Mejores Prácticas de Seguridad

1. ✅ **Cambia las contraseñas por defecto** inmediatamente
2. ✅ **Usa contraseñas fuertes**: Mínimo 12 caracteres, mayúsculas, minúsculas, números, símbolos
3. ✅ **No compartas tu contraseña** con nadie
4. ✅ **Revisa los logs de auditoría** regularmente
5. ✅ **Revoca accesos** cuando alguien deja la organización
6. ✅ **Haz backups** de la clave maestra y la base de datos
7. ✅ **Configura políticas** apropiadas para tu organización
8. ✅ **Usa "Ver en Memoria"** en lugar de descifrar cuando sea posible

---

### Glosario de Términos

- **AES-256**: Algoritmo de cifrado de nivel militar
- **Cifrado**: Convertir datos legibles en datos ilegibles
- **Descifrado**: Convertir datos cifrados de vuelta a su forma original
- **Token JWT**: Credencial de autenticación para la API
- **Rol**: Conjunto de permisos asignados a un usuario
- **Permiso**: Capacidad específica (ej: cifrar archivos)
- **Organización**: Empresa o entidad que usa File Secure
- **Departamento**: División dentro de una organización
- **Auditoría**: Registro de todas las acciones en el sistema
- **.enc**: Extensión de archivos cifrados

---

## 🎓 Ejemplos Prácticos Completos

### Ejemplo 1: Flujo Completo de Cifrado y Compartición

**Escenario:** María del departamento de RRHH quiere compartir contratos con el director.

```
1. María hace login:
   Usuario: maria.rrhh
   Contraseña: ********

2. María va a Archivos → Cifrar Archivo
   Archivo: contrato_juan_perez.pdf
   Descripción: Contrato de Juan Pérez - Ingeniero Senior
   Etiquetas: contrato, rrhh, 2025

3. File Secure cifra el archivo:
   ✅ contrato_juan_perez.pdf.enc creado
   ✅ Log registrado: "maria.rrhh cifró contrato_juan_perez.pdf"

4. María comparte con el director:
   Usuario: director.general
   Permisos: Descifrar + Descargar
   Expira: 30/06/2025

5. El director recibe notificación (si está configurado)

6. El director hace login y descifra:
   ✅ Puede ver el contrato
   ✅ Log registrado: "director.general descifró contrato_juan_perez.pdf"

7. Después del 30/06/2025:
   ❌ El director ya no puede acceder al archivo
```

---

### Ejemplo 2: Uso de la API para Automatizar Tareas

**Escenario:** Script Python para monitorear accesos sospechosos.

```python
#!/usr/bin/env python3
"""
Script para detectar accesos sospechosos a archivos
"""
import requests
from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000/api/v1"

# 1. Login
response = requests.post(
    f"{BASE_URL}/auth/login",
    json={"username": "auditor", "password": "contraseña_segura"}
)
token = response.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# 2. Obtener logs de los últimos 7 días
# (Nota: Este endpoint es ilustrativo, puede no estar implementado aún)
response = requests.get(
    f"{BASE_URL}/audit/logs",
    headers=headers,
    params={
        "action": "file.decrypt",
        "status": "success",
        "days": 7
    }
)

logs = response.json()

# 3. Detectar patrones sospechosos
suspicious = []
for log in logs:
    # Detección: Más de 10 descargas por día del mismo usuario
    # (Lógica simplificada)
    if log.get("count", 0) > 10:
        suspicious.append(log)

# 4. Generar alerta
if suspicious:
    print("⚠️ ALERTA: Actividad sospechosa detectada")
    for log in suspicious:
        print(f"  Usuario: {log['user']}")
        print(f"  Descargas: {log['count']}")
        print(f"  Fecha: {log['date']}")
else:
    print("✅ No se detectó actividad sospechosa")
```

---

**¡Fin del Manual de Usuario!**

Para más información técnica, consulta el [README.md](README.md).

---

**File Secure v3.2 Enterprise Edition**
*Protección de nivel empresarial para tus archivos más importantes*

© 2025 Zeligmax - Todos los derechos reservados
