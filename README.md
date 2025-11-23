# 📁 File Secure v3.1 - Guía Completa para Principiantes

> Sistema profesional de cifrado de archivos con autenticación por usuario, visualizador en memoria y control de acceso basado en IP local.
> **Soporta múltiples formatos**: PDF, DOCX, XLSX, TXT, PBIP, PBIX

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

---

## 📖 **Tabla de Contenidos**

1. [¿Qué es File Secure?](#-qué-es-file-secure)
2. [Características Principales](#-características-principales)
3. [📁 Soporte Multi-formato](#-soporte-multi-formato-desde-v31)
4. [🆕 API de Detección de Usuarios](#-api-de-detección-de-usuarios)
5. [Requisitos del Sistema](#-requisitos-del-sistema)
6. [Instalación Paso a Paso](#-instalación-paso-a-paso)
7. [Configuración Inicial](#-configuración-inicial)
8. [Cómo Usar el Programa](#-cómo-usar-el-programa)
9. [Ejemplos Prácticos](#-ejemplos-prácticos)
10. [Preguntas Frecuentes](#-preguntas-frecuentes)
11. [Solución de Problemas](#-solución-de-problemas)
12. [Seguridad y Buenas Prácticas](#-seguridad-y-buenas-prácticas)

---

## 🤔 **¿Qué es File Secure?**

File Secure es un sistema profesional que te permite **proteger cualquier tipo de archivo** (PDF, DOCX, XLSX, TXT, PBIP, PBIX, y más) para que solo personas autorizadas puedan abrirlos.

### **¿Cómo funciona?**

1. **Tú cifras** un archivo y especificas quién puede abrirlo
2. El programa **genera claves únicas** para cada persona autorizada
3. **Cada persona usa su clave** para descifrar y ver el archivo
4. El sistema **registra quién accedió** y cuándo (auditoría completa)

### **¿Por qué usarlo?**

✅ Proteger documentos confidenciales
✅ Controlar quién puede ver tus archivos
✅ Saber exactamente quién accedió a cada documento
✅ Las claves expiran automáticamente (seguridad temporal)
✅ No depende de contraseñas débiles
✅ **Nuevo**: Soporta múltiples formatos de archivo  

---

## ✨ **Características Principales**

- 🔐 **Cifrado AES-256**: Nivel militar de seguridad (v2.1 con metadatos cifrados)
- 👥 **Claves por Usuario**: Cada persona tiene su propia clave única
- 🔑 **Verificación de Usuario del Sistema**: Valida que el usuario logueado coincida con el autorizado
- 📁 **Soporte Multi-formato (v3.1)**: PDF, DOCX, XLSX, TXT, PBIP, PBIX, y más
- 🌐 **Control de IP Local**: Whitelist opcional de dispositivos autorizados
- 📊 **Auditoría Completa**: Registro detallado de todos los accesos
- ⏰ **Expiración Automática**: Las claves caducan después de 30 días (configurable)
- 🖥️ **Dos Interfaces**: GUI amigable y CLI para expertos
- 🔒 **Seguridad Mejorada**: Sin contraseñas hardcodeadas en el código
- 🆕 **API de Usuarios**: Detecta y lista usuarios del sistema operativo
- 👁️ **Visualizadores en Memoria**: Ver archivos sin guardarlos en disco (solo lectura)
  - PDF: Renderizado completo con PyMuPDF
  - Texto: Archivos .txt, .md, .log, .csv
  - Imágenes: .jpg, .png, .gif, .bmp, .webp
  - Office: Información de archivos .docx, .xlsx, .pptx

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

## 🆕 **API de Detección de Usuarios**

### **Nueva Funcionalidad: API REST para Detección de Usuarios**

File Secure incluye una API REST que permite detectar y listar usuarios del sistema operativo (Windows/Linux/macOS).

#### **¿Para qué sirve?**

✅ **Validar usuarios** antes de cifrar PDFs
✅ **Autocompletar** nombres de usuarios en la interfaz
✅ **Auditoría** de usuarios del sistema
✅ **Integración** con otros sistemas y aplicaciones

#### **Inicio Rápido**

```bash
# 1. Instalar dependencias
pip install flask flask-cors

# 2. Ejecutar la API
python run_users_api.py

# 3. Acceder a la API
# Navegador: http://localhost:5000
# curl: curl http://localhost:5000/api/users
```

#### **Endpoints Principales**

- `GET /api/users` - Lista todos los usuarios del sistema
- `GET /api/users/current` - Usuario actual
- `GET /api/users/logged` - Usuarios conectados
- `GET /api/system` - Información del sistema
- `GET /api/report` - Reporte completo

#### **Documentación Completa**

📖 Ver [API_USERS_GUIDE.md](API_USERS_GUIDE.md) para documentación detallada
🚀 Ver [QUICKSTART_API.md](QUICKSTART_API.md) para inicio rápido
💻 Ver [ejemplo_uso_api.py](ejemplo_uso_api.py) para ejemplos de código

---

## 💻 **Requisitos del Sistema**

### **Software Necesario:**

- **Python 3.8 o superior** ([Descargar aquí](https://www.python.org/downloads/))
- **pip** (gestor de paquetes de Python, viene con Python)
- **Sistema Operativo**: Windows 10/11, macOS 10.14+, Linux (cualquier distribución)

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

---

## 📥 **Instalación Paso a Paso**

### **Paso 1: Descargar el Proyecto**

#### **Opción A: Usando Git (Recomendado)**

```bash
# Abre una terminal y ejecuta:
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro
```

#### **Opción B: Descarga Manual**

1. Ve a: https://github.com/zeligmax/proyecto_pdf_seguro
2. Click en el botón verde **"Code"** → **"Download ZIP"**
3. Descomprime el archivo en una carpeta de tu elección
4. Abre una terminal en esa carpeta

---

### **Paso 2: Crear la Estructura de Archivos**

Asegúrate de que tu proyecto tenga esta estructura:

```
proyecto_pdf_seguro/
├── app/
│   ├── config.py
│   ├── user_auth.py
│   ├── pdf_utils_v2.py
│   ├── ip_check.py
│   ├── main.py
│   └── app_gui.py
├── requirements.txt
├── setup.py
└── README.md
```

Si falta algún archivo, copia el código de los artifacts proporcionados.

---

### **Paso 3: Instalar Dependencias**

Abre una terminal en la carpeta del proyecto y ejecuta:

**Dependencias Básicas (Obligatorias):**

**Windows:**
```cmd
pip install cryptography
```

**macOS/Linux:**
```bash
pip3 install cryptography
```

**Dependencias Opcionales (Para visualizador de PDF):**

Si quieres usar el visualizador de PDF integrado en la GUI:

```bash
pip install PyMuPDF Pillow
```

**O usando el archivo requirements.txt:**
```bash
pip install -r requirements.txt
```

Espera a que termine la instalación. Verás algo como:
```
Successfully installed cryptography-41.0.7
Successfully installed PyMuPDF-1.26.6 Pillow-10.x.x
```

✅ ¡Listo! Ya tienes todo instalado.

---

## 🔧 **Configuración Inicial**

### **Paso 1: Generar y Configurar la Clave Maestra**

La clave maestra es **MUY IMPORTANTE**. Sin ella, no podrás cifrar ni descifrar archivos.

#### **En Windows (PowerShell):**

```powershell
# 1. Genera la clave
$key = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. Muestra la clave (¡CÓPIALA EN UN LUGAR SEGURO!)
echo $key

# 3. Configura la variable de entorno
$env:PDF_SECURE_MASTER_KEY = $key

# 4. Verifica que funcionó
echo $env:PDF_SECURE_MASTER_KEY
```

#### **En macOS/Linux (Terminal):**

```bash
# 1. Genera y configura la clave en un solo paso
export PDF_SECURE_MASTER_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# 2. Verifica que funcionó
echo $PDF_SECURE_MASTER_KEY
```

Deberías ver algo como: `gAAAAABk7X9Y...` (una cadena larga de caracteres)

---

### **Paso 2: Hacer la Configuración Permanente (Opcional pero Recomendado)**

Si cierras la terminal, tendrás que volver a configurar la clave. Para evitarlo:

#### **Windows (Permanente):**

```powershell
# Ejecuta PowerShell como Administrador y ejecuta:
[Environment]::SetEnvironmentVariable('PDF_SECURE_MASTER_KEY', 'pega_aqui_tu_clave', 'User')
```

Reemplaza `pega_aqui_tu_clave` con la clave que generaste.

#### **macOS/Linux (Permanente):**

```bash
# Agrega la clave a tu archivo de configuración del shell
echo 'export PDF_SECURE_MASTER_KEY="pega_aqui_tu_clave"' >> ~/.bashrc

# Si usas zsh (macOS moderno):
echo 'export PDF_SECURE_MASTER_KEY="pega_aqui_tu_clave"' >> ~/.zshrc

# Recarga la configuración
source ~/.bashrc  # o source ~/.zshrc
```

---

### **Paso 3: Verificar la Instalación**

```bash
python3 app/config.py
```

Deberías ver:
```
📁 Configuración de PDF Secure
==================================================
📂 Directorio: /home/usuario/.pdf_secure
✅ Existe: True
🔑 Clave maestra: ✅ Configurada
🌐 IPs en whitelist: 0
```

✅ **¡Perfecto! Ya estás listo para usar PDF Secure.**

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

![GUI Screenshot](https://github.com/zeligmax/proyecto_pdf_seguro/blob/main/GUI_Screenshot.png)

#### **Las Pestañas:**

1. **🔒 Cifrar Archivo**: Para proteger tus archivos (PDF, DOCX, XLSX, TXT, PBIP, PBIX)
2. **🔓 Descifrar Archivo**: Para abrir archivos protegidos (2 opciones disponibles)
   - **👁️ Ver Archivo**: Visualiza el archivo en memoria sin guardarlo en disco (solo lectura)
     - PDF: Renderizado completo
     - Texto: Editor de texto integrado
     - Imágenes: Visor de imágenes
     - Office: Información del archivo
   - **🔓 Descifrar y Guardar**: Descifra y guarda el archivo en disco
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
1. 🔒 Cifrar Archivo
2. 🔓 Descifrar Archivo
3. 📋 Ver información de archivo
4. 👥 Gestionar usuarios
5. 🌐 Gestionar IPs autorizadas
6. 📊 Ver logs de acceso
7. 🧹 Mantenimiento
8. 🔍 Gestionar API de Usuarios
9. ❓ Ayuda
0. 🚪 Salir

ℹ️  Formatos soportados: PDF, DOCX, XLSX, TXT, PBIP, PBIX
```

Simplemente escribe el número de la opción que quieres y presiona Enter.

---

## 📚 **Ejemplos Prácticos**

### **Ejemplo 1: Proteger un Archivo para 3 Personas**

#### **Usando la GUI:**

1. **Abre la GUI**: `python3 app/app_gui.py`

2. **Ve a la pestaña "🔒 Cifrar Archivo"**

3. **Selecciona tu archivo:**
   - Click en "Examinar"
   - Busca y selecciona tu archivo (ej: `contrato_secreto.pdf`, `datos.xlsx`, `reporte.docx`)
   - Formatos soportados: PDF, DOCX, XLSX, TXT, PBIP, PBIX

4. **El archivo de salida se autocompleta** (ej: `contrato_secreto.enc`)

5. **Ingresa los usuarios autorizados:**
   ```
   juan, maria, carlos
   ```

6. **Click en "🔒 Cifrar"**

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

#### **Opción A: Ver PDF sin guardarlo (Nuevo en v2.1)**

Esta opción te permite ver el PDF sin crear ningún archivo en disco (máxima seguridad).

1. **Abre la GUI**: `python3 app/app_gui.py`

2. **Ve a la pestaña "🔓 Descifrar PDF"**

   ℹ️ **Nota**: Verás tu usuario actual del sistema (ej: "👤 Usuario del sistema: María"). Solo podrás descifrar archivos autorizados para ese usuario.

3. **Selecciona el archivo cifrado:**
   - Click en "Examinar"
   - Busca `contrato_secreto.enc`

4. **Ingresa tu clave:**
   ```
   z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0
   ```

5. **(Opcional) Marca "Mostrar clave"** para verificar que la escribiste bien

6. **Click en "👁️ Ver PDF"**

7. **¡Listo!** Se abre una ventana emergente mostrando el PDF:
   - ✅ Puedes ver todas las páginas con scroll
   - ✅ El PDF NO se guarda en disco
   - ✅ Es solo lectura (no se puede editar)
   - ✅ Mayor seguridad: no deja rastros en disco

**⚠️ Importante**: El sistema verifica que:
- La clave sea correcta
- El usuario del sistema coincida con el usuario autorizado para esa clave
- La IP esté autorizada (si hay whitelist activa)

#### **Opción B: Descifrar y guardar en disco (Tradicional)**

Si necesitas guardar el PDF para editarlo o usarlo con otras aplicaciones:

1. **Sigue los pasos 1-5 del Opción A**

2. **Click en "🔓 Descifrar y Guardar"** (en lugar de "Ver PDF")

3. **¡Listo!** El PDF descifrado aparece en la misma carpeta con un nombre como:
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
- Tipo de acceso (VIEW_ATTEMPT o DECRYPT_ATTEMPT)

---

### **¿Cuál es la diferencia entre "Ver PDF" y "Descifrar y Guardar"?**

**👁️ Ver PDF (Nuevo en v2.1):**
- ✅ El PDF se descifra **solo en memoria** (RAM)
- ✅ **NO se guarda** ningún archivo en disco
- ✅ Mayor seguridad: no deja rastros
- ✅ Solo lectura: no se puede editar
- ✅ Ideal para consultas rápidas o información sensible
- ⚠️ Requiere PyMuPDF instalado

**🔓 Descifrar y Guardar:**
- ✅ El PDF se descifra y **se guarda en disco**
- ✅ Puedes editarlo con cualquier programa
- ✅ El archivo queda disponible sin necesidad de clave
- ⚠️ Menos seguro: el archivo queda en disco sin protección

**¿Cuándo usar cada uno?**
- **Ver PDF**: Para revisar documentos confidenciales sin dejar rastro
- **Descifrar y Guardar**: Cuando necesitas editar o trabajar con el PDF

---

### **¿Qué significa "Usuario del sistema no coincide"?**

**Explicación**: File Secure implementa una capa adicional de seguridad que verifica que el usuario logueado en el sistema operativo coincida con el usuario autorizado para la clave.

**Ejemplo del error:**
```
Usuario del sistema no coincide.
Usuario actual del sistema: Juan
Usuario autorizado para esta clave: María
Debes estar logueado como 'María' para descifrar este archivo.
```

**¿Por qué pasa esto?**

Cada clave está vinculada a un usuario específico. Cuando María cifró el PDF y autorizó a "María" como usuario, el sistema ahora verifica que quien intenta descifrar esté realmente logueado como "María" en el sistema operativo.

**Solución:**

1. **Opción A (Recomendada)**: Cierra sesión e inicia sesión con el usuario correcto
   - Windows: Cambiar de usuario o reiniciar sesión
   - Linux/macOS: `su - usuario_correcto` o cambiar de sesión

2. **Opción B**: Pide al administrador que genere una nueva clave para tu usuario actual

**Seguridad mejorada:**

Esta verificación previene que alguien que robó una clave pueda usarla desde otra cuenta de usuario, añadiendo una capa extra de protección.

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

### **Problema: El botón "Ver PDF" no muestra el PDF**

**Causa**: PyMuPDF no está instalado.

**Solución**:
```bash
pip install PyMuPDF Pillow
```

Luego reinicia la aplicación y vuelve a intentar.

**Nota**: Si no puedes instalar PyMuPDF, usa el botón "Descifrar y Guardar" en su lugar.

---

### **Problema: El visualizador muestra páginas borrosas**

**Causa**: Renderizado a baja resolución.

**Solución**: El visualizador ya está configurado con zoom 2.0 para mejor calidad. Si aún así se ve borroso, usa "Descifrar y Guardar" y abre el PDF con un visor profesional.

---

### **Problema: "Usuario del sistema no coincide"**

**Error completo:**
```
Usuario del sistema no coincide.
Usuario actual del sistema: User
Usuario autorizado para esta clave: Juan
Debes estar logueado como 'Juan' para descifrar este archivo.
```

**Causa**: Estás intentando descifrar con una clave que pertenece a otro usuario.

**Solución**:

**Opción 1 - Cambiar de usuario (Windows):**
```
1. Win + L (Bloquear sesión)
2. Click en "Cambiar de usuario"
3. Inicia sesión con el usuario correcto
4. Vuelve a intentar descifrar
```

**Opción 2 - Cambiar de usuario (Linux/macOS):**
```bash
# Cambiar a otro usuario
su - nombre_usuario

# O iniciar nueva sesión de terminal
sudo -u nombre_usuario -i
```

**Opción 3 - Generar nueva clave:**

Si no puedes cambiar de usuario, pide al administrador que cifre nuevamente el archivo incluyendo tu usuario actual en la lista de autorizados.

**Nota de seguridad**: Esta verificación es intencional para prevenir que claves robadas sean usadas desde otras cuentas.

---

## 🔒 **Seguridad y Buenas Prácticas**

### **✅ Recomendaciones de Seguridad**

1. **Gestión de Claves**:
   - ✅ Usa un gestor de contraseñas (LastPass, 1Password, Bitwarden)
   - ✅ Nunca compartas claves por email o chat
   - ✅ Cambia claves periódicamente (cada 30-60 días)
   - ❌ No escribas claves en papeles o archivos de texto sin cifrar
   - ⚠️ **Cada clave está vinculada a un usuario específico del sistema**

2. **Verificación de Usuario del Sistema** (NUEVO en v2.1):
   - ✅ El sistema verifica que el usuario logueado coincida con el usuario autorizado
   - ✅ **No basta con tener la clave**: debes estar logueado como el usuario correcto
   - ✅ Esto previene que claves robadas sean usadas desde otras cuentas
   - ⚠️ Si cambias de computadora, asegúrate de usar el mismo nombre de usuario

3. **Visualización de PDFs**:
   - ✅ **Usa "Ver PDF" en lugar de "Descifrar y Guardar"** cuando solo necesites consultar el documento
   - ✅ El visualizador en memoria NO deja rastros en disco
   - ✅ Mayor seguridad para información confidencial
   - ⚠️ Si descifras y guardas, elimina el archivo cuando termines

4. **Backups**:
   - ✅ Haz backup regular de `~/.pdf_secure/`
   - ✅ Guarda tu clave maestra en un lugar seguro
   - ✅ Documenta qué usuarios tienen acceso a qué archivos

5. **Monitoreo**:
   - ✅ Revisa los logs semanalmente
   - ✅ Investiga intentos de acceso fallidos
   - ✅ Diferencia entre VIEW_ATTEMPT y DECRYPT_ATTEMPT en los logs
   - ✅ Monitorea intentos con estado USER_MISMATCH (posibles claves robadas)
   - ✅ Limpia claves expiradas regularmente

6. **Control de Acceso**:
   - ✅ Usa whitelist de IPs cuando sea posible
   - ✅ Revoca acceso inmediatamente cuando sea necesario
   - ✅ Usa descripciones claras para cada IP autorizada

---

### **⚠️ Limitaciones Conocidas**

1. **Trazabilidad post-descifrado**: Una vez que alguien descifra el PDF, puede copiarlo sin restricciones. El PDF descifrado no tiene protección adicional.

2. **Dependencia de clave maestra**: Si pierdes la clave maestra, pierdes acceso a TODOS los archivos cifrados.

3. **IP local únicamente**: El control de IP solo funciona en red local, no identifica dispositivos específicos de forma única.

4. **Verificación de usuario basada en nombre**: La verificación de usuario del sistema compara nombres de usuario (Windows, Linux, macOS). Si dos computadoras tienen el mismo nombre de usuario, ambas podrán descifrar (siempre que tengan la clave correcta).

---

### **🔐 Autenticación de Dos Factores**

**File Secure implementa autenticación de dos factores:**

1. **Factor 1 - Lo que sabes**: La clave de usuario (64 caracteres hexadecimales)
2. **Factor 2 - Quién eres**: Tu nombre de usuario en el sistema operativo

**Ventajas:**
- ✅ Una clave robada no es suficiente para descifrar
- ✅ El atacante también necesitaría acceso a la cuenta del usuario
- ✅ Los logs registran intentos con usuario incorrecto (USER_MISMATCH)

**Ejemplo práctico:**

Si María tiene la clave `abc123...` pero Juan roba esa clave:
- Juan intenta descifrar desde su cuenta → ❌ DENEGADO (usuario no coincide)
- María descifra desde su cuenta → ✅ PERMITIDO (clave + usuario correcto)

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

## 📜 **Licencia**

Este proyecto está licenciado bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 **Autor**

**Desarrollado por**: Zeligmax
**Versión**: 3.1
**Fecha**: Enero 2025

**Novedades v3.1**:
- 🎯 **Renombramiento completo**: De "PDF Secure" a "File Secure"
- 🔧 **Arquitectura mejorada**: Clase `FileSecureManager` (antes `PDFSecureManager`)
- 📁 **Soporte multi-formato**: PDF, DOCX, XLSX, TXT, PBIP, PBIX
- 👁️ **Múltiples visualizadores**: PDF (renderizado), texto, imágenes, información de Office
- 🔄 **Compatibilidad total**: Compatible con archivos v2.0, v2.1 y v2.2
- 🎨 **Interfaz actualizada**: GUI y CLI reflejan la nueva identidad

**Novedades v2.2** (integradas en v3.1):
- Soporte multi-formato inicial
- Visualizadores especializados por tipo de archivo
- Metadatos con información de tipo de archivo

**Novedades v2.1**:
- Visualizador de PDF en memoria (sin guardar en disco)
- Metadatos cifrados para mayor seguridad
- Logs diferenciados (VIEW_ATTEMPT vs DECRYPT_ATTEMPT)
- Verificación de usuario del sistema (clave + usuario logueado)  

---

## 🙏 **Agradecimientos**

Agradecimientos especiales a todos los colaboradores y revisores técnicos que hicieron posible las mejoras de seguridad implementadas en v2.0.

---

## 🚀 **¿Listo para Empezar?**

```bash
# 1. Clona el repositorio
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro

# 2. Instala dependencias
pip install cryptography PyMuPDF Pillow

# 3. Configura la clave maestra
export PDF_SECURE_MASTER_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# 4. ¡Inicia la aplicación!
python3 app/app_gui.py

# 5. Prueba el visualizador en memoria:
#    - Ve a "Descifrar PDF"
#    - Selecciona un archivo .enc
#    - Ingresa tu clave
#    - Click en "Ver PDF" para visualizar sin guardar en disco
```

---

**💡 Recuerda**: La seguridad de tus documentos depende de cómo gestiones las claves. ¡Guárdalas de forma segura!

---

<div align="center">

**Si este proyecto te resultó útil, ¡dale una ⭐ en GitHub!**

[⬆ Volver arriba](#-file-secure-v31---guía-completa-para-principiantes)

</div>
