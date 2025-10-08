# 📄 PDF Secure v2.0 - Guía Completa para Principiantes

> Sistema de cifrado de PDFs con autenticación por usuario y control de acceso basado en IP local.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

---

## 📖 **Tabla de Contenidos**

1. [¿Qué es PDF Secure?](#-qué-es-pdf-secure)
2. [Características Principales](#-características-principales)
3. [Requisitos del Sistema](#-requisitos-del-sistema)
4. [Instalación Paso a Paso](#-instalación-paso-a-paso)
5. [Configuración Inicial](#-configuración-inicial)
6. [Cómo Usar el Programa](#-cómo-usar-el-programa)
7. [Ejemplos Prácticos](#-ejemplos-prácticos)
8. [Preguntas Frecuentes](#-preguntas-frecuentes)
9. [Solución de Problemas](#-solución-de-problemas)
10. [Seguridad y Buenas Prácticas](#-seguridad-y-buenas-prácticas)

---

## 🤔 **¿Qué es PDF Secure?**

PDF Secure es un programa que te permite **proteger tus archivos PDF** para que solo personas autorizadas puedan abrirlos. 

### **¿Cómo funciona?**

1. **Tú cifras** un archivo PDF y especificas quién puede abrirlo
2. El programa **genera claves únicas** para cada persona autorizada
3. **Cada persona usa su clave** para descifrar y ver el PDF
4. El sistema **registra quién accedió** y cuándo (auditoría completa)

### **¿Por qué usarlo?**

✅ Proteger documentos confidenciales  
✅ Controlar quién puede ver tus PDFs  
✅ Saber exactamente quién accedió a cada documento  
✅ Las claves expiran automáticamente (seguridad temporal)  
✅ No depende de contraseñas débiles  

---

## ✨ **Características Principales**

- 🔐 **Cifrado AES-256**: Nivel militar de seguridad
- 👥 **Claves por Usuario**: Cada persona tiene su propia clave única
- 🌐 **Control de IP Local**: Whitelist opcional de dispositivos autorizados
- 📊 **Auditoría Completa**: Registro detallado de todos los accesos
- ⏰ **Expiración Automática**: Las claves caducan después de 30 días (configurable)
- 🖥️ **Dos Interfaces**: GUI amigable y CLI para expertos
- 🔒 **Seguridad Mejorada**: Sin contraseñas hardcodeadas en el código

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

**Windows:**
```cmd
pip install cryptography
```

**macOS/Linux:**
```bash
pip3 install cryptography
```

**O usando el archivo requirements.txt:**
```bash
pip install -r requirements.txt
```

Espera a que termine la instalación. Verás algo como:
```
Successfully installed cryptography-41.0.7
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

## 📜 **Licencia**

Este proyecto está licenciado bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 **Autor**

**Desarrollado por**: Zeligmax  
**Versión**: 2.0  
**Fecha**: Enero 2025  

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
pip install cryptography

# 3. Configura la clave maestra
export PDF_SECURE_MASTER_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# 4. ¡Inicia la aplicación!
python3 app/app_gui.py
```

---

**💡 Recuerda**: La seguridad de tus documentos depende de cómo gestiones las claves. ¡Guárdalas de forma segura!

---

<div align="center">

**Si este proyecto te resultó útil, ¡dale una ⭐ en GitHub!**

[⬆ Volver arriba](#-pdf-secure-v20---guía-completa-para-principiantes)

</div>