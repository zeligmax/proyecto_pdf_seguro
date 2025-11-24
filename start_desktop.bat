@echo off
chcp 65001 >nul
title File Secure Manager - Desktop App

echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║      File Secure Manager - Desktop Launcher               ║
echo ║                     Version 3.1                           ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

REM Verificar que Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python no está instalado o no está en el PATH
    echo.
    echo Por favor instala Python desde: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo ✅ Python detectado
echo.

REM Verificar/Crear entorno virtual
if not exist ".venv" (
    echo 📦 Creando entorno virtual...
    python -m venv .venv
    echo ✅ Entorno virtual creado
    echo.
)

REM Verificar que las dependencias están instaladas
.venv\Scripts\python.exe -c "import cryptography, PIL, fitz" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Instalando dependencias necesarias...
    echo.
    .venv\Scripts\pip.exe install cryptography pillow PyMuPDF requests --quiet
    echo ✅ Dependencias instaladas
    echo.
)

echo 🚀 Iniciando File Secure Manager...
echo.

REM Ejecutar aplicación de escritorio usando el venv
.venv\Scripts\python.exe app\app_gui.py

echo.
echo 👋 Aplicación cerrada
echo.
pause
