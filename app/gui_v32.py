#!/usr/bin/env python3
"""
File Secure GUI v3.2 Enterprise Edition
Interfaz gráfica básica para File Secure v3.2
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

# Agregar directorio al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import get_db_manager
from app.core.config import get_config_manager
from sqlalchemy.orm import Session


class LoginWindow:
    """Ventana de login"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Secure v3.2 - Login")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        # Centrar ventana
        self.root.eval('tk::PlaceWindow . center')

        # Variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.user = None
        self.session = None

        self.create_widgets()

    def create_widgets(self):
        """Crear widgets de login"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Logo/Título
        title_label = ttk.Label(
            main_frame,
            text="📁 File Secure v3.2",
            font=('Arial', 18, 'bold')
        )
        title_label.pack(pady=(0, 10))

        subtitle = ttk.Label(
            main_frame,
            text="Enterprise Edition",
            font=('Arial', 10)
        )
        subtitle.pack(pady=(0, 20))

        # Frame de login
        login_frame = ttk.LabelFrame(main_frame, text="Iniciar Sesión", padding="15")
        login_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Usuario
        ttk.Label(login_frame, text="Usuario:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(login_frame, textvariable=self.username_var, width=25)
        username_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        username_entry.focus()

        # Contraseña
        ttk.Label(login_frame, text="Contraseña:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=25)
        password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))

        # Bind Enter key
        password_entry.bind('<Return>', lambda e: self.login())

        # Botón login
        login_btn = ttk.Button(
            login_frame,
            text="Iniciar Sesión",
            command=self.login,
            width=20
        )
        login_btn.grid(row=2, column=0, columnspan=2, pady=15)

        # Info
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(10, 0))

        info_text = ttk.Label(
            info_frame,
            text="Credenciales por defecto:\nUsuario: admin\nContraseña: Admin@123456",
            font=('Arial', 8),
            foreground='gray',
            justify=tk.CENTER
        )
        info_text.pack()

    def login(self):
        """Procesar login"""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Ingresa usuario y contraseña")
            return

        try:
            # Obtener database manager
            config = get_config_manager()
            db_manager = get_db_manager(config.config.database.url)

            # Crear sesión directamente (no como context manager)
            self.session = db_manager.SessionLocal()

            # Importar modelo User
            from app.models.user import User

            # Buscar usuario
            user = self.session.query(User).filter_by(username=username).first()

            if not user:
                messagebox.showerror("Error", "Usuario no encontrado")
                self.session.close()
                self.session = None
                return

            # Verificar contraseña
            if not user.check_password(password):
                messagebox.showerror("Error", "Contraseña incorrecta")
                self.session.close()
                self.session = None
                return

            # Verificar usuario activo
            if not user.is_active:
                messagebox.showerror("Error", "Usuario desactivado")
                self.session.close()
                self.session = None
                return

            # Verificar usuario bloqueado
            if user.is_locked:
                messagebox.showerror("Error", "Usuario bloqueado")
                self.session.close()
                self.session = None
                return

            # Login exitoso
            self.user = user
            self.root.destroy()

        except Exception as e:
            messagebox.showerror("Error de Login", f"Error al iniciar sesión:\n{str(e)}")
            if self.session:
                self.session.close()
                self.session = None

    def run(self):
        """Ejecutar ventana de login"""
        self.root.mainloop()
        return self.user, self.session


class MainWindow:
    """Ventana principal después del login"""

    def __init__(self, user, session):
        self.user = user
        self.session = session

        self.root = tk.Tk()
        self.root.title(f"File Secure v3.2 - {user.username}")
        self.root.geometry("900x600")

        # Configurar cierre
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.create_widgets()

    def create_widgets(self):
        """Crear widgets principales"""
        # Frame superior - Barra de info
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)

        ttk.Label(
            top_frame,
            text=f"👤 Usuario: {self.user.username} ({self.user.full_name or 'Sin nombre'})",
            font=('Arial', 10, 'bold')
        ).pack(side=tk.LEFT)

        # Obtener roles
        roles_text = ", ".join([role.name for role in self.user.roles]) if self.user.roles else "Sin roles"
        ttk.Label(
            top_frame,
            text=f"🎭 Roles: {roles_text}",
            font=('Arial', 9)
        ).pack(side=tk.LEFT, padx=(20, 0))

        ttk.Button(
            top_frame,
            text="Cerrar Sesión",
            command=self.on_closing
        ).pack(side=tk.RIGHT)

        # Separador
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Notebook con pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Crear pestañas
        self.create_dashboard_tab()
        self.create_info_tab()
        self.create_api_tab()

        # Barra de estado
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_label = ttk.Label(
            status_frame,
            text=f"📁 File Secure v3.2 Enterprise | Organización: {self.user.organization.display_name}",
            relief=tk.SUNKEN
        )
        self.status_label.pack(fill=tk.X, padx=2, pady=2)

    def create_dashboard_tab(self):
        """Pestaña de dashboard"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Dashboard")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="Bienvenido a File Secure v3.2 Enterprise",
            font=('Arial', 16, 'bold')
        ).pack(pady=(0, 20))

        # Información del usuario
        user_frame = ttk.LabelFrame(main_frame, text="👤 Información del Usuario", padding="15")
        user_frame.pack(fill=tk.X, pady=10)

        user_info = f"""Usuario: {self.user.username}
Email: {self.user.email or 'No configurado'}
Nombre completo: {self.user.full_name or 'No configurado'}
Organización: {self.user.organization.display_name}
Departamento: {self.user.department.display_name if self.user.department else 'Sin departamento'}
Admin: {'Sí' if self.user.is_admin else 'No'}
Roles: {', '.join([role.name for role in self.user.roles]) if self.user.roles else 'Sin roles'}
MFA: {'Activado' if self.user.mfa_enabled else 'Desactivado'}
Último login: {self.user.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.user.last_login else 'Nunca'}"""

        text = tk.Text(user_frame, height=10, wrap=tk.WORD, font=('Courier', 9))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, user_info)
        text.config(state=tk.DISABLED)

        # Estadísticas
        stats_frame = ttk.LabelFrame(main_frame, text="📊 Estadísticas del Sistema", padding="15")
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        try:
            from app.models.user import User
            from app.models.file import SecureFile
            from app.models.audit_log import AuditLog

            total_users = self.session.query(User).count()
            total_files = self.session.query(SecureFile).count()
            total_logs = self.session.query(AuditLog).count()

            stats_text = f"""Total de usuarios: {total_users}
Total de archivos: {total_files}
Total de logs de auditoría: {total_logs}
Base de datos: SQLite/PostgreSQL"""

            text = tk.Text(stats_frame, height=5, wrap=tk.WORD, font=('Courier', 9))
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, stats_text)
            text.config(state=tk.DISABLED)
        except Exception as e:
            ttk.Label(stats_frame, text=f"Error al cargar estadísticas: {str(e)}").pack()

    def create_info_tab(self):
        """Pestaña de información"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="ℹ️ Info")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="Acerca de File Secure v3.2",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        info_text = """📁 File Secure v3.2 Enterprise Edition

✨ Características Principales:
• Multi-Tenancy: Organizaciones y departamentos aislados
• RBAC Completo: 6 roles predefinidos + permisos granulares
• Auditoría Centralizada: Logs de todas las acciones
• Políticas Configurables: 6 tipos de políticas
• REST API v1: JWT authentication
• Cifrado AES-256: Nivel militar de seguridad
• Soporte multi-formato: PDF, DOCX, XLSX, TXT, PBIP, PBIX

🔐 Roles del Sistema:
• SuperAdmin: Control total del sistema
• OrgAdmin: Administrador de organización
• DepartmentManager: Gestor de departamento
• Editor: Crear y editar archivos
• Viewer: Solo lectura
• Auditor: Acceso a logs y reportes

📚 Documentación:
• README.md: Guía completa del sistema
• USER_MANUAL.md: Manual para usuarios finales
• API: http://localhost:5000/api/v1 (si está corriendo)

👨‍💻 Desarrollado por: Zeligmax
📄 Licencia: MIT
📅 Fecha: Enero 2025
"""

        text = tk.Text(main_frame, wrap=tk.WORD, font=('Courier', 9))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, info_text)
        text.config(state=tk.DISABLED)

    def create_api_tab(self):
        """Pestaña de información de API"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔌 API REST")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="REST API v1",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.BOTH, expand=True)

        api_info = """🔌 REST API de File Secure v3.2

Para funciones avanzadas, usa la API REST:

1. Iniciar la API:
   python run_api_v32.py

2. La API estará disponible en:
   http://localhost:5000/api/v1

3. Endpoints disponibles:
   • POST /api/v1/auth/login - Login
   • GET /api/v1/auth/me - Info del usuario
   • POST /api/v1/auth/change-password - Cambiar contraseña
   • POST /api/v1/auth/logout - Cerrar sesión

4. Ejemplo de login con curl:
   curl -X POST http://localhost:5000/api/v1/auth/login \\
     -H "Content-Type: application/json" \\
     -d '{"username":"admin","password":"Admin@123456"}'

5. Ejemplo con Python:
   import requests

   response = requests.post(
       'http://localhost:5000/api/v1/auth/login',
       json={'username': 'admin', 'password': 'Admin@123456'}
   )

   token = response.json()['token']

📖 Para más información, consulta:
• USER_MANUAL.md - Manual completo con ejemplos
• README.md - Documentación técnica
"""

        text = tk.Text(info_frame, wrap=tk.WORD, font=('Courier', 9))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, api_info)
        text.config(state=tk.DISABLED)

        # Botón para copiar ejemplo
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            btn_frame,
            text="📋 Copiar comando de inicio de API",
            command=lambda: self.copy_to_clipboard("python run_api_v32.py")
        ).pack(side=tk.LEFT)

    def copy_to_clipboard(self, text):
        """Copiar texto al portapapeles"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copiado", "Comando copiado al portapapeles")

    def on_closing(self):
        """Cerrar ventana"""
        if messagebox.askokcancel("Cerrar Sesión", "¿Deseas cerrar File Secure?"):
            try:
                if self.session:
                    self.session.close()
            except:
                pass
            self.root.destroy()

    def run(self):
        """Ejecutar ventana principal"""
        self.root.mainloop()


def main():
    """Función principal"""
    try:
        # Verificar Tkinter
        root = tk.Tk()
        root.withdraw()
        root.destroy()
    except tk.TclError:
        print("❌ Tkinter no está disponible")
        print("   En Linux: sudo apt-get install python3-tk")
        sys.exit(1)

    try:
        # Mostrar ventana de login
        login_window = LoginWindow()
        user, session = login_window.run()

        # Si el login fue exitoso, mostrar ventana principal
        if user and session:
            main_window = MainWindow(user, session)
            main_window.run()

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
