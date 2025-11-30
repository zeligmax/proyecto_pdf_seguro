#!/usr/bin/env python3
"""
File Secure GUI v3.2 Enterprise Edition
Interfaz gráfica básica para File Secure v3.2
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
import threading

# Agregar directorio al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import get_db_manager
from app.core.config import get_config_manager
from app.services.file_service import FileService
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
        self.root.geometry("1000x700")

        # Configurar cierre
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Variables para cifrado/descifrado
        self.file_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.users_var = tk.StringVar()
        self.encrypted_path_var = tk.StringVar()
        self.user_key_var = tk.StringVar()
        self.decrypt_output_var = tk.StringVar()

        # Inicializar FileService
        try:
            self.file_service = FileService(self.session, self.user)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo inicializar FileService:\n{str(e)}\n\nAsegúrate de configurar PDF_SECURE_MASTER_KEY")
            self.file_service = None

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
        if self.file_service:  # Solo si FileService se inicializó correctamente
            self.create_encrypt_tab()
            self.create_decrypt_tab()
            self.create_files_tab()
        # Pestaña de gestión de usuarios (solo para admins)
        if self.can_manage_users():
            self.create_users_tab()
        self.create_logs_tab()
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

    def create_encrypt_tab(self):
        """Pestaña de cifrado de archivos"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔒 Cifrar Archivo")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="🔒 Cifrar Archivo con Claves de Usuario",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        # Archivo a cifrar
        file_frame = ttk.LabelFrame(main_frame, text="📄 Archivo a Cifrar", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        file_entry_frame = ttk.Frame(file_frame)
        file_entry_frame.pack(fill=tk.X)
        ttk.Entry(file_entry_frame, textvariable=self.file_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_entry_frame, text="Examinar", command=self.browse_file_to_encrypt).pack(side=tk.RIGHT, padx=(5, 0))

        # Archivo de salida (opcional)
        output_frame = ttk.LabelFrame(main_frame, text="💾 Archivo de Salida (Opcional)", padding=10)
        output_frame.pack(fill=tk.X, pady=(0, 10))

        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X)
        ttk.Entry(output_entry_frame, textvariable=self.output_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_entry_frame, text="Examinar", command=self.browse_output_file).pack(side=tk.RIGHT, padx=(5, 0))

        # Usuarios autorizados
        users_frame = ttk.LabelFrame(main_frame, text="👥 Usuarios Autorizados", padding=10)
        users_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(users_frame, text="Ingresa los nombres de usuario separados por comas:").pack(anchor=tk.W)
        ttk.Entry(users_frame, textvariable=self.users_var, width=50).pack(fill=tk.X, pady=(5, 0))
        ttk.Label(users_frame, text="Ejemplo: usuario1, usuario2, admin", font=('Arial', 9), foreground='gray').pack(anchor=tk.W, pady=(2, 0))

        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)
        ttk.Button(buttons_frame, text="🔒 Cifrar Archivo", command=self.encrypt_file).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="🧹 Limpiar", command=self.clear_encrypt_fields).pack(side=tk.LEFT)

        # Resultados
        results_frame = ttk.LabelFrame(main_frame, text="🔑 Claves Generadas", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.encrypt_results = ScrolledText(results_frame, height=10, wrap=tk.WORD)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True)
        ttk.Button(results_frame, text="📋 Copiar Claves", command=self.copy_encryption_results).pack(pady=(5, 0))

    def create_decrypt_tab(self):
        """Pestaña de descifrado de archivos"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔓 Descifrar Archivo")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="🔓 Descifrar Archivo con Clave de Usuario",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        # Archivo cifrado
        encrypted_frame = ttk.LabelFrame(main_frame, text="🔒 Archivo Cifrado", padding=10)
        encrypted_frame.pack(fill=tk.X, pady=(0, 10))
        encrypted_entry_frame = ttk.Frame(encrypted_frame)
        encrypted_entry_frame.pack(fill=tk.X)
        ttk.Entry(encrypted_entry_frame, textvariable=self.encrypted_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(encrypted_entry_frame, text="Examinar", command=self.browse_encrypted_file).pack(side=tk.RIGHT, padx=(5, 0))

        # Clave de usuario
        key_frame = ttk.LabelFrame(main_frame, text="🔑 Clave de Usuario", padding=10)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Entry(key_frame, textvariable=self.user_key_var, width=50, show="*").pack(fill=tk.X)
        ttk.Button(key_frame, text="👁️ Mostrar/Ocultar", command=self.toggle_key_visibility).pack(pady=(5, 0))

        # Archivo de salida
        decrypt_output_frame = ttk.LabelFrame(main_frame, text="💾 Archivo de Salida (Opcional)", padding=10)
        decrypt_output_frame.pack(fill=tk.X, pady=(0, 10))
        decrypt_output_entry_frame = ttk.Frame(decrypt_output_frame)
        decrypt_output_entry_frame.pack(fill=tk.X)
        ttk.Entry(decrypt_output_entry_frame, textvariable=self.decrypt_output_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(decrypt_output_entry_frame, text="Examinar", command=self.browse_decrypt_output).pack(side=tk.RIGHT, padx=(5, 0))

        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)
        ttk.Button(buttons_frame, text="🔓 Descifrar Archivo", command=self.decrypt_file).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="🧹 Limpiar", command=self.clear_decrypt_fields).pack(side=tk.LEFT)

        # Resultado
        result_frame = ttk.LabelFrame(main_frame, text="📄 Resultado", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.decrypt_results = ScrolledText(result_frame, height=10, wrap=tk.WORD)
        self.decrypt_results.pack(fill=tk.BOTH, expand=True)

    def create_files_tab(self):
        """Pestaña de gestión de archivos"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📁 Mis Archivos")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="📁 Gestión de Archivos Cifrados",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        # Botones de acción
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(buttons_frame, text="🔄 Actualizar Lista", command=self.refresh_files_list).pack(side=tk.LEFT, padx=(0, 10))

        # Lista de archivos
        list_frame = ttk.LabelFrame(main_frame, text="Archivos Accesibles", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview con scrollbar
        tree_scroll = ttk.Scrollbar(list_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.files_tree = ttk.Treeview(
            list_frame,
            columns=('filename', 'size', 'date', 'users'),
            show='headings',
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.files_tree.yview)

        self.files_tree.heading('filename', text='Archivo')
        self.files_tree.heading('size', text='Tamaño')
        self.files_tree.heading('date', text='Fecha de Cifrado')
        self.files_tree.heading('users', text='Cifrado por')

        self.files_tree.column('filename', width=300)
        self.files_tree.column('size', width=100)
        self.files_tree.column('date', width=150)
        self.files_tree.column('users', width=150)

        self.files_tree.pack(fill=tk.BOTH, expand=True)

        # Cargar archivos al inicio
        self.refresh_files_list()

    def create_logs_tab(self):
        """Pestaña de logs de auditoría"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📋 Logs")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="📋 Logs de Auditoría",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        # Botones de acción
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(buttons_frame, text="🔄 Actualizar Logs", command=self.refresh_logs).pack(side=tk.LEFT)

        # Logs
        logs_frame = ttk.LabelFrame(main_frame, text="Últimos 50 Logs", padding=10)
        logs_frame.pack(fill=tk.BOTH, expand=True)

        self.logs_text = ScrolledText(logs_frame, wrap=tk.WORD, font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True)

        # Cargar logs al inicio
        self.refresh_logs()

    # Métodos auxiliares para cifrado
    def browse_file_to_encrypt(self):
        filename = filedialog.askopenfilename(
            title="Seleccionar archivo a cifrar",
            filetypes=[("Todos los archivos", "*.*"), ("PDF", "*.pdf"), ("Word", "*.docx"), ("Excel", "*.xlsx")]
        )
        if filename:
            self.file_path_var.set(filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(
            title="Guardar archivo cifrado como",
            defaultextension=".encrypted",
            filetypes=[("Archivo cifrado", "*.encrypted"), ("Todos los archivos", "*.*")]
        )
        if filename:
            self.output_path_var.set(filename)

    def browse_encrypted_file(self):
        filename = filedialog.askopenfilename(
            title="Seleccionar archivo cifrado",
            filetypes=[("Archivo cifrado", "*.encrypted"), ("Todos los archivos", "*.*")]
        )
        if filename:
            self.encrypted_path_var.set(filename)

    def browse_decrypt_output(self):
        filename = filedialog.asksaveasfilename(
            title="Guardar archivo descifrado como",
            filetypes=[("Todos los archivos", "*.*")]
        )
        if filename:
            self.decrypt_output_var.set(filename)

    def toggle_key_visibility(self):
        """Alternar visibilidad de la clave"""
        # Este método necesitaría una referencia al Entry widget
        # Por ahora solo muestra un mensaje
        messagebox.showinfo("Info", "Copia y pega la clave desde el portapapeles")

    def clear_encrypt_fields(self):
        """Limpiar campos de cifrado"""
        self.file_path_var.set("")
        self.output_path_var.set("")
        self.users_var.set("")
        self.encrypt_results.delete('1.0', tk.END)

    def clear_decrypt_fields(self):
        """Limpiar campos de descifrado"""
        self.encrypted_path_var.set("")
        self.user_key_var.set("")
        self.decrypt_output_var.set("")
        self.decrypt_results.delete('1.0', tk.END)

    def encrypt_file(self):
        """Cifrar archivo"""
        file_path = self.file_path_var.get().strip()
        output_path = self.output_path_var.get().strip() or None
        users_str = self.users_var.get().strip()

        if not file_path:
            messagebox.showerror("Error", "Selecciona un archivo a cifrar")
            return

        if not users_str:
            messagebox.showerror("Error", "Ingresa al menos un usuario autorizado")
            return

        # Parsear usuarios
        authorized_users = [u.strip() for u in users_str.split(',') if u.strip()]

        def encrypt_worker():
            try:
                self.status_label.config(text="Cifrando archivo...")
                secure_file, user_keys = self.file_service.encrypt_file(
                    file_path=file_path,
                    authorized_usernames=authorized_users,
                    output_path=output_path
                )

                # Mostrar resultados
                result_text = f"✅ Archivo cifrado exitosamente\n\n"
                result_text += f"Archivo: {secure_file.original_filename}\n"
                result_text += f"Ubicación: {secure_file.file_path}\n\n"
                result_text += "🔑 CLAVES DE USUARIO (guárdalas de forma segura):\n"
                result_text += "=" * 60 + "\n\n"

                for username, key in user_keys.items():
                    result_text += f"Usuario: {username}\n"
                    result_text += f"Clave: {key}\n"
                    result_text += "-" * 60 + "\n\n"

                result_text += "\n⚠️ IMPORTANTE: Guarda estas claves de forma segura.\n"
                result_text += "Sin la clave, no será posible descifrar el archivo."

                self.encrypt_results.delete('1.0', tk.END)
                self.encrypt_results.insert('1.0', result_text)
                self.status_label.config(text="Archivo cifrado correctamente")

                messagebox.showinfo("Éxito", "Archivo cifrado correctamente")

            except Exception as e:
                self.status_label.config(text="Error al cifrar archivo")
                messagebox.showerror("Error", f"No se pudo cifrar el archivo:\n{str(e)}")

        # Ejecutar en thread separado
        thread = threading.Thread(target=encrypt_worker, daemon=True)
        thread.start()

    def decrypt_file(self):
        """Descifrar archivo"""
        encrypted_path = self.encrypted_path_var.get().strip()
        user_key = self.user_key_var.get().strip()
        output_path = self.decrypt_output_var.get().strip() or None

        if not encrypted_path:
            messagebox.showerror("Error", "Selecciona un archivo cifrado")
            return

        if not user_key:
            messagebox.showerror("Error", "Ingresa la clave de usuario")
            return

        def decrypt_worker():
            try:
                self.status_label.config(text="Descifrando archivo...")
                decrypted_path = self.file_service.decrypt_file(
                    encrypted_path=encrypted_path,
                    user_key=user_key,
                    output_path=output_path,
                    read_only=False
                )

                result_text = f"✅ Archivo descifrado exitosamente\n\n"
                result_text += f"Ubicación: {decrypted_path}\n\n"
                result_text += "El archivo ha sido descifrado y guardado correctamente."

                self.decrypt_results.delete('1.0', tk.END)
                self.decrypt_results.insert('1.0', result_text)
                self.status_label.config(text="Archivo descifrado correctamente")

                messagebox.showinfo("Éxito", f"Archivo descifrado en:\n{decrypted_path}")

            except Exception as e:
                self.status_label.config(text="Error al descifrar archivo")
                messagebox.showerror("Error", f"No se pudo descifrar el archivo:\n{str(e)}")

        # Ejecutar en thread separado
        thread = threading.Thread(target=decrypt_worker, daemon=True)
        thread.start()

    def copy_encryption_results(self):
        """Copiar resultados de cifrado al portapapeles"""
        text = self.encrypt_results.get('1.0', tk.END)
        if text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copiado", "Claves copiadas al portapapeles")

    def refresh_files_list(self):
        """Actualizar lista de archivos"""
        if not self.file_service:
            return

        try:
            # Limpiar tree
            for item in self.files_tree.get_children():
                self.files_tree.delete(item)

            # Obtener archivos
            files = self.file_service.list_user_files()

            for file in files:
                size_kb = file.encrypted_size / 1024 if file.encrypted_size else 0
                size_str = f"{size_kb:.2f} KB"
                date_str = file.created_at.strftime('%Y-%m-%d %H:%M') if file.created_at else 'N/A'

                # Obtener usuario que cifró
                from app.models.user import User
                uploader = self.session.query(User).filter_by(id=file.uploaded_by).first()
                uploader_name = uploader.username if uploader else 'N/A'

                self.files_tree.insert('', 'end', values=(
                    file.original_filename,
                    size_str,
                    date_str,
                    uploader_name
                ))

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la lista de archivos:\n{str(e)}")

    def refresh_logs(self):
        """Actualizar logs de auditoría"""
        try:
            from app.models.audit_log import AuditLog

            # Obtener últimos 50 logs del usuario
            logs = self.session.query(AuditLog).filter_by(
                user_id=self.user.id
            ).order_by(AuditLog.timestamp.desc()).limit(50).all()

            log_text = ""
            for log in logs:
                log_text += f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
                log_text += f"{log.action} - {log.status}\n"
                if log.details:
                    log_text += f"  Detalles: {log.details}\n"
                log_text += "-" * 80 + "\n"

            if not log_text:
                log_text = "No hay logs disponibles"

            self.logs_text.delete('1.0', tk.END)
            self.logs_text.insert('1.0', log_text)

        except Exception as e:
            self.logs_text.delete('1.0', tk.END)
            self.logs_text.insert('1.0', f"Error al cargar logs:\n{str(e)}")

    def can_manage_users(self):
        """Verifica si el usuario puede gestionar usuarios"""
        # Verificar si es admin
        if self.user.is_admin:
            return True

        # Verificar permisos específicos
        user_permissions = []
        for role in self.user.roles:
            for perm in role.permissions:
                user_permissions.append(perm.name)

        # Necesita al menos uno de estos permisos
        required_permissions = ['user.view', 'user.create', 'user.edit', 'user.assign_roles']
        return any(perm in user_permissions for perm in required_permissions)

    def create_users_tab(self):
        """Pestaña de gestión de usuarios"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="👥 Usuarios")

        main_frame = ttk.Frame(frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="👥 Gestión de Usuarios",
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 20))

        # Botones de acción
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(buttons_frame, text="➕ Crear Usuario", command=self.create_new_user).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="✏️ Editar Usuario", command=self.edit_selected_user).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="🔄 Actualizar Lista", command=self.refresh_users_list).pack(side=tk.LEFT)

        # Lista de usuarios
        list_frame = ttk.LabelFrame(main_frame, text="Usuarios de la Organización", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview con scrollbar
        tree_scroll = ttk.Scrollbar(list_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.users_tree = ttk.Treeview(
            list_frame,
            columns=('username', 'email', 'full_name', 'roles', 'status'),
            show='headings',
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.users_tree.yview)

        self.users_tree.heading('username', text='Usuario')
        self.users_tree.heading('email', text='Email')
        self.users_tree.heading('full_name', text='Nombre Completo')
        self.users_tree.heading('roles', text='Roles')
        self.users_tree.heading('status', text='Estado')

        self.users_tree.column('username', width=150)
        self.users_tree.column('email', width=200)
        self.users_tree.column('full_name', width=200)
        self.users_tree.column('roles', width=200)
        self.users_tree.column('status', width=100)

        self.users_tree.pack(fill=tk.BOTH, expand=True)

        # Doble click para editar
        self.users_tree.bind('<Double-1>', lambda e: self.edit_selected_user())

        # Cargar usuarios al inicio
        self.refresh_users_list()

    def refresh_users_list(self):
        """Actualizar lista de usuarios"""
        try:
            # Limpiar tree
            for item in self.users_tree.get_children():
                self.users_tree.delete(item)

            # Obtener usuarios de la organización
            from app.models.user import User
            users = self.session.query(User).filter_by(
                organization_id=self.user.organization_id
            ).order_by(User.username).all()

            for user in users:
                roles_text = ", ".join([role.name for role in user.roles]) if user.roles else "Sin roles"

                if user.is_locked:
                    status = "🔒 Bloqueado"
                elif not user.is_active:
                    status = "❌ Inactivo"
                else:
                    status = "✅ Activo"

                self.users_tree.insert('', 'end', values=(
                    user.username,
                    user.email or 'N/A',
                    user.full_name or 'N/A',
                    roles_text,
                    status
                ), tags=(user.id,))

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la lista de usuarios:\n{str(e)}")

    def create_new_user(self):
        """Crear nuevo usuario"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Nuevo Usuario")
        dialog.geometry("500x600")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Crear Nuevo Usuario", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Username
        ttk.Label(main_frame, text="Nombre de usuario *").pack(anchor=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=username_var, width=40).pack(fill=tk.X, pady=(0, 10))

        # Email
        ttk.Label(main_frame, text="Email *").pack(anchor=tk.W)
        email_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=email_var, width=40).pack(fill=tk.X, pady=(0, 10))

        # Full name
        ttk.Label(main_frame, text="Nombre completo").pack(anchor=tk.W)
        full_name_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=full_name_var, width=40).pack(fill=tk.X, pady=(0, 10))

        # Password
        ttk.Label(main_frame, text="Contraseña *").pack(anchor=tk.W)
        password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=password_var, show="*", width=40).pack(fill=tk.X, pady=(0, 10))

        # Confirm password
        ttk.Label(main_frame, text="Confirmar contraseña *").pack(anchor=tk.W)
        confirm_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=confirm_password_var, show="*", width=40).pack(fill=tk.X, pady=(0, 10))

        # Roles
        ttk.Label(main_frame, text="Roles").pack(anchor=tk.W, pady=(10, 5))
        roles_frame = ttk.LabelFrame(main_frame, text="Selecciona roles", padding=10)
        roles_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Obtener roles disponibles
        from app.models.role import Role
        available_roles = self.session.query(Role).filter_by(
            organization_id=None,  # Roles de sistema
            is_active=True
        ).all()

        role_vars = {}
        for role in available_roles:
            var = tk.BooleanVar()
            ttk.Checkbutton(roles_frame, text=f"{role.name} - {role.display_name}", variable=var).pack(anchor=tk.W)
            role_vars[role.id] = (var, role)

        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        def save_user():
            username = username_var.get().strip()
            email = email_var.get().strip()
            full_name = full_name_var.get().strip()
            password = password_var.get()
            confirm_password = confirm_password_var.get()

            # Validaciones
            if not username or not email or not password:
                messagebox.showerror("Error", "Completa los campos obligatorios (*)")
                return

            if password != confirm_password:
                messagebox.showerror("Error", "Las contraseñas no coinciden")
                return

            if len(password) < 8:
                messagebox.showerror("Error", "La contraseña debe tener al menos 8 caracteres")
                return

            try:
                from app.models.user import User

                # Verificar si el usuario ya existe
                existing = self.session.query(User).filter_by(username=username).first()
                if existing:
                    messagebox.showerror("Error", f"El usuario '{username}' ya existe")
                    return

                # Crear usuario
                new_user = User(
                    organization_id=self.user.organization_id,
                    department_id=self.user.department_id,
                    username=username,
                    email=email,
                    full_name=full_name or None,
                    is_active=True
                )
                new_user.set_password(password)

                # Asignar roles seleccionados
                for role_id, (var, role) in role_vars.items():
                    if var.get():
                        new_user.roles.append(role)

                self.session.add(new_user)
                self.session.commit()

                # Registrar en auditoría
                from app.services.audit_service import AuditService
                audit = AuditService(self.session)
                audit.log_action(
                    user_id=self.user.id,
                    action='user.create',
                    resource_type='User',
                    resource_id=new_user.id,
                    status='success',
                    details=f"Created user '{username}'",
                    ip_address='127.0.0.1'
                )

                messagebox.showinfo("Éxito", f"Usuario '{username}' creado exitosamente")
                dialog.destroy()
                self.refresh_users_list()

            except Exception as e:
                self.session.rollback()
                messagebox.showerror("Error", f"No se pudo crear el usuario:\n{str(e)}")

        ttk.Button(buttons_frame, text="💾 Guardar", command=save_user).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="❌ Cancelar", command=dialog.destroy).pack(side=tk.LEFT)

    def edit_selected_user(self):
        """Editar usuario seleccionado"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Selecciona un usuario para editar")
            return

        # Obtener ID del usuario desde los tags
        item = selection[0]
        values = self.users_tree.item(item, 'values')
        username = values[0]

        # Buscar usuario
        from app.models.user import User
        user = self.session.query(User).filter_by(
            username=username,
            organization_id=self.user.organization_id
        ).first()

        if not user:
            messagebox.showerror("Error", "Usuario no encontrado")
            return

        # Crear diálogo de edición
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Editar Usuario: {username}")
        dialog.geometry("500x650")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Editar Usuario: {username}", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Email
        ttk.Label(main_frame, text="Email").pack(anchor=tk.W)
        email_var = tk.StringVar(value=user.email or "")
        ttk.Entry(main_frame, textvariable=email_var, width=40).pack(fill=tk.X, pady=(0, 10))

        # Full name
        ttk.Label(main_frame, text="Nombre completo").pack(anchor=tk.W)
        full_name_var = tk.StringVar(value=user.full_name or "")
        ttk.Entry(main_frame, textvariable=full_name_var, width=40).pack(fill=tk.X, pady=(0, 10))

        # Estado
        state_frame = ttk.LabelFrame(main_frame, text="Estado", padding=10)
        state_frame.pack(fill=tk.X, pady=(0, 10))

        is_active_var = tk.BooleanVar(value=user.is_active)
        ttk.Checkbutton(state_frame, text="Usuario activo", variable=is_active_var).pack(anchor=tk.W)

        is_locked_var = tk.BooleanVar(value=user.is_locked)
        ttk.Checkbutton(state_frame, text="Usuario bloqueado", variable=is_locked_var).pack(anchor=tk.W)

        # Cambiar contraseña
        password_frame = ttk.LabelFrame(main_frame, text="Cambiar Contraseña (opcional)", padding=10)
        password_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(password_frame, text="Nueva contraseña").pack(anchor=tk.W)
        new_password_var = tk.StringVar()
        ttk.Entry(password_frame, textvariable=new_password_var, show="*", width=40).pack(fill=tk.X, pady=(0, 5))

        ttk.Label(password_frame, text="Confirmar contraseña").pack(anchor=tk.W)
        confirm_password_var = tk.StringVar()
        ttk.Entry(password_frame, textvariable=confirm_password_var, show="*", width=40).pack(fill=tk.X)

        # Roles
        ttk.Label(main_frame, text="Roles").pack(anchor=tk.W, pady=(10, 5))
        roles_frame = ttk.LabelFrame(main_frame, text="Selecciona roles", padding=10)
        roles_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Obtener roles disponibles y roles actuales del usuario
        from app.models.role import Role
        available_roles = self.session.query(Role).filter_by(
            organization_id=None,
            is_active=True
        ).all()

        current_role_ids = [role.id for role in user.roles]
        role_vars = {}
        for role in available_roles:
            var = tk.BooleanVar(value=role.id in current_role_ids)
            ttk.Checkbutton(roles_frame, text=f"{role.name} - {role.display_name}", variable=var).pack(anchor=tk.W)
            role_vars[role.id] = (var, role)

        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        def save_changes():
            email = email_var.get().strip()
            full_name = full_name_var.get().strip()
            new_password = new_password_var.get()
            confirm_password = confirm_password_var.get()

            # Validar contraseña si se está cambiando
            if new_password:
                if new_password != confirm_password:
                    messagebox.showerror("Error", "Las contraseñas no coinciden")
                    return
                if len(new_password) < 8:
                    messagebox.showerror("Error", "La contraseña debe tener al menos 8 caracteres")
                    return

            try:
                # Actualizar datos
                user.email = email or None
                user.full_name = full_name or None
                user.is_active = is_active_var.get()
                user.is_locked = is_locked_var.get()

                # Cambiar contraseña si se proporcionó
                if new_password:
                    user.set_password(new_password)

                # Actualizar roles
                user.roles.clear()
                for role_id, (var, role) in role_vars.items():
                    if var.get():
                        user.roles.append(role)

                self.session.commit()

                # Registrar en auditoría
                from app.services.audit_service import AuditService
                audit = AuditService(self.session)
                audit.log_action(
                    user_id=self.user.id,
                    action='user.update',
                    resource_type='User',
                    resource_id=user.id,
                    status='success',
                    details=f"Updated user '{username}'",
                    ip_address='127.0.0.1'
                )

                messagebox.showinfo("Éxito", f"Usuario '{username}' actualizado exitosamente")
                dialog.destroy()
                self.refresh_users_list()

            except Exception as e:
                self.session.rollback()
                messagebox.showerror("Error", f"No se pudo actualizar el usuario:\n{str(e)}")

        ttk.Button(buttons_frame, text="💾 Guardar Cambios", command=save_changes).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="❌ Cancelar", command=dialog.destroy).pack(side=tk.LEFT)

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
