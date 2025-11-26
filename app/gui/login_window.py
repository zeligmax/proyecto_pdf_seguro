#!/usr/bin/env python3
"""
login_window.py - Login Window for File Secure v3.2
Database authentication with organization selection
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

from app.core.database import get_db_manager
from app.services import AuthenticationService
from app.models import User


class LoginWindow(tk.Toplevel):
    """
    Ventana de login con autenticación de base de datos
    """

    def __init__(self, parent):
        super().__init__(parent)

        self.title("File Secure v3.2 - Login")
        self.geometry("450x500")
        self.resizable(False, False)

        self.authenticated_user = None
        self.auth_token = None

        # Centrar ventana
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (450 // 2)
        y = (self.winfo_screenheight() // 2) - (500 // 2)
        self.geometry(f"450x500+{x}+{y}")

        self._create_widgets()

        # Make modal
        self.transient(parent)
        self.grab_set()

        # Focus en username
        self.username_entry.focus()

    def _create_widgets(self):
        """Crea los widgets de la ventana de login"""

        # Header con logo
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=20)

        ttk.Label(
            header,
            text="📁",
            font=('Arial', 48)
        ).pack()

        ttk.Label(
            header,
            text="File Secure v3.2",
            font=('Arial', 20, 'bold')
        ).pack()

        ttk.Label(
            header,
            text="Enterprise Edition",
            font=('Arial', 10),
            foreground='gray'
        ).pack()

        # Separator
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=10)

        # Login form
        form_frame = ttk.Frame(self, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # Username
        ttk.Label(form_frame, text="Username or Email:", font=('Arial', 10)).pack(anchor=tk.W, pady=(10, 5))
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(form_frame, textvariable=self.username_var, font=('Arial', 11), width=35)
        self.username_entry.pack(fill=tk.X, pady=(0, 15))
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())

        # Password
        ttk.Label(form_frame, text="Password:", font=('Arial', 10)).pack(anchor=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show='●', font=('Arial', 11), width=35)
        self.password_entry.pack(fill=tk.X, pady=(0, 5))
        self.password_entry.bind('<Return>', lambda e: self.login())

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_pass_check = ttk.Checkbutton(
            form_frame,
            text="Show password",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        )
        show_pass_check.pack(anchor=tk.W, pady=(0, 20))

        # Remember me checkbox
        self.remember_var = tk.BooleanVar()
        ttk.Checkbutton(
            form_frame,
            text="Remember me",
            variable=self.remember_var
        ).pack(anchor=tk.W, pady=(0, 20))

        # Login button
        self.login_btn = ttk.Button(
            form_frame,
            text="🔓 Login",
            command=self.login,
            width=20
        )
        self.login_btn.pack(pady=10)

        # Status label
        self.status_label = ttk.Label(
            form_frame,
            text="",
            foreground='red',
            font=('Arial', 9)
        )
        self.status_label.pack(pady=5)

        # Footer
        footer = ttk.Frame(self)
        footer.pack(fill=tk.X, side=tk.BOTTOM, pady=10)

        ttk.Label(
            footer,
            text="Need help? Contact your system administrator",
            font=('Arial', 8),
            foreground='gray'
        ).pack()

    def _toggle_password_visibility(self):
        """Muestra/oculta la contraseña"""
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='●')

    def login(self):
        """Procesa el login"""
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username or not password:
            self.status_label.config(text="❌ Please enter username and password")
            return

        # Deshabilitar botón
        self.login_btn.config(state='disabled', text="Authenticating...")
        self.status_label.config(text="🔄 Authenticating...", foreground='blue')
        self.update()

        try:
            # Obtener DB manager
            db_manager = get_db_manager()

            with db_manager.get_session() as session:
                # Intentar autenticar
                auth_service = AuthenticationService(session)
                result = auth_service.authenticate_user(
                    username,
                    password,
                    ip_address="127.0.0.1"  # Local GUI
                )

                if result:
                    # Login exitoso
                    self.authenticated_user = result['user']
                    self.auth_token = result['token']

                    self.status_label.config(text="✅ Login successful!", foreground='green')
                    self.update()

                    # Esperar un momento antes de cerrar
                    self.after(500, self.destroy)

                else:
                    # Login fallido
                    self.status_label.config(text="❌ Invalid credentials", foreground='red')
                    self.login_btn.config(state='normal', text="🔓 Login")
                    self.password_var.set('')
                    self.password_entry.focus()

        except Exception as e:
            error_msg = str(e)

            if "PDF_SECURE_MASTER_KEY" in error_msg or "DATABASE_URL" in error_msg:
                # Error de configuración
                messagebox.showerror(
                    "Configuration Error",
                    "Database or encryption key not configured.\n\n"
                    "Please run:\n"
                    "python -m app.scripts.init_data\n\n"
                    "And set the PDF_SECURE_MASTER_KEY environment variable."
                )
            else:
                self.status_label.config(text=f"❌ Error: {error_msg}", foreground='red')

            self.login_btn.config(state='normal', text="🔓 Login")


# Demo
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal

    login_window = LoginWindow(root)
    root.wait_window(login_window)

    if login_window.authenticated_user:
        print("Login successful!")
        print(f"User: {login_window.authenticated_user['username']}")
        print(f"Token: {login_window.auth_token[:50]}...")
    else:
        print("Login cancelled or failed")

    root.destroy()
