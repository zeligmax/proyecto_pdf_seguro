#!/usr/bin/env python3
"""
user_manager.py - User Management Widget for File Secure v3.2
Create, edit, delete users and assign roles
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime


class UserManagerWidget(ttk.Frame):
    """
    Widget de gestión de usuarios
    """

    def __init__(self, parent, db_session, current_user, organization_id):
        """
        Inicializa el gestor de usuarios

        Args:
            parent: Widget padre
            db_session: Sesión de base de datos
            current_user: Usuario actual (dict)
            organization_id: ID de la organización
        """
        super().__init__(parent)

        self.db = db_session
        self.current_user = current_user
        self.organization_id = organization_id

        self._create_widgets()
        self.refresh_users()

    def _create_widgets(self):
        """Crea los widgets de la interfaz"""

        # Header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(header, text="👥 User Management", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)

        # Botones de acción
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side=tk.RIGHT)

        self.btn_add = ttk.Button(btn_frame, text="➕ Add User", command=self.add_user)
        self.btn_add.pack(side=tk.LEFT, padx=5)

        self.btn_edit = ttk.Button(btn_frame, text="✏️ Edit", command=self.edit_user, state='disabled')
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        self.btn_delete = ttk.Button(btn_frame, text="🗑️ Delete", command=self.delete_user, state='disabled')
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        self.btn_refresh = ttk.Button(btn_frame, text="🔄 Refresh", command=self.refresh_users)
        self.btn_refresh.pack(side=tk.LEFT, padx=5)

        # Búsqueda
        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self._on_search)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Filtros
        ttk.Label(search_frame, text="Status:").pack(side=tk.LEFT, padx=(20, 5))
        self.status_filter = tk.StringVar(value="All")
        status_combo = ttk.Combobox(
            search_frame,
            textvariable=self.status_filter,
            values=["All", "Active", "Inactive", "Locked"],
            state='readonly',
            width=15
        )
        status_combo.pack(side=tk.LEFT, padx=5)
        status_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_users())

        # Tabla de usuarios
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollbars
        scrollbar_y = ttk.Scrollbar(table_frame)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Treeview
        columns = ('username', 'email', 'full_name', 'department', 'roles', 'status', 'last_login')
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show='tree headings',
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set,
            selectmode='browse'
        )

        # Configurar scrollbars
        scrollbar_y.config(command=self.tree.yview)
        scrollbar_x.config(command=self.tree.xview)

        # Configurar columnas
        self.tree.heading('#0', text='ID')
        self.tree.column('#0', width=50, stretch=False)

        self.tree.heading('username', text='Username')
        self.tree.column('username', width=120)

        self.tree.heading('email', text='Email')
        self.tree.column('email', width=180)

        self.tree.heading('full_name', text='Full Name')
        self.tree.column('full_name', width=150)

        self.tree.heading('department', text='Department')
        self.tree.column('department', width=120)

        self.tree.heading('roles', text='Roles')
        self.tree.column('roles', width=150)

        self.tree.heading('status', text='Status')
        self.tree.column('status', width=80)

        self.tree.heading('last_login', text='Last Login')
        self.tree.column('last_login', width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Bind events
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Double-Button-1>', lambda e: self.edit_user())

        # Status bar
        self.status_label = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, padx=10, pady=5)

    def _on_select(self, event=None):
        """Callback cuando se selecciona un usuario"""
        selection = self.tree.selection()
        if selection:
            self.btn_edit.config(state='normal')
            self.btn_delete.config(state='normal')
        else:
            self.btn_edit.config(state='disabled')
            self.btn_delete.config(state='disabled')

    def _on_search(self, *args):
        """Callback cuando cambia el texto de búsqueda"""
        # Implementar búsqueda en tiempo real
        self.refresh_users()

    def refresh_users(self):
        """Actualiza la lista de usuarios"""
        try:
            # Limpiar tabla
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Aquí iría la consulta a la base de datos
            # Por ahora, datos de ejemplo
            users = self._get_users_from_db()

            # Aplicar filtros
            search_term = self.search_var.get().lower()
            status_filter = self.status_filter.get()

            filtered_users = []
            for user in users:
                # Filtro de búsqueda
                if search_term:
                    if not (search_term in user['username'].lower() or
                           search_term in user.get('email', '').lower() or
                           search_term in user.get('full_name', '').lower()):
                        continue

                # Filtro de estado
                if status_filter != "All":
                    if status_filter == "Active" and not user.get('is_active'):
                        continue
                    if status_filter == "Inactive" and user.get('is_active'):
                        continue
                    if status_filter == "Locked" and not user.get('is_locked'):
                        continue

                filtered_users.append(user)

            # Agregar usuarios a la tabla
            for user in filtered_users:
                # Determinar ícono de estado
                if user.get('is_locked'):
                    status = "🔒 Locked"
                elif user.get('is_active'):
                    status = "✅ Active"
                else:
                    status = "⛔ Inactive"

                # Formatear último login
                last_login = user.get('last_login', 'Never')
                if last_login and last_login != 'Never':
                    try:
                        dt = datetime.fromisoformat(last_login)
                        last_login = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass

                self.tree.insert(
                    '',
                    'end',
                    text=user.get('id', '')[:8],
                    values=(
                        user.get('username', ''),
                        user.get('email', ''),
                        user.get('full_name', ''),
                        user.get('department', 'N/A'),
                        ', '.join(user.get('roles', [])),
                        status,
                        last_login
                    )
                )

            self.status_label.config(text=f"Showing {len(filtered_users)} of {len(users)} users")

        except Exception as e:
            messagebox.showerror("Error", f"Error loading users: {str(e)}")

    def _get_users_from_db(self):
        """Obtiene usuarios de la base de datos"""
        # Aquí iría la consulta real a la base de datos
        # Por ahora, retornar datos de ejemplo
        return [
            {
                'id': '1',
                'username': 'admin',
                'email': 'admin@filesecure.local',
                'full_name': 'System Administrator',
                'department': 'IT',
                'roles': ['SuperAdmin'],
                'is_active': True,
                'is_locked': False,
                'last_login': datetime.now().isoformat()
            },
            {
                'id': '2',
                'username': 'john.doe',
                'email': 'john@example.com',
                'full_name': 'John Doe',
                'department': 'Finance',
                'roles': ['Editor'],
                'is_active': True,
                'is_locked': False,
                'last_login': '2024-01-15T10:30:00'
            }
        ]

    def add_user(self):
        """Abre el diálogo para agregar un nuevo usuario"""
        dialog = UserEditDialog(self, title="Add New User", user_data=None, db_session=self.db)
        self.wait_window(dialog)

        if dialog.result:
            self.refresh_users()

    def edit_user(self):
        """Abre el diálogo para editar el usuario seleccionado"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        user_id = item['text']

        # Obtener datos completos del usuario
        user_data = self._get_user_by_id(user_id)

        if user_data:
            dialog = UserEditDialog(self, title="Edit User", user_data=user_data, db_session=self.db)
            self.wait_window(dialog)

            if dialog.result:
                self.refresh_users()

    def delete_user(self):
        """Elimina el usuario seleccionado"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        username = item['values'][0]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user '{username}'?"):
            try:
                # Aquí iría la eliminación en la BD
                self.status_label.config(text=f"User '{username}' deleted successfully")
                self.refresh_users()
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting user: {str(e)}")

    def _get_user_by_id(self, user_id):
        """Obtiene un usuario por ID"""
        # Mock data
        return {
            'id': user_id,
            'username': 'john.doe',
            'email': 'john@example.com',
            'full_name': 'John Doe'
        }


class UserEditDialog(tk.Toplevel):
    """Diálogo para crear/editar usuarios"""

    def __init__(self, parent, title="Edit User", user_data=None, db_session=None):
        super().__init__(parent)

        self.title(title)
        self.geometry("500x600")
        self.resizable(False, False)

        self.user_data = user_data or {}
        self.db = db_session
        self.result = None

        self._create_widgets()

        # Centrar ventana
        self.transient(parent)
        self.grab_set()

    def _create_widgets(self):
        """Crea los widgets del diálogo"""

        # Form frame
        form_frame = ttk.Frame(self, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)

        row = 0

        # Username
        ttk.Label(form_frame, text="Username:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(value=self.user_data.get('username', ''))
        ttk.Entry(form_frame, textvariable=self.username_var, width=40).grid(row=row, column=1, pady=5)
        row += 1

        # Email
        ttk.Label(form_frame, text="Email:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.email_var = tk.StringVar(value=self.user_data.get('email', ''))
        ttk.Entry(form_frame, textvariable=self.email_var, width=40).grid(row=row, column=1, pady=5)
        row += 1

        # Full Name
        ttk.Label(form_frame, text="Full Name:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.fullname_var = tk.StringVar(value=self.user_data.get('full_name', ''))
        ttk.Entry(form_frame, textvariable=self.fullname_var, width=40).grid(row=row, column=1, pady=5)
        row += 1

        # Password (solo para nuevos usuarios)
        if not self.user_data.get('id'):
            ttk.Label(form_frame, text="Password:").grid(row=row, column=0, sticky=tk.W, pady=5)
            self.password_var = tk.StringVar()
            ttk.Entry(form_frame, textvariable=self.password_var, show='*', width=40).grid(row=row, column=1, pady=5)
            row += 1

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Save", command=self.save).pack(side=tk.RIGHT, padx=5)

    def save(self):
        """Guarda los cambios"""
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()

        if not username:
            messagebox.showerror("Error", "Username is required")
            return

        # Aquí iría la lógica para guardar en BD
        self.result = {
            'username': username,
            'email': email,
            'full_name': self.fullname_var.get().strip()
        }

        self.destroy()
