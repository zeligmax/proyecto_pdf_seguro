#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Secure GUI - Version 3.1
Interfaz gráfica para el sistema de cifrado de archivos seguros
Soporta múltiples formatos: PDF, DOCX, XLSX, TXT, PBIP, PBIX
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
from datetime import datetime
import io
from PIL import Image, ImageTk

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar directorio app al path
sys.path.append(str(Path(__file__).parent))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import FileSecureManager
from ip_check import IPChecker
from api_manager import get_api_manager
from i18n import init_translator, get_translator, t
from modern_styles import ModernTheme

class PDFSecureGUI:
    def __init__(self):
        # Inicializar traductor con idioma guardado
        self.load_user_settings()
        saved_lang = self.user_settings.get('language', 'es')
        init_translator(saved_lang)

        # Crear ventana PRIMERO
        self.root = tk.Tk()
        self.root.title("📁 File Secure v3.1")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)

        # Aplicar tema moderno con colores pastel
        ModernTheme.configure_style(self.root)

        # Variables
        self.pdf_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.encrypted_path_var = tk.StringVar()
        self.user_key_var = tk.StringVar()
        self.users_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.ip_desc_var = tk.StringVar()
        self.log_limit_var = tk.StringVar(value="50")
        self.language_var = tk.StringVar(value=saved_lang)

        # Inicializar atributos del backend como None
        self.config = None
        self.auth_manager = None
        self.pdf_manager = None
        self.ip_checker = None
        self.api_manager = None
        
        # CREAR WIDGETS (incluye status_label)
        self.create_widgets()
        
        # LUEGO inicializar backend
        try:
            self.config = SecureConfig()
            self.auth_manager = UserAuthManager(self.config)
            self.pdf_manager = FileSecureManager(self.config, self.auth_manager)
            self.ip_checker = IPChecker(self.config)
            self.api_manager = get_api_manager()

            # Actualizar status
            self.status_label.config(text="✅ Sistema listo")
            
            # Cargar datos iniciales
            self.update_ip_info()  # Actualizar info de IP
            self.refresh_users()
            self.refresh_ips()
            self.update_status()
            
        except ValueError as e:
            error_msg = str(e)
            if "PDF_SECURE_MASTER_KEY" in error_msg:
                messagebox.showerror("Error de Configuración", 
                    "❌ Clave maestra no configurada\n\n"
                    "Para configurarla, ejecuta en PowerShell:\n\n"
                    "$key = python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
                    "$env:PDF_SECURE_MASTER_KEY = $key\n\n"
                    "Luego reinicia la aplicación.")
            else:
                messagebox.showerror("Error de Configuración", f"Error: {error_msg}")
            
            self.status_label.config(text="❌ Error de configuración")
            # NO cerrar la ventana, dejar que el usuario la cierre
            
        except Exception as e:
            messagebox.showerror("Error", f"Error inesperado: {str(e)}")
            self.status_label.config(text="❌ Error inesperado")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        # Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Crear pestañas
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_users_tab()
        self.create_ips_tab()
        self.create_logs_tab()
        self.create_api_tab()
        self.create_settings_tab()
        
        # Barra de estado
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Listo", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)
        
        self.ip_status_label = ttk.Label(self.status_frame, text="", relief=tk.SUNKEN)
        self.ip_status_label.pack(side=tk.RIGHT, padx=2, pady=2)
    
    def create_encrypt_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_encrypt', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_encrypt', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Archivo a cifrar - Frame blanco simple (compacto)
        pdf_frame = ttk.LabelFrame(main, text=t('label_file_to_encrypt', 'gui'), padding=8)
        pdf_frame.pack(fill=tk.X, pady=(0, 5))

        pdf_entry = ttk.Frame(pdf_frame)
        pdf_entry.pack(fill=tk.X)
        ttk.Entry(pdf_entry, textvariable=self.pdf_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ModernTheme.create_modern_button(pdf_entry, t('button_browse', 'gui'),
                                        command=self.browse_pdf, style='Secondary').pack(side=tk.RIGHT)

        ttk.Label(pdf_frame, text=t('info_supported_formats', 'gui'),
                 foreground=ModernTheme.COLORS['text_secondary'],
                 font=ModernTheme.FONTS['small']).pack(anchor=tk.W, pady=(3, 0))

        # Salida - Frame blanco simple (compacto)
        out_frame = ttk.LabelFrame(main, text=t('label_output', 'gui'), padding=8)
        out_frame.pack(fill=tk.X, pady=(0, 5))

        out_entry = ttk.Frame(out_frame)
        out_entry.pack(fill=tk.X)
        ttk.Entry(out_entry, textvariable=self.output_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ModernTheme.create_modern_button(out_entry, t('button_browse', 'gui'),
                                        command=self.browse_output, style='Secondary').pack(side=tk.RIGHT)

        # Usuarios - Frame blanco simple (compacto)
        users_frame = ttk.LabelFrame(main, text=t('label_users', 'gui'), padding=8)
        users_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(users_frame, text=t('label_users_comma_separated', 'gui'),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['small']).pack(anchor=tk.W, pady=(0, 3))
        ttk.Entry(users_frame, textvariable=self.users_var, width=50).pack(fill=tk.X)

        # Botones con estilos modernos (compacto)
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=8)
        ModernTheme.create_modern_button(btn_frame, t('button_encrypt', 'gui'),
                                        command=self.encrypt_pdf, style='Primary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame, t('button_clear', 'gui'),
                                        command=self.clear_encrypt, style='Warning').pack(side=tk.LEFT)

        # Resultados - Frame blanco simple (expandido para ocupar todo el espacio restante)
        res_frame = ttk.LabelFrame(main, text=t('label_keys_section', 'gui'), padding=10)
        res_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

        self.encrypt_results = scrolledtext.ScrolledText(res_frame, height=18,
                                                         font=ModernTheme.FONTS['code'],
                                                         bg=ModernTheme.COLORS['bg_white'],
                                                         fg=ModernTheme.COLORS['text_primary'],
                                                         relief='flat',
                                                         borderwidth=2)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True, pady=(3, 3))

        ModernTheme.create_modern_button(res_frame, t('button_copy', 'gui'),
                                        command=self.copy_results, style='Secondary').pack()
    
    def create_decrypt_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_decrypt', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_decrypt', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Mostrar usuario actual del sistema
        import getpass
        try:
            current_user = getpass.getuser()
        except:
            import os
            try:
                current_user = os.getlogin()
            except:
                current_user = "Unknown"

        # Info usuario - Frame blanco simple
        user_info_frame = ttk.LabelFrame(main, text="👤 " + t('label_current_user', 'gui', username=''), padding=15)
        user_info_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(user_info_frame,
                 text=t('label_current_user', 'gui', username=current_user),
                 foreground=ModernTheme.COLORS['info'],
                 font=ModernTheme.FONTS['heading']).pack(anchor=tk.W)

        ttk.Label(user_info_frame,
                 text=t('info_only_decrypt_authorized', 'gui'),
                 foreground=ModernTheme.COLORS['text_secondary'],
                 font=ModernTheme.FONTS['small']).pack(anchor=tk.W, pady=(5, 0))

        # Archivo cifrado - Frame blanco simple
        enc_frame = ttk.LabelFrame(main, text=t('label_encrypted_file_section', 'gui'), padding=15)
        enc_frame.pack(fill=tk.X, pady=(0, 15))

        enc_entry = ttk.Frame(enc_frame)
        enc_entry.pack(fill=tk.X, pady=(5, 0))
        ttk.Entry(enc_entry, textvariable=self.encrypted_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ModernTheme.create_modern_button(enc_entry, t('button_browse', 'gui'),
                                        command=self.browse_encrypted, style='Secondary').pack(side=tk.RIGHT)

        # Clave - Frame blanco simple
        key_frame = ttk.LabelFrame(main, text=t('label_key_section', 'gui'), padding=15)
        key_frame.pack(fill=tk.X, pady=(0, 15))

        key_entry = ttk.Entry(key_frame, textvariable=self.user_key_var, show="*", width=50)
        key_entry.pack(fill=tk.X, pady=(5, 0))

        show_var = tk.BooleanVar()
        ttk.Checkbutton(key_frame, text="Mostrar", variable=show_var,
                       command=lambda: key_entry.config(show="" if show_var.get() else "*")).pack(anchor=tk.W, pady=(8, 0))

        # Botones con estilos modernos
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=20)

        ModernTheme.create_modern_button(btn_frame, t('button_view', 'gui'),
                                        command=self.view_pdf, style='Secondary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame, t('button_decrypt', 'gui'),
                                        command=self.decrypt_pdf, style='Primary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame, t('button_clear', 'gui'),
                                        command=self.clear_decrypt, style='Warning').pack(side=tk.LEFT)

        # Status con estilo moderno
        self.decrypt_status = tk.Label(main, text="",
                                       bg=ModernTheme.COLORS['bg_main'],
                                       fg=ModernTheme.COLORS['success'],
                                       font=ModernTheme.FONTS['heading'])
        self.decrypt_status.pack(pady=(10, 0))
    
    def create_users_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_users', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_users', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Controles - Frame púrpura pastel
        ctrl_frame = ttk.LabelFrame(main, text="⚙️ " + t('info_api_controls', 'gui'),
                                     padding=15, style='TLabelframe')
        ctrl_frame.pack(fill=tk.X, pady=(0, 15))

        ctrl = ttk.Frame(ctrl_frame)
        ctrl.pack(fill=tk.X)
        ModernTheme.create_modern_button(ctrl, t('button_refresh', 'gui'),
                                        command=self.refresh_users, style='Secondary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(ctrl, t('button_cleanup', 'gui'),
                                        command=self.cleanup_keys, style='Warning').pack(side=tk.LEFT)

        # Lista - Frame blanco con bordes
        list_frame = ttk.LabelFrame(main, text=t('info_active_keys', 'gui'), padding=15)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        cols = (t('column_user', 'gui'), t('column_file', 'gui'), t('column_created', 'gui'),
                t('column_expires', 'gui'), t('column_accesses', 'gui'))
        self.users_tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=12)
        for col in cols:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=120)

        scroll_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        self.users_tree.configure(yscrollcommand=scroll_v.set)

        self.users_tree.grid(row=0, column=0, sticky="nsew")
        scroll_v.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Acciones con botones modernos
        actions = ttk.Frame(main)
        actions.pack(fill=tk.X)
        ModernTheme.create_modern_button(actions, t('button_revoke', 'gui'),
                                        command=self.revoke_key, style='Danger').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(actions, t('button_extend', 'gui'),
                                        command=self.extend_key, style='Secondary').pack(side=tk.LEFT)

        self.refresh_users()
    
    def create_ips_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_ips', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_ips', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Info actual - Frame blanco simple
        info_frame = ttk.LabelFrame(main, text=t('info_current_ip', 'gui'), padding=15)
        info_frame.pack(fill=tk.X, pady=(0, 15))

        # Guardar referencia para actualizar después
        self.ip_info_label1 = ttk.Label(info_frame, text=t('ip_info_loading', 'gui'),
                                        foreground=ModernTheme.COLORS['text_primary'],
                                        font=ModernTheme.FONTS['body'])
        self.ip_info_label1.pack(anchor=tk.W, pady=2)
        self.ip_info_label2 = ttk.Label(info_frame, text=t('ip_info_loading', 'gui'),
                                        foreground=ModernTheme.COLORS['text_primary'],
                                        font=ModernTheme.FONTS['body'])
        self.ip_info_label2.pack(anchor=tk.W, pady=2)

        # Agregar - Frame naranja pastel
        add_frame = ttk.LabelFrame(main, text=t('info_add_ip', 'gui'),
                                   padding=15, style='TLabelframe')
        add_frame.pack(fill=tk.X, pady=(0, 15))

        ip_entry = ttk.Frame(add_frame)
        ip_entry.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(ip_entry, text=t('label_ip', 'gui')).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(ip_entry, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=(0, 10))

        # Botón que se actualizará después
        self.btn_add_current_ip = ModernTheme.create_modern_button(
            ip_entry, t('button_add_current_ip', 'gui'),
            command=self.add_current_ip, style='Secondary')
        self.btn_add_current_ip.pack(side=tk.LEFT)

        desc_entry = ttk.Frame(add_frame)
        desc_entry.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(desc_entry, text=t('label_description', 'gui')).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(desc_entry, textvariable=self.ip_desc_var, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)

        ModernTheme.create_modern_button(add_frame, t('button_add_ip', 'gui'),
                                        command=self.add_ip, style='Primary').pack()

        # Lista - Frame blanco con bordes
        list_frame = ttk.LabelFrame(main, text=t('info_authorized_ips', 'gui'), padding=15)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        ip_cols = (t('column_ip', 'gui'), t('column_description', 'gui'), t('column_added', 'gui'),
                   t('column_accesses', 'gui'), t('column_last_access', 'gui'))
        self.ips_tree = ttk.Treeview(list_frame, columns=ip_cols, show="headings", height=10)
        for col in ip_cols:
            self.ips_tree.heading(col, text=col)
            self.ips_tree.column(col, width=120)

        scroll_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.ips_tree.yview)
        self.ips_tree.configure(yscrollcommand=scroll_v.set)

        self.ips_tree.grid(row=0, column=0, sticky="nsew")
        scroll_v.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Acciones con botones modernos
        actions = ttk.Frame(main)
        actions.pack(fill=tk.X)
        ModernTheme.create_modern_button(actions, t('button_refresh', 'gui'),
                                        command=self.refresh_ips, style='Secondary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(actions, t('button_remove_ip', 'gui'),
                                        command=self.remove_ip, style='Danger').pack(side=tk.LEFT)
    
    def add_current_ip(self):
        """Agrega la IP actual al campo"""
        if self.ip_checker:
            try:
                network_info = self.ip_checker.get_network_info()
                self.ip_var.set(network_info['local_ip'])
            except:
                messagebox.showwarning("Aviso", "No se pudo obtener la IP actual")
        else:
            messagebox.showwarning("Aviso", "Sistema no inicializado")
    
    def update_ip_info(self):
        """Actualiza la información de IP en la pestaña"""
        if self.ip_checker and hasattr(self, 'ip_info_label1'):
            try:
                network_info = self.ip_checker.get_network_info()
                self.ip_info_label1.config(text=f"🖥️ IP: {network_info['local_ip']}")
                self.ip_info_label2.config(text=f"🏠 Host: {network_info['hostname']}")
            except:
                pass
        
        self.refresh_ips()
    
    def create_logs_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_logs', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_logs', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Controles - Frame blanco simple
        ctrl_frame = ttk.LabelFrame(main, text="⚙️ " + t('info_api_controls', 'gui'), padding=15)
        ctrl_frame.pack(fill=tk.X, pady=(0, 15))

        ctrl = ttk.Frame(ctrl_frame)
        ctrl.pack(fill=tk.X)
        ModernTheme.create_modern_button(ctrl, t('button_refresh', 'gui'),
                                        command=self.refresh_logs, style='Secondary').pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(ctrl, text=t('label_show_limit', 'gui'),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['body']).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Combobox(ctrl, textvariable=self.log_limit_var, values=["25", "50", "100"], width=8).pack(side=tk.LEFT)

        # Logs - Frame blanco simple
        logs_frame = ttk.LabelFrame(main, text=t('info_logs', 'gui'), padding=15)
        logs_frame.pack(fill=tk.BOTH, expand=True)

        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20,
                                                   font=ModernTheme.FONTS['code'],
                                                   bg=ModernTheme.COLORS['bg_white'],
                                                   fg=ModernTheme.COLORS['text_primary'],
                                                   relief='flat',
                                                   borderwidth=2)
        self.logs_text.pack(fill=tk.BOTH, expand=True)

        self.refresh_logs()

    def create_api_tab(self):
        """Crea la pestaña de gestión de la API de Usuarios"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_api', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_api', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Estado de la API - Frame blanco simple
        status_frame = ttk.LabelFrame(main, text=t('info_api_status', 'gui'), padding=15)
        status_frame.pack(fill=tk.X, pady=(0, 15))

        self.api_status_label = ttk.Label(status_frame, text=t('api_status_stopped', 'gui'),
                                          foreground=ModernTheme.COLORS['text_primary'],
                                          font=ModernTheme.FONTS['subtitle'])
        self.api_status_label.pack(anchor=tk.W, pady=(0, 8))

        self.api_url_label = ttk.Label(status_frame, text=t('api_url_na', 'gui'),
                                       foreground=ModernTheme.COLORS['text_secondary'],
                                       font=ModernTheme.FONTS['body'])
        self.api_url_label.pack(anchor=tk.W, pady=(0, 8))

        self.api_health_label = ttk.Label(status_frame, text="",
                                          foreground=ModernTheme.COLORS['text_secondary'],
                                          font=ModernTheme.FONTS['body'])
        self.api_health_label.pack(anchor=tk.W)

        # Controles - Frame blanco simple
        controls_frame = ttk.LabelFrame(main, text=t('info_api_controls', 'gui'), padding=15)
        controls_frame.pack(fill=tk.X, pady=(0, 15))

        btn_frame = ttk.Frame(controls_frame)
        btn_frame.pack(fill=tk.X)

        ModernTheme.create_modern_button(btn_frame, t('button_start_api', 'gui'),
                                        command=self.start_api, style='Primary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame, t('button_stop_api', 'gui'),
                                        command=self.stop_api, style='Danger').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame, t('button_refresh_status', 'gui'),
                                        command=self.refresh_api_status, style='Secondary').pack(side=tk.LEFT, padx=(0, 10))

        btn_frame2 = ttk.Frame(controls_frame)
        btn_frame2.pack(fill=tk.X, pady=(10, 0))

        ModernTheme.create_modern_button(btn_frame2, t('button_open_browser', 'gui'),
                                        command=self.open_api_browser, style='Secondary').pack(side=tk.LEFT, padx=(0, 10))
        ModernTheme.create_modern_button(btn_frame2, t('button_list_users', 'gui'),
                                        command=self.list_system_users, style='Secondary').pack(side=tk.LEFT)

        # Lista de usuarios del sistema - Frame blanco simple
        users_frame = ttk.LabelFrame(main, text=t('info_system_users', 'gui'), padding=15)
        users_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self.system_users_text = scrolledtext.ScrolledText(users_frame, height=15,
                                                           font=ModernTheme.FONTS['code'],
                                                           bg=ModernTheme.COLORS['bg_white'],
                                                           fg=ModernTheme.COLORS['text_primary'],
                                                           relief='flat',
                                                           borderwidth=2)
        self.system_users_text.pack(fill=tk.BOTH, expand=True)

        # Info - Frame con texto informativo
        info_frame = ttk.Frame(main)
        info_frame.pack(fill=tk.X)

        tk.Label(info_frame, text=t('info_api_description', 'gui'),
                bg=ModernTheme.COLORS['bg_main'],
                fg=ModernTheme.COLORS['info'],
                font=ModernTheme.FONTS['body']).pack(anchor=tk.W)

        # Actualizar estado inicial
        self.refresh_api_status()

    def create_settings_tab(self):
        """Crea la pestaña de configuración con opciones de idioma"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t('tab_settings', 'gui'))

        # Crear encabezado con fondo gris
        ModernTheme.create_gradient_header(frame, t('header_settings', 'gui'), 'bg_main')

        main = ttk.Frame(frame, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Sección de idioma - Frame blanco simple
        lang_frame = ttk.LabelFrame(main, text=t('info_language_section', 'gui'), padding=15)
        lang_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(lang_frame, text=t('settings_language_select', 'gui'),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['heading']).pack(anchor=tk.W, pady=(0, 10))

        # Dropdown de idiomas
        lang_selector_frame = ttk.Frame(lang_frame)
        lang_selector_frame.pack(fill=tk.X, pady=(0, 10))

        language_options = [
            (t('settings_language_spanish', 'gui'), "es"),
            (t('settings_language_english', 'gui'), "en")
        ]

        for lang_name, lang_code in language_options:
            ttk.Radiobutton(
                lang_selector_frame,
                text=lang_name,
                variable=self.language_var,
                value=lang_code,
                command=self.on_language_change
            ).pack(anchor=tk.W, pady=2)

        # Info sobre reinicio
        info_subframe = ttk.Frame(lang_frame)
        info_subframe.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(info_subframe, text=t('settings_restart_required', 'gui'),
                 foreground=ModernTheme.COLORS['info'],
                 font=ModernTheme.FONTS['small']).pack(anchor=tk.W)

        # Información del sistema - Frame blanco simple
        system_info_frame = ttk.LabelFrame(main, text=t('info_system', 'gui'), padding=15)
        system_info_frame.pack(fill=tk.X)

        ttk.Label(system_info_frame, text=t('settings_version', 'gui'),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['body']).pack(anchor=tk.W, pady=5)

        ttk.Label(system_info_frame, text=t('settings_python_version', 'gui', version=sys.version.split()[0]),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['body']).pack(anchor=tk.W, pady=5)

        # Idioma actual
        current_lang = get_translator().language
        lang_name = t('settings_language_spanish', 'gui') if current_lang == "es" else t('settings_language_english', 'gui')
        ttk.Label(system_info_frame, text=t('settings_current_language', 'gui', language=lang_name),
                 foreground=ModernTheme.COLORS['text_primary'],
                 font=ModernTheme.FONTS['body']).pack(anchor=tk.W, pady=5)

    def load_user_settings(self):
        """Carga las preferencias del usuario desde config/user_settings.json"""
        settings_file = Path(__file__).parent.parent / 'config' / 'user_settings.json'

        if settings_file.exists():
            try:
                import json
                with open(settings_file, 'r', encoding='utf-8') as f:
                    self.user_settings = json.load(f)
            except Exception:
                self.user_settings = {'language': 'es'}
        else:
            self.user_settings = {'language': 'es'}

    def save_user_settings(self):
        """Guarda las preferencias del usuario en config/user_settings.json"""
        settings_file = Path(__file__).parent.parent / 'config' / 'user_settings.json'

        # Crear directorio si no existe
        settings_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            import json
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.user_settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error guardando configuración: {e}")

    def on_language_change(self):
        """Maneja el cambio de idioma"""
        new_lang = self.language_var.get()

        # Guardar preferencia
        self.user_settings['language'] = new_lang
        self.save_user_settings()

        # Cambiar idioma del traductor
        get_translator().change_language(new_lang)

        # Mostrar mensaje
        title = t('language_updated_title', 'gui')
        message = t('language_updated_message', 'gui')

        messagebox.showinfo(title, message)

        # Actualizar status
        self.status_label.config(text=f"✅ {t('status_language_updated', 'gui')}")

    # Métodos de archivos
    def browse_pdf(self):
        f = filedialog.askopenfilename(
            title=t('select_file_to_encrypt', 'gui'),
            filetypes=[
                (t('file_types_supported', 'gui'), "*.pdf *.docx *.xlsx *.txt *.pbip *.pbix"),
                (t('file_types_pdf', 'gui'), "*.pdf"),
                (t('file_types_word', 'gui'), "*.docx"),
                (t('file_types_excel', 'gui'), "*.xlsx"),
                (t('file_types_text', 'gui'), "*.txt"),
                (t('file_types_powerbi', 'gui'), "*.pbip *.pbix"),
                (t('file_types_all', 'gui'), "*.*")
            ]
        )
        if f:
            self.pdf_path_var.set(f)
            self.output_path_var.set(str(Path(f).with_suffix('.enc')))

    def browse_output(self):
        f = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[(t('file_types_encrypted', 'gui'), "*.enc")])
        if f:
            self.output_path_var.set(f)

    def browse_encrypted(self):
        f = filedialog.askopenfilename(filetypes=[(t('file_types_encrypted', 'gui'), "*.enc"), (t('file_types_json', 'gui'), "*.json")])
        if f:
            self.encrypted_path_var.set(f)
    
    # Cifrado
    def encrypt_pdf(self):
        if not self.pdf_manager:
            messagebox.showerror("Error", "Sistema no inicializado correctamente")
            return
            
        pdf = self.pdf_path_var.get().strip()
        out = self.output_path_var.get().strip()
        users = self.users_var.get().strip()
        
        if not all([pdf, out, users]):
            messagebox.showerror("Error", "Completa todos los campos")
            return
        
        if not Path(pdf).exists():
            messagebox.showerror("Error", "Archivo no existe")
            return
        
        users_list = [u.strip() for u in users.split(',') if u.strip()]
        if not users_list:
            messagebox.showerror("Error", "Especifica al menos un usuario")
            return
        
        def worker():
            try:
                self.status_label.config(text="Cifrando...")
                keys = self.pdf_manager.encrypt_pdf_with_user_keys(pdf, out, users_list)
                
                result = f"✅ Cifrado: {out}\n\n🔑 CLAVES:\n{'='*50}\n\n"
                for user, key in keys.items():
                    result += f"👤 {user}\n🔑 {key}\n\n"
                result += "⚠️ GUARDA ESTAS CLAVES DE FORMA SEGURA"
                
                self.root.after(0, lambda: self.show_results(result))
                self.root.after(0, lambda: self.status_label.config(text="Completado"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.status_label.config(text="Error"))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def show_results(self, text):
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.insert(tk.END, text)
        self.encrypt_results.config(state=tk.DISABLED)
    
    def copy_results(self):
        try:
            text = self.encrypt_results.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copiado", "Claves copiadas")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # Descifrado
    def decrypt_pdf(self):
        if not self.pdf_manager:
            messagebox.showerror("Error", "Sistema no inicializado correctamente")
            return
            
        enc = self.encrypted_path_var.get().strip()
        key = self.user_key_var.get().strip()
        
        if not all([enc, key]):
            messagebox.showerror("Error", "Completa todos los campos")
            return
        
        if not Path(enc).exists():
            messagebox.showerror("Error", "Archivo no existe")
            return
        
        def worker():
            try:
                self.status_label.config(text="Descifrando...")
                result = self.pdf_manager.decrypt_pdf_with_user_key(enc, key)
                
                self.root.after(0, lambda: messagebox.showinfo("Éxito", f"Descifrado:\n{result}"))
                self.root.after(0, lambda: self.decrypt_status.config(text=f"✅ {Path(result).name}", foreground='green'))
                self.root.after(0, lambda: self.status_label.config(text="Completado"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.decrypt_status.config(text="❌ Error", foreground='red'))
                self.root.after(0, lambda: self.status_label.config(text="Error"))
        
        threading.Thread(target=worker, daemon=True).start()

    def view_pdf(self):
        """Visualiza el PDF descifrado en memoria sin guardarlo"""
        if not self.pdf_manager:
            messagebox.showerror("Error", "Sistema no inicializado correctamente")
            return

        enc = self.encrypted_path_var.get().strip()
        key = self.user_key_var.get().strip()

        if not all([enc, key]):
            messagebox.showerror("Error", "Completa todos los campos")
            return

        if not Path(enc).exists():
            messagebox.showerror("Error", "Archivo no existe")
            return

        def worker():
            try:
                self.status_label.config(text="Descifrando en memoria...")
                file_bytes, original_filename, file_type = self.pdf_manager.decrypt_pdf_to_memory(enc, key)

                # Abrir ventana de visualización según el tipo de archivo
                self.root.after(0, lambda: self.show_file_viewer(file_bytes, original_filename, file_type))
                self.root.after(0, lambda: self.decrypt_status.config(text=f"✅ Visualizando: {original_filename}", foreground='green'))
                self.root.after(0, lambda: self.status_label.config(text="Completado"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.decrypt_status.config(text="❌ Error", foreground='red'))
                self.root.after(0, lambda: self.status_label.config(text="Error"))

        threading.Thread(target=worker, daemon=True).start()

    def show_file_viewer(self, file_bytes, filename, file_type):
        """Muestra ventana con visualizador según el tipo de archivo"""
        # Detectar tipo de archivo y mostrar visualizador apropiado
        file_type_lower = file_type.lower()

        if file_type_lower == '.pdf':
            self.show_pdf_viewer(file_bytes, filename)
        elif file_type_lower in ['.txt', '.md', '.log', '.csv']:
            self.show_text_viewer(file_bytes, filename, file_type_lower)
        elif file_type_lower in ['.docx', '.xlsx', '.pptx', '.pbip', '.pbix']:
            self.show_office_info_viewer(file_bytes, filename, file_type_lower)
        elif file_type_lower in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            self.show_image_viewer(file_bytes, filename)
        else:
            # Tipo de archivo no soportado para visualización
            self.show_generic_file_info(file_bytes, filename, file_type_lower)

    def show_pdf_viewer(self, pdf_bytes, filename):
        """Muestra ventana con visualizador de PDF"""
        # Crear ventana emergente
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Visualizador PDF - {filename} (Solo lectura)")
        viewer.geometry("800x900")

        # Frame principal
        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Encabezado
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text=f"📄 {filename}", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Label(header, text="(Solo lectura - No guardado en disco)", foreground='blue').pack(side=tk.LEFT, padx=(10, 0))

        # Intentar convertir PDF a imágenes
        viewer_success = False
        error_message = None

        # Debug: mostrar qué Python se está usando
        import sys
        print(f"DEBUG: Python executable: {sys.executable}")
        print(f"DEBUG: Python version: {sys.version}")

        try:
            import fitz  # PyMuPDF
            print(f"DEBUG: PyMuPDF imported successfully, version: {fitz.version}")

            # Abrir PDF desde bytes
            pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
            print(f"DEBUG: PDF opened, {len(pdf_document)} pages")

            # Frame con scroll para las páginas
            canvas = tk.Canvas(main_frame)
            scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            # Renderizar cada página
            for page_num in range(len(pdf_document)):
                page = pdf_document[page_num]

                # Convertir a imagen (zoom 2.0 para mejor calidad)
                mat = fitz.Matrix(2.0, 2.0)
                pix = page.get_pixmap(matrix=mat)

                # Convertir a formato PIL
                img_data = pix.tobytes("ppm")
                img = Image.open(io.BytesIO(img_data))

                # Redimensionar si es muy grande
                max_width = 750
                if img.width > max_width:
                    ratio = max_width / img.width
                    new_size = (max_width, int(img.height * ratio))
                    img = img.resize(new_size, Image.Resampling.LANCZOS)

                # Convertir a PhotoImage
                photo = ImageTk.PhotoImage(img)

                # Crear label con la imagen
                page_frame = ttk.LabelFrame(scrollable_frame, text=f"Página {page_num + 1}/{len(pdf_document)}", padding=5)
                page_frame.pack(fill=tk.X, pady=5)

                img_label = ttk.Label(page_frame, image=photo)
                img_label.image = photo  # Mantener referencia
                img_label.pack()

            pdf_document.close()

            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            viewer_success = True
            print("DEBUG: PDF viewer loaded successfully!")

        except ImportError as e:
            error_message = f"ImportError: {e}"
            print(f"DEBUG: {error_message}")
        except Exception as e:
            error_message = f"{type(e).__name__}: {e}"
            print(f"DEBUG: Other exception: {error_message}")
            import traceback
            traceback.print_exc()

        # Si hubo error, mostrar mensaje de fallback
        if not viewer_success:
            error_frame = ttk.Frame(main_frame)
            error_frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(error_frame, text="⚠️ PyMuPDF no está instalado", font=('Arial', 14, 'bold'), foreground='orange').pack(pady=20)
            ttk.Label(error_frame, text="Para visualizar PDFs en la aplicación, instala PyMuPDF:", wraplength=600).pack(pady=10)

            code_frame = ttk.Frame(error_frame)
            code_frame.pack(pady=10)
            code_text = tk.Text(code_frame, height=2, width=50, bg='#f0f0f0')
            code_text.insert('1.0', 'pip install PyMuPDF Pillow')
            code_text.config(state='disabled')
            code_text.pack()

            if error_message:
                ttk.Label(error_frame, text=f"Error: {error_message}", foreground='red', font=('Arial', 9)).pack(pady=5)

            ttk.Label(error_frame, text=f"Tamaño del PDF: {len(pdf_bytes):,} bytes", foreground='gray').pack(pady=20)
            ttk.Label(error_frame, text="El archivo ha sido descifrado en memoria correctamente.", foreground='green').pack()
            ttk.Label(error_frame, text="Usa el botón 'Descifrar y Guardar' si deseas guardarlo en disco.", wraplength=600).pack(pady=10)

        # Botón cerrar
        ttk.Button(main_frame, text="Cerrar", command=viewer.destroy).pack(pady=(10, 0))

    def show_text_viewer(self, file_bytes, filename, file_type):
        """Muestra ventana con visualizador de texto"""
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Visualizador de Texto - {filename} (Solo lectura)")
        viewer.geometry("800x600")

        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Encabezado
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text=f"📄 {filename}", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Label(header, text="(Solo lectura - No guardado en disco)", foreground='blue').pack(side=tk.LEFT, padx=(10, 0))

        # Área de texto con scroll
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        text_widget = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=('Consolas', 10))
        text_widget.pack(fill=tk.BOTH, expand=True)

        # Decodificar y mostrar texto
        try:
            text_content = file_bytes.decode('utf-8')
            text_widget.insert('1.0', text_content)
        except UnicodeDecodeError:
            try:
                text_content = file_bytes.decode('latin-1')
                text_widget.insert('1.0', text_content)
            except:
                text_widget.insert('1.0', "[Error: No se pudo decodificar el archivo como texto]")

        text_widget.config(state='disabled')  # Solo lectura

        ttk.Button(main_frame, text="Cerrar", command=viewer.destroy).pack(pady=(10, 0))

    def show_image_viewer(self, file_bytes, filename):
        """Muestra ventana con visualizador de imágenes"""
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Visualizador de Imagen - {filename} (Solo lectura)")
        viewer.geometry("800x700")

        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Encabezado
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text=f"🖼️ {filename}", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Label(header, text="(Solo lectura - No guardado en disco)", foreground='blue').pack(side=tk.LEFT, padx=(10, 0))

        try:
            # Abrir imagen desde bytes
            img = Image.open(io.BytesIO(file_bytes))

            # Redimensionar si es muy grande
            max_width, max_height = 750, 600
            if img.width > max_width or img.height > max_height:
                img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)

            # Convertir a PhotoImage
            photo = ImageTk.PhotoImage(img)

            # Mostrar imagen
            img_label = ttk.Label(main_frame, image=photo)
            img_label.image = photo  # Mantener referencia
            img_label.pack()

            # Info
            info_text = f"Dimensiones: {img.width}x{img.height} | Tamaño: {len(file_bytes):,} bytes"
            ttk.Label(main_frame, text=info_text, foreground='gray').pack(pady=5)

        except Exception as e:
            ttk.Label(main_frame, text=f"Error al cargar imagen: {str(e)}", foreground='red').pack()

        ttk.Button(main_frame, text="Cerrar", command=viewer.destroy).pack(pady=(10, 0))

    def show_office_info_viewer(self, file_bytes, filename, file_type):
        """Muestra información sobre archivos Office (no se pueden visualizar directamente)"""
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Información del Archivo - {filename}")
        viewer.geometry("600x400")

        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(main_frame, text=f"📦 {filename}", font=('Arial', 14, 'bold')).pack(pady=20)

        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Label(info_frame, text="✅ Archivo descifrado en memoria correctamente", foreground='green', font=('Arial', 11)).pack(pady=10)
        ttk.Label(info_frame, text=f"Tipo: {file_type.upper()}", font=('Arial', 10)).pack(pady=5)
        ttk.Label(info_frame, text=f"Tamaño: {len(file_bytes):,} bytes", font=('Arial', 10)).pack(pady=5)

        ttk.Label(info_frame, text="\n⚠️ Visualización no disponible", foreground='orange', font=('Arial', 11, 'bold')).pack(pady=10)
        ttk.Label(info_frame, text=f"Los archivos {file_type.upper()} no se pueden visualizar directamente.", wraplength=500).pack(pady=5)
        ttk.Label(info_frame, text='Usa el botón "Descifrar y Guardar" para obtener el archivo\ny ábrelo con la aplicación apropiada.', wraplength=500).pack(pady=5)

        ttk.Button(main_frame, text="Cerrar", command=viewer.destroy).pack(pady=(10, 0))

    def show_generic_file_info(self, file_bytes, filename, file_type):
        """Muestra información genérica sobre archivos no soportados"""
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Información del Archivo - {filename}")
        viewer.geometry("600x350")

        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(main_frame, text=f"📄 {filename}", font=('Arial', 14, 'bold')).pack(pady=20)

        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Label(info_frame, text="✅ Archivo descifrado en memoria correctamente", foreground='green', font=('Arial', 11)).pack(pady=10)
        ttk.Label(info_frame, text=f"Tipo: {file_type}", font=('Arial', 10)).pack(pady=5)
        ttk.Label(info_frame, text=f"Tamaño: {len(file_bytes):,} bytes", font=('Arial', 10)).pack(pady=5)

        ttk.Label(info_frame, text="\nℹ️ El archivo no se guarda en disco", foreground='blue', font=('Arial', 10)).pack(pady=10)
        ttk.Label(info_frame, text='Usa "Descifrar y Guardar" si necesitas el archivo en disco.', wraplength=500).pack(pady=5)

        ttk.Button(main_frame, text="Cerrar", command=viewer.destroy).pack(pady=(10, 0))

    # Usuarios
    def refresh_users(self):
        if not self.auth_manager:
            return
            
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        try:
            keys = self.auth_manager.load_user_keys()
            count = 0
            
            from datetime import datetime
            for key_id, data in keys.items():
                try:
                    exp = datetime.fromisoformat(data['expires'])
                    if datetime.now() <= exp:
                        self.users_tree.insert('', tk.END, 
                            values=(data.get('username'), Path(data.get('pdf_path', '')).name,
                                  data.get('created', '')[:10], exp.strftime('%Y-%m-%d'),
                                  data.get('access_count', 0)),
                            tags=(key_id,))
                        count += 1
                except:
                    pass
            
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"Claves activas: {count}")
        except Exception as e:
            messagebox.showerror("Error al cargar usuarios", str(e))
    
    def revoke_key(self):
        sel = self.users_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una clave")
            return
        
        key_id = self.users_tree.item(sel[0], 'tags')[0]
        user = self.users_tree.item(sel[0], 'values')[0]
        
        if messagebox.askyesno("Confirmar", f"¿Revocar clave de '{user}'?"):
            try:
                keys = self.auth_manager.load_user_keys()
                if key_id in keys:
                    if self.auth_manager.revoke_user_key(keys[key_id]['user_key']):
                        messagebox.showinfo("Éxito", "Clave revocada")
                        self.refresh_users()
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def extend_key(self):
        sel = self.users_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una clave")
            return
        
        key_id = self.users_tree.item(sel[0], 'tags')[0]
        user = self.users_tree.item(sel[0], 'values')[0]
        
        try:
            import tkinter.simpledialog
            days = tkinter.simpledialog.askstring("Extender", f"¿Días para '{user}'?", initialvalue="30")
            if days:
                keys = self.auth_manager.load_user_keys()
                if key_id in keys:
                    if self.auth_manager.extend_key_expiration(keys[key_id]['user_key'], int(days)):
                        messagebox.showinfo("Éxito", f"Extendida {days} días")
                        self.refresh_users()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def cleanup_keys(self):
        try:
            cleaned = self.auth_manager.cleanup_expired_keys()
            messagebox.showinfo("Limpieza", f"Eliminadas {cleaned} claves" if cleaned > 0 else "Sin claves expiradas")
            self.refresh_users()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # IPs
    def add_ip(self):
        ip = self.ip_var.get().strip()
        desc = self.ip_desc_var.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Especifica IP")
            return
        
        valid, msg = self.ip_checker.validate_ip_format(ip)
        if not valid:
            messagebox.showerror("Error", msg)
            return
        
        try:
            self.config.add_ip_to_whitelist(ip, desc)
            messagebox.showinfo("Éxito", f"IP {ip} agregada")
            self.ip_var.set("")
            self.ip_desc_var.set("")
            self.refresh_ips()
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def refresh_ips(self):
        if not self.config:
            return
            
        for item in self.ips_tree.get_children():
            self.ips_tree.delete(item)
        
        try:
            whitelist = self.config.load_ip_whitelist()
            for entry in whitelist:
                self.ips_tree.insert('', tk.END, values=(
                    entry.get('ip'), entry.get('description', ''),
                    entry.get('added', '')[:10], entry.get('access_count', 0),
                    entry.get('last_access', '')[:10] if entry.get('last_access') else 'Nunca'
                ))
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"IPs: {len(whitelist)}")
        except Exception as e:
            messagebox.showerror("Error al cargar IPs", str(e))
    
    def remove_ip(self):
        sel = self.ips_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una IP")
            return
        
        ip = self.ips_tree.item(sel[0], 'values')[0]
        if messagebox.askyesno("Confirmar", f"¿Eliminar '{ip}'?"):
            try:
                self.config.remove_ip_from_whitelist(ip)
                messagebox.showinfo("Éxito", "IP eliminada")
                self.refresh_ips()
                self.update_status()
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    # Logs
    def refresh_logs(self):
        if not self.pdf_manager:
            return

        try:
            limit = int(self.log_limit_var.get())
            logs = self.pdf_manager.get_access_logs(limit)

            self.logs_text.config(state=tk.NORMAL)
            self.logs_text.delete(1.0, tk.END)

            if not logs:
                self.logs_text.insert(tk.END, "Sin logs\n")
            else:
                self.logs_text.insert(tk.END, f"Últimos {len(logs)} registros:\n\n")
                for log in reversed(logs[-limit:]):
                    icon = "🔒" if log.get('action') == 'ENCRYPT' else "✅" if log.get('status') == 'SUCCESS' else "❌"
                    line = f"{icon} {log.get('timestamp', '')[:19]} | {log.get('action', '')} | {log.get('username', 'N/A')} | {log.get('ip', '')}\n"
                    self.logs_text.insert(tk.END, line)

            self.logs_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # Utilidades
    def update_status(self):
        if not self.ip_checker:
            return
            
        try:
            info = self.ip_checker.get_network_info()
            ip = info['local_ip']
            auth, _ = self.ip_checker.is_ip_authorized(ip)
            
            if auth:
                self.ip_status_label.config(text=f"✅ IP: {ip}", foreground='green')
            else:
                self.ip_status_label.config(text=f"⚠️ IP: {ip}", foreground='orange')
        except:
            self.ip_status_label.config(text="❓ IP: Unknown", foreground='gray')
    
    def clear_encrypt(self):
        self.pdf_path_var.set("")
        self.output_path_var.set("")
        self.users_var.set("")
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.config(state=tk.DISABLED)
    
    def clear_decrypt(self):
        self.encrypted_path_var.set("")
        self.user_key_var.set("")
        self.decrypt_status.config(text="")
    
    def on_closing(self):
        if messagebox.askokcancel("Salir", "¿Cerrar?"):
            # Detener API si está ejecutándose
            if self.api_manager and self.api_manager.is_running():
                self.api_manager.stop()
            self.root.destroy()

    # Métodos de gestión de API
    def start_api(self):
        """Inicia el servidor de la API"""
        if not self.api_manager:
            messagebox.showerror("Error", "API Manager no inicializado")
            return

        self.status_label.config(text="Iniciando API...")

        def worker():
            success, message = self.api_manager.start(in_thread=True)
            if success:
                self.root.after(0, lambda: messagebox.showinfo("Éxito", message))
                self.root.after(0, lambda: self.status_label.config(text="API iniciada"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", message))
                self.root.after(0, lambda: self.status_label.config(text="Error al iniciar API"))

            self.root.after(0, self.refresh_api_status)

        threading.Thread(target=worker, daemon=True).start()

    def stop_api(self):
        """Detiene el servidor de la API"""
        if not self.api_manager:
            messagebox.showerror("Error", "API Manager no inicializado")
            return

        self.status_label.config(text="Deteniendo API...")

        def worker():
            success, message = self.api_manager.stop()
            if success:
                self.root.after(0, lambda: messagebox.showinfo("Éxito", message))
                self.root.after(0, lambda: self.status_label.config(text="API detenida"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", message))
                self.root.after(0, lambda: self.status_label.config(text="Error al detener API"))

            self.root.after(0, self.refresh_api_status)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_api_status(self):
        """Actualiza el estado de la API en la interfaz"""
        if not self.api_manager:
            return

        status = self.api_manager.get_status()

        if status['running']:
            self.api_status_label.config(text="✅ EJECUTÁNDOSE", foreground='green')
            self.api_url_label.config(text=f"URL: {status['url']}")

            if status.get('healthy'):
                health_text = "❤️ Salud: ✅ Saludable"
                if 'version' in status:
                    health_text += f" | Versión: {status['version']}"
                self.api_health_label.config(text=health_text, foreground='green')
            else:
                self.api_health_label.config(text="⚠️ Salud: Responde con errores", foreground='orange')
        else:
            self.api_status_label.config(text="⭕ DETENIDA", foreground='red')
            self.api_url_label.config(text="URL: N/A")
            self.api_health_label.config(text="")

    def open_api_browser(self):
        """Abre el navegador en la URL de la API"""
        if not self.api_manager:
            messagebox.showerror("Error", "API Manager no inicializado")
            return

        success, message = self.api_manager.open_browser()
        if success:
            self.status_label.config(text="Navegador abierto")
        else:
            messagebox.showerror("Error", message)

    def list_system_users(self):
        """Lista los usuarios del sistema usando la API"""
        if not self.api_manager:
            messagebox.showerror("Error", "API Manager no inicializado")
            return

        self.status_label.config(text="Obteniendo usuarios...")
        self.system_users_text.delete(1.0, tk.END)

        def worker():
            users_data = self.api_manager.get_users(filter_type='all', format_type='json')

            if users_data and users_data.get('success'):
                users = users_data.get('data', [])
                total = users_data.get('count', 0)

                result = f"{'='*60}\n"
                result += f"USUARIOS DEL SISTEMA - Total: {total}\n"
                result += f"{'='*60}\n\n"

                for i, user in enumerate(users, 1):
                    username = user.get('username', 'Unknown')
                    result += f"{i}. {username}\n"

                    # Info adicional según el SO
                    if 'full_name' in user and user['full_name']:
                        result += f"   Nombre completo: {user['full_name']}\n"
                    if 'home_directory' in user:
                        result += f"   Home: {user['home_directory']}\n"
                    if 'shell' in user:
                        result += f"   Shell: {user['shell']}\n"
                    if 'uid' in user:
                        result += f"   UID: {user['uid']}\n"

                    is_system = user.get('is_system_user', False)
                    result += f"   Tipo: {'Sistema' if is_system else 'Usuario'}\n"

                    result += "\n"

                self.root.after(0, lambda r=result: self.system_users_text.insert(1.0, r))
                self.root.after(0, lambda: self.status_label.config(text=f"{total} usuarios obtenidos"))
            else:
                error_msg = "❌ No se pudo obtener la lista de usuarios\n\n"
                error_msg += "Asegúrate de que la API esté ejecutándose.\n"
                error_msg += "Usa el botón '▶️ Iniciar API' para iniciarla."

                self.root.after(0, lambda: self.system_users_text.insert(1.0, error_msg))
                self.root.after(0, lambda: self.status_label.config(text="Error obteniendo usuarios"))

        threading.Thread(target=worker, daemon=True).start()

    def run(self):
        self.update_status()
        self.root.mainloop()

def main():
    try:
        app = PDFSecureGUI()
        app.run()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()