#!/usr/bin/env python3
"""
File Secure GUI - Version 3.2 Enterprise Edition
Interfaz gráfica para el sistema de cifrado de archivos seguros
Soporta múltiples formatos: PDF, DOCX, XLSX, TXT, PBIP, PBIX

Nuevas características v3.2:
- Multi-tenancy (organizaciones y departamentos)
- RBAC completo (roles y permisos granulares)
- Auditoría centralizada
- Políticas configurables
- Dashboard ejecutivo
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
from datetime import datetime

# Agregar el directorio app al path
sys.path.append(str(Path(__file__).parent))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager
from ip_check import IPChecker

class PDFSecureGUI:
    def __init__(self):
        # Inicializar configuración
        try:
            self.config = SecureConfig()
            self.auth_manager = UserAuthManager(self.config)
            self.pdf_manager = PDFSecureManager(self.config, self.auth_manager)
            self.ip_checker = IPChecker(self.config)
        except ValueError as e:
            messagebox.showerror("Error de Configuración", 
                                f"Error: {str(e)}\n\nPara configurar la clave maestra, ejecuta:\n"
                                "export PDF_SECURE_MASTER_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')")
            sys.exit(1)
        
        # Crear ventana principal
        self.root = tk.Tk()
        self.root.title("📁 File Secure v3.2 Enterprise")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)

        # Configurar estilo básico (ModernTheme no existe en este archivo)
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Variables de la interfaz
        self.pdf_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.encrypted_path_var = tk.StringVar()
        self.user_key_var = tk.StringVar()
        self.users_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.ip_desc_var = tk.StringVar()
        
        # Crear interfaz
        self.create_widgets()
        self.update_status()
        
        # Configurar cierre de ventana
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """Crea todos los widgets de la interfaz"""
        # Crear notebook para pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Crear pestañas
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_users_tab()
        self.create_ips_tab()
        self.create_logs_tab()
        self.create_info_tab()
        
        # Barra de estado
        self.create_status_bar()
    
    def create_status_bar(self):
        """Crea la barra de estado"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Listo", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)
        
        # Indicador de estado IP
        self.ip_status_label = ttk.Label(self.status_frame, text="", relief=tk.SUNKEN)
        self.ip_status_label.pack(side=tk.RIGHT, padx=2, pady=2)
    
    # CONTINÚA DESDE PARTE 1...
    
    def create_encrypt_tab(self):
        """Crea la pestaña de cifrado"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Cifrar PDF")
        
        main_frame = ttk.Frame(encrypt_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        ttk.Label(main_frame, text="🔒 Cifrar PDF con Claves de Usuario", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Archivo PDF
        pdf_frame = ttk.LabelFrame(main_frame, text="📄 Archivo PDF", padding=10)
        pdf_frame.pack(fill=tk.X, pady=(0, 10))
        
        pdf_entry_frame = ttk.Frame(pdf_frame)
        pdf_entry_frame.pack(fill=tk.X)
        ttk.Entry(pdf_entry_frame, textvariable=self.pdf_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pdf_entry_frame, text="Examinar", command=self.browse_pdf_file).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Archivo de salida
        output_frame = ttk.LabelFrame(main_frame, text="💾 Archivo de Salida", padding=10)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X)
        ttk.Entry(output_entry_frame, textvariable=self.output_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_entry_frame, text="Examinar", command=self.browse_output_file).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Usuarios
        users_frame = ttk.LabelFrame(main_frame, text="👥 Usuarios Autorizados", padding=10)
        users_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(users_frame, text="Ingresa los nombres de usuario separados por comas:").pack(anchor=tk.W)
        ttk.Entry(users_frame, textvariable=self.users_var, width=50).pack(fill=tk.X, pady=(5, 0))
        ttk.Label(users_frame, text="Ejemplo: usuario1, usuario2, admin", 
                 font=('Arial', 9), foreground='gray').pack(anchor=tk.W, pady=(2, 0))
        
        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)
        ttk.Button(buttons_frame, text="🔒 Cifrar PDF", command=self.encrypt_pdf).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="🧹 Limpiar", command=self.clear_encrypt_fields).pack(side=tk.LEFT)
        
        # Resultados
        results_frame = ttk.LabelFrame(main_frame, text="🔑 Claves Generadas", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.encrypt_results = scrolledtext.ScrolledText(results_frame, height=10, wrap=tk.WORD)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True)
        ttk.Button(results_frame, text="📋 Copiar Claves", command=self.copy_encryption_results).pack(pady=(5, 0))
    
    def create_decrypt_tab(self):
        """Crea la pestaña de descifrado"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Descifrar PDF")
        
        main_frame = ttk.Frame(decrypt_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="🔓 Descifrar PDF con Clave de Usuario", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Archivo cifrado
        encrypted_frame = ttk.LabelFrame(main_frame, text="🔒 Archivo Cifrado", padding=10)
        encrypted_frame.pack(fill=tk.X, pady=(0, 10))
        encrypted_entry_frame = ttk.Frame(encrypted_frame)
        encrypted_entry_frame.pack(fill=tk.X)
        ttk.Entry(encrypted_entry_frame, textvariable=self.encrypted_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(encrypted_entry_frame, text="Examinar", command=self.browse_encrypted_file).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Clave
        key_frame = ttk.LabelFrame(main_frame, text="🔑 Clave de Usuario", padding=10)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        key_entry = ttk.Entry(key_frame, textvariable=self.user_key_var, width=50, show="*")
        key_entry.pack(fill=tk.X)
        show_key_var = tk.BooleanVar()
        ttk.Checkbutton(key_frame, text="Mostrar clave", variable=show_key_var,
                       command=lambda: key_entry.config(show="" if show_key_var.get() else "*")).pack(anchor=tk.W, pady=(5, 0))
        
        # Info del archivo
        info_frame = ttk.LabelFrame(main_frame, text="ℹ️ Información del Archivo", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        self.file_info_text = tk.Text(info_frame, height=4, wrap=tk.WORD, state=tk.DISABLED)
        self.file_info_text.pack(fill=tk.X)
        ttk.Button(info_frame, text="📋 Ver Información", command=self.show_file_info).pack(pady=(5, 0))
        
        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)
        ttk.Button(buttons_frame, text="🔓 Descifrar PDF", command=self.decrypt_pdf).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="🧹 Limpiar", command=self.clear_decrypt_fields).pack(side=tk.LEFT)
        
        self.decrypt_status = ttk.Label(main_frame, text="", foreground='green')
        self.decrypt_status.pack(pady=(10, 0))

    # CONTINÚA DESDE PARTE 2...
    
    def create_users_tab(self):
        """Crea la pestaña de gestión de usuarios"""
        users_frame = ttk.Frame(self.notebook)
        self.notebook.add(users_frame, text="👥 Usuarios")
        
        main_frame = ttk.Frame(users_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="👥 Gestión de Usuarios y Claves", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Controles
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(control_frame, text="🔄 Actualizar", command=self.refresh_users_list).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="🧹 Limpiar Expiradas", command=self.cleanup_expired_keys).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="📊 Estadísticas", command=self.show_user_stats).pack(side=tk.LEFT)
        
        # Lista
        list_frame = ttk.LabelFrame(main_frame, text="🔑 Claves Activas", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Usuario", "Archivo", "Creada", "Expira", "Accesos")
        self.users_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)
        for col in columns:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=120)
        
        scrollbar_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        scrollbar_h = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.users_tree.xview)
        self.users_tree.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
        
        self.users_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_v.grid(row=0, column=1, sticky="ns")
        scrollbar_h.grid(row=1, column=0, sticky="ew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Acciones
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(actions_frame, text="❌ Revocar", command=self.revoke_selected_key).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions_frame, text="⏰ Extender", command=self.extend_selected_key).pack(side=tk.LEFT)
        
        self.refresh_users_list()
    
    def create_ips_tab(self):
        """Crea la pestaña de gestión de IPs"""
        ips_frame = ttk.Frame(self.notebook)
        self.notebook.add(ips_frame, text="🌐 IPs")
        
        main_frame = ttk.Frame(ips_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="🌐 Gestión de IPs Autorizadas", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Info actual
        info_frame = ttk.LabelFrame(main_frame, text="ℹ️ Información Actual", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        network_info = self.ip_checker.get_network_info()
        ttk.Label(info_frame, text=f"🖥️ Tu IP: {network_info['local_ip']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"🏠 Host: {network_info['hostname']}").pack(anchor=tk.W)
        
        # Agregar IP
        add_frame = ttk.LabelFrame(main_frame, text="➕ Agregar IP", padding=10)
        add_frame.pack(fill=tk.X, pady=(0, 10))
        
        ip_entry_frame = ttk.Frame(add_frame)
        ip_entry_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(ip_entry_frame, text="IP:").pack(side=tk.LEFT)
        ttk.Entry(ip_entry_frame, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=(5, 10))
        ttk.Button(ip_entry_frame, text="➕ IP Actual", command=lambda: self.ip_var.set(network_info['local_ip'])).pack(side=tk.LEFT)
        
        desc_frame = ttk.Frame(add_frame)
        desc_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(desc_frame, text="Descripción:").pack(side=tk.LEFT)
        ttk.Entry(desc_frame, textvariable=self.ip_desc_var, width=30).pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        
        ttk.Button(add_frame, text="➕ Agregar IP", command=self.add_ip).pack(pady=(5, 0))
        
        # Lista IPs
        list_frame = ttk.LabelFrame(main_frame, text="📋 IPs Autorizadas", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        ip_columns = ("IP", "Descripción", "Agregada", "Accesos", "Último Acceso")
        self.ips_tree = ttk.Treeview(list_frame, columns=ip_columns, show="headings", height=10)
        for col in ip_columns:
            self.ips_tree.heading(col, text=col)
            self.ips_tree.column(col, width=120)
        
        scrollbar_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.ips_tree.yview)
        scrollbar_h = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.ips_tree.xview)
        self.ips_tree.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
        
        self.ips_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_v.grid(row=0, column=1, sticky="ns")
        scrollbar_h.grid(row=1, column=0, sticky="ew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Acciones
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(actions_frame, text="🔄 Actualizar", command=self.refresh_ips_list).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions_frame, text="❌ Eliminar", command=self.remove_selected_ip).pack(side=tk.LEFT)
        
        self.refresh_ips_list()
    
    def create_logs_tab(self):
        """Crea la pestaña de logs"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📊 Logs")
        
        main_frame = ttk.Frame(logs_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="📊 Logs de Acceso", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Controles
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(controls_frame, text="🔄 Actualizar", command=self.refresh_logs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(controls_frame, text="Mostrar:").pack(side=tk.LEFT, padx=(10, 5))
        self.log_limit_var = tk.StringVar(value="50")
        ttk.Combobox(controls_frame, textvariable=self.log_limit_var, values=["25", "50", "100", "200"], width=8).pack(side=tk.LEFT)
        ttk.Button(controls_frame, text="📋 Exportar", command=self.export_logs).pack(side=tk.LEFT, padx=(10, 0))
        
        # Logs
        logs_text_frame = ttk.LabelFrame(main_frame, text="📄 Registro", padding=10)
        logs_text_frame.pack(fill=tk.BOTH, expand=True)
        self.logs_text = scrolledtext.ScrolledText(logs_text_frame, height=20, wrap=tk.WORD, font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_logs()
    
    def create_info_tab(self):
        """Crea la pestaña de información"""
        info_frame = ttk.Frame(self.notebook)
        self.notebook.add(info_frame, text="ℹ️ Info")
        
        main_frame = ttk.Frame(info_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="ℹ️ Información del Sistema", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Sistema
        system_frame = ttk.LabelFrame(main_frame, text="🖥️ Sistema", padding=10)
        system_frame.pack(fill=tk.X, pady=(0, 10))
        network_info = self.ip_checker.get_network_info()
        system_info = f"""🖥️ Hostname: {network_info['hostname']}
🌐 IP Local: {network_info['local_ip']}
🏠 IP Privada: {'Sí' if network_info['is_private'] else 'No'}
📁 Config: {self.config.config_dir}
🔑 Clave Maestra: {'✅ Configurada' if os.getenv('PDF_SECURE_MASTER_KEY') else '❌ No'}"""
        
        system_text = tk.Text(system_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
        system_text.pack(fill=tk.X)
        system_text.config(state=tk.NORMAL)
        system_text.insert(tk.END, system_info)
        system_text.config(state=tk.DISABLED)
        
        # Estadísticas
        stats_frame = ttk.LabelFrame(main_frame, text="📊 Estadísticas", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        self.stats_text = tk.Text(stats_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.stats_text.pack(fill=tk.X)
        ttk.Button(stats_frame, text="🔄 Actualizar", command=self.update_stats).pack(pady=(5, 0))
        
        # Acerca de
        app_frame = ttk.LabelFrame(main_frame, text="📄 Acerca de", padding=10)
        app_frame.pack(fill=tk.X)
        app_info = """📄 PDF Secure v2.0
🔐 Sistema de PDFs seguros con autenticación

✨ Características:
• Cifrado AES-256 con claves únicas
• Control de acceso por usuario
• Whitelist de IPs locales
• Trazabilidad completa

👨‍💻 Desarrollado por: Zeligmax
📄 Licencia: MIT"""
        
        app_text = tk.Text(app_frame, height=12, wrap=tk.WORD, state=tk.DISABLED)
        app_text.pack(fill=tk.X)
        app_text.config(state=tk.NORMAL)
        app_text.insert(tk.END, app_info)
        app_text.config(state=tk.DISABLED)
        
        self.update_stats()

    # CONTINÚA DESDE PARTE 3... (FINAL)
    
    # Métodos de archivos
    def browse_pdf_file(self):
        file_path = filedialog.askopenfilename(title="Seleccionar PDF", filetypes=[("PDF", "*.pdf"), ("Todos", "*.*")])
        if file_path:
            self.pdf_path_var.set(file_path)
            self.output_path_var.set(str(Path(file_path).with_suffix('.enc')))
    
    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(title="Guardar como", defaultextension=".enc", filetypes=[("Cifrado", "*.enc"), ("Todos", "*.*")])
        if file_path:
            self.output_path_var.set(file_path)
    
    def browse_encrypted_file(self):
        file_path = filedialog.askopenfilename(title="Seleccionar cifrado", filetypes=[("Cifrado", "*.enc"), ("JSON", "*.json"), ("Todos", "*.*")])
        if file_path:
            self.encrypted_path_var.set(file_path)
    
    # Cifrado/Descifrado
    def encrypt_pdf(self):
        pdf_path = self.pdf_path_var.get().strip()
        output_path = self.output_path_var.get().strip()
        users_input = self.users_var.get().strip()
        
        if not all([pdf_path, output_path, users_input]):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
        
        if not Path(pdf_path).exists():
            messagebox.showerror("Error", f"Archivo no existe: {pdf_path}")
            return
        
        authorized_users = [u.strip() for u in users_input.split(',') if u.strip()]
        if not authorized_users:
            messagebox.showerror("Error", "Especifica al menos un usuario")
            return
        
        def encrypt_worker():
            try:
                self.status_label.config(text="Cifrando...")
                user_keys = self.pdf_manager.encrypt_pdf_with_user_keys(pdf_path, output_path, authorized_users)
                
                results = f"✅ Cifrado: {output_path}\n\n🔑 CLAVES:\n" + "="*50 + "\n\n"
                for username, key in user_keys.items():
                    results += f"👤 {username}\n🔑 {key}\n\n"
                results += "⚠️ IMPORTANTE: Guarda estas claves de forma segura.\n"
                
                self.root.after(0, lambda: self.show_encrypt_results(results))
                self.root.after(0, lambda: self.status_label.config(text="Cifrado completado"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.status_label.config(text="Error"))
        
        threading.Thread(target=encrypt_worker, daemon=True).start()
    
    def show_encrypt_results(self, results):
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.insert(tk.END, results)
        self.encrypt_results.config(state=tk.DISABLED)
        self.notebook.select(0)
    
    def copy_encryption_results(self):
        try:
            results = self.encrypt_results.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(results)
            messagebox.showinfo("Copiado", "Claves copiadas al portapapeles")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo copiar: {str(e)}")
    
    def decrypt_pdf(self):
        encrypted_path = self.encrypted_path_var.get().strip()
        user_key = self.user_key_var.get().strip()
        
        if not all([encrypted_path, user_key]):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
        
        if not Path(encrypted_path).exists():
            messagebox.showerror("Error", f"Archivo no existe: {encrypted_path}")
            return
        
        def decrypt_worker():
            try:
                self.status_label.config(text="Descifrando...")
                ip_auth, ip_info = self.ip_checker.is_ip_authorized()
                if not ip_auth:
                    self.root.after(0, lambda: messagebox.showerror("Acceso Denegado", f"{ip_info['reason']}\nIP: {ip_info['ip']}"))
                    return
                
                decrypted_path = self.pdf_manager.decrypt_pdf_with_user_key(encrypted_path, user_key)
                
                self.root.after(0, lambda: messagebox.showinfo("Éxito", f"PDF descifrado:\n{decrypted_path}"))
                self.root.after(0, lambda: self.decrypt_status.config(text=f"✅ Descifrado: {Path(decrypted_path).name}", foreground='green'))
                self.root.after(0, lambda: self.status_label.config(text="Descifrado completado"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.decrypt_status.config(text="❌ Error", foreground='red'))
                self.root.after(0, lambda: self.status_label.config(text="Error"))
        
        threading.Thread(target=decrypt_worker, daemon=True).start()
    
    def show_file_info(self):
        encrypted_path = self.encrypted_path_var.get().strip()
        if not encrypted_path:
            messagebox.showerror("Error", "Selecciona un archivo")
            return
        if not Path(encrypted_path).exists():
            messagebox.showerror("Error", "El archivo no existe")
            return
        
        try:
            info = self.pdf_manager.get_file_info(encrypted_path)
            info_text = f"📄 {info['filename']}\n📊 {info['size']:,} bytes\n🕐 {info['encrypted_on']}\n🔐 {info['encryption_method']}\n👥 {', '.join(info['authorized_users'])}"
            
            self.file_info_text.config(state=tk.NORMAL)
            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, info_text)
            self.file_info_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener información: {str(e)}")
    
    # Gestión de usuarios
    def refresh_users_list(self):
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        try:
            user_keys = self.auth_manager.load_user_keys()
            active_count = 0
            
            from datetime import datetime
            for key_id, key_data in user_keys.items():
                try:
                    expires = datetime.fromisoformat(key_data['expires'])
                    if datetime.now() <= expires:
                        username = key_data.get('username', 'Unknown')
                        pdf_name = Path(key_data.get('pdf_path', '')).name
                        created = key_data.get('created', '')[:10]
                        expires_str = expires.strftime('%Y-%m-%d')
                        access_count = key_data.get('access_count', 0)
                        
                        self.users_tree.insert('', tk.END, values=(username, pdf_name, created, expires_str, access_count), tags=(key_id,))
                        active_count += 1
                except (ValueError, KeyError):
                    continue
            
            self.status_label.config(text=f"Claves activas: {active_count}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar usuarios: {str(e)}")
    
    def revoke_selected_key(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecciona una clave")
            return
        
        item = selection[0]
        key_id = self.users_tree.item(item, 'tags')[0]
        username = self.users_tree.item(item, 'values')[0]
        
        if messagebox.askyesno("Confirmar", f"¿Revocar clave de '{username}'?"):
            try:
                user_keys = self.auth_manager.load_user_keys()
                if key_id in user_keys:
                    user_key = user_keys[key_id]['user_key']
                    if self.auth_manager.revoke_user_key(user_key):
                        messagebox.showinfo("Éxito", f"Clave de '{username}' revocada")
                        self.refresh_users_list()
                    else:
                        messagebox.showerror("Error", "No se pudo revocar")
                else:
                    messagebox.showerror("Error", "Clave no encontrada")
            except Exception as e:
                messagebox.showerror("Error", f"Error: {str(e)}")
    
    def extend_selected_key(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecciona una clave")
            return
        
        item = selection[0]
        key_id = self.users_tree.item(item, 'tags')[0]
        username = self.users_tree.item(item, 'values')[0]
        
        try:
            import tkinter.simpledialog
            days_str = tkinter.simpledialog.askstring("Extender", f"¿Cuántos días para '{username}'?", initialvalue="30")
            if not days_str:
                return
            
            days = int(days_str)
            user_keys = self.auth_manager.load_user_keys()
            if key_id in user_keys:
                user_key = user_keys[key_id]['user_key']
                if self.auth_manager.extend_key_expiration(user_key, days):
                    messagebox.showinfo("Éxito", f"Extendida por {days} días")
                    self.refresh_users_list()
                else:
                    messagebox.showerror("Error", "No se pudo extender")
            else:
                messagebox.showerror("Error", "Clave no encontrada")
        except ValueError:
            messagebox.showerror("Error", "Número de días no válido")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def cleanup_expired_keys(self):
        try:
            cleaned = self.auth_manager.cleanup_expired_keys()
            if cleaned > 0:
                messagebox.showinfo("Limpieza", f"Eliminadas {cleaned} claves expiradas")
                self.refresh_users_list()
            else:
                messagebox.showinfo("Limpieza", "No hay claves expiradas")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def show_user_stats(self):
        try:
            user_keys = self.auth_manager.load_user_keys()
            active_keys = 0
            expired_keys = 0
            total_accesses = 0
            
            from datetime import datetime
            for key_data in user_keys.values():
                try:
                    expires = datetime.fromisoformat(key_data['expires'])
                    if datetime.now() <= expires:
                        active_keys += 1
                    else:
                        expired_keys += 1
                    total_accesses += key_data.get('access_count', 0)
                except (ValueError, KeyError):
                    expired_keys += 1
            
            stats_msg = f"""📊 Estadísticas de Usuarios:

🔑 Claves activas: {active_keys}
⏰ Claves expiradas: {expired_keys}
📊 Total: {len(user_keys)}
🎯 Accesos: {total_accesses}"""
            
            messagebox.showinfo("Estadísticas", stats_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    # Gestión de IPs
    def add_ip(self):
        ip = self.ip_var.get().strip()
        description = self.ip_desc_var.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Especifica una IP")
            return
        
        valid, msg = self.ip_checker.validate_ip_format(ip)
        if not valid:
            messagebox.showerror("Error", f"IP inválida: {msg}")
            return
        
        try:
            self.config.add_ip_to_whitelist(ip, description)
            messagebox.showinfo("Éxito", f"IP {ip} agregada")
            self.ip_var.set("")
            self.ip_desc_var.set("")
            self.refresh_ips_list()
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def refresh_ips_list(self):
        for item in self.ips_tree.get_children():
            self.ips_tree.delete(item)
        
        try:
            whitelist = self.config.load_ip_whitelist()
            for entry in whitelist:
                ip = entry.get('ip', 'Unknown')
                description = entry.get('description', '')
                added = entry.get('added', '')[:10] if entry.get('added') else 'Unknown'
                access_count = entry.get('access_count', 0)
                last_access = entry.get('last_access', '')[:10] if entry.get('last_access') else 'Nunca'
                
                self.ips_tree.insert('', tk.END, values=(ip, description, added, access_count, last_access))
            
            self.status_label.config(text=f"IPs autorizadas: {len(whitelist)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def remove_selected_ip(self):
        selection = self.ips_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecciona una IP")
            return
        
        item = selection[0]
        ip = self.ips_tree.item(item, 'values')[0]
        
        if messagebox.askyesno("Confirmar", f"¿Eliminar IP '{ip}'?"):
            try:
                self.config.remove_ip_from_whitelist(ip)
                messagebox.showinfo("Éxito", f"IP {ip} eliminada")
                self.refresh_ips_list()
                self.update_status()
            except Exception as e:
                messagebox.showerror("Error", f"Error: {str(e)}")
    
    # Logs
    def refresh_logs(self):
        try:
            limit = int(self.log_limit_var.get())
            logs = self.pdf_manager.get_access_logs(limit)
            
            self.logs_text.config(state=tk.NORMAL)
            self.logs_text.delete(1.0, tk.END)
            
            if not logs:
                self.logs_text.insert(tk.END, "📄 No hay logs\n")
            else:
                self.logs_text.insert(tk.END, f"📊 Últimos {len(logs)} registros:\n\n")
                
                for log in reversed(logs[-limit:]):
                    timestamp = log.get('timestamp', 'Unknown')[:19]
                    action = log.get('action', 'Unknown')
                    status = log.get('status', 'Unknown')
                    username = log.get('username', 'Unknown')
                    ip = log.get('ip', 'Unknown')
                    
                    if action == 'ENCRYPT':
                        icon = "🔒"
                    elif status == 'SUCCESS':
                        icon = "✅"
                    elif 'FAILED' in status or 'UNAUTHORIZED' in status:
                        icon = "❌"
                    else:
                        icon = "📄"
                    
                    log_line = f"{icon} {timestamp} | {action}"
                    if username != 'Unknown':
                        log_line += f" | 👤 {username}"
                    if status != 'Unknown':
                        log_line += f" | {status}"
                    log_line += f" | 🌐 {ip}"
                    
                    if log.get('pdf_path'):
                        pdf_name = Path(log['pdf_path']).name
                        log_line += f" | 📄 {pdf_name}"
                    
                    self.logs_text.insert(tk.END, log_line + "\n")
            
            self.logs_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def export_logs(self):
        try:
            file_path = filedialog.asksaveasfilename(title="Exportar logs", defaultextension=".txt", 
                                                     filetypes=[("Texto", "*.txt"), ("JSON", "*.json")])
            if not file_path:
                return
            
            logs = self.pdf_manager.get_access_logs(1000)
            
            if file_path.endswith('.json'):
                import json
                with open(file_path, 'w') as f:
                    json.dump(logs, f, indent=2)
            else:
                with open(file_path, 'w') as f:
                    f.write(f"PDF Secure v2.0 - Logs\nExportado: {datetime.now().isoformat()}\n" + "="*50 + "\n\n")
                    for log in logs:
                        f.write(f"Timestamp: {log.get('timestamp', 'Unknown')}\n")
                        f.write(f"Acción: {log.get('action', 'Unknown')}\n")
                        f.write(f"Estado: {log.get('status', 'Unknown')}\n")
                        if log.get('username') != 'Unknown':
                            f.write(f"Usuario: {log.get('username')}\n")
                        f.write(f"IP: {log.get('ip', 'Unknown')}\n")
                        if log.get('pdf_path'):
                            f.write(f"Archivo: {Path(log['pdf_path']).name}\n")
                        f.write("-"*30 + "\n")
            
            messagebox.showinfo("Éxito", f"Logs exportados a: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    # Estadísticas
    def update_stats(self):
        try:
            user_keys = self.auth_manager.load_user_keys()
            active_keys = 0
            expired_keys = 0
            total_accesses = 0
            
            from datetime import datetime
            for key_data in user_keys.values():
                try:
                    expires = datetime.fromisoformat(key_data['expires'])
                    if datetime.now() <= expires:
                        active_keys += 1
                    else:
                        expired_keys += 1
                    total_accesses += key_data.get('access_count', 0)
                except (ValueError, KeyError):
                    expired_keys += 1
            
            whitelist = self.config.load_ip_whitelist()
            logs = self.pdf_manager.get_access_logs(1000)
            successful = len([l for l in logs if l.get('status') == 'SUCCESS'])
            failed = len([l for l in logs if 'FAILED' in l.get('status', '') or 'UNAUTHORIZED' in l.get('status', '')])
            
            stats_text = f"""📊 ESTADÍSTICAS
{'-'*30}

🔑 Claves de Usuario:
   • Activas: {active_keys}
   • Expiradas: {expired_keys}
   • Total: {len(user_keys)}
   • Accesos: {total_accesses}

🌐 IPs: {len(whitelist)}

📄 Actividad:
   • Éxitos: {successful}
   • Fallos: {failed}
   • Total: {len(logs)}

🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self.stats_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def update_status(self):
        try:
            network_info = self.ip_checker.get_network_info()
            current_ip = network_info['local_ip']
            ip_auth, ip_info = self.ip_checker.is_ip_authorized(current_ip)
            
            if ip_auth:
                if ip_info['status'] == 'whitelisted':
                    self.ip_status_label.config(text=f"✅ IP: {current_ip} (Autorizada)", foreground='green')
                else:
                    self.ip_status_label.config(text=f"⚠️ IP: {current_ip} (Sin whitelist)", foreground='orange')
            else:
                self.ip_status_label.config(text=f"❌ IP: {current_ip} (No autorizada)", foreground='red')
        except Exception:
            self.ip_status_label.config(text="❓ Estado desconocido", foreground='gray')
    
    # Utilidades
    def clear_encrypt_fields(self):
        self.pdf_path_var.set("")
        self.output_path_var.set("")
        self.users_var.set("")
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.config(state=tk.DISABLED)
    
    def clear_decrypt_fields(self):
        self.encrypted_path_var.set("")
        self.user_key_var.set("")
        self.file_info_text.config(state=tk.NORMAL)
        self.file_info_text.delete(1.0, tk.END)
        self.file_info_text.config(state=tk.DISABLED)
        self.decrypt_status.config(text="")
    
    def on_closing(self):
        if messagebox.askokcancel("Salir", "¿Cerrar PDF Secure?"):
            self.root.destroy()
    
    def run(self):
        self.update_status()
        self.root.mainloop()

def main():
    import tkinter.simpledialog
    
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
    except tk.TclError:
        print("❌ Tkinter no disponible")
        print("   Linux: sudo apt-get install python3-tk")
        sys.exit(1)
    
    try:
        app = PDFSecureGUI()
        app.run()
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()