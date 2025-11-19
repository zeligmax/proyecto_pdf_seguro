#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDF Secure GUI - Version 2.0 - COMPLETO
Interfaz gráfica para el sistema de PDFs seguros
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
from datetime import datetime

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar directorio app al path
sys.path.append(str(Path(__file__).parent))

from config import SecureConfig
from user_auth import UserAuthManager
from pdf_utils_v2 import PDFSecureManager
from ip_check import IPChecker

class PDFSecureGUI:
    def __init__(self):
        # Crear ventana PRIMERO
        self.root = tk.Tk()
        self.root.title("PDF Secure v2.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Variables
        self.pdf_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.encrypted_path_var = tk.StringVar()
        self.user_key_var = tk.StringVar()
        self.users_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.ip_desc_var = tk.StringVar()
        self.log_limit_var = tk.StringVar(value="50")
        
        # Inicializar atributos del backend como None
        self.config = None
        self.auth_manager = None
        self.pdf_manager = None
        self.ip_checker = None
        
        # CREAR WIDGETS (incluye status_label)
        self.create_widgets()
        
        # LUEGO inicializar backend
        try:
            self.config = SecureConfig()
            self.auth_manager = UserAuthManager(self.config)
            self.pdf_manager = PDFSecureManager(self.config, self.auth_manager)
            self.ip_checker = IPChecker(self.config)
            
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
        
        # Barra de estado
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Listo", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)
        
        self.ip_status_label = ttk.Label(self.status_frame, text="", relief=tk.SUNKEN)
        self.ip_status_label.pack(side=tk.RIGHT, padx=2, pady=2)
    
    def create_encrypt_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔒 Cifrar")
        
        main = ttk.Frame(frame)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main, text="🔒 Cifrar PDF", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # PDF
        pdf_frame = ttk.LabelFrame(main, text="📄 Archivo PDF", padding=10)
        pdf_frame.pack(fill=tk.X, pady=(0, 10))
        pdf_entry = ttk.Frame(pdf_frame)
        pdf_entry.pack(fill=tk.X)
        ttk.Entry(pdf_entry, textvariable=self.pdf_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pdf_entry, text="Examinar", command=self.browse_pdf).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Salida
        out_frame = ttk.LabelFrame(main, text="💾 Salida", padding=10)
        out_frame.pack(fill=tk.X, pady=(0, 10))
        out_entry = ttk.Frame(out_frame)
        out_entry.pack(fill=tk.X)
        ttk.Entry(out_entry, textvariable=self.output_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(out_entry, text="Examinar", command=self.browse_output).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Usuarios
        users_frame = ttk.LabelFrame(main, text="👥 Usuarios", padding=10)
        users_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(users_frame, text="Nombres separados por comas:").pack(anchor=tk.W)
        ttk.Entry(users_frame, textvariable=self.users_var).pack(fill=tk.X, pady=(5, 0))
        
        # Botones
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="🔒 Cifrar", command=self.encrypt_pdf).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🧹 Limpiar", command=self.clear_encrypt).pack(side=tk.LEFT)
        
        # Resultados
        res_frame = ttk.LabelFrame(main, text="🔑 Claves", padding=10)
        res_frame.pack(fill=tk.BOTH, expand=True)
        self.encrypt_results = scrolledtext.ScrolledText(res_frame, height=10)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True)
        ttk.Button(res_frame, text="📋 Copiar", command=self.copy_results).pack(pady=(5, 0))
    
    def create_decrypt_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔓 Descifrar")
        
        main = ttk.Frame(frame)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main, text="🔓 Descifrar PDF", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Cifrado
        enc_frame = ttk.LabelFrame(main, text="🔒 Archivo Cifrado", padding=10)
        enc_frame.pack(fill=tk.X, pady=(0, 10))
        enc_entry = ttk.Frame(enc_frame)
        enc_entry.pack(fill=tk.X)
        ttk.Entry(enc_entry, textvariable=self.encrypted_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(enc_entry, text="Examinar", command=self.browse_encrypted).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Clave
        key_frame = ttk.LabelFrame(main, text="🔑 Clave", padding=10)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        key_entry = ttk.Entry(key_frame, textvariable=self.user_key_var, show="*")
        key_entry.pack(fill=tk.X)
        show_var = tk.BooleanVar()
        ttk.Checkbutton(key_frame, text="Mostrar", variable=show_var,
                       command=lambda: key_entry.config(show="" if show_var.get() else "*")).pack(anchor=tk.W, pady=(5, 0))
        
        # Botones
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=20)
        ttk.Button(btn_frame, text="🔓 Descifrar", command=self.decrypt_pdf).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🧹 Limpiar", command=self.clear_decrypt).pack(side=tk.LEFT)
        
        self.decrypt_status = ttk.Label(main, text="")
        self.decrypt_status.pack()
    
    def create_users_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="👥 Usuarios")
        
        main = ttk.Frame(frame)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main, text="👥 Gestión de Usuarios", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Controles
        ctrl = ttk.Frame(main)
        ctrl.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(ctrl, text="🔄 Actualizar", command=self.refresh_users).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(ctrl, text="🧹 Limpiar", command=self.cleanup_keys).pack(side=tk.LEFT)
        
        # Lista
        list_frame = ttk.LabelFrame(main, text="🔑 Claves Activas", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        cols = ("Usuario", "Archivo", "Creada", "Expira", "Accesos")
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
        
        # Acciones
        actions = ttk.Frame(main)
        actions.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(actions, text="❌ Revocar", command=self.revoke_key).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions, text="⏰ Extender", command=self.extend_key).pack(side=tk.LEFT)
        
        self.refresh_users()
    
    def create_ips_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 IPs")
        
        main = ttk.Frame(frame)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main, text="🌐 Gestión de IPs", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Info - se actualizará después
        info_frame = ttk.LabelFrame(main, text="ℹ️ Info Actual", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Guardar referencia para actualizar después
        self.ip_info_label1 = ttk.Label(info_frame, text="🖥️ IP: Cargando...")
        self.ip_info_label1.pack(anchor=tk.W)
        self.ip_info_label2 = ttk.Label(info_frame, text="🏠 Host: Cargando...")
        self.ip_info_label2.pack(anchor=tk.W)
        
        # Agregar
        add_frame = ttk.LabelFrame(main, text="➕ Agregar IP", padding=10)
        add_frame.pack(fill=tk.X, pady=(0, 10))
        
        ip_entry = ttk.Frame(add_frame)
        ip_entry.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(ip_entry, text="IP:").pack(side=tk.LEFT)
        ttk.Entry(ip_entry, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=(5, 10))
        
        # Botón que se actualizará después
        self.btn_add_current_ip = ttk.Button(ip_entry, text="➕ Actual", command=self.add_current_ip)
        self.btn_add_current_ip.pack(side=tk.LEFT)
        
        desc_entry = ttk.Frame(add_frame)
        desc_entry.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(desc_entry, text="Descripción:").pack(side=tk.LEFT)
        ttk.Entry(desc_entry, textvariable=self.ip_desc_var, width=30).pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        
        ttk.Button(add_frame, text="➕ Agregar", command=self.add_ip).pack()
        
        # Lista
        list_frame = ttk.LabelFrame(main, text="📋 IPs Autorizadas", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        ip_cols = ("IP", "Descripción", "Agregada", "Accesos", "Último")
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
        
        # Acciones
        actions = ttk.Frame(main)
        actions.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(actions, text="🔄 Actualizar", command=self.refresh_ips).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions, text="❌ Eliminar", command=self.remove_ip).pack(side=tk.LEFT)
    
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
        self.notebook.add(frame, text="📊 Logs")
        
        main = ttk.Frame(frame)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main, text="📊 Logs de Acceso", font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Controles
        ctrl = ttk.Frame(main)
        ctrl.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(ctrl, text="🔄 Actualizar", command=self.refresh_logs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ctrl, text="Mostrar:").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Combobox(ctrl, textvariable=self.log_limit_var, values=["25", "50", "100"], width=8).pack(side=tk.LEFT)
        
        # Logs
        logs_frame = ttk.LabelFrame(main, text="📄 Registro", padding=10)
        logs_frame.pack(fill=tk.BOTH, expand=True)
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20, font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_logs()
    
    # Métodos de archivos
    def browse_pdf(self):
        f = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if f:
            self.pdf_path_var.set(f)
            self.output_path_var.set(str(Path(f).with_suffix('.enc')))
    
    def browse_output(self):
        f = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Cifrado", "*.enc")])
        if f:
            self.output_path_var.set(f)
    
    def browse_encrypted(self):
        f = filedialog.askopenfilename(filetypes=[("Cifrado", "*.enc"), ("JSON", "*.json")])
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
            messagebox.showerror("Error", "PDF no existe")
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
            self.root.destroy()
    
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