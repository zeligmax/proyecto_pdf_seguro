#!/usr/bin/env python3
"""
audit_viewer.py - Audit Log Viewer Widget for File Secure v3.2
View and filter audit logs
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta


class AuditViewer(ttk.Frame):
    """
    Visor de logs de auditoría
    """

    def __init__(self, parent, db_session, organization_id):
        super().__init__(parent)

        self.db = db_session
        self.organization_id = organization_id

        self._create_widgets()
        self.refresh_logs()

    def _create_widgets(self):
        """Crea los widgets de la interfaz"""

        # Header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(header, text="📋 Audit Logs", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)

        # Botones
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side=tk.RIGHT)

        ttk.Button(btn_frame, text="🔄 Refresh", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📊 Export", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Clear Filters", command=self.clear_filters).pack(side=tk.LEFT, padx=5)

        # Filtros
        filter_frame = ttk.LabelFrame(self, text="Filters", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)

        # Fila 1
        row1 = ttk.Frame(filter_frame)
        row1.pack(fill=tk.X, pady=5)

        ttk.Label(row1, text="Action:").pack(side=tk.LEFT, padx=(0, 5))
        self.action_filter = tk.StringVar(value="All")
        action_combo = ttk.Combobox(
            row1,
            textvariable=self.action_filter,
            values=["All", "auth.login", "auth.logout", "file.encrypt", "file.decrypt",
                   "user.create", "user.update", "policy.update"],
            state='readonly',
            width=20
        )
        action_combo.pack(side=tk.LEFT, padx=5)
        action_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_logs())

        ttk.Label(row1, text="Status:").pack(side=tk.LEFT, padx=(20, 5))
        self.status_filter = tk.StringVar(value="All")
        status_combo = ttk.Combobox(
            row1,
            textvariable=self.status_filter,
            values=["All", "success", "failure", "denied"],
            state='readonly',
            width=15
        )
        status_combo.pack(side=tk.LEFT, padx=5)
        status_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_logs())

        ttk.Label(row1, text="Severity:").pack(side=tk.LEFT, padx=(20, 5))
        self.severity_filter = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(
            row1,
            textvariable=self.severity_filter,
            values=["All", "info", "warning", "error", "critical"],
            state='readonly',
            width=15
        )
        severity_combo.pack(side=tk.LEFT, padx=5)
        severity_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_logs())

        # Fila 2
        row2 = ttk.Frame(filter_frame)
        row2.pack(fill=tk.X, pady=5)

        ttk.Label(row2, text="Time Range:").pack(side=tk.LEFT, padx=(0, 5))
        self.timerange_filter = tk.StringVar(value="Last 24 Hours")
        timerange_combo = ttk.Combobox(
            row2,
            textvariable=self.timerange_filter,
            values=["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
            state='readonly',
            width=20
        )
        timerange_combo.pack(side=tk.LEFT, padx=5)
        timerange_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_logs())

        ttk.Label(row2, text="Search:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.refresh_logs())
        ttk.Entry(row2, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=5)

        # Tabla de logs
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollbars
        scrollbar_y = ttk.Scrollbar(table_frame)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Treeview
        columns = ('timestamp', 'user', 'action', 'resource', 'status', 'severity', 'ip')
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show='headings',
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        scrollbar_y.config(command=self.tree.yview)
        scrollbar_x.config(command=self.tree.xview)

        # Configurar columnas
        self.tree.heading('timestamp', text='Timestamp')
        self.tree.column('timestamp', width=150)

        self.tree.heading('user', text='User')
        self.tree.column('user', width=120)

        self.tree.heading('action', text='Action')
        self.tree.column('action', width=150)

        self.tree.heading('resource', text='Resource')
        self.tree.column('resource', width=150)

        self.tree.heading('status', text='Status')
        self.tree.column('status', width=80)

        self.tree.heading('severity', text='Severity')
        self.tree.column('severity', width=80)

        self.tree.heading('ip', text='IP Address')
        self.tree.column('ip', width=120)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Tags para colores
        self.tree.tag_configure('success', foreground='green')
        self.tree.tag_configure('failure', foreground='red')
        self.tree.tag_configure('denied', foreground='orange')
        self.tree.tag_configure('critical', background='#ffebee')
        self.tree.tag_configure('error', background='#fff3e0')

        # Bind double-click
        self.tree.bind('<Double-Button-1>', self._show_details)

        # Status bar
        self.status_label = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, padx=10, pady=5)

    def refresh_logs(self):
        """Actualiza la lista de logs"""
        try:
            # Limpiar tabla
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Obtener logs de la BD
            logs = self._get_logs_from_db()

            # Aplicar filtros
            filtered_logs = self._apply_filters(logs)

            # Agregar a la tabla
            for log in filtered_logs:
                # Determinar tags
                tags = []
                if log['status'] in ['success', 'failure', 'denied']:
                    tags.append(log['status'])
                if log['severity'] in ['critical', 'error']:
                    tags.append(log['severity'])

                # Formatear timestamp
                try:
                    dt = datetime.fromisoformat(log['timestamp'])
                    timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    timestamp_str = log['timestamp']

                # Íconos de severidad
                severity_icons = {
                    'critical': '🔴',
                    'error': '🟠',
                    'warning': '🟡',
                    'info': '🔵'
                }
                severity_display = f"{severity_icons.get(log['severity'], '')} {log['severity']}"

                self.tree.insert(
                    '',
                    'end',
                    values=(
                        timestamp_str,
                        log.get('user', 'N/A'),
                        log['action'],
                        log.get('resource_name', log.get('resource_type', 'N/A')),
                        log['status'],
                        severity_display,
                        log.get('ip_address', 'N/A')
                    ),
                    tags=tags
                )

            self.status_label.config(text=f"Showing {len(filtered_logs)} of {len(logs)} logs")

        except Exception as e:
            messagebox.showerror("Error", f"Error loading logs: {str(e)}")

    def _apply_filters(self, logs):
        """Aplica los filtros seleccionados"""
        filtered = logs

        # Filtro de acción
        action = self.action_filter.get()
        if action != "All":
            filtered = [log for log in filtered if log['action'] == action]

        # Filtro de estado
        status = self.status_filter.get()
        if status != "All":
            filtered = [log for log in filtered if log['status'] == status]

        # Filtro de severidad
        severity = self.severity_filter.get()
        if severity != "All":
            filtered = [log for log in filtered if log['severity'] == severity]

        # Filtro de tiempo
        timerange = self.timerange_filter.get()
        if timerange != "All Time":
            now = datetime.now()
            if timerange == "Last Hour":
                cutoff = now - timedelta(hours=1)
            elif timerange == "Last 24 Hours":
                cutoff = now - timedelta(days=1)
            elif timerange == "Last 7 Days":
                cutoff = now - timedelta(days=7)
            elif timerange == "Last 30 Days":
                cutoff = now - timedelta(days=30)

            filtered = [
                log for log in filtered
                if datetime.fromisoformat(log['timestamp']) >= cutoff
            ]

        # Filtro de búsqueda
        search_term = self.search_var.get().lower()
        if search_term:
            filtered = [
                log for log in filtered
                if search_term in log['action'].lower() or
                   search_term in log.get('user', '').lower() or
                   search_term in log.get('resource_name', '').lower()
            ]

        return filtered

    def _get_logs_from_db(self):
        """Obtiene logs de la base de datos"""
        # Mock data - en producción obtener de BD
        now = datetime.now()
        return [
            {
                'timestamp': (now - timedelta(minutes=5)).isoformat(),
                'user': 'john.doe',
                'action': 'file.decrypt',
                'resource_type': 'file',
                'resource_name': 'document.pdf',
                'status': 'success',
                'severity': 'info',
                'ip_address': '192.168.1.100'
            },
            {
                'timestamp': (now - timedelta(minutes=10)).isoformat(),
                'user': 'admin',
                'action': 'user.create',
                'resource_type': 'user',
                'resource_name': 'jane.smith',
                'status': 'success',
                'severity': 'info',
                'ip_address': '192.168.1.1'
            },
            {
                'timestamp': (now - timedelta(minutes=15)).isoformat(),
                'user': 'unknown',
                'action': 'auth.failed_login',
                'resource_type': None,
                'resource_name': None,
                'status': 'failure',
                'severity': 'warning',
                'ip_address': '192.168.1.50'
            },
            {
                'timestamp': (now - timedelta(hours=1)).isoformat(),
                'user': 'bob.wilson',
                'action': 'file.access_denied',
                'resource_type': 'file',
                'resource_name': 'confidential.docx',
                'status': 'denied',
                'severity': 'warning',
                'ip_address': '192.168.1.102'
            }
        ]

    def _show_details(self, event=None):
        """Muestra detalles del log seleccionado"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        values = item['values']

        # Crear ventana de detalles
        details_window = tk.Toplevel(self)
        details_window.title("Log Details")
        details_window.geometry("500x400")

        text = tk.Text(details_window, wrap=tk.WORD, padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True)

        details = f"""
Timestamp: {values[0]}
User: {values[1]}
Action: {values[2]}
Resource: {values[3]}
Status: {values[4]}
Severity: {values[5]}
IP Address: {values[6]}
        """.strip()

        text.insert('1.0', details)
        text.config(state='disabled')

    def clear_filters(self):
        """Limpia todos los filtros"""
        self.action_filter.set("All")
        self.status_filter.set("All")
        self.severity_filter.set("All")
        self.timerange_filter.set("Last 24 Hours")
        self.search_var.set("")
        self.refresh_logs()

    def export_logs(self):
        """Exporta logs a archivo CSV"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if filename:
            try:
                import csv

                # Obtener datos visibles
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)

                    # Header
                    writer.writerow(['Timestamp', 'User', 'Action', 'Resource', 'Status', 'Severity', 'IP Address'])

                    # Datos
                    for item in self.tree.get_children():
                        values = self.tree.item(item)['values']
                        writer.writerow(values)

                messagebox.showinfo("Success", f"Logs exported to:\n{filename}")

            except Exception as e:
                messagebox.showerror("Error", f"Error exporting logs: {str(e)}")
