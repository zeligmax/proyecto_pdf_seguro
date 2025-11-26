#!/usr/bin/env python3
"""
dashboard.py - Executive Dashboard Widget for File Secure v3.2
Real-time metrics and statistics (Tkinter implementation)
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import random


class ExecutiveDashboard(ttk.Frame):
    """
    Dashboard ejecutivo con métricas en tiempo real
    """

    def __init__(self, parent, db_session, organization_id):
        super().__init__(parent)

        self.db = db_session
        self.organization_id = organization_id

        self._create_widgets()
        self.refresh_data()

    def _create_widgets(self):
        """Crea los widgets del dashboard"""

        # Header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(header, text="📊 Executive Dashboard", font=('Arial', 16, 'bold')).pack(side=tk.LEFT)

        refresh_btn = ttk.Button(header, text="🔄 Refresh", command=self.refresh_data)
        refresh_btn.pack(side=tk.RIGHT, padx=5)

        # KPIs Frame
        kpi_frame = ttk.Frame(self)
        kpi_frame.pack(fill=tk.X, padx=10, pady=10)

        # 4 KPI cards
        self.kpi_users = self._create_kpi_card(kpi_frame, "👥 Users", "0", "active users")
        self.kpi_users.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.kpi_files = self._create_kpi_card(kpi_frame, "📁 Files", "0", "encrypted files")
        self.kpi_files.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.kpi_accesses = self._create_kpi_card(kpi_frame, "🔓 Accesses", "0", "last 30 days")
        self.kpi_accesses.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.kpi_alerts = self._create_kpi_card(kpi_frame, "⚠️ Alerts", "0", "critical events")
        self.kpi_alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # Charts Frame (usando text para simular gráficos)
        charts_frame = ttk.LabelFrame(self, text="📈 Activity Trends (Last 7 Days)", padding=10)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Text-based chart
        self.chart_text = tk.Text(charts_frame, height=12, font=('Courier', 9), wrap=tk.NONE)
        self.chart_text.pack(fill=tk.BOTH, expand=True)

        # Recent Activity
        activity_frame = ttk.LabelFrame(self, text="🔔 Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollbar
        scrollbar = ttk.Scrollbar(activity_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Listbox para actividad reciente
        self.activity_listbox = tk.Listbox(
            activity_frame,
            font=('Courier', 9),
            yscrollcommand=scrollbar.set,
            height=8
        )
        self.activity_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.activity_listbox.yview)

        # Organization Stats
        org_frame = ttk.LabelFrame(self, text="🏢 Organization Overview", padding=10)
        org_frame.pack(fill=tk.X, padx=10, pady=10)

        self.org_stats_text = tk.Text(org_frame, height=4, font=('Arial', 9), wrap=tk.WORD)
        self.org_stats_text.pack(fill=tk.X)

    def _create_kpi_card(self, parent, title, value, subtitle):
        """Crea una tarjeta KPI"""
        card = ttk.Frame(parent, relief=tk.RAISED, borderwidth=2)

        # Title
        title_label = ttk.Label(card, text=title, font=('Arial', 10, 'bold'))
        title_label.pack(pady=(10, 5))

        # Value
        value_label = ttk.Label(card, text=value, font=('Arial', 24, 'bold'), foreground='#2563eb')
        value_label.pack()

        # Subtitle
        subtitle_label = ttk.Label(card, text=subtitle, font=('Arial', 8), foreground='gray')
        subtitle_label.pack(pady=(5, 10))

        # Guardar referencia al label de valor
        card.value_label = value_label

        return card

    def refresh_data(self):
        """Actualiza todos los datos del dashboard"""
        try:
            # Obtener estadísticas
            stats = self._get_statistics()

            # Actualizar KPIs
            self.kpi_users.value_label.config(text=str(stats['users']))
            self.kpi_files.value_label.config(text=str(stats['files']))
            self.kpi_accesses.value_label.config(text=str(stats['accesses']))
            self.kpi_alerts.value_label.config(text=str(stats['alerts']))

            # Actualizar gráfico de tendencias
            self._update_trend_chart(stats['daily_activity'])

            # Actualizar actividad reciente
            self._update_recent_activity(stats['recent_logs'])

            # Actualizar stats de organización
            self._update_org_stats(stats['org_info'])

        except Exception as e:
            print(f"Error refreshing dashboard: {e}")

    def _get_statistics(self):
        """Obtiene estadísticas de la base de datos"""
        # Mock data - en producción, obtener de la BD
        return {
            'users': 127,
            'files': 1543,
            'accesses': 8234,
            'alerts': 3,
            'daily_activity': [45, 67, 52, 89, 76, 94, 88],  # Últimos 7 días
            'recent_logs': [
                {'time': '10:30', 'user': 'john.doe', 'action': 'File decrypted', 'status': 'success'},
                {'time': '10:25', 'user': 'jane.smith', 'action': 'User logged in', 'status': 'success'},
                {'time': '10:20', 'user': 'admin', 'action': 'Policy updated', 'status': 'success'},
                {'time': '10:15', 'user': 'bob.wilson', 'action': 'Failed login attempt', 'status': 'failure'},
                {'time': '10:10', 'user': 'alice.jones', 'action': 'File encrypted', 'status': 'success'},
            ],
            'org_info': {
                'name': 'Default Organization',
                'departments': 5,
                'active_users': 98,
                'inactive_users': 29
            }
        }

    def _update_trend_chart(self, daily_data):
        """Actualiza el gráfico de tendencias (text-based)"""
        self.chart_text.delete('1.0', tk.END)

        if not daily_data:
            self.chart_text.insert('1.0', "No data available")
            return

        max_val = max(daily_data) if daily_data else 1
        height = 10

        # Días de la semana
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        today_idx = datetime.now().weekday()

        # Calcular días
        chart_days = []
        for i in range(7):
            day_idx = (today_idx - 6 + i) % 7
            chart_days.append(days[day_idx])

        # Dibujar gráfico de barras ASCII
        chart_lines = []
        for level in range(height, 0, -1):
            line = f"{level * 10:3d} |"
            for value in daily_data:
                bar_height = int((value / max_val) * height)
                if bar_height >= level:
                    line += "  ███"
                else:
                    line += "     "
            chart_lines.append(line)

        # Línea de separación
        chart_lines.append("    +" + "-" * (len(daily_data) * 5))

        # Labels de días
        day_line = "      "
        for day in chart_days:
            day_line += f" {day} "
        chart_lines.append(day_line)

        # Mostrar
        chart_text = "\n".join(chart_lines)
        self.chart_text.insert('1.0', chart_text)

    def _update_recent_activity(self, logs):
        """Actualiza la lista de actividad reciente"""
        self.activity_listbox.delete(0, tk.END)

        for log in logs:
            status_icon = "✅" if log['status'] == 'success' else "❌"
            line = f"{log['time']} {status_icon} {log['user']:15} {log['action']}"
            self.activity_listbox.insert(tk.END, line)

    def _update_org_stats(self, org_info):
        """Actualiza las estadísticas de organización"""
        self.org_stats_text.delete('1.0', tk.END)

        text = f"""
Organization: {org_info['name']}
Departments: {org_info['departments']} | Active Users: {org_info['active_users']} | Inactive: {org_info['inactive_users']}
Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """.strip()

        self.org_stats_text.insert('1.0', text)
        self.org_stats_text.config(state='disabled')


# Demo
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Executive Dashboard Demo")
    root.geometry("900x700")

    dashboard = ExecutiveDashboard(root, None, "org_1")
    dashboard.pack(fill=tk.BOTH, expand=True)

    root.mainloop()
