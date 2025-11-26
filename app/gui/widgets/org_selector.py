#!/usr/bin/env python3
"""
org_selector.py - Organization Selector Widget for File Secure v3.2
Dropdown to select organization and department
"""

import tkinter as tk
from tkinter import ttk


class OrganizationSelector(ttk.Frame):
    """
    Widget selector de organización y departamento
    """

    def __init__(self, parent, on_change_callback=None):
        """
        Inicializa el selector de organización

        Args:
            parent: Widget padre
            on_change_callback: Función a llamar cuando cambia la selección
        """
        super().__init__(parent)

        self.on_change_callback = on_change_callback
        self.organizations = []
        self.departments = []

        self._create_widgets()

    def _create_widgets(self):
        """Crea los widgets del selector"""

        # Frame para organización
        org_frame = ttk.LabelFrame(self, text="🏢 Organization", padding=10)
        org_frame.pack(fill=tk.X, padx=5, pady=5)

        # Selector de organización
        ttk.Label(org_frame, text="Organization:").pack(side=tk.LEFT, padx=5)
        self.org_var = tk.StringVar()
        self.org_combo = ttk.Combobox(
            org_frame,
            textvariable=self.org_var,
            state='readonly',
            width=30
        )
        self.org_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.org_combo.bind('<<ComboboxSelected>>', self._on_org_changed)

        # Frame para departamento
        dept_frame = ttk.LabelFrame(self, text="🏛️ Department", padding=10)
        dept_frame.pack(fill=tk.X, padx=5, pady=5)

        # Selector de departamento
        ttk.Label(dept_frame, text="Department:").pack(side=tk.LEFT, padx=5)
        self.dept_var = tk.StringVar()
        self.dept_combo = ttk.Combobox(
            dept_frame,
            textvariable=self.dept_var,
            state='readonly',
            width=30
        )
        self.dept_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.dept_combo.bind('<<ComboboxSelected>>', self._on_dept_changed)

        # Info label
        self.info_label = ttk.Label(self, text="", foreground="gray")
        self.info_label.pack(fill=tk.X, padx=10, pady=5)

    def _on_org_changed(self, event=None):
        """Callback cuando cambia la organización seleccionada"""
        org_name = self.org_var.get()

        # Actualizar info
        self.info_label.config(text=f"Selected: {org_name}")

        # Limpiar departamento
        self.dept_var.set('')
        self.dept_combo['values'] = []

        # Llamar callback si existe
        if self.on_change_callback:
            self.on_change_callback('organization', org_name)

    def _on_dept_changed(self, event=None):
        """Callback cuando cambia el departamento seleccionado"""
        dept_name = self.dept_var.get()
        org_name = self.org_var.get()

        # Actualizar info
        self.info_label.config(text=f"Selected: {org_name} / {dept_name}")

        # Llamar callback si existe
        if self.on_change_callback:
            self.on_change_callback('department', dept_name)

    def set_organizations(self, organizations):
        """
        Establece la lista de organizaciones disponibles

        Args:
            organizations: Lista de dicts con {id, name, display_name}
        """
        self.organizations = organizations
        org_names = [org['display_name'] for org in organizations]
        self.org_combo['values'] = org_names

        # Seleccionar primera si existe
        if org_names:
            self.org_var.set(org_names[0])
            self._on_org_changed()

    def set_departments(self, departments):
        """
        Establece la lista de departamentos disponibles

        Args:
            departments: Lista de dicts con {id, name, display_name}
        """
        self.departments = departments
        dept_names = [dept['display_name'] for dept in departments]
        self.dept_combo['values'] = dept_names

        # Seleccionar primera si existe
        if dept_names:
            self.dept_var.set(dept_names[0])
            self._on_dept_changed()

    def get_selected_organization(self):
        """
        Obtiene la organización seleccionada

        Returns:
            dict: Organización seleccionada o None
        """
        org_name = self.org_var.get()
        for org in self.organizations:
            if org['display_name'] == org_name:
                return org
        return None

    def get_selected_department(self):
        """
        Obtiene el departamento seleccionado

        Returns:
            dict: Departamento seleccionado o None
        """
        dept_name = self.dept_var.get()
        for dept in self.departments:
            if dept['display_name'] == dept_name:
                return dept
        return None


# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Organization Selector Demo")
    root.geometry("500x300")

    def on_change(selector_type, value):
        print(f"{selector_type} changed to: {value}")

    selector = OrganizationSelector(root, on_change_callback=on_change)
    selector.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Mock data
    selector.set_organizations([
        {'id': '1', 'name': 'finance', 'display_name': 'Finance Department'},
        {'id': '2', 'name': 'hr', 'display_name': 'Human Resources'},
        {'id': '3', 'name': 'it', 'display_name': 'IT Department'}
    ])

    selector.set_departments([
        {'id': '1', 'name': 'accounting', 'display_name': 'Accounting'},
        {'id': '2', 'name': 'payroll', 'display_name': 'Payroll'},
        {'id': '3', 'name': 'treasury', 'display_name': 'Treasury'}
    ])

    root.mainloop()
