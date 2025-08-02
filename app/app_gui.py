import tkinter as tk
from tkinter import filedialog, messagebox
import os
from config import FERNET_KEY, WHITELISTED_IPS
from pdf_utils import encrypt_pdf, decrypt_pdf
from ip_check import get_ip

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.py")

class PDFProtectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Protector")
        self.selected_pdf = None

        # --- Widgets ---
        self.label = tk.Label(root, text="Archivo seleccionado: Ninguno")
        self.label.pack(pady=10)

        self.btn_select = tk.Button(root, text="Seleccionar PDF", command=self.select_pdf)
        self.btn_select.pack()

        self.btn_encrypt = tk.Button(root, text="Encriptar PDF", command=self.encrypt_selected_pdf)
        self.btn_encrypt.pack(pady=5)

        self.btn_decrypt = tk.Button(root, text="Desencriptar y Leer PDF", command=self.decrypt_pdf_with_check)
        self.btn_decrypt.pack(pady=5)

        self.ip_label = tk.Label(root, text="Añadir IP a lista blanca:")
        self.ip_label.pack(pady=(20, 0))

        self.ip_entry = tk.Entry(root)
        self.ip_entry.pack()

        self.btn_add_ip = tk.Button(root, text="Añadir IP", command=self.add_ip_to_whitelist)
        self.btn_add_ip.pack(pady=5)

        self.whitelist_label = tk.Label(root, text="IPs autorizadas:")
        self.whitelist_label.pack(pady=(20, 0))

        self.whitelist_box = tk.Text(root, height=6, width=40)
        self.whitelist_box.pack()
        self.refresh_whitelist_display()

    def select_pdf(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.selected_pdf = file_path
            self.label.config(text=f"Archivo seleccionado: {os.path.basename(file_path)}")

    def encrypt_selected_pdf(self):
        if not self.selected_pdf:
            messagebox.showwarning("Advertencia", "Selecciona un archivo PDF primero.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not output_path:
            return

        encrypt_pdf(self.selected_pdf, output_path, FERNET_KEY)
        messagebox.showinfo("Éxito", f"Archivo encriptado guardado en: {output_path}")

    def decrypt_pdf_with_check(self):
        current_ip = get_ip()
        if current_ip not in WHITELISTED_IPS:
            messagebox.showerror("Acceso Denegado", f"Tu IP {current_ip} no está autorizada.")
            return

        file_path = filedialog.askopenfilename(title="Seleccionar PDF encriptado")
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], title="Guardar PDF desencriptado")
        if not output_path:
            return

        try:
            decrypt_pdf(file_path, output_path, FERNET_KEY)
            messagebox.showinfo("Éxito", f"Archivo desencriptado guardado en: {output_path}")
            os.startfile(output_path)
        except Exception as e:
            messagebox.showerror("Error", f"Fallo al desencriptar: {str(e)}")

    def add_ip_to_whitelist(self):
        new_ip = self.ip_entry.get().strip()
        if not new_ip:
            return
        if new_ip in WHITELISTED_IPS:
            messagebox.showinfo("Info", "La IP ya está en la lista blanca.")
            return

        try:
            with open(CONFIG_PATH, 'r') as file:
                lines = file.readlines()

            for i, line in enumerate(lines):
                if line.startswith("WHITELISTED_IPS"):
                    lines[i] = line.strip().rstrip("]") + f', "{new_ip}"]\n'

            with open(CONFIG_PATH, 'w') as file:
                file.writelines(lines)

            messagebox.showinfo("Éxito", f"IP {new_ip} añadida.")
            self.ip_entry.delete(0, tk.END)
            self.refresh_whitelist_display()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo modificar config.py: {str(e)}")

    def refresh_whitelist_display(self):
        self.whitelist_box.delete('1.0', tk.END)
        for ip in WHITELISTED_IPS:
            self.whitelist_box.insert(tk.END, f"{ip}\n")

if __name__ == '__main__':
    root = tk.Tk()
    app = PDFProtectorApp(root)
    root.mainloop()
