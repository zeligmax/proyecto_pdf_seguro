import tkinter as tk
from tkinter import filedialog, messagebox
from .pdf_utils import encrypt_pdf, decrypt_pdf
from .ip_check import get_ip, is_ip_authorized
from .config import FERNET_KEY, WHITELISTED_IPS
import re
import sys
import os
sys.path.append(os.path.dirname(__file__))

class PDFSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Secure")
        self.root.geometry("400x350")

        self.label = tk.Label(root, text="Selecciona una acción:")
        self.label.pack(pady=10)

        self.encrypt_btn = tk.Button(root, text="Encriptar PDF", command=self.encrypt_pdf_ui)
        self.encrypt_btn.pack(pady=5)

        self.decrypt_btn = tk.Button(root, text="Desencriptar PDF", command=self.decrypt_pdf_ui)
        self.decrypt_btn.pack(pady=5)

        self.add_ip_btn = tk.Button(root, text="Gestionar lista blanca de IPs", command=self.add_ip_ui)
        self.add_ip_btn.pack(pady=5)

    def actualizar_config_ips(self):
        try:
            with open("app/config.py", "r+", encoding="utf-8") as f:
                lines = f.readlines()
                f.seek(0)
                f.truncate()
                for line in lines:
                    if line.startswith("WHITELISTED_IPS"):
                        f.write(f"WHITELISTED_IPS = {repr(WHITELISTED_IPS)}\n")
                    else:
                        f.write(line)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo actualizar config.py:\n{str(e)}")

    def encrypt_pdf_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if not file_path:
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if not save_path:
            return

        # Forzar extensión .enc si no está presente
        if not save_path.lower().endswith(".enc"):
            save_path += ".enc"

        print(f"Guardando archivo en: {save_path}")  # Para depurar la ruta en consola
        encrypt_pdf(file_path, save_path, FERNET_KEY, WHITELISTED_IPS)
        messagebox.showinfo("Éxito", f"PDF encriptado correctamente y guardado en:\n{save_path}")

    def decrypt_pdf_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not file_path:
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if not save_path:
            return

        # Forzar extensión .pdf si no está presente
        if not save_path.lower().endswith(".pdf"):
            save_path += ".pdf"

        try:
            success = decrypt_pdf(file_path, save_path, FERNET_KEY)
            if success:
                messagebox.showinfo("Éxito", f"PDF desencriptado correctamente y guardado en:\n{save_path}")
            else:
                messagebox.showerror("Acceso denegado", "Tu IP no está autorizada para desencriptar este archivo.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desencriptar el archivo:\n{str(e)}")

    def add_ip_ui(self):
        def guardar_ip(ip):
            if ip in WHITELISTED_IPS:
                messagebox.showinfo("Ya autorizada", f"La IP {ip} ya está autorizada.")
                return
            if not self.validar_ip(ip):
                messagebox.showerror("IP inválida", f"La IP '{ip}' no tiene un formato válido.")
                return

            WHITELISTED_IPS.append(ip)
            self.actualizar_config_ips()
            messagebox.showinfo("IP añadida", f"La IP {ip} ha sido añadida a la lista blanca.")
            top.destroy()

        def eliminar_ip(ip):
            if ip in WHITELISTED_IPS:
                WHITELISTED_IPS.remove(ip)
                self.actualizar_config_ips()
                messagebox.showinfo("IP eliminada", f"La IP {ip} ha sido eliminada de la lista blanca.")
                top.destroy()

        top = tk.Toplevel(self.root)
        top.title("Gestionar IPs autorizadas")
        top.geometry("400x400")

        current_ip = get_ip()

        tk.Label(top, text=f"Tu IP actual es: {current_ip}").pack(pady=5)

        tk.Button(top, text="Añadir mi IP actual", command=lambda: guardar_ip(current_ip)).pack(pady=5)

        tk.Label(top, text="O introduce una IP manualmente:").pack(pady=5)
        ip_entry = tk.Entry(top)
        ip_entry.pack(pady=5)

        tk.Button(top, text="Añadir IP ingresada", command=lambda: guardar_ip(ip_entry.get())).pack(pady=5)

        tk.Label(top, text="IPs actualmente autorizadas:").pack(pady=10)

        if WHITELISTED_IPS:
            for ip in WHITELISTED_IPS:
                frame = tk.Frame(top)
                frame.pack(pady=2, fill="x", padx=20)
                tk.Label(frame, text=ip).pack(side="left")
                tk.Button(frame, text="Eliminar", command=lambda ip=ip: eliminar_ip(ip)).pack(side="right")
        else:
            tk.Label(top, text="(No hay IPs en la lista blanca)").pack()

    def validar_ip(self, ip):
        patron = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(patron, ip):
            return False
        return all(0 <= int(part) <= 255 for part in ip.split('.'))

def main():
    root = tk.Tk()
    app = PDFSecureApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
