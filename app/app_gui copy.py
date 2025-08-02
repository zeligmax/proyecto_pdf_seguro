import tkinter as tk
from tkinter import filedialog, messagebox
from .pdf_utils import encrypt_pdf, decrypt_pdf
from .config import FERNET_KEY
import os

class PDFSecureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("PDF Secure")

        self.file_path = ""
        self.output_path = ""
        self.authorized_ips = []

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Ruta del archivo PDF:").pack()

        self.entry = tk.Entry(self.master, width=60)
        self.entry.pack(pady=5)

        tk.Button(self.master, text="Seleccionar archivo", command=self.select_file).pack()

        tk.Label(self.master, text="IPs autorizadas (una por línea):").pack()
        self.ip_text = tk.Text(self.master, height=5, width=50)
        self.ip_text.pack(pady=5)

        tk.Button(self.master, text="Encriptar PDF", command=self.encrypt).pack(pady=5)
        tk.Button(self.master, text="Desencriptar PDF", command=self.decrypt).pack(pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Archivos PDF o ZIP", "*.pdf *.zip")])
        if file_path:
            self.file_path = file_path
            self.entry.delete(0, tk.END)
            self.entry.insert(0, file_path)

    def encrypt(self):
        if not self.file_path.lower().endswith('.pdf'):
            messagebox.showerror("Error", "Selecciona un archivo PDF para encriptar.")
            return

        # Obtener IPs de la caja de texto
        self.authorized_ips = [ip.strip() for ip in self.ip_text.get("1.0", tk.END).splitlines() if ip.strip()]

        if not self.authorized_ips:
            messagebox.showerror("Error", "Debes añadir al menos una IP autorizada.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Archivo ZIP", "*.zip")])
        if not output_path:
            return

        try:
            encrypt_pdf(self.file_path, output_path, FERNET_KEY, self.authorized_ips)
            messagebox.showinfo("Éxito", "PDF encriptado con IPs autorizadas.")
        except Exception as e:
            messagebox.showerror("Error", f"Falló la encriptación: {e}")

    def decrypt(self):
        if not self.file_path.lower().endswith('.zip'):
            messagebox.showerror("Error", "Selecciona un archivo ZIP generado por la app.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not output_path:
            return

        try:
            success = decrypt_pdf(self.file_path, output_path, FERNET_KEY)
            if success:
                messagebox.showinfo("Éxito", "PDF desencriptado correctamente.")
            else:
                messagebox.showwarning("Acceso denegado", "Tu IP no está autorizada para este documento.")
        except Exception as e:
            messagebox.showerror("Error", f"Falló la desencriptación: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFSecureApp(root)
    root.mainloop()
