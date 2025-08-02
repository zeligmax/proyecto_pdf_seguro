import tkinter as tk
from tkinter import filedialog, messagebox
from .pdf_utils import encrypt_pdf, decrypt_pdf
from .ip_check import get_ip, is_ip_authorized
from .config import FERNET_KEY, WHITELISTED_IPS

class PDFSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Secure")
        self.root.geometry("400x300")

        self.label = tk.Label(root, text="Selecciona una acción:")
        self.label.pack(pady=10)

        self.encrypt_btn = tk.Button(root, text="Encriptar PDF", command=self.encrypt_pdf_ui)
        self.encrypt_btn.pack(pady=5)

        self.decrypt_btn = tk.Button(root, text="Desencriptar PDF", command=self.decrypt_pdf_ui)
        self.decrypt_btn.pack(pady=5)

        self.add_ip_btn = tk.Button(root, text="Añadir IP a lista blanca", command=self.add_ip_ui)
        self.add_ip_btn.pack(pady=5)

    def encrypt_pdf_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if not file_path:
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if not save_path:
            return

        encrypt_pdf(file_path, save_path, FERNET_KEY)
        messagebox.showinfo("Éxito", "PDF encriptado correctamente.")

    def decrypt_pdf_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not file_path:
            return

        current_ip = get_ip()
        if not is_ip_authorized(current_ip):
            messagebox.showerror("Acceso denegado", f"Tu IP ({current_ip}) no está autorizada.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if not save_path:
            return

        try:
            decrypt_pdf(file_path, save_path, FERNET_KEY)
            messagebox.showinfo("Éxito", "PDF desencriptado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desencriptar el archivo:\n{str(e)}")

    def add_ip_ui(self):
        current_ip = get_ip()
        if current_ip not in WHITELISTED_IPS:
            WHITELISTED_IPS.append(current_ip)
            with open("app/config.py", "r+", encoding="utf-8") as f:
                lines = f.readlines()
                f.seek(0)
                for line in lines:
                    if line.startswith("WHITELISTED_IPS"):
                        f.write(f"WHITELISTED_IPS = {repr(WHITELISTED_IPS)}\n")
                    else:
                        f.write(line)
            messagebox.showinfo("IP añadida", f"IP {current_ip} añadida a la lista blanca.")
        else:
            messagebox.showinfo("Ya autorizada", f"La IP {current_ip} ya está autorizada.")

def main():
    root = tk.Tk()
    app = PDFSecureApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
