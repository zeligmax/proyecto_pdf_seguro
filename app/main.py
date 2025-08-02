import os
from pdf_utils import encrypt_pdf, decrypt_pdf
from ip_check import get_public_ip, is_ip_authorized
from server_client import log_access
from config import FERNET_KEY

def main():
    encrypted_file = "documento_encriptado.pdf"
    decrypted_file = "documento_descifrado_temp.pdf"

    ip = get_public_ip()
    print(f"IP detectada: {ip}")

    if not is_ip_authorized(ip):
        print("IP no autorizada. Eliminando archivo.")
        log_access(ip, "DENIED")
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        return
    else:
        print("IP autorizada. Acceso concedido.")
        log_access(ip, "AUTHORIZED")

    # Desencriptar y abrir el archivo (simulado)
    decrypt_pdf(encrypted_file, decrypted_file, FERNET_KEY)
    os.system(f'start {decrypted_file}')  # Windows only

if __name__ == "__main__":
    main()
