import os
from .config import FERNET_KEY
from .pdf_utils import encrypt_pdf, decrypt_pdf
from .ip_check import get_ip


def main():
    print("=== PDF Secure CLI ===")
    print("1. Encriptar PDF")
    print("2. Desencriptar ZIP")
    choice = input("Elige una opción (1/2): ")

    if choice == "1":
        input_pdf = input("Ruta al archivo PDF: ").strip()
        output_zip = input("Ruta de salida (.zip): ").strip()
        ips = input("Introduce IPs autorizadas (separadas por comas): ").split(",")
        ips = [ip.strip() for ip in ips if ip.strip()]
        
        encrypt_pdf(input_pdf, output_zip, FERNET_KEY, ips)
        print("✅ PDF encriptado exitosamente con IPs permitidas.")

    elif choice == "2":
        input_zip = input("Ruta al archivo .zip cifrado: ").strip()
        output_pdf = input("Ruta de salida del PDF descifrado: ").strip()

        success = decrypt_pdf(input_zip, output_pdf, FERNET_KEY)
        if success:
            print("✅ Desencriptado correcto.")
        else:
            print("❌ Acceso denegado. Tu IP no está autorizada.")

    else:
        print("❌ Opción inválida.")

if __name__ == "__main__":
    main()
