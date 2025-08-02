import json
import zipfile
from cryptography.fernet import Fernet
from .ip_check import get_ip

def encrypt_pdf(input_path: str, output_zip_path: str, key: bytes, authorized_ips: list):
    """
    Cifra el PDF y guarda el archivo cifrado junto con las IPs autorizadas dentro de un ZIP.
    """
    fernet = Fernet(key)
    with open(input_path, "rb") as f:
        pdf_bytes = f.read()

    encrypted_data = fernet.encrypt(pdf_bytes)

    metadata = {
        "authorized_ips": authorized_ips
    }

    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("document.encrypted", encrypted_data)
        zipf.writestr("metadata.json", json.dumps(metadata))

def decrypt_pdf(input_zip_path: str, output_path: str, key: bytes) -> bool:
    """
    Desencripta el PDF si la IP actual está autorizada.
    Retorna True si desencripta correctamente, False si la IP no está autorizada.
    """
    fernet = Fernet(key)

    with zipfile.ZipFile(input_zip_path, "r") as zipf:
        encrypted_data = zipf.read("document.encrypted")
        metadata_json = zipf.read("metadata.json").decode()
        metadata = json.loads(metadata_json)

    current_ip = get_ip()
    authorized_ips = metadata.get("authorized_ips", [])

    print(f"IP actual: {current_ip}")
    if current_ip not in authorized_ips:
        print("⚠️ IP no autorizada. Acceso denegado.")
        return False

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    print("✅ Archivo desencriptado exitosamente.")
    return True
