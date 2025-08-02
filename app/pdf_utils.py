import json
import zipfile
from cryptography.fernet import Fernet
from .ip_check import get_ip

def encrypt_pdf(input_path, output_zip_path, key, authorized_ips):
    """Cifra el PDF y guarda las IPs autorizadas en un archivo ZIP."""
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as f:
        encrypted_data = fernet.encrypt(f.read())

    metadata = {
        "authorized_ips": authorized_ips
    }

    with zipfile.ZipFile(output_zip_path, 'w') as zipf:
        zipf.writestr("document.encrypted", encrypted_data)
        zipf.writestr("metadata.json", json.dumps(metadata).encode())

def decrypt_pdf(input_zip_path, output_path, key):
    """Desencripta el PDF si la IP está autorizada."""
    fernet = Fernet(key)

    with zipfile.ZipFile(input_zip_path, 'r') as zipf:
        encrypted_data = zipf.read("document.encrypted")
        metadata = json.loads(zipf.read("metadata.json").decode())

    current_ip = get_ip()
    authorized_ips = metadata.get("authorized_ips", [])

    print(f"IP actual: {current_ip}")
    if current_ip not in authorized_ips:
        print("⚠️  IP no autorizada. Acceso denegado.")
        return False

    decrypted_data = fernet.decrypt(encrypted_data)
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print("✅ Archivo desencriptado exitosamente.")
    return True
