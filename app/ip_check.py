import socket
import requests
from .config import WHITELISTED_IPS


def get_ip() -> str:
    """
    Obtiene la IP global, en un principio, de la máquina. Si no, la IP local.
    """
    try:
        response = requests.get("https://api.ipify.org?format=text", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException:
        # En caso de error, opcionalmente devuelve la IP local o None
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip

def is_ip_authorized(ip: str) -> bool:
    """
    Verifica si la IP está en la lista blanca.
    """
    return ip in WHITELISTED_IPS
