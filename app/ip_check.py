import requests
from config import WHITELISTED_IPS

def get_public_ip():
    return requests.get("https://api.ipify.org").text

def is_ip_authorized(ip):
    return ip in WHITELISTED_IPS

def get_ip():
    try:
        response = requests.get("https://api.ipify.org?format=text", timeout=5)
        return response.text.strip()
    except Exception as e:
        print(f"Error obteniendo IP: {e}")
        return "0.0.0.0"