import requests
from datetime import datetime
from config import SERVER_ENDPOINT

def log_access(ip, status):
    data = {
        "ip": ip,
        "status": status,
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        requests.post(SERVER_ENDPOINT, json=data)
    except Exception as e:
        print(f"Error enviando log al servidor: {e}")
