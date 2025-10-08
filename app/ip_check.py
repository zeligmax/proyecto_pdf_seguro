import socket
import ipaddress
from datetime import datetime

class IPChecker:
    """Clase simplificada para verificación de IP local únicamente"""
    
    def __init__(self, config):
        self.config = config
    
    def get_local_ip(self):
        """
        Obtiene la IP local del sistema
        Solo se usa IP local para evitar problemas con IPs dinámicas/VPN
        """
        try:
            # Crear socket para obtener IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            
            # Conectar a una dirección remota para determinar la IP local
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            return local_ip
        except Exception:
            # Fallback a localhost si falla
            return '127.0.0.1'
    
    def get_network_info(self):
        """Obtiene información básica de la red local"""
        try:
            local_ip = self.get_local_ip()
            hostname = socket.gethostname()
            
            return {
                'local_ip': local_ip,
                'hostname': hostname,
                'timestamp': datetime.now().isoformat(),
                'is_localhost': local_ip in ['127.0.0.1', '::1'],
                'is_private': self._is_private_ip(local_ip)
            }
        except Exception as e:
            return {
                'local_ip': '127.0.0.1',
                'hostname': 'localhost',
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'is_localhost': True,
                'is_private': True
            }
    
    def _is_private_ip(self, ip):
        """Verifica si la IP es privada"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def is_ip_authorized(self, ip=None):
        """
        Verifica si la IP está autorizada según la whitelist
        
        Args:
            ip: IP a verificar (si no se proporciona, usa la IP local)
            
        Returns:
            tuple: (autorizada: bool, info: dict)
        """
        if ip is None:
            ip = self.get_local_ip()
        
        whitelist = self.config.load_ip_whitelist()
        
        # Si no hay whitelist configurada, permitir acceso
        if not whitelist:
            return True, {
                'status': 'allowed',
                'reason': 'No whitelist configured',
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }
        
        # Verificar si la IP está en la whitelist
        for entry in whitelist:
            if entry.get('ip') == ip:
                # Actualizar contador de acceso
                self.config.increment_ip_access_count(ip)
                
                return True, {
                    'status': 'whitelisted',
                    'reason': f"IP found in whitelist: {entry.get('description', 'No description')}",
                    'ip': ip,
                    'whitelist_entry': entry,
                    'timestamp': datetime.now().isoformat()
                }
        
        return False, {
            'status': 'blocked',
            'reason': 'IP not found in whitelist',
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }
    
    def validate_ip_format(self, ip):
        """Valida que el formato de IP sea correcto"""
        try:
            ipaddress.ip_address(ip)
            return True, "IP format is valid"
        except ValueError as e:
            return False, f"Invalid IP format: {str(e)}"
    
    def get_ip_subnet_info(self, ip):
        """Obtiene información sobre la subred de la IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Determinar red típica para IP privada
            if ip_obj.is_private:
                if ip.startswith('192.168.'):
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                elif ip.startswith('10.'):
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                elif ip.startswith('172.'):
                    # Verificar si está en rango 172.16-172.31
                    octets = ip.split('.')
                    if 16 <= int(octets[1]) <= 31:
                        network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    else:
                        network = None
                else:
                    network = None
            else:
                network = None
            
            return {
                'ip': str(ip_obj),
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'network': str(network) if network else 'Unknown',
                'version': ip_obj.version
            }
        
        except ValueError as e:
            return {
                'error': str(e),
                'ip': ip
            }
    
    def scan_local_network_ips(self):
        """
        Escanea IPs activas en la red local
        NOTA: Solo para uso administrativo, puede ser lento
        """
        local_ip = self.get_local_ip()
        
        if local_ip == '127.0.0.1':
            return [{'ip': '127.0.0.1', 'hostname': 'localhost', 'status': 'active'}]
        
        try:
            # Determinar red local
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            active_ips = []
            
            # Agregar la IP local primero
            active_ips.append({
                'ip': local_ip,
                'hostname': socket.gethostname(),
                'status': 'local'
            })
            
            # Nota: Escaneo completo puede ser lento, solo devolver IP local por defecto
            return active_ips
            
        except Exception as e:
            return [{
                'ip': local_ip,
                'hostname': 'localhost',
                'status': 'local',
                'error': str(e)
            }]