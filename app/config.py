#!/usr/bin/env python3
"""
config.py - Configuración Segura para PDF Secure v2.0

Este módulo maneja toda la configuración del sistema de forma segura:
- Clave maestra desde variables de entorno (no hardcodeada)
- Gestión de whitelist de IPs con metadatos en JSON
- Almacenamiento estructurado de datos de configuración
"""

import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime


class SecureConfig:
    """
    Clase para gestionar la configuración segura del sistema
    
    Almacena todos los datos de configuración en ~/.pdf_secure/
    y gestiona la clave maestra desde variables de entorno.
    """
    
    def __init__(self):
        """Inicializa la configuración y crea estructura de directorios"""
        # Directorio de configuración en home del usuario
        self.config_dir = Path.home() / '.pdf_secure'
        self.config_dir.mkdir(exist_ok=True)
        
        # Archivos de configuración
        self.whitelist_file = self.config_dir / 'ip_whitelist.json'
        self.user_keys_file = self.config_dir / 'user_keys.json'
        self.access_log_file = self.config_dir / 'access_log.json'
    
    def get_master_key(self):
        """
        Obtiene la clave maestra desde variable de entorno
        
        La clave NUNCA debe estar hardcodeada en el código.
        Debe configurarse como variable de entorno:
        export PDF_SECURE_MASTER_KEY='tu_clave_aqui'
        
        Returns:
            bytes: Clave maestra en formato bytes
            
        Raises:
            ValueError: Si la variable de entorno no está configurada
        """
        key = os.getenv('PDF_SECURE_MASTER_KEY')
        if not key:
            raise ValueError(
                "PDF_SECURE_MASTER_KEY no encontrada en variables de entorno.\n"
                "Para configurarla ejecuta:\n"
                "export PDF_SECURE_MASTER_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
            )
        return key.encode()
    
    def load_ip_whitelist(self):
        """
        Carga la whitelist de IPs con metadatos desde archivo JSON
        
        Returns:
            list: Lista de diccionarios con información de IPs
                  Cada entrada contiene: ip, description, added, access_count, etc.
        """
        if not self.whitelist_file.exists():
            return []
        
        try:
            with open(self.whitelist_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            # Si el archivo está corrupto, retornar lista vacía
            return []
    
    def save_ip_whitelist(self, whitelist):
        """
        Guarda la whitelist de IPs con timestamps actualizados
        
        Args:
            whitelist (list): Lista de entradas de IP con metadatos
        """
        # Agregar timestamp si no existe en las entradas
        for entry in whitelist:
            if 'timestamp' not in entry:
                entry['timestamp'] = datetime.now().isoformat()
        
        with open(self.whitelist_file, 'w') as f:
            json.dump(whitelist, f, indent=2)
    
    def add_ip_to_whitelist(self, ip, description=""):
        """
        Añade una IP a la whitelist con metadatos completos
        
        Si la IP ya existe, actualiza su descripción y timestamp.
        Si es nueva, la agrega con todos los metadatos inicializados.
        
        Args:
            ip (str): Dirección IP a agregar
            description (str): Descripción opcional de la IP
            
        Returns:
            bool: True si se agregó o actualizó correctamente
        """
        whitelist = self.load_ip_whitelist()
        
        # Verificar si la IP ya existe
        for entry in whitelist:
            if entry['ip'] == ip:
                # Actualizar entrada existente
                entry['last_updated'] = datetime.now().isoformat()
                if description:
                    entry['description'] = description
                self.save_ip_whitelist(whitelist)
                return True
        
        # Agregar nueva entrada con metadatos completos
        new_entry = {
            'ip': ip,
            'description': description,
            'added': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'access_count': 0,
            'last_access': None
        }
        
        whitelist.append(new_entry)
        self.save_ip_whitelist(whitelist)
        return True
    
    def remove_ip_from_whitelist(self, ip):
        """
        Elimina una IP de la whitelist
        
        Args:
            ip (str): Dirección IP a eliminar
            
        Returns:
            bool: True si se eliminó correctamente
        """
        whitelist = self.load_ip_whitelist()
        # Filtrar la lista excluyendo la IP especificada
        whitelist = [entry for entry in whitelist if entry['ip'] != ip]
        self.save_ip_whitelist(whitelist)
        return True
    
    def is_ip_whitelisted(self, ip):
        """
        Verifica si una IP está en la whitelist
        
        Args:
            ip (str): Dirección IP a verificar
            
        Returns:
            bool: True si la IP está autorizada
        """
        whitelist = self.load_ip_whitelist()
        return any(entry['ip'] == ip for entry in whitelist)
    
    def increment_ip_access_count(self, ip):
        """
        Incrementa el contador de accesos para una IP y actualiza timestamp
        
        Args:
            ip (str): Dirección IP cuyo contador se incrementará
        """
        whitelist = self.load_ip_whitelist()
        
        for entry in whitelist:
            if entry['ip'] == ip:
                # Incrementar contador y actualizar timestamp
                entry['access_count'] = entry.get('access_count', 0) + 1
                entry['last_access'] = datetime.now().isoformat()
                break
        
        self.save_ip_whitelist(whitelist)
    
    def get_ip_info(self, ip):
        """
        Obtiene información completa de una IP específica
        
        Args:
            ip (str): Dirección IP a consultar
            
        Returns:
            dict: Diccionario con toda la información de la IP, o None si no existe
        """
        whitelist = self.load_ip_whitelist()
        
        for entry in whitelist:
            if entry['ip'] == ip:
                return entry
        
        return None
    
    def cleanup_old_entries(self, days=90):
        """
        Limpia entradas de IPs que no han tenido acceso en X días
        
        Args:
            days (int): Número de días de inactividad para considerar limpieza
            
        Returns:
            int: Número de entradas eliminadas
        """
        from datetime import datetime, timedelta
        
        whitelist = self.load_ip_whitelist()
        cutoff_date = datetime.now() - timedelta(days=days)
        original_count = len(whitelist)
        
        # Filtrar solo las IPs que han tenido acceso reciente
        cleaned_whitelist = []
        for entry in whitelist:
            last_access = entry.get('last_access')
            
            if last_access:
                try:
                    access_date = datetime.fromisoformat(last_access)
                    if access_date >= cutoff_date:
                        cleaned_whitelist.append(entry)
                except ValueError:
                    # Si hay error en el formato, mantener la entrada
                    cleaned_whitelist.append(entry)
            else:
                # Si nunca ha tenido acceso, mantener la entrada
                cleaned_whitelist.append(entry)
        
        self.save_ip_whitelist(cleaned_whitelist)
        return original_count - len(cleaned_whitelist)
    
    def get_config_status(self):
        """
        Obtiene el estado actual de la configuración
        
        Returns:
            dict: Diccionario con información del estado del sistema
        """
        return {
            'config_dir': str(self.config_dir),
            'config_dir_exists': self.config_dir.exists(),
            'whitelist_file': str(self.whitelist_file),
            'whitelist_exists': self.whitelist_file.exists(),
            'user_keys_file': str(self.user_keys_file),
            'user_keys_exists': self.user_keys_file.exists(),
            'access_log_file': str(self.access_log_file),
            'access_log_exists': self.access_log_file.exists(),
            'master_key_configured': bool(os.getenv('PDF_SECURE_MASTER_KEY')),
            'total_ips': len(self.load_ip_whitelist())
        }


# Ejemplo de uso
if __name__ == "__main__":
    """
    Ejemplo de uso del módulo de configuración
    """
    try:
        config = SecureConfig()
        
        print("📁 Configuración de PDF Secure")
        print("=" * 50)
        
        status = config.get_config_status()
        
        print(f"📂 Directorio: {status['config_dir']}")
        print(f"✅ Existe: {status['config_dir_exists']}")
        print(f"🔑 Clave maestra: {'✅ Configurada' if status['master_key_configured'] else '❌ No configurada'}")
        print(f"🌐 IPs en whitelist: {status['total_ips']}")
        
        if not status['master_key_configured']:
            print("\n⚠️  Para configurar la clave maestra:")
            print("export PDF_SECURE_MASTER_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")