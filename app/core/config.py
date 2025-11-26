#!/usr/bin/env python3
"""
config.py - Enhanced Configuration for File Secure v3.2
Supports YAML configs, environment variables, and policies
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from cryptography.fernet import Fernet


@dataclass
class DatabaseConfig:
    """Configuración de base de datos"""
    url: str = "sqlite:///~/.pdf_secure/filesecure_v3.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


@dataclass
class RedisConfig:
    """Configuración de Redis (opcional)"""
    enabled: bool = False
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None


@dataclass
class SecurityConfig:
    """Configuración de seguridad"""
    secret_key: str = field(default_factory=lambda: Fernet.generate_key().decode())
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60
    password_min_length: int = 12
    max_failed_attempts: int = 3
    lockout_duration_minutes: int = 30
    require_mfa: bool = False


@dataclass
class PolicyConfig:
    """Configuración de políticas"""
    max_file_size_mb: int = 100
    allowed_extensions: list = field(default_factory=lambda: [".pdf", ".docx", ".xlsx", ".txt", ".pbip", ".pbix"])
    retention_days: int = 365
    key_rotation_days: int = 90
    session_timeout_minutes: int = 30


@dataclass
class AuditConfig:
    """Configuración de auditoría"""
    enabled: bool = True
    log_retention_days: int = 730
    elasticsearch_enabled: bool = False
    elasticsearch_url: Optional[str] = None


@dataclass
class AppConfig:
    """Configuración principal de la aplicación"""
    app_name: str = "File Secure"
    version: str = "3.2"
    debug: bool = False
    config_dir: Path = field(default_factory=lambda: Path.home() / '.pdf_secure')

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


class ConfigManager:
    """Gestor de configuración con soporte para YAML y variables de entorno"""

    def __init__(self, config_file: Optional[str] = None, env_prefix: str = "FILESECURE_"):
        """
        Inicializa el gestor de configuración

        Args:
            config_file: Ruta al archivo YAML de configuración
            env_prefix: Prefijo para variables de entorno
        """
        self.env_prefix = env_prefix
        self.config = AppConfig()

        # Crear directorio de configuración
        self.config.config_dir.mkdir(parents=True, exist_ok=True)

        # Cargar desde archivo YAML si existe
        if config_file and Path(config_file).exists():
            self.load_from_yaml(config_file)

        # Sobreescribir con variables de entorno
        self.load_from_env()

    def load_from_yaml(self, config_file: str):
        """Carga configuración desde archivo YAML"""
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f)

        if not data:
            return

        # Database
        if 'database' in data:
            db_cfg = data['database']
            self.config.database.url = db_cfg.get('url', self.config.database.url)
            self.config.database.pool_size = db_cfg.get('pool_size', self.config.database.pool_size)
            self.config.database.max_overflow = db_cfg.get('max_overflow', self.config.database.max_overflow)
            self.config.database.echo = db_cfg.get('echo', self.config.database.echo)

        # Redis
        if 'redis' in data:
            redis_cfg = data['redis']
            self.config.redis.enabled = redis_cfg.get('enabled', self.config.redis.enabled)
            self.config.redis.host = redis_cfg.get('host', self.config.redis.host)
            self.config.redis.port = redis_cfg.get('port', self.config.redis.port)
            self.config.redis.db = redis_cfg.get('db', self.config.redis.db)
            self.config.redis.password = redis_cfg.get('password', self.config.redis.password)

        # Security
        if 'security' in data:
            sec_cfg = data['security']
            self.config.security.jwt_expiration_minutes = sec_cfg.get('jwt_expiration_minutes', self.config.security.jwt_expiration_minutes)
            self.config.security.password_min_length = sec_cfg.get('password_min_length', self.config.security.password_min_length)
            self.config.security.max_failed_attempts = sec_cfg.get('max_failed_attempts', self.config.security.max_failed_attempts)
            self.config.security.lockout_duration_minutes = sec_cfg.get('lockout_duration_minutes', self.config.security.lockout_duration_minutes)
            self.config.security.require_mfa = sec_cfg.get('require_mfa', self.config.security.require_mfa)

        # Policy
        if 'policy' in data:
            pol_cfg = data['policy']
            self.config.policy.max_file_size_mb = pol_cfg.get('max_file_size_mb', self.config.policy.max_file_size_mb)
            self.config.policy.allowed_extensions = pol_cfg.get('allowed_extensions', self.config.policy.allowed_extensions)
            self.config.policy.retention_days = pol_cfg.get('retention_days', self.config.policy.retention_days)
            self.config.policy.key_rotation_days = pol_cfg.get('key_rotation_days', self.config.policy.key_rotation_days)
            self.config.policy.session_timeout_minutes = pol_cfg.get('session_timeout_minutes', self.config.policy.session_timeout_minutes)

        # Audit
        if 'audit' in data:
            audit_cfg = data['audit']
            self.config.audit.enabled = audit_cfg.get('enabled', self.config.audit.enabled)
            self.config.audit.log_retention_days = audit_cfg.get('log_retention_days', self.config.audit.log_retention_days)
            self.config.audit.elasticsearch_enabled = audit_cfg.get('elasticsearch_enabled', self.config.audit.elasticsearch_enabled)
            self.config.audit.elasticsearch_url = audit_cfg.get('elasticsearch_url', self.config.audit.elasticsearch_url)

    def load_from_env(self):
        """Carga configuración desde variables de entorno"""
        # Database
        if db_url := os.getenv(f"{self.env_prefix}DATABASE_URL"):
            self.config.database.url = db_url

        # Security
        if secret_key := os.getenv(f"{self.env_prefix}SECRET_KEY"):
            self.config.security.secret_key = secret_key

        if master_key := os.getenv('PDF_SECURE_MASTER_KEY'):
            # Mantener compatibilidad con v3.1
            self.config.security.secret_key = master_key

        # Debug mode
        if debug := os.getenv(f"{self.env_prefix}DEBUG"):
            self.config.debug = debug.lower() in ('true', '1', 'yes')

    def get_master_key(self) -> bytes:
        """
        Obtiene la clave maestra para cifrado

        Returns:
            bytes: Clave maestra
        """
        key = self.config.security.secret_key
        if isinstance(key, str):
            return key.encode()
        return key

    def save_to_yaml(self, output_file: str):
        """Guarda la configuración actual a un archivo YAML"""
        data = {
            'database': {
                'url': self.config.database.url,
                'pool_size': self.config.database.pool_size,
                'max_overflow': self.config.database.max_overflow,
                'echo': self.config.database.echo
            },
            'redis': {
                'enabled': self.config.redis.enabled,
                'host': self.config.redis.host,
                'port': self.config.redis.port,
                'db': self.config.redis.db
            },
            'security': {
                'jwt_expiration_minutes': self.config.security.jwt_expiration_minutes,
                'password_min_length': self.config.security.password_min_length,
                'max_failed_attempts': self.config.security.max_failed_attempts,
                'lockout_duration_minutes': self.config.security.lockout_duration_minutes,
                'require_mfa': self.config.security.require_mfa
            },
            'policy': {
                'max_file_size_mb': self.config.policy.max_file_size_mb,
                'allowed_extensions': self.config.policy.allowed_extensions,
                'retention_days': self.config.policy.retention_days,
                'key_rotation_days': self.config.policy.key_rotation_days,
                'session_timeout_minutes': self.config.policy.session_timeout_minutes
            },
            'audit': {
                'enabled': self.config.audit.enabled,
                'log_retention_days': self.config.audit.log_retention_days,
                'elasticsearch_enabled': self.config.audit.elasticsearch_enabled,
                'elasticsearch_url': self.config.audit.elasticsearch_url
            }
        }

        with open(output_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, indent=2)


# Instancia global
_config_manager = None

def get_config_manager(config_file: Optional[str] = None) -> ConfigManager:
    """Obtiene la instancia global del gestor de configuración"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
    return _config_manager


# Ejemplo de uso
if __name__ == "__main__":
    config = get_config_manager()
    print(f"App: {config.config.app_name} v{config.config.version}")
    print(f"Database: {config.config.database.url}")
    print(f"Debug: {config.config.debug}")
