#!/usr/bin/env python3
"""
database.py - Database Configuration for File Secure v3.2
PostgreSQL with SQLAlchemy ORM
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
import os
from contextlib import contextmanager

# Base para modelos
Base = declarative_base()

class DatabaseManager:
    """Gestor de conexiones a la base de datos"""

    def __init__(self, database_url=None):
        """
        Inicializa el gestor de base de datos

        Args:
            database_url: URL de conexión (ej: postgresql://user:pass@host/db)
                         Si es None, usa variable de entorno o SQLite local
        """
        if database_url is None:
            database_url = os.getenv(
                'DATABASE_URL',
                'sqlite:///~/.pdf_secure/filesecure_v3.db'  # Fallback a SQLite
            )

        # Expandir ~ en la ruta si es SQLite
        if database_url.startswith('sqlite:///~'):
            from pathlib import Path
            home = str(Path.home())
            database_url = database_url.replace('~', home)

            # Crear directorio si no existe
            db_path = Path(database_url.replace('sqlite:///', ''))
            db_path.parent.mkdir(parents=True, exist_ok=True)

        self.database_url = database_url
        self.is_sqlite = database_url.startswith('sqlite')

        # Configurar engine según el tipo de BD
        if self.is_sqlite:
            self.engine = create_engine(
                database_url,
                connect_args={'check_same_thread': False},
                echo=os.getenv('SQL_DEBUG', 'false').lower() == 'true'
            )
            # Habilitar foreign keys en SQLite
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        else:
            # PostgreSQL
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,  # Verificar conexiones antes de usar
                echo=os.getenv('SQL_DEBUG', 'false').lower() == 'true'
            )

        # Crear session factory
        self.SessionLocal = scoped_session(
            sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
        )

    def create_all_tables(self):
        """Crea todas las tablas en la base de datos"""
        Base.metadata.create_all(bind=self.engine)

    def drop_all_tables(self):
        """Elimina todas las tablas (¡CUIDADO!)"""
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def get_session(self):
        """
        Context manager para obtener una sesión de BD

        Usage:
            with db_manager.get_session() as session:
                user = session.query(User).first()
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_db(self):
        """
        Generator para dependency injection en FastAPI/Flask

        Usage:
            db = next(db_manager.get_db())
        """
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def health_check(self):
        """
        Verifica que la conexión a la BD esté funcionando

        Returns:
            dict: Estado de la conexión
        """
        try:
            with self.get_session() as session:
                session.execute("SELECT 1")
            return {
                'status': 'healthy',
                'database': self.database_url.split('@')[-1] if '@' in self.database_url else 'sqlite',
                'type': 'sqlite' if self.is_sqlite else 'postgresql'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }


# Instancia global (singleton)
_db_manager = None

def get_db_manager(database_url=None):
    """
    Obtiene o crea la instancia global del gestor de BD

    Args:
        database_url: URL de conexión (solo en primera llamada)

    Returns:
        DatabaseManager: Instancia del gestor
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(database_url)
    return _db_manager


def init_db(database_url=None):
    """
    Inicializa la base de datos y crea las tablas

    Args:
        database_url: URL de conexión
    """
    db_manager = get_db_manager(database_url)
    db_manager.create_all_tables()
    return db_manager


# Ejemplo de uso
if __name__ == "__main__":
    print("🗄️  File Secure v3.2 - Database Manager")
    print("=" * 60)

    # Inicializar con SQLite por defecto
    db_manager = init_db()

    # Health check
    status = db_manager.health_check()
    print(f"Database Status: {status}")
