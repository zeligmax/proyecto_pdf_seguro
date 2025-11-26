#!/usr/bin/env python3
"""
audit_service.py - Audit Service for File Secure v3.2
Centralized audit logging and reporting
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from app.models import AuditLog, User, Organization


class AuditService:
    """
    Servicio de auditoría centralizado
    """

    def __init__(self, db_session: Session):
        """
        Inicializa el servicio de auditoría

        Args:
            db_session: Sesión de base de datos SQLAlchemy
        """
        self.db = db_session

    def log(self, action: str, user_id: str = None, organization_id: str = None,
            department_id: str = None, resource_type: str = None, resource_id: str = None,
            resource_name: str = None, status: str = "success", severity: str = "info",
            ip_address: str = None, user_agent: str = None, metadata: Dict[str, Any] = None,
            error_message: str = None) -> AuditLog:
        """
        Crea un registro de auditoría

        Args:
            action: Acción realizada
            user_id: ID del usuario
            organization_id: ID de la organización
            department_id: ID del departamento
            resource_type: Tipo de recurso
            resource_id: ID del recurso
            resource_name: Nombre del recurso
            status: Estado (success, failure, denied)
            severity: Severidad (info, warning, error, critical)
            ip_address: Dirección IP
            user_agent: User agent
            metadata: Metadatos adicionales
            error_message: Mensaje de error

        Returns:
            AuditLog: Registro creado
        """
        return AuditLog.log_action(
            self.db,
            action=action,
            user_id=user_id,
            organization_id=organization_id,
            department_id=department_id,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            status=status,
            severity=severity,
            ip_address=ip_address,
            metadata=metadata,
            error_message=error_message
        )

    def get_logs(self, organization_id: str = None, user_id: str = None,
                 action: str = None, resource_type: str = None, status: str = None,
                 severity: str = None, start_date: datetime = None, end_date: datetime = None,
                 limit: int = 100, offset: int = 0) -> List[dict]:
        """
        Obtiene registros de auditoría con filtros

        Args:
            organization_id: Filtrar por organización
            user_id: Filtrar por usuario
            action: Filtrar por acción
            resource_type: Filtrar por tipo de recurso
            status: Filtrar por estado
            severity: Filtrar por severidad
            start_date: Fecha inicial
            end_date: Fecha final
            limit: Límite de resultados
            offset: Offset para paginación

        Returns:
            list: Lista de logs
        """
        query = self.db.query(AuditLog)

        # Aplicar filtros
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        if user_id:
            query = query.filter_by(user_id=user_id)
        if action:
            query = query.filter_by(action=action)
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        if status:
            query = query.filter_by(status=status)
        if severity:
            query = query.filter_by(severity=severity)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        # Ordenar por fecha descendente
        query = query.order_by(AuditLog.timestamp.desc())

        # Aplicar paginación
        query = query.limit(limit).offset(offset)

        return [log.to_dict() for log in query.all()]

    def get_user_activity(self, user_id: str, days: int = 30, limit: int = 100) -> List[dict]:
        """
        Obtiene la actividad de un usuario

        Args:
            user_id: ID del usuario
            days: Días hacia atrás
            limit: Límite de resultados

        Returns:
            list: Lista de actividades
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        return self.get_logs(
            user_id=user_id,
            start_date=start_date,
            limit=limit
        )

    def get_failed_login_attempts(self, organization_id: str = None, hours: int = 24) -> List[dict]:
        """
        Obtiene intentos de login fallidos

        Args:
            organization_id: ID de la organización (opcional)
            hours: Horas hacia atrás

        Returns:
            list: Lista de intentos fallidos
        """
        start_date = datetime.utcnow() - timedelta(hours=hours)

        return self.get_logs(
            organization_id=organization_id,
            action="auth.failed_login",
            status="failure",
            start_date=start_date,
            limit=1000
        )

    def get_critical_events(self, organization_id: str = None, days: int = 7) -> List[dict]:
        """
        Obtiene eventos críticos

        Args:
            organization_id: ID de la organización (opcional)
            days: Días hacia atrás

        Returns:
            list: Lista de eventos críticos
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        return self.get_logs(
            organization_id=organization_id,
            severity="critical",
            start_date=start_date,
            limit=1000
        )

    def get_access_denied_events(self, organization_id: str = None, days: int = 7) -> List[dict]:
        """
        Obtiene eventos de acceso denegado

        Args:
            organization_id: ID de la organización (opcional)
            days: Días hacia atrás

        Returns:
            list: Lista de accesos denegados
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        return self.get_logs(
            organization_id=organization_id,
            status="denied",
            start_date=start_date,
            limit=1000
        )

    def get_statistics(self, organization_id: str = None, days: int = 30) -> Dict[str, Any]:
        """
        Obtiene estadísticas de auditoría

        Args:
            organization_id: ID de la organización (opcional)
            days: Días hacia atrás

        Returns:
            dict: Estadísticas
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        query = self.db.query(AuditLog).filter(AuditLog.timestamp >= start_date)
        if organization_id:
            query = query.filter_by(organization_id=organization_id)

        # Total de eventos
        total_events = query.count()

        # Por estado
        success_count = query.filter_by(status="success").count()
        failure_count = query.filter_by(status="failure").count()
        denied_count = query.filter_by(status="denied").count()

        # Por severidad
        critical_count = query.filter_by(severity="critical").count()
        error_count = query.filter_by(severity="error").count()
        warning_count = query.filter_by(severity="warning").count()

        # Usuarios únicos
        unique_users = query.filter(AuditLog.user_id.isnot(None)).distinct(AuditLog.user_id).count()

        # Acciones más comunes
        top_actions = self.db.query(
            AuditLog.action,
            func.count(AuditLog.action).label('count')
        ).filter(AuditLog.timestamp >= start_date)

        if organization_id:
            top_actions = top_actions.filter_by(organization_id=organization_id)

        top_actions = top_actions.group_by(AuditLog.action).order_by(
            func.count(AuditLog.action).desc()
        ).limit(10).all()

        return {
            'period_days': days,
            'total_events': total_events,
            'by_status': {
                'success': success_count,
                'failure': failure_count,
                'denied': denied_count
            },
            'by_severity': {
                'critical': critical_count,
                'error': error_count,
                'warning': warning_count,
                'info': total_events - critical_count - error_count - warning_count
            },
            'unique_users': unique_users,
            'top_actions': [{'action': action, 'count': count} for action, count in top_actions]
        }

    def get_file_access_report(self, file_id: str) -> Dict[str, Any]:
        """
        Genera reporte de accesos a un archivo

        Args:
            file_id: ID del archivo

        Returns:
            dict: Reporte de accesos
        """
        logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.resource_type == "file",
                AuditLog.resource_id == file_id
            )
        ).order_by(AuditLog.timestamp.desc()).all()

        decrypt_count = sum(1 for log in logs if log.action == "file.decrypt")
        download_count = sum(1 for log in logs if log.action == "file.download")
        denied_count = sum(1 for log in logs if log.status == "denied")

        unique_users = set(log.user_id for log in logs if log.user_id)

        return {
            'file_id': file_id,
            'total_accesses': len(logs),
            'decrypt_count': decrypt_count,
            'download_count': download_count,
            'access_denied_count': denied_count,
            'unique_users_count': len(unique_users),
            'first_access': logs[-1].timestamp.isoformat() if logs else None,
            'last_access': logs[0].timestamp.isoformat() if logs else None,
            'recent_accesses': [log.to_dict() for log in logs[:10]]
        }

    def get_user_access_report(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """
        Genera reporte de actividad de un usuario

        Args:
            user_id: ID del usuario
            days: Días hacia atrás

        Returns:
            dict: Reporte de actividad
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= start_date
            )
        ).all()

        # Contar por acción
        action_counts = {}
        for log in logs:
            action_counts[log.action] = action_counts.get(log.action, 0) + 1

        # Files accedidos
        files_accessed = set(
            log.resource_id for log in logs
            if log.resource_type == "file" and log.action in ["file.decrypt", "file.download"]
        )

        # Intentos fallidos
        failed_attempts = sum(1 for log in logs if log.status == "failure")

        return {
            'user_id': user_id,
            'period_days': days,
            'total_actions': len(logs),
            'action_breakdown': action_counts,
            'files_accessed_count': len(files_accessed),
            'failed_attempts': failed_attempts,
            'last_activity': logs[0].timestamp.isoformat() if logs else None
        }

    def cleanup_old_logs(self, retention_days: int = 730) -> int:
        """
        Limpia logs antiguos según política de retención

        Args:
            retention_days: Días de retención

        Returns:
            int: Número de logs eliminados
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        # Contar logs a eliminar
        count = self.db.query(AuditLog).filter(AuditLog.timestamp < cutoff_date).count()

        # Eliminar
        self.db.query(AuditLog).filter(AuditLog.timestamp < cutoff_date).delete()
        self.db.commit()

        return count

    def export_logs(self, organization_id: str = None, start_date: datetime = None,
                   end_date: datetime = None, format: str = "json") -> Any:
        """
        Exporta logs en formato específico

        Args:
            organization_id: ID de la organización (opcional)
            start_date: Fecha inicial
            end_date: Fecha final
            format: Formato de exportación (json, csv)

        Returns:
            Any: Datos exportados según formato
        """
        logs = self.get_logs(
            organization_id=organization_id,
            start_date=start_date,
            end_date=end_date,
            limit=100000  # Sin límite real para exportación
        )

        if format == "json":
            return logs
        elif format == "csv":
            # Convertir a formato CSV
            import csv
            import io

            output = io.StringIO()
            if logs:
                fieldnames = logs[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(logs)

            return output.getvalue()

        return logs
