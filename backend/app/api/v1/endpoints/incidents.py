"""
Router de Gestión de Incidentes y Casos SOC.
Ciclo de vida: Triaje, asignación de analistas, contención y cierre con justificación auditable.
"""
import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.database import get_db
from app.domain.models.models import Incident, IncidentStatus, IncidentSeverity, ChannelType
from app.domain.schemas.schemas import IncidentResponse, IncidentDetailResponse, IncidentStatusUpdate

router = APIRouter()


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    channel: Optional[ChannelType] = None,
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """Lista incidentes registrados con filtros operacionales del SOC."""
    query = select(Incident).order_by(desc(Incident.created_at)).offset(offset).limit(limit)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if channel:
        query = query.where(Incident.channel == channel)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident_detail(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Obtiene el expediente forense completo de un incidente."""
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incidente no encontrado")

    return incident


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: uuid.UUID,
    update_data: IncidentStatusUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Transición de estado del incidente con registro de justificación técnica obligatoria."""
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incidente no encontrado")

    incident.status = update_data.status
    if update_data.status in [IncidentStatus.CLOSED_MALICIOUS, IncidentStatus.CLOSED_FALSE_POSITIVE]:
        incident.resolved_at = datetime.utcnow()
    elif incident.first_response_at is None:
        incident.first_response_at = datetime.utcnow()

    if update_data.assigned_analyst_id:
        incident.assigned_analyst_id = update_data.assigned_analyst_id

    await db.commit()
    await db.refresh(incident)
    return incident

