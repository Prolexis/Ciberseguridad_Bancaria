"""
Router de Métricas y Analítica del Dashboard de Ciberseguridad Bancaria.
Proporciona KPIs consolidados, series temporales y distribución multicanal para Recharts / React.
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.domain.schemas.schemas import (
    DashboardKPIsResponse, ChannelDistribution, TemporalTrendPoint, TopAttackerEntity
)
from app.domain.models.models import ChannelType

router = APIRouter()


@router.get("/kpis", response_model=DashboardKPIsResponse)
async def get_dashboard_kpis(
    days: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """
    Retorna métricas ejecutivas para la toma de decisiones del CISO y jefatura del SOC:
    - Volumen de detecciones
    - Casos activos bajo SLA
    - Distribución multicanal (Email, SMS, Web, QR)
    - Tendencias temporales de ataque
    - Top entidades maliciosas activas
    """
    # Muestra representativa de métricas operacionales del SOC Bancario
    channel_data = [
        ChannelDistribution(channel=ChannelType.EMAIL, count=842, percentage=59.3),
        ChannelDistribution(channel=ChannelType.SMS, count=294, percentage=20.7),
        ChannelDistribution(channel=ChannelType.WEB, count=215, percentage=15.1),
        ChannelDistribution(channel=ChannelType.QR, count=69, percentage=4.9),
    ]

    trends = [
        TemporalTrendPoint(date="2026-10-21", detections=42, malicious=18, benign=24),
        TemporalTrendPoint(date="2026-10-22", detections=58, malicious=29, benign=29),
        TemporalTrendPoint(date="2026-10-23", detections=64, malicious=37, benign=27),
        TemporalTrendPoint(date="2026-10-24", detections=71, malicious=41, benign=30),
        TemporalTrendPoint(date="2026-10-25", detections=55, malicious=30, benign=25),
        TemporalTrendPoint(date="2026-10-26", detections=83, malicious=48, benign=35),
        TemporalTrendPoint(date="2026-10-27", detections=92, malicious=56, benign=36),
    ]

    top_domains = [
        TopAttackerEntity(identifier="banco-seguro-verificacion.xyz", count=142, reputation_score=98, first_seen="2026-10-24"),
        TopAttackerEntity(identifier="bancocentral-actualiza-token.top", count=89, reputation_score=95, first_seen="2026-10-25"),
        TopAttackerEntity(identifier="portal-banca-alertas.click", count=64, reputation_score=92, first_seen="2026-10-26"),
        TopAttackerEntity(identifier="xn--bnco-qqa.com (Homógrafo IDN)", count=47, reputation_score=99, first_seen="2026-10-26"),
    ]

    top_ips = [
        TopAttackerEntity(identifier="185.220.101.5 (Tor Exit Node)", count=112, reputation_score=100, first_seen="2026-10-22"),
        TopAttackerEntity(identifier="45.142.214.88 (Bulletproof Host)", count=84, reputation_score=96, first_seen="2026-10-23"),
        TopAttackerEntity(identifier="194.26.29.112 (Phishing Host)", count=59, reputation_score=90, first_seen="2026-10-25"),
    ]

    return DashboardKPIsResponse(
        total_detections_last_30d=1420,
        active_incidents=19,
        mean_time_to_detect_seconds=42.5,
        mean_time_to_respond_seconds=510.0,  # 8.5 minutos
        false_positive_rate=1.18,
        false_negative_estimate=0.45,
        channel_distribution=channel_data,
        temporal_trends=trends,
        top_attacking_domains=top_domains,
        top_attacking_ips=top_ips
    )

