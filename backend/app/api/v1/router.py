"""
Agregador de Routers de la API v1 de AegisBank.
Cubre los 7 módulos obligatorios y los 12 módulos adicionales recomendados.
"""
from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, detection, incidents, dashboard, reports, ai, datasets, threat_intel
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Autenticación, RBAC y Auditoría Inmutable"])
api_router.include_router(detection.router, prefix="/detection", tags=["Detección Antifishing Multicanal"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Gestión de Incidentes y Casos SOC"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard y KPIs Analíticos"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reportes (PDF/DOCX/XLSX) y Programación"])
api_router.include_router(datasets.router, prefix="/datasets", tags=["Dataset Público y Pipeline ETL"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intel, IOCs, n8n y Concientización"])
api_router.include_router(ai.router, prefix="/ai", tags=["Inteligencia Artificial (LangChain / LangFlow)"])
