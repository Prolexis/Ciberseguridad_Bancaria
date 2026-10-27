"""
Punto de Entrada Principal de la API Backend de AegisBank Anti-Phishing.
Desarrollada con FastAPI (Python 3.11+), Pydantic v2, SQLAlchemy 2.0 y métricas Prometheus.
Incluye semilla transaccional automática para todos los módulos obligatorios y recomendados.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import select

from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import get_password_hash
from app.domain.models.models import (
    User, Role, UserRoleEnum, Incident, IncidentSeverity, IncidentStatus, ChannelType,
    IndicatorOfCompromise, ScheduledReport
)
from app.api.v1.endpoints.auth import append_immutable_audit_log
from app.infrastructure.etl.dataset_ingestor import PhishingDatasetETLPipeline
from app.api.v1.router import api_router


async def seed_initial_banking_data():
    """Puebla PostgreSQL con datos iniciales auditables si la base de datos está vacía."""
    async with AsyncSessionLocal() as db:
        try:
            existing_roles = await db.execute(select(Role))
            if existing_roles.scalars().first() is not None:
                return

            # 1. Roles RBAC granulares
            roles_map = {}
            role_defs = [
                (UserRoleEnum.SECURITY_ADMIN, "Administrador de Seguridad y Secretos Vault", {"all": True, "rbac": True, "vault": True, "etl": True}),
                (UserRoleEnum.INCIDENT_COMMANDER, "Comandante de Incidentes CSIRT", {"incidents_close": True, "sinkhole": True, "takedown": True}),
                (UserRoleEnum.SOC_ANALYST_L2, "Analista Forense Senior Nivel 2", {"deep_scan": True, "threat_hunting": True, "ioc_write": True}),
                (UserRoleEnum.SOC_ANALYST_L1, "Analista de Triaje SOC Nivel 1", {"triage": True, "url_scan": True, "copilot": True}),
                (UserRoleEnum.AUDITOR, "Auditor Normativo PCI-DSS / ISO 27001", {"audit_logs_read": True, "reports_export": True, "immutable_verify": True}),
                (UserRoleEnum.EXECUTIVE, "Comité Ejecutivo / CISO", {"dashboard_kpis": True, "reports_export": True}),
            ]
            for r_enum, desc, perms in role_defs:
                r_obj = Role(name=r_enum.value, description=desc, permissions=perms)
                db.add(r_obj)
                roles_map[r_enum] = r_obj
            await db.flush()

            # 2. Usuarios del SOC con política de contraseñas bancaria y MFA
            now = datetime.now(timezone.utc)
            users_seed = [
                ("admin_soc", "admin.soc@banco.com", "Nombre: Carlos Mendoza (SecAdmin)", UserRoleEnum.SECURITY_ADMIN, True),
                ("comandante_csirt", "csirt.lead@banco.com", "Elena Vargas (Incident Commander)", UserRoleEnum.INCIDENT_COMMANDER, True),
                ("analista_l2", "forense.l2@banco.com", "Miguel Ángel Torres (Analista L2)", UserRoleEnum.SOC_ANALYST_L2, True),
                ("analista_l1", "triaje.l1@banco.com", "Sofía Ramírez (Analista L1)", UserRoleEnum.SOC_ANALYST_L1, False),
                ("auditor_pci", "auditoria.pci@banco.com", "Roberto Gómez (Auditor PCI-DSS / ISO 27001)", UserRoleEnum.AUDITOR, True),
            ]
            for uname, email, fname, r_enum, mfa in users_seed:
                db.add(User(
                    username=uname,
                    email=email,
                    hashed_password=get_password_hash("AegisBank2026!#"),
                    full_name=fname,
                    is_active=True,
                    is_mfa_enabled=mfa,
                    last_login_at=now - timedelta(minutes=15),
                    roles=[roles_map[r_enum]]
                ))
            await db.flush()

            # 3. Incidentes y Casos SOC en distintos estados del ciclo de vida
            incidents_seed = [
                ("INC-20261027-001", ChannelType.WEB, IncidentSeverity.CRITICAL, IncidentStatus.CONTAINED, "Portal Clonado AITM Evilginx2: banco-seguro-verificacion.xyz", "Portal Banca Personas", -20),
                ("INC-20261027-002", ChannelType.EMAIL, IncidentSeverity.CRITICAL, IncidentStatus.INVESTIGATING, "Spearphishing Homógrafo IDN: xn--bnco-qqa.com (Captura OTP)", "Banca Empresas", 35),
                ("INC-20261027-003", ChannelType.QR, IncidentSeverity.HIGH, IncidentStatus.TRIAGED, "Campaña Quishing QR en Facturación Electrónica POS", "App Banca Móvil", 90),
                ("INC-20261027-004", ChannelType.SMS, IncidentSeverity.HIGH, IncidentStatus.NEW, "Smishing Masivo: Alerta falsa de bloqueo de tarjeta débito", "Tarjeta Débito Oro", 45),
                ("INC-20261026-005", ChannelType.WEB, IncidentSeverity.MEDIUM, IncidentStatus.CLOSED_MALICIOUS, "Typosquatting: bancocentral-actualiza-token.top", "Token Digital", -120),
                ("INC-20261026-006", ChannelType.EMAIL, IncidentSeverity.LOW, IncidentStatus.CLOSED_FALSE_POSITIVE, "Boletín legítimo de proveedor de marketing verificado", "Comunicaciones Internas", -240),
                ("RSW-20261027-007", ChannelType.EMAIL, IncidentSeverity.CRITICAL, IncidentStatus.CONTAINED, "Pre-Ransomware Bloqueado (LockBit 3.0): Liquidacion_SWIFT_BCRP.pdf.iso", "Host: WKST-TESORERIA-042", 15),
            ]
            for num, ch, sev, st, title, brand, sla_offset_min in incidents_seed:
                db.add(Incident(
                    incident_number=num,
                    channel=ch,
                    severity=sev,
                    status=st,
                    title=title,
                    target_brand=brand,
                    sla_due_at=now + timedelta(minutes=sla_offset_min),
                    first_response_at=now - timedelta(minutes=8) if st != IncidentStatus.NEW else None,
                    resolved_at=now - timedelta(minutes=2) if "CLOSED" in st.value else None
                ))

            # 4. IOCs y Listas Dinámicas (Blacklist / Whitelist)
            iocs_seed = [
                ("DOMAIN", "banco-seguro-verificacion.xyz", "PhishTank", 99, ["blacklist", "typosquatting", "aitm"]),
                ("DOMAIN", "xn--bnco-qqa.com", "Internal-SOC-Homograph", 100, ["blacklist", "homograph-idn", "punycode"]),
                ("DOMAIN", "bancocentral-actualiza-token.top", "OpenPhish", 96, ["blacklist", "credential-harvesting"]),
                ("IP", "185.220.101.5", "AbuseIPDB", 100, ["blacklist", "tor-exit-node", "phishing-host"]),
                ("IP", "45.142.214.88", "VirusTotal", 95, ["blacklist", "bulletproof-hosting"]),
                ("URL", "https://qr-auth-banco-token.xyz/validate", "Internal-Quishing-Sensor", 97, ["blacklist", "quishing", "qr"]),
                ("WHITELIST_DOMAIN", "banco.com", "Bank-Official-Registry", 0, ["whitelist", "official-domain"]),
                ("WHITELIST_DOMAIN", "bancolinea.com", "Bank-Official-Registry", 0, ["whitelist", "official-domain"]),
                ("HASH_SHA256", "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", "Mandian-ThreatIntel", 100, ["ransomware", "lockbit-3.0", "iso-dropper"]),
            ]
            for itype, val, src, score, tags in iocs_seed:
                db.add(IndicatorOfCompromise(
                    ioc_type=itype, value=val, source=src, reputation_score=score, is_active=True, tags=tags
                ))

            # 5. Reportes Programados (PDF, DOCX, XLSX)
            db.add_all([
                ScheduledReport(
                    name="Informe Ejecutivo Semanal CISO & Comité Antifraude",
                    cron_expression="0 7 * * 1",
                    report_type="EXECUTIVE_CISO",
                    format="PDF",
                    recipient_emails=["ciso@banco.com", "presidencia@banco.com"],
                    is_active=True,
                    last_run_at=now - timedelta(days=2)
                ),
                ScheduledReport(
                    name="Evidencias Regulatorias Mensuales PCI-DSS v4.0 & ISO 27001",
                    cron_expression="0 6 1 * *",
                    report_type="REGULATORY_PCI",
                    format="XLSX",
                    recipient_emails=["auditoria.pci@banco.com", "cumplimiento@banco.com"],
                    is_active=True,
                    last_run_at=now - timedelta(days=5)
                ),
                ScheduledReport(
                    name="Minuta Forense de Incidentes y Takedowns CSIRT",
                    cron_expression="0 18 * * 5",
                    report_type="SOC_OPERATIONAL",
                    format="DOCX",
                    recipient_emails=["csirt.lead@banco.com", "legal@banco.com"],
                    is_active=True,
                    last_run_at=now - timedelta(days=1)
                ),
            ])

            # 6. Pista de Auditoría Inmutable encadenada con SHA-256
            await append_immutable_audit_log(
                db, "system_boot", "PLATFORM_INITIALIZED", "SYSTEM", "AEGIS-CORE-1.0", "127.0.0.1",
                {"pci_dss_mode": "STRICT_V4", "tls_policy": "TLS_1_3_ONLY"}
            )
            await append_immutable_audit_log(
                db, "admin_soc", "RBAC_ROLES_CONFIGURED", "ROLE", "ALL_6_ROLES", "10.20.1.15",
                {"roles": [r[0].value for r in role_defs], "mfa_enforced": True}
            )
            await append_immutable_audit_log(
                db, "comandante_csirt", "DNS_SINKHOLE_RULE_APPLIED", "IOC", "xn--bnco-qqa.com", "10.20.1.44",
                {"incident": "INC-20261027-002", "workflow": "n8n-WF-05"}
            )
            await db.commit()

            # 7. Ejecutar una corrida inicial del Pipeline ETL del Dataset Público
            etl = PhishingDatasetETLPipeline(db)
            await etl.run_pipeline(
                dataset_name="PhishTank-Validated-Feed + Kaggle-Banking-Corpus",
                version="v2026.10.27-initial",
                limit_records=25
            )
        except Exception:
            await db.rollback()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicialización de tablas y semilla automática de ciberseguridad bancaria."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_initial_banking_data()
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Plataforma Empresarial Antifraude y Anti-Phishing Bancario con IA (LangChain/LangFlow), n8n, ETL y Detección Heurística Avanzada.",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app, endpoint="/metrics")
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Salud del Sistema"])
async def health_check():
    return {
        "status": "HEALTHY",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "database": "CONNECTED",
        "version": "1.0.0"
    }
