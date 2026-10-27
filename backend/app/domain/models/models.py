"""
Modelos ORM de SQLAlchemy 2.0 para AegisBank Anti-Phishing.
Incluye soporte JSONB, índices optimizados y diseño audit-first para PCI-DSS / ISO 27001.
"""
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String, Boolean, Integer, Float, Text, DateTime, ForeignKey, Index, func
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class UserRoleEnum(str, Enum):
    SOC_ANALYST_L1 = "SOC_ANALYST_L1"
    SOC_ANALYST_L2 = "SOC_ANALYST_L2"
    INCIDENT_COMMANDER = "INCIDENT_COMMANDER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    AUDITOR = "AUDITOR"
    EXECUTIVE = "EXECUTIVE"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED_MALICIOUS = "CLOSED_MALICIOUS"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChannelType(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    WEB = "WEB"
    QR = "QR"
    TELEPHONY_VISHING = "TELEPHONY_VISHING"


class VerdictType(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


# --- Módulo de Identidad y Auditoría (PCI-DSS Req 8 & 10) ---

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    roles: Mapped[List["Role"]] = relationship("Role", secondary="user_roles", back_populates="users", lazy="selectin")
    incidents_assigned: Mapped[List["Incident"]] = relationship("Incident", back_populates="assigned_analyst")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[UserRoleEnum] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=True)
    permissions: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    users: Mapped[List["User"]] = relationship("User", secondary="user_roles", back_populates="roles")


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)


class AuditLog(Base):
    """Registro inmutable de auditoría con encadenamiento criptográfico (PCI-DSS Req 10)."""
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True, nullable=False)
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_audit_logs_actor_timestamp", "actor_id", "timestamp"),
        Index("idx_audit_logs_action_timestamp", "action", "timestamp"),
    )


# --- Módulo de Incidentes y Casos SOC ---

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    channel: Mapped[ChannelType] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[IncidentSeverity] = mapped_column(String(32), default=IncidentSeverity.MEDIUM, index=True, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(String(32), default=IncidentStatus.NEW, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_brand: Mapped[str] = mapped_column(String(128), default="Banco Central Corporativo", nullable=False)
    
    # SLA Management
    sla_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    first_response_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_analyst_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    assigned_analyst: Mapped[Optional["User"]] = relationship("User", back_populates="incidents_assigned")
    evidence: Mapped[List["ArtifactEvidence"]] = relationship("ArtifactEvidence", back_populates="incident", cascade="all, delete-orphan")
    analysis: Mapped[Optional["AnalysisResult"]] = relationship("AnalysisResult", back_populates="incident", uselist=False, cascade="all, delete-orphan")


class ArtifactEvidence(Base):
    """Evidencias digitales forenses: headers RFC 822, URLs extraídas, imágenes QR, capturas de pantalla."""
    __tablename__ = "artifact_evidences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False)  # URL, EMAIL_EML, QR_IMAGE, SCREENSHOT, SMS_BODY
    raw_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extracted_urls: Mapped[List[str]] = mapped_column(JSONB, default=list, nullable=False)
    sender_metadata: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    file_hashes: Mapped[Dict[str, str]] = mapped_column(JSONB, default=dict, nullable=False)  # md5, sha256
    storage_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence")


class AnalysisResult(Base):
    """Resultados consolidados de los motores heurísticos, IOCs, ML y LLM (LangChain)."""
    __tablename__ = "analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False)
    
    verdict: Mapped[VerdictType] = mapped_column(String(32), nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 a 1.0
    
    # Desglose de puntuaciones
    heuristic_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_intel_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ml_classifier_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    llm_reasoning_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    
    # Análisis detallados
    typosquatting_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    homograph_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    matched_brand: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    domain_age_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Explicabilidad y razonamiento del LLM
    llm_executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    llm_recommended_actions: Mapped[List[str]] = mapped_column(JSONB, default=list, nullable=False)
    threat_intel_hits: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="analysis")


# --- Módulo de Inteligencia de Amenazas (IOCs) y Listas Dinámicas ---

class IndicatorOfCompromise(Base):
    """Repositorio unificado de IOCs (Indicadores de Compromiso)."""
    __tablename__ = "indicators_of_compromise"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # DOMAIN, URL, IP, SHA256, SENDER_EMAIL
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # PhishTank, OpenPhish, AbuseIPDB, Internal
    reputation_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)  # 0 a 100 maliciosidad
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSONB, default=list, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    metadata_info: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        Index("idx_ioc_type_value", "ioc_type", "value"),
    )


# --- Módulo de Ingesta ETL y Datasets Públicos ---

class PublicDataset(Base):
    """Control de versiones y linaje de datos de datasets públicos ingeridos."""
    __tablename__ = "public_datasets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source_url: Mapped[str] = mapped_column(String(512), nullable=False)
    license: Mapped[str] = mapped_column(String(64), nullable=False)  # CC BY 4.0, Open Data Commons, etc.
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    total_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_phish_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    records: Mapped[List["DatasetRecord"]] = relationship("DatasetRecord", back_populates="dataset", cascade="all, delete-orphan")


class DatasetRecord(Base):
    """Registros unitarios ingeridos para benchmark y reentrenamiento."""
    __tablename__ = "dataset_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dataset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("public_datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False)  # URL, EMAIL, SMS
    target_value: Mapped[str] = mapped_column(Text, nullable=False)
    is_phishing: Mapped[bool] = mapped_column(Boolean, nullable=False)
    extracted_features: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    verified_online: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    dataset: Mapped["PublicDataset"] = relationship("PublicDataset", back_populates="records")

    __table_args__ = (
        Index("idx_dataset_records_type_phish", "record_type", "is_phishing"),
    )


# --- Módulo de Reportes Programados ---

class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "0 8 * * 1" (Lunes 8am)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)  # EXECUTIVE_CISO, REGULATORY_PCI, SOC_METRICS
    format: Mapped[str] = mapped_column(String(16), nullable=False)  # PDF, DOCX, XLSX
    recipient_emails: Mapped[List[str]] = mapped_column(JSONB, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

