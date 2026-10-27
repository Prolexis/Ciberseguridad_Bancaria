"""
Esquemas de validación y DTOs con Pydantic v2.
Tipado estricto, serialización automática y documentación Swagger/OpenAPI.
"""
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl
from app.domain.models.models import ChannelType, IncidentSeverity, IncidentStatus, VerdictType, UserRoleEnum


# --- Autenticación y Usuarios ---

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class TokenPayload(BaseModel):
    sub: str
    roles: List[str]
    exp: int


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=6)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: EmailStr
    full_name: str
    is_active: bool
    is_mfa_enabled: bool
    roles: List[str] = []
    created_at: datetime


# --- Análisis de URLs, Emails y QR (Detección Antifraud) ---

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., example="https://seguridad-banco-verificacion.com/login.php")
    channel: ChannelType = Field(default=ChannelType.WEB)
    reported_by: Optional[str] = Field(None, example="employee_id_9921")
    user_agent: Optional[str] = None
    force_deep_scan: bool = Field(default=False, description="Activa análisis de IA y captura de pantalla")


class DomainFeatures(BaseModel):
    domain: str
    entropy: float
    length: int
    has_ip_address: bool
    suspicious_tld: bool
    typosquatting_detected: bool
    homograph_detected: bool
    matched_target_brand: Optional[str] = None
    similarity_ratio: float = 0.0
    domain_age_days: Optional[int] = None
    dns_resolves: bool = True
    nameservers: List[str] = []
    has_valid_tls: bool = False


class URLAnalysisResponse(BaseModel):
    url: str
    verdict: VerdictType
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Puntuación de riesgo 0 a 100")
    confidence: float = Field(..., ge=0.0, le=1.0)
    domain_features: DomainFeatures
    threat_intel_matches: List[Dict[str, Any]] = []
    llm_rationale: Optional[str] = None
    recommended_mitigation: List[str] = []
    incident_id: Optional[uuid.UUID] = None
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., example="soporte@banco-actualizacion.tk")
    recipient: str = Field(..., example="cliente_vip@banco.com")
    subject: str = Field(..., example="Urgente: Cuenta bancaria bloqueada - Actualice sus claves")
    body_text: str = Field(..., min_length=5)
    body_html: Optional[str] = None
    eml_headers: Optional[Dict[str, str]] = None


class EmailAnalysisResponse(BaseModel):
    verdict: VerdictType
    risk_score: float
    confidence: float
    extracted_urls: List[str]
    spoofing_indicators: Dict[str, Any]  # SPF, DKIM, DMARC mismatches
    llm_analysis: Dict[str, Any]
    incident_id: Optional[uuid.UUID] = None


class QRAnalysisRequest(BaseModel):
    image_base64: Optional[str] = None
    extracted_payload_url: Optional[str] = None


# --- Incidentes y Casos SOC ---

class IncidentFilterParams(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    channel: Optional[ChannelType] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    assigned_to_me: bool = False
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_number: str
    channel: ChannelType
    severity: IncidentSeverity
    status: IncidentStatus
    title: str
    target_brand: str
    sla_due_at: datetime
    created_at: datetime
    updated_at: datetime
    assigned_analyst: Optional[UserResponse] = None


class IncidentDetailResponse(IncidentResponse):
    evidence: List[Dict[str, Any]] = []
    analysis: Optional[Dict[str, Any]] = None


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    justification: str = Field(..., min_length=10)
    assigned_analyst_id: Optional[uuid.UUID] = None


# --- Dashboard y Métricas de Ciberseguridad ---

class ChannelDistribution(BaseModel):
    channel: ChannelType
    count: int
    percentage: float


class TemporalTrendPoint(BaseModel):
    date: str
    detections: int
    malicious: int
    benign: int


class TopAttackerEntity(BaseModel):
    identifier: str  # Dominio o IP
    count: int
    reputation_score: int
    first_seen: str


class DashboardKPIsResponse(BaseModel):
    total_detections_last_30d: int
    active_incidents: int
    mean_time_to_detect_seconds: float
    mean_time_to_respond_seconds: float
    false_positive_rate: float
    false_negative_estimate: float
    channel_distribution: List[ChannelDistribution]
    temporal_trends: List[TemporalTrendPoint]
    top_attacking_domains: List[TopAttackerEntity]
    top_attacking_ips: List[TopAttackerEntity]


# --- Asistente Copilot para Analista SOC (LangChain / LangFlow) ---

class CopilotChatRequest(BaseModel):
    incident_id: Optional[uuid.UUID] = None
    message: str = Field(..., min_length=2)
    conversation_history: List[Dict[str, str]] = []


class CopilotChatResponse(BaseModel):
    reply: str
    suggested_actions: List[str]
    retrieved_threat_ttp: List[Dict[str, Any]]
    execution_time_ms: float


# --- Reportes Operacionales y Regulatorios ---

class ReportGenerationRequest(BaseModel):
    report_type: str = Field(..., example="EXECUTIVE_CISO")  # EXECUTIVE_CISO, REGULATORY_PCI, SOC_OPERATIONAL
    format: str = Field(..., example="PDF")  # PDF, DOCX, XLSX
    start_date: datetime
    end_date: datetime
    include_raw_evidence: bool = False
    recipient_emails: Optional[List[EmailStr]] = None

