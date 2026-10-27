"""
Configuración centralizada de la plataforma antifraude bancaria AegisBank.
Cumplimiento estricto de Pydantic v2 Settings y validación tipada.
"""
from typing import List, Optional
from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AegisBank Anti-Phishing Defense Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "production"  # development, staging, production
    DEBUG: bool = False

    # Seguridad y JWT
    SECRET_KEY: str = "CHANGE_THIS_IN_PROD_USE_VAULT_KEY_256_BITS_MINIMUM_HEX"
    ALGORITHM: str = "HS256"  # Se recomienda RS256 en producción bancaria con SSO
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "https://soc.banco.internal",
    ]

    # Base de Datos PostgreSQL
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegis_secops"
    POSTGRES_PASSWORD: str = "AegisSecurePass2026!#"
    POSTGRES_DB: str = "aegis_antiphishing"
    SQLALCHEMY_DATABASE_URI: Optional[str] = None

    @field_validator("SQLALCHEMY_DATABASE_URI", mode="before")
    def assemble_db_connection(cls, v: Optional[str], info) -> str:
        if isinstance(v, str) and v:
            return v
        data = info.data
        user = data.get("POSTGRES_USER")
        password = data.get("POSTGRES_PASSWORD")
        server = data.get("POSTGRES_SERVER")
        port = data.get("POSTGRES_PORT")
        db = data.get("POSTGRES_DB")
        return f"postgresql+asyncpg://{user}:{password}@{server}:{port}/{db}"

    # Redis (Rate Limiting y Cache)
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None

    # n8n Webhook Triggers
    N8N_WEBHOOK_URL_CRITICAL_ALERT: str = "http://localhost:5678/webhook/aegis-critical-alert"
    N8N_WEBHOOK_URL_SINKHOLE: str = "http://localhost:5678/webhook/aegis-sinkhole-action"
    N8N_API_KEY: str = "n8n_sec_vault_token_placeholder"

    # Threat Intelligence Feeds (Claves seguras administradas vía Vault)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    PHISHTANK_APP_KEY: Optional[str] = None

    # Configuración de LLM / IA
    AI_PROVIDER: str = "ollama"  # "ollama" (on-premise seguro bancario) o "azure_openai"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL_NAME: str = "llama3:8b-instruct-q8_0"
    AZURE_OPENAI_API_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_DEPLOYMENT: Optional[str] = None

    # Parámetros Bancarios de Detección
    BANK_OFFICIAL_DOMAINS: List[str] = [
        "banco.com",
        "bancolinea.com",
        "seguridad-banco.com",
        "bancaempresas.banco.com",
        "auth.banco.com"
    ]
    TYPOSQUATTING_THRESHOLD: float = 0.82

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()

