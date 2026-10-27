"""
Seguridad criptográfica, hashing de contraseñas con Bcrypt nativo y emisión de JWT para AegisBank.
Cumplimiento estricto de OWASP ASVS v4 y PCI-DSS Req 8.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Union, Optional
import bcrypt
from jose import jwt
from app.core.config import settings


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica el hash de la contraseña contra el texto plano usando salt seguro de bcrypt."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Genera hash seguro de contraseña con factor de costo 12 para banca."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8")[:72], salt).decode("utf-8")


def create_access_token(subject: Union[str, Any], roles: list[str], expires_delta: Optional[timedelta] = None) -> str:
    """Genera token JWT firmado con expiración corta (30 minutos por defecto)."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    to_encode = {
        "sub": str(subject),
        "roles": roles,
        "exp": expire,
        "iat": now,
        "iss": "AegisBank-Security-Authority"
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: Union[str, Any]) -> str:
    """Genera token de refresco con vigencia extendida."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {
        "sub": str(subject),
        "type": "refresh",
        "exp": expire,
        "iat": now
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
