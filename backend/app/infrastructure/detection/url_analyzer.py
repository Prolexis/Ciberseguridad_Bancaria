"""
Motor de Análisis Heurístico y Forense de URLs Antifishing.
Especializado en vectores bancarios: Typosquatting, Homograph (IDN), entropía y DNS.
"""
import math
import re
import socket
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlparse
import unicodedata
from app.core.config import settings
from app.domain.models.models import VerdictType
from app.domain.schemas.schemas import DomainFeatures, URLAnalysisResponse


class URLForensicAnalyzer:
    """Analizador heurístico multivariable para URLs sospechosas de suplantar entidades bancarias."""

    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "click", "buzz", "gq", "cf", "tk", "ml", "ga", "country", "loan", "stream"
    }

    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "secure", "banco", "update", "banking", "token", "password", 
        "clave", "tarjeta", "seguridad", "auth", "confirm", "suspension", "alert"
    ]

    # Mapeo de homógrafos comunes (cirílico/griego que suplantan caracteres latinos)
    HOMOGRAPH_LOOKALIKES = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'і': 'i', 'ј': 'j',
        'ԁ': 'd', 'ԛ': 'q', 'ѡ': 'w', 'ѵ': 'v', 'х': 'x', 'у': 'y', 'ո': 'n', 'հ': 'h',
        '0': 'o', '1': 'l'
    }

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calcula la entropía de Shannon. Valores altos (> 3.8) denotan dominios DGA o aleatorios."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        frequencies = {c: text.count(c) / length for c in set(text)}
        for p in frequencies.values():
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def detect_homograph_attack(cls, domain: str) -> Tuple[bool, str]:
        """Detecta caracteres no ASCII o Punycode (xn--) diseñados para ataques homógrafos."""
        is_homograph = False
        normalized = domain.lower()

        # Detección de Punycode IDN
        if "xn--" in normalized:
            try:
                decoded = normalized.encode("ascii").decode("idna")
                return True, f"Punycode detectado: {normalized} resuelve a {decoded}"
            except Exception:
                return True, "Punycode IDN malicioso o malformado detectado"

        # Detección de caracteres no-ASCII simulando alfabeto latino
        non_ascii_chars = [c for c in normalized if ord(c) > 127]
        if non_ascii_chars:
            details = ", ".join(f"'{c}' (U+{ord(c):04X})" for c in non_ascii_chars[:5])
            return True, f"Caracteres no latinos detectados: {details}"

        return False, "Sin indicadores de homógrafo"

    @classmethod
    def calculate_jaro_winkler_similarity(cls, s1: str, s2: str) -> float:
        """Calcula similitud fonética/ortográfica entre dominio analizado y dominio oficial."""
        if s1 == s2:
            return 1.0
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0

        match_distance = (max(len1, len2) // 2) - 1
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        matches = 0
        transpositions = 0

        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break

        if matches == 0:
            return 0.0

        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1

        jaro = (
            (matches / len1) +
            (matches / len2) +
            ((matches - transpositions / 2) / matches)
        ) / 3.0

        # Prefijo común de Winkler (máx 4 caracteres)
        prefix = 0
        for i in range(min(4, min(len1, len2))):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break

        return round(jaro + (prefix * 0.1 * (1.0 - jaro)), 4)

    @classmethod
    def check_typosquatting(cls, domain: str) -> Tuple[bool, Optional[str], float]:
        """Compara el dominio con la lista oficial de dominios bancarios para detectar typosquatting."""
        clean_domain = domain.lower().split(":")[0]  # remover puerto
        parts = clean_domain.split(".")
        if len(parts) >= 2:
            registered_name = parts[-2]
        else:
            registered_name = clean_domain

        max_sim = 0.0
        best_target = None

        for official in settings.BANK_OFFICIAL_DOMAINS:
            official_name = official.split(".")[0]
            if clean_domain == official:
                return False, official, 1.0  # Es el dominio legítimo oficial

            sim = cls.calculate_jaro_winkler_similarity(registered_name, official_name)
            if sim > max_sim:
                max_sim = sim
                best_target = official

        # Si supera el umbral pero no es idéntico, se clasifica como typosquatting
        is_typo = (max_sim >= settings.TYPOSQUATTING_THRESHOLD and max_sim < 1.0)
        return is_typo, best_target, max_sim

    @classmethod
    def verify_dns_resolution(cls, domain: str) -> Tuple[bool, list]:
        """Verifica si el dominio resuelve en DNS públicos (indicador de sitio activo)."""
        clean_domain = domain.lower().split(":")[0]
        try:
            _, _, ip_list = socket.gethostbyname_ex(clean_domain)
            return True, ip_list
        except (socket.gaierror, socket.herror, Exception):
            return False, []

    @classmethod
    async def analyze_url(cls, raw_url: str, force_deep_scan: bool = False) -> URLAnalysisResponse:
        """
        Ejecuta el pipeline completo de análisis estático y dinámico para una URL.
        Retorna score de riesgo estandarizado (0-100) y veredicto bancario.
        """
        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        tld = netloc.split(".")[-1] if "." in netloc else ""

        # 1. Extracción de características
        entropy = cls.calculate_shannon_entropy(netloc)
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", netloc))
        is_suspicious_tld = tld in cls.SUSPICIOUS_TLDS
        is_homograph, homograph_reason = cls.detect_homograph_attack(netloc)
        is_typo, matched_brand, sim_score = cls.check_typosquatting(netloc)
        dns_ok, ips = cls.verify_dns_resolution(netloc)

        # 2. Ponderación Heurística de Riesgo (Risk Score 0-100)
        risk_score = 0.0

        if is_ip:
            risk_score += 35.0  # URLs con IP directa en banca son altamente sospechosas
        if is_homograph:
            risk_score += 45.0  # Ataque de suplantación visual directa
        if is_typo:
            risk_score += 40.0  # Typosquatting dirigido a la marca bancaria
        if is_suspicious_tld:
            risk_score += 20.0
        if entropy > 3.8:
            risk_score += 15.0  # DGA o subdominios aleatorios
        if any(keyword in path or keyword in netloc for keyword in cls.SUSPICIOUS_KEYWORDS):
            risk_score += 15.0  # Palabras clave de señuelo financiero
        if parsed.scheme != "https":
            risk_score += 10.0  # Falta de TLS en contexto bancario
        if not dns_ok:
            risk_score = min(risk_score, 40.0)  # Dominio inactivo / no registrado aún

        risk_score = min(max(risk_score, 0.0), 100.0)

        # 3. Determinación de Veredicto
        if risk_score >= 65.0 or is_homograph or (is_typo and sim_score >= 0.88):
            verdict = VerdictType.MALICIOUS
        elif risk_score >= 35.0:
            verdict = VerdictType.SUSPICIOUS
        else:
            verdict = VerdictType.BENIGN

        confidence = round(min(0.60 + (risk_score / 250.0), 0.99), 2)

        # 4. Mitigaciones recomendadas automáticas
        mitigations = []
        if verdict == VerdictType.MALICIOUS:
            mitigations.extend([
                "Bloquear de inmediato en Firewall Perimetral y DNS Sinkhole corporativo.",
                "Disparar workflow n8n de notificación a CSIRT / CISO y Abuse Registrar.",
                "Escanear logs de proxy web bancario para identificar cuentahabientes o empleados que hayan interactuado.",
            ])
        elif verdict == VerdictType.SUSPICIOUS:
            mitigations.extend([
                "Poner dominio en lista gris con monitoreo de resolución DNS cada 15 minutos.",
                "Notificar al analista SOC L1 para revisión manual de captura de pantalla.",
            ])
        else:
            mitigations.append("Tráfico autorizado. Mantener telemetría rutinaria.")

        features = DomainFeatures(
            domain=netloc,
            entropy=entropy,
            length=len(netloc),
            has_ip_address=is_ip,
            suspicious_tld=is_suspicious_tld,
            typosquatting_detected=is_typo,
            homograph_detected=is_homograph,
            matched_target_brand=matched_brand,
            similarity_ratio=sim_score,
            dns_resolves=dns_ok,
            nameservers=ips[:3],
            has_valid_tls=(parsed.scheme == "https")
        )

        return URLAnalysisResponse(
            url=raw_url,
            verdict=verdict,
            risk_score=round(risk_score, 2),
            confidence=confidence,
            domain_features=features,
            threat_intel_matches=[],
            llm_rationale=(
                f"Evaluación Heurística: {verdict.value} (Riesgo: {risk_score:.1f}/100). "
                f"Typosquatting={is_typo} ({matched_brand or 'N/A'}), "
                f"Homógrafo={is_homograph}, Entropía={entropy:.2f}."
            ),
            recommended_mitigation=mitigations
        )

