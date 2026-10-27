"""
Módulo de Integración con LLM mediante LangChain.
Diseñado bajo estrictos principios de gobernanza bancaria:
- Prioridad a modelos locales on-premise (Ollama: Llama 3 / Mistral) para evitar fuga de PII bancaria.
- Fallback configurable a Azure OpenAI en nube privada certificada (PCI-DSS / SOC 2).
- Razonamiento forense estructurado (Few-Shot Prompting, JSON estricto).
"""
import json
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from app.core.config import settings

logger = logging.getLogger(__name__)


class ForensicsReportOutput(BaseModel):
    executive_summary: str = Field(description="Resumen de alto nivel para el CISO y equipo ejecutivo")
    technical_verdict: str = Field(description="BENIGN, SUSPICIOUS o MALICIOUS")
    confidence_score: float = Field(description="Nivel de certidumbre entre 0.0 y 1.0")
    attack_techniques_mitre: List[str] = Field(description="Técnicas MITRE ATT&CK identificadas, ej. T1566.002")
    targeted_assets: List[str] = Field(description="Activos o credenciales en riesgo")
    containment_steps: List[str] = Field(description="Acciones de contención inmediatas para el SOC")


SYSTEM_PROMPT_SOC_EXPERT = """
Eres un Analista Forense Senior del SOC y Arquitecto de Ciberseguridad Bancaria.
Tu misión es analizar telemetría sospechosa de phishing, correos electrónicos, URLs y códigos QR.
Debes apegarte estrictamente a las mejores prácticas de PCI-DSS, NIST SP 800-61r2 y MITRE ATT&CK.

CRITERIOS ESTRICTOS:
1. Jamás reveles ni transmitas datos sensibles de clientes (números de tarjeta PAN, CVV, contraseñas).
2. Si detectas URLs con dominios que imitan la marca oficial del banco (typosquatting o homógrafos), clasifícalas como MALICIOUS.
3. Evalúa el sentido de urgencia psicológica, pretextos financieros (bloqueo de cuenta, transferencias no reconocidas) y técnicas de evasión.
4. Tu salida DEBE ser estrictamente en formato JSON válido correspondiente al esquema solicitado.
"""


class BankingPhishingLangChainAgent:
    """Agente autónomo de LangChain para enriquecimiento y análisis forense con LLMs."""

    def __init__(self):
        self.provider = settings.AI_PROVIDER
        self._init_llm()

    def _init_llm(self):
        """Inicializa el cliente de LLM según la política de seguridad bancaria."""
        try:
            if self.provider == "ollama":
                from langchain_community.llms import Ollama
                self.llm = Ollama(
                    base_url=settings.OLLAMA_BASE_URL,
                    model=settings.OLLAMA_MODEL_NAME,
                    temperature=0.1,  # Temperatura baja para reproducibilidad y determinismo forense
                )
                logger.info(f"LangChain inicializado con Ollama local ({settings.OLLAMA_MODEL_NAME})")
            elif self.provider == "azure_openai" and settings.AZURE_OPENAI_API_KEY:
                from langchain_openai import AzureChatOpenAI
                self.llm = AzureChatOpenAI(
                    azure_deployment=settings.AZURE_OPENAI_DEPLOYMENT,
                    openai_api_version="2024-02-15-preview",
                    azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
                    api_key=settings.AZURE_OPENAI_API_KEY,
                    temperature=0.1,
                )
                logger.info("LangChain inicializado con Azure OpenAI en nube privada")
            else:
                self.llm = None
                logger.warning("No hay LLM configurado. Se utilizará motor heurístico de respaldo.")
        except Exception as e:
            logger.error(f"Error al inicializar LLM en LangChain: {str(e)}")
            self.llm = None

    async def analyze_suspicious_artifact(
        self,
        artifact_type: str,
        content: str,
        features: Dict[str, Any]
    ) -> ForensicsReportOutput:
        """
        Ejecuta el análisis forense con LLM y genera el dictamen estructurado.
        Si el LLM no está disponible, realiza un fallback determinista seguro.
        """
        if not self.llm:
            return self._heuristic_fallback(artifact_type, features)

        prompt = f"""
{SYSTEM_PROMPT_SOC_EXPERT}

Analiza el siguiente artefacto detectado por la plataforma bancaria:
Tipo de Artefacto: {artifact_type}
Contenido/URL: {content}
Características Heurísticas Detectadas: {json.dumps(features, indent=2)}

Genera la evaluación técnica en formato JSON con las claves:
- "executive_summary": Texto explicativo
- "technical_verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS"
- "confidence_score": Número decimal entre 0.0 y 1.0
- "attack_techniques_mitre": Lista de strings con identificadores MITRE
- "targeted_assets": Lista de credenciales o recursos objetivo
- "containment_steps": Lista ordenada de acciones de mitigación para el equipo SOC
"""
        try:
            # Invocación sincrónica/asincrónica
            response_text = self.llm.invoke(prompt)
            # Limpieza básica de bloques markdown de código ```json ... ```
            cleaned = response_text.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            parsed = json.loads(cleaned)
            return ForensicsReportOutput(**parsed)
        except Exception as ex:
            logger.warning(f"Excepción en LLM LangChain ({ex}). Usando fallback heurístico.")
            return self._heuristic_fallback(artifact_type, features)

    def _heuristic_fallback(self, artifact_type: str, features: Dict[str, Any]) -> ForensicsReportOutput:
        """Fallback local determinista que garantiza alta disponibilidad ante caídas de LLM."""
        is_typo = features.get("typosquatting_detected", False)
        is_homo = features.get("homograph_detected", False)

        if is_typo or is_homo:
            verdict = "MALICIOUS"
            score = 0.95
            summary = (
                f"Alerta Crítica: Se detectó una campaña activa de suplantación bancaria dirigida. "
                f"El artefacto ({artifact_type}) emplea técnicas de evasión avanzada (Typosquatting/Homógrafo) "
                f"para capturar credenciales de acceso de clientes."
            )
            mitre = ["T1566.002 - Spearphishing Link", "T1583.001 - Domains: TypoSquatting"]
            steps = [
                "Disparar bloqueo perimetral en Firewalls y DNS Resolver.",
                "Iniciar takedown registral mediante el módulo automatizado de n8n.",
                "Revisar accesos concurrentes en banca móvil en la última hora."
            ]
        else:
            verdict = "SUSPICIOUS"
            score = 0.70
            summary = "Artefacto con anomalías sintácticas o heurísticas. Se recomienda revisión de un analista L1."
            mitre = ["T1566 - Phishing"]
            steps = ["Continuar monitoreo en lista gris y solicitar confirmación al usuario."]

        return ForensicsReportOutput(
            executive_summary=summary,
            technical_verdict=verdict,
            confidence_score=score,
            attack_techniques_mitre=mitre,
            targeted_assets=["Credenciales de Banca en Línea", "Tokens de Segundo Factor"],
            containment_steps=steps
        )

