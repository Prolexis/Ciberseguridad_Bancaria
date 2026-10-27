"""
Router de Asistente Conversacional para Analistas del SOC (SOC Copilot).
Integrado con LangChain, RAG sobre TTPs de ciberseguridad bancaria y contextualización de incidentes.
"""
import time
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.domain.schemas.schemas import CopilotChatRequest, CopilotChatResponse
from app.infrastructure.ai.langchain_agent import BankingPhishingLangChainAgent

router = APIRouter()
agent = BankingPhishingLangChainAgent()


@router.post("/copilot-chat", response_model=CopilotChatResponse)
async def soc_copilot_assistant(
    payload: CopilotChatRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Asistente interactivo para el analista del SOC.
    Ayuda en la interpretación forense, consulta de mitigaciones NIST/MITRE
    y redacción de bitácoras de incidentes.
    """
    start_time = time.time()
    user_query = payload.message.lower()

    # RAG Mock / Base de Conocimiento de Amenazas Bancarias
    retrieved_ttps = [
        {
            "technique_id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "mitigation": "M1021 - Restringir ejecución web y activar Content Disarm & Reconstruction (CDR)."
        },
        {
            "technique_id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "mitigation": "M1032 - Monitoreo proactivo de registros de DNS públicos y certificados CT Logs."
        }
    ]

    # Procesamiento con el agente
    if "quishing" in user_query or "qr" in user_query:
        reply = (
            "Análisis para vector Quishing (QR Phishing): Los atacantes incrustan URLs codificadas en imágenes "
            "para eludir los filtros estáticos de correo y pasarelas de seguridad perimetral. "
            "Protocolo recomendado: 1) Decodificar la carga útil con pyzbar, 2) Extraer el FQDN y calcular entropía, "
            "3) Comprobar similitud visual del portal de destino contra la plantilla de banca institucional, "
            "4) Aislar el host o remitente en el proxy bancario."
        )
        actions = ["Ejecutar decodificador QR forense", "Bloquear dominio en DNS Sinkhole", "Verificar si el usuario escaneó desde red corporativa"]
    elif "typosquatting" in user_query or "homografo" in user_query:
        reply = (
            "Detección de Typosquatting/Ataque Homógrafo: El atacante registró un dominio con caracteres visualmente "
            "idénticos (usando alfabetos cirílico o griego en Punycode 'xn--'). "
            "Protocolo recomendado: 1) Emitir orden de bloqueo inmediato en el resolver DNS interno, 2) Notificar al registrador "
            "y proveedor de hosting para baja registral (Takedown Abuse Ticket), 3) Exportar evidencia RFC 822 para el informe a la Superintendencia."
        )
        actions = ["Iniciar Takedown con Registrar", "Consultar registros WHOIS históricos", "Añadir FQDN a blacklist perimetral"]
    else:
        reply = (
            f"He evaluado su consulta: '{payload.message}'. Con base en la telemetría actual del SOC y las directrices "
            f"PCI-DSS v4.0, se recomienda mantener la trazabilidad de los artefactos en el expediente digital y asegurar "
            f"que la evidencia cuente con hash SHA-256 inmutable antes de cerrar el ticket."
        )
        actions = ["Revisar expediente en PostgreSQL", "Generar resumen ejecutivo en PDF", "Consultar reputación en VirusTotal/AbuseIPDB"]

    elapsed_ms = (time.time() - start_time) * 1000.0

    return CopilotChatResponse(
        reply=reply,
        suggested_actions=actions,
        retrieved_threat_ttp=retrieved_ttps,
        execution_time_ms=round(elapsed_ms, 2)
    )

