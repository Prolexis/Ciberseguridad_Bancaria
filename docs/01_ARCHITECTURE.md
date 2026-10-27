# 01. Documento de Arquitectura de Software: AegisBank™ Anti-Phishing Defense Platform

## 1. Visión General del Sistema
**AegisBank™ Anti-Phishing Defense Platform** es una solución empresarial de ciberseguridad bancaria diseñada para neutralizar amenazas de suplantación de identidad en tiempo real en un entorno financiero estrictamente regulado (**PCI-DSS v4.0, ISO/IEC 27001:2022, SOC 2 Type II y normativas de supervisión bancaria local**).

La plataforma protege proactivamente activos digitales, canales transaccionales y marcas bancarias frente a vectores de ataque modernos:
- **Smishing (SMS)**: Mensajes con señuelos de bloqueo de cuenta y enlaces fraudulentos.
- **Vishing (Telefónico)**: Suplantación de voz de agentes bancarios para extracción de OTP.
- **Pharming**: Envenenamiento de caché DNS y redirección no autorizada.
- **Typosquatting & Homograph Attacks**: Registro de dominios con similitud ortográfica y alfabetos cirílico/griego en Punycode (`xn--`).
- **Sitios Clonados**: Portales bancarios clonados con captura dinámica de credenciales y segundo factor (AITM - Adversary-in-the-Middle).
- **Quishing (QR Phishing)**: Códigos QR incrustados en correos y terminales físicas para evadir escaneos de pasarelas perimetrales.

---

## 2. Patrones Arquitectónicos y Principios de Diseño

### 2.1 Arquitectura Limpia / Hexagonal (Ports & Adapters)
El núcleo de la lógica de negocio bancaria es agnóstico a tecnologías externas:
- **Core / Dominio**: Reglas de negocio de scoring de riesgo, modelos de entidades (Incident, IndicatorOfCompromise, AnalysisResult) y objetos de valor inmutables.
- **Puertos (Interfaces)**: Definición abstracta de repositorios, resolutores DNS, analizadores WHOIS, clientes LLM y notificadores.
- **Adaptadores**: Implementaciones concretas (SQLAlchemy 2.0 / PostgreSQL, LangChain / Ollama, n8n Webhooks, VirusTotal API, ReportLab).

### 2.2 Event-Driven Architecture (EDA) & Asincronía
- **FastAPI Async Core**: Manejo no bloqueante de miles de peticiones simultáneas con `async/await` nativo y pooling con `asyncpg`.
- **Triage en Dos Velocidades**:
  1. *Filtro Rápido (< 30ms)*: Heurísticas estáticas en memoria (entropía de Shannon, distancia Jaro-Winkler, validación de Punycode y comprobación de listas negras en Redis).
  2. *Análisis Forense Profundo (Asíncrono en Background Tasks / n8n)*: Inferencia con LLM (LangChain), inspección de certificados TLS, resolución DNS recursiva y captura de pantalla headless.

### 2.3 Command Query Responsibility Segregation (CQRS Light)
- Rutas de lectura optimizadas para paneles de monitoreo analítico (KPIs, series temporales agregadas).
- Rutas de escritura con validación estricta, trazabilidad de auditoría inmutable encadenada con SHA-256 e integridad referencial.

---

## 3. Diagrama General de Componentes del Sistema

```mermaid
flowchart TD
    subgraph Ingestion["Capa de Ingesta Multicanal"]
        A1["Buzón de Empleados / Botón Phishing"]
        A2["Pasarela de Correo (SEG / Postfix RFC 822)"]
        A3["Feeds Públicos (PhishTank, OpenPhish)"]
        A4["Sensor de Terminales POS / QR Quishing"]
        A5["Webhooks de Telemetría Externa"]
    end

    subgraph Perimeter["Perímetro Seguro & API Gateway"]
        GW["Reverse Proxy / WAF / Traefik / NGINX"]
        RL["Rate Limiter (Token Bucket en Redis)"]
        AUTH["OAuth2 / JWT Provider + SSO LDAP/SAML"]
    end

    subgraph CoreBackend["Backend FastAPI (Python 3.11+)"]
        API["REST API v1 Router"]
        DET["Motor Heurístico Forense (Typosquatting/Homógrafo)"]
        CASE["Gestión de Casos SOC & SLAs"]
        ETL["Pipeline ETL & Feature Store"]
        REP["Generador de Reportes (PDF, DOCX, XLSX)"]
    end

    subgraph AIEngine["Capa de IA y LLM (Gobernanza Bancaria)"]
        LC["LangChain Orchestrator"]
        LF["LangFlow Prototyping Studio"]
        OLL["Ollama Local (Llama 3 8B On-Premise)"]
        AZ["Azure OpenAI (Nube Privada Certificada)"]
        RAG["Base Vectorial RAG (MITRE ATT&CK / TTPs)"]
    end

    subgraph Automation["Orquestación de Procesos n8n"]
        N1["Workflow 01: Ingesta Periódica Feeds"]
        N2["Workflow 02: Alertas Críticas Multicanal"]
        N3["Workflow 03: Escalamiento SLA Vencido"]
        N4["Workflow 04: Reporte Semanal C-Level"]
        N5["Workflow 05: DNS Sinkhole & Abuse Takedown"]
    end

    subgraph DataStorage["Capa de Persistencia y Caché"]
        PG[("PostgreSQL 15+ (pg_trgm, JSONB, Audit Chain)")]
        RD[("Redis 7 (Sesiones, Rate Limit, In-Memory IOCs)")]
    end

    subgraph Presentation["Capa de Presentación"]
        FE["React 18 SPA (Vite, TypeScript, Tailwind, Recharts)"]
    end

    Ingestion --> GW
    GW --> RL --> AUTH --> API
    API --> DET
    API --> CASE
    API --> ETL
    API --> REP
    DET --> LC
    LC --> OLL
    LC -.-> AZ
    LC --> RAG
    CASE --> Automation
    API --> PG
    API --> RD
    FE <--> API
```

---

## 4. Diagrama de Secuencia Forense: Flujo de Detección y Contención

```mermaid
sequenceDiagram
    autonumber
    actor Cuentahabiente as Cuentahabiente / Empleado
    participant UI as Portal / Botón Reporte
    participant API as FastAPI Backend
    participant Heuristic as Motor Heurístico
    participant AI as LangChain Agent (Ollama)
    participant DB as PostgreSQL 15+
    participant N8N as Orquestador n8n
    participant Perimeter as DNS Sinkhole / WAF
    participant Analyst as Analista SOC L2

    Cuentahabiente->>UI: Reporta URL sospechosa (https://xn--banc-9na.com/login)
    UI->>API: POST /api/v1/detection/analyze-url
    API->>Heuristic: Análisis Rápido (Entropía, Typosquatting, Homógrafo)
    Heuristic-->>API: Alerta: Homógrafo detectado + Typosquatting (Score: 94.5)
    
    API->>AI: Solicitar Dictamen Forense y TTPs MITRE
    AI-->>API: Veredicto: MALICIOUS, Técnica T1566.002, Contención recomendada
    
    API->>DB: Crear Incidente (INC-2026-X), Guardar Evidencia y Registro Hash
    API-->>UI: Retorna Veredicto y Acciones Inmediatas
    
    API->>N8N: Disparar Webhook de Alerta Crítica (Background Task)
    par Mitigación Automatizada
        N8N->>Perimeter: Aplicar regla RPZ en DNS Sinkhole corporativo
        N8N->>N8N: Emitir notificación Abuse al Registrador de Dominio
    and Notificación al SOC
        N8N->>Analyst: Enviar Alerta Crítica (Slack / Teams / PagerDuty)
    end
    Analyst->>API: Apertura de Expediente y Cierre Forense
```

---

## 5. Registro de Decisiones de Arquitectura (ADR)

### ADR-001: Procesamiento Híbrido en Dos Fases (Heurística Estática + LLM Selectivo)
- **Contexto**: Un banco procesa cientos de miles de eventos de navegación y correos por hora. Enviar cada URL a un LLM saturaría recursos computacionales y degradaría la latencia.
- **Decisión**: Se implementa un filtro heurístico determinista (< 30ms). Solo las URLs con score de riesgo sospechoso (> 35.0) o solicitadas mediante `force_deep_scan` activan el agente de LangChain.
- **Consecuencias**: Tiempos de respuesta óptimos (p95 < 50ms para URLs benignas), reducción del 92% en costo de inferencia de IA y SLA bancario garantizado.

### ADR-002: Despliegue de LLM On-Premise (Ollama) con Fallback a Nube Privada
- **Contexto**: Las regulaciones bancarias (PCI-DSS Req 3 y regulaciones de secreto bancario) prohíben enviar PII, datos de transacciones o credenciales a modelos públicos en la nube.
- **Decisión**: Se despliega **Ollama (Llama 3 8B Instruct)** localmente en contenedor aislado sin acceso a Internet externo para analizar el contenido de correos y URLs. Para consultas analíticas no confidenciales, se permite fallback a Azure OpenAI en VPC bancaria.
- **Consecuencias**: Cumplimiento normativo absoluto, cero fuga de PII hacia proveedores de terceros y total soberanía sobre los datos.

