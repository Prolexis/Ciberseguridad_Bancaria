# AegisBank™ Anti-Phishing Defense Platform

Plataforma empresarial de detección, mitigación y orquestación antifraude y anti-phishing bancario diseñada bajo normativas **PCI-DSS v4.0, ISO/IEC 27001:2022 y SOC 2 Type II**.

---

## 🛠 Stack Tecnológico

- **Backend**: Python 3.11+ con FastAPI (asíncrono), Pydantic v2, SQLAlchemy 2.0 (asyncpg) y Alembic.
- **Frontend**: React 18+ con TypeScript, Vite, TailwindCSS y Recharts.
- **Base de Datos**: PostgreSQL 15+ con extensiones `pg_trgm`, `uuid-ossp`, `pgcrypto` y particionamiento por rangos temporales.
- **Caché y Mensajería**: Redis 7 para rate limiting en ventana deslizante y almacenamiento volátil de IOCs.
- **Orquestación**: n8n autoalojado con workflows para ingesta de feeds, alertas críticas multicanal, escalamiento por SLA, reportes ejecutivos y takedown registral.
- **Inteligencia Artificial**: LangChain (agentes forenses, chains y RAG híbrido) + LangFlow para prototipado visual, con inferencia local privada on-premise en Ollama (Llama 3 8B) y fallback opcional a Azure OpenAI.
- **Reportes Multiformato**: ReportLab (PDF formal), python-docx (Word editable) y openpyxl/pandas (Excel estructurado).
- **Contenedores y Monitoreo**: Docker Compose / Kubernetes, métricas Prometheus (RED method) y dashboards en Grafana.

---

## 📂 Estructura del Repositorio

```text
├── docs/                               # Especificaciones técnicas de arquitectura y diseño
│   ├── 01_ARCHITECTURE.md              # Arquitectura limpia/hexagonal, diagramas y ADRs
│   ├── 02_DATA_MODEL.md                # Diagrama ER, índices, particionamiento y retención
│   ├── 03_API_SPECIFICATION.md         # Catálogo de endpoints REST, rate limit y RFC 7807
│   ├── 04_FUNCTIONAL_MODULES.md        # Especificación detallada de 19 módulos funcionales
│   ├── 05_N8N_WORKFLOWS.md             # Documentación exhaustiva de los 5 workflows de n8n
│   ├── 06_LANGCHAIN_LANGFLOW.md        # Prompts, herramientas, RAG y gobernanza bancaria
│   ├── 07_ETL_PIPELINE.md              # Pipeline ETL para PhishTank/Kaggle, feature store y DVC
│   ├── 08_TEST_PLAN.md                 # Plan de pruebas unitarias, integración, E2E y Locust
│   ├── 09_SECURITY_COMPLIANCE.md       # OWASP ASVS Nivel 3, Vault, TLS 1.3, PCI-DSS v4.0
│   ├── 10_DEPLOYMENT_OBSERVABILITY.md  # Docker, K8s HPA, CI/CD GitHub Actions y Prometheus
│   └── 11_ROADMAP_ESTIMATIONS.md       # Cronograma por fases, Sprints y preguntas abiertas
├── backend/                            # Núcleo Backend en FastAPI (Python 3.11+)
│   ├── app/
│   │   ├── core/                       # Configuración Pydantic v2, seguridad JWT y DB async
│   │   ├── domain/                     # Modelos SQLAlchemy 2.0 y esquemas Pydantic v2
│   │   ├── infrastructure/             # Heurística de URLs, LangChain agent, ETL y Reportes
│   │   ├── api/v1/                     # Routers de endpoints REST
│   │   └── main.py                     # Entrypoint con instrumentación Prometheus
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                           # Panel Web para Analistas SOC (React 18 + Vite)
│   ├── src/
│   │   ├── features/                   # Dashboard KPIs, Scanner Forense y SOC Copilot Chat
│   │   ├── types/                      # Interfaces TypeScript
│   │   └── App.tsx
│   ├── Dockerfile
│   └── package.json
├── n8n/                                # Workflows exportables en formato JSON listos para importar
│   ├── workflow_01_feed_ingestion.json
│   ├── workflow_02_critical_alerts.json
│   ├── workflow_03_sla_escalation.json
│   ├── workflow_04_weekly_reports.json
│   └── workflow_05_sinkhole_takedown.json
├── monitoring/                         # Configuración de observabilidad
│   └── prometheus.yml
└── docker-compose.yml                  # Orquestación local completa de todos los servicios
```

---

## 🚀 Despliegue Rápido Local (Quick Start)

### Requisitos Previos
- Docker y Docker Compose instalados.
- Python 3.11+ y Node.js 18+ (para ejecución fuera de contenedor).

### 1. Iniciar toda la infraestructura con Docker Compose
```bash
docker-compose up -d --build
```

### 2. URLs de Servicios
- **Frontend SOC (React)**: [http://localhost:3000](http://localhost:3000)
- **Backend API Docs (Swagger UI)**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **Métricas Prometheus**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
- **Orquestador n8n**: [http://localhost:5678](http://localhost:5678)
- **Métricas Grafana**: [http://localhost:3001](http://localhost:3001) (Credenciales: `admin` / `GrafanaAdmin2026!`)

