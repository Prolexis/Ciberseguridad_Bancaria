# 03. Especificación de API REST (FastAPI / OpenAPI 3.1)

## 1. Lineamientos Generales
- **Base URL**: `https://soc.banco.internal/api/v1`
- **Formato**: JSON (Content-Type: `application/json; charset=utf-8`)
- **Autenticación**: `Authorization: Bearer <JWT_ACCESS_TOKEN>`
- **Manejo de Errores**: Formato estandarizado **RFC 7807 (Problem Details for HTTP APIs)**:
```json
{
  "type": "https://soc.banco.internal/errors/rate-limit-exceeded",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Ha superado el límite de 100 peticiones por minuto para su API Key.",
  "instance": "/api/v1/detection/analyze-url",
  "timestamp": "2026-10-27T13:30:00Z"
}
```

---

## 2. Política de Rate Limiting (Protección Anti-DDoS y Abuso)
Implementada mediante algoritmo Sliding Window en Redis:
- **Endpoints Públicos / Empleados** (`/analyze-url`, `/analyze-email`): 120 peticiones/minuto por IP / Token.
- **Endpoints Analista SOC / Búsquedas**: 300 peticiones/minuto por usuario autenticado.
- **Cabeceras HTTP de Control Retornadas**:
  - `X-RateLimit-Limit`: Cuota máxima permitida en la ventana.
  - `X-RateLimit-Remaining`: Peticiones disponibles en la ventana actual.
  - `X-RateLimit-Reset`: Timestamp UNIX del reinicio de cuota.

---

## 3. Catálogo de Endpoints de la API v1

| Método | Endpoint | Roles Requeridos | Descripción | Códigos HTTP |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/auth/login` | Público | Autenticación con credenciales + MFA TOTP | `200`, `401`, `423` (Locked) |
| `POST` | `/auth/refresh` | Público | Renovación de access token mediante refresh token seguro | `200`, `401` |
| `POST` | `/detection/analyze-url` | `SOC_ANALYST_L1`, `L2`, `SYSTEM` | Inspección forense de URLs (Heurística + LLM) | `200`, `400`, `429` |
| `POST` | `/detection/analyze-email` | `SOC_ANALYST_L1`, `L2`, `SYSTEM` | Análisis de remitente, cuerpo y cabeceras EML | `200`, `400` |
| `POST` | `/detection/analyze-qr` | `SOC_ANALYST_L1`, `L2` | Decodificación y análisis de códigos QR sospechosos | `200`, `422` |
| `GET` | `/incidents` | `SOC_ANALYST_L1`, `L2`, `AUDITOR` | Listado paginado de incidentes con filtros de severidad/estado | `200`, `403` |
| `GET` | `/incidents/{id}` | `SOC_ANALYST_L1`, `L2`, `AUDITOR` | Expediente forense completo, artefactos y dictamen | `200`, `404` |
| `PATCH`| `/incidents/{id}/status`| `SOC_ANALYST_L1`, `L2`, `COMMANDER` | Transición de estado con justificación técnica obligatoria | `200`, `400`, `404` |
| `GET` | `/dashboard/kpis` | `SOC_ANALYST_L1`, `EXECUTIVE`, `AUDITOR`| Agregados analíticos, MTTR, distribución y tendencias | `200` |
| `GET` | `/reports/export` | `EXECUTIVE`, `AUDITOR`, `COMMANDER`| Descarga de reportes en PDF (ReportLab), DOCX o XLSX | `200`, `400` |
| `POST` | `/ai/copilot-chat` | `SOC_ANALYST_L1`, `SOC_ANALYST_L2` | Diálogo interactivo con SOC Copilot asistido por LangChain | `200`, `503` |
| `POST` | `/datasets/ingest-batch`| `SECURITY_ADMIN`, `SYSTEM` | Ingesta masiva desde pipeline ETL de feeds públicos | `200`, `400`, `401` |
| `GET` | `/health` | Todos / K8s Probes | Sondeo de salud de la plataforma (Readiness / Liveness) | `200`, `503` |
| `GET` | `/metrics` | Prometheus Scraper | Exportación de métricas de telemetría en formato estándar | `200` |

