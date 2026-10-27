# 08. Plan Maestro de Pruebas y Aseguramiento de Calidad (QA)

Para una plataforma bancaria crítica, el aseguramiento de calidad cubre la pirámide de pruebas completa, con énfasis en resiliencia bajo carga extrema y resistencia a ataques adversarios.

---

## 1. Niveles de Pruebas

### 1.1 Pruebas Unitarias (Unit Testing)
- **Herramientas**: `pytest`, `pytest-asyncio`, `pytest-mock` para Backend; `Vitest` / `React Testing Library` para Frontend.
- **Cobertura Mínima Exigida**: **85%** en código general y **95%** en el motor heurístico de detección y módulos criptográficos.
- **Casos Clave**:
  - Cálculo de entropía de Shannon contra cadenas de control predeterminadas.
  - Detección de homógrafos con alfabetos cirílicos (`а`, `с`, `о`) y Punycode (`xn--`).
  - Detección de typosquatting con distancias Jaro-Winkler calibradas.
  - Validación estricta de esquemas Pydantic v2 y control de transiciones de estado de incidentes.

### 1.2 Pruebas de Integración (Integration Testing)
- **Herramientas**: `Testcontainers` para levantar instancias efímeras de PostgreSQL 15 y Redis durante los tests en CI/CD.
- **Casos Clave**:
  - Inserción y consulta en PostgreSQL con extensiones `pg_trgm` y búsqueda difusa.
  - Rate limiting en Redis (validar retorno de HTTP 429 al exceder la cuota).
  - Flujo completo de autenticación JWT: Login -> Emisión de Access/Refresh Token -> Acceso a endpoint protegido -> Intento con token expirado (HTTP 401).
  - Integración asíncrona de BackgroundTasks y webhooks de n8n.

### 1.3 Pruebas de Extremo a Extremo (E2E Testing)
- **Herramientas**: `Playwright` con TypeScript.
- **Flujos Críticos Evaluados**:
  1. Analista SOC inicia sesión con usuario y MFA -> Consulta el Dashboard -> Filtra incidentes críticos -> Abre expediente -> Reasigna a L2 -> Descarga reporte PDF.
  2. Empleado introduce URL con typosquatting en el formulario -> Verifica veredicto "MALICIOUS" en tiempo real -> Comprueba la sugerencia de mitigación.

---

## 2. Pruebas de Carga y Rendimiento (Performance & Stress Testing)
- **Herramienta**: `Locust` (Python-based distributed load testing).
- **Escenario de Prueba (Target)**:
  - Endpoint `/api/v1/detection/analyze-url` bajo una carga sostenida de **5,000 peticiones por minuto** durante 30 minutos continuos.
- **Criterios de Aceptación (SLA Bancario)**:
  - Latencia **p95 < 120 ms** y **p99 < 350 ms**.
  - Tasa de error HTTP (5xx) menor al **0.01%**.
  - Uso de CPU en pods de FastAPI por debajo del 70% (con auto-escalado horizontal HPA activo).

---

## 3. Pruebas de Seguridad y Resiliencia (Security Testing)

| Tipo de Prueba | Herramienta | Alcance y Objetivos |
| :--- | :--- | :--- |
| **SAST (Static Analysis)** | `Bandit`, `SonarQube`, `Semgrep` | Detección de inyecciones SQL, uso de algoritmos criptográficos débiles (MD5/SHA1), manejo inseguro de credenciales o deserialización no confiable. |
| **DAST (Dynamic Analysis)**| `OWASP ZAP`, `Burp Suite Enterprise` | Escaneo dinámico contra OWASP Top 10: XSS, inyecciones de cabeceras, bypass de autenticación y CSRF. |
| **Fuzzing Testing** | `Atheris` / `Boofuzz` | Inyección de cargas binarias malformadas en los parsers de correos RFC 822 y decodificadores de imágenes QR para descartar desbordamientos de buffer o loops infinitos. |
| **Dependency Scanning** | `Trivy`, `Snyk`, `pip-audit` | Escaneo de imágenes Docker y librerías de `requirements.txt` frente a vulnerabilidades CVE conocidas. Cero tolerancias para CVEs de severidad "Critical" o "High". |

