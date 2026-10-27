# 04. Descripción Funcional Detallada de Módulos del Sistema

## 1. Módulos Obligatorios

### Módulo 1: Dashboard Analítico con KPIs de Ciberseguridad
- **Objetivo**: Proveer visibilidad en tiempo real al CISO y jefes de turno del SOC sobre el panorama de amenazas de suplantación bancaria.
- **Entradas**: Telemetría de detección en tiempo real, eventos de bloqueo, cambios de estado en expedientes de incidentes.
- **Salidas**: Métricas agregadas (Total detecciones, MTTR, MTTD, tasa de falsos positivos/negativos), gráficas de series temporales (Recharts AreaChart), desglose porcentual por canal (Email, SMS, Web, QR) y tablas de top dominios/IPs hostiles.
- **Reglas de Negocio**:
  - Las métricas de tiempo medio de respuesta (MTTR) deben alertar visualmente en rojo si superan el umbral SLA bancario de 15 minutos.
  - La tasa de falsos positivos debe mantenerse calibrada por debajo del 3.0% para evitar fatiga de alertas.
- **Dependencias**: PostgreSQL 15+ (vistas materializadas y consultas agregadas), Redis (caché de métricas de 60 segundos), React 18 / Recharts.

---

### Módulo 2: Gestión de Identidades, RBAC y Auditoría de Accesos
- **Objetivo**: Controlar de manera granular el acceso a la plataforma bancaria garantizando el principio de menor privilegio (PoLP) y cumplimiento de PCI-DSS Req 7 y 8.
- **Entradas**: Credenciales de usuario, códigos MFA TOTP de 6 dígitos, tokens SAML/OIDC de SSO corporativo (Active Directory).
- **Salidas**: Tokens JWT de acceso (vigencia de 30 min) y Refresh Tokens (7 días) almacenados en cookies HTTP-only SameSite=Strict.
- **Reglas de Negocio**:
  - Bloqueo automático de cuenta tras 5 intentos fallidos consecutivos durante 15 minutos.
  - Complejidad de contraseñas: mínimo 12 caracteres, al menos una mayúscula, un número y un símbolo especial; prohibición de reutilización de las últimas 6 contraseñas.
  - Roles definidos: `SOC_ANALYST_L1` (triaje), `SOC_ANALYST_L2` (investigación profunda), `INCIDENT_COMMANDER` (cierre y contención), `SECURITY_ADMIN` (configuración), `AUDITOR` (acceso de solo lectura a pistas de auditoría), `EXECUTIVE` (acceso a dashboards de alto nivel).
- **Dependencias**: Passlib (Bcrypt), Python-Jose (JWT), Redis (registro de intentos fallidos).

---

### Módulo 3: Motor de Generación y Distribución de Reportes Multiformato
- **Objetivo**: Automatizar la confección de informes forenses y regulatorios en formatos estándares para auditoría y comités ejecutivos.
- **Formatos Soportados**:
  - **PDF (ReportLab)**: Documentos corporativos maquetados con membrete institucional, tablas de KPIs, clasificación confidencial y resumen ejecutivo.
  - **Word .docx (python-docx)**: Minutas de trabajo forense y actas editables para comités de crisis y asesoría jurídica.
  - **Excel .xlsx (openpyxl / pandas)**: Libros de trabajo estructurados con registros de incidentes, metadatos y listado de IOCs para exportación hacia herramientas SIEM/SOAR externas.
- **Reglas de Negocio**:
  - Todo reporte generado debe incluir marca de tiempo UTC, identificador único de generación y clasificación de confidencialidad bancaria.
  - Soporte de envíos programados por correo electrónico mediante n8n.
- **Dependencias**: ReportLab, python-docx, openpyxl, pandas, FastAPI BackgroundTasks.

---

### Módulo 4: Ingesta ETL y Linaje de Datasets Públicos de Phishing
- **Objetivo**: Ingerir, validar y enriquecer feeds abiertos reconocidos (PhishTank, OpenPhish, Kaggle Phishing Corpus) para alimentar el feature store y servir como base de pruebas.
- **Entradas**: Feeds JSON/CSV remotos descargados por streaming HTTP.
- **Salidas**: Registros enriquecidos con vectores de características (longitud, entropía, flags de typosquatting y homógrafos) cargados en PostgreSQL con versión semántica.
- **Reglas de Negocio**:
  - Verificación de integridad obligatoria mediante checksum SHA-256 antes de procesar el archivo.
  - Deduplicación automática de URLs basada en FQDN canónico y esquema normalizado.
  - Registro de linaje de datos (fuente, fecha de captura, total de registros, tasa de phishing confirmado).
- **Dependencias**: Httpx, hashlib, SQLAlchemy 2.0, n8n (disparador programado).

---

### Módulo 5: Motor de Detección Antifraude Multicapa
- **Objetivo**: Clasificar artefactos sospechosos combinando heurística sintáctica, análisis de infraestructura y modelos de lenguaje.
- **Capas de Detección**:
  1. *Análisis Sintáctico y Léxico de URLs*: Entropía de Shannon (detección de dominios DGA), longitud, subdominios anidados, TLDs de alto riesgo.
  2. *Detección de Typosquatting*: Comparación fonética y ortográfica contra marcas bancarias oficiales usando el algoritmo de distancia Jaro-Winkler calibrado a un umbral de 0.82.
  3. *Detección de Ataques Homógrafos*: Decodificación de Punycode (`xn--`) y escaneo de caracteres no latinos (alfabetos cirílico, griego o caracteres similares) que suplantan letras del alfabeto latino.
  4. *Inspección de Infraestructura*: Verificación de resolución DNS en tiempo real, validación de certificados TLS y búsqueda en listas de reputación.
  5. *Análisis de Contenido*: Extracción de señuelos psicológicos de urgencia ("cuenta suspendida", "actualice clave") y suplantación de remitentes en correos (SPF, DKIM, DMARC).
  6. *Decodificación Quishing*: Extracción de payloads maliciosos embebidos en códigos QR usando librerías de visión por computadora.
- **Dependencias**: URLForensicAnalyzer, dnspython, python-whois, pyzbar, Pillow.

---

### Módulo 6: Orquestación de Automatizaciones con n8n
- **Objetivo**: Desacoplar la lógica de notificaciones, escalamiento y tareas programadas en flujos visuales autoalojados de alta resiliencia.
- **Flujos Implementados**:
  1. Ingesta periódica de feeds cada 4 horas.
  2. Despacho multicanal de alertas críticas (Slack, Microsoft Teams, SMS Twilio).
  3. Escalamiento de incidentes por SLA vencido cada 5 minutos.
  4. Generación y distribución de reporte ejecutivo semanal para el CISO.
  5. Automatización de Takedown registral y actualización de DNS Sinkhole.
- **Dependencias**: n8n container, webhooks HTTP autenticados, integraciones API.

---

### Módulo 7: Integración con LLMs mediante LangChain y LangFlow
- **Objetivo**: Proporcionar razonamiento semántico avanzado, explicabilidad forense y asistencia interactiva a los analistas del SOC.
- **Módulos con IA**:
  - *Agente Forense LangChain*: Razona sobre artefactos sospechosos y estructura la salida en formato JSON estricto con técnicas MITRE ATT&CK.
  - *RAG sobre TTPs Bancarios*: Búsqueda semántica en base vectorial sobre procedimientos de mitigación y marcos NIST.
  - *SOC Copilot*: Chatbot especializado que guía al analista L1 en el triaje de campañas complejas (Quishing, Sitios Clonados).
  - *LangFlow*: Entorno visual para que los ingenieros de detección del banco experimenten con nuevos grafos de prompts sin recompilar el backend.
- **Dependencias**: LangChain, LangFlow, Ollama (Llama 3 8B), AzureChatOpenAI.

---

## 2. Módulos Adicionales Recomendados (Justificación Bancaria)

1. **Gestión de Incidentes y Casos SOC**: Necesario para garantizar trazabilidad formal de expedientes bajo el estándar NIST SP 800-61r2 y control riguroso de SLAs de respuesta.
2. **Motor de Reglas y Listas Dinámicas**: Permite al SOC añadir IOCs de emergencia (bloqueo instantáneo de URLs o IPs) sin requerir despliegues de software.
3. **Integración con Threat Intelligence Feeds**: Conexión con VirusTotal, PhishTank y AbuseIPDB para enriquecimiento de reputación externa.
4. **Simulador de Campañas de Phishing Educativo**: Permite evaluar la resiliencia del personal bancario frente a técnicas emergentes de ingeniería social.
5. **Módulo de Reporte del Empleado (Botón de Phishing)**: Convierte a los empleados de sucursales en sensores activos de seguridad, canalizando correos dudosos directamente al pipeline de triaje.
6. **Notificaciones Multicanal**: Reduce el tiempo de respuesta enviando alertas críticas inmediatamente a los canales donde opera el equipo (Teams, Slack, SMS).
7. **Auditoría y Logging Centralizado Inmutable**: Obligatorio por PCI-DSS Req 10; cada acción de analistas y administradores queda registrada con hash encadenado SHA-256 para prevenir manipulación forense.
8. **Gestión de Secretos con HashiCorp Vault**: Elimina credenciales quemadas en código y gestiona la rotación dinámica de API keys y certificados TLS.
9. **Panel de Reentrenamiento y Evaluación de Modelos**: Permite calibrar los clasificadores de Machine Learning con telemetría propia del banco y medir la deriva del concepto (data drift).
10. **API Pública Documentada (OpenAPI)**: Facilita la integración bidireccional con el SIEM bancario (Splunk, QRadar, Sentinel) y el SOAR institucional.
11. **Módulo de Threat Hunting**: Permite a analistas senior ejecutar búsquedas avanzadas por expresiones regulares o consultas difusas sobre millones de artefactos históricos.
12. **Módulo de Cumplimiento y Evidencias**: Genera paquetes de evidencia criptográficamente sellados para presentar ante auditores de PCI-DSS, ISO 27001 o la Superintendencia Bancaria.

