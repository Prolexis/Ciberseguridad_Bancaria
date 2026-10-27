# 05. Especificación y Documentación de Workflows n8n

La plataforma utiliza **n8n** autoalojado en un contenedor Docker (`aegis_n8n`) como orquestador de procesos y automatizaciones operacionales. Cada flujo está diseñado para operar con idempotencia, manejo de excepciones y bajo autenticación por token seguro.

---

## 1. Catálogo de Workflows Implementados

### Workflow 01: Ingestión Programada de Feeds y Datasets Públicos
- **Archivo de Exportación**: `n8n/workflow_01_feed_ingestion.json`
- **Disparador (Trigger)**: Cron Trigger programado cada 4 horas (`0 */4 * * *`).
- **Nodos del Flujo**:
  1. `Cron Trigger`: Inicia la ejecución periódica.
  2. `HTTP Request (PhishTank Feed)`: Descarga el stream JSON de sitios maliciosos activos (`http://data.phishtank.com/data/online-valid.json`) con timeout de 30 segundos.
  3. `Code (Filtrar y Sanitizar)`: Ejecuta código JavaScript en sandbox para descartar URLs malformadas y seleccionar registros verificados (`verified === 'yes'`).
  4. `HTTP Request (POST a Backend ETL)`: Envía el lote filtrado hacia el endpoint interno `/api/v1/datasets/ingest-batch` autenticado con cabecera `X-Aegis-Auth`.
  5. `Slack (Notificación SOC)`: Notifica al canal `#soc-telemetria` con el total de registros incorporados al feature store.
- **Salida**: Ingesta masiva en PostgreSQL y métricas de ejecución.

---

### Workflow 02: Envío Multicanal de Alertas Críticas SOC
- **Archivo de Exportación**: `n8n/workflow_02_critical_alerts.json`
- **Disparador (Trigger)**: Webhook POST `/webhook/aegis-critical-alert` recibido desde el backend cuando se detecta una amenaza con veredicto `MALICIOUS`.
- **Nodos del Flujo**:
  1. `Webhook Inbound`: Recibe el payload del incidente (`incident_number`, `target_url`, `risk_score`).
  2. `IF Node`: Valida si `verdict === 'MALICIOUS'`.
  3. *Ejecución Paralela de Notificaciones*:
     - `Slack Node`: Emite mensaje formateado en canal `#incidentes-criticos`.
     - `Microsoft Teams Node`: Genera tarjeta adaptativa con alerta roja para el equipo del CISO.
     - `Twilio SMS Node`: Envía mensaje SMS de emergencia al teléfono del Coordinador de Turno SOC.
- **Salida**: Alerta multicanal entregada en menos de 5 segundos tras la detección.

---

### Workflow 03: Escalamiento Automático de Incidentes por SLA Vencido
- **Archivo de Exportación**: `n8n/workflow_03_sla_escalation.json`
- **Disparador (Trigger)**: Cron Trigger cada 5 minutos.
- **Nodos del Flujo**:
  1. `Cron Trigger (5 min)`: Sondeo regular.
  2. `HTTP Request (Query Pending Cases)`: Consulta a la API `/api/v1/incidents?status=NEW&limit=50`.
  3. `Code Node (SLA Breached Logic)`: Compara el campo `sla_due_at` con la hora actual. Si el tiempo restante es menor a 15 minutos o ya venció, se clasifica como caso en riesgo.
  4. `HTTP Request (PATCH Status)`: Actualiza el estado a `INVESTIGATING` en el backend con la justificación: `"Escalamiento automático por n8n: SLA comprometido"`.
  5. `Slack Node`: Notifica al canal de supervisión `#soc-jefatura` con el identificador del caso reasignado.
- **Salida**: Reasignación obligatoria de tickets estancados para garantizar el cumplimiento del SLA bancario.

---

### Workflow 04: Generación y Distribución de Reportes Ejecutivos Semanales
- **Archivo de Exportación**: `n8n/workflow_04_weekly_reports.json`
- **Disparador (Trigger)**: Cron Trigger cada lunes a las 07:00 AM (`0 7 * * 1`).
- **Nodos del Flujo**:
  1. `Cron Trigger`: Arranque semanal.
  2. `HTTP Request (Descargar PDF)`: Solicita el archivo binario maquetado con ReportLab al endpoint `/api/v1/reports/export?format=PDF&report_type=EXECUTIVE_CISO`.
  3. `Email Send Node (SMTP Corporativo)`: Adjunta el documento PDF y lo despacha al CISO y al equipo de Auditoría Interna.
- **Salida**: Informe confidencial entregado en la bandeja de entrada del equipo directivo al iniciar la semana.

---

### Workflow 05: Notificación Registral (Abuse Takedown) y DNS Sinkhole
- **Archivo de Exportación**: `n8n/workflow_05_sinkhole_takedown.json`
- **Disparador (Trigger)**: Webhook POST `/webhook/aegis-sinkhole-action` emitido tras la confirmación de un dominio malicioso por parte de un analista L2.
- **Nodos del Flujo**:
  1. `Webhook Inbound`: Recibe FQDN del sitio falso y número de caso.
  2. `HTTP Request (DNS RPZ)`: Inyecta el dominio en la política de bloqueo RPZ del resolver corporativo para redirigir peticiones internas a un servidor honeypot/sinkhole.
  3. `Email Send Node`: Genera y envía formalmente la solicitud de baja por abuso (Abuse Takedown Notice) a la dirección de contacto del registrador del dominio fraudulento con las evidencias RFC 822 adjuntas.
- **Salida**: Aislamiento inmediato de los clientes bancarios frente al dominio clonado.

