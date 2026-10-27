# 02. Modelo de Datos y Esquema Relacional (PostgreSQL 15+)

## 1. Diagrama Entidad-Relación (ERD)

```mermaid
erDiagram
    USERS ||--o{ USER_ROLES : "posee"
    ROLES ||--o{ USER_ROLES : "asignado_a"
    USERS ||--o{ INCIDENTS : "investiga"
    USERS ||--o{ AUDIT_LOGS : "genera"
    
    INCIDENTS ||--|{ ARTIFACT_EVIDENCES : "contiene"
    INCIDENTS ||--|| ANALYSIS_RESULTS : "evaluado_por"
    
    PUBLIC_DATASETS ||--|{ DATASET_RECORDS : "almacena"
    
    INDICATORS_OF_COMPROMISE {
        uuid id PK
        string ioc_type
        string value
        string source
        int reputation_score
        boolean is_active
        jsonb tags
        timestamp first_seen_at
        timestamp last_seen_at
    }

    INCIDENTS {
        uuid id PK
        string incident_number UK
        string channel
        string severity
        string status
        string title
        string target_brand
        timestamp sla_due_at
        timestamp first_response_at
        timestamp resolved_at
        uuid assigned_analyst_id FK
        timestamp created_at
    }

    ARTIFACT_EVIDENCES {
        uuid id PK
        uuid incident_id FK
        string artifact_type
        text raw_content
        jsonb extracted_urls
        jsonb sender_metadata
        jsonb file_hashes
        string storage_path
        timestamp created_at
    }

    ANALYSIS_RESULTS {
        uuid id PK
        uuid incident_id FK,UK
        string verdict
        float confidence_score
        float heuristic_score
        float threat_intel_score
        float ml_classifier_score
        float llm_reasoning_score
        boolean typosquatting_detected
        boolean homograph_detected
        text llm_executive_summary
        jsonb llm_recommended_actions
        timestamp evaluated_at
    }

    AUDIT_LOGS {
        uuid id PK
        timestamp timestamp
        uuid actor_id FK
        string actor_username
        string action
        string resource_type
        string resource_id
        string ip_address
        jsonb details
        string previous_hash
        string record_hash
    }

    PUBLIC_DATASETS {
        uuid id PK
        string name UK
        string source_url
        string license
        string version
        int total_records
        string checksum_sha256
        timestamp ingested_at
    }

    DATASET_RECORDS {
        uuid id PK
        uuid dataset_id FK
        string record_type
        text target_value
        boolean is_phishing
        jsonb extracted_features
        boolean verified_online
    }
```

---

## 2. Estrategia de Índices y Optimización
Para satisfacer latencias menores a 50 milisegundos en peticiones del SOC:

1. **Extensiones Habilitadas**:
   - `pg_trgm`: Búsqueda difusa de dominios similares (`CREATE INDEX idx_iocs_value_trgm ON indicators_of_compromise USING gin (value gin_trgm_ops);`). Permite detectar al instante intentos de typosquatting y dominios registrados similares a la entidad bancaria.
   - `uuid-ossp` & `pgcrypto`: Generación criptográfica segura de identificadores y hashing HMAC-SHA256 para auditoría inmutable.
2. **Índices B-Tree Compuestos**:
   - `(channel, status, severity)` en tabla `incidents` para filtros concurrentes en el panel web de React.
   - `(ioc_type, value)` en `indicators_of_compromise` para chequeo en tiempo constante O(log N) durante el filtrado perimetral.
3. **Índices GIN sobre JSONB**:
   - `extracted_urls` y `tags` para consultas sobre telemetría sin desnormalizar tablas auxiliares.

---

## 3. Particionamiento de Tablas y Política de Retención (PCI-DSS Req 10.7)

### 3.1 Particionamiento por Rango Temporal (`RANGE Partitioning`)
Las tablas con alto volumen transaccional (`incidents`, `artifact_evidences` y `audit_logs`) se particionan mensualmente por su campo temporal:
```sql
CREATE TABLE incidents (
    id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ...
) PARTITION BY RANGE (created_at);

-- Partición de ejemplo para Octubre 2026
CREATE TABLE incidents_2026_10 PARTITION OF incidents
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
```

### 3.2 Niveles de Almacenamiento (Hot / Cold Tiering)
- **Nivel Caliente (Hot - 0 a 90 días)**: Almacenado en SSD NVMe de alto rendimiento en PostgreSQL. Acceso instantáneo para el SOC y consultas en vivo.
- **Nivel Tibio (Warm - 91 a 365 días)**: Particiones en almacenamiento estándar. Disponibles para reportes regulatorios trimestrales y auditorías PCI-DSS.
- **Nivel Frío (Cold - 1 a 5 años)**: Volcados periódicos en formato Parquet comprimido con Snappy, cifrados con AES-256 en buckets de almacenamiento inmutable (WORM - Write Once, Read Many) para cumplimiento normativo de retención legal bancaria.

