-- Inicialización de extensiones obligatorias de PostgreSQL para Ciberseguridad Bancaria
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Configuración de zona horaria y auditoría
SET timezone = 'UTC';

