"""
Router de Ingesta, Versionado y Linaje del Dataset Público de Phishing (Pipeline ETL).
Soporta ejecución en vivo del pipeline ETL, inspección de esquema, licencia y vectores de características.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domain.models.models import PublicDataset, DatasetRecord
from app.infrastructure.etl.dataset_ingestor import PhishingDatasetETLPipeline
from app.api.v1.endpoints.auth import append_immutable_audit_log

router = APIRouter()


class TriggerETLRequest(BaseModel):
    dataset_name: str = Field(default="PhishTank-Validated-Feed + Kaggle-Banking-Phishing")
    version: Optional[str] = None
    limit_records: int = Field(default=100, ge=1, le=1000)


@router.get("/")
async def list_public_datasets(db: AsyncSession = Depends(get_db)):
    """Retorna el catálogo versionado de datasets públicos ingeridos junto con metadatos de fuente y licencia."""
    stmt = select(PublicDataset).order_by(desc(PublicDataset.ingested_at))
    res = await db.execute(stmt)
    datasets = res.scalars().all()

    return {
        "dataset_specification": {
            "primary_source": "PhishTank Validated Online Phishes (http://data.phishtank.com/data/online-valid.json)",
            "secondary_source": "Kaggle Phishing Email Dataset & UCI Phishing Websites Corpus",
            "license": "Open Data Commons Attribution License (ODC-By) / CC BY 4.0",
            "schema_fields": [
                "phish_id (int)", "url (text)", "target_brand (varchar)", "verified (bool)",
                "entropy (float)", "homograph_flag (bool)", "typosquatting_flag (bool)", "similarity_ratio (float)"
            ],
            "etl_stages": [
                "1. Extract (HTTP Stream / API Feed)",
                "2. Validate & Sanitize (Checksum SHA-256 + RFC 3986 URL Filter + Deduplication)",
                "3. Transform (Shannon Entropy + Punycode IDN + Jaro-Winkler Brand Distance)",
                "4. Load (PostgreSQL Async Batch Insert + GIN/B-Tree Indexing)",
                "5. Lineage & Versioning (SHA-256 Snapshot + DVC Tracking)"
            ]
        },
        "versions": [
            {
                "id": str(d.id),
                "name": d.name,
                "source_url": d.source_url,
                "license": d.license,
                "version": d.version,
                "total_records": d.total_records,
                "verified_phish_count": d.verified_phish_count,
                "checksum_sha256": d.checksum_sha256,
                "ingested_at": d.ingested_at.isoformat()
            }
            for d in datasets
        ]
    }


@router.post("/ingest")
async def trigger_etl_pipeline(
    payload: TriggerETLRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Ejecuta el pipeline ETL completo de ingesta, validación, transformación de features y versionado."""
    version_tag = payload.version or f"v{datetime.now(timezone.utc).strftime('%Y.%m.%d-%H%M%S')}"
    pipeline = PhishingDatasetETLPipeline(db)
    result = await pipeline.run_pipeline(
        dataset_name=payload.dataset_name,
        version=version_tag,
        limit_records=payload.limit_records
    )

    client_ip = request.client.host if request.client else "127.0.0.1"
    await append_immutable_audit_log(
        db, "etl_orchestrator", "DATASET_ETL_INGESTED", "PUBLIC_DATASET", result["dataset_id"], client_ip,
        {"version": version_tag, "total_loaded": result["total_loaded"], "checksum": result["checksum_sha256"]}
    )
    await db.commit()
    return result


@router.get("/records")
async def list_dataset_records(limit: int = 30, db: AsyncSession = Depends(get_db)):
    """Obtiene los registros unitarios transformados en el Feature Store con sus vectores heurísticos."""
    stmt = select(DatasetRecord).order_by(desc(DatasetRecord.id)).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [
        {
            "id": str(r.id),
            "dataset_id": str(r.dataset_id),
            "record_type": r.record_type,
            "target_value": r.target_value,
            "is_phishing": r.is_phishing,
            "extracted_features": r.extracted_features,
            "verified_online": r.verified_online
        }
        for r in records
    ]

