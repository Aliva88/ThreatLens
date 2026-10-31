"""FastAPI application for ThreatLens."""

from fastapi import FastAPI, HTTPException

from backend.schemas import IOCEnrichmentRequest
from backend.services import enrich_observable
from src.utils.security import IOCValidationError

app = FastAPI(
    title="ThreatLens API",
    description="API backend for ThreatLens Cyber Threat Intelligence.",
    version="1.0.0",
)


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "ThreatLens API",
    }


@app.post("/api/ioc/enrich")
def enrich_ioc_endpoint(request: IOCEnrichmentRequest):
    try:
        return enrich_observable(request.value, request.ioc_type)
    except IOCValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
