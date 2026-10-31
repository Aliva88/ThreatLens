"""Request schemas for the ThreatLens API."""

from pydantic import BaseModel, ConfigDict, Field

from src.models import IOCType


class IOCEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=2048)
    ioc_type: IOCType
