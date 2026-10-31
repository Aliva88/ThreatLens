"""Services connecting the API to the existing ThreatLens engine."""

from functools import lru_cache

from src.enrichers.registry import build_enrichers, enrich_ioc
from src.models import IOC, IOCType
from src.storage import InvestigationStore
from src.utils.config import Config
from src.utils.quota import RequestBudget
from src.utils.security import validate_ioc


@lru_cache(maxsize=1)
def get_api_resources():
    """Create API-specific configuration and isolated storage once."""
    config = Config()
    store = InvestigationStore(".threatlens/api-investigations.db")
    return config, store


def enrich_observable(value: str, ioc_type: IOCType) -> dict:
    """Validate and enrich one IOC using existing ThreatLens providers."""
    canonical_value = validate_ioc(value, ioc_type)

    config, store = get_api_resources()

    # A fresh budget is created for each enrichment request.
    request_budget = RequestBudget(config.max_requests)

    enrichers = build_enrichers(
        config,
        request_budget=request_budget,
        store=store,
    )

    ioc = IOC(value=canonical_value, ioc_type=ioc_type)
    result = enrich_ioc(ioc, enrichers)

    return result.to_dict()
