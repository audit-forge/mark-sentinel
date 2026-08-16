"""
Arckon — Base cost/usage connector for AI model spend tracking.

This module defines a common schema and base class for fetching token usage
and estimated cost from AI providers.  Connectors are read-only and intentionally
do not store credentials: callers must supply API keys or secret paths.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any


@dataclass
class SpendRecord:
    """Normalized spend record across all supported AI providers."""

    provider: str
    model: str
    period_date: str  # ISO-8601 date, e.g. "2026-08-14"
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    currency: str = "USD"
    raw_snapshot: str = ""
    request_count: int | None = None

    def __post_init__(self) -> None:
        if not self.total_tokens:
            self.total_tokens = self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CostConnector(ABC):
    """Abstract base for a provider-specific cost/usage connector."""

    provider: str = ""

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    @abstractmethod
    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        """Fetch normalized spend records for the requested date range."""

    @staticmethod
    def _date_range(
        start_date: date,
        end_date: date | None = None,
    ) -> list[date]:
        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date
        days = (end - start_date).days
        return [start_date + timedelta(days=d) for d in range(days + 1)]

    @staticmethod
    def _today() -> date:
        return datetime.now(timezone.utc).date()

    @staticmethod
    def _serialize_raw(raw: Any) -> str:
        return json.dumps(raw, default=str, separators=(",", ":"))
