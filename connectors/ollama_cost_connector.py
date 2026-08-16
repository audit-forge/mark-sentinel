"""Arckon Ollama token-usage connector.

Ollama has no account-wide historical usage or billing API. Token usage can
only be captured prospectively from generate/chat response metadata.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import date
from typing import Any

from connectors.cost_connector import CostConnector, SpendRecord

_OLLAMA_API_URL = "http://localhost:11434"


class OllamaCostConnector(CostConnector):
    provider = "ollama"

    def __init__(self, base_url: str = _OLLAMA_API_URL) -> None:
        super().__init__(api_key="")
        self.base_url = base_url.rstrip("/")

    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        # There is no historical endpoint to poll. Returning no records avoids
        # presenting fabricated zero-cost days as fetched provider data.
        return []

    def fetch_from_response(self, model: str, response_json: dict[str, Any]) -> SpendRecord:
        """Estimate usage from an Ollama generate/chat response object."""
        try:
            usage = response_json.get("usage", {})
            prompt_eval = usage.get("prompt_eval_count") or response_json.get("prompt_eval_count", 0)
            eval_count = usage.get("eval_count") or response_json.get("eval_count", 0)
            return SpendRecord(
                provider=self.provider,
                model=model,
                period_date=self._today().isoformat(),
                input_tokens=int(prompt_eval),
                output_tokens=int(eval_count),
                cost_usd=0.0,
                raw_snapshot=self._serialize_raw(response_json),
            )
        except (ValueError, TypeError):
            return SpendRecord(
                provider=self.provider,
                model=model or "unknown",
                period_date=self._today().isoformat(),
                cost_usd=0.0,
                raw_snapshot=self._serialize_raw(response_json),
            )
