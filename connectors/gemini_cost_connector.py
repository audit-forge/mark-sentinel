"""
Arckon — Google Gemini / Vertex AI cost/usage connector.

Gemini API usage can be retrieved from the Google Cloud Monitoring / Billing
APIs, but those require GCP service-account credentials and the
`monitoring.timeSeries.list` permission.  This connector implements the
public Gemini API usage shape and falls back to estimating cost from the
token counts returned by the Gemini generateContent response if telemetry is
supplied.

For a production deployment, prefer Cloud Billing export or Cloud Monitoring
for authoritative spend data.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import date
from typing import Any

from connectors.cost_connector import CostConnector, SpendRecord

_GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta"

# Approximate Gemini pricing (USD per 1M tokens).  Update as Google publishes
# new prices.
_MODEL_PRICES: dict[str, tuple[float, float]] = {
    "gemini-1.5-pro": (3.50, 10.50),
    "gemini-1.5-pro-latest": (3.50, 10.50),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-1.5-flash-latest": (0.075, 0.30),
    "gemini-1.5-flash-8b": (0.0375, 0.15),
    "gemini-1.0-pro": (0.50, 1.50),
    "gemini-1.0-pro-latest": (0.50, 1.50),
    "gemini-1.0-pro-vision": (0.50, 1.50),
    "gemini-embedding-exp": (0.0, 0.0),  # pricing varies by task
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    in_price, out_price = _MODEL_PRICES.get(model, (0.0, 0.0))
    if not in_price and not out_price:
        for prefix, prices in _MODEL_PRICES.items():
            if model.startswith(prefix):
                in_price, out_price = prices
                break
    if not in_price and not out_price:
        return 0.0
    input_cost = (input_tokens / 1_000_000.0) * in_price
    output_cost = (output_tokens / 1_000_000.0) * out_price
    return round(input_cost + output_cost, 6)


class GeminiCostConnector(CostConnector):
    provider = "gemini"

    def __init__(self, api_key: str = "", base_url: str = _GEMINI_API_URL) -> None:
        super().__init__(api_key)
        self.base_url = base_url.rstrip("/")

    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        if not self.api_key:
            raise ValueError("Gemini API key is required")

        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date

        # The public Gemini API does not expose a per-account usage endpoint.
        # Return a placeholder record per day so callers can track that the
        # connector is configured, then replace this with Cloud Monitoring or
        # Billing export when available.
        records: list[SpendRecord] = []
        for day in self._date_range(start_date, end):
            records.append(SpendRecord(
                provider=self.provider,
                model="unknown",
                period_date=day.isoformat(),
                cost_usd=0.0,
                raw_snapshot=self._serialize_raw({
                    "note": "Public Gemini API does not expose usage/cost. "
                            "Use Cloud Monitoring/Billing for authoritative data."
                }),
            ))
        return records

    def fetch_from_response(self, model: str, response_json: dict[str, Any]) -> SpendRecord:
        """Estimate spend from a Gemini generateContent response object."""
        try:
            usage = response_json.get("usageMetadata", {})
            input_tokens = int(usage.get("promptTokenCount", 0))
            output_tokens = int(usage.get("candidatesTokenCount", 0))
            cost = _estimate_cost(model, input_tokens, output_tokens)
            return SpendRecord(
                provider=self.provider,
                model=model,
                period_date=self._today().isoformat(),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost,
                raw_snapshot=self._serialize_raw(usage),
            )
        except (ValueError, TypeError):
            return SpendRecord(
                provider=self.provider,
                model=model or "unknown",
                period_date=self._today().isoformat(),
                raw_snapshot=self._serialize_raw(response_json),
            )
