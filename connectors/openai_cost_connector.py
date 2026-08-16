"""
Arckon — OpenAI cost/usage connector.

Fetches daily token usage and estimated cost from the OpenAI Usage/Project
APIs.  Cost is estimated using a built-in per-model price table because the
public API does not expose spend directly for many tiers.

https://platform.openai.com/docs/api-reference/usage
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import date, timedelta
from typing import Any

from connectors.cost_connector import CostConnector, SpendRecord

_OPENAI_USAGE_URL = "https://api.openai.com/v1/usage"

# Rough per-model pricing (USD per 1M tokens).  Update as OpenAI publishes
# new prices.  These are estimates; billing dashboards are authoritative.
_MODEL_PRICES: dict[str, tuple[float, float]] = {
    # (input_per_1m, output_per_1m)
    "gpt-4o": (5.00, 15.00),
    "gpt-4o-mini": (0.150, 0.600),
    "gpt-4o-2024-05-13": (5.00, 15.00),
    "gpt-4o-mini-2024-07-18": (0.150, 0.600),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4-turbo-2024-04-09": (10.00, 30.00),
    "gpt-4-0125-preview": (10.00, 30.00),
    "gpt-4-1106-preview": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "gpt-3.5-turbo-0125": (0.50, 1.50),
    "gpt-3.5-turbo-1106": (1.00, 2.00),
    "o1-preview": (15.00, 60.00),
    "o1-preview-2024-09-12": (15.00, 60.00),
    "o1-mini": (3.00, 12.00),
    "o1-mini-2024-09-12": (3.00, 12.00),
    "text-embedding-3-small": (0.02, 0.0),
    "text-embedding-3-large": (0.13, 0.0),
    "text-embedding-ada-002": (0.10, 0.0),
    "dall-e-3": (0.0, 0.0),  # image pricing is per image, not per token
    "whisper-1": (0.0, 0.0),  # audio pricing is per minute
    "tts-1": (0.0, 0.0),  # audio pricing is per 1M chars
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    in_price, out_price = _MODEL_PRICES.get(model, (0.0, 0.0))
    if not in_price and not out_price:
        return 0.0
    input_cost = (input_tokens / 1_000_000.0) * in_price
    output_cost = (output_tokens / 1_000_000.0) * out_price
    return round(input_cost + output_cost, 6)


class OpenAICostConnector(CostConnector):
    provider = "openai"

    def __init__(self, api_key: str = "", base_url: str = _OPENAI_USAGE_URL) -> None:
        super().__init__(api_key)
        self.base_url = base_url.rstrip("/")

    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        if not self.api_key:
            raise ValueError("OpenAI API key is required")

        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date

        records: list[SpendRecord] = []
        for day in self._date_range(start_date, end):
            records.extend(self._fetch_day(day))
        return records

    def _fetch_day(self, day: date) -> list[SpendRecord]:
        # OpenAI usage endpoints generally accept a date query param.
        url = f"{self.base_url}?date={day.isoformat()}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            raise RuntimeError(f"OpenAI usage API HTTP {e.code}: {err_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"OpenAI usage API connection error: {e.reason}") from e

        # The /v1/usage response shape varies by account type.  Support the two
        # most common shapes: a flat list of "data" entries, or nested buckets.
        data = body.get("data", [])
        if not data and "usage" in body:
            data = body.get("usage", [])

        out: list[SpendRecord] = []
        for entry in data:
            try:
                model = entry.get("model") or entry.get("model_id") or "unknown"
                input_tokens = int(entry.get("n_input_tokens", 0) or entry.get("input_tokens", 0))
                output_tokens = int(entry.get("n_output_tokens", 0) or entry.get("output_tokens", 0))
                req_count = entry.get("n_requests") or entry.get("request_count")
                cost = _estimate_cost(model, input_tokens, output_tokens)

                record = SpendRecord(
                    provider=self.provider,
                    model=model,
                    period_date=day.isoformat(),
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=cost,
                    raw_snapshot=self._serialize_raw(entry),
                    request_count=int(req_count) if req_count is not None else None,
                )
                out.append(record)
            except (ValueError, TypeError) as e:
                # Skip malformed entries rather than aborting the whole day.
                continue

        return out
