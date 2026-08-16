"""Arckon Anthropic Usage & Cost Admin API connector."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from connectors.cost_connector import CostConnector, SpendRecord


_ANTHROPIC_API_URL = "https://api.anthropic.com"
_MAX_DAYS_PER_USAGE_REQUEST = 31


class AnthropicCostConnector(CostConnector):
    """Fetch authoritative Claude Platform organization usage and costs.

    Anthropic exposes these reports only to organization Admin API keys. Normal
    Messages API keys cannot retrieve account-level spend.
    """

    provider = "anthropic"

    def __init__(self, api_key: str = "", base_url: str = _ANTHROPIC_API_URL) -> None:
        super().__init__(api_key)
        self.base_url = base_url.rstrip("/")

    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        if not self.api_key:
            raise ValueError("Anthropic Admin API key is required")
        if not self.api_key.startswith("sk-ant-admin01-"):
            raise ValueError(
                "Anthropic spend tracking requires an Admin API key "
                "(sk-ant-admin01-...), not a standard Claude API key"
            )

        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date

        usage_buckets: list[dict[str, Any]] = []
        cost_buckets: list[dict[str, Any]] = []
        chunk_start = start_date
        while chunk_start <= end:
            chunk_end = min(chunk_start + timedelta(days=_MAX_DAYS_PER_USAGE_REQUEST - 1), end)
            usage_buckets.extend(self._fetch_report(
                "/v1/organizations/usage_report/messages", chunk_start, chunk_end,
                ["model"],
            ))
            cost_buckets.extend(self._fetch_report(
                "/v1/organizations/cost_report", chunk_start, chunk_end,
                ["description"],
            ))
            chunk_start = chunk_end + timedelta(days=1)

        return self._merge_reports(usage_buckets, cost_buckets)

    def _fetch_report(
        self,
        path: str,
        start_date: date,
        end_date: date,
        group_by: list[str],
    ) -> list[dict[str, Any]]:
        params: list[tuple[str, str]] = [
            ("starting_at", f"{start_date.isoformat()}T00:00:00Z"),
            ("ending_at", f"{(end_date + timedelta(days=1)).isoformat()}T00:00:00Z"),
            ("bucket_width", "1d"),
            ("limit", str(_MAX_DAYS_PER_USAGE_REQUEST)),
        ]
        params.extend(("group_by[]", value) for value in group_by)
        page: str | None = None
        buckets: list[dict[str, Any]] = []

        while True:
            query = list(params)
            if page:
                query.append(("page", page))
            url = f"{self.base_url}{path}?{urllib.parse.urlencode(query)}"
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "Arckon/1.0 (https://arckon.riskraven.ai)",
                "Accept": "application/json",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    raise RuntimeError(
                        "Anthropic Admin Usage & Cost API access denied; use an Admin API key "
                        "(sk-ant-admin01-...) for an Anthropic Organization"
                    ) from exc
                raise RuntimeError(f"Anthropic Usage & Cost API HTTP {exc.code}: {exc.read().decode()}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"Anthropic Usage & Cost API connection error: {exc.reason}") from exc

            buckets.extend(item for item in body.get("data", []) if isinstance(item, dict))
            if not body.get("has_more"):
                return buckets
            page = body.get("next_page")
            if not page:
                raise RuntimeError("Anthropic Usage & Cost API returned has_more without next_page")

    def _merge_reports(
        self,
        usage_buckets: list[dict[str, Any]],
        cost_buckets: list[dict[str, Any]],
    ) -> list[SpendRecord]:
        merged: dict[tuple[str, str], dict[str, Any]] = {}

        for bucket in usage_buckets:
            period_date = str(bucket.get("starting_at", ""))[:10]
            if not period_date:
                continue
            for result in bucket.get("results", []):
                if not isinstance(result, dict):
                    continue
                model = result.get("model") or "unknown"
                entry = merged.setdefault((period_date, model), {
                    "input_tokens": 0, "output_tokens": 0, "cost_usd": Decimal("0"),
                    "usage": [], "cost": [],
                })
                cache_creation = result.get("cache_creation") or {}
                entry["input_tokens"] += self._as_int(result.get("uncached_input_tokens"))
                entry["input_tokens"] += self._as_int(result.get("cache_read_input_tokens"))
                entry["input_tokens"] += self._as_int(cache_creation.get("ephemeral_1h_input_tokens"))
                entry["input_tokens"] += self._as_int(cache_creation.get("ephemeral_5m_input_tokens"))
                entry["output_tokens"] += self._as_int(result.get("output_tokens"))
                entry["usage"].append(result)

        for bucket in cost_buckets:
            period_date = str(bucket.get("starting_at", ""))[:10]
            if not period_date:
                continue
            for result in bucket.get("results", []):
                if not isinstance(result, dict):
                    continue
                # Non-token services have no model. Preserve their billed cost under
                # a stable label instead of dropping it from the organization total.
                model = result.get("model") or result.get("cost_type") or "other"
                entry = merged.setdefault((period_date, model), {
                    "input_tokens": 0, "output_tokens": 0, "cost_usd": Decimal("0"),
                    "usage": [], "cost": [],
                })
                entry["cost_usd"] += self._cents_to_usd(result.get("amount"))
                entry["cost"].append(result)

        records: list[SpendRecord] = []
        for (period_date, model), entry in sorted(merged.items()):
            records.append(SpendRecord(
                provider=self.provider,
                model=model,
                period_date=period_date,
                input_tokens=entry["input_tokens"],
                output_tokens=entry["output_tokens"],
                cost_usd=float(entry["cost_usd"]),
                raw_snapshot=self._serialize_raw({"usage": entry["usage"], "cost": entry["cost"]}),
            ))
        return records

    @staticmethod
    def _as_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _cents_to_usd(value: Any) -> Decimal:
        try:
            return Decimal(str(value or "0")) / Decimal("100")
        except (InvalidOperation, ValueError):
            return Decimal("0")
