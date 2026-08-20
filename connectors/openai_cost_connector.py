"""Arckon — OpenAI organization costs connector.

OpenAI exposes organization-wide billed costs through its Administration API.  That
endpoint requires an Admin API key; project keys can make model requests but
cannot read organization spend.
"""
from __future__ import annotations

import json
import logging
import time as time_module
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from connectors.cost_connector import CostConnector, SpendRecord

_OPENAI_API_URL = "https://api.openai.com"
_MAX_DAYS_PER_REQUEST = 31
log = logging.getLogger(__name__)

class OpenAICostConnector(CostConnector):
    provider = "openai"

    def __init__(self, api_key: str = "", base_url: str = _OPENAI_API_URL) -> None:
        super().__init__(api_key)
        self.base_url = base_url.rstrip("/")

    def fetch_usage(
        self,
        start_date: date,
        end_date: date | None = None,
    ) -> list[SpendRecord]:
        if not self.api_key:
            raise ValueError("OpenAI Admin API key is required")
        if not self.api_key.startswith("sk-admin-"):
            raise ValueError(
                "OpenAI spend tracking requires an Admin API key (sk-admin-...), "
                "not a project key (sk-proj-...)"
            )

        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date

        records: list[SpendRecord] = []
        chunk_start = start_date
        while chunk_start <= end:
            chunk_end = min(chunk_start + timedelta(days=_MAX_DAYS_PER_REQUEST - 1), end)
            records.extend(self._fetch_range(chunk_start, chunk_end))
            records.extend(self._fetch_completion_usage_range(chunk_start, chunk_end))
            chunk_start = chunk_end + timedelta(days=1)
        return records

    def _fetch_range(self, start_date: date, end_date: date) -> list[SpendRecord]:
        start_time = int(datetime.combine(start_date, time.min, tzinfo=timezone.utc).timestamp())
        end_time = int(datetime.combine(
            end_date + timedelta(days=1), time.min, tzinfo=timezone.utc).timestamp())
        params: list[tuple[str, str]] = [
            ("start_time", str(start_time)),
            ("end_time", str(end_time)),
            ("bucket_width", "1d"),
            ("group_by", "line_item"),
            ("limit", str(_MAX_DAYS_PER_REQUEST)),
        ]
        page: str | None = None
        buckets: list[dict[str, Any]] = []
        while True:
            query = list(params)
            if page:
                query.append(("page", page))
            url = f"{self.base_url}/v1/organization/costs?{urllib.parse.urlencode(query)}"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "User-Agent": "Arckon/1.0 (https://arckon.riskraven.ai)",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        body = json.loads(resp.read().decode())
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                        log.warning("OpenAI Organization Costs API HTTP %s; retrying", e.code)
                        time_module.sleep(2 ** attempt)
                        continue
                    if e.code in (401, 403):
                        raise RuntimeError(
                            "OpenAI Organization Costs API access denied; configure an "
                            "OpenAI Admin API key (sk-admin-...), not a project key"
                        ) from e
                    log.warning("OpenAI Organization Costs API HTTP %s", e.code)
                    raise RuntimeError(f"OpenAI Organization Costs API HTTP {e.code}") from e
                except urllib.error.URLError as e:
                    if attempt < 2:
                        log.warning("OpenAI Organization Costs API connection error; retrying")
                        time_module.sleep(2 ** attempt)
                        continue
                    raise RuntimeError("OpenAI Organization Costs API connection error") from e

            data = body.get("data", [])
            if not isinstance(data, list):
                raise RuntimeError("OpenAI Organization Costs API returned an invalid data payload")
            buckets.extend(bucket for bucket in data if isinstance(bucket, dict))
            if not body.get("has_more"):
                break
            page = body.get("next_page")
            if not page:
                raise RuntimeError("OpenAI Organization Costs API returned has_more without next_page")

        out: list[SpendRecord] = []
        for bucket in buckets:
            bucket_start = bucket.get("start_time")
            if not isinstance(bucket_start, int):
                continue
            period_date = datetime.fromtimestamp(bucket_start, tz=timezone.utc).date().isoformat()
            for entry in bucket.get("results", []):
                if not isinstance(entry, dict):
                    continue
                amount = entry.get("amount")
                if not isinstance(amount, dict):
                    continue
                try:
                    cost_usd = float(amount.get("value"))
                except (TypeError, ValueError):
                    continue
                out.append(SpendRecord(
                    provider=self.provider,
                    model=entry.get("line_item") or "OpenAI organization cost",
                    period_date=period_date,
                    cost_usd=round(cost_usd, 6),
                    currency=str(amount.get("currency") or "USD").upper(),
                    raw_snapshot=self._serialize_raw(entry),
                ))
        return out

    def _fetch_completion_usage_range(self, start_date: date, end_date: date) -> list[SpendRecord]:
        """Fetch daily completion tokens by model from the Organization Usage API."""
        start_time = int(datetime.combine(start_date, time.min, tzinfo=timezone.utc).timestamp())
        end_time = int(datetime.combine(
            end_date + timedelta(days=1), time.min, tzinfo=timezone.utc).timestamp())
        params: list[tuple[str, str]] = [
            ("start_time", str(start_time)),
            ("end_time", str(end_time)),
            ("bucket_width", "1d"),
            ("group_by", "model"),
            ("limit", str(_MAX_DAYS_PER_REQUEST)),
        ]
        page: str | None = None
        buckets: list[dict[str, Any]] = []
        while True:
            query = list(params)
            if page:
                query.append(("page", page))
            url = f"{self.base_url}/v1/organization/usage/completions?{urllib.parse.urlencode(query)}"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "User-Agent": "Arckon/1.0 (https://arckon.riskraven.ai)",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        body = json.loads(resp.read().decode())
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                        log.warning("OpenAI Organization Usage API HTTP %s; retrying", e.code)
                        time_module.sleep(2 ** attempt)
                        continue
                    if e.code in (401, 403):
                        raise RuntimeError(
                            "OpenAI Organization Usage API access denied; configure an "
                            "OpenAI Admin API key (sk-admin-...), not a project key"
                        ) from e
                    raise RuntimeError(f"OpenAI Organization Usage API HTTP {e.code}") from e
                except urllib.error.URLError as e:
                    if attempt < 2:
                        time_module.sleep(2 ** attempt)
                        continue
                    raise RuntimeError("OpenAI Organization Usage API connection error") from e

            data = body.get("data", [])
            if not isinstance(data, list):
                raise RuntimeError("OpenAI Organization Usage API returned an invalid data payload")
            buckets.extend(bucket for bucket in data if isinstance(bucket, dict))
            if not body.get("has_more"):
                break
            page = body.get("next_page")
            if not page:
                raise RuntimeError("OpenAI Organization Usage API returned has_more without next_page")

        out: list[SpendRecord] = []
        for bucket in buckets:
            bucket_start = bucket.get("start_time")
            if not isinstance(bucket_start, int):
                continue
            period_date = datetime.fromtimestamp(bucket_start, tz=timezone.utc).date().isoformat()
            for entry in bucket.get("results", []):
                if not isinstance(entry, dict):
                    continue
                input_tokens = int(entry.get("input_tokens") or 0)
                output_tokens = int(entry.get("output_tokens") or 0)
                if not input_tokens and not output_tokens:
                    continue
                out.append(SpendRecord(
                    provider=self.provider,
                    model=str(entry.get("model") or "OpenAI completions"),
                    period_date=period_date,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    request_count=int(entry.get("num_model_requests") or 0),
                    raw_snapshot=self._serialize_raw(entry),
                ))
        return out
