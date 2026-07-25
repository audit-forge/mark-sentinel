#!/usr/bin/env python3
"""Arckon Edge DNS Sensor.

Consumes authorized dnsmasq or Unbound query logs and writes only matched AI
provider-domain events. It does not capture packets, inspect content, or send
data to Arckon Cloud; SaaS ingestion is a separate, authenticated API contract.
"""
import argparse
import json
import logging
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from arckon_version import EDGE_DNS_EVENT_SCHEMA_VERSION, VERSION

LOG = logging.getLogger("arckon-edge-dns")
CATALOG_PATH = Path(__file__).with_name("edge_ai_domains.json")

# dnsmasq: "query[A] chat.openai.com from 192.168.1.143"
_DNSMASQ_QUERY = re.compile(
    r"query\[[^]]+\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)", re.IGNORECASE
)
# Unbound verbosity 1: "info: 192.168.1.143 chat.openai.com. A IN"
_UNBOUND_QUERY = re.compile(
    r"(?:info:\s+)?(?P<client>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<domain>[A-Za-z0-9._-]+)\.?(?:\s+[A-Z]+){1,3}\s*$",
    re.IGNORECASE,
)


def load_catalog(path: Path = CATALOG_PATH) -> list[dict]:
    """Load the reviewed AI-domain catalog without accepting arbitrary regexes."""
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("AI domain catalog must be a JSON list")
    required = {"domain", "provider", "category", "confidence"}
    for entry in entries:
        if not isinstance(entry, dict) or not required.issubset(entry):
            raise ValueError("AI domain catalog entry is missing required fields")
    return entries


def classify_domain(domain: str, catalog: list[dict]) -> dict | None:
    normalized = domain.lower().rstrip(".")
    for entry in catalog:
        suffix = entry["domain"].lower().rstrip(".")
        if normalized == suffix or normalized.endswith("." + suffix):
            return entry
    return None


def parse_query(line: str, source: str) -> tuple[str, str] | None:
    """Return client IPv4 and domain for known resolver query log formats."""
    pattern = _DNSMASQ_QUERY if source == "dnsmasq" else _UNBOUND_QUERY
    match = pattern.search(line)
    if not match:
        return None
    return match.group("client"), match.group("domain").rstrip(".")


def event_for_line(line: str, source: str, sensor_id: str, catalog: list[dict]) -> dict | None:
    parsed = parse_query(line, source)
    if not parsed:
        return None
    client_ip, domain = parsed
    classification = classify_domain(domain, catalog)
    if not classification:
        return None
    return {
        "schema_version": EDGE_DNS_EVENT_SCHEMA_VERSION,
        "event_type": "ai_dns_observed",
        "observed_at": datetime.now(UTC).isoformat(),
        "sensor_id": sensor_id,
        "source_type": source,
        "client_ip": client_ip,
        "query_domain": domain.lower(),
        "provider": classification["provider"],
        "category": classification["category"],
        "confidence": classification["confidence"],
    }


def emit_event(event: dict, out_file: Path | None) -> None:
    encoded = json.dumps(event, separators=(",", ":"), sort_keys=True)
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with out_file.open("a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
    else:
        print(encoded, flush=True)


def process_stream(stream, source: str, sensor_id: str, catalog: list[dict], out_file: Path | None) -> int:
    matched = 0
    for line in stream:
        event = event_for_line(line, source, sensor_id, catalog)
        if event:
            emit_event(event, out_file)
            matched += 1
    return matched


def follow_log(log_file: Path, source: str, sensor_id: str, catalog: list[dict], out_file: Path | None) -> None:
    """Follow appended lines. Log rotation support belongs in the production sensor."""
    with log_file.open("r", encoding="utf-8", errors="replace") as stream:
        stream.seek(0, 2)
        while True:
            line = stream.readline()
            if line:
                event = event_for_line(line, source, sensor_id, catalog)
                if event:
                    emit_event(event, out_file)
            else:
                time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Arckon Edge DNS Sensor")
    parser.add_argument("--log-file", required=True, type=Path, help="Authorized resolver query log")
    parser.add_argument("--source", choices=("dnsmasq", "unbound"), required=True)
    parser.add_argument("--sensor-id", required=True, help="Stable customer-defined sensor identifier")
    parser.add_argument("--out-file", type=Path, help="Write matched events as JSON Lines instead of stdout")
    parser.add_argument("--once", action="store_true", help="Process existing log contents and exit")
    parser.add_argument("--version", action="version", version=f"Arckon Edge DNS Sensor {VERSION}")
    args = parser.parse_args()

    if not args.log_file.is_file():
        parser.error(f"log file does not exist: {args.log_file}")
    try:
        catalog = load_catalog()
        if args.once:
            with args.log_file.open("r", encoding="utf-8", errors="replace") as stream:
                matched = process_stream(stream, args.source, args.sensor_id, catalog, args.out_file)
            LOG.info("processed existing log; emitted %d matched AI DNS event(s)", matched)
        else:
            follow_log(args.log_file, args.source, args.sensor_id, catalog, args.out_file)
    except KeyboardInterrupt:
        LOG.info("sensor stopped")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOG.error("sensor failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()
