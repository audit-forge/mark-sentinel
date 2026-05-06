"""
M.A.R.K. Sentinel — Presidio PII Connector
Optional enhancement for AI-OUT-002 (PII detection in config files and live responses).

Install:
  pip install presidio-analyzer
  python -m spacy download en_core_web_lg
"""
try:
    from presidio_analyzer import AnalyzerEngine as _Engine
    _analyzer = _Engine()
    HAS_PRESIDIO = True
except (ImportError, OSError):
    _analyzer = None
    HAS_PRESIDIO = False

_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
    "IBAN_CODE", "IP_ADDRESS", "LOCATION", "US_PASSPORT", "US_DRIVER_LICENSE",
    "MEDICAL_LICENSE",
]

_MIN_SCORE = 0.7

# Don't flag these as PII — they appear in config files legitimately
_ALLOWLIST_PATTERNS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "example.com",
    "your-domain.com", "yourdomain.com", "placeholder",
})


def analyze(text: str, language: str = "en") -> list:
    """Return PII hits above the confidence threshold as dicts."""
    if not HAS_PRESIDIO or not text:
        return []
    try:
        results = _analyzer.analyze(text=text, entities=_ENTITIES, language=language)
        hits = []
        for r in results:
            if r.score < _MIN_SCORE:
                continue
            snippet = text[r.start:r.end].strip()
            if snippet.lower() in _ALLOWLIST_PATTERNS:
                continue
            hits.append({
                "entity_type": r.entity_type,
                "text": snippet,
                "score": round(r.score, 2),
            })
        return hits
    except Exception:
        return []


def has_pii(text: str, language: str = "en") -> tuple:
    """Return (found: bool, evidence: list[str]) for text."""
    hits = analyze(text, language)
    evidence = [
        f"{h['entity_type']}: {repr(h['text'])} (confidence={h['score']})"
        for h in hits
    ]
    return bool(evidence), evidence


def scan_files_for_pii(files: dict, max_files: int = 50) -> list:
    """Scan a {path: content} dict for PII. Returns evidence strings."""
    evidence = []
    checked = 0
    for path, content in files.items():
        if checked >= max_files:
            break
        # Only scan files that might contain config/data, not generated artifacts
        if any(path.endswith(ext) for ext in ('.py', '.json', '.yaml', '.yml', '.env', '.txt', '.conf', '.ini', '.toml')):
            found, hits = has_pii(content)
            if found:
                for hit in hits[:3]:
                    evidence.append(f"{path}: {hit}")
            checked += 1
    return evidence
