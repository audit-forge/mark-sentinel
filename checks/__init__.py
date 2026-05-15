from dataclasses import dataclass, field

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"
NA   = "N/A"

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
STATUS_RANK = {FAIL: 0, WARN: 1, PASS: 2, SKIP: 3, NA: 4}


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str
    severity: str
    category: str
    details: str
    evidence: list = field(default_factory=list)
    remediation: str = ""
    frameworks: dict = field(default_factory=dict)
