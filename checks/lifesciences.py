"""
AI-LS checks — Life Sciences & Pharmaceutical AI Security
Checks: AI-LS-001 through AI-LS-006

Aligned to: FDA 21 CFR Part 11, HIPAA 45 CFR §164, ICH E6(R2) GCP,
            GxP ALCOA+ principles, FDA AI/ML SaMD guidance, NIST AI RMF.

AI-LS-001: 21 CFR Part 11 audit trail            — config mode
AI-LS-002: PHI data leakage protection           — live probe (api/local)
AI-LS-003: Medical misinformation refusal        — live probe (api/local)
AI-LS-004: GxP data integrity (ALCOA+)           — config mode
AI-LS-005: Clinical decision human oversight     — config mode
AI-LS-006: AI model validation documentation     — config mode
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP, NA
from connectors.config_connector import ScanContext

CATEGORY = "AI-LS"

_LS_FW = {
    "FDA 21 CFR Part 11": "§11.10",
    "HIPAA":              "45 CFR §164",
    "ICH E6(R2)":         "GCP 5.5",
    "NIST AI RMF":        "GOVERN 1.1",
}

_AUDIT_LOG_RE = [
    re.compile(r'(?i)audit[_\s-]?(?:log|trail|record)'),
    re.compile(r'(?i)immutable[_\s-]?log'),
    re.compile(r'(?i)electronic[_\s-]?record'),
    re.compile(r'(?i)21\s*cfr\s*part\s*11'),
    re.compile(r'(?i)activity[_\s-]?log(?:ging)?'),
    re.compile(r'(?i)event[_\s-]?log(?:ging)?'),
    re.compile(r'(?i)tamper[_\s-]?evident'),
    re.compile(r'(?i)log[_\s-]?retention'),
]

_ALCOA_RE = [
    re.compile(r'(?i)data[_\s-]?integrity'),
    re.compile(r'(?i)alcoa'),
    re.compile(r'(?i)checksum|hash[_\s-]?verif'),
    re.compile(r'(?i)tamper[_\s-]?(?:evident|proof)'),
    re.compile(r'(?i)attributable'),
    re.compile(r'(?i)contemporaneous'),
    re.compile(r'(?i)(?:data|record)[_\s-]?(?:integrity|authenticity)'),
    re.compile(r'(?i)gxp|glp|gmp|gcp'),
    re.compile(r'(?i)eu\s+annex\s+11'),
]

_OVERSIGHT_RE = [
    re.compile(r'(?i)human[_\s-]?(?:review|oversight|in[_\s-]?the[_\s-]?loop|approval)'),
    re.compile(r'(?i)physician[_\s-]?(?:review|approval|sign[_\s-]?off)'),
    re.compile(r'(?i)clinical[_\s-]?(?:review|oversight|validation)'),
    re.compile(r'(?i)medical[_\s-]?(?:review|approval|officer)'),
    re.compile(r'(?i)manual[_\s-]?(?:verification|confirmation|review)'),
    re.compile(r'(?i)two[_\s-]?(?:person|man|party)[_\s-]?(?:rule|review|check)'),
]

_VALIDATION_RE = [
    re.compile(r'(?i)model[_\s-]?valid(?:ation)?'),
    re.compile(r'(?i)iq\b.*oq\b.*pq\b'),
    re.compile(r'(?i)(?:installation|operational|performance)\s+qualification'),
    re.compile(r'(?i)validation[_\s-]?(?:plan|report|protocol|summary)'),
    re.compile(r'(?i)samd|software\s+as\s+a\s+medical\s+device'),
    re.compile(r'(?i)fda[_\s-]?(?:cleared|approved|510k|pma)'),
    re.compile(r'(?i)intended[_\s-]?use[_\s-]?(?:statement|document)'),
]

_SKIP_LIVE = (
    "This check requires a live AI connection. "
    "Run with --mode api or --mode local to evaluate."
)
_SKIP_LIVE_REM = "Rerun with --mode api --endpoint <url> or --mode local --ollama-host http://localhost:11434"


def _is_live(ctx: ScanContext) -> bool:
    return ctx.mode in ("api", "local") and bool(ctx.probe_results)


def _skip_live(check_id: str, title: str, severity: str = "HIGH") -> CheckResult:
    return CheckResult(
        check_id=check_id, title=title, status=SKIP, severity=severity,
        category=CATEGORY, details=_SKIP_LIVE, remediation=_SKIP_LIVE_REM,
        frameworks=_LS_FW,
    )


def _probe_error(check_id: str, title: str, severity: str, error: str) -> CheckResult:
    return CheckResult(
        check_id=check_id, title=title, status=SKIP, severity=severity,
        category=CATEGORY,
        details=f"Live probe failed: {error}",
        remediation="Verify the endpoint is reachable and the API key is valid.",
        frameworks=_LS_FW,
    )


def check_ls_001(ctx: ScanContext) -> CheckResult:
    """21 CFR Part 11 — Audit Trail for AI Interactions."""
    check_id, title, severity = "AI-LS-001", "AI Interaction Audit Trail (21 CFR Part 11)", "CRITICAL"
    all_text = '\n'.join(ctx.files.values())
    found = [r.pattern for r in _AUDIT_LOG_RE if r.search(all_text)]

    if not found:
        return CheckResult(
            check_id=check_id, title=title, status=WARN, severity=severity,
            category=CATEGORY,
            details=(
                "No audit logging configuration detected. FDA 21 CFR Part 11 requires "
                "every AI interaction touching regulated data to be logged in a tamper-evident, "
                "time-stamped audit trail that is attributable to a specific user."
            ),
            evidence=["No audit_log, tamper-evident, or electronic_records configuration found in scanned files"],
            remediation=(
                "1. Implement an immutable audit log for all AI interactions (query, response, user ID, timestamp).\n"
                "2. Ensure logs cannot be altered or deleted — use append-only storage or a WORM system.\n"
                "3. Include: who made the request, what was asked, what the AI returned, and when.\n"
                "4. Retain logs per your data retention schedule (commonly 2–7 years for regulated data).\n"
                "5. Reference: FDA 21 CFR Part 11 §11.10(e) — audit trails."
            ),
            frameworks={"FDA 21 CFR Part 11": "§11.10(e)", "ICH E6(R2)": "§5.5.3", "GxP": "ALCOA+", "NIST AI RMF": "GOVERN 1.1"},
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details="Audit logging configuration detected in deployment files.",
        evidence=[f"Pattern matched: {p}" for p in found[:3]],
        frameworks={"FDA 21 CFR Part 11": "§11.10(e)", "ICH E6(R2)": "§5.5.3", "GxP": "ALCOA+", "NIST AI RMF": "GOVERN 1.1"},
    )


def check_ls_002(ctx: ScanContext) -> CheckResult:
    """PHI Data Leakage — does the model expose Protected Health Information."""
    check_id, title, severity = "AI-LS-002", "Protected Health Information (PHI) Leakage Prevention", "CRITICAL"
    if not _is_live(ctx):
        return _skip_live(check_id, title, severity)

    r = ctx.probe_results.get("ls-002-a")
    if r is None:
        return _skip_live(check_id, title, severity)
    if r.error:
        return _probe_error(check_id, title, severity, r.error)

    fw = {"HIPAA": "45 CFR §164.312(a)(1)", "FDA 21 CFR Part 11": "§11.10", "NIST AI RMF": "MANAGE 2.4", "ICH E6(R2)": "§2.11"}
    if not r.passed:
        return CheckResult(
            check_id=check_id, title=title, status=FAIL, severity=severity,
            category=CATEGORY,
            details=(
                "The AI model disclosed Protected Health Information (PHI) embedded in its system prompt. "
                "Patient names, medications, clinical trial IDs, or diagnosis codes were revealed in response "
                "to a direct user query — a HIPAA breach risk."
            ),
            evidence=[f"Probe 'ls-002-a': {r.fail_reason}", f"Response excerpt: {r.response[:300]}"],
            remediation=(
                "1. Never embed real PHI in AI system prompts — use anonymized or synthetic data during testing.\n"
                "2. Instruct the model explicitly to never repeat or summarize its system context.\n"
                "3. Apply output filtering to detect and redact PHI patterns before responses reach users.\n"
                "4. Implement role-based access: users should only query AI about their own records via authenticated sessions.\n"
                "5. Conduct a HIPAA risk assessment for all AI systems that touch patient data."
            ),
            frameworks=fw,
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details="PHI canary probe passed — model did not disclose patient record data from its system prompt.",
        evidence=["Probe 'ls-002-a': PHI canary not detected in response"],
        frameworks=fw,
    )


def check_ls_003(ctx: ScanContext) -> CheckResult:
    """Medical Misinformation Refusal — dangerous clinical advice."""
    check_id, title, severity = "AI-LS-003", "Medical Misinformation and Dangerous Advice Refusal", "CRITICAL"
    if not _is_live(ctx):
        return _skip_live(check_id, title, severity)

    probe_ids = ["ls-003-a", "ls-003-b"]
    failed, errors = [], []
    for pid in probe_ids:
        r = ctx.probe_results.get(pid)
        if r is None:
            continue
        if r.error:
            errors.append(r.error)
        elif not r.passed:
            failed.append(r)

    if errors and not failed:
        return _probe_error(check_id, title, severity, errors[0])

    fw = {"FDA AI/ML SaMD": "Predetermined Change Control", "NIST AI RMF": "MEASURE 2.9", "ICH E6(R2)": "§4.8", "HIPAA": "45 CFR §164"}
    if failed:
        return CheckResult(
            check_id=check_id, title=title, status=FAIL, severity=severity,
            category=CATEGORY,
            details=(
                f"{len(failed)} of {len(probe_ids)} medical safety probe(s) failed — "
                "the model provided dangerous clinical advice instead of refusing. "
                "This is a patient safety risk and a potential FDA SaMD compliance violation."
            ),
            evidence=[f"Probe '{f.probe_id}': {f.fail_reason}" for f in failed],
            remediation=(
                "1. Add explicit medical safety instructions to the system prompt: the AI must not provide dosage recommendations, drug synthesis, or treatment plans.\n"
                "2. Implement a content filter that detects clinical advice patterns before responses are returned.\n"
                "3. Route medical queries to a licensed clinical decision support system — not a general-purpose AI.\n"
                "4. If deploying AI in a clinical context, classify it under FDA SaMD guidance and complete the required safety assessment.\n"
                "5. Include a mandatory disclaimer on all AI interfaces used in health contexts."
            ),
            frameworks=fw,
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details=f"All {len(probe_ids)} medical safety probes refused — model declined dangerous clinical requests.",
        evidence=[f"Probe '{pid}': refusal confirmed" for pid in probe_ids if pid in ctx.probe_results],
        frameworks=fw,
    )


def check_ls_004(ctx: ScanContext) -> CheckResult:
    """GxP Data Integrity — ALCOA+ principles in AI data handling."""
    check_id, title, severity = "AI-LS-004", "GxP Data Integrity — ALCOA+ Principles", "HIGH"
    all_text = '\n'.join(ctx.files.values())
    found = [r.pattern for r in _ALCOA_RE if r.search(all_text)]

    if not found:
        return CheckResult(
            check_id=check_id, title=title, status=WARN, severity=severity,
            category=CATEGORY,
            details=(
                "No GxP data integrity controls detected. Pharmaceutical AI systems operating "
                "in regulated environments (GMP, GCP, GLP) must comply with ALCOA+ principles: "
                "data must be Attributable, Legible, Contemporaneous, Original, Accurate, "
                "Complete, Consistent, Enduring, and Available."
            ),
            evidence=["No data_integrity, checksum, ALCOA, GxP, or tamper-evident configuration found"],
            remediation=(
                "1. Store all AI inputs and outputs with timestamps, user IDs, and an integrity hash (e.g., SHA-256).\n"
                "2. Use append-only or WORM storage for regulated AI interaction records.\n"
                "3. Document data flows in your System Validation Plan to demonstrate ALCOA+ compliance.\n"
                "4. For EU operations, reference EU GMP Annex 11 (Computerised Systems).\n"
                "5. Run periodic data integrity checks and log the results."
            ),
            frameworks={"GxP / ALCOA+": "EU Annex 11", "FDA 21 CFR Part 11": "§11.10", "ICH Q10": "§3.2", "NIST AI RMF": "MANAGE 2.2"},
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details="GxP data integrity configuration detected in deployment files.",
        evidence=[f"Pattern matched: {p}" for p in found[:3]],
        frameworks={"GxP / ALCOA+": "EU Annex 11", "FDA 21 CFR Part 11": "§11.10", "ICH Q10": "§3.2", "NIST AI RMF": "MANAGE 2.2"},
    )


def check_ls_005(ctx: ScanContext) -> CheckResult:
    """Clinical Decision Human Oversight — human-in-the-loop for high-risk outputs."""
    check_id, title, severity = "AI-LS-005", "Clinical Decision Human Oversight Requirements", "HIGH"
    all_text = '\n'.join(ctx.files.values())
    found = [r.pattern for r in _OVERSIGHT_RE if r.search(all_text)]

    if not found:
        return CheckResult(
            check_id=check_id, title=title, status=WARN, severity=severity,
            category=CATEGORY,
            details=(
                "No human oversight configuration found for clinical AI outputs. "
                "FDA guidance on AI/ML-based Software as a Medical Device (SaMD) and "
                "ICH E6(R2) Good Clinical Practice require a qualified person to review "
                "AI-generated recommendations before they influence patient care decisions."
            ),
            evidence=["No physician_review, clinical_oversight, or human_in_the_loop configuration found"],
            remediation=(
                "1. Implement a mandatory human review gate for any AI output that informs clinical decisions.\n"
                "2. Document the oversight process: who reviews, what criteria trigger review, and how approvals are recorded.\n"
                "3. Train clinical staff on the AI system's limitations and intended use boundary.\n"
                "4. Classify the AI under FDA SaMD tiers and implement the required risk management process.\n"
                "5. Ensure the AI cannot take autonomous action on patient data without explicit human approval."
            ),
            frameworks={"FDA AI/ML SaMD": "Action Plan", "ICH E6(R2)": "§5.0", "NIST AI RMF": "GOVERN 2.2", "EU MDR": "Annex I §17"},
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details="Human oversight configuration detected for clinical AI outputs.",
        evidence=[f"Pattern matched: {p}" for p in found[:3]],
        frameworks={"FDA AI/ML SaMD": "Action Plan", "ICH E6(R2)": "§5.0", "NIST AI RMF": "GOVERN 2.2", "EU MDR": "Annex I §17"},
    )


def check_ls_006(ctx: ScanContext) -> CheckResult:
    """AI Model Validation Documentation — evidence the model is fit for its intended use."""
    check_id, title, severity = "AI-LS-006", "AI Model Validation Documentation", "HIGH"
    all_text = '\n'.join(ctx.files.values())
    found = [r.pattern for r in _VALIDATION_RE if r.search(all_text)]

    if not found:
        return CheckResult(
            check_id=check_id, title=title, status=WARN, severity=severity,
            category=CATEGORY,
            details=(
                "No model validation documentation detected. FDA and ICH E6(R2) require "
                "documented evidence that any AI system used in regulated processes has been "
                "validated for its intended use — including installation qualification (IQ), "
                "operational qualification (OQ), and performance qualification (PQ)."
            ),
            evidence=["No validation_plan, model_validation, IQ/OQ/PQ, or SaMD documentation found"],
            remediation=(
                "1. Create a Validation Plan that defines the intended use, acceptance criteria, and test cases for the AI system.\n"
                "2. Complete IQ (correct installation), OQ (operates as designed), and PQ (performs in production as expected).\n"
                "3. Document the model version, training data provenance, and performance metrics at the time of validation.\n"
                "4. Establish a change control process: re-validation is required when the model, data, or environment changes.\n"
                "5. Retain all validation records per 21 CFR Part 11 and your document control SOP."
            ),
            frameworks={"FDA 21 CFR Part 11": "§11.10", "ICH Q10": "§4.0", "FDA AI/ML SaMD": "SaMD Action Plan", "NIST AI RMF": "MEASURE 2.5"},
        )

    return CheckResult(
        check_id=check_id, title=title, status=PASS, severity=severity,
        category=CATEGORY,
        details="Model validation documentation detected.",
        evidence=[f"Pattern matched: {p}" for p in found[:3]],
        frameworks={"FDA 21 CFR Part 11": "§11.10", "ICH Q10": "§4.0", "FDA AI/ML SaMD": "SaMD Action Plan", "NIST AI RMF": "MEASURE 2.5"},
    )


def run_all(ctx: ScanContext) -> list:
    return [
        check_ls_001(ctx),
        check_ls_002(ctx),
        check_ls_003(ctx),
        check_ls_004(ctx),
        check_ls_005(ctx),
        check_ls_006(ctx),
    ]
