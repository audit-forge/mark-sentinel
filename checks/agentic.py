"""
AI-AGENT checks — Agentic & Tool Use Safety
Checks: AI-AGENT-001 through AI-AGENT-006

AI-AGENT-003 requires a live probe — SKIP in config mode.
All others are partially evaluable from agent config files.
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-AGENT"

_BROAD_TOOL_RE = [
    re.compile(r'(?i)"path"\s*:\s*"[/\\]"'),          # Root filesystem access
    re.compile(r'(?i)"path"\s*:\s*"~'),               # Home directory access
    re.compile(r'(?i)"(?:url|endpoint)"\s*:\s*"\*"'), # Wildcard URL
    re.compile(r'(?i)"allow[_-]?all"\s*:\s*true'),
    re.compile(r'(?i)"unrestricted"\s*:\s*true'),
    re.compile(r'(?i)"(?:permissions?|scope)"\s*:\s*"(?:admin|all|full|root|\*)"'),
]

_LEAST_PRIV_RE = [
    re.compile(r'(?i)"(?:permissions?|scope)"\s*:\s*"\w'),
    re.compile(r'(?i)"read[_-]?only"\s*:\s*true'),
    re.compile(r'(?i)"allowed[_-]?paths?"\s*:'),
    re.compile(r'(?i)"allowed[_-]?domains?"\s*:'),
    re.compile(r'(?i)"allowlist"\s*:'),
    re.compile(r'(?i)"restrict(?:ed)?[_-]?to"\s*:'),
]

_CONFIRM_RE = [
    re.compile(r'(?i)"require[_-]?confirm(?:ation)?"\s*:\s*true'),
    re.compile(r'(?i)"human[_-]?in[_-]?(?:the[_-]?)?loop"\s*:\s*true'),
    re.compile(r'(?i)"confirm[_-]?(?:destructive|irreversible|before[_-]?action)"\s*:\s*true'),
    re.compile(r'(?i)"approval[_-]?required"\s*:\s*true'),
    re.compile(r'(?i)"hitl"\s*:\s*true'),
    re.compile(r'(?i)confirm(?:ation)?[_-]?gate'),
]

_INTER_AGENT_AUTH_RE = [
    re.compile(r'(?i)"agent[_-]?auth(?:entication)?"\s*:'),
    re.compile(r'(?i)"trust[_-]?(?:level|policy|model)"\s*:'),
    re.compile(r'(?i)"verify[_-]?agent"\s*:\s*true'),
    re.compile(r'(?i)"agent[_-]?(?:token|secret|key)"\s*:'),
    re.compile(r'(?i)"signed[_-]?messages?"\s*:\s*true'),
]

_ACTION_LOG_RE = [
    re.compile(r'(?i)"action[_-]?log(?:ging)?"\s*[=::{]'),
    re.compile(r'(?i)"audit[_-]?trail"\s*:\s*true'),
    re.compile(r'(?i)"log[_-]?(?:tool[_-]?calls?|actions?|tool[_-]?use)"\s*:\s*true'),
    re.compile(r'(?i)"tool[_-]?log(?:ging)?"\s*:\s*true'),
    re.compile(r'(?i)action[_-]?log(?:ger)?\b'),
]

_DOMAIN_ALLOWLIST_RE = [
    re.compile(r'(?i)"(?:allowed[_-]?|approved[_-]?)?domains?"\s*:\s*\['),
    re.compile(r'(?i)"(?:allowed[_-]?|approved[_-]?)?urls?"\s*:\s*\['),
    re.compile(r'(?i)"(?:domain[_-]?|url[_-]?)?allowlist"\s*:'),
    re.compile(r'(?i)"egress[_-]?filter"\s*:'),
    re.compile(r'(?i)"(?:approved|permitted)[_-]?endpoints?"\s*:'),
]

_BROAD_HTTP_RE = [
    re.compile(r'(?i)"http[_-]?(?:get|post|request|fetch)"\s*:\s*\{[^}]*"url"\s*:\s*"\*"'),
    re.compile(r'(?i)"allow[_-]?all[_-]?(?:urls?|domains?|hosts?)"\s*:\s*true'),
    re.compile(r'(?i)"unrestricted[_-]?(?:http|web|internet)"\s*:\s*true'),
]

_TOOLS_RE = re.compile(r'(?i)"tools?"\s*:\s*\[')


def _has_agent_config(ctx: ScanContext) -> bool:
    return bool(ctx.agent_config or ctx.agent_config_raw)


def _agent_config_text(ctx: ScanContext) -> str:
    return ctx.agent_config_raw or ''


def check_agent_001(ctx: ScanContext) -> CheckResult:
    if not _has_agent_config(ctx):
        return CheckResult(
            check_id="AI-AGENT-001",
            title="Tool/Function Permissions Follow Least Privilege",
            status=SKIP,
            severity="CRITICAL",
            category=CATEGORY,
            details="No agent configuration file found (agent_config.json, agent.json, tools.json). Point --target at a directory containing your agent configuration.",
            remediation="Ensure agent_config.json or tools.json is present in the target directory.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-6", "NIST AI RMF": "GOVERN 6.1"},
        )

    text = _agent_config_text(ctx)
    has_broad = any(r.search(text) for r in _BROAD_TOOL_RE)
    has_scoped = any(r.search(text) for r in _LEAST_PRIV_RE)

    if has_broad:
        return CheckResult(
            check_id="AI-AGENT-001",
            title="Tool/Function Permissions Follow Least Privilege",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                "Broad or unrestricted tool permissions detected in agent config. "
                "Overpermissioned tools dramatically increase blast radius if the agent is compromised."
            ),
            evidence=["Broad permission pattern detected (admin/all/root/wildcard scope or unrestricted path)"],
            remediation=(
                "1. Audit each tool in your agent config — ask: does this agent actually need this?\n"
                "2. Remove tools not needed for the agent's defined function.\n"
                "3. Restrict filesystem tools to specific directories (e.g., /workspace/data/ only).\n"
                "4. Restrict HTTP tools to an explicit domain allowlist.\n"
                "5. Use read-only database views for agents that only need to query data."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-6", "NIST AI RMF": "GOVERN 6.1"},
        )
    elif has_scoped:
        return CheckResult(
            check_id="AI-AGENT-001",
            title="Tool/Function Permissions Follow Least Privilege",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="Scoped tool permissions found in agent config.",
            evidence=["Permission scoping found: read_only, allowed_paths, or allowlist configuration"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-6", "NIST AI RMF": "GOVERN 6.1"},
        )
    else:
        return CheckResult(
            check_id="AI-AGENT-001",
            title="Tool/Function Permissions Follow Least Privilege",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details="Agent config found but no explicit permission scoping detected. Cannot confirm least privilege.",
            evidence=["Agent config present but no read_only, allowed_paths, or allowlist settings found"],
            remediation="Add explicit permission scoping to each tool definition (allowed_paths, allowed_domains, read_only).",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-6", "NIST AI RMF": "GOVERN 6.1"},
        )


def check_agent_002(ctx: ScanContext) -> CheckResult:
    if not _has_agent_config(ctx):
        return CheckResult(
            check_id="AI-AGENT-002",
            title="Agent Cannot Take Destructive Actions Without Confirmation",
            status=SKIP,
            severity="CRITICAL",
            category=CATEGORY,
            details="No agent configuration file found.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )

    text = _agent_config_text(ctx)
    has_confirm = any(r.search(text) for r in _CONFIRM_RE)

    # Check if there are write/delete/send tool types without confirmation
    has_write_tools = bool(re.search(
        r'(?i)"(?:type|action)"\s*:\s*"(?:write|delete|send|post|execute|deploy|rm|drop)',
        text,
    ))

    if has_write_tools and not has_confirm:
        return CheckResult(
            check_id="AI-AGENT-002",
            title="Agent Cannot Take Destructive Actions Without Confirmation",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                "Agent has write/delete/send tools configured without a confirmation gate. "
                "A single prompt injection or hallucination could trigger irreversible real-world actions."
            ),
            evidence=["write/delete/send tool types detected", "No require_confirmation or human_in_the_loop setting found"],
            remediation=(
                "1. Classify all tools: read-only (no confirm needed) vs. irreversible (require human confirm).\n"
                "2. Add 'require_confirmation': true to all write, delete, send, and deploy tool definitions.\n"
                "3. For automated pipelines: queue irreversible actions for human review rather than executing immediately.\n"
                "4. Log all confirmation events: what was proposed, who confirmed, when."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3, AU-2", "NIST AI RMF": "GOVERN 6.1"},
        )
    elif has_confirm:
        return CheckResult(
            check_id="AI-AGENT-002",
            title="Agent Cannot Take Destructive Actions Without Confirmation",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="Confirmation gate configuration found for destructive actions.",
            evidence=["require_confirmation or human_in_the_loop setting detected"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )
    else:
        return CheckResult(
            check_id="AI-AGENT-002",
            title="Agent Cannot Take Destructive Actions Without Confirmation",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details="Cannot confirm whether destructive actions require human confirmation. No confirmation gate found.",
            evidence=["No require_confirmation, human_in_the_loop, or approval_required setting found"],
            remediation="Add explicit confirmation gates for all irreversible agent actions.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )


def check_agent_003(ctx: ScanContext) -> CheckResult:
    return CheckResult(
        check_id="AI-AGENT-003",
        title="Agent Memory/Context Cannot Be Poisoned by External Input",
        status=SKIP,
        severity="HIGH",
        category=CATEGORY,
        details=(
            "This check requires a live agent session to test memory poisoning via adversarial inputs. "
            "Run with --mode api or --mode local to evaluate."
        ),
        remediation="Rerun with --mode api or --mode local with an agent that has persistent memory configured.",
        frameworks={"OWASP LLM": "LLM01", "FedRAMP": "SI-7", "NIST AI RMF": "MANAGE 1.3"},
    )


def check_agent_004(ctx: ScanContext) -> CheckResult:
    if not _has_agent_config(ctx):
        return CheckResult(
            check_id="AI-AGENT-004",
            title="Inter-Agent Trust Not Implicitly Granted",
            status=SKIP,
            severity="HIGH",
            category=CATEGORY,
            details="No agent configuration found. N/A for single-agent deployments.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )

    text = _agent_config_text(ctx)
    is_multi_agent = bool(re.search(r'(?i)"agents?"\s*:\s*\[', text) or
                          re.search(r'(?i)"sub[_-]?agents?"\s*:', text) or
                          re.search(r'(?i)"orchestrat', text))

    if not is_multi_agent:
        return CheckResult(
            check_id="AI-AGENT-004",
            title="Inter-Agent Trust Not Implicitly Granted",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Single-agent deployment detected. Inter-agent trust is not applicable.",
            evidence=["No multi-agent configuration found in agent_config"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )

    has_auth = any(r.search(text) for r in _INTER_AGENT_AUTH_RE)
    if not has_auth:
        return CheckResult(
            check_id="AI-AGENT-004",
            title="Inter-Agent Trust Not Implicitly Granted",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "Multi-agent configuration found with no inter-agent authentication. "
                "Messages between agents should be authenticated — implicit trust enables cascading compromise."
            ),
            evidence=["Multi-agent setup detected", "No agent_auth, trust_level, or signed_messages configuration"],
            remediation=(
                "1. Implement agent authentication: each agent needs a signed identity token.\n"
                "2. Treat inter-agent messages with the same skepticism as user messages.\n"
                "3. Define explicit trust policies: Agent B only accepts X category actions from Agent A.\n"
                "4. Log all inter-agent communications."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3, IA-3", "NIST AI RMF": "GOVERN 6.1"},
        )
    else:
        return CheckResult(
            check_id="AI-AGENT-004",
            title="Inter-Agent Trust Not Implicitly Granted",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Inter-agent authentication configuration found.",
            evidence=["agent_auth or trust verification configuration detected"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 6.1"},
        )


def check_agent_005(ctx: ScanContext) -> CheckResult:
    if not _has_agent_config(ctx):
        return CheckResult(
            check_id="AI-AGENT-005",
            title="Agent Action Logs Captured and Auditable",
            status=SKIP,
            severity="HIGH",
            category=CATEGORY,
            details="No agent configuration found.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AU-2", "NIST AI RMF": "MEASURE 2.5"},
        )

    all_text = '\n'.join(ctx.files.values())
    has_action_log = any(r.search(all_text) for r in _ACTION_LOG_RE)

    if not has_action_log:
        return CheckResult(
            check_id="AI-AGENT-005",
            title="Agent Action Logs Captured and Auditable",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No action logging configuration found in agent config. "
                "Without tool call logs, you cannot reconstruct what the agent did or investigate incidents."
            ),
            evidence=["No action_log, audit_trail, or tool_logging configuration detected"],
            remediation=(
                "1. Add action logging at the tool call wrapper level — log before and after each tool execution.\n"
                "2. Log: tool name, parameters, response, timestamp, session ID.\n"
                "3. Store action logs separately from the database the agent can write to.\n"
                "4. Retain action logs for minimum 90 days for regulated environments."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AU-2, AU-9", "NIST AI RMF": "MEASURE 2.5"},
        )
    else:
        return CheckResult(
            check_id="AI-AGENT-005",
            title="Agent Action Logs Captured and Auditable",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Action logging configuration found.",
            evidence=["action_log or audit_trail configuration detected"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AU-2", "NIST AI RMF": "MEASURE 2.5"},
        )


def check_agent_006(ctx: ScanContext) -> CheckResult:
    if not _has_agent_config(ctx):
        return CheckResult(
            check_id="AI-AGENT-006",
            title="Agent Cannot Exfiltrate Data to Unapproved Endpoints",
            status=SKIP,
            severity="CRITICAL",
            category=CATEGORY,
            details="No agent configuration found.",
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-4, SC-7", "NIST AI RMF": "MANAGE 1.3"},
        )

    text = _agent_config_text(ctx)
    has_http_tool = bool(re.search(r'(?i)"(?:http|web|url|fetch|request)"\s*:', text))
    has_allowlist = any(r.search(text) for r in _DOMAIN_ALLOWLIST_RE)
    if has_http_tool and not has_allowlist:
        return CheckResult(
            check_id="AI-AGENT-006",
            title="Agent Cannot Exfiltrate Data to Unapproved Endpoints",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                "HTTP/web tool found in agent config with no domain allowlist. "
                "An injected instruction could exfiltrate conversation data to an attacker-controlled server."
            ),
            evidence=[
                "HTTP/fetch/web tool detected in agent config",
                "No allowed_domains, allowlist, or egress_filter configuration found",
            ],
            remediation=(
                "1. Add a domain allowlist to all HTTP tools: 'allowed_domains': ['api.approved.com'].\n"
                "2. Add egress network filtering at the host/container level (defense in depth).\n"
                "3. Monitor all outbound connections from the agent process.\n"
                "4. Restrict email tools to approved sending domains and recipient allowlists."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-4, SC-7", "NIST AI RMF": "MANAGE 1.3"},
        )
    elif has_allowlist:
        return CheckResult(
            check_id="AI-AGENT-006",
            title="Agent Cannot Exfiltrate Data to Unapproved Endpoints",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="Domain allowlist or egress filter configuration found.",
            evidence=["allowed_domains or allowlist configuration detected"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-4", "NIST AI RMF": "MANAGE 1.3"},
        )
    else:
        return CheckResult(
            check_id="AI-AGENT-006",
            title="Agent Cannot Exfiltrate Data to Unapproved Endpoints",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details="No HTTP tools detected in agent config, but domain allowlisting could not be verified.",
            evidence=["No HTTP tool found — if agent has no web access, this check is N/A"],
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "AC-4", "NIST AI RMF": "MANAGE 1.3"},
        )


def run_all(ctx: ScanContext) -> list:
    return [
        check_agent_001(ctx),
        check_agent_002(ctx),
        check_agent_003(ctx),
        check_agent_004(ctx),
        check_agent_005(ctx),
        check_agent_006(ctx),
    ]
