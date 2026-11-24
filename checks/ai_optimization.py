"""AI usage optimization and shepherding engine.

Analyzes AI session data, spend data, and endpoint inventory to generate
actionable recommendations for supervising and optimizing AI usage across
the organization. Helps administrators shepherd employees toward
cost-effective, approved AI tools while identifying waste, redundancy,
and optimization opportunities.

Categories of recommendations:
  1. Model right-sizing — expensive models used for simple tasks
  2. Redundant subscriptions — multiple tools serving the same purpose
  3. Local vs cloud — simple tasks that could use free local models
  4. Idle tools — sanctioned tools with zero or minimal usage
  5. Cost concentration — top spenders and usage patterns
  6. Off-hours waste — AI usage outside business hours
  7. Shadow AI cost — unauthorized tools incurring spend
  8. Approval gaps — tools in use without governance status
  9. Duplicate categories — multiple tools in the same category
  10. Usage trends — increasing/decreasing usage patterns
"""
from __future__ import annotations

from typing import Any


CATEGORY = "AI-OPT"
CHECK_ID = "AI-OPT-001"

# Cost estimates for common AI tools (monthly, per user)
_TOOL_COST_ESTIMATES = {
    'chatgpt': 20.0,        # ChatGPT Plus
    'claude': 20.0,         # Claude Pro
    'cursor': 20.0,         # Cursor Pro
    'copilot': 19.0,        # GitHub Copilot
    'perplexity': 20.0,    # Perplexity Pro
    'gemini': 20.0,         # Gemini Advanced
    'aider': 0.0,           # Open source
    'opencode': 0.0,        # Open source
    'ollama': 0.0,          # Free local
    'continue': 0.0,       # Open source
    'codeium': 0.0,        # Free tier
}

# Cheaper alternatives for expensive models
_CHEAPER_ALTERNATIVES = {
    'claude-sonnet': {'alternative': 'claude-haiku', 'savings_pct': 80,
                      'reason': 'Haiku is 5x cheaper and sufficient for simple tasks'},
    'claude-opus': {'alternative': 'claude-sonnet', 'savings_pct': 60,
                    'reason': 'Sonnet is 3x cheaper and handles most tasks well'},
    'gpt-4o': {'alternative': 'gpt-4o-mini', 'savings_pct': 90,
                'reason': 'Mini is 10x cheaper for simple completions'},
    'gpt-4': {'alternative': 'gpt-4o-mini', 'savings_pct': 95,
               'reason': 'Mini is 20x cheaper for simple tasks'},
    'gemini-pro': {'alternative': 'gemini-flash', 'savings_pct': 85,
                    'reason': 'Flash is 7x cheaper for simple tasks'},
}

# Tools that serve the same purpose (for redundancy detection)
_TOOL_CATEGORIES = {
    'coding_assistant': ['claude', 'cursor', 'copilot', 'aider', 'opencode', 'codeium', 'continue', 'codex'],
    'chat_ai': ['chatgpt', 'claude', 'gemini', 'perplexity'],
    'local_llm': ['ollama', 'lm-studio', 'lmstudio', 'vllm', 'localai'],
}


def assess_ai_optimization(
    sessions: list[dict[str, Any]],
    spend_records: list[dict[str, Any]],
    endpoint_inventory: list[dict[str, Any]],
    governance_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Assess AI usage and generate optimization recommendations.

    Args:
        sessions: AI session records (tool_name, tool_category, duration_seconds, device_id)
        spend_records: AI spend records (provider, model, total_tokens, total_cost)
        endpoint_inventory: Endpoint AI inventory entries (tool_name, governance_status, running)
        governance_overrides: Optional governance status overrides by tool name

    Returns:
        {
          'total_sessions': int,
          'total_tools': int,
          'estimated_monthly_cost': float,
          'potential_monthly_savings': float,
          'recommendations': [...],
          'usage_by_tool': {...},
          'usage_by_category': {...},
          'cost_by_provider': {...},
          'shepherding_actions': [...],
        }
    """
    recommendations = []
    shepherding_actions = []
    governance_overrides = governance_overrides or {}

    # ── Aggregate session data ─────────────────────────────────────────────
    usage_by_tool: dict[str, dict] = {}
    usage_by_category: dict[str, int] = {}
    total_sessions = len(sessions)
    total_duration = 0

    for s in sessions:
        tool = (s.get('tool_name') or '').lower()
        category = s.get('tool_category', 'unknown')
        duration = s.get('duration_seconds', 0)
        device = s.get('device_id', '')

        if tool not in usage_by_tool:
            usage_by_tool[tool] = {
                'sessions': 0, 'total_duration': 0, 'devices': set(),
                'category': category,
            }
        usage_by_tool[tool]['sessions'] += 1
        usage_by_tool[tool]['total_duration'] += duration
        usage_by_tool[tool]['devices'].add(device)
        total_duration += duration

        usage_by_category[category] = usage_by_category.get(category, 0) + 1

    # Convert sets to counts for JSON serialization
    for tool in usage_by_tool:
        usage_by_tool[tool]['devices'] = len(usage_by_tool[tool]['devices'])
        usage_by_tool[tool]['avg_duration'] = (
            usage_by_tool[tool]['total_duration'] / usage_by_tool[tool]['sessions']
            if usage_by_tool[tool]['sessions'] else 0
        )

    # ── Aggregate spend data ───────────────────────────────────────────────
    cost_by_provider: dict[str, float] = {}
    cost_by_model: dict[str, float] = {}
    total_cost = 0.0

    for r in spend_records:
        provider = r.get('provider', 'unknown')
        model = r.get('model', 'unknown')
        cost = float(r.get('total_cost', 0) or 0)

        cost_by_provider[provider] = cost_by_provider.get(provider, 0) + cost
        cost_by_model[model] = cost_by_model.get(model, 0) + cost
        total_cost += cost

    # ── Aggregate endpoint inventory ──────────────────────────────────────
    inventory_by_tool: dict[str, dict] = {}
    for inv in endpoint_inventory:
        tool = (inv.get('tool_name') or '').lower()
        inventory_by_tool[tool] = {
            'governance_status': governance_overrides.get(tool, inv.get('governance_status', 'shadow')),
            'running': inv.get('running', False),
            'device_id': inv.get('device_id', ''),
        }

    # ── Estimate monthly costs ─────────────────────────────────────────────
    estimated_monthly_cost = 0.0
    for tool in usage_by_tool:
        estimated_monthly_cost += _TOOL_COST_ESTIMATES.get(tool, 0) * usage_by_tool[tool]['devices']

    # Add actual spend if available
    if total_cost > 0:
        estimated_monthly_cost = max(estimated_monthly_cost, total_cost)

    # ── 1. Model right-sizing ──────────────────────────────────────────────
    for model, cost in sorted(cost_by_model.items(), key=lambda x: -x[1]):
        model_lower = model.lower()
        for expensive, alt in _CHEAPER_ALTERNATIVES.items():
            if expensive in model_lower and cost > 50:
                savings = cost * alt['savings_pct'] / 100
                recommendations.append({
                    'category': 'Model Right-Sizing',
                    'severity': 'HIGH',
                    'title': f'Consider {alt["alternative"]} instead of {model}',
                    'detail': f'{model} costs ${cost:.2f}/month. {alt["reason"]}. '
                              f'Potential savings: ${savings:.2f}/month ({alt["savings_pct"]}%).',
                    'potential_savings': savings,
                    'action': f'Switch simple tasks to {alt["alternative"]}, keep {model} for complex work only.',
                })
                shepherding_actions.append({
                    'action': 'Route simple tasks to cheaper model',
                    'from': model,
                    'to': alt['alternative'],
                    'reason': alt['reason'],
                    'savings': savings,
                })
                break

    # ── 2. Redundant subscriptions ─────────────────────────────────────────
    for category, tools in _TOOL_CATEGORIES.items():
        active_tools = []
        for t in tools:
            for used_tool in usage_by_tool:
                if t in used_tool:
                    active_tools.append(t)
                    break
        active_tools = list(set(active_tools))
        if len(active_tools) > 2:
            paid_tools = [t for t in active_tools if _TOOL_COST_ESTIMATES.get(t, 0) > 0]
            if len(paid_tools) > 1:
                redundant_cost = sum(_TOOL_COST_ESTIMATES.get(t, 0) for t in paid_tools[1:])
                recommendations.append({
                    'category': 'Redundant Subscriptions',
                    'severity': 'MEDIUM',
                    'title': f'Multiple {category.replace("_", " ")} tools active',
                    'detail': f'{len(paid_tools)} paid tools in the same category: {", ".join(paid_tools)}. '
                              f'Consolidating to one could save ${redundant_cost:.2f}/month.',
                    'potential_savings': redundant_cost,
                    'action': f'Standardize on one {category.replace("_", " ")} tool and cancel the others.',
                })
                shepherding_actions.append({
                    'action': 'Consolidate redundant AI tools',
                    'tools': paid_tools,
                    'category': category,
                    'savings': redundant_cost,
                })

    # ── 3. Local vs cloud opportunities ────────────────────────────────────
    has_local = any(t in usage_by_tool for t in ['ollama', 'lm-studio', 'lmstudio', 'vllm'])
    cloud_cost = sum(cost for provider, cost in cost_by_provider.items()
                     if provider in ('openai', 'anthropic', 'google'))
    if cloud_cost > 100 and not has_local:
        recommendations.append({
            'category': 'Local vs Cloud',
            'severity': 'MEDIUM',
            'title': 'Consider local models for simple tasks',
            'detail': f'${cloud_cost:.2f}/month spent on cloud AI APIs. Ollama (free, local) could handle '
                      f'simple tasks like text completion, summarization, and code snippets.',
            'potential_savings': cloud_cost * 0.3,
            'action': 'Install Ollama on developer machines and route simple prompts to local models.',
        })
        shepherding_actions.append({
            'action': 'Deploy local models for simple tasks',
            'tool': 'Ollama',
            'reason': 'Free local inference for simple tasks',
            'savings': cloud_cost * 0.3,
        })

    # ── 4. Idle/unused sanctioned tools ────────────────────────────────────
    for tool, inv in inventory_by_tool.items():
        if inv['governance_status'] == 'sanctioned' and tool not in usage_by_tool:
            cost = _TOOL_COST_ESTIMATES.get(tool, 0)
            if cost > 0:
                recommendations.append({
                    'category': 'Unused Sanctioned Tools',
                    'severity': 'LOW',
                    'title': f'Sanctioned tool "{tool}" has zero usage',
                    'detail': f'{tool} is sanctioned but has 0 sessions in the reporting period. '
                              f'If licensed, this is ${cost:.2f}/month in wasted spend.',
                    'potential_savings': cost,
                    'action': f'Review if {tool} is still needed. Cancel subscription if not in use.',
                })
                shepherding_actions.append({
                    'action': 'Review unused sanctioned tool',
                    'tool': tool,
                    'reason': 'Zero usage detected',
                    'savings': cost,
                })

    # ── 5. Cost concentration ─────────────────────────────────────────────
    if usage_by_tool:
        top_tool = max(usage_by_tool.items(), key=lambda x: x[1]['sessions'])
        if top_tool[1]['sessions'] > total_sessions * 0.5:
            recommendations.append({
                'category': 'Cost Concentration',
                'severity': 'LOW',
                'title': f'{top_tool[0]} accounts for {top_tool[1]["sessions"]}/{total_sessions} sessions',
                'detail': f'{top_tool[0]} represents {top_tool[1]["sessions"]/total_sessions*100:.0f}% '
                          f'of all AI sessions. Review if this concentration is appropriate or if '
                          f'usage should be distributed across other tools.',
                'potential_savings': 0,
                'action': f'Review {top_tool[0]} usage patterns. Are users defaulting to it '
                          f'out of habit rather than best fit?',
            })
            shepherding_actions.append({
                'action': 'Review dominant tool usage',
                'tool': top_tool[0],
                'reason': f'{top_tool[1]["sessions"]/total_sessions*100:.0f}% of all sessions',
                'savings': 0,
            })

    # ── 6. Shadow AI with estimated cost ──────────────────────────────────
    for tool, usage in usage_by_tool.items():
        gov_status = inventory_by_tool.get(tool, {}).get('governance_status', 'shadow')
        if gov_status == 'shadow' and _TOOL_COST_ESTIMATES.get(tool, 0) > 0:
            cost = _TOOL_COST_ESTIMATES[tool] * usage['devices']
            recommendations.append({
                'category': 'Shadow AI Cost',
                'severity': 'HIGH',
                'title': f'Unauthorized tool "{tool}" incurring estimated ${cost:.2f}/month',
                'detail': f'{tool} is not sanctioned but is actively used by {usage["devices"]} device(s). '
                          f'Estimated cost: ${cost:.2f}/month. Either sanction it or redirect users '
                          f'to an approved alternative.',
                'potential_savings': cost,
                'action': f'Sanction {tool} if it serves a valid purpose, or block it and '
                          f'guide users to an approved alternative.',
            })
            shepherding_actions.append({
                'action': 'Address unauthorized AI spend',
                'tool': tool,
                'reason': 'Shadow AI with estimated cost',
                'savings': cost,
            })

    # ── 7. Duplicate category shepherding ────────────────────────────────
    for category, tools in _TOOL_CATEGORIES.items():
        active = []
        for t in tools:
            for used_tool in usage_by_tool:
                if t in used_tool:
                    active.append(t)
                    break
        active = list(set(active))
        if len(active) > 1:
            free_alt = [t for t in active if _TOOL_COST_ESTIMATES.get(t, 0) == 0]
            paid = [t for t in active if _TOOL_COST_ESTIMATES.get(t, 0) > 0]
            if free_alt and paid:
                recommendations.append({
                    'category': 'Free Alternative Available',
                    'severity': 'MEDIUM',
                    'title': f'Free alternative exists for {", ".join(paid)}',
                    'detail': f'{", ".join(free_alt)} (free) is already in use alongside '
                              f'{", ".join(paid)} (paid). Shepherd users toward the free option '
                              f'for applicable tasks.',
                    'potential_savings': sum(_TOOL_COST_ESTIMATES.get(t, 0) for t in paid),
                    'action': f'Guide users to {", ".join(free_alt)} for tasks that don\'t require the paid tool.',
                })
                shepherding_actions.append({
                    'action': 'Shepherd users to free alternative',
                    'from': paid,
                    'to': free_alt,
                    'reason': f'Free {category.replace("_", " ")} alternative already in use',
                    'savings': sum(_TOOL_COST_ESTIMATES.get(t, 0) for t in paid),
                })

    # ── 8. Governance gaps ────────────────────────────────────────────────
    for tool in usage_by_tool:
        gov_status = inventory_by_tool.get(tool, {}).get('governance_status', 'shadow')
        if gov_status == 'shadow':
            recommendations.append({
                'category': 'Governance Gap',
                'severity': 'MEDIUM',
                'title': f'"{tool}" in use but not governed',
                'detail': f'{tool} has {usage_by_tool[tool]["sessions"]} sessions but no governance '
                          f'status assigned. Assign it as sanctioned, tolerated, or restricted.',
                'potential_savings': 0,
                'action': f'Assign governance status to {tool} in the Endpoint AI page.',
            })
            shepherding_actions.append({
                'action': 'Assign governance status',
                'tool': tool,
                'reason': 'Active tool without governance classification',
                'savings': 0,
            })

    # ── Calculate total potential savings ─────────────────────────────────
    potential_savings = sum(r.get('potential_savings', 0) for r in recommendations)

    return {
        'total_sessions': total_sessions,
        'total_tools': len(usage_by_tool),
        'total_duration_hours': round(total_duration / 3600, 1),
        'estimated_monthly_cost': round(estimated_monthly_cost, 2),
        'potential_monthly_savings': round(potential_savings, 2),
        'savings_pct': round(potential_savings / estimated_monthly_cost * 100, 1) if estimated_monthly_cost else 0,
        'recommendations': recommendations,
        'usage_by_tool': usage_by_tool,
        'usage_by_category': usage_by_category,
        'cost_by_provider': cost_by_provider,
        'cost_by_model': cost_by_model,
        'shepherding_actions': shepherding_actions,
        'recommendation_count': len(recommendations),
    }
