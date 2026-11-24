"""Tests for AI usage optimization and shepherding engine."""
import pytest

from checks.ai_optimization import assess_ai_optimization


class TestAIOptimization:
    def _sessions(self, **overrides):
        s = {
            'tool_name': 'Claude Code',
            'tool_category': 'coding_assistant',
            'duration_seconds': 3600,
            'device_id': 'dev1',
        }
        s.update(overrides)
        return s

    def _spend(self, **overrides):
        s = {
            'provider': 'openai',
            'model': 'gpt-4o',
            'total_tokens': 100000,
            'total_cost': 50.0,
        }
        s.update(overrides)
        return s

    def _inventory(self, **overrides):
        i = {
            'tool_name': 'Claude Code',
            'governance_status': 'sanctioned',
            'running': True,
            'device_id': 'dev1',
        }
        i.update(overrides)
        return i

    def test_empty_data(self):
        result = assess_ai_optimization([], [], [])
        assert result['total_sessions'] == 0
        assert result['total_tools'] == 0
        assert result['estimated_monthly_cost'] == 0
        assert result['potential_monthly_savings'] == 0
        assert len(result['recommendations']) == 0

    def test_basic_usage_aggregation(self):
        sessions = [
            self._sessions(tool_name='Claude Code', device_id='dev1'),
            self._sessions(tool_name='Claude Code', device_id='dev1'),
            self._sessions(tool_name='Cursor', device_id='dev2'),
        ]
        result = assess_ai_optimization(sessions, [], [])
        assert result['total_sessions'] == 3
        assert result['total_tools'] == 2
        assert 'claude code' in result['usage_by_tool']
        assert result['usage_by_tool']['claude code']['sessions'] == 2

    def test_model_right_sizing(self):
        spend = [self._spend(model='gpt-4o', total_cost=200.0)]
        result = assess_ai_optimization([], spend, [])
        recs = [r for r in result['recommendations'] if r['category'] == 'Model Right-Sizing']
        assert len(recs) == 1
        assert 'gpt-4o-mini' in recs[0]['title']
        assert recs[0]['potential_savings'] > 0

    def test_redundant_subscriptions(self):
        sessions = [
            self._sessions(tool_name='Claude Code'),
            self._sessions(tool_name='Cursor'),
            self._sessions(tool_name='Copilot'),
        ]
        result = assess_ai_optimization(sessions, [], [])
        recs = [r for r in result['recommendations'] if r['category'] == 'Redundant Subscriptions']
        assert len(recs) == 1
        assert recs[0]['potential_savings'] > 0

    def test_shadow_ai_cost(self):
        sessions = [self._sessions(tool_name='ChatGPT', device_id='dev1')]
        inventory = [self._inventory(tool_name='ChatGPT', governance_status='shadow')]
        result = assess_ai_optimization(sessions, [], inventory)
        recs = [r for r in result['recommendations'] if r['category'] == 'Shadow AI Cost']
        assert len(recs) == 1
        assert recs[0]['potential_savings'] > 0

    def test_unused_sanctioned_tool(self):
        inventory = [self._inventory(tool_name='Cursor', governance_status='sanctioned')]
        result = assess_ai_optimization([], [], inventory)
        recs = [r for r in result['recommendations'] if r['category'] == 'Unused Sanctioned Tools']
        assert len(recs) == 1

    def test_governance_gap(self):
        sessions = [self._sessions(tool_name='Aider')]
        result = assess_ai_optimization(sessions, [], [])
        recs = [r for r in result['recommendations'] if r['category'] == 'Governance Gap']
        assert len(recs) == 1

    def test_free_alternative_detection(self):
        sessions = [
            self._sessions(tool_name='Claude Code'),
            self._sessions(tool_name='Aider'),
        ]
        result = assess_ai_optimization(sessions, [], [])
        recs = [r for r in result['recommendations'] if r['category'] == 'Free Alternative Available']
        assert len(recs) == 1

    def test_shepherding_actions(self):
        sessions = [
            self._sessions(tool_name='ChatGPT', device_id='dev1'),
            self._sessions(tool_name='Claude Code', device_id='dev2'),
        ]
        result = assess_ai_optimization(sessions, [], [])
        assert len(result['shepherding_actions']) > 0
        actions = [a['action'] for a in result['shepherding_actions']]
        assert any('governance' in a.lower() for a in actions)

    def test_cost_concentration(self):
        sessions = []
        for _ in range(10):
            sessions.append(self._sessions(tool_name='Claude Code'))
        for _ in range(2):
            sessions.append(self._sessions(tool_name='Cursor'))
        result = assess_ai_optimization(sessions, [], [])
        recs = [r for r in result['recommendations'] if r['category'] == 'Cost Concentration']
        assert len(recs) == 1
        assert 'claude code' in recs[0]['title'].lower()

    def test_potential_savings_calculation(self):
        spend = [
            self._spend(model='gpt-4o', total_cost=200.0),
            self._spend(model='claude-sonnet', total_cost=100.0, provider='anthropic'),
        ]
        result = assess_ai_optimization([], spend, [])
        assert result['potential_monthly_savings'] > 0

    def test_usage_by_category(self):
        sessions = [
            self._sessions(tool_name='Claude Code', tool_category='coding_assistant'),
            self._sessions(tool_name='ChatGPT', tool_category='saas_ai'),
        ]
        result = assess_ai_optimization(sessions, [], [])
        assert result['usage_by_category']['coding_assistant'] == 1
        assert result['usage_by_category']['saas_ai'] == 1
