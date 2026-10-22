"""Offline scorer/adapter contract tests, NOT model accuracy observations."""
import hashlib
import inspect

import pytest

from scripts.accuracy_eval_adapter import capture_trial, score_facts, score_files


def test_no_model_initialization_without_authorization():
    calls = []
    with pytest.raises(PermissionError):
        capture_trial(lambda **k: calls.append(k), prompt='synthetic', task_id='t1',
                      model='mock', provider='mock', base_url='https://mock.invalid', toolsets=[])
    assert calls == []


def test_adapter_matches_current_callable_signatures():
    from run_agent import AIAgent
    keys = {'model', 'provider', 'base_url', 'enabled_toolsets', 'max_iterations',
            'skip_context_files', 'skip_memory', 'save_trajectories', 'quiet_mode'}
    assert keys <= set(inspect.signature(AIAgent.__init__).parameters)
    assert {'user_message', 'task_id'} <= set(inspect.signature(AIAgent.run_conversation).parameters)


def test_fake_transport_captures_real_contract_fields():
    class FakeAgent:
        tools = []
        def __init__(self, **kwargs):
            assert kwargs['skip_memory'] and kwargs['skip_context_files']
            assert kwargs['enabled_toolsets'] == []
        def run_conversation(self, user_message, task_id):
            return {'final_response': user_message, 'messages': [], 'completed': True, 'api_calls': 0}
    row = capture_trial(FakeAgent, prompt='synthetic', task_id='t1', model='mock',
                        provider='mock', base_url='https://mock.invalid', toolsets=[], allow_model_calls=True)
    assert row['result']['api_calls'] == 0
    assert row['result']['final_response'] == 'synthetic'


@pytest.mark.parametrize('claim', [
    {'value': 99, 'source_id': 'memo', 'quote': 'Approved count: 12.'},
    {'value': 12, 'source_id': 'memo', 'quote': 'Approved count: 99.'},
    {'value': 12, 'source_id': 'other', 'quote': 'Approved count: 12.'},
    {'value': True, 'source_id': 'memo', 'quote': 'Approved count: 12.'},
])
def test_plausible_but_wrong_fact_or_grounding_fails(claim):
    oracle = {'count': {'value': 12, 'source_id': 'memo', 'quote': 'Approved count: 12.'}}
    assert not score_facts(oracle, {'count': claim}, {'memo': 'Approved count: 12.'})['all_correct']


def test_expected_fact_with_real_span_passes_but_extra_claim_fails():
    oracle = {'count': {'value': 12, 'source_id': 'memo', 'quote': 'Approved count: 12.'}}
    sources = {'memo': 'Approved count: 12.'}
    assert score_facts(oracle, oracle, sources)['all_correct']
    assert not score_facts(oracle, {**oracle, 'made_up': {'value': 8}}, sources)['all_correct']


def test_final_artifact_content_not_completion_claim(tmp_path):
    digest = hashlib.sha256(b'count,total\n2,12\n').hexdigest()
    oracle = {'result.csv': digest}
    assert score_files(tmp_path, oracle) == {'result.csv': False}
    (tmp_path / 'result.csv').write_bytes(b'count,total\n2,99\n')
    assert score_files(tmp_path, oracle) == {'result.csv': False}
    (tmp_path / 'result.csv').write_bytes(b'count,total\n2,12\n')
    assert score_files(tmp_path, oracle) == {'result.csv': True}


def test_symlink_output_and_traversing_oracle_rejected(tmp_path):
    source = tmp_path / 'source'
    source.write_bytes(b'ok')
    (tmp_path / 'result').symlink_to(source)
    assert not score_files(tmp_path, {'result': hashlib.sha256(b'ok').hexdigest()})['result']
    with pytest.raises(ValueError):
        score_files(tmp_path, {'../outside': 'unused'})
