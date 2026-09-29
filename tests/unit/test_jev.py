from __future__ import annotations

import json

import pytest

from imprint.retrieve.jev import JevSelector, prefilter
from imprint.retrieve.models import RetrievalRecord


def item(record_id: str, text: str) -> RetrievalRecord:
    return RetrievalRecord(record_id, text, "general", "captured", "captured_judgment", ("e",), ("c",), provenance_complete=True)


def test_prefilter_is_bounded_and_relevance_ordered():
    values = [item("irrelevant", "gardening flowers"), item("relevant", "deploy production safely")]
    assert [x.record_id for x in prefilter("production deploy", values, keep=1)] == ["relevant"]


def stub_request(monkeypatch, selector, response):
    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: response)


def test_selector_parses_scores_floor_top_and_dedupes(monkeypatch):
    values = [item(name, "write a safe release") for name in "abcd"]
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    stub_request(monkeypatch, selector, {
        "answers": {
            "a": {"noul": 0.9},
            "b": {"noul": 0.4},
            "c": {"noul": 0.8},
            "d": {"noul": 0.7},
            "unknown": {"noul": 0.99},
        },
    })
    result = selector.select("release", values, top=2, floor=0.55)
    assert [(x.record_id, score) for x, score in result] == [("a", 0.9), ("c", 0.8)]
    assert len({x.record_id for x, _ in result}) == len(result)


def test_selector_ignores_answers_outside_the_documented_shape(monkeypatch):
    values = [item("a", "write a safe release"), item("b", "write a safe release")]
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    stub_request(monkeypatch, selector, {"answers": {"a": 0.9, "b": {"noul": "0.9"}}})
    assert selector.select("release", values) == []
    stub_request(monkeypatch, selector, {"scores": {"a": {"noul": 0.9}}})
    assert selector.select("release", values) is None


def test_request_sends_state_and_noul_questions(monkeypatch):
    sent = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"answers": {"a": {"noul": 0.9}}}'

    def fake_urlopen(request, timeout):
        sent["body"] = json.loads(request.data)
        sent["timeout"] = timeout
        return Reply()

    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr("imprint.retrieve.jev.urllib.request.urlopen", fake_urlopen)
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    result = selector.select("release", [item("a", "write a safe release")], timeout=2.5)
    assert [(x.record_id, score) for x, score in result] == [("a", 0.9)]
    assert sent["timeout"] == 2.5
    assert sent["body"]["model"] == "jev"
    assert sent["body"]["state"] == "release"
    assert sent["body"]["questions"]["a"]["type"] == "noul"


def test_missing_key_falls_back(monkeypatch):
    monkeypatch.delenv("JEV_TEST_MISSING", raising=False)
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_MISSING")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: pytest.fail("network must not be reached"))
    assert selector.select("one", [item("a", "one")]) is None


def test_network_error_and_timeout_fall_back(monkeypatch):
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    for error in (OSError("network down"), TimeoutError()):
        def fail(*args, error=error, **kwargs):
            raise error

        monkeypatch.setattr(selector, "_request", fail)
        assert selector.select("one", [item("a", "one")]) is None


def _write_config(tmp_path, selector):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"config_version": "3.1.1", "selector": selector}), encoding="utf-8")
    return path


def test_selector_defaults_to_deterministic(tmp_path):
    from imprint.config import load_config

    assert load_config(tmp_path / "missing.json")["selector"]["mode"] == "deterministic"


def test_selector_config_accepts_jev_mode_with_partial_overrides(tmp_path):
    from imprint.config import load_config

    path = _write_config(tmp_path, {"mode": "jev", "jev": {"top": 5}})
    assert load_config(path)["selector"]["mode"] == "jev"


@pytest.mark.parametrize("selector", [
    {"mode": "fast"},
    {"mode": "jev", "extra": 1},
    {"mode": "jev", "jev": {"unknown": 1}},
    {"mode": "jev", "jev": {"top": 0}},
    {"mode": "jev", "jev": {"top": True}},
    {"mode": "jev", "jev": {"score_floor": 1.5}},
    {"mode": "jev", "jev": {"timeout_seconds": 0}},
    {"mode": "jev", "jev": {"prefilter_keep": 0}},
    {"mode": "jev", "jev": {"endpoint": " "}},
])
def test_selector_config_rejects_invalid_values(tmp_path, selector):
    from imprint.config import load_config
    from imprint.errors import ValidationError

    with pytest.raises(ValidationError):
        load_config(_write_config(tmp_path, selector))


def retrieval_fixture(monkeypatch, records):
    import imprint.retrieve as retrieval

    class Source:
        def __init__(self, store):
            pass

        def retrieval_candidates(self, snapshot_id):
            return records

    class Store:
        def retrieval_generation(self):
            return 'test-store', 1

    monkeypatch.setattr(retrieval, 'StoreRetrievalSource', Source)
    monkeypatch.setenv('JEV_TEST_KEY', 'not-a-real-key')
    return Store(), {'mode': 'jev', 'jev': {'api_key_env': 'JEV_TEST_KEY'}}


@pytest.mark.parametrize('domain_only,partitions', [(False, None), (True, None), (False, ['business_declared'])])
def test_retrieval_filters_before_remote_disclosure(monkeypatch, tmp_path, domain_only, partitions):
    from dataclasses import replace
    from imprint.retrieve import retrieve_payload

    base = item('good', 'ship safely')
    records = [base, replace(base, record_id='selected-domain', section='domain', domain_id='chosen'),
               replace(base, record_id='other-domain', section='domain', domain_id='other'),
               replace(base, record_id='domain-escape', domain_id='other'),
               replace(base, record_id='declared', ontology_partition='business_declared'),
               replace(base, record_id='rejected', rejected=True),
               replace(base, record_id='deleted', tombstoned=True),
               replace(base, record_id='old', current=False),
               replace(base, record_id='expired', valid_until='2020-01-01'),
               replace(base, record_id='no-proof', provenance_complete=False),
               replace(base, record_id='no-evidence', evidence_ids=()),
               replace(base, record_id='inferred', provenance_status='inferred', authority_tier='inferred_candidate'),
               replace(base, record_id='unselected-import', provenance_status='extracted', authority_tier='imported_floor')]
    store, config = retrieval_fixture(monkeypatch, records)
    sent = []

    def request(self, prompt, candidates, timeout):
        sent.extend(x.record_id for x in candidates)
        return {'answers': {x.record_id: {'noul': 0.9} for x in candidates}}

    monkeypatch.setattr(JevSelector, '_request', request)
    response = retrieve_payload(store, root=tmp_path, session_id='private-session', prompt='ship',
                                explicit_domain='chosen', domain_only=domain_only,
                                ontology_partitions=partitions, selector_config=config)
    expected = {'declared'} if partitions else ({'selected-domain'} if domain_only else {'good', 'declared', 'selected-domain'})
    assert set(sent) == expected
    assert set(response['selected_ids']) == expected
    assert response['eligible_count'] == len(expected)
    assert sum(response['section_bytes'].values()) == response['selected_bytes']
    assert {x for ids in response['selected_by_partition'].values() for x in ids} == expected


@pytest.mark.parametrize('output_format', ['compact', 'audit'])
def test_jev_full_payload_preserves_rendering_provenance_and_metadata(monkeypatch, tmp_path, output_format):
    from dataclasses import replace
    from imprint.retrieve import retrieve_payload, commit_payload_delivery

    record = replace(item('large', 'ship safely ' * 4000), case_referents=('real case',))
    store, config = retrieval_fixture(monkeypatch, [record])
    calls = []

    def request(self, *args):
        calls.append(1)
        return {'answers': {'large': {'noul': 0.99}}}

    monkeypatch.setattr(JevSelector, '_request', request)
    kwargs = dict(root=tmp_path, session_id='s', prompt='ship', budget=4096,
                  selector_config=config, output_format=output_format)
    result = retrieve_payload(store, **kwargs)
    assert result['selected_ids'] == ['large']
    assert result['selected_bytes'] > 4096
    assert result['budget_bytes'] == result['selected_bytes']
    assert result['section_bytes']['general'] == len(result['payload'].encode())
    assert result['selected_by_partition'] == {'judgment': ['large']}
    assert result['omitted_count'] == 0
    if output_format == 'audit':
        value = json.loads(result['payload'])
        assert value['text'] == record.text
        assert value['evidence_ids'] == ['e'] and value['case_ids'] == ['c']
        assert value['selector'] == {'mode': 'jev', 'score': 0.99, 'rank': 1}
    else:
        assert 'Case: real case' in result['payload']
        assert 'Jev score=0.990, rank=1' in result['payload']
    assert retrieve_payload(store, **kwargs) == result
    assert calls == [1]
    assert commit_payload_delivery(root=tmp_path, session_id='s', snapshot_id=result['snapshot_id'], domain_id=result['receipt_scope'])
    assert retrieve_payload(store, **kwargs)['status'] == 'already_delivered'
    assert calls == [1]


@pytest.mark.parametrize('failure', ['missing-key', 'network', 'timeout', 'invalid-json', 'empty'])
def test_retrieve_payload_failure_retains_exact_deterministic_result(monkeypatch, tmp_path, failure):
    from imprint.retrieve import retrieve_payload

    store, config = retrieval_fixture(monkeypatch, [item('a', 'ship safely')])
    kwargs = dict(root=tmp_path, session_id='s', prompt='ship', refresh=True)
    expected = retrieve_payload(store, **kwargs)
    if failure == 'missing-key':
        monkeypatch.delenv('JEV_TEST_KEY')

    def request(*args):
        if failure == 'empty':
            return {'answers': {}}
        if failure == 'missing-key':
            pytest.fail('missing key must not make a network request')
        raise {'network': OSError('offline'), 'timeout': TimeoutError(),
               'invalid-json': ValueError('malformed response')}[failure]

    monkeypatch.setattr(JevSelector, '_request', request)
    assert retrieve_payload(store, **kwargs, selector_config=config) == expected


def test_prompt_hooks_select_without_domain_dedupe_and_reset(monkeypatch, tmp_path, capsys):
    import io
    from imprint.cli import main

    records = [item('seed', 'brief rule'), item('a', 'alpha ' * 1200), item('b', 'beta ' * 1200)]
    _, selector = retrieval_fixture(monkeypatch, records)
    selector['jev']['top'] = 1
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'config_version': '3.1.1', 'data_root': str(tmp_path / 'data'),
                                  'context_budget_bytes': 4096, 'selector': selector}))
    sent = []

    def request(self, prompt, candidates, timeout):
        sent.append({x.record_id for x in candidates})
        target = 'a' if 'alpha' in prompt else 'b'
        return {'answers': {target: {'noul': 0.99}}}

    monkeypatch.setattr(JevSelector, '_request', request)

    def hook(action, **event):
        monkeypatch.setattr('sys.stdin', io.StringIO(json.dumps({'session_id': 'hook-session', **event})))
        assert main(['--config', str(config), 'hook', action]) == 0
        return json.loads(capsys.readouterr().out)

    start = hook('session-start')
    assert 'brief rule' in start['hookSpecificOutput']['additionalContext']
    assert sent == []
    first = hook('user-prompt-submit', prompt='alpha')
    assert 'alpha ' in first['hookSpecificOutput']['additionalContext']
    second = hook('user-prompt-submit', prompt='beta')
    assert 'beta ' in second['hookSpecificOutput']['additionalContext']
    assert sent == [{'a', 'b'}, {'b'}]
    assert hook('user-prompt-submit', prompt='alpha')['status'] == 'already_delivered'
    hook('session-start', source='compact')
    assert 'alpha ' in hook('user-prompt-submit', prompt='alpha')['hookSpecificOutput']['additionalContext']
    assert sent[-1] == {'a', 'b'}
