"""P2.4 — Data protection, DLP taint-gate & at-rest encryption (LG-DP-01..11).

Focus on the genuinely NEW surface this step adds (redaction LG-DP-03/05,
TLS LG-DP-06, think-scrub LG-DP-09 already landed at P0/P1 and are re-attested
in the report, not re-implemented):

  * LG-DP-01/02 — CUI vs public classification + marking detection/preservation
  * LG-DP-04    — CUI/PII pattern pack (SSN, DOB, CUI banner lines)
  * LG-DP-10    — DLP taint-gate: a CUI-tainted session cannot egress to a
                  non-allowlisted sink (the step's key VERIFY)
  * LG-DP-07/08 — at-rest crypto wrapper keyed outside the agent's write reach
  * LG-DP-11    — output masking + retention TTL marker on tool results

No-op on low-side postures (capability preserving).
"""

from __future__ import annotations

import pytest


_STRICT = {"security": {"posture": "strict"}}

_CUI_DOC = (
    "CUI\n"
    "Contract N0003924C0007 delivery schedule.\n"
    "POC SSN 123-45-6789, DOB 1984-03-02.\n"
    "CUI"
)
_PUBLIC_DOC = "Public release: the weather tomorrow is sunny, high 78F."


@pytest.fixture
def strict_dp(monkeypatch):
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: _STRICT)
    import agent.data_protection as dp

    dp.reset_dp_state()
    yield dp
    dp.reset_dp_state()


# ---------------------------------------------------------------------------
# 1. LG-DP-01/02 — classification + marking
# ---------------------------------------------------------------------------

def test_cui_banner_marks_content_as_cui(strict_dp):
    c = strict_dp.classify_content(_CUI_DOC)
    assert c.level == "cui"
    assert "CUI" in c.markings


def test_pii_content_without_banner_is_cui(strict_dp):
    c = strict_dp.classify_content("Employee SSN 123-45-6789 on file.")
    assert c.level == "cui"  # PII drives the CUI tag even without a banner


def test_public_content_classified_public(strict_dp):
    c = strict_dp.classify_content(_PUBLIC_DOC)
    assert c.level == "public"
    assert not c.markings


def test_low_side_classifies_everything_public(monkeypatch):
    monkeypatch.setattr(
        "lliam_cli.config.load_config", lambda *a, **kw: {"security": {}}
    )
    import agent.data_protection as dp

    dp.reset_dp_state()
    assert dp.classify_content(_CUI_DOC).level == "public"  # no-op low-side
    dp.reset_dp_state()


# ---------------------------------------------------------------------------
# 2. LG-DP-04 — CUI/PII pattern pack
# ---------------------------------------------------------------------------

def test_pattern_pack_matches_ssn_and_dob(strict_dp):
    hits = strict_dp.cui_pii_matches("SSN 123-45-6789 born 1984-03-02")
    kinds = {h.kind for h in hits}
    assert "ssn" in kinds
    assert "dob" in kinds


def test_pattern_pack_clean_text_no_hits(strict_dp):
    assert strict_dp.cui_pii_matches(_PUBLIC_DOC) == []


# ---------------------------------------------------------------------------
# 3. LG-DP-10 — DLP taint-gate (the key VERIFY)
# ---------------------------------------------------------------------------

def test_cui_exposure_taints_session(strict_dp):
    assert strict_dp.session_cui_tainted() is False
    strict_dp.note_cui_exposure("read_file", _CUI_DOC)
    assert strict_dp.session_cui_tainted() is True


def test_public_content_does_not_taint(strict_dp):
    strict_dp.note_cui_exposure("read_file", _PUBLIC_DOC)
    assert strict_dp.session_cui_tainted() is False


def test_tainted_session_blocked_from_non_allowlisted_sink(strict_dp):
    strict_dp.note_cui_exposure("read_file", _CUI_DOC)
    d = strict_dp.dlp_egress_decision("https://pastebin.test/x", allowlist=["mil"])
    assert d.blocked is True
    assert "cui" in d.reason.lower()


def test_tainted_session_allowed_to_allowlisted_sink(strict_dp):
    strict_dp.note_cui_exposure("read_file", _CUI_DOC)
    d = strict_dp.dlp_egress_decision("https://mail.agency.mil/send", allowlist=["agency.mil"])
    assert d.blocked is False


def test_untainted_session_egress_not_blocked(strict_dp):
    d = strict_dp.dlp_egress_decision("https://pastebin.test/x", allowlist=["mil"])
    assert d.blocked is False  # no CUI exposed → DLP does not gate (capability)


def test_taint_clears_on_reset(strict_dp):
    strict_dp.note_cui_exposure("read_file", _CUI_DOC)
    strict_dp.reset_dp_state()
    assert strict_dp.session_cui_tainted() is False


def test_cui_taint_is_scoped_to_runtime_session(strict_dp):
    strict_dp.note_cui_exposure("read_file", _CUI_DOC, session_id="session-a")
    assert strict_dp.session_cui_tainted(session_id="session-a")
    assert not strict_dp.session_cui_tainted(session_id="session-b")


def test_serialized_tool_result_cannot_hide_cui_banner(strict_dp):
    payload = '{"path":"doc.txt","content":"CUI\\nContract data\\nCUI"}'
    assert strict_dp.note_cui_exposure("read_file", payload, session_id="session-a")


def test_allowlist_matching_rejects_host_substring_suffix(strict_dp):
    strict_dp.note_cui_exposure("read_file", _CUI_DOC)
    decision = strict_dp.dlp_egress_decision(
        "https://agency.mil.evil.test/send", allowlist=["agency.mil"]
    )
    assert decision.blocked is True


# ---------------------------------------------------------------------------
# 4. LG-DP-07/08 — at-rest encryption wrapper, key outside agent write reach
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip(strict_dp, tmp_path, monkeypatch):
    keyfile = tmp_path / "keys" / "at-rest.key"
    monkeypatch.setenv("LLIAM_AT_REST_KEYFILE", str(keyfile))
    strict_dp.ensure_at_rest_key()
    token = strict_dp.encrypt_at_rest(b"CUI payload: contract data")
    assert token != b"CUI payload: contract data"        # actually encrypted
    assert b"CUI payload" not in token
    assert strict_dp.decrypt_at_rest(token) == b"CUI payload: contract data"


def test_at_rest_keyfile_is_on_the_write_denylist(strict_dp, tmp_path, monkeypatch):
    from agent import file_safety as fs

    home = str(tmp_path)
    monkeypatch.setenv("HERMES_HOME", home)
    monkeypatch.setenv("LLIAM_HOME", home)
    keyfile = strict_dp.at_rest_keyfile_path()
    # The key store must be unreachable by the agent's own write tools (LG-DP-08).
    assert fs.is_write_denied(str(keyfile))


# ---------------------------------------------------------------------------
# 5. LG-DP-11 — output masking + retention TTL marker
# ---------------------------------------------------------------------------

def test_mask_tool_result_redacts_pii(strict_dp):
    masked = strict_dp.mask_tool_result("SSN 123-45-6789 here")
    assert "123-45-6789" not in masked


def test_retention_ttl_exposed_from_config(strict_dp, monkeypatch):
    cfg = {"security": {"posture": "strict",
                        "data_protection": {"result_retention_ttl_seconds": 3600}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    assert strict_dp.result_retention_ttl_seconds() == 3600


# ---------------------------------------------------------------------------
# 6. Runtime binding — CUI exposure escalates egress via the PDP (LG-DP-10)
# ---------------------------------------------------------------------------

def test_egress_escalated_to_hitl_after_cui_exposure(tmp_path, monkeypatch):
    import textwrap

    policy = tmp_path / "tool-risk-policy.yaml"
    policy.write_text(textwrap.dedent(
        """
        metadata: {default_disposition: deny, fail_closed: true}
        action_classes:
          - {class: network.egress, tier: detect_log}
          - {class: file_read, tier: allow}
        """
    ), encoding="utf-8")
    cfg = {"security": {"posture": "strict", "tool_risk_policy": {
        "enabled": True, "policy_path": str(policy),
        "default_disposition": "deny", "fail_closed": True}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda *a, **kw: cfg)
    import agent.data_protection as dp
    import tools.tool_policy as tp

    dp.reset_dp_state()
    tp.reset_pdp_state()
    # Clean session: egress proceeds.
    assert tp.evaluate_call("vision_analyze", {"image": "x"}).disposition == "detect_log"
    # Expose CUI, then egress escalates to HITL; reads stay allowed.
    dp.note_cui_exposure("read_file", _CUI_DOC)
    d = tp.evaluate_call("vision_analyze", {"image": "x"})
    assert d.disposition == "hitl_approve" and d.origin == "cui_taint"
    assert tp.evaluate_call("read_file", {"path": "n"}).allows_execution
    dp.reset_dp_state()
    tp.reset_pdp_state()


def test_concurrent_first_tool_results_share_one_durable_key(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from agent import data_protection as dp

    keyfile = tmp_path / "keys" / "test.key"
    monkeypatch.setenv("LLIAM_AT_REST_KEYFILE", str(keyfile))
    first_write = Barrier(8)

    def store(i):
        first_write.wait(timeout=10)
        return dp.encrypt_at_rest(str(i).encode())

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(store, range(8)))
    assert [dp.decrypt_at_rest(blob) for blob in results] == [str(i).encode() for i in range(8)]
    from agent.file_safety import get_read_block_error, is_write_denied
    assert get_read_block_error(str(keyfile))
    assert is_write_denied(str(keyfile))


def test_governed_read_file_masks_before_display_and_preserves_taint(strict_dp, tmp_path):
    import json
    from model_tools import handle_function_call

    document = tmp_path / "example.txt"
    document.write_text("Synthetic identifier 123-45-6789")
    raw = handle_function_call("read_file", {"path": str(document)}, session_id="test-view")
    result = json.loads(raw)
    assert "[REDACTED-SSN]" in result["content"]
    assert "123-45-6789" not in raw
    assert strict_dp.session_cui_tainted(session_id="test-view")


def test_governed_dispatch_masks_errors_for_direct_callers(strict_dp, monkeypatch, caplog):
    import json
    from model_tools import handle_function_call, registry

    def unavailable(*args, **kwargs):
        raise RuntimeError("Synthetic record 123-45-6789 unavailable")

    monkeypatch.setattr(registry, "dispatch", unavailable)
    result = json.loads(handle_function_call("read_file", {"path": "fixture"}))
    assert "[REDACTED-SSN]" in result["error"]
    assert "123-45-6789" not in result["error"]
    assert "123-45-6789" not in caplog.text


@pytest.mark.parametrize("serialized", [False, True])
def test_masked_credentials_preserve_json_structure(strict_dp, serialized):
    import json

    original = [{"name": "first", "data": {"api_key": 'example"quoted secret'}}]
    result = strict_dp.mask_tool_result(json.dumps(original) if serialized else original)
    masked = json.loads(result) if serialized else result
    assert masked[0]["name"] == "first"
    assert "secret" not in masked[0]["data"]["api_key"]
