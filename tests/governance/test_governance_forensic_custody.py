"""SR-22: forensic custody of evidence in the governed profile.

The oss-forensics skill's evidence store (tests/test_evidence_store.py) is
DENIED under the governed profile, so it cannot be the custody evidence for a
governed deployment. No allowed governance component offers a separate
custody store. The component that does hold custody is the hash-chained
governance audit ledger (agent/governance_audit.py) and its verifiers: the
CI/cron chain gate and the portable attestation that anchors the chain tip.
This file re-points the custody properties the oss-forensics test checks onto
that ledger, under the shipped overlay:

  * every governed action becomes a record: sequential id, unique event id,
    UTC timestamp, attributable actor, action, decision (custody log);
  * records persist and reload, and a restarted writer extends the same chain;
  * each record is sealed: record_hash is SHA-256 over its canonical bytes and
    links to its predecessor, and masked evidence keeps a content_hash an
    investigator can recompute from the original;
  * any edit, deletion, reorder or forged insertion is detected by the
    governance chain gate (exit 1, first break named), and suffix truncation
    is detected against the attested chain-tip anchor;
  * the agent's own write tools cannot reach the ledger.

tests/test_evidence_store.py is kept; it still covers the optional skill.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys

import pytest

from tests.governance._governed_profile import (
    REPO,
    call_tool,
    enter_governed_profile,
    stub_tool_handlers,
)

sys.path.insert(0, str(REPO / "ci" / "governance-ci-gates"))

import attestation_export as ax  # noqa: E402
import audit_chain_gate as acg  # noqa: E402

_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

_SESSION = [
    ("read_file", {"path": "src/app.py"}),
    ("search_files", {"pattern": "TODO", "path": "src"}),
    ("terminal", {"command": f"git push https://x:{_SECRET}@example.invalid/r.git"}),
    ("terminal", {"command": "pytest -q"}),
]


@pytest.fixture
def custody(tmp_path, monkeypatch):
    gp = enter_governed_profile(tmp_path, monkeypatch)
    calls = stub_tool_handlers(monkeypatch)
    for name, args in _SESSION:
        call_tool(name, args, task_id="incident-42")
    return gp, calls


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _rewrite(path, records):
    path.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":"))
                            + "\n" for r in records), encoding="utf-8")


def _gate(path) -> int:
    return acg.main(["--ledger", str(path), "--require-strict"])


# --- why the re-point: the optional evidence store is not available ---------

def test_oss_forensics_evidence_store_is_denied_in_governed_profile(tmp_path, monkeypatch):
    enter_governed_profile(tmp_path, monkeypatch)
    from tools.tool_policy import skill_load_decision

    skill_dir = REPO / "optional-skills" / "security" / "oss-forensics"
    assert (skill_dir / "scripts" / "evidence-store.py").is_file()
    decision, reason = skill_load_decision("oss-forensics", skill_dir)
    assert decision == "deny", reason


# --- custody log: one attributable, ordered record per action --------------

def test_every_governed_action_has_a_custody_record(custody):
    gp, calls = custody
    recs = _records(gp.ledger_path)
    assert [c[0] for c in calls] == [n for n, _ in _SESSION]   # work still ran

    assert [r["seq"] for r in recs] == list(range(1, len(recs) + 1))
    assert len({r["event_id"] for r in recs}) == len(recs)
    stamps = [dt.datetime.fromisoformat(r["ts"]) for r in recs]
    assert all(s.utcoffset() == dt.timedelta(0) for s in stamps)
    assert stamps == sorted(stamps)

    dispatches = [r for r in recs if r["event"] == "tool.dispatch"]
    results = [r for r in recs if r["event"] == "tool.result"]
    assert [r["action"] for r in dispatches] == [f"tool.{n}" for n, _ in _SESSION]
    assert [r["action"] for r in results] == [f"tool.{n}" for n, _ in _SESSION]
    assert {r["correlation_id"] for r in recs} == {"task-incident-42"}
    for r in dispatches:
        actor = r["actor"]
        assert actor["type"] == "npe"
        assert str(actor["instance_id"]).startswith("sha256:")
        assert str(actor["config_hash"]).startswith("sha256:")


def test_custody_persists_and_restart_extends_the_same_chain(custody):
    from agent.governance_audit import GovernanceLedger, verify_chain

    gp, _calls = custody
    before = _records(gp.ledger_path)
    reopened = GovernanceLedger(gp.ledger_path)
    rec = reopened.emit("security.error", action="custody.reopen_probe",
                        source_module="tests/governance/custody")
    assert rec["seq"] == before[-1]["seq"] + 1
    assert rec["prev_hash"] == before[-1]["record_hash"]
    assert _records(gp.ledger_path)[: len(before)] == before
    assert verify_chain(gp.ledger_path).ok


# --- integrity: sealed records + recomputable evidence hash ----------------

def test_records_are_sealed_and_linked(custody):
    from agent.governance_audit import GENESIS_PREV_HASH, canonical_bytes

    gp, _calls = custody
    prev = GENESIS_PREV_HASH
    for r in _records(gp.ledger_path):
        assert r["record_hash"] == hashlib.sha256(canonical_bytes(r)).hexdigest()
        assert r["prev_hash"] == prev
        prev = r["record_hash"]
    assert _gate(gp.ledger_path) == 0


def test_masked_evidence_keeps_a_recomputable_content_hash(custody):
    gp, calls = custody
    raw = gp.ledger_path.read_text(encoding="utf-8")
    assert _SECRET not in raw                       # never on disk
    secret_args = dict(_SESSION[2][1])
    assert calls[2] == ("terminal", secret_args)    # handler got the real value
    original = json.dumps(secret_args, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(original).hexdigest()
    disp = [r for r in _records(gp.ledger_path)
            if r["event"] == "tool.dispatch" and r["action"] == "tool.terminal"][0]
    assert disp["parameters"]["content_hash"] == expected


# --- tamper evidence via the governance chain gate --------------------------

def _tamper_edit(recs):
    recs[2]["outcome"] = {"status": "failure", "class": "edited"}
    return recs, recs[2]["seq"]


def _tamper_delete(recs):
    gone = recs.pop(3)
    return recs, gone["seq"] + 1


def _tamper_reorder(recs):
    recs[2], recs[3] = recs[3], recs[2]
    return recs, recs[2]["seq"]


def _tamper_forged_insert(recs):
    from agent.governance_audit import canonical_bytes

    forged = dict(recs[1], event_id="forged", action="tool.read_file")
    forged["record_hash"] = hashlib.sha256(canonical_bytes(forged)).hexdigest()
    recs.insert(2, forged)
    return recs, forged["seq"]


@pytest.mark.parametrize("tamper", [_tamper_edit, _tamper_delete, _tamper_reorder,
                                    _tamper_forged_insert],
                         ids=["edit", "delete", "reorder", "forged-insert"])
def test_chain_gate_detects_tamper(custody, capsys, tamper):
    from agent.governance_audit import verify_chain

    gp, _calls = custody
    assert _gate(gp.ledger_path) == 0
    recs, expected_break = tamper(_records(gp.ledger_path))
    _rewrite(gp.ledger_path, recs)
    assert _gate(gp.ledger_path) == 1
    assert "TAMPER DETECTED" in capsys.readouterr().out
    result = verify_chain(gp.ledger_path)
    assert not result.ok and result.break_seq == expected_break


def test_truncation_detected_against_attested_tip(custody, monkeypatch):
    from agent.governance_audit import verify_chain

    gp, _calls = custody
    signed = ax.sign_attestation(ax.build_attestation(
        repo_root=REPO, stamp="2026-10-20T00:00:00Z", attested_by="isso@agency.mil"))
    assert ax.verify_attestation(signed)
    tip = signed["audit_chain"]
    recs = _records(gp.ledger_path)
    assert tip == {"status": "live", "tip_record_hash": recs[-1]["record_hash"],
                   "tip_seq": recs[-1]["seq"]}

    # Legitimate growth after the anchor verifies from the attested tip.
    call_tool("read_file", {"path": "README.md"}, task_id="incident-42")
    assert verify_chain(gp.ledger_path, start_after_seq=tip["tip_seq"],
                        start_prev_hash=tip["tip_record_hash"]).ok

    # Suffix truncation still leaves an internally consistent prefix, so the
    # plain gate passes (documented residual)...
    _rewrite(gp.ledger_path, recs[:-2])
    assert verify_chain(gp.ledger_path).ok
    # ...but the attested anchor no longer exists: custody break detected.
    anchored = verify_chain(gp.ledger_path, start_after_seq=tip["tip_seq"],
                            start_prev_hash=tip["tip_record_hash"])
    assert not anchored.ok and "anchor" in anchored.reason

    # And the attestation itself cannot be re-pointed at the shorter chain.
    forged = dict(signed, audit_chain=dict(tip, tip_seq=tip["tip_seq"] - 2))
    assert not ax.verify_attestation(forged)


def test_agent_write_tools_cannot_reach_the_ledger(custody):
    import agent.file_safety as fs

    gp, _calls = custody
    assert fs.is_write_denied(str(gp.ledger_path))
    assert not fs.is_write_denied(str(gp.safe_root / "notes.md"))
