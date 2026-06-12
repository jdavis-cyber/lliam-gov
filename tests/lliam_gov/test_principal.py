"""Principal binding + production root refusal — LG-4.1 / AI-218.

WHY: SP 800-171 3.1.1/3.1.2 require system access limited to identified,
authenticated principals; ISO 27001 A.8.5 requires secure authentication
context. These tests pin (1) the principal comes from the OS euid, not
spoofable env vars, (2) root is refused under the production profile at
both security choke points, and (3) audit events carry the bound principal.
"""

import os

import pytest

from lliam_gov.security.principal import (
    PRODUCTION_PROFILE_ENV,
    ProductionRootRefused,
    get_principal,
    production_mode,
    require_principal,
)

posix_only = pytest.mark.skipif(
    not hasattr(os, "geteuid"), reason="POSIX-only principal model"
)


@posix_only
def test_principal_resolved_from_euid_not_env(monkeypatch):
    import pwd

    monkeypatch.setenv("USER", "spoofed-user")
    monkeypatch.setenv("LOGNAME", "spoofed-user")
    p = get_principal()
    assert p.username == pwd.getpwuid(os.geteuid()).pw_name
    assert p.username != "spoofed-user"
    assert p.uid == os.geteuid()
    assert p.method == "os_euid"


def test_production_mode_parsing(monkeypatch):
    monkeypatch.delenv(PRODUCTION_PROFILE_ENV, raising=False)
    assert not production_mode()
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "production")
    assert production_mode()
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "Production ")
    assert production_mode()
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "dev")
    assert not production_mode()


@posix_only
def test_root_refused_in_production(monkeypatch):
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "production")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ProductionRootRefused, match="refuses to run as root"):
        require_principal()


@posix_only
def test_root_allowed_outside_production(monkeypatch):
    """Dev hosts are unaffected — refusal is a production-profile control."""
    monkeypatch.delenv(PRODUCTION_PROFILE_ENV, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    p = require_principal()
    assert p.uid == 0


@posix_only
def test_normal_user_passes_in_production(monkeypatch):
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "production")
    p = require_principal()
    assert p.uid == os.geteuid() != 0


# ── choke-point integration ────────────────────────────────────────────────


@posix_only
def test_audit_events_carry_authenticated_principal(tmp_path, monkeypatch):
    import json
    import pwd

    from lliam_gov.security.audit_logger import AuditLogger

    monkeypatch.setenv("USER", "spoofed-user")
    logger = AuditLogger(audit_dir=tmp_path)
    logger.log_event(event_type="test_event", params={})
    record = json.loads(
        next(tmp_path.glob("*.jsonl")).read_text().splitlines()[0]
    )
    assert record["principal"] == pwd.getpwuid(os.geteuid()).pw_name


@posix_only
def test_shared_audit_logger_refuses_root_in_production(tmp_path, monkeypatch):
    import lliam_gov.security.audit_logger as al

    monkeypatch.setattr(al, "_shared_audit_logger", None)
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "production")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ProductionRootRefused):
        al.get_shared_audit_logger(audit_dir=tmp_path)


@posix_only
def test_shared_key_manager_refuses_root_in_production(monkeypatch):
    from lliam_gov.security import encrypted_file

    encrypted_file.reset_shared_key_manager()
    monkeypatch.setenv(PRODUCTION_PROFILE_ENV, "production")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ProductionRootRefused):
        encrypted_file.get_shared_key_manager()
