"""Gateway startup posture audit must read the EFFECTIVE merged config.

P1 review finding: ``start_gateway`` passed ``read_raw_config()`` (overlay-less)
to the startup audit, so ``security.no_default_credentials`` — injected by the
gov overlay and absent from the raw home config — was missing and the LG-IA-05
default-credential check was silently inert.
"""

from __future__ import annotations


def test_startup_audit_uses_merged_config_so_default_cred_check_fires(monkeypatch):
    import gateway.run as gr
    import lliam_cli.security_audit_startup as sas

    # The overlay switch lives ONLY in the merged config. A gateway that read
    # the raw shape would miss it and never flag the default credential.
    monkeypatch.setattr(
        "lliam_cli.config.load_config",
        lambda: {"security": {"no_default_credentials": True}},
    )
    monkeypatch.setattr(
        "lliam_cli.config.read_raw_config",
        lambda: {},  # overlay-less: would make the LG-IA-05 check inert
    )
    monkeypatch.setenv("PROVIDER_API_KEY", "changeme")  # a known default value
    monkeypatch.setattr(sas, "_AUDIT_RAN", False)  # allow the once-per-process run

    findings = gr._run_startup_security_audit(lliam_home=None)

    assert any(
        "PROVIDER_API_KEY" in f and "default" in f.lower() for f in findings
    ), findings


def test_start_gateway_binds_audit_cfg_in_scope():
    """Regression: extracting _run_startup_security_audit must not orphan the
    _audit_cfg references still used downstream in start_gateway (the LG-IA-02
    identity emit and the control-plane / audit-chain gate fallbacks).

    A name assigned in a function body is a local (co_varnames); a name only
    ever loaded is resolved as a global/builtin (co_names). If _audit_cfg is
    only assigned inside the helper, start_gateway's reads become unbound and
    raise NameError — swallowed by the surrounding non-fatal handlers, which
    silently kills the identity emit on every startup. _audit_cfg MUST be a
    local of start_gateway.
    """
    import gateway.run as gr

    code = gr.start_gateway.__code__
    assert "_audit_cfg" in code.co_varnames
    assert "_audit_cfg" not in code.co_names
