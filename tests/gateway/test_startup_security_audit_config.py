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
