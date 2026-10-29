"""AI-1184: outside lazy_deps' own tests, a missing optional SDK is unavailable."""

import pytest

from tools import lazy_deps as ld


def test_missing_sdk_reads_as_unavailable(monkeypatch):
    # e.g. the edge-tts availability check during AIAgent setup: it must not
    # install into the shared venv.
    monkeypatch.setattr(ld, "feature_missing", lambda feature: ("edge-tts==7.2.7",))
    with pytest.raises(ld.FeatureUnavailable, match="lazy installs disabled"):
        ld.ensure("tts.edge", prompt=False)
