"""First-run provider card view-models (AI-329, backend half).

Maps a :class:`ProviderReadinessReport` into a render-ready card the desktop
first-run screen and model picker can display directly, with one card state per
readiness value and an exact CLI setup command — **never** an API-key prompt.

Keeping this mapping on the backend means the renderer is a thin consumer and
the state/command/copy logic is unit-tested in the Python gate. The React
wiring + renderer (vitest) tests are the remaining AI-329 increment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from providers.cli.contract import ProviderReadinessReport, Readiness

# Per-state UX copy. ``selectable`` gates whether the model picker may pick the
# provider; only READY (CLI installed + authenticated) is selectable. No state
# ever asks for an API key — actions are CLI install/login commands only.
_STATE_UX: dict[Readiness, dict] = {
    Readiness.READY: {
        "status_label": "Ready",
        "tone": "positive",
        "selectable": True,
        "action_label": "",
    },
    Readiness.NOT_INSTALLED: {
        "status_label": "Not installed",
        "tone": "neutral",
        "selectable": False,
        "action_label": "Install",
    },
    Readiness.NOT_AUTHENTICATED: {
        "status_label": "Needs sign-in",
        "tone": "warning",
        "selectable": False,
        "action_label": "Sign in",
    },
    Readiness.DEGRADED: {
        "status_label": "Degraded",
        "tone": "warning",
        "selectable": True,
        "action_label": "Retry",
    },
    Readiness.UNAVAILABLE: {
        "status_label": "Unavailable",
        "tone": "error",
        "selectable": False,
        "action_label": "",
    },
}


@dataclass(frozen=True)
class ProviderCard:
    """Render-ready first-run/model-picker card. Carries no secrets."""

    id: str
    display_name: str
    state: str
    status_label: str
    tone: str
    selectable: bool
    action_label: str
    action_command: str  # exact CLI command to run — never an API key
    default_model: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def to_card(report: ProviderReadinessReport) -> ProviderCard:
    """Build a :class:`ProviderCard` from a readiness report."""
    ux = _STATE_UX.get(report.readiness, _STATE_UX[Readiness.UNAVAILABLE])
    return ProviderCard(
        id=report.id,
        display_name=report.display_name,
        state=report.readiness.value,
        status_label=ux["status_label"],
        tone=ux["tone"],
        selectable=ux["selectable"],
        action_label=ux["action_label"],
        # setup_hint is the CLI install/login command for the current state.
        action_command=report.setup_hint,
        default_model=report.default_model,
    )


def cards_for(reports: list[ProviderReadinessReport]) -> list[ProviderCard]:
    return [to_card(r) for r in reports]
