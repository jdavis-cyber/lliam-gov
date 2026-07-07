"""Guard test: defines "rename complete" for Phase R (hermes -> lliam).

TOKEN/LINE-LEVEL ALLOWLIST (R.8e-3c redesign)
=============================================
Earlier this guard was file-level (any file naming "hermes" was an offender).
After the full literal sweep almost every *file* that still says "hermes" does
so only on lines that are legitimate KEEPS — env vars, live contract keys,
upstream attribution, binary-DETECTION strings, opaque test-fixture data. A
file-level guard can therefore never go green without deleting real contracts.

New semantics: scan every (non-excluded) file line-by-line. For each line that
contains "hermes" (case-insensitive), the line PASSES iff either
  (a) its path is under a whole-tree keep (WHOLE_TREE_KEEPS), or
  (b) the line matches one documented KEEP_PATTERNS regex.
Any line that matches neither is an un-allowlisted "hermes" and FAILS the guard.

Every KEEP_PATTERNS entry carries a one-line rationale (why this hermes
survives) and is cross-referenced in
docs/governance/verification/R8e-keep-register.md — the assessor-facing
justification that "guard green == every survivor is a documented, justified
keep."

Discipline for future edits: before adding a pattern ask "is this the product's
DISPLAY NAME / command (→ rename it, don't allowlist) or opaque
data / contract / detection / upstream (→ keep + document)?" Over-keeping is
safe; the register documents it. NEVER allowlist-away a real product-name rename.
"""

import re
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Directory / glob EXCLUDES — mirror scripts/rename/exclude_globs.sh byte-for-byte.
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) planning docs — they quote the OLD name on purpose (history).
# ---------------------------------------------------------------------------
EXCLUDES = [
    "-g", "!**/node_modules/**", "-g", "!**/.git/**", "-g", "!**/dist/**",
    "-g", "!**/build/**", "-g", "!**/*.egg-info/**", "-g", "!graphify-out/**",
    "-g", "!evidence/**", "-g", "!**/*.lock", "-g", "!**/package-lock.json",
    "-g", "!NOTICE", "-g", "!ATTRIBUTION*", "-g", "!LICENSE*", "-g", "!docs/upstream/**",
    "-g", "!docs/governance/plans/**",   # planning docs quote the old name on purpose (history)
]

# ---------------------------------------------------------------------------
# WHOLE-TREE KEEPS — every "hermes" under these paths is a documented keep, so
# the guard does not read them line-by-line. Path is matched as a prefix
# (a directory entry covers everything beneath it) OR as an exact file.
#   - The one-time migration routine + env-compat shim are Lliam-owned but MUST
#     name the old home/env to migrate FROM it.
#   - tests/rename + scripts/rename ARE the rename infrastructure; they say
#     "hermes" to describe what they scan for.
#   - docker/** encodes the container's OS install identity (the `hermes` OS
#     user/group, /opt/hermes tree, s6 supervision) — an inherited runtime
#     contract, not the product display name.
#   - the upstream hermes-agent skills + the generated website skill-catalog +
#     the upstream marketing post are D4 upstream-authored / registry-keyed.
# ---------------------------------------------------------------------------
WHOLE_TREE_KEEPS = [
    "lliam_cli/migrate_home.py",
    "lliam_cli/env_compat.py",
    "hermes_cli/migrate_home.py",   # pre-R.2 path duality (harmless if absent)
    "hermes_cli/env_compat.py",
    "tests/rename",
    "scripts/rename",
    # Container / OS install identity — whole docker/ tree.
    "docker",
    # Upstream (D4) skills — `name:` is a registry key; renaming orphans them.
    "skills/autonomous-ai-agents/hermes-agent",
    "skills/software-development/hermes-agent-skill-authoring",
    # Generated skill-catalog mirrors of the above upstream skills.
    "website/docs/user-guide/skills/bundled/autonomous-ai-agents/autonomous-ai-agents-hermes-agent.md",
    "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/user-guide/skills/bundled/autonomous-ai-agents/autonomous-ai-agents-hermes-agent.md",
    "website/docs/user-guide/skills/optional/devops/devops-hermes-s6-container-supervision.md",
    "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/user-guide/skills/optional/devops/devops-hermes-s6-container-supervision.md",
    # Upstream marketing post authored in Lliam-GOV's own voice (D4).
    "hermes-already-has-routines.md",
    # OpenClaw->Hermes migration tool + its test. The rebrand-identity map
    # (OpenClaw/ClawdBot/MoltBot -> "Hermes") and its lowercase branch are
    # functionally coupled to the KEPT `.hermes` home: lowercase matches must
    # rewrite `~/.openclaw` -> `~/.hermes` (the real home), not a non-existent
    # `~/.lliam-gov`. 50+ rebrand outputs are asserted by string-equality in the
    # test. Renaming the replacement value would inject a migration bug and break
    # the external-contract test. Filename openclaw_to_hermes.py is itself a
    # documented keep. Kept whole; a separate D-level decision, not a mechanical
    # rename, governs whether the migration target identity ever changes.
    "optional-skills/migration/openclaw-migration/scripts/openclaw_to_hermes.py",
    "tests/skills/test_openclaw_migration.py",
]


def _is_whole_tree_keep(path: str) -> bool:
    normalized = path[2:] if path.startswith("./") else path
    return any(
        normalized == keep or normalized.startswith(keep + "/")
        for keep in WHOLE_TREE_KEEPS
    )


# ---------------------------------------------------------------------------
# KEEP_PATTERNS — line-level allowlist. Each (regex, rationale). A "hermes"
# line PASSES if ANY pattern matches. Patterns are applied to the raw line text
# (path stripped) case-insensitively unless noted. Rationale mirrored in
# docs/governance/verification/R8e-keep-register.md.
# ---------------------------------------------------------------------------
KEEP_PATTERNS: list[tuple[str, str]] = [
    # --- Legacy home / paths (migrate-FROM literals) ---
    (r"~/\.hermes", "legacy home dir literal ~/.hermes — migrate-from path"),
    (r"\.hermes(?![a-z])", "legacy .hermes home/dir/file literal — migrate-from path"),
    (r"%LOCALAPPDATA%\\+hermes", "Windows legacy install path — migrate-from"),
    (r"hermes_history", "legacy history filename — migrate-from artifact"),
    (r"hermes_state\.db", "legacy state DB filename — migrate-from artifact"),
    (r"HERMES\.md", "legacy project-context filename (_LLIAM_MD_NAMES contract)"),

    # --- Env vars: whole HERMES_* namespace is a preserved back-compat contract ---
    (r"HERMES_[A-Z0-9_]+", "HERMES_* env var — preserved backward-compat env API"),

    # --- Contract literals: live keys / kwargs / wire fields ---
    (r"hermes_home", "live kwargs-dispatch key / var / detection substring for HERMES_HOME"),
    (r"hermes_root", "live argparse dest / dispatch key (paired with --lliam-root alias)"),
    (r"hermesRoot|active_hermes_root", "live JS/electron config key for the resolved root"),
    (r"hermes_version", "contract field name in status/version payloads"),
    (r"hermes_bin", "contract field: resolved gateway binary path"),
    (r"hermes_env", "contract field: env snapshot key"),
    (r"hermes_pkce", "contract field: OAuth PKCE session key"),
    (r"hermes_session_(at|rt|key|id|platform|source|chat_id|pkce|token)",
     "hermes_session_* live session-contract field names"),
    (r"hermes_client_tag", "contract field: client tag"),
    (r"hermes-index", "contract identifier: index name"),
    (r"PAL_HERMES", "contract env/const prefix"),
    (r"X-Hermes-[A-Za-z-]+", "X-Hermes-* HTTP header contract"),
    (r"x-hermes-session-[a-z]+", "x-hermes-session-* HTTP header contract"),
    (r"__hermes_session_token__|window\.__HERMES", "live JS dashboard global"),
    (r"_HERMES_CORE_TOOLS|__HERMES_PLUGIN", "live JS plugin-SDK global"),
    (r"hermes_agent\.plugins", "live pip entry-point group ENTRY_POINTS_GROUP"),

    # --- Legacy service / process detection markers (detecting/cleaning OLD binary) ---
    (r"hermes-gateway", "legacy service/process name — detection marker"),
    (r"hermes\.service|ai\.hermes\.gateway", "legacy systemd/launchd unit id — detection"),
    (r"s6-setuidgid hermes", "legacy s6 supervision directive — container detection"),
    (r"main-hermes", "legacy tmux/session marker — detection"),
    (r"hermes gateway|/hermes gateway", "legacy CLI-invocation string matched for detection"),
    (r"Hermes_Gateway", "legacy scheduled-task name — detection"),
    (r'source_host.*hermes_', "legacy source-host prefix detection"),
    (r"hermes\.exe\.old", "old-binary cleanup filename"),
    (r"command -v hermes\b|shutil\.which\(.hermes.\)|which\(.hermes.\)",
     "OLD-binary presence detection (not invoking the new product binary)"),
    (r"taskkill.*hermes\.exe|hermes\.exe.*taskkill", "OLD-binary termination — cleanup"),
    (r"looks_like_gateway_command_line|_gateway_runtime_command_line",
     "OLD gateway command-line detection helper"),
    (r"hermes\.exe(?!\.)", "OLD desktop/gateway binary name — detection/cleanup target"),
    (r"hermes\.app", "OLD macOS app bundle name — detection/cleanup target"),
    (r"hermes\.plist|hermes-gateway\.service", "legacy service unit filename — detection"),

    # --- External identifiers registered with third parties (renaming breaks integration) ---
    (r"hermes-cli", "OAuth client_id registered with provider — external contract"),
    (r"DEFAULT_NOUS_CLIENT_ID", "Nous OAuth default client id constant"),
    (r"hermes-weixin-", "WeChat/Weixin registered app prefix — external"),
    (r"hermes-agent", "upstream product id / registered wire tag (portal, exa, copilot, honcho)"),
    (r'product=hermes|"topic":\s*"hermes', "registered wire product/topic tag — external"),
    (r"_ECHO_TAG|x-exa-integration", "registered integration tag value — external"),
    (r"/hermes\b", "Slack slash-command registered with the app — external"),
    (r"hermes slack manifest|slack.*hermes manifest", "Slack app manifest name — external"),
    (r"@[Hh]ermes(bot|_bot)?\b", "Matrix/Telegram/IRC registered handle — external"),
    (r"hermes-whatsapp-bridge", "npm package name (externally referenced) — external"),
    (r"hermesbot-cron", "IRC handle — external"),
    (r"hermes-telegram|hermes-acp|hermes-achievements|hermes-update",
     "registered plugin/integration ids — external/contract"),
    (r'"hermes-[a-z][a-z-]*"',
     "toolset/platform-preset config key (cli-config.yaml.example platform_toolsets namespace) — "
     "user-facing config contract; renaming breaks existing configs + string-equality tests"),
    (r'hermes-\*|hermes-<|startswith\("hermes-"\)|"hermes-"|\[len\("hermes-"\)',
     "toolset-key NAMESPACE prefix literal — the `hermes-<platform>` preset contract; "
     "the startswith/prefix logic must match the kept toolset keys"),

    # --- Wire attribution to 3rd-party APIs (X-Title / User-Agent / registry name) ---
    (r'X-Title.*Hermes Agent|"Hermes Agent"', "OpenRouter X-Title / ACP registry name — wire attribution"),
    (r"Hermes-Watcher|Hermes[- ]Agent[/ ]", "User-Agent value sent to 3rd-party API"),
    (r"codex_cli_rs|graph-client|x-exa", "3rd-party User-Agent/integration value on a hermes line"),

    # --- Upstream (D4): Nous Research / Hermes-4 model + repo attribution ---
    (r"nous_hermes|is_nous_hermes", "upstream Nous Hermes model detection"),
    (r"Hermes-4|Hermes 4|Hermes-3|Hermes 3", "upstream Nous Research model family name"),
    (r"nousresearch/hermes-agent|NousResearch/hermes-agent",
     "upstream repo path — attribution + working link"),
    (r"hermes-agent\.nousresearch\.com", "upstream download/site host — attribution"),
    (r"teknium|@PCinkusz|Nous Research", "upstream author/lab attribution"),
    (r"services\.hermes-agent", "upstream nix service identifier"),

    # --- Container / OS install identity (also covered by docker/** whole-tree keep) ---
    (r"/opt/hermes", "container install prefix — OS install identity"),
    (r"TARGET_USER=hermes|GROUP_NAME=hermes|useradd.*hermes|groupadd.*hermes",
     "container OS user/group identity"),
    (r"hermes_uid|hermes_gid|hermes_tree", "container OS uid/gid/tree identity"),

    # --- Incident / proper-noun ---
    (r"hermes-0day", "security incident proper-noun name"),
    (r"hermesagent26@users\.noreply\.github\.com", "contributor email — proper noun"),

    # --- Upstream file/skill refs ---
    (r"openclaw_to_hermes\.py", "real un-renamed migration script filename"),
    (r"HermesClaw|hermesclaw", "third-party project name (not this fork)"),

    # --- Tooling: migrate_home / env_compat / migration markers ---
    (r"migrate_home|env_compat|\.migrated_from_hermes", "one-time migration tooling"),
    (r"--hermes-root", "back-compat CLI alias for --lliam-root (kept one release)"),
    (r"--hermes-home", "back-compat CLI alias for --lliam-home / HERMES_HOME (kept one release)"),
    (r"LLIAM_DESKTOP_HERMES", "desktop back-compat env prefix"),

    # --- Arbitrary test-fixture DATA (opaque values a test asserts/uses, NOT the product name) ---
    (r'tmp_path\s*/\s*"?hermes"?', "pytest tmp fixture dir name — opaque data"),
    (r'"topic":\s*"hermes-in"', "test fixture topic value — opaque data"),
    (r'_agent\s*=\s*"hermes"', "test fixture provider-agent value — opaque data"),
    (r"hermes@(test|localhost)", "test fixture email — opaque data"),
    (r"hermes/feat", "test fixture git branch name — opaque data"),
    (r"hermes-desktop-|hermes-relaunch-", "test tmp-file prefix — opaque data"),
    (r"hermes please help|\^hermes|@Hermes agent|MyHermesBot",
     "wake-word / bot-name test fixture — opaque data"),
    (r"hermes-security", "test host-key/profile fixture — opaque data"),
    (r"hermes_test\b|hermes_kanban|hermes_timezone|hermes_stream_retries",
     "opaque test fixture identifiers seeded as data"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), why) for rx, why in KEEP_PATTERNS]


def _line_is_allowed(text: str) -> bool:
    return any(rx.search(text) for rx, _ in _COMPILED)


def test_no_lliam_owned_hermes_refs():
    # Repo root = two parents up from this file (tests/rename/<this file>).
    # rg must run with this as cwd so relative excludes keep matching.
    repo_root = Path(__file__).resolve().parents[2]

    # -i case-insensitive, -n line numbers, --no-heading path:line:text per match.
    result = subprocess.run(
        ["rg", "-in", "--no-heading", "hermes", *EXCLUDES, "."],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    # rg exit codes: 0 = matches found, 1 = no matches, 2+ = actual error.
    assert result.returncode in (0, 1), (
        f"rg failed to run (exit {result.returncode}): {result.stderr}"
    )

    offenders: list[str] = []
    for raw in result.stdout.splitlines():
        # Split "path:linenum:content" — path may contain ':' only on Windows,
        # not here; split on the first two colons.
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        path, _lineno, text = parts
        if _is_whole_tree_keep(path):
            continue
        if _line_is_allowed(text):
            continue
        offenders.append(f"{path}:{_lineno}: {text.strip()[:160]}")

    shown = offenders[:30]
    assert not offenders, (
        f"{len(offenders)} un-allowlisted 'hermes' lines remain "
        f"(each is either a Lliam-owned rename target, or a legitimate keep "
        f"needing a documented KEEP_PATTERNS entry). First {len(shown)}:\n"
        + "\n".join(shown)
    )
