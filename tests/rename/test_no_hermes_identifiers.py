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
import shutil
import subprocess
from pathlib import Path

from tests.rename import _hermes_scan

# ---------------------------------------------------------------------------
# Directory / glob EXCLUDES — mirror scripts/rename/exclude_globs.sh byte-for-byte.
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering;
#           (d) planning docs — they quote the OLD name on purpose (history);
#           (e) the rename keep-register / verify-report — meta-docs that MUST
#               quote the old name to document the surviving keeps.
# ---------------------------------------------------------------------------
EXCLUDES = [
    "-g", "!**/node_modules/**", "-g", "!**/.git/**", "-g", "!**/dist/**",
    "-g", "!**/build/**", "-g", "!**/*.egg-info/**", "-g", "!graphify-out/**",
    "-g", "!evidence/**", "-g", "!**/*.lock", "-g", "!**/package-lock.json",
    "-g", "!NOTICE", "-g", "!ATTRIBUTION*", "-g", "!LICENSE*", "-g", "!docs/upstream/**",
    "-g", "!docs/governance/plans/**",   # planning docs quote the old name on purpose (history)
    "-g", "!docs/governance/verification/*keep-register.md",   # keep-registers document the kept old-name tokens
    "-g", "!docs/governance/verification/R-rename-report.md",  # R.V report cites the keeps
]

# ---------------------------------------------------------------------------
# WHOLE-TREE KEEPS — every "hermes" under these paths is a documented keep, so
# the guard does not read them line-by-line. Path is matched as a prefix
# (a directory entry covers everything beneath it) OR as an exact file.
#   - The one-time migration routine + env-compat shim are Lliam-owned but MUST
#     name the old home/env to migrate FROM it.
#   - tests/rename + scripts/rename ARE the rename infrastructure; they say
#     "hermes" to describe what they scan for.
#   - the upstream hermes-agent skills + the generated website skill-catalog +
#     the upstream marketing post are D4 upstream-authored / registry-keyed.
# ---------------------------------------------------------------------------
WHOLE_TREE_KEEPS = [
    "lliam_cli/migrate_home.py",
    "lliam_cli/env_compat.py",
    # Desktop localStorage-key migration: maps the OLD `hermes*` keys onto the
    # new `lliam-gov*` keys. Every `hermes*` literal is a migrate-from source
    # (same role as migrate_home.py) — renaming them breaks the migration.
    "apps/desktop/src/lib/migrate-storage-keys.ts",
    "apps/desktop/src/lib/migrate-storage-keys.test.ts",
    "hermes_cli/migrate_home.py",   # pre-R.2 path duality (harmless if absent)
    "hermes_cli/env_compat.py",
    "tests/rename",
    "scripts/rename",
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
    # Tauri bootstrap-installer (Rust src-tauri): a self-consistent, test-asserted
    # internal identity the base rebrand deliberately left unchanged — CLI-resolution
    # (resolve_hermes_desktop_exe), straggler-kill, Tauri IPC command names (JS<->Rust
    # wire contract), and the hermes_bootstrap_lib crate. Whether that binary is
    # `hermes` or `lliam-gov` is a flagged D-level follow-up, not a mechanical rename.
    "apps/bootstrap-installer",
    # ⚑ FLAGGED DESKTOP FINDING (R.5/R.9): the electron main process still references
    # the PRE-RENAME backend Python package throughout its integration — `import
    # hermes_cli`, `path.join(root, 'hermes_cli', 'main.py'/'__init__.py')`,
    # `-m hermes_cli.uninstall`, and hermes_cli/hermes_constants/hermes_logging in
    # comments. The backend package is `lliam_cli` now, so these are functional and
    # likely BROKEN (the desktop app may not resolve/spawn the renamed backend). This
    # was NOT updated during Phase R (R.5 handled electron IDENTITY — appId/IPC/protocol
    # — not backend-package references). Migrating these to lliam_cli is a functional
    # desktop task that MUST be verified with `npm run test:ui` + a real backend spawn,
    # NOT a blind text rename in a guard-cleanup. Kept here (documented, NOT masked) so
    # the finding is explicit; see R8e-keep-register.md §G and the R.V desktop proof.
    "apps/desktop/electron",
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
    (r"LOCALAPPDATA,\s*'hermes'|localappdata.*'hermes'",
     "JS Windows legacy home path (path.join(LOCALAPPDATA,'hermes')) — migrate-from"),
    (r"'hermes-home'|\"hermes-home\"",
     "legacy desktop data-subdir literal 'hermes-home' — inherited path"),
    (r"99-hermes-wsl-windows-fonts\.conf",
     "product-written fontconfig filename under the legacy hermes dir — install artifact"),
    (r"hermes-setup(\.exe)?",
     "staged Tauri bootstrap-installer binary name detected by the desktop — "
     "coordinated staging filename; renaming risks breaking staged-installer detection"),
    (r"hermes_history", "legacy history filename — migrate-from artifact"),
    (r"hermes_state\.db", "legacy state DB filename — migrate-from artifact"),
    (r"HERMES\.md", "legacy project-context filename (_LLIAM_MD_NAMES contract)"),

    # --- Env vars: whole HERMES_* namespace is a preserved back-compat contract ---
    # (?-i:...) forces UPPERCASE-only: env vars are always ALL-CAPS. Without it the
    # global re.IGNORECASE made this match lowercase hermes_<word> too, silently
    # masking 500+ stale hermes_cli / hermes_constants / hermes_logging module refs.
    (r"(?-i:HERMES_[A-Z0-9_]*)", "HERMES_* env var / namespace prefix (UPPERCASE-only; incl. bare `HERMES_`/`HERMES_*` in prose) — preserved backward-compat env API"),

    # --- Contract literals: live keys / kwargs / wire fields ---
    (r"hermes_home", "live kwargs-dispatch key / var / detection substring for HERMES_HOME"),
    (r"hermes_root", "live argparse dest / dispatch key (paired with --lliam-root alias)"),
    (r"<hermes-root>", "doc placeholder for the resolved root dir (paired with the kept root contract)"),
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
    (r'"?hermes\.(session|run|tool\.progress|subagent\.[a-z]+|api_server[a-z.]*|governance\.posture|lastlocation)"?|'
     r'hermes\.session\.(chat\.completion|deleted)|"?object"?:\s*"hermes|'
     r'\[.hermes.\]\s*=|response_data\["hermes"\]|err_body\["error"\]\["hermes"\]|finish_chunk\["hermes"\]|'
     r'"owned_by":\s*"hermes"|event:\s*hermes\.',
     "API wire-protocol object type / response-envelope key returned to HTTP clients — "
     "external contract, test-asserted (tests/gateway/test_session_api.py, test_api_server.py)"),
    (r"hermes\.tokenReloadAttempted|hermesTokenStorage|hermes\.governance\.posture",
     "dashboard/portal client-side storage + telemetry keys — persisted-state contract"),
    (r"_HERMES_CORE_TOOLS|__HERMES_PLUGIN", "live JS plugin-SDK global"),
    (r"hermes_agent\.plugins", "live pip entry-point group ENTRY_POINTS_GROUP"),
    (r"persist:hermes-remote-oauth",
     "electron session-partition storage key — renaming orphans persisted OAuth sessions"),
    (r"hermes-dashboard-theme|hermes-dashboard-font|hermes-theme-custom-css|"
     r"data-hermes-theme-(css|font)|hermes-dashboard-[a-z-]+",
     "web-dashboard localStorage key / DOM data-attribute — persisted-state contract with no "
     "migration path (unlike the desktop keys); renaming orphans user prefs"),
    (r"currentHermesSessionId|rootHermesSessionId|parentHermesSessionId|previousHermesSessionId",
     "ACP provenance session-id JSON key — external wire contract, test-asserted "
     "(tests/acp/test_session_provenance.py)"),
    (r"hermes:fs:[a-zA-Z]+|hermes:[a-z]+:[a-z]+",
     "electron IPC channel name — JS<->main wire contract"),
    (r"hermes-auth-store", "auth-record source tag — persisted/contract field"),
    (r"can_update_hermes", "dashboard capability JSON field — wire contract"),
    (r"hermes-webui", "upstream/container WebUI image name — inherited image identity"),
    (r'"hermes" in mid\.lower\(\)', "legacy message-id substring DETECTION — keep matching old ids"),

    # --- Legacy service / process detection markers (detecting/cleaning OLD binary) ---
    (r"hermes-gateway", "legacy service/process name — detection marker"),
    (r"hermes\.service|ai\.hermes\.gateway", "legacy systemd/launchd unit id — detection"),
    (r"s6-setuidgid hermes", "legacy s6 supervision directive — container detection"),
    (r"main-hermes", "legacy tmux/session marker — detection"),
    (r"lliam-gov gateway|/lliam-gov gateway", "legacy CLI-invocation string matched for detection"),
    (r"Hermes_Gateway", "legacy scheduled-task name — detection"),
    (r'source_host.*hermes_', "legacy source-host prefix detection"),
    (r'"hermes" units|ai\.\*.*hermes\*|/opt/custom-hermes|username \(e\.g\. hermes\)|'
     r'hermes\* jobs|third-party.*hermes',
     "gateway service/job DETECTION prose + a kept /opt/custom-hermes rename example + a bot-"
     "username example — detection strings must keep matching legacy 'hermes' units"),
    (r"hermes\.exe\.old", "old-binary cleanup filename"),
    (r"command -v hermes\b|shutil\.which\(.hermes.\)|which\(.hermes.\)",
     "OLD-binary presence detection (not invoking the new product binary)"),
    (r"taskkill.*hermes\.exe|hermes\.exe.*taskkill", "OLD-binary termination — cleanup"),
    (r"looks_like_gateway_command_line|_gateway_runtime_command_line",
     "OLD gateway command-line detection helper"),
    (r"resolve_hermes\b|venv_hermes\b|force_kill_other_hermes|resolve_hermes_desktop_app|"
     r"launch_hermes_desktop|the hermes CLI|venv shim.*hermes|hermes <args>|&hermes,|"
     r"venv.*bin.*hermes|isn't named hermes\.exe|\$HermesHome",
     "bootstrap-installer (src-tauri) CLI-resolution + OLD-straggler-kill + Tauri IPC-command "
     "family — a self-consistent, test-asserted internal identity the base rebrand commit "
     "deliberately left unchanged (IPC command names are a JS<->Rust wire contract). The "
     "`venv/bin/hermes` shim path + PowerShell $HermesHome ref pair with the desktop install "
     "root; whether that binary is `hermes` or `lliam-gov` is a flagged D-level follow-up"),
    (r"local_app_data\.join\(\"hermes\"\)",
     "Rust legacy Windows home path (LOCALAPPDATA/hermes) — migrate-from"),
    (r"hermes-swap-test-|hermes-bootstrap-test-|hermes-desktop-build-",
     "Rust #[cfg(test)] temp-dir fixture prefix — opaque test data"),
    (r"\.hermes-update-(new|old|in-progress)",
     "cross-process update marker filename — written by Tauri, read by electron "
     "(apps/desktop/electron/update-marker.cjs); both sides must agree, so kept"),
    (r'setproctitle\(\s*"hermes"\)|prctl\(15,\s*b"hermes"|pthread_setname_np\(\s*b"hermes"|process title to .hermes',
     "process title 'hermes' — coordinated with the pkill/pgrep self-termination "
     "guard (tools/approval.py) that blocks killing the running gateway; kept so "
     "the guard keeps matching and already-running processes stay detectable"),
    (r"process show up as 'hermes'|show up as .hermes",
     "comment documenting the kept 'hermes' proctitle value"),
    (r'\(hermes\|gateway\|cli\.py\)|pkill hermes|pgrep -f hermes|hermes\.\*dashboard|hermes/gateway',
     "process-name detection/kill-guard pattern — must match the kept 'hermes' proctitle"),
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
    (r"--client hermes|--client \{name\}.*hermes|归因.*hermes|agent 名称.*hermes",
     "here-now skill --client attribution tag value 'hermes' — external routing/attribution tag"),
    (r"%40hermes|%40hermes%3a|hermes%3ayour-server|@hermesbyt4|hermes龙虾|hermesbench|"
     r"hermes\.coder|hermes-outreach|hermes-run|hermes\.process_input",
     "matrix device-id URL encoding / handle / benchmark / fixture data — opaque external/data literal"),
    (r"hermes[-.]atof|hermes[-.]atif|hermes\.nemo_relay|hermes-session-\{|hermes\.turn\.|"
     r"hermes\.api\.(response|error)|hermes\.tool\.response|hermes\.[a-z_.]+\.(start|end|unmatched)",
     "NeMo observability telemetry event/file/subscriber name emitted to an external "
     "relay — external wire/telemetry contract"),
    (r"hermes-nemo-relay", "NeMo-relay internal task/thread name — telemetry-adjacent identifier"),
    (r'host != "hermes"|aiPeer.*"hermes"|workspace.*"hermes"|"aiPeer",\s*"hermes"|'
     r'"workspace",\s*"hermes"|HermesAgent',
     "Honcho/Signal external service peer/workspace/link identifier — registered with the "
     "3rd-party service; renaming addresses a different peer"),
    (r"/hermes\b", "Slack slash-command registered with the app — external"),
    (r"hermes slack manifest|slack.*hermes manifest", "Slack app manifest name — external"),
    (r"@[Hh]ermes(bot|_bot)?\b", "Matrix/Telegram/IRC registered handle — external"),
    (r"hermes-whatsapp-bridge", "npm package name (externally referenced) — external"),
    (r"hermesbot-cron", "IRC handle — external"),
    (r"hermes-telegram|hermes-acp|hermes-achievements|hermes-update",
     "registered plugin/integration ids — external/contract"),
    (r'"?hermes-(api-server|cron|discord|whatsapp|slack|signal|sms|webhook|email|matrix|'
     r'mattermost|dingtalk|feishu|weixin|qqbot|wecom|wecom-callback|yuanbao|bluebubbles|'
     r'homeassistant|teams|google_chat|telegram|gateway|acp|cli)"?|\[hermes-[a-z_]+\]',
     "toolset/platform-preset config key (cli-config.yaml.example platform_toolsets namespace) — "
     "user-facing config contract; renaming breaks existing configs + string-equality tests"),
    (r'hermes-\*|hermes-<|startswith\("hermes-"\)|"hermes-"|\[len\("hermes-"\)',
     "toolset-key NAMESPACE prefix literal — the `hermes-<platform>` preset contract; "
     "the startswith/prefix logic must match the kept toolset keys"),

    # --- Wire attribution to 3rd-party APIs (X-Title / User-Agent / registry name) ---
    (r'X-Title.*Hermes Agent|"Hermes Agent"', "OpenRouter X-Title / ACP registry name — wire attribution"),
    (r"Hermes-Watcher|Hermes[- ]Agent[/ ]", "User-Agent value sent to 3rd-party API"),
    (r'"User-Agent":\s*"Hermes"|User-Agent.*"Hermes"|"Hermes/[0-9]',
     "bare 'Hermes' / 'Hermes/1.0' User-Agent value sent to a 3rd-party API — wire attribution"),
    (r"HermesDashboard/|hermes-dashboard/1\.0",
     "User-Agent value the dashboard sends to 3rd-party APIs — wire attribution"),
    (r"codex_cli_rs|graph-client|x-exa", "3rd-party User-Agent/integration value on a hermes line"),

    # --- Upstream (D4): Nous Research / Hermes-4 model + repo attribution ---
    (r"nous_hermes|is_nous_hermes", "upstream Nous Hermes model detection"),
    (r"Hermes-4|Hermes 4|Hermes-3|Hermes 3", "upstream Nous Research model family name"),
    (r"hermes-honcho:|hermes2-pro|hermes-llm-\d|nous-hermes-\d|hermes3\b|hermes-mystery|"
     r'validate_toolset\("hermes"\)|"hermes" anywhere|Qwen3 wrapper|"hermes-does-not-exist"|'
     r"hermes-brain:|opencode_go",
     "model-name / toolset-name test fixture data (incl. the nous_hermes detection test's own "
     "sample model ids) — opaque data / detection fixtures, not the product display name"),
    (r"nousresearch/hermes-agent|NousResearch/hermes-agent",
     "upstream repo path — attribution + working link"),
    (r"hermes-agent\.nousresearch\.com", "upstream download/site host — attribution"),
    (r"teknium|@PCinkusz|Nous Research", "upstream author/lab attribution"),
    (r"services\.hermes-agent", "upstream nix service identifier"),

    # --- Container / OS install identity (also covered by docker/** whole-tree keep) ---
    (r"/opt/hermes", "container install prefix — OS install identity"),
    (r'TARGET_USER="?hermes|GROUP_NAME="?hermes|useradd.*hermes|groupadd.*hermes',
     "container OS user/group identity"),
    (r"hermes_uid|hermes_gid|hermes_tree", "container OS uid/gid/tree identity"),
    (r"container_name:\s*hermes|image:\s*hermes-agent",
     "docker-compose container/image identity — inherited runtime contract"),
    (r"hermes user|hermes group|hermes-group|hermes/env|python interpreter as hermes|"
     r'default = "hermes"|host-installed hermes|interpreter as hermes',
     "NixOS module OS user/group identity — same inherited runtime-account contract as docker/**"),
    (r"rtk-hermes", "external third-party repo name (rtk-hermes) — not this product"),
    (r"hermes:hermes|hermes-owned|unprivileged hermes|the .hermes. user|'hermes'|"
     r"drops from root to the .hermes.|chown.*hermes",
     "s6/service OS-account identity (hermes user/group) — same inherited runtime-account "
     "contract as docker/** and the NixOS module"),
    (r"hermes-profile|hermes-task-id|label=hermes|hermes-\{uuid|hermes-\{_?uuid|"
     r"hermes-tagged|hermes-created|hermes-\{.*hex",
     "Docker container-management label / generated container name — runtime contract for "
     "cross-process container reuse + sweep (tools/environments/docker.py)"),
    (r'bank_?[iI]d.*hermes|"hermes":|"hermes",\s*(llm_provider|status|profile)?|'
     r'default:\s*hermes\)|get\(.profile., .hermes.\)|_bank_id = "hermes"|'
     r'"bankId":.*"hermes"|setdefault\(.bank_id., .hermes.\)|hermes-\{user\}',
     "Hindsight memory-bank / profile default identifier value — opaque data pointing at an "
     "external memory bank; changing it silently switches which bank is addressed"),
    (r'profile or "hermes"',
     "Hindsight profile fallback default value — opaque data (see bank_id keep)"),
    (r'"hermes-user"|"hermes-pgvector"|_PGVECTOR_PASSWORD = "hermes"|agent_id.*"hermes"|'
     r'"USER", "hermes|Agent ID \[hermes\]|user_id.*hermes-user',
     "mem0 default user_id/agent_id/container/password identifier value — opaque data / "
     "external-service default; changing it addresses a different memory namespace"),
    (r'exec_user", "hermes"|exec_user.*hermes',
     "container exec_user default 'hermes' — OS-account identity default"),
    (r"#hermes\b|hermes-bot\b|nickname.*hermes|IRC.*hermes",
     "IRC channel/nick example + default bot nickname — opaque config data / external handle"),
    (r"hermes-cleanup-\{|directory is hermes-|is hermes-$",
     "internal docker-cleanup thread name / wrapped 'hermes-owned' comment — "
     "container-management identity, opaque"),

    # --- Incident / proper-noun ---
    (r"hermes-0day", "security incident proper-noun name"),
    (r"hermes #\d+", "upstream issue-tracker reference (hermes #NNNNN) — attribution/traceability"),
    (r"hermesagent26@users\.noreply\.github\.com", "contributor email — proper noun"),
    (r"hermes@[a-z0-9.]+|hermesagent26@|nadyahermes|hermes-shim|hermes-eval",
     "git contributor email / handle / PR-reference proper-noun in the release attribution "
     "map (scripts/release.py) — historical author data, not the product name"),

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
    (r'hermes-\{short_id\}|hermes/\{wt_name\}|``hermes/\*``|hermes/\*.*branch',
     "worktree/branch naming prefix — the create-side and the prune-side matcher are a "
     "coordinated pair, test-asserted (tests/cli/test_worktree.py); existing user worktrees/"
     "branches carry this prefix, so renaming would strand them"),
    (r"NOUS HERMES",
     "default compact-banner branding — test-asserted as intentional legacy Nous Hermes "
     "attribution (test_default_compact_banner_keeps_legacy_nous_hermes_branding)"),
    (r"hermes-desktop-|hermes-relaunch-|hermes-pty-active-", "tmp-file prefix — opaque data"),
    (r"hermes please help|\^hermes|@Hermes agent|MyHermesBot",
     "wake-word / bot-name test fixture — opaque data"),
    (r"restart\s.*hermes\s+gateway|restart\s.*hermes|@\?hermes\\s\+agent|@\?hermes\\b|"
     r"\?<!\[.w@\]\)@\?hermes",
     "wake-word / restart-command DETECTION regex — must keep matching what users still type"),
    (r"hermes\.observer\.v\d|hermes\.middleware\.v\d",
     "observer/middleware wire SCHEMA_VERSION string — external schema contract"),
    (r"hermes\.example\.com|hermes\.\{old_name\}|hermes\.old_name|legacy_old_host.*hermes",
     "example/placeholder host + legacy per-profile host literal — opaque/migration data"),
    (r"hermes-mux:|source=hermes|sha256.*hermes",
     "wire hash-namespace prefix / source query-tag — contract literal"),
    (r"hermes-ws-pub|hermes-plugin-command-await|hermes-migration|hermes-nemo|"
     r"hermes-bench-eval-|hermes-syntax-check-|hermes-tui-active-session-|hermes-verify-|"
     r"hermes-ad-hoc-|hermes-backup-|hermes-config-\*|hermes-dashboard-\*",
     "internal task/thread/temp-file/glob name — opaque runtime identifier, not the display name"),
    (r'spec_from_file_location\("openclaw_to_hermes"|"openclaw_to_hermes"',
     "import spec name for the kept openclaw_to_hermes.py migration module"),
    (r'shim_dir, "hermes"\)|os\.path\.join\(shim_dir, "hermes"\)|the `hermes` CLI child|'
     r'`hermes`, ask it to|Run `hermes`|another hermes process|client_id": "hermes-\d',
     "test fixture: fake 'hermes' shim binary / CLI-run instruction / opaque process reference / "
     "client_id fixture — opaque test data"),
    # --- Final broad test-fixture-DATA keeps (opaque values a test sets/asserts/negates) ---
    (r'"peer":\s*"hermes"|"peer",\s*"hermes"|peerName|peer": "hermes"|hermes\.dreamer|'
     r'seen\["host"\] == "hermes"|works on hermes|prewarm.*hermes',
     "Honcho peer/host fixture value a test asserts — opaque external-service datum"),
    (r'_current_nick = "hermes"|001 hermes|433 \* hermes|PRIVMSG.*hermes|:hermes!bot@host|'
     r'current_nick.*hermes|nick.*"hermes"',
     "IRC adapter fixture: current-nick / server-numeric / PRIVMSG line 'hermes' a test drives — opaque data"),
    (r'"hermes" not in|not in finish|not in data|assert "hermes" not in',
     "negative assertion checking 'hermes' is ABSENT from output — a rename would make the "
     "assertion vacuous; kept as the thing being asserted-absent"),
    (r'prog="hermes"|prog="hermes [a-z]+"|ArgumentParser\(prog="hermes|`hermes meet`|hermes meet|'
     r'"cognee hermes"|command = "hermes "|projects" / "hermes"|/ "hermes"\)|approved via ``hermes|'
     r'append_message\([^)]*"hermes"|owned_by"\] == "hermes"|command_link_dir / "hermes"',
     "argparse prog-name replica / tmp-dir name / pairing-approval fixture / wire owned_by value / "
     "appended-message content / command-link fixture — opaque test data a test constructs or asserts"),
    (r'HermesIndexSource', "test helper class name for the skills index — internal test identifier"),
    # --- Final tail: ACP contract key, container-fixture, kanban-shim detection, misc opaque data ---
    (r'== \{"hermes"\}|meta\.keys\(\) == \{"hermes"\}|set\(meta',
     "ACP provenance metadata key set {'hermes'} — external wire contract (test_session_provenance)"),
    (r'No such container: hermes|OPENVIKING_AGENT", "hermes|OpenClaw→Hermes|'
     r'enabled_toolsets = \["hermes-core"\]|"hermes-core"|"branch": "hermes/|scope.push.*hermes|'
     r'"scope", "hermes"|hermes-task"|title="hermes-task|Legacy Hermes/petdex|cached hermes modules|'
     r'lliam_xai_user_agent|profile": ',
     "container-name / openviking-agent / toolset / branch / scope-tag / kanban-title / petdex / "
     "cached-module test fixture value — opaque test data"),
    (r'shim = tmp_path.*hermes|path_lliam = tmp_path.*hermes|bin" / "hermes"|`hermes` is on PATH|'
     r"use a `hermes|Workers spawned.*hermes|NOT `hermes`|`hermes` package|python -m hermes|"
     r"module name.*hermes|hermes-too|the shim|`hermes` on|created by root in the shim",
     "kanban worker/shim DETECTION test: a fake 'hermes' binary on PATH + the shim-vs-module "
     "resolution the test asserts — opaque fixture + detection of the legacy command name"),
    (r'The hermes install dir|the hermes install|without the h[a-z]*$|reachable in the te|'
     r"gateway was launched without|Falls back to sys.executable",
     "install-dir/env-blocklist test narration — references the kept install-dir behavior; non-shipping"),
    (r'you are hermes|instructions="you are hermes"|huge hermes system prompt|'
     r'port goal command to hermes|content": "hermes|assistant", "hermes|"container: hermes"|'
     r'"%PDF-1\.4 hermes|Hermes-processed output|Hermes/1\.0',
     "system-prompt / goal / container-name / PDF-byte / message-content test fixture value a "
     "test constructs or asserts equality on — opaque test data"),
    (r"hermes CLI \(console_script\)|leaves hermes|hermes start even|TestLegacyHermesUnitDetection|"
     r"macOS mirror of TestLegacyHermes|custom.*hermes|custom_home.*hermes",
     "bootstrap/legacy-unit-detection test narration + a custom_home tmp-dir fixture — "
     "references the kept console-script / legacy-unit detection; non-shipping test data"),
    # --- Memory-provider agent/source/bank fixture DATA (external-service identifiers a test asserts) ---
    (r'agent == "hermes"|"agent":\s*"hermes"|_retain_source == "hermes"|_sanitize_bank_segment\("hermes"\)|'
     r'result == "hermes"|retain_source.*hermes|assistant_peer_id|X-OpenViking.*hermes|'
     r'headers\["X-OpenViking',
     "openviking/hindsight memory-provider agent/source/bank fixture value 'hermes' a test asserts "
     "equality on — opaque external-service datum (renaming would change what bank/actor is addressed)"),
    (r'hermes-exdev-test|hermes-dedup-|hermes-write-ded|_make_safe_tempdir\("hermes|'
     r'shm / f"hermes-|"hermes test document|hello from hermes|hermes-install-dir',
     "test temp-dir prefix / PDF-fixture bytes / message-content fixture — opaque test data"),
    (r"restarting Hermes|hermes's own graceful|hermes accumulat|hermes still run|"
     r"hermes uses an internal scheduler|owning hermes PID|concurrent hermes process|"
     r"which hermes process|across hermes|reachable in the test|TestHermesBinDir|bare ``hermes``|"
     r"real ``hermes``|missing the hermes dir|the hermes dir|hermes secrets|hermes is not on PATH|"
     r"hermes home|Hermes-home|hermes-dedup|Patch the hermes",
     "docker/lifecycle/install-dir test narration referencing the kept container command + PID "
     "ownership + install-dir behavior — describes the kept 'hermes' runtime identity, or a "
     "process-reference in test prose; non-shipping test narration"),
]

KEEP_PATTERNS += [
    (r"hermes: 'nous'|hermes:\s*.nous.",
     "skin-name mapping data (hermes->nous) — the default skin's registry key"),
    (r"hermes-audit@|hermes-your-platform|start-open-webui-hermes",
     "example contributor email / doc placeholder toolset / external-tool launcher name — opaque"),
    (r"get-shit-done-cc --hermes|npx get-shit-done-cc",
     "external 'get-shit-done-cc' npm tool's --hermes install flag — 3rd-party CLI flag, external"),
    (r"hermes-security", "test host-key/profile fixture — opaque data"),
    (r"hermes_test\b|hermes_kanban|hermes_timezone|hermes_stream_retries",
     "opaque test fixture identifiers seeded as data"),
    # --- Bot-name / mention-pattern / wake-word fixture DATA (test asserts these values) ---
    (r'"[A-Za-z ]*Hermes[A-Za-z ]*Bot"|"Hermes Bot"|"Env Hermes"|"Hydrated Hermes"|'
     r'_bot_name.*[Hh]ermes|FEISHU_BOT_NAME.*[Hh]ermes|bot_name.*[Hh]ermes',
     "bot-name fixture value a test sets and asserts (adapter._bot_name) — opaque data"),
    (r"hey hermes|ok hermes|HEY HERMES|hermes,|hermes do this|mention_patterns.*hermes|"
     r"SLACK_MENTION_PATTERNS.*hermes|matches_mention.*hermes|@hermes\b",
     "wake-word / mention-pattern fixture value a test asserts matching against — opaque data"),
    (r'"[Hh]ermes help"|"[Hh]ermes agent|please ask Hermes|_is_bot_mentioned\(|_clean_mention_text\(|'
     r'_strip_mention\(|_make_event\("[Hh]ermes|<at>Hermes</at>|"Hermes help me"|Can Hermes reply|'
     r'ask Hermes about this',
     "mention-detection input/expected fixture text a test passes to _is_bot_mentioned / "
     "_clean_mention_text / _strip_mention and asserts on — opaque data"),
    (r'"Hermes Server|guild_name.*Hermes|chat_name.*Hermes|Hermes Server / #|"Hermes is thinking',
     "Discord/voice fixture guild/chat name + a 'thinking…' status message a test asserts — opaque data"),
    # --- Broad opaque test-fixture identifiers (task ids, session ids, hosts, tags a test uses as data) ---
    (r"hermes-managed|hermes-mytask|hermes-session-s\d|hermes-temp-hello|hermes-ok|hermes-ws-ok|"
     r"hermes-custom|hermes-local|hermes-at\b|hermes-mcp|hermes-test\b|hermes\.partner|hermes\.env\b|"
     r"hermes\.ssi_health|hermes\.cmd|hermes/python|from-hermes-home|hermes-readable|hermes-_test_platform|"
     r"hermes\.system|hermes/system|fake-hermes|pure-hermes|non-hermes|other-hermes|hermesacpagent|"
     r"hermes-uid\b|hermes3\b|hermes-token|hermesbot\b",
     "opaque test-fixture datum — task/session id, host, tag, path, provider-list entry, or fake "
     "binary name a test uses as input or asserts on; not the product display name"),
]

# The bulk below is appended so the ordering above (specific contract keeps) wins first.
KEEP_PATTERNS += [
]

KEEP_PATTERNS += [
    # --- Logger channel names (stable log-routing namespace) ---
    (r'getLogger\("hermes\.[a-z_.]+"\)|"hermes\.[a-z_]+\.[a-z_.]+"',
     "logging.getLogger('hermes.<x>') channel name — stable log-routing namespace"),
    # --- External API routing / wire tags (functional routing keys, not display) ---
    (r"x-sm-source|sm_source|x-sdk-runtime|from=hermes|tp=hermes|connect=hermes|container_tag",
     "external memory/API routing header/query tag ('hermes') — functional routing key sent to a 3rd party"),
    (r"hermes-plugin\b", "x-sdk-runtime plugin tag value — external wire"),
    # --- External-service peer/workspace/host default identifiers ---
    (r'hermes-default|hermes-assistant|HOST = "hermes"|ai_peer.*"hermes"|_acct_id.*"hermes"|'
     r'"hermes-\{identity\}"|hermes-\{identity\}|hermes-coder|hermes-\{profile\}|hermes\.<profile>|'
     r'_host_key.*"hermes"|host == "hermes"|host="hermes"|profile_host_key.*"hermes"|'
     r'resolve_active_host\(\) == "hermes"|hosts.*\["hermes"\]|"hermes"\]|from_env\(host="hermes"|'
     r'"hermetika", "hermes"|client_id": "hermes-\d',
     "external Honcho memory-service host/peer default identifier ('hermes') a test asserts — opaque data"),
    (r"_DEFAULT_CONTAINER_TAG = \"hermes\"|default_headers.*hermes|HermesMeetSink|hermes-meet-node|"
     r'source: str = "hermes-desktop"|"hermes-desktop"',
     "external-service default container/source/display identifier — opaque data / wire tag"),
    # --- Plugin / engine registry ids (external or registered) ---
    (r"hermes-memory-store|hermes-lcm|hermes-ink|hermes-achievements|hermes-kanban",
     "plugin/engine registry id or external package/repo name — registered identifier"),
    (r"HermesPluginSDK|HermesMCPOAuthProvider|HermesSweEnv|HermesSetupBot|HermesDebugBoundary|"
     r"HermesMeetSink|HermesDialog",
     "public SDK type / provider-class / benchmark-env / boundary token — API surface or "
     "registered identifier kept to avoid breaking a wire/import/registry contract"),
    # --- Web/desktop persisted-state + DOM identifiers (no/first-paint migration) ---
    (r"hermes-locale|hermes-sidebar-collapsed|hermes-sidebar-plugin|persist:hermes-[a-z]+|"
     r"data-hermes-plugin|hermes-boot-|hermes-chat-xterm-host|hermes-fade-in|hermes:dev-session-token|"
     r'"hermes":\)|\|hermes\):|about\|hermes',
     "web/desktop localStorage key, session-partition, DOM class/attr, or URL-scheme literal — "
     "persisted-state / first-paint contract; renaming orphans state or needs coordinated migration"),
    # --- Detection / kill / classification regexes (must keep matching legacy 'hermes') ---
    (r"lliam-gov\|lliam\|hermes|CLAUDE\|CODEX\|HERMES|hermes\\s\+gateway|hermes.*gateway|"
     r'base == "hermes"|base\.startswith\("hermes|"hermes" in|"off", "default", "disable", "hermes"|'
     r"hermes\[-_ \]\?\[34\]|kickstart.*hermes|systemctl.*hermes|p\?kill.*hermes|hermes-brain|"
     r"killall hermes|pkill( -9)? hermes|pgrep hermes|pidof hermes|pkill -f.*hermes|"
     r'"pkill", "-f", "hermes"|"killall", "hermes"|hermes-themed|hermes-triage',
     "gateway/service/model DETECTION or kill/pkill/pgrep test command — must keep matching "
     "legacy 'hermes' process name (these tests assert the kill-guard blocks self-termination)"),
    # --- Internal temp-dir / task / thread / container-name prefixes (opaque) ---
    (r"hermes-ssh|hermes-sync-back-|hermes-overlays|hermes-cmd-stt-|hermes-local-stt-|"
     r"hermes-skills-safe-|hermes-core-constraints-|hermes-bws-|hermes-osint|hermes-lsp-loop|"
     r"hermes-\{task_id|hermes-\{|hermes-\$\{|hermes-<|daytona.*hermes|sandbox_name.*hermes|"
     r'mkdtemp.*hermes|prefix=f?"hermes-|prefix="hermes-|/ "hermes-|hermes-dialog-bridge|'
     r"hermes-macos-electron-binary-fallback",
     "internal temp-dir / task / thread / generated-container name prefix — opaque runtime identifier"),
    # --- ntfy / feishu / social wire tags + skills metadata key ---
    (r'"hermes-in"|"hermes-out"|hermes-in\b|hermes-ig-embed|hermes-tt-embed|hermes-tw-embed',
     "ntfy topic / social-embed element id — wire/registered identifier"),
    (r'^\s*hermes:\s*$|metadata.*hermes|meta\.get\("hermes"\)|get\("hermes"\)|"  hermes:"|"hermes:"',
     "SKILL.md/blueprint frontmatter `hermes:` metadata key — schema key read by the loader"),
    # --- ASCII / pentest / creative literal art & payload tokens (opaque) ---
    (r"HERMES</span>|HERMES.*font|pyfiglet .HERMES|text=HERMES|HERMES-PENTEST|HERMESPENTEST|"
     r"echo HERMES|HERMES ONLINE|hermes-chan|hermes-san|hermes-web-pentest|hermes-pentest|"
     r"hermes-comfyui|hermes-fast|hermes-audit|hermes-issues|hermes-system",
     "ASCII-art / pentest-payload / creative-copy / example literal — opaque string, not the display name"),
    # --- Nix package pnames + Rust crate + PowerShell param (internal build identifiers) ---
    (r'pname = "hermes-(tui|web|desktop)"|mainProgram = "hermes-desktop"|"hermes-tui"|"hermes-web"|'
     r'name = "hermes-bootstrap"|hermes-bootstrap|hermes-config-(attrs|merge)|hermes-documents|'
     r"hermes-container-entrypoint|repo = \"hermes-lcm\"|hermes-config-\*",
     "internal Nix package pname / Rust crate name / build-derivation name — build-time identifier, "
     "not the shipped display name (the shipped artifacts are Lliam-GOV*)"),
    (r"-HermesHome\b", "PowerShell -HermesHome install param — back-compat with install.ps1"),
    (r'\[Alias\("HermesHome"\)\]', "install.ps1 parameter alias so legacy -HermesHome callers reach -LliamHome"),
    # --- Env-compat rebrand shims (migrate-from) ---
    (r"rebrandEnv|rebrand.*hermes|hermes -> lliam|hermes \*|legacy .hermes\*|hermes\* localStorage|"
     r"Migrate legacy .hermes",
     "env/storage-key rebrand-compat shim comment — describes the migrate-from side"),
    # --- Codex/copilot provider token help + misc CLI-adjacent kept refs ---
    (r"copilot.*provider.*hermes|Copilot subscription token.*hermes",
     "provider help string referencing the kept internal token flow"),
    # --- i18n message KEYS (the values are already Lliam-GOV; keys are code identifiers) ---
    (r"updateHermes|updatingHermes|latest_hint",
     "i18n message-KEY name (value already reads 'Lliam-GOV') — renaming the key means "
     "renaming every locale file + call site in lockstep; kept as an internal string key"),
    # --- OAuth client_id + pub/sub example ---
    (r"client_id:\s*hermes-dashboard|hermes-dashboard\b",
     "dashboard OAuth client_id — registered identifier / config contract"),
    (r"hermes-chat-events", "Pub/Sub topic example name — opaque data"),
    # --- Legacy home literal forms consumed by the migration / default-home resolver ---
    (r'_get_platform_default_home\("hermes"\)|state_home / "hermes"|/ "hermes" /|'
     r'AppData.*hermes|Local.hermes|home consulted only by the one-time migration',
     "legacy home-dir literal 'hermes' — the migrate-from default consulted only by migration"),
    # --- Uninstall / backend-probe DETECTION of the OLD install ---
    (r'PATH line containing hermes|component contains "hermes"|chermes-foo|ephermeral|'
     r"hermes-desktop\$|hermes\.desktop|stale hermes\.cmd|hermes\.cmd shim|to a hermes|"
     r'remove any PATH.*hermes|entry whose path.*hermes',
     "uninstall / backend-probe DETECTION + cleanup of the OLD 'hermes' install — must keep "
     "matching the legacy name to find and remove it"),
    # --- Shell-completion function name registered for the new command ---
    (r"_hermes\(\)|compdef _hermes|_hermes\b",
     "zsh/bash completion function name — internal identifier registered FOR the lliam-gov "
     "command (see `compdef _hermes lliam-gov lliam`); renaming is cosmetic-only churn"),
    # --- git worktree branch prefix (cjs side of the kept create/prune pair) ---
    (r"hermes/\$\{slug\}|hermes/\$\{|`hermes/",
     "desktop git-worktree branch prefix — cjs counterpart of the kept worktree naming pair"),
    # --- kanban/godmode opaque account/model data ---
    (r'kc_account="\$\{2:-hermes\}|check_key.*hermes|return "hermes"|installed hermes CLI',
     "kanban service-account default / godmode model-name data / skill diagnostic — opaque data"),
    (r'restart\\s\+.*hermes|restart\s+hermes|Fallback:.*"hermes"|seen\.add\("hermes"\)|'
     r'Portal NAS #293 / hermes|3\. Fallback',
     "restart-command DETECTION regex / honcho profile fallback default / seeded provider-list "
     "datum / wrapped upstream issue ref — detection or opaque data"),
    (r"hermes-already-has-routines",
     "reference to the kept upstream marketing post filename (in a governance keep-register)"),
    (r'"lliam-gov -p" in content or "hermes -p" in content|legacy \(hermes\)|'
     r'legacy_needle = f"hermes -p|pre-rename wrapper body',
     "profile-wrapper back-compat DETECTION — recognizes both new (lliam-gov) and legacy "
     "(hermes) wrapper bodies so a re-install cleanly overwrites a pre-rename wrapper"),
    (r"windows-hermes-resolution\.test\.cjs|hermes\.cmd/\.exe|shadow hermes\.cmd",
     "descriptive test filename + a Windows shim-shadowing detection fixture — opaque"),
    (r"'hermes-release'|hermes-release' patched",
     "self-improvement fixture skill name — opaque test data"),
    # --- Test-fixture data under apps/**/*.test.* (opaque values a test asserts/uses) ---
    (r"pattern=hermes|'hermes-x'|'hermes-y'|\"hermes-x\"|\"hermes-y\"|hermes-probes-ghost-|"
     r"hermes-probes-o|\.mount_Hermes|hermes-execf|Hermes here\.|hermes/test-gui-stuff|"
     r"C:\\\\hermes|/home/x/\.hermes|hermesHome: home",
     "apps/**/*.test.* fixture data — opaque model ids / tmp prefixes / branch names / ANSI "
     "sample text a test asserts or uses as input, not the product display name"),
]

# ---------------------------------------------------------------------------
# R.8e-3c FINAL residual keeps — the last-tail offenders adjudicated 2026-07-08.
# Every entry here is opaque test-fixture DATA a test asserts/uses, prose that
# describes a KEPT runtime identity (container command, .hermes mirror marker,
# log namespace), an external/registered value, or an upstream reference — NOT
# the product display name. Cross-referenced in
# docs/governance/verification/R8e-keep-register.md.
# ---------------------------------------------------------------------------
KEEP_PATTERNS += [
    # SKILL.md/blueprint frontmatter `hermes:` metadata-key fixture (schema key)
    (r'hermes:\\n"', "SKILL.md frontmatter `hermes:` metadata-key fixture — schema key a test constructs"),
    # Honcho external-service host/peer default identifier fixtures (opaque)
    (r'resolve_active_host", lambda: "hermes"|peer="hermes"',
     "Honcho external-service host/peer default identifier fixture a test sets/asserts — opaque data"),
    # NeMo relay scope handle fixture (opaque)
    (r"hermes-session-parent-session", "NeMo-relay scope handle fixture value — opaque data"),
    # Container command/argv identity (docker OS install identity; docker/** is a whole-tree keep)
    (r"running hermes containers|re-execs .?hermes|explicit .?hermes.? argv0",
     "test narration describing the KEPT container command/argv `hermes` (docker OS install identity)"),
    # Toolset-name corruption fixture: `hermes-cli` rewritten to `hermes` (#38798)
    (r"`hermes` is deliberately absent",
     "toolset-name `hermes` in the #38798 corruption-detection test (hermes-cli->hermes) — opaque asserted data"),
    # Generated skill-doc example `owner` field fixture
    (r'"owner":\s*"hermes"', "generated skill-catalog example `owner` field fixture value — opaque data"),
    # pytest tmp-dir path segments + SUDO_USER fixture (opaque)
    (r'"home"\s*/\s*"hermes"|"opt"\s*/\s*"hermes"|"adapters"\s*/\s*"hermes"',
     "pytest tmp-dir path-segment fixture (home/opt/adapters) — opaque data"),
    (r'SUDO_USER", "hermes"', "SUDO_USER env fixture value — opaque OS-account data"),
    # OpenClaw->Hermes migration posture reference (openclaw migration is a whole-tree keep)
    (r"migrate-hermes", "OpenClaw->Hermes migration posture reference — the kept openclaw-migration identity"),
    # Log-routing channel namespace (same stable namespace as getLogger('hermes.<x>'))
    (r'logger="hermes\.[a-z_.]+"', "log-channel namespace passed to caplog — stable log-routing namespace"),
    # OpenViking memory-provider peer_id fixture (opaque external-service datum)
    (r'"peer_id":\s*"hermes"', "OpenViking memory-provider peer_id fixture value — opaque external-service datum"),
    # Nous-Hermes model-name detection substring narration (upstream model detection)
    (r'"hermes".{0,4}anywhere', "Nous-Hermes model-name detection substring narration — upstream model detection"),
    # package.json `name` fixture the gui-command test writes (opaque)
    (r'\{"name":"hermes"\}', "package.json `name` fixture the gui-command test writes — opaque data"),
    # DingTalk registration `source` wire tag (external)
    (r'"source":\s*"hermes"', "DingTalk registration `source` wire tag value — external wire contract"),
    # Wake-word / mention fixture input (opaque)
    (r"Hermes what's the weather", "wake-word/mention fixture input a test dispatches — opaque data"),
    # docker exec `-u hermes` OS-account asserted value (docker OS identity)
    (r'idx_u \+ 1\] == "hermes"', "asserts `docker exec -u hermes` container OS user — kept OS-account identity"),
    # Kept `/hermes` Slack slash-command name asserted (external contract)
    (r'slashes\[0\]\[0\] == "hermes"', "asserts the kept `/hermes` Slack slash-command name — external contract"),
    # Profile-alias collision + legacy .bat wrapper body fixtures (opaque / legacy)
    (r'check_alias_collision\("hermes"\)', "profile-alias collision test input `hermes` (reserved legacy command name)"),
    (r"hermes -p \w", "legacy profile-wrapper .bat body fixture (`hermes -p <profile>`) — pre-rename wrapper body"),
    # Search-tool query-argument fixture value (opaque search term)
    (r'"q":\s*"hermes"|"query":\s*"hermes"', "search-tool query-argument fixture value a test passes/asserts — opaque data"),
    # Sandbox-mirror classifier narration referencing the KEPT `.hermes`/HERMES_HOME mirror marker
    (r"Hermes-state mirroring|anything-not-hermes",
     "sandbox-mirror classifier test narration referencing the KEPT `.hermes`/HERMES_HOME mirror marker "
     "(agent/file_safety.py matches `home/.hermes`)"),
    # Historical (now-removed) OpenRouter overlay class name in a regression-test docstring
    (r"HermesOverlay", "historical removed OpenRouter overlay class name in a regression-test docstring — proper-noun symbol ref"),
    # References the kept `hermes_pkce` OAuth credential contract
    (r"Hermes-PKCE", "references the kept `hermes_pkce` OAuth PKCE credential contract — a PKCE-only credential setup"),
]

# ---------------------------------------------------------------------------
# R.8e-3d — case-sensitive-fix residual keeps (2026-07-08). Making the HERMES_*
# env keep UPPERCASE-only surfaced ~660 lowercase hermes_<word> lines it had been
# masking. The stale renamed-module refs (hermes_cli/constants/logging/state/time/
# bootstrap) were RENAMED to lliam_*; everything below is a documented keep, scoped
# to specific token families (NOT a hermes_\w+ catch-all — that was the original
# masking bug). See docs/governance/verification/R8e-keep-register.md §G.
# ---------------------------------------------------------------------------
KEEP_PATTERNS += [
    # Platform approval-button action_id / callback wire contracts (Slack/Feishu/Teams
    # echo these values back to the app; renaming breaks live approval buttons).
    (r"hermes_(action|approve|approve_once|approve_always|approve_session|deny|"
     r"confirm_once|confirm_always|confirm_cancel|update_prompt_action)\b",
     "platform approval-button action_id / callback wire contract — Slack/Feishu/Teams echo it back"),
    # i18n message KEY (the localized VALUE already reads Lliam-GOV; the key is a code
    # identifier — renaming means renaming every locale file + call site in lockstep).
    (r"hermes_cmd_not_found|hermes_cmd\b", "i18n message-key name (value already reads lliam-gov)"),
    # Profile-manifest version-requirement schema field.
    (r"hermes_requires\b", "profile-manifest version-requirement schema field — renaming breaks existing manifests"),
    # Honcho / memory external host-key + peer fixture values (address a specific bank).
    (r"hermes_coder|hermes_dreamer|hermes_user_memory\b|hermes_heimdall",
     "Honcho/memory external host-key or peer fixture value — addresses a specific external memory bank"),
    # pip entry-point group + packaging path / label fixtures.
    (r"hermes_agent[_.]|hermes_agent\b",
     "hermes_agent.plugins entry-point group + packaging path / label fixture — live packaging contract / opaque data"),
    # code-execution generated-stub module (parent generates hermes_tools.py, child
    # imports it — functional both-sides contract) + tools MCP server ref.
    (r"hermes_tools\b|hermes_tools_mcp_server",
     "code-execution generated-stub module name (parent writes hermes_tools.py, child imports it) — functional both-sides contract"),
    # log-routing component namespace + dashboard-plugin fixture ids.
    (r"hermes_plugins\b|hermes_plugin\b|hermes_dashboard_plugin\w*",
     "log-routing component namespace + dashboard-plugin test-fixture id"),
    # registered bot handle (@hermes_bot) + pairing / opaque bot-username fixtures.
    (r"hermes_[a-z0-9]*bot\w*|hermes_pair\w*|hermes_abcdef\w*",
     "registered bot handle (@hermes_bot) + pairing / opaque bot-username test fixtures"),
    # concurrent-instance / old-binary / legacy-unit detection (must keep matching legacy name).
    (r"hermes_instances\b|_detect_concurrent_hermes|hermes_exe\b|hermes_is_installed|hermes_units\b",
     "concurrent-instance / old-binary / legacy-unit DETECTION identifiers — must keep matching the legacy name"),
    # opaque test-fixture identifiers / internal temp-dir / probe names (not the display name).
    (r"hermes_(bg|now|voice|conversation|meet_sink|meet_src|meet|ec|dv|hard|host|"
     r"4\w*|8340\w*|fts5?_probe|fts_health\w*|hydrated|injection_test|approval_test|"
     r"e2e\w*|empty__|file_state_test\w*|exec_|subprocess_env|task_id|node_dirs|argv|"
     r"command\w*|memory_builtin\w*|hook_|dist_\w+)\b",
     "opaque test-fixture identifier / internal temp-dir / probe name — not the product display name"),
    # Internal identifiers / fixtures that are non-display and non-contract but live
    # (completion helpers, oauth-login helper, config-module + dotenv fixtures, profiles,
    # user-cron import namespace). Documented, NOT masked; a dedicated test-gated rename
    # pass may finish these — they carry zero audit-facing product-name risk.
    (r"hermes_completion\b|hermes_oauth_login_pure|run_hermes_oauth_login|hermes_config_mod|"
     r"hermes_dotenv\w*|hermes_profiles\b|hermes_user_cron\b|hermes_command_path",
     "internal identifier / test fixture (completion, oauth-login helper, config-module + dotenv "
     "fixtures, profiles, user-cron import namespace) — non-display, documented; dedicated rename pass may finish"),
]

KEEP_PATTERNS += [
    # Generated runtime-id prefix: f"hermes_<...>" — Honcho host key (hermes_<profile>),
    # external browser/matrix/dingtalk/singularity session·txn·user·instance ids, and the
    # Telegram bot username (hermes_<slug>_bot). External/opaque runtime identifiers a
    # rename would repoint or break.
    (r"hermes_\{|hermes_<[a-z]|hermes_partner\b",
     "generated runtime-id prefix f\"hermes_<...>\" or doc placeholder hermes_<slug>/hermes_<profile> "
     "(Honcho host key / external session·txn·user·instance id / bot username) — external/opaque"),
    # Literal `hermes_` prefix a test asserts on, or an IRC nick/retry sequence — the
    # generated-identifier prefix itself (startswith/removeprefix/len assertions).
    (r'startswith\("hermes_"|removeprefix\("hermes_"|"hermes_" in|len\("hermes_"\)|'
     r'NICK hermes_|hermes_, hermes_1|mod\.startswith\("hermes_',
     "assertion on the generated `hermes_<...>` identifier prefix / IRC nick retry — opaque prefix contract"),
    # Opaque temp-file / dir / socket / cache prefixes + get_lliam_home() mock dirs + fixtures.
    (r"hermes_conversation|hermes_profile_import_|hermes_rpc|hermes_shrink_|hermes_prompt_|"
     r"hermes_bg|hermes_terminal|hermes_sandbox_|hermes_voice|hermes_test_\w+|hermes_h.llo|"
     r"agent-browser-hermes_|hermes_scaffolding|hermes_tz\b",
     "opaque temp-file/dir/socket/cache prefix + get_lliam_home() mock dir + test fixture — not the display name"),
    # User-provider/plugin import namespaces, internal sentinels, and deferred internal
    # identifiers (documented, not masked; a dedicated rename pass may finish these).
    (r"_hermes_user_provider|_is_hermes_provider|__hermes_user_skipped__|_hermes_run_generation|"
     r"_build_hermes_tools|hermes_tools_mcp|find_hermes_node_executable",
     "user-provider import namespace / internal sentinel / deferred internal identifier — import contract or non-display internal name"),
    # Legacy module entry-point path baked into pre-rename launchd/systemd plists,
    # Windows scheduled tasks, running-process argv, and the electron backend
    # spawn/detection. Current invocations already use `lliam_cli.main`; these
    # `hermes_cli.main` refs are legacy-DETECTION markers (recognize/upgrade old
    # installs). Whether the desktop/gateway invocation should migrate to
    # `lliam_cli.main` is a functional R.5/R.9 decision, NOT a guard-cleanup rename.
    (r"hermes_cli\.main", "legacy module entry-point path (pre-rename plists / scheduled tasks / process argv / electron spawn+detect) — legacy-DETECTION marker"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), why) for rx, why in KEEP_PATTERNS]


_EXACT_CREDITS = {
    "README.md": {"Lliam-GOV is a governance-hardened fork of the MIT-licensed Hermes Agent. It"},
}


def _line_is_allowed(text: str, path: str = "") -> bool:
    # Preserve this exact upstream credit without allowing appended stale markers.
    if text in _EXACT_CREDITS.get(path.removeprefix("./"), set()):
        return True
    return any(rx.search(text) for rx, _ in _COMPILED)


def test_exact_upstream_credit_allowed_only_in_readme():
    credit = "Lliam-GOV is a governance-hardened fork of the MIT-licensed Hermes Agent. It"
    assert _line_is_allowed(credit, "./README.md")
    assert not _line_is_allowed(credit, "app/banner.txt")


def test_upstream_credit_exception_does_not_hide_stale_markers():
    credit = "Lliam-GOV is a governance-hardened fork of the MIT-licensed Hermes Agent. It"
    assert not _line_is_allowed(credit + " Welcome to HermesOldProduct", "README.md")
    assert not _line_is_allowed("Welcome to HermesOldProduct", "README.md")


def test_no_lliam_owned_hermes_refs():
    # Repo root = two parents up from this file (tests/rename/<this file>).
    # rg must run with this as cwd so relative excludes keep matching.
    repo_root = Path(__file__).resolve().parents[2]

    if shutil.which("rg"):
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
        stdout = result.stdout
    else:
        # No ripgrep on PATH: the pure-Python scan prints the same lines rg
        # would (same file set, excludes, encoding and case rules — proven
        # against rg in test_hermes_scan_fallback.py). For binary files it
        # prints every match before the first NUL, the most any rg version
        # shows, so the guard without rg is never looser than with it.
        stdout = _hermes_scan.scan(repo_root, EXCLUDES)

    offenders: list[str] = []
    for raw in stdout.splitlines():
        # Split "path:linenum:content" — path may contain ':' only on Windows,
        # not here; split on the first two colons.
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        path, _lineno, text = parts
        if _is_whole_tree_keep(path):
            continue
        if _line_is_allowed(text, path):
            continue
        offenders.append(f"{path}:{_lineno}: {text.strip()[:160]}")

    shown = offenders[:30]
    assert not offenders, (
        f"{len(offenders)} un-allowlisted 'hermes' lines remain "
        f"(each is either a Lliam-owned rename target, or a legitimate keep "
        f"needing a documented KEEP_PATTERNS entry). First {len(shown)}:\n"
        + "\n".join(shown)
    )
