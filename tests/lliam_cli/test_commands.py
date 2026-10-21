"""Tests for the central command registry and autocomplete."""

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from lliam_cli.commands import (
    COMMAND_REGISTRY,
    COMMANDS,
    COMMANDS_BY_CATEGORY,
    CommandDef,
    SUBCOMMANDS,
    SlashCommandAutoSuggest,
    SlashCommandCompleter,
    resolve_command,
)


def _completions(completer: SlashCommandCompleter, text: str):
    return list(
        completer.get_completions(
            Document(text=text),
            CompleteEvent(completion_requested=True),
        )
    )


# ---------------------------------------------------------------------------
# CommandDef registry tests
# ---------------------------------------------------------------------------

class TestCommandRegistry:
    def test_registry_is_nonempty(self):
        assert len(COMMAND_REGISTRY) > 30

    def test_every_entry_is_commanddef(self):
        for entry in COMMAND_REGISTRY:
            assert isinstance(entry, CommandDef), f"Unexpected type: {type(entry)}"

    def test_no_duplicate_canonical_names(self):
        names = [cmd.name for cmd in COMMAND_REGISTRY]
        assert len(names) == len(set(names)), f"Duplicate names: {[n for n in names if names.count(n) > 1]}"

    def test_no_alias_collides_with_canonical_name(self):
        """An alias must not shadow another command's canonical name."""
        canonical_names = {cmd.name for cmd in COMMAND_REGISTRY}
        for cmd in COMMAND_REGISTRY:
            for alias in cmd.aliases:
                if alias in canonical_names:
                    # reset -> new is intentional (reset IS an alias for new)
                    target = next(c for c in COMMAND_REGISTRY if c.name == alias)
                    # This should only happen if the alias points to the same entry
                    assert resolve_command(alias).name == cmd.name or alias == cmd.name, \
                        f"Alias '{alias}' of '{cmd.name}' shadows canonical '{target.name}'"

    def test_every_entry_has_valid_category(self):
        valid_categories = {"Session", "Configuration", "Tools & Skills", "Info", "Exit"}
        for cmd in COMMAND_REGISTRY:
            assert cmd.category in valid_categories, f"{cmd.name} has invalid category '{cmd.category}'"

    def test_reasoning_subcommands_are_in_logical_order(self):
        reasoning = next(cmd for cmd in COMMAND_REGISTRY if cmd.name == "reasoning")
        assert reasoning.subcommands[:6] == (
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
        )

    def test_cli_only_and_gateway_only_are_mutually_exclusive(self):
        for cmd in COMMAND_REGISTRY:
            assert not (cmd.cli_only and cmd.gateway_only), \
                f"{cmd.name} cannot be both cli_only and gateway_only"


# ---------------------------------------------------------------------------
# resolve_command tests
# ---------------------------------------------------------------------------

class TestResolveCommand:
    def test_canonical_name_resolves(self):
        assert resolve_command("help").name == "help"
        assert resolve_command("background").name == "background"
        assert resolve_command("copy").name == "copy"
        assert resolve_command("agents").name == "agents"

    def test_alias_resolves_to_canonical(self):
        assert resolve_command("bg").name == "background"
        assert resolve_command("reset").name == "new"
        assert resolve_command("q").name == "queue"
        assert resolve_command("exit").name == "quit"
        assert resolve_command("reload_mcp").name == "reload-mcp"
        assert resolve_command("codex_runtime").name == "codex-runtime"
        assert resolve_command("tasks").name == "agents"


    def test_leading_slash_stripped(self):
        assert resolve_command("/help").name == "help"
        assert resolve_command("/bg").name == "background"

    def test_unknown_returns_none(self):
        assert resolve_command("nonexistent") is None
        assert resolve_command("") is None


# ---------------------------------------------------------------------------
# Derived dicts (backwards compat)
# ---------------------------------------------------------------------------

class TestDerivedDicts:
    def test_commands_dict_excludes_gateway_only(self):
        """gateway_only commands should NOT appear in the CLI COMMANDS dict."""
        for cmd in COMMAND_REGISTRY:
            if cmd.gateway_only:
                assert f"/{cmd.name}" not in COMMANDS, \
                    f"gateway_only command /{cmd.name} should not be in COMMANDS"

    def test_commands_dict_includes_all_cli_commands(self):
        for cmd in COMMAND_REGISTRY:
            if not cmd.gateway_only:
                assert f"/{cmd.name}" in COMMANDS, \
                    f"/{cmd.name} missing from COMMANDS dict"

    def test_commands_dict_includes_aliases(self):
        assert "/bg" in COMMANDS
        assert "/reset" in COMMANDS
        assert "/q" in COMMANDS
        assert "/exit" in COMMANDS
        assert "/reload_mcp" in COMMANDS

    def test_commands_by_category_covers_all_categories(self):
        registry_categories = {cmd.category for cmd in COMMAND_REGISTRY if not cmd.gateway_only}
        assert set(COMMANDS_BY_CATEGORY.keys()) == registry_categories

    def test_every_command_has_nonempty_description(self):
        for cmd, desc in COMMANDS.items():
            assert isinstance(desc, str) and len(desc) > 0, f"{cmd} has empty description"


# ---------------------------------------------------------------------------
# Gateway helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Config-gated gateway commands
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Autocomplete (SlashCommandCompleter)
# ---------------------------------------------------------------------------

class TestSlashCommandCompleter:
    # -- basic prefix completion -----------------------------------------

    def test_builtin_prefix_completion_uses_shared_registry(self):
        completions = _completions(SlashCommandCompleter(), "/re")
        texts = {item.text for item in completions}

        assert "reset" in texts
        assert "retry" in texts
        assert "reload-mcp" in texts

    def test_builtin_completion_display_meta_shows_description(self):
        completions = _completions(SlashCommandCompleter(), "/help")
        assert len(completions) == 1
        assert completions[0].display_meta_text == "Show available commands"

    # -- exact-match trailing space --------------------------------------

    def test_exact_match_completion_adds_trailing_space(self):
        completions = _completions(SlashCommandCompleter(), "/help")

        assert [item.text for item in completions] == ["help "]

    def test_partial_match_does_not_add_trailing_space(self):
        completions = _completions(SlashCommandCompleter(), "/hel")

        assert [item.text for item in completions] == ["help"]

    # -- non-slash input returns nothing ---------------------------------

    def test_no_completions_for_non_slash_input(self):
        assert _completions(SlashCommandCompleter(), "help") == []

    def test_no_completions_for_empty_input(self):
        assert _completions(SlashCommandCompleter(), "") == []

    # -- skill commands via provider ------------------------------------

    def test_skill_commands_are_completed_from_provider(self):
        completer = SlashCommandCompleter(
            skill_commands_provider=lambda: {
                "/gif-search": {"description": "Search for GIFs across providers"},
            }
        )

        completions = _completions(completer, "/gif")

        assert len(completions) == 1
        assert completions[0].text == "gif-search"
        assert completions[0].display_text == "/gif-search"
        assert completions[0].display_meta_text == "⚡ Search for GIFs across providers"

    def test_skill_exact_match_adds_trailing_space(self):
        completer = SlashCommandCompleter(
            skill_commands_provider=lambda: {
                "/gif-search": {"description": "Search for GIFs"},
            }
        )

        completions = _completions(completer, "/gif-search")

        assert len(completions) == 1
        assert completions[0].text == "gif-search "

    def test_no_skill_provider_means_no_skill_completions(self):
        """Default (None) provider should not blow up or add completions."""
        completer = SlashCommandCompleter()
        completions = _completions(completer, "/gif")
        # /gif doesn't match any builtin command
        assert completions == []

    def test_skill_provider_exception_is_swallowed(self):
        """A broken provider should not crash autocomplete."""
        completer = SlashCommandCompleter(
            skill_commands_provider=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        # Should return builtin matches only, no crash
        completions = _completions(completer, "/he")
        texts = {item.text for item in completions}
        assert "help" in texts

    def test_skill_description_truncated_at_50_chars(self):
        long_desc = "A" * 80
        completer = SlashCommandCompleter(
            skill_commands_provider=lambda: {
                "/long-skill": {"description": long_desc},
            }
        )
        completions = _completions(completer, "/long")
        assert len(completions) == 1
        meta = completions[0].display_meta_text
        # "⚡ " prefix + 50 chars + "..."
        assert meta == f"⚡ {'A' * 50}..."

    def test_skill_missing_description_uses_fallback(self):
        completer = SlashCommandCompleter(
            skill_commands_provider=lambda: {
                "/no-desc": {},
            }
        )
        completions = _completions(completer, "/no-desc")
        assert len(completions) == 1
        assert "Skill command" in completions[0].display_meta_text


# ── SUBCOMMANDS extraction ──────────────────────────────────────────────


class TestSubcommands:
    def test_explicit_subcommands_extracted(self):
        """Commands with explicit subcommands on CommandDef are extracted."""
        assert "/skills" in SUBCOMMANDS
        assert "install" in SUBCOMMANDS["/skills"]

    def test_reasoning_has_subcommands(self):
        assert "/reasoning" in SUBCOMMANDS
        subs = SUBCOMMANDS["/reasoning"]
        assert "high" in subs
        assert "show" in subs
        assert "hide" in subs

    def test_fast_has_subcommands(self):
        assert "/fast" in SUBCOMMANDS
        subs = SUBCOMMANDS["/fast"]
        assert "fast" in subs
        assert "normal" in subs
        assert "status" in subs

    def test_voice_has_subcommands(self):
        assert "/voice" in SUBCOMMANDS
        assert "on" in SUBCOMMANDS["/voice"]
        assert "off" in SUBCOMMANDS["/voice"]

    def test_cron_has_subcommands(self):
        assert "/cron" in SUBCOMMANDS
        assert "list" in SUBCOMMANDS["/cron"]
        assert "add" in SUBCOMMANDS["/cron"]

    def test_commands_without_subcommands_not_in_dict(self):
        """Plain commands should not appear in SUBCOMMANDS."""
        assert "/help" not in SUBCOMMANDS
        assert "/quit" not in SUBCOMMANDS
        assert "/clear" not in SUBCOMMANDS


# ── Subcommand tab completion ───────────────────────────────────────────


class TestSubcommandCompletion:
    def test_subcommand_completion_after_space(self):
        """Typing '/reasoning ' then Tab should show subcommands."""
        completions = _completions(SlashCommandCompleter(), "/reasoning ")
        texts = {c.text for c in completions}
        assert "high" in texts
        assert "show" in texts

    def test_fast_subcommand_completion_after_space(self):
        completions = _completions(SlashCommandCompleter(), "/fast ")
        texts = {c.text for c in completions}
        assert "fast" in texts
        assert "normal" in texts

    def test_fast_command_filtered_out_when_unavailable(self):
        completions = _completions(
            SlashCommandCompleter(command_filter=lambda cmd: cmd != "/fast"),
            "/fa",
        )
        texts = {c.text for c in completions}
        assert "fast" not in texts

    def test_subcommand_prefix_filters(self):
        """Typing '/reasoning sh' should only show 'show'."""
        completions = _completions(SlashCommandCompleter(), "/reasoning sh")
        texts = {c.text for c in completions}
        assert texts == {"show"}

    def test_subcommand_exact_match_suppressed(self):
        """Typing the full subcommand shouldn't re-suggest it."""
        completions = _completions(SlashCommandCompleter(), "/reasoning show")
        texts = {c.text for c in completions}
        assert "show" not in texts

    def test_no_subcommands_for_plain_command(self):
        """Commands without subcommands yield nothing after space."""
        completions = _completions(SlashCommandCompleter(), "/help ")
        assert completions == []

    def test_tools_subcommand_completion(self):
        """`/tools ` should suggest list, disable, enable."""
        completions = _completions(SlashCommandCompleter(), "/tools ")
        texts = {c.text for c in completions}
        assert texts == {"list", "disable", "enable"}

    def test_tools_subcommand_prefix_filters(self):
        completions = _completions(SlashCommandCompleter(), "/tools en")
        texts = {c.text for c in completions}
        assert texts == {"enable"}

    def test_tools_enable_completes_toolset_names(self, monkeypatch):
        """`/tools enable ` should suggest currently-disabled toolsets."""

        # `web` is enabled, `spotify` is disabled — enabling should only offer
        # the disabled ones.
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_platform_tools",
            lambda *_a, **_k: {"web", "file"},
        )
        monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_plugin_toolset_keys",
            lambda: set(),
        )

        completions = _completions(SlashCommandCompleter(), "/tools enable ")
        texts = {c.text for c in completions}
        # Should include disabled toolsets, exclude already-enabled ones.
        assert "web" not in texts
        assert "file" not in texts
        assert "spotify" in texts

    def test_tools_disable_completes_enabled_toolsets_only(self, monkeypatch):
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_platform_tools",
            lambda *_a, **_k: {"web", "file"},
        )
        monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_plugin_toolset_keys",
            lambda: set(),
        )

        completions = _completions(SlashCommandCompleter(), "/tools disable ")
        texts = {c.text for c in completions}
        # Should include enabled toolsets, exclude disabled ones.
        assert texts == {"web", "file"}

    def test_tools_enable_partial_filters(self, monkeypatch):
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_platform_tools",
            lambda *_a, **_k: set(),
        )
        monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_plugin_toolset_keys",
            lambda: set(),
        )

        completions = _completions(SlashCommandCompleter(), "/tools enable sp")
        texts = {c.text for c in completions}
        assert texts == {"spotify"}

    def test_tools_enable_skips_already_listed(self, monkeypatch):
        """If the user already typed a name, don't suggest it again."""
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_platform_tools",
            lambda *_a, **_k: set(),
        )
        monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_plugin_toolset_keys",
            lambda: set(),
        )

        completions = _completions(SlashCommandCompleter(), "/tools enable spotify ")
        texts = {c.text for c in completions}
        assert "spotify" not in texts

    def test_tools_suggests_mcp_server_prefixes(self, monkeypatch):
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_platform_tools",
            lambda *_a, **_k: set(),
        )
        monkeypatch.setattr(
            "lliam_cli.config.load_config",
            lambda: {"mcp_servers": {"github": {}, "linear": {}}},
        )
        monkeypatch.setattr(
            "lliam_cli.tools_config._get_plugin_toolset_keys",
            lambda: set(),
        )

        completions = _completions(SlashCommandCompleter(), "/tools enable git")
        texts = {c.text for c in completions}
        assert "github:" in texts

    def test_personality_completes_configured_personalities(self):
        """`/personality ` lists real personalities, not just `none`.

        Regression: the completer read load_config().agent.personalities, a path
        that never exists, so it always came back empty. It must resolve from the
        CLI config the runtime actually applies (which ships built-ins).
        """
        texts = {c.text for c in _completions(SlashCommandCompleter(), "/personality ")}
        assert "none" in texts
        assert len(texts) > 1


# ── Ghost text (SlashCommandAutoSuggest) ────────────────────────────────


def _suggestion(text: str, completer=None) -> str | None:
    """Get ghost text suggestion for given input."""
    suggest = SlashCommandAutoSuggest(completer=completer)
    doc = Document(text=text)

    class FakeBuffer:
        pass

    result = suggest.get_suggestion(FakeBuffer(), doc)
    return result.text if result else None


class TestGhostText:
    def test_command_name_suggestion(self):
        """/he → 'lp'"""
        assert _suggestion("/he") == "lp"

    def test_command_name_suggestion_reasoning(self):
        """/rea → 'soning'"""
        assert _suggestion("/rea") == "soning"

    def test_no_suggestion_for_complete_command(self):
        assert _suggestion("/help") is None

    def test_subcommand_suggestion(self):
        """/reasoning h → 'igh'"""
        assert _suggestion("/reasoning h") == "igh"

    def test_subcommand_suggestion_show(self):
        """/reasoning sh → 'ow'"""
        assert _suggestion("/reasoning sh") == "ow"

    def test_fast_subcommand_suggestion(self):
        assert _suggestion("/fast f") == "ast"

    def test_fast_subcommand_suggestion_hidden_when_filtered(self):
        completer = SlashCommandCompleter(command_filter=lambda cmd: cmd != "/fast")
        assert _suggestion("/fa", completer=completer) is None

    def test_no_suggestion_for_non_slash(self):
        assert _suggestion("hello") is None


# ---------------------------------------------------------------------------
# Telegram command name sanitization
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Telegram command name clamping (32-char limit)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Backward-compat aliases
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Plugin slash command integration
# ---------------------------------------------------------------------------

