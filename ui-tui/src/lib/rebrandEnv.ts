// Env-var compatibility shim for the hermes -> lliam rename (TUI subprocess
// contract, Task R.8b item 15). This is the node-side mirror of
// lliam_cli.env_compat.getenv_compat on the Python side.
//
// The TUI env contract crosses the Python <-> node boundary: Python (or the
// nix/homebrew wrapper) SETS HERMES_TUI_* / HERMES_PYTHON / HERMES_CWD /
// HERMES_VOICE* and node READS them (and vice-versa for the Python subprocess
// node spawns). Unlike Python, node has no getenv_compat, so a straight rename
// of one side would break the other. To flip safely: producers emit the new
// LLIAM_-prefixed name, and every reader accepts LLIAM_ first, then falls back
// to the legacy HERMES_ name. That keeps stragglers working — including the
// nix/homebrew wrappers that still export the HERMES_ names, and any operator
// docs/scripts that set them.

type EnvLike = Record<string, string | undefined>

/**
 * Read ``LLIAM_<suffix>`` if set-and-nonempty, else legacy ``HERMES_<suffix>``.
 * Empty string is treated as unset (matching the Python getenv_compat and the
 * ``?? ''``/``.trim()`` idioms used throughout the TUI).
 *
 * @param suffix the shared variable suffix WITHOUT the LLIAM_/HERMES_ prefix,
 *   e.g. ``"TUI_THEME"``, ``"PYTHON"``, ``"CWD"``, ``"VOICE_TTS"``.
 * @param env    the environment to read from (defaults to ``process.env``).
 */
export const renv = (suffix: string, env: EnvLike = process.env): string | undefined => {
  const next = env[`LLIAM_${suffix}`]
  if (next != null && next !== '') {
    return next
  }
  return env[`HERMES_${suffix}`]
}
