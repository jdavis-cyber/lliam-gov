#!/usr/bin/env python3
"""
claude-bridge — a tiny OpenAI-compatible server that routes inference through
the Claude Code CLI (`claude -p`), so Lliam-GOV runs Claude on the user's Max
subscription (first-party Claude Code, NOT the metered direct API).

Lliam-GOV (provider=custom, base_url=http://127.0.0.1:8765/v1)
    --OpenAI /v1/chat/completions-->  this bridge
        --subprocess-->  claude -p --output-format json  (CLAUDE_CODE_OAUTH_TOKEN)
            -->  Anthropic, billed against the Max plan

The OAuth token is read from ~/.lliam-gov/.claude_token at call time and passed
only into the claude subprocess environment. It is never logged.
"""
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn

HOME = Path.home()
TOKEN_FILE = HOME / ".lliam-gov" / ".claude_token"
CLAUDE_BIN = str(HOME / ".local" / "bin" / "claude")
# Neutral, empty working dir so Claude Code never scans the repo / prompts for
# workspace trust / reads a stray CLAUDE.md.
WORK_DIR = HOME / ".lliam-gov" / ".bridge_cwd"
WORK_DIR.mkdir(parents=True, exist_ok=True)
PORT = int(os.getenv("CLAUDE_BRIDGE_PORT", "8765"))
DEFAULT_MODEL = "claude-via-cli"
CLAUDE_TIMEOUT = int(os.getenv("CLAUDE_BRIDGE_TIMEOUT", "240"))

app = FastAPI(title="claude-bridge")


def _load_token() -> str:
    try:
        for line in TOKEN_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("CLAUDE_CODE_OAUTH_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _log(msg: str) -> None:
    try:
        with open("/tmp/claude_bridge.log", "a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except OSError:
        pass


def _map_model(requested: str) -> str | None:
    """Map a requested model id to a Claude Code CLI alias the Max plan accepts.

    Default to 'sonnet' (not Claude Code's auto-select) so behaviour is
    deterministic and we never silently land on a gated/exhausted Opus bucket.
    """
    m = (requested or "").lower()
    if "opus" in m:
        return "opus"
    if "haiku" in m:
        return "haiku"
    return "sonnet"


def _text_of(content) -> str:
    """Collapse an OpenAI message 'content' (str or list of parts) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                if p.get("type") in ("text", "input_text") and p.get("text"):
                    parts.append(p["text"])
                elif isinstance(p.get("content"), str):
                    parts.append(p["content"])
        return "\n".join(parts)
    return "" if content is None else str(content)


def _build(messages):
    """Split into (system_prompt, flattened_conversation_prompt)."""
    system_parts, convo = [], []
    for msg in messages:
        role = msg.get("role")
        text = _text_of(msg.get("content"))
        if not text:
            continue
        if role == "system":
            system_parts.append(text)
        elif role == "assistant":
            convo.append(f"Assistant: {text}")
        else:  # user / tool / anything else
            convo.append(f"User: {text}")
    system = "\n\n".join(system_parts).strip()
    if len(convo) <= 1:
        prompt = convo[0][len("User: "):] if convo else ""
    else:
        prompt = (
            "Here is the conversation so far. Continue as the assistant and reply "
            "ONLY with your next message.\n\n" + "\n\n".join(convo)
        )
    return system, prompt


def _clean_env(token: str) -> dict:
    """Minimal, isolated environment for the claude subprocess.

    CRITICAL: do NOT inherit the parent's environment. The bridge may be
    launched from inside another Claude Code / Cowork session whose
    CLAUDE_CODE_* / ANTHROPIC_* vars (session id, entrypoint, oauth scopes,
    base_url) would contaminate the nested `claude -p` and route it onto a
    metered/nested auth path ("out of extra usage"). Start clean and inject
    only the user's subscription OAuth token.
    """
    env = {}
    for k in ("PATH", "HOME", "USER", "LOGNAME", "TERM", "LANG", "LC_ALL", "TMPDIR", "SHELL"):
        v = os.environ.get(k)
        if v:
            env[k] = v
    if token:
        env["CLAUDE_CODE_OAUTH_TOKEN"] = token
    return env


# --- capability tiers (opt-in; default 'off' = pure responder) -----------------
WORKSPACE = HOME / ".lliam-gov" / "workspace"
WORKSPACE.mkdir(parents=True, exist_ok=True)
BRIDGE_ENV = HOME / ".lliam-gov" / ".bridge_env"

# tier -> {tools csv, turns, dirs, mcp servers, write}
# write=False = least-privilege: GitHub uses its read-only endpoint, Linear is
# allowlisted to get*/search* only. write=True unlocks mutation deliberately.
_TIERS = {
    "off":      {"tools": "",                         "turns": 1,  "dirs": [],               "mcp": [],                  "write": False, "edit": False},
    "read":     {"tools": "Read,Grep,Glob,WebSearch", "turns": 8,  "dirs": [str(WORKSPACE)], "mcp": [],                  "write": False, "edit": False},
    "pm":       {"tools": "Read,Grep,Glob,WebSearch", "turns": 14, "dirs": [str(WORKSPACE)], "mcp": ["github", "linear"], "write": False, "edit": False},
    "pm-write": {"tools": "Read,Grep,Glob,WebSearch", "turns": 16, "dirs": [str(WORKSPACE)], "mcp": ["github", "linear"], "write": True,  "edit": False},
    # agent = implementation: edit/create files in the designated project (cwd=project,
    # acceptEdits, writes confined to project+workspace). No raw Bash (unconfined).
    "agent":    {"tools": "Read,Grep,Glob,WebSearch,Edit,Write", "turns": 24, "dirs": [str(WORKSPACE)], "mcp": [], "write": False, "edit": True},
}


def _gh_token() -> str:
    try:
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _linear_key() -> str:
    """Linear API key from ~/.lliam-gov/.linear_key (KEY=... or bare), if present."""
    p = HOME / ".lliam-gov" / ".linear_key"
    try:
        raw = p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("LINEAR_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
        if line and not line.startswith("#"):
            return line
    return ""


def _mcp_config(servers: list, write: bool) -> dict:
    """Build a claude --mcp-config for the requested servers, injecting creds.

    Creds are fetched live (gh token / Linear key file) so nothing static is
    persisted with a token in it; the caller writes this to a 600 temp file
    OUTSIDE the --add-dir sandbox and deletes it after the call. When write is
    False, GitHub uses its read-only endpoint (mutation tools aren't even
    exposed); Linear is scoped at the allowlist layer (see _mcp_allow).
    """
    out = {}
    if "github" in servers:
        tok = _gh_token()
        if tok:
            url = ("https://api.githubcopilot.com/mcp/" if write
                   else "https://api.githubcopilot.com/mcp/readonly")
            out["github"] = {
                "type": "http",
                "url": url,
                "headers": {"Authorization": f"Bearer {tok}"},
            }
    if "linear" in servers:
        key = _linear_key()
        if key:
            # Linear's official remote MCP is OAuth-only (no PAT via header), so
            # use a local key-based stdio server with a Personal API Key.
            out["linear"] = {
                "command": "npx",
                "args": ["-y", "@tacticlaunch/mcp-linear"],
                "env": {"LINEAR_API_TOKEN": key},
            }
    return {"mcpServers": out}


def _mcp_allow(active_servers: list, write: bool) -> list:
    """allowedTools entries for the configured MCP servers, scoped by write.

    GitHub: the read-only endpoint already hides mutation tools, so allowing the
    whole server is safe either way. Linear: in read mode, allow only the
    get*/search* tools via wildcard; in write mode, allow the whole server.
    """
    entries = []
    for s in active_servers:
        if s == "github":
            entries.append("mcp__github")
        elif s == "linear":
            if write:
                entries.append("mcp__linear")
            else:
                entries += ["mcp__linear__linear_get*", "mcp__linear__linear_search*"]
    return entries


def _tools_mode() -> str:
    """Read CLAUDE_BRIDGE_TOOLS (env wins, else ~/.lliam-gov/.bridge_env). Default 'off'."""
    val = os.environ.get("CLAUDE_BRIDGE_TOOLS", "").strip().lower()
    if not val:
        try:
            for line in BRIDGE_ENV.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("CLAUDE_BRIDGE_TOOLS="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
                    break
        except OSError:
            pass
    return val if val in _TIERS else "off"


PROJECT_FILE = HOME / ".lliam-gov" / ".bridge_project"
# Paths the project setting may never expose (creds / other instances / system).
_PROJECT_DENY = {
    str(HOME), str(HOME / ".lliam-gov"), str(HOME / ".hermes"),
    str(HOME / ".ssh"), str(HOME / ".aws"), str(HOME / ".gnupg"),
    str(HOME / ".config"), "/", "/etc", "/var", "/usr",
}


# The desktop app's native folder picker (Choose project directory) saves the
# chosen folder here, in the Electron userData dir.
APP_PROJECT_JSON = HOME / "Library" / "Application Support" / "Hermes" / "project-dir.json"


def _candidate_project_paths() -> list:
    """Raw project paths from (1) the app's native folder picker, then
    (2) the optional ~/.lliam-gov/.bridge_project file (power-user override)."""
    paths = []
    # 1. App folder picker → project-dir.json {"dir": "..."}
    try:
        d = json.loads(APP_PROJECT_JSON.read_text(encoding="utf-8"))
        if isinstance(d, dict) and (d.get("dir") or "").strip():
            paths.append(d["dir"].strip())
    except Exception:
        pass
    # 2. Manual file (optional)
    try:
        for raw in PROJECT_FILE.read_text(encoding="utf-8").splitlines():
            p = raw.strip()
            if p and not p.startswith("#"):
                paths.append(p)
    except OSError:
        pass
    return paths


def _project_dirs() -> list:
    """Absolute, existing project folders for RAG / implementation.

    Primary source is the desktop app's folder picker (no terminal needed);
    ~/.lliam-gov/.bridge_project is an optional override. Sensitive roots are
    refused so a stray entry can't hand Claude the cred files.
    """
    out = []
    for p in _candidate_project_paths():
        try:
            rp = str(Path(p).expanduser().resolve())
        except Exception:
            continue
        if rp in _PROJECT_DENY or not Path(rp).is_dir():
            continue
        if rp not in out:
            out.append(rp)
    return out


def _run_claude(system: str, prompt: str, model: str | None):
    token = _load_token()
    env = _clean_env(token)
    mode = _tools_mode()
    tier = _TIERS.get(mode, _TIERS["off"])
    allowed, max_turns = tier["tools"], tier["turns"]
    edit = tier.get("edit", False)
    perm_mode = "acceptEdits" if edit else "default"
    add_dirs = list(tier["dirs"])
    cwd = str(WORKSPACE) if mode != "off" else str(WORK_DIR)

    # Project folder(s): RAG context for read tiers; the implementation target
    # (and cwd, so writes land there) for the agent tier.
    projects = _project_dirs() if mode != "off" else []
    if projects:
        add_dirs += projects
        if edit:
            cwd = projects[0]
            note = ("Implementation mode. You may create and edit files within the "
                    "project: " + ", ".join(projects) + ". Make focused, reviewable "
                    "changes; the user reviews via git diff. Never write outside the "
                    "project/working directory.")
        else:
            note = ("Project folder(s) available for retrieval: " + ", ".join(projects)
                    + ". Ground your answer in these files — use Grep/Glob to locate "
                    "and Read to load the relevant ones before responding.")
        system = (system + "\n\n" + note) if system else note

    # MCP config (token-bearing) goes to a 600 temp file in TMPDIR — OUTSIDE the
    # --add-dir sandbox, so the model's Read tool can never reach the creds.
    write = tier.get("write", False)
    mcp_path = None
    mcp_active = []
    if tier["mcp"]:
        cfg = _mcp_config(tier["mcp"], write)
        if cfg["mcpServers"]:
            mcp_active = list(cfg["mcpServers"].keys())
            fd, mcp_path = tempfile.mkstemp(prefix="lliam_mcp_", suffix=".json")
            with os.fdopen(fd, "w") as fh:
                json.dump(cfg, fh)
            os.chmod(mcp_path, 0o600)
            mcp_allow = ",".join(_mcp_allow(mcp_active, write))
            allowed = f"{allowed},{mcp_allow}" if allowed else mcp_allow

    cmd = [CLAUDE_BIN, "-p", "--output-format", "json",
           "--max-turns", str(max_turns), "--allowedTools", allowed]
    if mode != "off":
        cmd += ["--permission-mode", perm_mode]
        for d in add_dirs:
            cmd += ["--add-dir", d]
    if mcp_path:
        cmd += ["--mcp-config", mcp_path, "--strict-mcp-config"]
    if model:
        cmd += ["--model", model]
    if system:
        cmd += ["--append-system-prompt", system]
    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True,
            env=env, cwd=cwd, timeout=CLAUDE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, "claude-bridge: claude -p timed out", {}
    finally:
        if mcp_path:
            try:
                os.unlink(mcp_path)
            except OSError:
                pass
    _log(f"mcp_active={mcp_active}")
    out = (proc.stdout or "").strip()
    if not out:
        _log(f"model={model} EMPTY stderr={(proc.stderr or '')[:200]}")
        return None, f"claude-bridge: empty output (stderr: {(proc.stderr or '')[:300]})", {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        # plain-text fallback
        _log(f"model={model} non-json out[:120]={out[:120]!r}")
        return out, None, {}
    if data.get("is_error"):
        _log(f"model={model} IS_ERROR result={(data.get('result') or '')[:160]!r} "
             f"prompt_bytes={len(prompt)} sys_bytes={len(system)}")
        return None, f"claude-bridge: {data.get('result') or 'claude error'}", {}
    _log(f"mode={mode} model={model} OK models={list((data.get('modelUsage') or {}).keys())} "
         f"prompt_bytes={len(prompt)} sys_bytes={len(system)}")
    usage = {}
    mu = data.get("modelUsage") or {}
    if mu:
        first = next(iter(mu.values()))
        usage = {
            "prompt_tokens": int(first.get("inputTokens", 0) or 0),
            "completion_tokens": int(first.get("outputTokens", 0) or 0),
        }
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    return data.get("result", ""), None, usage


def _completion_obj(text, model, usage, finish="stop"):
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()) if False else 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": finish,
        }],
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _sse_stream(text, model, usage):
    cid = "chatcmpl-" + uuid.uuid4().hex[:24]
    base = {"id": cid, "object": "chat.completion.chunk", "created": 0, "model": model}

    def gen():
        first = dict(base)
        first["choices"] = [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]
        yield f"data: {json.dumps(first)}\n\n"
        chunk = dict(base)
        chunk["choices"] = [{"index": 0, "delta": {"content": text}, "finish_reason": None}]
        yield f"data: {json.dumps(chunk)}\n\n"
        last = dict(base)
        last["choices"] = [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        if usage:
            last["usage"] = {**usage}
        yield f"data: {json.dumps(last)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/v1/models")
@app.get("/models")
def list_models():
    now = 0
    ids = [DEFAULT_MODEL, "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"]
    return {"object": "list", "data": [
        {"id": i, "object": "model", "created": now, "owned_by": "claude-code-cli"} for i in ids
    ]}


@app.get("/health")
def health():
    return {"ok": True, "token_present": bool(_load_token()), "claude": CLAUDE_BIN,
            "tools_mode": _tools_mode(), "workspace": str(WORKSPACE),
            "project_dirs": _project_dirs()}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    messages = body.get("messages", []) or []
    model_req = body.get("model", DEFAULT_MODEL)
    stream = bool(body.get("stream", False))
    system, prompt = _build(messages)
    text, err, usage = _run_claude(system, prompt, _map_model(model_req))
    if err is not None:
        # Surface as assistant content so it's visible in the app while iterating.
        text = f"[{err}]"
    if stream:
        return _sse_stream(text, model_req, usage)
    return JSONResponse(_completion_obj(text, model_req, usage))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
