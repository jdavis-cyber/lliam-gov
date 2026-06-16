"""Tests for the desktop voice bridge: /api/audio/{transcribe,speak,elevenlabs/voices}.

These routes connect the desktop microphone / spoken-reply UI to the existing
STT (tools.transcription_tools.transcribe_audio) and TTS
(tools.tts_tool.text_to_speech_tool) engines. The engines themselves have their
own coverage; here we pin the *contract the desktop renderer depends on*
(apps/desktop/src/types/hermes.ts) and the route's decode / temp-file / encode /
error-mapping / auth behaviour. Engines are mocked so the suite stays hermetic
(no network, no whisper model, no ffmpeg).
"""

import base64
import json
import os
from pathlib import Path

import pytest

import hermes_cli.web_server as ws

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover - fastapi optional in some envs
    TestClient = None

pytestmark = pytest.mark.skipif(TestClient is None, reason="fastapi not installed")

WEBM_DATA_URL = "data:audio/webm;base64," + base64.b64encode(b"\x1aE\xdf\xa3fakewebm").decode()


@pytest.fixture
def client(monkeypatch):
    # Host-header middleware is bypassed when no interface is bound (test mode).
    monkeypatch.setattr(ws.app.state, "bound_host", None, raising=False)
    return TestClient(ws.app)


@pytest.fixture
def auth():
    return {ws._SESSION_HEADER_NAME: ws._SESSION_TOKEN}


# --- transcribe ------------------------------------------------------------

def test_transcribe_success_maps_contract(client, auth, monkeypatch):
    captured = {}

    def fake_stt(path, model=None):
        # The route must hand the engine a real temp file with the
        # extension implied by the audio MIME type (webm here).
        captured["path"] = path
        assert os.path.exists(path)
        assert path.endswith(".webm")
        return {"success": True, "transcript": "hello world", "provider": "local"}

    monkeypatch.setattr("tools.transcription_tools.transcribe_audio", fake_stt)
    r = client.post(
        "/api/audio/transcribe", headers=auth,
        json={"data_url": WEBM_DATA_URL, "mime_type": "audio/webm"},
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "provider": "local", "transcript": "hello world"}
    # temp file must be cleaned up after the request
    assert not os.path.exists(captured["path"])


def test_transcribe_empty_data_url(client, auth):
    r = client.post("/api/audio/transcribe", headers=auth, json={"data_url": "  "})
    body = r.json()
    assert r.status_code == 200 and body["ok"] is False and body["transcript"] == ""


def test_transcribe_engine_failure_surfaces_error(client, auth, monkeypatch):
    monkeypatch.setattr(
        "tools.transcription_tools.transcribe_audio",
        lambda path, model=None: {"success": False, "error": "no STT provider"},
    )
    r = client.post(
        "/api/audio/transcribe", headers=auth,
        json={"data_url": WEBM_DATA_URL, "mime_type": "audio/webm"},
    )
    body = r.json()
    assert r.status_code == 200
    assert body["ok"] is False
    assert body["transcript"] == ""
    assert "no STT provider" in body["error"]


# --- speak -----------------------------------------------------------------

def test_speak_success_returns_data_url(client, auth, monkeypatch):
    def fake_tts(text, output_path=None):
        Path(output_path).write_bytes(b"ID3" + b"\x00" * 2000)  # pretend mp3
        return json.dumps({"success": True, "file_path": output_path})

    monkeypatch.setattr("tools.tts_tool.text_to_speech_tool", fake_tts)
    monkeypatch.setattr(ws, "load_config", lambda: {"tts": {"provider": "edge"}})

    r = client.post("/api/audio/speak", headers=auth, json={"text": "Hello, I am Lliam."})
    body = r.json()
    assert r.status_code == 200
    assert body["ok"] is True
    assert body["mime_type"] == "audio/mpeg"
    assert body["provider"] == "edge"
    assert body["data_url"].startswith("data:audio/mpeg;base64,")
    decoded = base64.b64decode(body["data_url"].split(",", 1)[1])
    assert decoded.startswith(b"ID3")


def test_speak_empty_text(client, auth):
    r = client.post("/api/audio/speak", headers=auth, json={"text": "   "})
    body = r.json()
    assert r.status_code == 200 and body["ok"] is False and body["data_url"] == ""


def test_speak_engine_failure_surfaces_error(client, auth, monkeypatch):
    monkeypatch.setattr(
        "tools.tts_tool.text_to_speech_tool",
        lambda text, output_path=None: json.dumps({"success": False, "error": "boom"}),
    )
    monkeypatch.setattr(ws, "load_config", lambda: {"tts": {"provider": "edge"}})
    r = client.post("/api/audio/speak", headers=auth, json={"text": "hi"})
    body = r.json()
    assert r.status_code == 200 and body["ok"] is False and "boom" in body["error"]


# --- elevenlabs voices -----------------------------------------------------

def test_voices_unavailable_without_key(client, auth, monkeypatch):
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)
    monkeypatch.delenv("ELEVEN_API_KEY", raising=False)
    monkeypatch.setattr(ws, "load_config", lambda: {"tts": {"provider": "edge"}})
    r = client.get("/api/audio/elevenlabs/voices", headers=auth)
    assert r.status_code == 200
    assert r.json() == {"available": False, "voices": []}


# --- auth boundary ---------------------------------------------------------

@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("post", "/api/audio/transcribe", {"data_url": WEBM_DATA_URL}),
        ("post", "/api/audio/speak", {"text": "hi"}),
        ("get", "/api/audio/elevenlabs/voices", None),
    ],
)
def test_audio_routes_require_session_token(client, method, path, payload):
    fn = getattr(client, method)
    r = fn(path, json=payload) if payload is not None else fn(path)
    assert r.status_code == 401
