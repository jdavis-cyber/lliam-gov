"""Local image cache for tool output (MCP image content blocks).

Moved out of the removed messaging-gateway adapter base (JER-198). Tools that
receive raw image bytes (e.g. an MCP server returning an image block) write
them here and hand the agent a ``MEDIA:<path>`` tag, so the vision tool can
read a local file.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from lliam_constants import get_lliam_dir

# Default location: {LLIAM_HOME}/cache/images/ (legacy: image_cache/)
IMAGE_CACHE_DIR = get_lliam_dir("cache/images", "image_cache")

# Raw image payloads are buffered fully in memory before being written. Cap
# them so one oversized payload can't spike RAM (#13145). 128 MiB is generous
# for ordinary images while still bounding a hostile one.
MAX_IMAGE_BYTES = 128 * 1024 * 1024


def get_image_cache_dir() -> Path:
    """Return the image cache directory, creating it if it doesn't exist."""
    IMAGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return IMAGE_CACHE_DIR


def _looks_like_image(data: bytes) -> bool:
    """Return True if *data* starts with a known image magic-byte sequence."""
    if len(data) < 4:
        return False
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if data[:3] == b"\xff\xd8\xff":
        return True
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return True
    if data[:2] == b"BM":
        return True
    if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        return True
    return False


def cache_image_from_bytes(data: bytes, ext: str = ".jpg") -> str:
    """Save raw image bytes to the cache and return the absolute file path.

    Raises:
        ValueError: If *data* is larger than ``MAX_IMAGE_BYTES`` or does not
            look like a valid image (e.g. an HTML error page).
    """
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image payload is too large ({len(data)} bytes > {MAX_IMAGE_BYTES} bytes)"
        )
    if not _looks_like_image(data):
        snippet = data[:80].decode("utf-8", errors="replace")
        raise ValueError(
            f"Refusing to cache non-image data as {ext} "
            f"(starts with: {snippet!r})"
        )
    cache_dir = get_image_cache_dir()
    filename = f"img_{uuid.uuid4().hex[:12]}{ext}"
    filepath = cache_dir / filename
    filepath.write_bytes(data)
    return str(filepath)
