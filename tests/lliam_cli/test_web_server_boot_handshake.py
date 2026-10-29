"""
Desktop boot handshake: concurrent /api/status probes must all answer.

The desktop shell polls ``/api/status`` while the backend boots. If the event
loop were blocked, later probes would pile up and the shell would reset the
connection (WinError 10054, PR #50231 / issue #50209). The original slow path
(a cold import of the messaging gateway module during status) was removed
with the gateway (JER-198); this keeps the concurrency guarantee covered.
"""

from __future__ import annotations

import asyncio

import lliam_cli.web_server as web_server_mod


def test_concurrent_status_probes_all_respond():
    import httpx

    PROBES = 3
    responses: list[int] = []

    async def _run():
        transport = httpx.ASGITransport(app=web_server_mod.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            tasks = [client.get("/api/status", timeout=10) for _ in range(PROBES)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                responses.append(-1 if isinstance(r, Exception) else r.status_code)

    asyncio.run(_run())

    failed = [c for c in responses if c != 200]
    assert not failed, f"{len(failed)}/{PROBES} probes failed (codes: {responses})"
