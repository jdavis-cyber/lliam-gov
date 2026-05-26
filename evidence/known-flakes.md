# Known-flake Register

Tests that fail intermittently under heavy CI load but pass deterministically on the Mac mini development host. **None of these are introduced by Lliam-GOV work** — they are pre-existing upstream Hermes flakes inherited via the v0.14.0 baseline import. Recorded here so future agents and Jerome don't chase phantom regressions.

Policy per Rev. 3 plan §11.7 (upstream sync): hard fork from upstream Hermes; immediate cherry-pick for security only; **quarterly batch for everything else**. Test-flake fixes that originate upstream land in the next quarterly review unless they bite repeatedly.

Convention: each entry carries (a) the test ID, (b) the failure signature, (c) the analysis, (d) the local-reproduction status, (e) the disposition, (f) the next-quarterly-review pointer.

---

## Flake 1 — `test_pub_broadcasts_to_events_subscribers` (timing-sensitive WebSocket race)

**Test:** `tests/hermes_cli/test_web_server.py::TestPtyWebSocket::test_pub_broadcasts_to_events_subscribers`

**First observed:** Workflow run [#13](https://github.com/jdavis-cyber/lliam-gov/actions/runs/26426964277), Tests / slice 5/6, on the PR #8 (Phase 2 control matrix) CI execution, 2026-05-25 ~21:23 ET. Surfaced via the GitHub failure-notice email.

**Failure signature:**
```
FAILED tests/hermes_cli/test_web_server.py::TestPtyWebSocket::test_pub_broadcasts_to_events_subscribers
AssertionError: broadcast not received within 10s — server likely dropped the
frame silently (see _broadcast_event except Exception: pass)
============= 1 failed, 144 passed, 1 warning in 23.61s =============
Slice 5/6, exit code 1
```

### Analysis

**Cause: structural race condition in the ASGI WebSocket accept/register sequence.**

The test exercises the dashboard's pub/sub event stream:
1. Subscriber connects to `/api/events?channel=broadcast-test`
2. Publisher connects to `/api/pub?channel=broadcast-test`
3. Publisher sends a text frame
4. Test asserts the subscriber receives it within 10s

The race: `WebSocket.accept()` returns to the client (the test's TestClient) BEFORE the server-side handler has added the subscriber to `_event_channels`. A publish issued immediately after accept can therefore reach `_broadcast_event` before the subscriber is registered — and the frame is dropped silently. The 5-second busy-wait on `_event_channels.get("broadcast-test")` (line 2325-2333 of the test) is the existing mitigation; the further 10-second receive timeout (line 2356) is the catch-all.

**The upstream test author already knew about this race** — two long comment blocks document the timing sensitivity explicitly:

> `tests/hermes_cli/test_web_server.py:2320-2324` — *"websocket_connect returns when ws.accept() completes, but the server adds us to `_event_channels` in a follow-up await, so a publish immediately after connect can race ahead of the subscriber registration and the message is dropped."*

> `tests/hermes_cli/test_web_server.py:2338-2344` — *"under heavy CI load the receive can race the broadcast and hang until pytest-timeout kills us."*

### Five mitigations the upstream author already added

The test is one of the most heavily armored in the upstream Hermes suite. Existing mitigations:

1. **5-second busy-wait on `_event_channels` registration** before the publisher connects (lines 2325-2333). Catches the accept-before-register race in the typical case.
2. **Explicit `_event_lock` in `_broadcast_event`** (`hermes_cli/web_server.py:3436`) for thread-safety on the subscriber registry.
3. **Background recv thread + `queue.Queue`** (lines 2344-2354) to decouple the test's wait from the ASGI app's broadcast handler. Without this, under heavy CI load the receive could race the broadcast and hang until pytest-timeout killed the test.
4. **10-second receive timeout** (line 2356) — generous in normal conditions, exceeded under heavy CI load.
5. **Best-effort error surfacing** — if `_recv` raises, the exception is captured and re-raised from the main test thread (lines 2350-2351, 2363-2364) so the failure mode is visible instead of a bare timeout.

Despite all five, the test still flakes on GitHub-hosted runners under contention.

### Stale assertion message — finger pointing at the wrong thing

The assertion message reads:

> *"server likely dropped the frame silently (see `_broadcast_event except Exception: pass`)"*

But the CURRENT `_broadcast_event` code (`hermes_cli/web_server.py:3434-3445`) does NOT have a bare `except Exception: pass` — it does `_log.warning(...)` with `exc_info=True`:

```python
async def _broadcast_event(channel: str, payload: str) -> None:
    """Fan out one publisher frame to every subscriber on `channel`."""
    async with _event_lock:
        subs = list(_event_channels.get(channel, ()))
    for sub in subs:
        try:
            await sub.send_text(payload)
        except Exception:
            # Subscriber went away mid-send; the /api/events finally clause
            # will remove it from the registry on its next iteration.
            _log.warning("broadcast send failed for subscriber on %s", channel, exc_info=True)
```

The assertion message was written against an older buggy version (pre-`_log.warning`) and was never updated when upstream fixed the exception suppression. **The actual failure mode is the accept/register race, not silent exception swallowing.** When the test prints its assertion text, it's giving outdated debugging guidance.

### Local reproduction

**Does not reproduce on the Mac mini development host.** Ran the test 5× sequentially under `UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov uv run pytest`:

```
=== run 1 ===  1 passed in 0.84s
=== run 2 ===  1 passed in 0.23s
=== run 3 ===  1 passed in 0.23s
=== run 4 ===  1 passed in 0.22s
=== run 5 ===  1 passed in 0.22s
```

5/5 pass deterministically, all sub-second. The Mac mini is dedicated hardware with no contention; GitHub-hosted Linux runners are shared and contended. The flake rate appears to be a function of runner load, not a function of the code.

### Additional signal — re-run passed on the same code

After the PR #8 merge to main, the SAME workflow ran AGAIN on main (run `26427055413`) and **succeeded** in 5m05s. Identical code, identical workflow definition, just a different runner. Confirms the flake is environmental, not logical.

### Disposition

**Documented; no code change.**

- **Not marking xfail** — would silently hide future real regressions of the same test.
- **Not adding `pytest-flaky` retries** — adds a plugin dependency and obscures the underlying race.
- **Not fixing `_broadcast_event`** — the bug is in upstream Hermes's ASGI accept/register sequencing, not in our overlay. Lliam-GOV's plan §11.7 governs upstream changes: non-security fixes wait for the quarterly batch.
- **Not modifying the stale assertion message** — same reason; it's upstream Hermes test code, and we don't casually touch upstream code per the fork-and-facelift posture (plan §6).
- **Standard mitigation when it bites: re-run the workflow.** That's the same posture upstream maintainers themselves use for this class of flake.

### Action items for the next quarterly upstream review

Per plan §11.7 (next review cadence: Q3 2026):

1. Check upstream Hermes's main for any fix to the accept/register race in `hermes_cli/web_server.py` `_event_channels` registration ordering. If a fix lands upstream that makes registration synchronous (or otherwise eliminates the race), cherry-pick it and record an audit event per plan.
2. While we're in that file, also check whether upstream has updated the stale assertion message in `tests/hermes_cli/test_web_server.py:2358-2362`. The current text incorrectly fingers `except Exception: pass`. If upstream has corrected it, take the cherry-pick. If not, leave it — modifying upstream test assertion text in the fork creates a merge-conflict for future cherry-picks.

If the same flake bites Lliam-GOV CI **three or more times across separate PRs** before the quarterly review, escalate: open an issue at https://github.com/NousResearch/hermes-agent with the analysis above. Don't fix-in-place in our fork.

---

## Future entries

Append additional flakes here as they are observed. One per top-level `##` section, using the same template (test ID, signature, analysis, local reproduction, disposition, quarterly-review action items).
