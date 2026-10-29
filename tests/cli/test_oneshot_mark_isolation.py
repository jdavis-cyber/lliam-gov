"""AI-1172: the one-shot approval mark must not leak from one test to the next.

``tools.approval.mark_oneshot_process()`` sets a plain module global. The
autouse ``_reset_oneshot_process_mark`` fixture in tests/conftest.py clears
it around every test. These two tests run in file order: the first sets the
mark the way ``cli.main(query=...)`` does, the second checks it is gone.
"""

import tools.approval as approval_module


def test_marking_oneshot_sets_the_process_flag():
    approval_module.mark_oneshot_process()
    assert approval_module._oneshot_process is True


def test_next_test_starts_without_the_oneshot_mark():
    assert approval_module._oneshot_process is False
