"""Test isolation.

Airlock resolves its mode from ambient state: `$AIRLOCK_MODE`, and failing that a
`~/.airlock-mode` FILE. That means a bare test run silently inherits the mode of
whatever machine it happens to execute on. It bit us for real: the suite was green
in CI and on a fresh box, then went red the moment the DGX was set to `observe` --
because observe correctly suppresses the very blocks the tests assert. The tests
weren't testing the code, they were testing the host.

So every test gets a private HOME and a clean environment. If you want a mode, say
so explicitly.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_ambient_state(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_MODE", raising=False)
    monkeypatch.delenv("AIRLOCK_HEADLESS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        os.path, "expanduser",
        lambda p: p.replace("~", str(tmp_path), 1) if p.startswith("~") else p)
    return tmp_path
