"""Shared test fixtures: isolated state, an initialized store, corpus paths.

Every test runs with its own ``SCAMPI_HOME`` / ``SCAMPI_DB_PATH`` /
``HERMES_HOME`` so nothing touches the developer's real profile, and with the
provider environment variables cleared so no test can accidentally reach the
network.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT.parent) not in sys.path:
    sys.path.insert(0, str(ROOT.parent))

from scampi.core.hermes import runtime  # noqa: E402
from scampi.core.store import store  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMPI_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCAMPI_DB_PATH", str(tmp_path / "scampi.db"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.setattr(runtime, "_ctx", None, raising=False)
    monkeypatch.setattr(runtime, "_config_file_cache", None, raising=False)
    yield tmp_path


@pytest.fixture()
def conn():
    with store.connection() as connection:
        yield connection


@pytest.fixture()
def base_settings():
    from scampi.core.config import settings as settings_mod

    config = settings_mod.load()
    config["network_enabled"] = False
    return config


@pytest.fixture()
def corpus_dir():
    return FIXTURES
