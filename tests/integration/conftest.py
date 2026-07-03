"""Fixtures specific to the integration suite.

The integration tests stand up an actual NACo listener (the consolidated
``naco.app:app``) bound to an ephemeral port, run the RADIUS server in a
worker thread, and pump real packets through it via ``radclient`` from
``freeradius-utils``. CI installs ``freeradius-utils`` and provisions
PostgreSQL + Redis containers; locally you can run::

    pytest -m integration tests/integration

Tests are skipped automatically when ``radclient`` is not on ``PATH``.
"""
from __future__ import annotations

import os
import shutil
import socket

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: tests that require external binaries / services",
    )


# Mark every test in this directory with @pytest.mark.integration
def pytest_collection_modifyitems(config, items):
    for item in items:
        if "tests/integration" in str(getattr(item, "fspath", "")):
            item.add_marker(pytest.mark.integration)


# ---------------------------------------------------------------------------
# Helpers exposed to test modules
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def have_radclient() -> bool:
    return shutil.which("radclient") is not None


@pytest.fixture(scope="session")
def have_tacacs_client() -> bool:
    # FreeRADIUS doesn't ship a TACACS+ client; `tac_plus` test clients are
    # typically `tac_plus-client` or the Python `tacacs_plus` library.
    return shutil.which("tac_plus") is not None


@pytest.fixture(scope="session")
def free_udp_port() -> int:
    """Ask the kernel for an ephemeral UDP port we can bind."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def env_postgres_url() -> str:
    return os.environ.get(
        "NACO_TEST_DATABASE_URL",
        "postgresql+asyncpg://naco:naco@127.0.0.1:5432/naco",
    )
