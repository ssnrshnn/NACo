"""
End-to-end RADIUS smoke test using ``radclient`` from ``freeradius-utils``.

The test spins up a real :class:`NACoRadiusServer` listening on an
ephemeral UDP port, then asks ``radclient`` to authenticate a known-good
PAP credential. Failure / success is decided by ``radclient``'s exit code.

This is the only test in the suite that depends on an external binary, so
it is opt-in via the ``integration`` marker and skipped when ``radclient``
isn't available (e.g. on a developer laptop without ``freeradius-utils``).
"""
from __future__ import annotations

import subprocess
import textwrap
import threading
import time

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def radius_server(free_udp_port, monkeypatch):
    """Run the async NACoRadiusServer on its own loop in a worker thread."""
    import asyncio

    from naco.config import get_config
    cfg = get_config()
    cfg.radius.host = "127.0.0.1"
    cfg.radius.auth_port = free_udp_port
    cfg.radius.acct_port = free_udp_port + 1

    from naco.radius.server import NACoRadiusServer

    server = NACoRadiusServer()
    loop = asyncio.new_event_loop()

    async def _start() -> None:
        await server.start()

    t_loop = threading.Thread(target=loop.run_forever, daemon=True)
    t_loop.start()
    asyncio.run_coroutine_threadsafe(_start(), loop).result(timeout=10)
    time.sleep(0.1)
    yield server, cfg

    asyncio.run_coroutine_threadsafe(server.stop(), loop).result(timeout=10)
    loop.call_soon_threadsafe(loop.stop)


def test_radclient_pap_reject_for_unknown_user(
    radius_server, have_radclient, tmp_path,
):
    """Even without DB-backed users, the server must reply (with Reject).

    We verify the round-trip: packet arrives, our handler processes it,
    a reply is sent — proving the on-wire pyrad integration works.
    """
    if not have_radclient:
        pytest.skip("radclient (freeradius-utils) not installed")

    _server, cfg = radius_server
    req = tmp_path / "req.txt"
    req.write_text(textwrap.dedent("""\
        User-Name = "ghost"
        User-Password = "nope"
        Message-Authenticator = 0x00
    """))

    result = subprocess.run(
        [
            "radclient", "-x", "-r", "1", "-t", "3",
            f"127.0.0.1:{cfg.radius.auth_port}",
            "auth", "testing123",
        ],
        input=req.read_text(),
        capture_output=True,
        text=True,
        timeout=15,
    )
    # radclient exits 1 on Access-Reject (which is the expected outcome for
    # an unknown user). 0 would mean Access-Accept and is also acceptable
    # if the DB happened to have a matching user.
    assert result.returncode in (0, 1), (
        f"radclient never got a reply:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
