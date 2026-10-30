"""End-to-end: real FreeRADIUS 3.2 in front of NACo, real RADIUS/EAP clients.

Run with:  pytest -m e2e tests/e2e   (needs Docker; builds three images)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from tests.e2e import pki

pytestmark = pytest.mark.e2e

HERE = Path(__file__).parent
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.yml")]
RADIUS = "172.31.250.11"
SECRET = "e2e-nas-shared-secret"
ALICE_PW = 'pa"ss\\wörd'
# wpa_supplicant config strings take no escapes, so EAP tests use a password
# with non-ASCII and a backslash but no double quote.
ERIN_PW = "Tünel\\şifre!"


def compose(*args: str, input_: str | None = None, check: bool = True, timeout: float = 600) -> str:
    proc = subprocess.run([*COMPOSE, *args], input=input_, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise AssertionError(f"docker compose {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout + proc.stderr


def in_client(cmd: str, stdin: str | None = None, service: str = "client") -> subprocess.CompletedProcess[str]:
    return subprocess.run([*COMPOSE, "exec", "-T", service, "sh", "-c", cmd], input=stdin,
                          capture_output=True, text=True, timeout=120)


def state() -> dict:
    out = compose("exec", "-T", "naco", "python", "-", input_=(HERE / "query.py").read_text())
    return json.loads(out.strip().splitlines()[-1])


@pytest.fixture(scope="module", autouse=True)
def stack():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    certs = HERE / ".certs"
    shutil.rmtree(certs, ignore_errors=True)
    pki.build(certs)
    compose("up", "-d", "--build", "--wait")
    compose("exec", "-T", "naco", "python", "-", input_=(HERE / "seed.py").read_text())
    for _ in range(60):
        if "Ready to process requests" in compose("logs", "freeradius", check=False):
            break
        time.sleep(1)
    else:
        raise AssertionError(compose("logs", "freeradius", check=False))
    yield
    if not __import__("os").environ.get("NACO_E2E_KEEP"):
        compose("down", "-v", "--remove-orphans", check=False)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def radclient(attrs: dict[str, str], *, kind: str = "auth", port: int = 1812, secret: str = SECRET,
              message_authenticator: bool = True, service: str = "client", wait: int = 3) -> str:
    lines = [f"{k} = {_quote(v)}" for k, v in attrs.items()]
    if message_authenticator and kind == "auth":
        lines.append("Message-Authenticator = 0x00")
    proc = in_client(f"radclient -x -r 1 -t {wait} {RADIUS}:{port} {kind} {secret}", "\n".join(lines) + "\n",
                     service=service)
    return proc.stdout + proc.stderr


def eapol_run(conf: str, mac: str = "02:00:00:00:00:01") -> subprocess.CompletedProcess[str]:
    return in_client(f"cat > /tmp/eap.conf && eapol_test -c /tmp/eap.conf -a {RADIUS} -s {SECRET} "
                     f"-M {mac} -t 15", conf)


def eapol(conf: str, mac: str = "02:00:00:00:00:01") -> bool:
    proc = eapol_run(conf, mac)
    if proc.returncode != 0 and "CTRL-EVENT-EAP-SUCCESS" in proc.stdout:
        # A RADIUS reject must never deliver EAP-Success to the supplicant.
        raise AssertionError("Access-Reject carried EAP-Success:\n" + proc.stdout[-2000:])
    if "(Access-Reject)" in proc.stdout and "EAP packet (code=4" not in proc.stdout:
        # ...and should tell it EAP-Failure (RFC 3579 §2.6.3).
        raise AssertionError("Access-Reject without EAP-Failure:\n" + proc.stdout[-2000:])
    return proc.returncode == 0


# ── PAP ────────────────────────────────────────────────────────────────────

def test_pap_accept_carries_vlan_and_policy_attributes():
    out = radclient({"User-Name": "alice", "User-Password": ALICE_PW,
                     "Calling-Station-Id": "02-00-00-00-00-01"})
    assert "Received Access-Accept" in out, out
    assert 'Tunnel-Private-Group-Id:0 = "10"' in out or 'Tunnel-Private-Group-Id = "10"' in out, out
    assert "Tunnel-Type" in out and "VLAN" in out
    assert 'Filter-Id = "staff-acl"' in out
    assert state()["logs"][0] | {} == {"result": "ACCEPT", "username": "alice", "mac": "02:00:00:00:00:01",
                                       "method": "PAP", "reason": "permitted by policy staff",
                                       "policy": "staff", "vlan": 10}


@pytest.mark.parametrize("user,password,reason", [
    ("alice", "wrong", "wrong password"),
    ("bob", "bob-password", "user disabled"),
    ("carol", "carol-password", "denied by policy no-carol"),
    ("nobody", "x", "unknown user"),
])
def test_pap_rejects(user, password, reason):
    out = radclient({"User-Name": user, "User-Password": password})
    assert "Received Access-Reject" in out, out
    assert state()["logs"][0]["reason"] == reason


def test_request_without_message_authenticator_is_dropped():
    out = radclient({"User-Name": "alice", "User-Password": ALICE_PW}, message_authenticator=False)
    assert "Received Access-Accept" not in out and "Received Access-Reject" not in out, out


def test_wrong_shared_secret_gets_nothing():
    out = radclient({"User-Name": "alice", "User-Password": ALICE_PW}, secret="not-the-secret")
    assert "Received Access-Accept" not in out, out


def test_unknown_nas_is_ignored():
    out = radclient({"User-Name": "alice", "User-Password": ALICE_PW}, service="stranger")
    assert "Received Access-Accept" not in out and "Received Access-Reject" not in out, out


# ── MAB ────────────────────────────────────────────────────────────────────

def mab(mac: str, username: str | None = None, wait: int = 3) -> str:
    user = username or mac.replace(":", "").lower()
    return radclient({"User-Name": user, "User-Password": user, "Calling-Station-Id": mac.replace(":", "-"),
                      "Service-Type": "Call-Check"}, wait=wait)


def test_mab_approved_printer():
    out = mab("02:00:00:00:00:40")
    assert "Received Access-Accept" in out and '"40"' in out, out


def test_mab_unknown_device_is_onboarded_as_pending():
    out = mab("02:00:00:00:00:50")
    assert "Received Access-Accept" in out and '"99"' in out, out
    assert state()["devices"]["02:00:00:00:00:50"] == "PENDING"


@pytest.mark.parametrize("user,station", [
    ("0200-0000-0060", "0200-0000-0060"),     # Huawei / H3C / Comware, no Service-Type
    ("020000-000061", "02-00-00-00-00-61"),   # ArubaOS-Switch single-dash
])
def test_mab_vendor_mac_formats(user, station):
    out = radclient({"User-Name": user, "User-Password": user, "Calling-Station-Id": station})
    assert "Received Access-Accept" in out and '"99"' in out, out


def test_mab_blocked_device():
    assert "Received Access-Reject" in mab("02:00:00:00:00:99")


def test_mab_username_must_match_station():
    out = mab("02:00:00:00:00:40", username="020000000041")
    assert "Received Access-Reject" in out, out
    assert state()["logs"][0]["reason"] == "not a valid MAB request"


# ── EAP ────────────────────────────────────────────────────────────────────

def ttls(user: str, password: str) -> str:
    return f'''network={{
  key_mgmt=WPA-EAP
  eap=TTLS
  identity="{user}"
  anonymous_identity="anonymous"
  password="{password}"
  phase2="auth=PAP"
  ca_cert="/certs/ca.pem"
}}
'''


def peap(user: str, password: str) -> str:
    return f'''network={{
  key_mgmt=WPA-EAP
  eap=PEAP
  identity="{user}"
  anonymous_identity="anonymous"
  password="{password}"
  phase2="auth=GTC"
  ca_cert="/certs/ca.pem"
}}
'''


def tls(name: str) -> str:
    return f'''network={{
  key_mgmt=WPA-EAP
  eap=TLS
  identity="{name}"
  ca_cert="/certs/ca.pem"
  client_cert="/certs/{name}.pem"
  private_key="/certs/{name}.key"
}}
'''


def test_eap_ttls_pap():
    assert eapol(ttls("erin", ERIN_PW))
    log = state()["logs"][0]
    assert (log["result"], log["username"], log["method"], log["vlan"]) == ("ACCEPT", "erin", "EAP-TTLS", 10)


def test_eap_ttls_wrong_password():
    assert not eapol(ttls("erin", "wrong"))
    assert state()["logs"][0]["reason"] == "wrong password"


def test_peap_gtc():
    assert eapol(peap("erin", ERIN_PW))
    log = state()["logs"][0]
    assert (log["result"], log["username"], log["method"]) == ("ACCEPT", "erin", "PEAP")


def test_peap_gtc_wrong_password():
    assert not eapol(peap("erin", "wrong"))


def test_eap_tls_goes_through_policy():
    assert eapol(tls("alice"))
    log = state()["logs"][0]
    assert (log["result"], log["username"], log["method"], log["vlan"]) == ("ACCEPT", "alice", "EAP-TLS", 10)


@pytest.mark.parametrize("name,reason", [("bob", "user disabled"), ("mallory", "unknown user")])
def test_eap_tls_identity_rules(name, reason):
    assert not eapol(tls(name))
    assert state()["logs"][0]["reason"] == reason


def test_eap_tls_untrusted_ca():
    assert not eapol(tls("rogue"))


# ── tunnels only carry the inner method NACo checks ─────────────────────────

@pytest.mark.parametrize("outer,phase2", [("TTLS", "autheap=TLS"), ("PEAP", "auth=TLS")])
def test_inner_eap_tls_cannot_claim_another_identity(outer, phase2):
    # A certificate the CA signed for mallory (unknown to NACo) must not log in
    # as erin by naming erin as the inner identity and NAKing GTC for TLS.
    conf = f'''network={{
  key_mgmt=WPA-EAP
  eap={outer}
  identity="erin"
  anonymous_identity="anonymous"
  phase2="{phase2}"
  ca_cert="/certs/ca.pem"
  ca_cert2="/certs/ca.pem"
  client_cert2="/certs/mallory.pem"
  private_key2="/certs/mallory.key"
}}
'''
    assert not eapol(conf)


# ── accounting ─────────────────────────────────────────────────────────────

def test_accounting_lifecycle():
    radclient({"User-Name": "alice", "User-Password": ALICE_PW, "Calling-Station-Id": "02-00-00-00-00-01"})
    base = {"Acct-Session-Id": "E2E-1", "User-Name": "alice", "Calling-Station-Id": "02-00-00-00-00-01"}
    out = radclient({**base, "Acct-Status-Type": "Start", "Framed-IP-Address": "192.0.2.10"},
                    kind="acct", port=1813)
    assert "Received Accounting-Response" in out, out
    (session,) = [s for s in state()["sessions"] if s["sid"] == "E2E-1"]
    assert session == {"sid": "E2E-1", "username": "alice", "vlan": 10, "framed_ip": "192.0.2.10"}
    radclient({**base, "Acct-Status-Type": "Stop"}, kind="acct", port=1813)
    assert not [s for s in state()["sessions"] if s["sid"] == "E2E-1"]


# ── fail closed (keep last: stops NACo) ────────────────────────────────────

def test_zz_no_answer_when_naco_cannot_be_asked():
    """FreeRADIUS stays silent, so the NAS counts it dead and applies its own
    server-dead action — and never lets anyone in."""
    # FreeRADIUS knows the NAS already (as with any switch in use); an
    # unknown NAS is ignored anyway while NACo cannot be asked.
    assert "Received Access-Accept" in radclient({"User-Name": "alice", "User-Password": ALICE_PW})
    compose("stop", "naco")
    try:
        # Long enough to see a reject: reaching a stopped NACo takes seconds.
        for out in (radclient({"User-Name": "alice", "User-Password": ALICE_PW}, wait=10),
                    mab("02:00:00:00:00:40", wait=10)):
            assert "Received Access-" not in out, out
        for conf in (ttls("erin", ERIN_PW), peap("erin", ERIN_PW), tls("alice")):
            proc = eapol_run(conf)
            assert proc.returncode != 0 and "Access-Accept" not in proc.stdout and "Access-Reject" not in proc.stdout, \
                proc.stdout[-2000:]
        acct = radclient({"Acct-Session-Id": "E2E-2", "Acct-Status-Type": "Start", "User-Name": "alice"},
                         kind="acct", port=1813)
        assert "Received Accounting-Response" not in acct, acct
    finally:
        compose("start", "naco")
    for _ in range(30):  # answers again as soon as NACo is back
        if "Received Access-Accept" in radclient({"User-Name": "alice", "User-Password": ALICE_PW}):
            break
        time.sleep(1)
    else:
        raise AssertionError("no answer after NACo came back")
