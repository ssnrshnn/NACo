"""Browser walkthrough of the admin UI against a real NACo process.

Run with:  pytest -m ui tests/ui     (needs Playwright + Chromium:
           `playwright install chromium`, or NACO_UI_BROWSER_CHANNEL=chrome)
Screenshots land in tests/ui/.shots/ for a visual check.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pyotp
import pytest

playwright = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright.sync_playwright
pytestmark = pytest.mark.ui

TOKEN = "naco-development-internal-token-not-for-production"
OUT = str(Path(__file__).parent / ".shots")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ui")
    http, internal = _free_port(), _free_port()
    (tmp / "config.yaml").write_text(
        f"server:\n  host: 127.0.0.1\n  http_port: {http}\n  internal_port: {internal}\n"
        "  timezone: Europe/Istanbul\n  name: ACME HQ\ntacacs:\n  enabled: false\n")
    env = {**os.environ, "NACO_CONFIG": str(tmp / "config.yaml"), "NACO_DATABASE_PATH": str(tmp / "naco.db"),
           "NACO_DEV": "1", "NACO_ADMIN_PASSWORD": "initial-admin-pass"}
    for var in ("NACO_MASTER_KEY", "NACO_INTERNAL_TOKEN"):
        env.pop(var, None)
    proc = subprocess.Popen([sys.executable, "-m", "naco.main"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{http}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/api/v1/health/ready", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    yield base, f"http://127.0.0.1:{internal}"
    proc.terminate()
    proc.wait(10)


def test_admin_ui_walkthrough(server):
    BASE, AAA = server
    os.makedirs(OUT, exist_ok=True)
    problems: list[str] = []

    def aaa(path, **attrs):
        body = json.dumps({k.replace("_", "-"): {"type": "string", "value": [v]} for k, v in attrs.items()}).encode()
        req = urllib.request.Request(AAA + path, data=body, method="POST",
                                     headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            return r.status

    def api(page, method, path, body=None):
        csrf = page.locator('meta[name="naco-csrf"]').get_attribute("content")
        r = page.request.fetch(BASE + "/api/v1" + path, method=method, data=json.dumps(body) if body is not None else None,
                               headers={"X-CSRF-Token": csrf, "Content-Type": "application/json", "Origin": BASE})
        if not r.ok:
            problems.append(f"API {method} {path} -> {r.status} {r.text()[:200]}")
        return r.json() if r.status != 204 else None

    def shot(page, name):
        page.wait_for_timeout(500)
        page.screenshot(path=f"{OUT}/{name}.png", full_page=False)

    with sync_playwright() as p:

        browser = p.chromium.launch(channel=os.environ.get("NACO_UI_BROWSER_CHANNEL") or None)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
        page = ctx.new_page()
        page.on("console", lambda m: m.type in ("error", "warning") and problems.append(f"console {m.type}: {m.text} @ {page.url}"))
        page.on("pageerror", lambda e: problems.append(f"pageerror: {e} @ {page.url}"))

        page.goto(BASE + "/")
        shot(page, "01-login")
        page.fill("#username", "admin")
        page.fill("#password", "initial-admin-pass")
        page.click("button[type=submit]")
        page.wait_for_url("**/setup")
        shot(page, "02-setup-password")
        page.fill("#cur", "initial-admin-pass")
        page.fill("#new", "a-much-better-passphrase")
        page.fill("#again", "a-much-better-passphrase")
        page.click("button[type=submit]")
        page.wait_for_selector("text=Set up authenticator")
        assert page.locator("#pw").count() == 0  # just typed it: not asked again
        page.click("button[type=submit]")
        page.wait_for_selector(".qr svg")
        page.reload()  # arriving at this step afresh: confirm the password
        page.wait_for_selector("#pw")
        page.fill("#pw", "a-much-better-passphrase")
        page.click("button[type=submit]")
        page.wait_for_selector(".qr svg")
        shot(page, "03-setup-qr")
        secret = page.locator(".secret-box").text_content().strip()
        page.fill("#code", pyotp.TOTP(secret).now())
        page.click("button[type=submit]")
        page.wait_for_selector(".codes")
        shot(page, "04-recovery-codes")
        page.click("text=I saved them")
        page.wait_for_url(BASE + "/")
        shot(page, "05-dashboard-empty")

        # Seed through the real API, as an admin would.
        staff = api(page, "POST", "/groups", {"name": "staff", "description": "Employees"})
        netadmins = api(page, "POST", "/groups", {"name": "netadmins", "device_admin_privilege": 15,
                                                  "device_admin_attributes": ["junos-exec: local-user-name=super-user"]})
        api(page, "POST", "/nas", {"name": "core-sw01", "ip_address": "10.0.0.1", "secret": "a-long-shared-secret-1"})
        api(page, "POST", "/nas", {"name": "wlc-hq", "ip_address": "10.0.0.2", "secret": "a-long-shared-secret-2",
                                   "vendor": "cisco", "require_message_authenticator": False})
        api(page, "POST", "/nas", {"name": "site-aps", "ip_address": "10.0.20.0/24", "secret": "a-long-shared-secret-3",
                                   "vendor": "standard"})
        for i, name in enumerate(["alice", "bob", "carol", "dave", "erin"]):
            api(page, "POST", "/users", {"username": name, "password": f"{name}-password-1", "full_name": name.title() + " Example",
                                         "group_id": staff["id"] if i < 4 else netadmins["id"]})
        api(page, "POST", "/policies", {"name": "Block contractors", "action": "DENY", "priority": 10,
                                        "conditions": [{"type": "username", "op": "equals", "value": "dave"}]})
        api(page, "POST", "/policies", {"name": "Staff on corporate Wi-Fi", "action": "PERMIT", "vlan": 10, "priority": 20,
                                        "description": "Employees get the corporate VLAN",
                                        "conditions": [{"type": "group", "op": "in", "value": ["staff"]},
                                                       {"type": "auth_method", "value": ["PEAP", "EAP-TLS", "PAP"]}],
                                        "reply_attributes": {"Filter-Id": "corp-acl"}})
        api(page, "POST", "/policies", {"name": "Approved printers", "action": "PERMIT", "vlan": 40, "priority": 30,
                                        "conditions": [{"type": "auth_method", "value": ["MAB"]},
                                                       {"type": "device_status", "value": ["approved"]}]})
        api(page, "POST", "/devices", {"mac_address": "00:1b:63:00:00:40", "device_type": "printer", "description": "Floor 2 printer"})
        api(page, "POST", "/command-sets", {"name": "read-only", "rules": [{"action": "PERMIT", "pattern": "show *"},
                                                                           {"action": "DENY", "pattern": "configure *"}]})
        api(page, "POST", "/guests", {"mac_address": "da:a1:19:00:00:01", "hours": 4, "full_name": "Visitor"})

        # Real AAA traffic through the internal API (what FreeRADIUS would send).
        for user in ["alice", "bob", "carol"]:
            station = f"3C-22-FB-00-00-0{len(user)}"
            aaa("/aaa/authenticate", User_Name=user, User_Password=f"{user}-password-1", NACo_NAS_IP="10.0.0.2",
                Calling_Station_Id=station)
            aaa("/aaa/authorize", User_Name=user, NACo_Auth_Method="PEAP", NACo_Inner_Identity=user, NACo_NAS_IP="10.0.0.2",
                Calling_Station_Id=station, Called_Station_Id="AA-BB-CC-00-00-01:ACME-Corp")
        aaa("/aaa/authenticate", User_Name="dave", User_Password="dave-password-1", NACo_NAS_IP="10.0.0.1")
        aaa("/aaa/authorize", User_Name="dave", NACo_Auth_Method="PAP", NACo_NAS_IP="10.0.0.1")
        for mac in ["00-1B-63-00-00-40", "F0-18-98-00-00-77", "B8-27-EB-00-00-12"]:
            aaa("/aaa/authorize", User_Name=mac.replace("-", "").lower(), User_Password=mac.replace("-", "").lower(),
                Calling_Station_Id=mac, NACo_Auth_Method="MAB", NACo_NAS_IP="10.0.0.1")
        for i, user in enumerate(["alice", "bob"]):
            aaa("/aaa/accounting", Acct_Status_Type="Start", Acct_Session_Id=f"S{i}", User_Name=user, NACo_NAS_IP="10.0.0.2",
                Calling_Station_Id=f"3C-22-FB-00-00-0{len(user)}", Framed_IP_Address=f"10.10.0.{i + 20}",
                Called_Station_Id="AA-BB-CC-00-00-01:ACME-Corp")

        pages = ["/", "/users", "/groups", "/devices", "/policies", "/simulator", "/nas", "/tacacs-clients",
                 "/command-sets", "/sessions", "/guests", "/logs", "/admins", "/tokens", "/audit", "/system", "/account"]
        for i, path in enumerate(pages):
            page.goto(BASE + path)
            page.wait_for_selector('#page[aria-busy="false"], .kpi .value', timeout=8000)
            shot(page, f"10-{i:02d}{path.replace('/', '-') or '-dashboard'}")

        # RADIUS clients: device type, network clients.
        page.goto(BASE + "/nas")
        page.wait_for_selector("text=10.0.20.0/24")
        assert page.locator("tr", has_text="wlc-hq").locator("text=Cisco IOS-XE / Catalyst 9800").count() == 1
        page.click("text=Add client")
        assert page.locator("dialog select option").count() >= 8
        page.keyboard.press("Escape")
        shot(page, "14-radius-clients-types")

        # Group form: vendor TACACS+ attributes, one per line.
        page.goto(BASE + "/groups")
        page.wait_for_selector("text=junos-exec")
        page.locator("tr", has_text="netadmins").locator("button[title=Edit]").click()
        area = page.locator("textarea")
        assert area.input_value() == "junos-exec: local-user-name=super-user"
        area.fill("junos-exec: local-user-name=super-user\nfortigate: admin_prof=super_admin\n")
        page.click("dialog button[type=submit]")
        page.wait_for_selector("text=fortigate")
        shot(page, "15-groups-vendor-attributes")

        # Live update: a new decision should slide into the dashboard feed.
        page.goto(BASE + "/")
        page.wait_for_timeout(1200)
        aaa("/aaa/authenticate", User_Name="erin", User_Password="erin-password-1", NACo_NAS_IP="10.0.0.1")
        aaa("/aaa/authorize", User_Name="erin", NACo_Auth_Method="PAP", NACo_NAS_IP="10.0.0.1")
        page.wait_for_selector(".feed li.enter", timeout=5000)
        shot(page, "20-dashboard-live")

        # Policy editor and simulator.
        page.goto(BASE + "/policies")
        page.wait_for_selector("table tbody tr")
        page.locator("button[title=Edit]").nth(1).click()
        page.wait_for_selector("dialog.sheet .cond")
        shot(page, "21-policy-editor")
        page.keyboard.press("Escape")
        page.goto(BASE + "/simulator")
        page.select_option("select", "PEAP")
        page.fill("input[placeholder=alice]", "alice")
        page.click("button[type=submit]")
        page.wait_for_selector(".trace")
        shot(page, "22-simulator")

        # Command palette and light theme.
        page.goto(BASE + "/")
        page.keyboard.press("Meta+k")
        page.keyboard.type("ali")
        page.wait_for_timeout(600)
        shot(page, "23-palette")
        page.keyboard.press("Escape")
        page.click("[data-action=theme]")
        shot(page, "24-dashboard-light")
        page.goto(BASE + "/policies")
        shot(page, "25-policies-light")
        page.goto(BASE + "/devices")
        shot(page, "26-devices-light")

        page.click(".account-menu summary")
        shot(page, "27-account-menu")
        page.click("body", position={"x": 600, "y": 600})

        # Mobile.
        mobile = browser.new_context(viewport={"width": 390, "height": 844}, storage_state=ctx.storage_state(), color_scheme="dark")
        m = mobile.new_page()
        m.goto(BASE + "/")
        m.wait_for_timeout(900)
        m.screenshot(path=f"{OUT}/30-mobile-dashboard.png")
        m.goto(BASE + "/portal")
        m.wait_for_timeout(500)
        m.screenshot(path=f"{OUT}/31-mobile-portal.png")
        browser.close()

    assert not problems, "\n".join(problems)
