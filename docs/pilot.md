# First deployment: a pilot

Start with one switch, one port and a handful of devices. Done in this
order, nobody loses network access while something is still wrong, and
each step shows in *Logs* whether it works. Allow half a day.

## 1. Before you start

- A Linux host or VM for NACo ([requirements](install.md#requirements)),
  with a fixed address and correct time.
- A switch (or access point) you can reach **without** going through a port
  you are about to put under 802.1X — the console, or a management VLAN on
  another port.
- Test devices: a Windows laptop, a Mac or iPhone, an Android phone, and one
  device that cannot do 802.1X (a printer) for MAB.
- The VLANs: users, onboarding (new devices), and a *critical* VLAN for
  when NACo cannot be reached (section 5).

## 2. Install NACo

```bash
git clone https://github.com/ssnrshnn/NACo.git && cd NACo
NACO_IMAGE=ghcr.io/ssnrshnn/naco:3.1.1 \
NACO_RADIUS_IMAGE=ghcr.io/ssnrshnn/naco-freeradius:3.1.1 ./quickstart.sh
docker compose exec naco nacoctl check-config
```

Sign in, choose a password and set up two-factor authentication. Open the
[firewall](install.md#firewall): switch → NACo UDP 1812/1813 (and TCP 49 for
TACACS+), NACo → switch UDP 3799.

## 3. Describe the pilot in NACo

1. **RADIUS clients** — the switch, with the address its RADIUS packets come
   from (`ip radius source-interface` on Cisco), a shared secret of at
   least 16 characters, and its *device type* (see the
   [vendor pages](network-devices.md#vendors)).
2. **Groups and users** — a group `staff` and two test users, or connect
   [LDAP / AD](configuration.md).
3. **Policies** — for example:

   ```text
   10  permit  group in staff                       VLAN <users>
   20  permit  MAB, device status approved          VLAN <users>
   30  permit  MAB, device status pending           VLAN <onboarding>
   ```

   Anything else is denied.
4. **Simulator** — run each test user and the printer's MAC through it. Fix
   the policies until every result is what you expect; the switch is not
   involved yet.

## 4. One port, monitor mode

Configure RADIUS globally as on your [vendor page](network-devices.md#vendors)
— without its port range — and put **one** port under 802.1X, in monitor
mode: the switch asks NACo and logs the answer, and lets traffic through
whatever it is. On Cisco IOS-XE with `authentication` commands:

```text
interface GigabitEthernet1/0/48
 switchport mode access
 switchport access vlan <onboarding>
 authentication open
 authentication host-mode multi-auth
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 mab
 dot1x pae authenticator
 spanning-tree portfast
```

Connect each test device to the port and configure its supplicant
([802.1X and certificates](eap.md)). (Cisco's `test aaa` command sends no
Message-Authenticator, so NACo ignores it unless the client is marked
Legacy NAS — test with a real device instead.)

| Device | Method | Trust |
|---|---|---|
| Windows 10/11 | EAP-TTLS with PAP, or EAP-TLS (PEAP-MSCHAPv2 is not supported) | `secrets/ca/ca.pem`, server name `NACO_HOST` |
| macOS, iOS | EAP-TTLS or EAP-TLS, through a configuration profile | same |
| Android | PEAP with GTC, EAP-TTLS with PAP, or EAP-TLS; set *Domain* to `NACO_HOST` | same |
| Printer | MAB — approve it on *Devices* | — |

Every attempt must show in *Logs* with the expected decision and VLAN;
`show access-session interface Gi1/0/48 details` shows what the switch
received. A reject explains itself in *Logs*; reproduce it in the
*Simulator*.

## 5. When NACo cannot be reached

NACo never lets a device in without a decision. When it cannot decide —
the host is down, or NACo is stopped, restarting or failing — the switch's
requests and Status-Server probes get **no answer** (within a minute at
most; see [network devices](network-devices.md#when-naco-cannot-decide)).
After a few unanswered tries the switch marks the server dead and applies
its *server dead* action: the critical VLAN, for example. Without one, new
devices get no access until NACo is back. Devices already connected
normally keep their session — check how your switch treats
re-authentication while the server is dead. Not every device has a critical
VLAN — wireless controllers mostly do not; the vendor pages say.

Configure the dead-server behaviour on the switch and test it — on Cisco
IOS-XE:

```text
radius server NACO
 automate-tester username naco-probe probe-on
radius-server dead-criteria time 5 tries 3
radius-server deadtime 2
!
interface GigabitEthernet1/0/48
 authentication event server dead action authorize vlan <critical>
 authentication event server dead action authorize voice
 authentication event server alive action reinitialize
```

(The probe appears in *Logs* as a rejected `naco-probe` — expected.) Stop
NACo (`docker compose stop naco`), wait a minute, connect a device, check
that it lands in the critical VLAN, then start NACo again and watch the
port re-authenticate.

## 6. Enforce

On the test port, `no authentication open`, then repeat section 4: every
device must get its VLAN, and an unknown device the onboarding VLAN. Test
that changes reach live sessions (Change of Authorization):

- approve or block a device on *Devices* — its port re-authenticates within
  seconds;
- change the VLAN of the `staff` policy — sessions it decided move;
- disable a test user — their session ends.

*Sessions* shows whether the device acknowledged each disconnect. On a
timeout, check the device's dynamic-authorization settings (Cisco: `aaa
server radius dynamic-author`) and that the CoA port is open from the NACo
host; on a NAK, check the client's device type. A wired MAB device whose
VLAN changed keeps its old IP address until it renews it — unplug it once
during the pilot.

## 7. Switch logins (optional)

[TACACS+](tacacs.md): keep a **local fallback account** in the switch
configuration and test from a second session before closing the first,
so a mistake cannot lock you out.

## 8. Widen the pilot

When the test port has behaved for a few days: more ports of the same
switch (monitor mode first again), then more switches, then wireless.
Keep *Logs* and the *Overview* open during each step; to back out, put a
port back with `authentication open` or `no authentication port-control
auto`.

Before relying on it: schedule [backups](operations.md#backups) and copy
them off the host, and keep `.env`, `secrets/` and
`deploy/freeradius/certs/` in a safe place.
