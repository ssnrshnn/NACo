# Network devices

Every switch, access point and wireless controller that asks NACo questions
is a **RADIUS client**. This page covers what all of them need; the vendor
pages below give the configuration for each platform.

Bringing NACo into a running network? Start with [a pilot](pilot.md): one
port in monitor mode, then the behaviour when NACo cannot be reached, then
enforcement.

## Vendors

| Vendor | Platforms | Device type in NACo |
|---|---|---|
| [Cisco](vendors/cisco.md) | Catalyst on IOS-XE, Catalyst 9800 and AireOS controllers, NX-OS logins | Cisco IOS-XE / Catalyst 9800 |
| [Cisco Meraki](vendors/meraki.md) | MS switches, MR access points | Cisco Meraki |
| [HPE Aruba Networking](vendors/aruba.md) | AOS-CX, ArubaOS-Switch, AOS 8 controllers, Instant and AOS 10 APs | HPE Aruba Networking |
| [HPE Comware and H3C](vendors/hpe-comware.md) | Comware 7 switches | Standard |
| [Juniper](vendors/juniper.md) | EX on Junos, Mist | Juniper |
| [Huawei](vendors/huawei.md) | S-series and CloudEngine S campus switches | Standard |
| [Fortinet](vendors/fortinet.md) | FortiGate with FortiSwitch and FortiAP | Fortinet |
| [Extreme Networks](vendors/extreme.md) | Switch Engine (EXOS) | Extreme Networks |
| [Ruckus](vendors/ruckus.md) | ICX switches; SmartZone and Unleashed wireless | Ruckus ICX; Standard for wireless |
| [Dell](vendors/dell.md) | PowerSwitch on OS10 | Standard |
| [MikroTik](vendors/mikrotik.md) | RouterOS 7: dot1x server, `wifi`, `wireless` | Standard |
| [Ubiquiti UniFi](vendors/unifi.md) | UniFi switches and access points | Standard |
| [TP-Link Omada](vendors/omada.md) | Omada switches and access points | Standard |

The vendor pages are written from each vendor's documentation; each ends
with what to check in the pilot. Another vendor that follows RFC 3580 and
RFC 5176 works with the *Standard* device type.

Three were also run against NACo in a lab, as virtual machines and
software: **MikroTik RouterOS 7.25** (wired dot1x server), **Extreme Switch
Engine 33.6.1** (NetLogin and TACACS+) and **hostapd 2.11**, the 802.1X
authenticator inside OpenWrt and many access points (wired, with its
Disconnect server requiring Event-Timestamp and Message-Authenticator).
802.1X, MAC authentication, VLANs, accounting, disconnects — by hand and
after a change in NACo — and the behaviour while NACo is down work as their
pages describe; the pages also say where each device needs care.

## Adding a client

*RADIUS clients → Add client*:

- **IP address or network** — the address the device's RADIUS packets come
  *from* (set its RADIUS source interface so it is predictable). Platforms
  that send RADIUS from every access point or switch — UniFi, Omada, Meraki,
  Mist, Instant, SmartZone without proxy — are easier to add as one network,
  e.g. `10.0.20.0/24` (at most /16, or /48 for IPv6). A packet belongs to the
  client with exactly its address, else to the narrowest network that holds
  it; NACo sends disconnects to the device itself.
- **Shared secret** — at least 16 random characters; the *Generate* button
  makes one. The same secret goes on the device. Some devices accept fewer
  characters than NACo generates — the vendor pages say which.
- **Device type** — decides what a disconnect request carries (see
  [below](#change-of-authorization)).
- **CoA port** — where the device listens for disconnect requests; empty
  means the device type's usual port (3799; Meraki 1700).
- **Require Message-Authenticator** — leave on (see below).

NACo picks a new client up at its first request; a changed secret or a
disabled client takes effect within a minute.

## What every device needs

| | |
|---|---|
| Authentication | NACo host, UDP **1812** — 802.1X (EAP), MAB and PAP all use this port |
| Accounting | NACo host, UDP **1813**, start/stop **and interim updates every 6 hours or less** — NACo drops a session it has not heard about for 24 hours |
| Dynamic authorization (CoA) | allow NACo's host address, same shared secret, the CoA port above |
| Calling-Station-Id | the client's MAC address (default on most devices) |
| Framed-IP-Address in accounting | needed only for the guest portal |

**802.1X methods**: EAP-TLS, EAP-TTLS with PAP inside, and PEAP with GTC
inside. PEAP-MSCHAPv2 is not supported — see [802.1X](eap.md). A switch that
terminates EAP itself and asks with CHAP must be set to relay EAP instead.

**MAB** (MAC authentication) is recognised when the device says so
(`Service-Type = Call-Check`), or when the user name is a MAC address and the
password is the same MAC, empty, or absent (CHAP MAC authentication counts
too; a MAC is no secret, so NACo does not check it). The MAC must equal
`Calling-Station-Id`. Every way of writing a MAC is understood —
`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aa.bb.cc.dd.ee.ff`,
`aabb.ccdd.eeff`, `aabb-ccdd-eeff`, `AABB:CCDD:EEFF`, `aabbcc-ddeeff`,
`aabbccddeeff`, in any case. A MAC as user name with any *other* password is
treated as a password login.

**VLANs**: NACo answers with an Access-Accept carrying the policy's VLAN as
`Tunnel-Type = VLAN`, `Tunnel-Medium-Type = IEEE-802`,
`Tunnel-Private-Group-Id = <id>` — understood by every major vendor — plus
the policy's reply attributes, named as in FreeRADIUS' dictionaries
(`Cisco-AVPair`, `Aruba-User-Role`, `Filter-Id`, …). A permit without a VLAN
leaves the client on the port's or SSID's own VLAN on most devices; the
vendor pages note exceptions. For EAP-TTLS and PEAP the Access-Accept also
carries the name NACo verified inside the tunnel as User-Name, so devices
that honour it (hostapd does) show and account the real user instead of
the anonymous outer identity.

**SSID** conditions use the SSID from `Called-Station-Id`
(`<MAC>:<SSID>`), or, when that has none, from `Called-Station-SSID`,
`Aruba-Essid-Name`, `Ruckus-SSID`, `Fortinet-SSID`, `Trapeze-SSID`,
`TP-CAPWAP-SSID` or Cisco's `cisco-wlan-ssid`.

### Message-Authenticator (BlastRADIUS)

Every Access-Request must carry a valid Message-Authenticator attribute
(CVE-2024-3596). EAP always includes it; current firmware of most vendors
includes it for MAB and PAP too — the vendor pages say from which version.
If a device's requests go unanswered and `docker compose logs freeradius`
says the packet has no Message-Authenticator, update the firmware — or, as a
last resort, switch *Require Message-Authenticator* off for that client; the
panel then shows it as **Legacy NAS**.

### Change of Authorization

When a policy, a user, a device or a guest registration changes, NACo
re-evaluates the active sessions and sends an RFC 5176 **Disconnect-Request**
to the sessions whose decision actually changed. The device ends the session,
the client authenticates again and gets the new decision. *Sessions →
Disconnect* does the same by hand and shows whether the device acknowledged.

Vendors accept different attributes in a disconnect, and some refuse one
they do not expect, so the client's device type decides what NACo sends —
always with the values the device itself reported in accounting:

| Device type | Identifies the session with | Event-Timestamp | Message-Authenticator |
|---|---|---|---|
| Standard (RFC 5176) | Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address, NAS-Identifier | yes | yes |
| Cisco IOS-XE / Catalyst 9800 | Acct-Session-Id, Calling-Station-Id, Cisco audit-session-id | yes | yes |
| Cisco Meraki | Calling-Station-Id, NAS-IP-Address, Cisco audit-session-id | — | yes |
| HPE Aruba Networking | Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address, NAS-Identifier | — | yes |
| Juniper | Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address | — | yes |
| Fortinet | User-Name, Calling-Station-Id, NAS-IP-Address | yes | yes |
| Extreme Networks | Calling-Station-Id, NAS-IP-Address | — | yes |
| Ruckus ICX | Calling-Station-Id, NAS-IP-Address | — | — |

An attribute the device did not report is left out. NACo sends disconnects
only — no CoA-Request to re-authenticate or bounce a port — so a wired MAB
device whose VLAN changes keeps its old IP address until it renews it.

### When NACo cannot decide

If NACo is stopped, restarting or failing, FreeRADIUS gives **no answer** —
not a reject — and answers no Status-Server probe either. The device marks
the server dead and applies its own *server dead* action, typically a
critical VLAN; NACo never lets anyone in without a decision. FreeRADIUS
remembers a device for a minute, so for up to a minute it may still answer
the first steps of an EAP exchange; after that everything is silent. The
[pilot](pilot.md#5-when-naco-cannot-be-reached) shows how to test it.

## Troubleshooting

- **No answer at all** — the device's source address is not a RADIUS client
  in NACo (FreeRADIUS logs *unknown client*), the shared secret differs, or
  the packet lacks Message-Authenticator. Check `docker compose logs freeradius`.
- **Rejected** — *Logs* shows the reason for every decision (wrong password,
  unknown user, device blocked, no policy matched, …). Reproduce it in the
  *Simulator*.
- **MAB treated as a password login** — the device sends a password that is
  neither the MAC nor empty; set its MAC-authentication password to the MAC
  (the vendor pages say how).
- **Accepted but wrong VLAN** — the port or SSID must allow dynamic VLANs
  and the VLAN must exist on the device.
- **Disconnect fails** — *Sessions* shows the outcome. A timeout means
  dynamic authorization is off on the device, it does not list the NACo
  host's address, or the port differs; a NAK means the device did not find
  the session — check the client's device type and the shared secret.
