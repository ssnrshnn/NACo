# Network devices

Every switch, access point and wireless controller that asks NACo questions
is a **RADIUS client**. Add it under *RADIUS clients* with:

- **IP address** — the address its RADIUS packets come *from* (often a
  management or loopback interface; set the device's RADIUS source interface
  so it is predictable).
- **Shared secret** — at least 16 random characters; the *Generate* button
  makes one. The same secret goes on the device.
- **CoA port** — where the device listens for disconnect requests, normally 3799.
- **Require Message-Authenticator** — leave on (see below).

NACo picks a new client up at its first request; a changed secret or a
disabled client takes effect within a minute.

Bringing NACo into a running network? Start with [a pilot](pilot.md): one
port in monitor mode, then the behaviour when NACo cannot be reached, then
enforcement.

## What every device needs

| | |
|---|---|
| Authentication | NACo host, UDP **1812** — 802.1X (EAP), MAB and PAP all use this port |
| Accounting | NACo host, UDP **1813**, start/stop **and interim updates** — sessions, CoA and the guest portal depend on it |
| Dynamic authorization (CoA) | allow NACo's host address, same shared secret, UDP 3799 |
| Calling-Station-Id | the client's MAC address (default on most devices) |
| Framed-IP-Address in accounting | needed only for the guest portal (IP device tracking on switches) |

NACo answers with an Access-Accept carrying the VLAN as
`Tunnel-Type = VLAN`, `Tunnel-Medium-Type = IEEE-802`,
`Tunnel-Private-Group-Id = <id>` — understood by every major vendor — plus
any reply attributes of the matching policy. A permit without a VLAN leaves
the port on its configured VLAN.

### Message-Authenticator (BlastRADIUS)

Every Access-Request must carry a valid Message-Authenticator attribute
(CVE-2024-3596). EAP always includes it; current firmware includes it for MAB
and PAP too. If a device's requests go unanswered and
`docker compose logs freeradius` says the packet has no
Message-Authenticator, update the firmware — or, as a last resort, switch
*Require Message-Authenticator* off for that client; the panel then shows it
as **Legacy NAS**.

### Change of Authorization

When a policy, a user, a device or a guest registration changes, NACo
re-evaluates the active sessions and sends an RFC 5176 **Disconnect-Request**
to the sessions whose decision actually changed. The device ends the session,
the client authenticates again and gets the new decision. Disconnects come
from the NACo host's address. *Sessions → Disconnect* does the same by hand.

## Cisco IOS-XE (Catalyst)

```text
radius server NACO
 address ipv4 10.0.0.10 auth-port 1812 acct-port 1813
 key <shared-secret>
!
aaa new-model
aaa group server radius NACO-GROUP
 server name NACO
 ip radius source-interface Vlan10
aaa authentication dot1x default group NACO-GROUP
aaa authorization network default group NACO-GROUP
aaa accounting dot1x default start-stop group NACO-GROUP
aaa accounting update newinfo periodic 1440
!
aaa server radius dynamic-author
 client 10.0.0.10 server-key <shared-secret>
 port 3799
 auth-type any
!
radius-server attribute 6 on-for-login-auth
radius-server attribute 8 include-in-access-req
radius-server attribute 25 access-request include
radius-server vsa send authentication
radius-server vsa send accounting
dot1x system-auth-control
!
device-tracking policy NACO-TRACK
 tracking enable
!
interface range GigabitEthernet1/0/1 - 48
 switchport mode access
 switchport access vlan 99
 device-tracking attach-policy NACO-TRACK
 authentication host-mode multi-auth
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 authentication periodic
 authentication timer reauthenticate server
 mab
 dot1x pae authenticator
 dot1x timeout tx-period 10
 spanning-tree portfast
```

`device-tracking` lets the switch report the client's IP address
(`Framed-IP-Address`) — needed only for the guest portal. Useful reply
attributes: `Cisco-AVPair` (a list: `["url-redirect-acl=GUEST", "url-redirect=http://nac.example.com/portal"]`),
`Filter-Id` (a named ACL), `Session-Timeout`.

When NACo cannot be reached the switch decides; give it a critical VLAN
(see [the pilot](pilot.md#5-when-naco-cannot-be-reached)):

```text
radius server NACO
 automate-tester username naco-probe probe-on
radius-server dead-criteria time 5 tries 3
radius-server deadtime 2
!
interface range GigabitEthernet1/0/1 - 48
 authentication event server dead action authorize vlan <critical>
 authentication event server dead action authorize voice
 authentication event server alive action reinitialize
```

Switch logins over TACACS+: see [tacacs.md](tacacs.md).

## Cisco Catalyst 9800 / AireOS WLC

*Configuration → Security → AAA*: add NACo as a RADIUS server (auth 1812,
acct 1813, *Support for CoA* on, CoA port 3799), put it in a server group,
and use it for the WLAN's 802.1X and MAC filtering methods and for
accounting. Enable *AAA Override* on the policy profile so VLAN and
`Cisco-AVPair` attributes are applied, and *RADIUS NAC* for central web
authentication.

## Aruba AOS-CX

```text
radius-server host 10.0.0.10 key plaintext <shared-secret> vrf default
aaa group server radius NACO
    server 10.0.0.10 vrf default
aaa authentication port-access dot1x authenticator
    radius server-group NACO
    enable
aaa authentication port-access mac-auth
    radius server-group NACO
    enable
aaa accounting port-access start-stop interim 15 group NACO
radius dyn-authorization enable
radius dyn-authorization client 10.0.0.10 secret-key plaintext <shared-secret> vrf default
!
interface 1/1/1-1/1/48
    aaa authentication port-access dot1x authenticator
        enable
    aaa authentication port-access mac-auth
        enable
```

Reply attributes: `Aruba-User-Role` places the client in a locally defined
role; the VLAN comes from the policy.

## ArubaOS-Switch / HPE ProCurve

```text
radius-server host 10.0.0.10 key "<shared-secret>"
radius-server host 10.0.0.10 dyn-authorization
radius-server host 10.0.0.10 time-window 0
aaa accounting network start-stop radius
aaa accounting update periodic 15
aaa authentication port-access eap-radius
aaa port-access authenticator 1-48
aaa port-access authenticator active
aaa port-access mac-based 1-48
```

## Juniper EX (Junos)

```text
set access radius-server 10.0.0.10 secret "<shared-secret>"
set access radius-server 10.0.0.10 source-address 10.0.0.2
set access profile NACO authentication-order radius
set access profile NACO radius authentication-server 10.0.0.10
set access profile NACO radius accounting-server 10.0.0.10
set access profile NACO accounting order radius
set access profile NACO accounting update-interval 15
set access radius-disconnect-port 3799
set access radius-disconnect 10.0.0.10 secret "<shared-secret>"
set protocols dot1x authenticator authentication-profile-name NACO
set protocols dot1x authenticator interface ge-0/0/1.0 supplicant multiple
set protocols dot1x authenticator interface ge-0/0/1.0 mac-radius
```

## MikroTik RouterOS 7 (wireless)

```text
/radius add service=wireless address=10.0.0.10 secret="<shared-secret>" \
    require-message-auth=yes-for-request-resp
/radius incoming set accept=yes port=3799
```

Then set the security profile of the interface to WPA2/WPA3-Enterprise with
RADIUS authentication and accounting.

## Ubiquiti UniFi

*Settings → Profiles → RADIUS*: authentication server `10.0.0.10:1812`,
accounting server `10.0.0.10:1813`, *Interim update* on. Use the profile for
WPA-Enterprise SSIDs and, on switch ports, for 802.1X control with MAC
authentication fallback. UniFi applies the VLAN attributes; it does not
accept disconnect requests on every model.

## Other vendors

Extreme, Ruckus, Fortinet FortiSwitch/FortiAP, Huawei, Arista and others work
the same way: RADIUS authentication 1812, accounting 1813 with interim
updates, dynamic authorization from the NACo host, and the standard VLAN
attributes. Vendor-specific attributes are named as in FreeRADIUS'
dictionaries (`Aruba-User-Role`, `Ruckus-User-Groups`,
`Fortinet-Group-Name`, `Extreme-Netlogin-Vlan`, `Huawei-Exec-Privilege`, …).

## Troubleshooting

- **No answer at all** — the device's source address is not a RADIUS client
  in NACo (FreeRADIUS logs *unknown client*), the shared secret differs, or
  the packet lacks Message-Authenticator. Check `docker compose logs freeradius`.
- **Rejected** — *Logs* shows the reason for every decision (wrong password,
  unknown user, device blocked, no policy matched, …). Reproduce it in the
  *Simulator*.
- **Accepted but wrong VLAN** — the port or SSID must allow dynamic VLANs
  and the VLAN must exist on the device.
- **A reply attribute does not arrive** — its name must exist in
  FreeRADIUS' dictionaries; misspelled names are dropped (FreeRADIUS logs a
  warning).
- **Disconnect fails** — dynamic authorization is off on the device, it does
  not list the NACo host's address, or the secret differs. *Sessions* shows
  the result of each disconnect.
