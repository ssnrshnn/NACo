# Ruckus

This page covers Ruckus ICX switches on FastIron 09.0.10 and 10.0.x
(checked against the 10.0.20 guides), Ruckus wireless on SmartZone and vSZ
6.1 and 7.x and on Unleashed 200.x, and RUCKUS One in brief. Choose the
device type **Ruckus ICX** for ICX switches, and **Standard (RFC 5176)** for
SmartZone, Unleashed and RUCKUS One. Read [network devices](../network-devices.md)
and [the pilot](../pilot.md) first; this page adds what is specific to Ruckus.

## In NACo — what to enter

*RADIUS clients → Add client*:

| | ICX switch | SmartZone / vSZ | Unleashed |
|---|---|---|---|
| IP address or network | the address of `management source-interface … protocol radius` | proxy mode: the management address of each controller node | a network that covers every AP that can become master |
| Shared secret | 16 characters or more; the ICX takes at most 64 (128 from 10.0.20b_cd1), without space, `#`, `{` or `}` | 16 characters or more | 16 characters or more |
| Device type | Ruckus ICX | Standard (RFC 5176) | Standard (RFC 5176) |
| CoA port | 3799 | 3799 | 3799 |

- **Ruckus ICX** device type: the Disconnect-Request carries only
  Calling-Station-Id and NAS-IP-Address, as the switch reported them in
  accounting, with no Event-Timestamp or Message-Authenticator. These are
  the two attributes Ruckus documents; it warns that other attributes may
  get a NAK.
- **Standard** device type: Acct-Session-Id, User-Name, Calling-Station-Id,
  NAS-IP-Address and NAS-Identifier as the controller reported them, plus
  Event-Timestamp and Message-Authenticator.
- **Require Message-Authenticator**: leave it on. 802.1X requests always
  carry the attribute. For MAC authentication Ruckus documents nothing, and
  a third-party report says ICX MAB requests lack it (there is no command to
  add it). If MAB requests get no answer and `docker compose logs freeradius`
  reports a missing Message-Authenticator, switch it off for that client
  (*Legacy NAS*).
- NACo sends only Disconnect-Requests, never a CoA-Request.
- **Accounting**: turn on interim updates, every 360 minutes or less. NACo
  closes a session that has had no accounting for 24 hours.
  Framed-IP-Address matters only for the [guest portal](../guest-portal.md).
- The *Generate* button makes secrets of letters and digits that fit every
  limit on this page.

Users authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## ICX switches

### RADIUS, accounting and Disconnect

```text
radius-server host <naco-ip> auth-port 1812 acct-port 1813 default key <shared-secret> dot1x mac-auth
management source-interface ve <mgmt-ve> protocol radius
aaa authentication dot1x default radius
aaa accounting dot1x default start-stop radius
aaa accounting mac-auth default start-stop radius
radius-server accounting interim-updates
radius-server accounting interim-interval 15
aaa authorization coa enable
radius-client coa host <naco-ip> key <shared-secret>
```

- Put the host and the key **on the same line**, or the ICX does not use
  the server for 802.1X or MAC authentication.
- `management source-interface` exists from 09.0.00. Without it the switch
  sends from its lowest-numbered address. In NACo, enter the address of
  this interface.
- `aaa authentication dot1x default radius` covers 802.1X and MAC
  authentication.
- Interim updates are off by default. The interval is in minutes (5–1440).
- The ICX admits a client only after its Accounting-Start is answered or
  times out, so a slow NACo delays admission.
- Disconnect needs both CoA commands; packets from other hosts are dropped.
  The port is UDP 3799 (`radius-client coa port` changes it).

### 802.1X and MAC authentication on a port

```text
vlan <auth-default-vlan> name AUTH-DEFAULT
exit
vlan <critical-vlan> name CRITICAL
exit
vlan <users-vlan> name USERS
exit
authentication
auth-default-vlan <auth-default-vlan>
critical-vlan <critical-vlan>
dot1x enable
dot1x enable ethernet 1/1/48
dot1x port-control auto ethernet 1/1/48
mac-authentication enable
mac-authentication enable ethernet 1/1/48
auth-timeout-action critical-vlan
exit
```

- **A permit without a VLAN puts the client in the auth-default VLAN**, not
  in the port's own VLAN. The auth-default VLAN is required, and its member
  ports cannot use 802.1X. Give every NACo permit for ICX ports a VLAN.
- 802.1X comes first, then MAC authentication. After an 802.1X *reject*,
  MAC authentication is tried only with `dot1x macauth-override`.
- By default a port has one untagged VLAN and at most two sessions. A second
  client that NACo puts in another VLAN is blocked; `auth-mode
  multiple-untagged` allows it.
- **A new VLAN or ACL reaches a session only when the session is cleared.**
  Re-authentication keeps the old one. NACo's Disconnect clears the session
  and the client authenticates again. A MAC-authenticated device then keeps
  its old IP address until its DHCP lease renews.
- Periodic re-authentication is off by default (`re-authentication`, every
  3600 s); a Session-Timeout from NACo overrides the period.
- `auth-timeout-action` takes effect only on ports with authentication
  enabled. Configure it last, and again after such a change.
- Not possible on LAG, mirror, static-ACL or Q-in-Q ports.
- ICX has no monitor mode like Cisco's `authentication open`. Start with one
  port and a test device.

### When NACo cannot be reached

When NACo cannot decide (host down, NACo stopped, restarting or failing),
FreeRADIUS does not answer at all. The ICX sends Status-Server probes by
default. Those go unanswered too, so the switch marks NACo dead at once.
Each unanswered request also triggers the timeout action, so the critical
VLAN works either way:

- The first client on a port goes to the critical VLAN. In the default
  single-untagged mode, a **new client on a port that already has a session
  is blocked**, not put in the critical VLAN.
- A session that re-authenticates while NACo is silent keeps its VLAN and
  ACL.
- Clients in the critical VLAN are retried every 300 s (`authentication
  reauth-timeout`).
- Timers: `radius-server timeout` (1–15 s, default 3) and `radius-server
  retransmit` (1–5).
- Always configure `auth-timeout-action`. Ruckus documents the default in
  two different ways.

### MAC address, VLAN and reply attributes

- User-Name and password are the MAC, by default `xxxxxxxxxxxx` in lower
  case. Every `mac-authentication password-format` choice works with NACo.
  Calling-Station-Id is `00-00-00-23-19-C0`; NACo compares normalised MACs.
- **Do not use `mac-authentication password-override`.** The MAC stays the
  user name, NACo sees a password login and rejects it.
- NACo sends the VLAN as a number (untagged). The ICX also takes names and
  `U:`/`T:` forms. If the VLAN does not exist, the ICX creates it. Create
  the VLANs yourself and carry them on the uplink. Dynamic VLANs are not
  saved to the running-config.

Useful reply attributes (FreeRADIUS names):

| Attribute | Use |
|---|---|
| `Filter-Id` | apply an existing ACL: `ip.<acl>.in`, `ip.<acl>.out`, `ip6.<acl>.in` |
| `Foundry-MAC-Authent-needs-802.1x` | whether a client that passed MAC authentication must also pass 802.1X (0 or 1) |
| `Foundry-802.1x-Valid-Lookup` | whether the MAC record is also valid for 802.1X |
| `Foundry-Voice-Phone-Config` | voice phone settings |
| `Foundry-Access-List` | ACL by vendor attribute |
| `Session-Timeout`, `Termination-Action`, `Idle-Timeout`, `Class` | standard |

The inline ACL rules `Foundry-NAS-Ipv4-Filter-Rule` and `-Ipv6-` are not in
FreeRADIUS' dictionary, so NACo cannot send them. A `User-Name` in the
Accept replaces the name the switch shows and sends in accounting.

## SmartZone and vSZ

SmartZone has two AAA modes. Use **proxy mode for authentication and
accounting**: the controller sends all RADIUS from its management address,
and Disconnect works only in this mode. In non-proxy mode every AP sends
RADIUS itself (a network client in NACo covers them), but do not expect
Disconnect: Ruckus lists UDP 3799 only towards the controller.

1. *Services & Profiles → Authentication → Proxy (SZ Authenticator) →
   Create*: name `NACo-Auth`, service protocol RADIUS, primary server
   `<naco-ip>`, port 1812, the shared secret.
2. *Services & Profiles → Accounting → Proxy → Create*: `NACo-Acct`,
   `<naco-ip>`, port 1813, the shared secret.
3. *Wireless LANs → Create*, two WLANs, authentication type *Standard
   usage*:
   - method *802.1X EAP*, WPA2 or WPA3 Enterprise, for users;
   - method *MAC Address*, open or PSK, for devices without 802.1X.

   On both: authentication service `NACo-Auth`, accounting service
   `NACo-Acct`, and *Use controller as proxy* ticked for both.
4. On both WLANs: *Advanced → Access VLAN → Enable Dynamic VLAN*; turn on
   *Single Session ID Accounting* so a roaming client keeps its
   Acct-Session-Id; set interim updates to 10–15 minutes.

Notes:

- Do not use *802.1X EAP & MAC*: both must pass, MAC first, so there is no
  fallback from 802.1X to MAB on one SSID.
- **MAC address**: every format SmartZone offers works with NACo. Leave the
  password at the default (the device MAC). With *Use user defined text as
  authentication password*, NACo sees a password login and rejects it.
- **SSID**: keep *RADIUS Options → Called Station ID* at `WLAN_BSSID` (the
  default) or `AP_MAC`. It sends `2C-AB-46-A3-46-A2:Secure`. NACo also reads
  `Ruckus-SSID` when Called-Station-Id holds no SSID.
- **Roles**: SmartZone 6.x and later map user roles on `Filter-Id`
  (*Services & Profiles → Authentication → <service> → User Role Mapping*;
  exact match, at most 16 mappings). Return `Filter-Id` in the NACo policy.
- **VLAN**: send numeric IDs. A user role can carry a VLAN too.
- **Disconnect**: UDP 3799 to the controller, not configurable.
- **When NACo cannot be reached**: WLANs have no critical VLAN. The
  controller marks NACo dead after its health-check timers, and new clients
  fail to connect. Only a secondary RADIUS server helps. Connected clients stay
  until they must authenticate again: at the WLAN's session timeout (two
  days by default), at a Session-Timeout from NACo, or when they roam
  without cached keys.

## Unleashed

1. *Services → Authentication Servers → Add* (older releases: *Admin &
   Services → Services → AAA Servers*): type RADIUS, `<naco-ip>`, port 1812,
   the shared secret. Add a second server of type *RADIUS Accounting*, port
   1813.
2. *Wi-Fi → Wi-Fi Networks List → Add*, usage type *Standard*: one WLAN with
   *802.1X EAP* (WPA2/WPA3), one with *MAC Address* (encryption none). As on
   SmartZone, 802.1X plus MAC means both must pass, so use two WLANs.
3. Turn on interim updates on the WLAN.

- RADIUS comes from the **master AP**. When another AP becomes master, the
  address changes, so cover all APs with a network client in NACo.
- Third-party guides show the MAC format `aabbccddeeff` and the MAC as the
  password by default. Do not set a custom MAC-authentication password:
  NACo would see a password login and reject it.
- Called-Station-Id is `BSSID:SSID` by default. To set it back:

  ```text
  enable
  config
  wlan "<wlan-name>"
  called-station-id-type wlan-bssid
  end
  ```

- There is no critical VLAN; only a backup RADIUS server and the retry
  settings.

## RUCKUS One

- *Network Control → Service Catalog → RADIUS Server → Add*: one server of
  type Authentication (1812), one of type Accounting (1813), `<naco-ip>`,
  the shared secret. Use an IP address: an FQDN forces proxy mode. Do not
  use RadSec; NACo does not offer it.
- Use **non-proxy** mode: the APs send RADIUS, and a network client in NACo
  covers them. In proxy mode requests come from Ruckus' cloud, so NACo
  would have to be reachable from the Internet.
- RUCKUS One documents incoming CoA only over RadSec. Do not count on
  *Sessions → Disconnect*.
- User roles map on `Filter-Id`, as on SmartZone.
- There is no critical VLAN. While NACo is silent, new clients cannot
  connect.

## Switch logins (TACACS+) on ICX

```text
username <local-admin> privilege 0 create-password <local-password>
tacacs-server host <naco-ip> auth-port 49 default key <tacacs-key>
management source-interface ve <mgmt-ve> protocol tacacs
aaa authorization exec default tacacs+ none
aaa authentication login default tacacs+ local
aaa authentication enable default tacacs+ local
aaa authentication login privilege-mode
aaa authorization commands 0 default tacacs+ none
aaa accounting exec default start-stop tacacs+
aaa accounting commands 0 default start-stop tacacs+
```

- In NACo: *TACACS+ clients*, with the address of `management
  source-interface … protocol tacacs` and a key of 16 to 32 characters (the
  ICX limit), without space, `#`, `{` or `}`.
- **Never leave out `aaa authorization exec default tacacs+`.** Without it,
  every user who logs in is super-user. From 10.0.10a the switch requires it
  before the `tacacs+` login and enable lines.
- The local user with `privilege 0` is a super-user fallback. The backup
  methods are used only when NACo cannot be reached, not after a reject.
  Test from a second session before you close the first.
- The group's device-admin privilege decides the ICX role: **15 gives
  super-user, 1–14 give port-config** (read-write on ports). ICX read-only
  needs level 0, and NACo's levels are 1–15, so a NACo user cannot be
  read-only through the privilege level.
- With `aaa authorization commands 0`, every command typed over console,
  Telnet or SSH goes to NACo's command set; the web UI does not. `exit`,
  `logout`, `end`, `quit` and `enable` are never sent.

## Verify

On an ICX:

```text
show radius servers
show aaa
show authentication sessions all
show authentication sessions detail ethernet 1/1/48
clear authentication sessions ethernet 1/1/48
```

On SmartZone: *Monitor → Troubleshooting and Diagnostics → Application
Logs*, module **RadiusProxy** at Debug; or *Troubleshooting*, type *Client
Connection*. On Unleashed: *Admin & Services → Administration → Diagnostics
→ Client Troubleshooting*.

Then check in NACo:

1. *Logs* shows one MAB and one 802.1X decision. On wireless, the SSID is
   filled in.
2. The client is in the right VLAN (`VLAN Type : Radius-VLAN` in the ICX's
   session detail).
3. *Sessions* shows the session with Start and interim updates.
4. *Sessions → Disconnect* returns ACK, and the session disappears from the
   device.
5. `show radius servers` reads `active` while NACo is healthy.
6. Stop NACo (`docker compose stop naco`) and wait a minute: FreeRADIUS
   keeps answering the first steps of an EAP exchange for up to a minute.
   Then connect a new device: on ICX it lands in the critical VLAN; on
   wireless it cannot connect. Start NACo again.

## Check in the pilot

- **ICX Disconnect**: whether the switch ACKs NACo's Disconnect-Request.
  Nothing authoritative confirms it. It also needs the switch to report
  NAS-IP-Address in accounting.
- **ICX MAB and Message-Authenticator**: whether MAB requests carry it (a
  third-party report says no). Check `docker compose logs freeradius`.
- **ICX Status-Server**: whether the probes pass NACo's checks.
  `show radius servers` must read `active` while NACo is healthy. If it reads
  dead while 802.1X and MAB work, add `status-server off` to the
  `radius-server host` line (10.0.10c_cd4 and later); the critical VLAN still
  works through per-request timeouts.
- **ICX client IP**: Ruckus sends Framed-IP-Address only on a "router
  image"; whether every 10.x image counts is not known. Check *Sessions* for
  an IP before you use the [guest portal](../guest-portal.md).
- **ICX monitor mode**: the interface command `authentication fail-action
  permit` moves rejected clients to the auth-default VLAN. Whether that
  serves as a pilot mode is not confirmed.
- **ICX TACACS+**: the switch very probably asks for `service=shell`
  (*Logs → TACACS+* shows it). The privilege it puts in its requests is not
  documented, and NACo refuses a request above the group's level, so test a
  group below 15. Whether the switch expands abbreviated commands before it
  sends them is not documented either; check your command-set patterns.
- **ICX read-only**: Ruckus reads a `foundry-privlvl` attribute before the
  privilege level (5 = read-only). A group line `shell: foundry-privlvl=5`
  under *TACACS+ attributes for other vendors* might give read-only. This
  is untested.
- **SmartZone Disconnect**: whether 6.x/7.x ACKs NACo's request. The
  controller probably accepts it only from the address configured as the
  AAA server, so NACo must send from `<naco-ip>`.
- **SmartZone clusters**: whether each node proxies for its own APs. Add
  every node's management address (or a network that covers them).
- **SmartZone and Unleashed MAB**: whether MAC-authentication requests carry
  Message-Authenticator. The SmartZone *Test AAA* button (PAP/CHAP) may lack
  it too.
- **Accounting IP on SmartZone and Unleashed**: Framed-IP-Address is
  documented for ZoneDirector 10.2 only.
- **SmartZone outages**: what connected clients do while NACo is dead.
- **Unleashed**: Disconnect, dynamic VLAN and Filter-Id roles are not
  documented. Test each one before you rely on it. Also check whether the
  management address or the master AP's own address is the source.
- **RUCKUS One**: MAC format, Called-Station-Id, Message-Authenticator and
  Disconnect in non-proxy mode are not documented.
- **VLAN names**: `Ruckus-Vlan-Name` and `Ruckus-User-Groups` are in
  FreeRADIUS' dictionary, but current SmartZone use is not confirmed. Use
  numeric VLANs and `Filter-Id`.

## References

- FastIron 10.0.20 Security Configuration Guide:
  [Flexible authentication globally](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/ConfiguringFlexibleAuthenticationGloballyGUID-B23BDE4D-C58F-44AD-8AE8-1B2FC0D84F4313en-US),
  [Change of Authorization](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/ChangeofAuthorizationGUID-2AA2FE1D-3EC6-44B3-BDEE-21948182C16B6en-US),
  [RADIUS attributes](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/RADIUSAttributesforAuthenticationandAccountingGUID-15CBE7F1-4898-4311-8A4E-28ED2268BD863en-US),
  [Authentication server timeout scenarios](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/AuthenticationServerTimeoutScenariosGUID-6D8AED7C-6FDC-40C9-BD30-C087D7D2BC0B3en-US),
  [Dynamic VLAN assignment](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/ConfiguringtheRADIUSServertoSupportDynamicVLANAssignmentforAuthentication30bGUID-BAE30D0D-89DF-4447-916C-79D7D86D192E10en-US),
  [TACACS+ exec authorization](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-securityguide/$/Configuringexecauthorization_FIGUID-A2449097-2DA4-4CD1-B2DA-C531D7A9058711en-US)
- FastIron 10.0.20 Command Reference:
  [radius-server host](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-commandref/$/radius-serverhostGUID-D14859DB-6BCC-45B6-AAAD-C49F4C9CA3EC13en-US),
  [tacacs-server host](https://docs.ruckusnetworks.com/prod/ruckus-docs/fastiron-10020-commandref/$/tacacs-serverhostGUID-842505F0-E2A2-4F39-BDFF-8676B9AF45E45en-US)
- [SmartZone 7.1.0 Public API Reference](https://docs.ruckuswireless.com/smartzone/7.1.0/sz144-public-api-reference-guide-710.html)
  (WLAN and AAA field descriptions)
- Ruckus KB [000014389](https://support.ruckuswireless.com/articles/000014389)
  (802.1X troubleshooting, RADIUS source addresses),
  [000015415](https://support.ruckuswireless.com/articles/000015415)
  (Filter-Id user role mapping),
  [000004891](https://support.ruckuswireless.com/articles/000004891)
  (Called-Station-Id)
- [SmartZone 5.1.1: creating a WLAN](https://docs.ruckuswireless.com/smartzone/5.1.1/sz100-vsze-administrator-guide/GUID-52C7C338-450C-4C3A-A45B-BD96E88F086B.html)
- [RUCKUS One: adding a RADIUS server](https://docs.cloud.ruckuswireless.com/ruckusone/userguide/GUID-F0DFD674-D2E0-42F8-AA09-CBCBE9E419BF.html)
