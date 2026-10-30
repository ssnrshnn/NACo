# HPE Aruba Networking

This page covers AOS-CX switches (written from the 10.16 guides),
ArubaOS-Switch (AOS-S 16.11, for example 2930F/M), AOS 8 Mobility
Controllers, Aruba Instant (Instant AOS-8) and AOS 10 access points managed
by Central. For all of them, choose the device type **HPE Aruba Networking
(AOS-CX, AOS-S, AOS 8/10, Instant)**. The configuration comes from HPE's
documentation and has not been run on every model. What every device needs
is in [network devices](../network-devices.md); what to test is at the end
of this page.

## In NACo — what to enter

*RADIUS clients → Add client*:

| Field | Value |
|---|---|
| IP address or network | where the RADIUS packets come from (next table) |
| Shared secret | 16 to 32 characters: AOS-CX accepts at most 32. *Generate* makes 24. |
| Device type | HPE Aruba Networking (AOS-CX, AOS-S, AOS 8/10, Instant) |
| CoA port | leave empty for 3799, the default on AOS-CX, AOS-S and AOS 8 |
| Require Message-Authenticator | on, with the firmware below |

| Platform | RADIUS client in NACo |
|---|---|
| AOS-CX, AOS-S | the switch's RADIUS source address (`ip source-interface radius`) |
| AOS 8 | the managed controller (`ip radius source-interface`); it is the NAS for its APs |
| Instant | the AP network, for example `10.0.20.0/24`: every AP sends from its own address. With `dynamic-radius-proxy`, only the Virtual Controller IP. |
| AOS 10, bridge mode | the AP network (every AP is the NAS), or the DRP IP with Dynamic RADIUS Proxy |
| AOS 10, tunnel or mixed mode | the gateway |

A network can be at most /16 (/48 for IPv6). A client with the exact
address wins over a network that contains it.

**Message-Authenticator.** EAP requests always carry it. Use firmware with
HPE's BlastRADIUS fix (advisory HPESBNW04662), at least these versions in
each release train; on AOS-CX the fix makes MAB requests carry it too.
AOS-CX 10.10.1140, 10.13.1040, 10.14.1010. AOS 8 8.10.0.14, 8.12.0.2.
Instant 8.10.0.14, 8.12.0.4, 8.13.0.1. AOS 10 APs 10.4.1.4, 10.6.0.3,
10.7.1.0; gateways 10.4.1.4, 10.6.0.3. AOS-S is not in the advisory; it
sends Message-Authenticator from 16.11.0025. On older firmware, update. As
a last resort, switch *Require Message-Authenticator* off for that client;
it then shows as **Legacy NAS**.

**Disconnects.** NACo sends Acct-Session-Id, User-Name, Calling-Station-Id,
NAS-IP-Address and NAS-Identifier as the device reported them in accounting,
plus Message-Authenticator, and no Event-Timestamp. The AOS-S `time-window`
setting therefore needs no change. NACo never bounces a port: a wired MAB
device whose VLAN changes keeps its old IP address until its DHCP lease
renews.

**Policies.** The VLAN goes out by ID as the RFC 3580 tunnel attributes.
Aruba attributes go in *Extra RADIUS attributes*
([reply attributes](../policies.md#reply-attributes)). 802.1X clients use
EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC, not PEAP-MSCHAPv2
([802.1X](../eap.md)).

**When NACo cannot decide**, nothing answers and the switch applies its
critical role or VLAN. For up to a minute after NACo stops, FreeRADIUS may
still answer the first steps of an EAP exchange, so wait longer than that
before you test the fallback
([details](../network-devices.md#when-naco-cannot-decide)).

## AOS-CX

```text
radius-server host <naco-ip> key plaintext <shared-secret> vrf default
ip source-interface radius interface vlan<mgmt-vlan> vrf default
aaa group server radius NACO
    server <naco-ip> vrf default
!
aaa authentication port-access dot1x authenticator radius server-group NACO
aaa authentication port-access dot1x authenticator enable
aaa authentication port-access mac-auth
    radius server-group NACO
    enable
!
aaa accounting port-access start-stop interim 15 group NACO
!
radius dyn-authorization enable
radius dyn-authorization client <naco-ip> secret-key plaintext <shared-secret> vrf default
!
port-access role NACO-CRITICAL
    vlan access <critical-vlan>
!
interface 1/1/1-1/1/48
    no shutdown
    no routing
    vlan access <onboarding-vlan>
    aaa authentication port-access client-limit 4
    aaa authentication port-access critical-role NACO-CRITICAL
    aaa authentication port-access dot1x authenticator
        enable
    aaa authentication port-access mac-auth
        enable
```

`<mgmt-vlan>` is the VLAN interface whose address you added in NACo.

- **Client limit.** The default is 1 client per port (range 1–256). Raise it
  for a phone with a PC behind it.
- **MAC authentication.** Every `addr-format` works; the default is
  `aabbccddeeff`. Keep the default `auth-method`, CHAP: NACo counts CHAP MAC
  authentication as MAB and does not check the CHAP value. With
  `auth-method pap` the password must be the same MAC as the user name, so
  do not set a MAC-auth `password`.
- **Server dead.** The critical role applies when NACo does not answer, at
  the first authentication or at re-authentication. To keep clients that
  were already in, see `cached-reauth` / `cached-reauth-period` (default
  3600 s) and the cached-critical role in the Security Guide. Clients in the
  cached-critical role send no accounting.
- **Server tracking** (optional): `tracking enable` on `radius-server host`
  probes with the user `radius-tracking-user`. NACo rejects it, which counts
  as reachable. Test it first (see the pilot list).
- **Disconnects.** AOS-CX requires NAS-IP-Address or NAS-Identifier, a
  session identifier and User-Name; this device type sends them. The default
  `rfc5176-enforcement-mode strict` is fine.
- **Role and VLAN.** When the Accept carries `Aruba-User-Role`, AOS-CX
  ignores the other authorization attributes, including the policy's VLAN.
  Leave the policy's VLAN empty and put the VLAN in the role:

  ```text
  port-access role STAFF
      vlan access <users-vlan>
  ```

- **Guest portal.** It needs Framed-IP-Address in accounting, which the
  guide does not list. The IP client tracker (`client track ip`, globally
  and on the VLAN; 6x00 series only) learns client addresses.
- On 8320, 8400 and 9300, a RADIUS server can be in only one user-defined
  server group.

Reply attributes (FreeRADIUS names): `Aruba-User-Role` (a local role),
`Filter-Id`, `NAS-Filter-Rule`, `Aruba-NAS-Filter-Rule`, `Egress-VLANID`,
`Egress-VLAN-Name`, `Aruba-Captive-Portal-URL`, `Aruba-Port-Auth-Mode`
(`Infrastructure-Mode`, `Client-Mode`, `Multi-Domain-Mode`),
`Aruba-PoE-Priority`. `Aruba-CPPM-Role` is for ClearPass only. Do not use
`Aruba-STP-Admin-Edge-Port`: AOS-CX and FreeRADIUS number it differently.

## ArubaOS-Switch (AOS-S)

```text
radius-server host <naco-ip> key "<shared-secret>"
radius-server host <naco-ip> dyn-authorization
ip source-interface radius vlan <mgmt-vlan>
aaa authentication port-access eap-radius
aaa port-access authenticator 1-48
aaa port-access authenticator active
aaa port-access mac-based 1-48
aaa accounting network start-stop radius
aaa accounting update periodic 15
aaa port-access 1-48 critical-auth data-vlan <critical-vlan>
```

- **802.1X.** Port access defaults to `local`, so `aaa authentication
  port-access eap-radius` is required. Do not use `chap-radius` there.
- **MAC authentication.** Every `addr-format` works; the default is
  `aabbccddeeff`. Keep the method `chap-radius` (the default; there is no
  PAP option): NACo counts it as MAB. `peap-mschapv2` does not work with
  NACo.
- **Clients per port.** `addr-limit` defaults to 1. Without MAC-based VLANs
  in the hardware, the switch rejects clients authorized on a VLAN other
  than the first client's.
- **Server dead.** `critical-auth` takes one data VLAN per port (also
  `voice-vlan` or `user-role`). A client whose re-authentication fails while
  NACo is unreachable is de-authenticated, unless you add `aaa
  authentication port-access eap-radius cached-reauth` and `aaa
  authentication mac-based chap-radius cached-reauth`. `radius-server
  tracking enable` probes with `radius-tracking-user` and allows only
  `dead-time infinite`; test it in the pilot.
- **Disconnects.** `dyn-authorization` on the server lets the switch accept
  them. `show radius host <naco-ip> dyn-authorization` counts refusals, for
  example "Disc-NAKs No Ses. Found".
- **VLAN.** RFC 3580 with a VLAN ID or name, or `Egress-VLANID` /
  `Egress-VLAN-Name`.
- **Guest portal.** Framed-IP-Address is not in AOS-S's accounting
  attributes, so the portal may not learn client addresses from AOS-S.

Reply attributes (vendor HP): `HP-User-Role`, `HP-Port-Client-Limit-Dot1x`,
`HP-Port-Client-Limit-MA`, `HP-Port-Client-Limit-WA`, `HP-Egress-VLANID`,
`HP-Egress-VLAN-Name`, `HP-Captive-Portal-URL`, and the standard
`Filter-Id`, `NAS-Filter-Rule`, `Egress-VLANID`, `Egress-VLAN-Name`.

## AOS 8 Mobility Controllers

Configure client authentication on or under `/md`; RADIUS under `/mm` is
only for managing the Conductor.

```text
aaa authentication-server radius NACO
    host <naco-ip>
    key <shared-secret>
    called-station-id type ap-macaddr delimiter colon include-ssid enable
    enable
aaa server-group NACO-SG
    auth-server NACO
ip radius source-interface vlan <mgmt-vlan>
aaa rfc-3576-server <naco-ip>
    key <shared-secret>
aaa authentication mac NACO-MAC
    delimiter colon
    case lower
aaa authentication dot1x NACO-DOT1X
aaa profile NACO-AAA
    authentication-dot1x NACO-DOT1X
    dot1x-server-group NACO-SG
    dot1x-default-role authenticated
    authentication-mac NACO-MAC
    mac-server-group NACO-SG
    mac-default-role authenticated
    radius-accounting NACO-SG
    radius-interim-accounting
    rfc-3576-server <naco-ip>
aaa timers stats-timeout 10
wlan ssid-profile <ssid-profile>
    essid <SSID>
wlan virtual-ap <vap>
    aaa-profile NACO-AAA
    ssid-profile <ssid-profile>
    vlan <users-vlan>
```

Set the SSID profile's `opmode` to the WPA2- or WPA3-Enterprise mode you use.

- **Default roles.** A new AAA profile puts 802.1X and MAC clients in the
  `guest` role, so an Accept with only a VLAN lands there. Set
  `authenticated` as above, or return `Aruba-User-Role`.
- **Accounting.** Interim updates are off until you add
  `radius-interim-accounting`. `aaa timers stats-timeout` sets the interval
  (5–60 minutes, default 10).
- **MAC authentication** is sent with Service-Type Call-Check, which NACo
  recognises as MAB. Leave `service-type-framed-user` off. Every delimiter
  and case works.
- **SSID.** By default Called-Station-Id is the Conductor's MAC with no
  SSID; `include-ssid enable` adds it. NACo reads the SSID after a colon
  behind the MAC, or from `Aruba-Essid-Name`.
- **VLAN.** All three RFC 3580 attributes must be present.
  `Aruba-User-Vlan` and `Aruba-Named-User-Vlan` override any earlier VLAN
  assignment (note the spelling `Vlan`).
- **Reply attributes:** `Aruba-User-Role` (the role must exist on the
  controller), `Aruba-User-Vlan`, `Aruba-Named-User-Vlan`; `Filter-Id` and
  `Class` can drive server-derivation rules.
- **Disconnects.** The controller finds the session by user name, framed
  IP, Calling-Station-Id or accounting session ID, so NACo's Disconnect
  matches. Supported for campus APs in tunnel or decrypt-tunnel mode and
  remote APs in tunnel or split-tunnel mode.
- **Server dead.** `aaa timers dead-time` needs two or more servers; with
  NACo alone it is never marked out of service. No critical role for WLANs
  was found, so while NACo cannot decide, new clients cannot connect.

## Aruba Instant

```text
wlan auth-server NACO
    ip <naco-ip>
    key <shared-secret>
    port 1812
    acctport 1813
    rfc3576
wlan ssid-profile <ssid-profile>
    essid <SSID>
    type employee
    auth-server NACO
    mac-authentication
    l2-auth-failthrough
    radius-accounting
    radius-interim-accounting-interval 10
    called-station-id include-ssid
    vlan <users-vlan>
commit apply
```

Set the SSID profile's `opmode` to the enterprise mode you use.

- **Who talks to NACo.** Every IAP sends from its own address: add the AP
  network. To send everything from the Virtual Controller instead, add
  `dynamic-radius-proxy`, set `nas-ip <vc-ip>` on the auth server, and add
  the VC IP in NACo.
- **Disconnects** need `rfc3576` (off by default). The CoA port is set on
  the VC with `ip radius rfc-3576-server udp-port`. From 8.13.0.0,
  `msg-auth-required` makes the AP discard disconnects without
  Message-Authenticator; NACo's carry it.
- **MAC authentication** is off by default. `l2-auth-failthrough` runs
  802.1X when MAC authentication fails. MAC authentication comes first, so a
  device that a MAB policy permits never reaches 802.1X. Every MAC format
  works. Leave `service-type-framed-user` off.
- **Accounting** is per SSID; `radius-interim-accounting-interval` is 0–60
  minutes, and 0 means no interim updates.
- **SSID.** Called-Station-Id is the IAP's MAC; `include-ssid` appends the
  SSID. NACo needs a colon between the two.
- **Server dead.** `auth-survivability` requires ClearPass and does not work
  with NACo. `deadtime` needs two or more servers. With
  `radius-reauth-interval`, a client whose re-authentication fails is
  disconnected.

## AOS 10 and Central

In Central: SSID wizard → *Security* → *Enterprise* → *Primary Server*.
Add NACo as a RADIUS server:

- IP address, ports 1812 and 1813, the shared secret.
- *NAS IP Address*: the VC IP for AP-based cluster deployments; the AP IP
  for Cloud AP based Campus WLAN deployments.
- *Dynamic Authorization* on. Also add NACo as a *Dynamic Authorization*
  server (its own server type) with the same secret.
- *Service Type Framed User*: leave 802.1X, MAC and Captive Portal unticked.
- *RFC 5997 status query* may be on: NACo answers Status-Server only while
  it can decide.
- *DRP IP*, mask, VLAN and gateway if you use Dynamic RADIUS Proxy.

On the SSID: *MAC authentication* (any delimiter and case) with *MAC
Authentication Fail-Through* for 802.1X after it; *Called Station ID* with
*Include SSID*; *Accounting* → *Use separate servers*, NACo, *Accounting
Interval* 1–60 minutes (0 turns interim updates off). With a *Reauth
Interval*, a client whose re-authentication fails is disconnected.

In **bridge mode** every AP is the NAS. When a client roams, the old AP
sends a Stop and the new AP a Start with a new Acct-Session-Id. In **tunnel
or mixed mode** the gateway proxies authentication and accounting. No
critical role was found for APs, and authentication survivability is
documented only for branch gateways: expect new clients to fail while NACo
cannot decide.

## Switch logins (TACACS+)

In NACo, add the switch under *TACACS+ clients* with its source address
and a key of at least 16 characters, and give the admins' group a
*device-admin privilege* ([TACACS+](../tacacs.md)). NACo answers the shell
service with `priv-lvl=<group's level>` and checks every command against
the group's command set. Keep a local account: the switch uses it only when
NACo does not answer, never after NACo refuses.

AOS-CX:

```text
tacacs-server host <naco-ip> key plaintext <tacacs-key> vrf default
ip source-interface tacacs interface vlan<mgmt-vlan> vrf default
aaa group server tacacs NACO-TAC
    server <naco-ip> vrf default
aaa authentication login default group NACO-TAC local
aaa authorization commands default group NACO-TAC local
aaa accounting all-mgmt default start-stop group NACO-TAC
```

Privilege 15 gives the *administrators* group, 1 *operators*, and 2–14 the
local user group named after the level; anything else fails the login.
(*auditors*, level 19, is outside NACo's 1–15.) If NACo refuses a command,
`local` is not tried. Command authorization applies to the CLI only, not
to the WebUI or REST.

AOS-S:

```text
tacacs-server host <naco-ip> key <tacacs-key>
ip source-interface tacacs vlan <mgmt-vlan>
aaa authentication ssh login tacacs local
aaa authentication ssh enable tacacs local
aaa authentication console login tacacs local
aaa authentication console enable tacacs local
aaa authentication login privilege-mode
aaa authorization commands tacacs
aaa accounting exec start-stop tacacs
aaa accounting commands stop-only tacacs
```

With `privilege-mode` the level comes from NACo: 15 is manager
(read/write), 14 and lower operator (read-only). On the console the second
method must be `local`. AOS-S sends no network accounting over TACACS+.

## Verify — show commands

AOS-CX (`aaa troubleshoot test-server` exists from 10.15 and shows the
returned attributes):

```text
show radius-server detail
show aaa server-groups
aaa troubleshoot test-server radius-server <naco-ip> vrf default auth-type pap user <test-user> password plaintext <password>
show aaa troubleshoot test-server status run <id>
show port-access clients detail
show aaa authentication port-access interface 1/1/1 client-status
show radius dyn-authorization
show port-access cached-clients
```

AOS-S:

```text
show radius host <naco-ip>
show radius host <naco-ip> dyn-authorization
show port-access clients
show port-access mac-based clients 1 detailed
show authentication
show ip source-interface
```

AOS 8 (test with PAP; NACo does not do MSCHAPv2):

```text
aaa test-server pap NACO <test-user> <password> verbose
show aaa rfc-3576-server statistics
show aaa debug vlan user mac <client-mac>
```

Instant:

```text
aaa test-server NACO username <test-user> password <password> auth-type pap
```

For AOS 10, use Central and NACo's *Logs* and *Sessions*.

## Check in the pilot

HPE's documentation does not confirm these points. Test them:

- **AOS-CX tracking**: whether the probes carry Message-Authenticator. If
  not, NACo drops them and the switch marks NACo dead while it works;
  `radius-tracking-user` must appear in *Logs*.
- **AOS-CX disconnects**: the accounting table marks User-Name as not sent,
  though the sample record has it, and AOS-CX refuses a Disconnect without
  it. Check that *Sessions → Disconnect* is acknowledged.
- **AOS-CX MAC-auth with PAP**: that the default password is the MAC in the
  user-name format (only if you set `auth-method pap`).
- **AOS-CX role and VLAN**: whether `aaa authentication port-access
  radius-override enable` lets the RADIUS VLAN override the role's.
- **AOS-CX guest portal**: whether `client track ip` puts Framed-IP-Address
  in accounting.
- **AOS-CX 4100i, 6000, 6100, 8xxx**: the commands come from the 6300/6400
  guide.
- **AOS-S Message-Authenticator**: whether 16.11.0025 and later send it
  without a setting. If MAB gets no answer and the FreeRADIUS log says the
  packet has no Message-Authenticator, it does not.
- **AOS-S disconnects**: HPE's example identifies a session by User-Name,
  NAS-Port-Id, NAS-IP-Address and Calling-Station-Id; NACo sends no
  NAS-Port-Id. Check that disconnects are acknowledged.
- **AOS-S tracking**: whether probes carry Message-Authenticator, and
  whether a reject counts as reachable.
- **AOS-S and AOS 8 guest portal**: whether accounting carries
  Framed-IP-Address.
- **AOS 8 and Instant SSID**: the character between MAC and SSID in
  Called-Station-Id. If *Logs* shows no SSID, check whether the device sends
  `Aruba-Essid-Name`; on Instant, `include-ssid` takes a delimiter.
- **AOS 8 fallback**: whether your release has a critical role for WLANs.
- **Instant and AOS 10 MAB**: Service-Type and password are not documented.
  Check that *Logs* shows MAC requests as MAB, not as a password login.
- **Instant and AOS 10 disconnects**: which attributes the AP matches. Test
  a client on an AP that is not the VC, and after a roam check that
  *Sessions* shows the new AP and a disconnect reaches it.
- **Instant VLAN and role**: the RFC 3580 attributes, `Aruba-User-Vlan`,
  `Aruba-Named-User-Vlan` and `Aruba-User-Role` are assumed to work as on
  AOS 8.
- **AOS 10 survivability**: whether it works with a server other than
  ClearPass.
- **TACACS+ on AOS-CX**: the shell service is assumed. WebUI and REST
  accounting show `service=https-server`; if *Logs → TACACS+* refuses a
  WebUI login with "no attributes for service https-server", the switch
  asks for that service.
- **TACACS+ on AOS-S**: the service it asks for is not documented. Check
  that a privilege-15 user gets manager access.

## References

- AOS-CX 10.16 Security Guide:
  [5420/6200/6300/6400](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/security_5420-6200-6300-6400.pdf),
  [4100i/6000/6100](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/security_4100i-6000-6100.pdf),
  [8100/8360](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/security_8100-8360.pdf);
  [CLI Guide](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/cli_6300-6400.pdf),
  [IP Routing Guide](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/ip_route_6300-6400-8100-83xx-9300-10000.pdf)
- [AOS-S 16.11 Access Security Guide (2930M/F)](https://www.arubanetworks.com/techdocs/AOS-Switch/16.11/Aruba%202930MF%20Access%20Security%20Guide%20for%20AOS-S%2016.11.pdf),
  [AOS-S 16.11 release notes](https://arubanetworking.hpe.com/techdocs/AOS-Switch-RN/Content/16.11RN/WC/Enhancements.htm)
- AOS 8: [RADIUS server](https://arubanetworking.hpe.com/techdocs/ArubaOS/AOS_8x_WebHelp/Content/arubaos-solutions/auth-servers/conf-radi-serv.htm),
  [RFC 3576 server](https://arubanetworking.hpe.com/techdocs/ArubaOS/AOS_8x_WebHelp/Content/arubaos-solutions/auth-servers/conf-rfc-radi-serv.htm),
  [VLAN assignment](https://arubanetworking.hpe.com/techdocs/ArubaOS/AOS_8x_WebHelp/Content/arubaos-solutions/nwk-params/unde-vlan-assi.htm),
  [AAA profile](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/aaa-profile.htm)
- Instant: [auth server](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/wlan-auth-serv.htm),
  [SSID profile](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/wlan-ssid-prof.htm),
  [dynamic RADIUS proxy](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/dyna-rad-prox.htm)
- AOS 10: [RADIUS server](https://arubanetworking.hpe.com/techdocs/central/latest/content/aos10x/cfg/bridge-mod-dep/cfg-external-auth-rad.htm),
  [dynamic authorization](https://arubanetworking.hpe.com/techdocs/central/latest/content/aos10x/cfg/bridge-mod-dep/cfg-external-auth-dyn-auth.htm),
  [enterprise SSID](https://arubanetworking.hpe.com/techdocs/central/latest/content/aos10x/cfg/bridge-mod-dep/cfg-security-bridge-ent.htm),
  [RADIUS accounting](https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/auth/radius-acct/)
- [HPE advisory HPESBNW04662 (BlastRADIUS)](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04662.txt),
  [FreeRADIUS 3.2 dictionaries](https://github.com/FreeRADIUS/freeradius-server/tree/v3.2.x/share)
