# Cisco

This page covers four things:

- Catalyst switches on IOS-XE 17 (802.1X and MAB). Cisco's documents used
  here describe IOS-XE 17.12 to 17.18 on the Catalyst 9300.
- The Catalyst 9800 wireless controller on IOS-XE 17.
- AireOS controllers, in brief.
- Switch logins over TACACS+ on IOS-XE and on NX-OS 10 (Nexus 9000).

In NACo, choose the device type **Cisco IOS-XE / Catalyst 9800** for every
Cisco RADIUS client on this page. Meraki has its own page:
[Cisco Meraki](meraki.md).

## In NACo — what to enter

Under *RADIUS clients → Add client*:

| Field | Catalyst switch | Catalyst 9800 |
|---|---|---|
| IP address or network | the address of the switch's `ip radius source-interface` | the wireless management interface (WMI). An HA SSO pair sends from the WMI and from both redundancy management interfaces (RMI): add all three, or one network that covers them |
| Shared secret | at least 16 characters, the same as `key` and `server-key` on the device | same |
| Device type | Cisco IOS-XE / Catalyst 9800 | same |
| CoA port | leave empty (3799). The configurations below set `port 3799` on the device | same |
| Require Message-Authenticator | on | on |

IOS listens for CoA on port **1700** unless you configure `port 3799`. If
you leave the device at its default, set the CoA port in NACo to 1700.

With this device type, NACo's Disconnect-Request (RFC 5176) carries
Acct-Session-Id, Calling-Station-Id, `Cisco-AVPair` `audit-session-id` (when
the device reported one), Event-Timestamp and Message-Authenticator. Every
value is exactly as the device reported it in accounting. It carries no
User-Name and no NAS-IP-Address. NACo sends only Disconnect-Requests, never
a CoA-Request: no reauthenticate, no port bounce.

## Catalyst switches (IOS-XE 17)

**Use IBNS 2.0** (the `policy-map type control subscriber` style) for new
deployments. It handles each event separately: the server is down for a
new host, the server is down for a host already authorized, the server
is back. It also has critical ACLs and service templates, which IBNS 1.0
lacks. IBNS 1.0 is covered briefly [at the end of this section](#ibns-10).

### Global configuration

```text
aaa new-model
aaa session-id common
!
radius server NACO
 address ipv4 <naco-ip> auth-port 1812 acct-port 1813
 key <shared-secret>
 automate-tester username naco-probe ignore-acct-port probe-on
!
aaa group server radius NACO-GROUP
 server name NACO
 ip radius source-interface <mgmt-if>
!
aaa authentication dot1x default group NACO-GROUP
aaa authorization network default group NACO-GROUP
aaa accounting identity default start-stop group NACO-GROUP
aaa accounting update newinfo periodic 360
!
radius-server dead-criteria time 10 tries 3
radius-server deadtime 5
radius-server attribute 6 on-for-login-auth
radius-server attribute 8 include-in-access-req
radius-server attribute 25 access-request include
radius-server vsa send authentication
radius-server vsa send accounting
!
aaa server radius dynamic-author
 client <naco-ip> server-key <shared-secret>
 port 3799
 auth-type any
!
dot1x system-auth-control
dot1x critical eapol
!
device-tracking policy NACO-TRACK
 tracking enable
 no protocol udp
```

- `ip radius source-interface` in the server group decides the address
  RADIUS packets come from. It takes priority over a global setting. Enter
  that interface's address in NACo.
- `periodic 360` sends an interim update at least every 6 hours. NACo
  closes a session that has had no accounting for 24 hours. After that, a
  Disconnect can no longer reach it.
- `automate-tester … probe-on` probes NACo only while the switch considers
  it dead. `ignore-acct-port` skips the accounting port. NACo rejects the
  probe user. That is expected: any answer, a reject too, marks the server
  alive.
- `deadtime 5`: a dead server returns to service after 5 minutes at the
  latest. A probe that gets an answer brings it back sooner. The default,
  0, puts it straight back.
- `device-tracking` lets the switch learn each client's IP address and
  report it as Framed-IP-Address. Only the [guest portal](../guest-portal.md)
  needs it.

### Ports: 802.1X with MAB fallback

```text
class-map type control subscriber match-all AAA_SVR_DOWN_AUTHD_HOST
 match result-type aaa-timeout
 match authorization-status authorized
class-map type control subscriber match-all AAA_SVR_DOWN_UNAUTHD_HOST
 match result-type aaa-timeout
 match authorization-status unauthorized
class-map type control subscriber match-all DOT1X_FAILED
 match method dot1x
 match result-type method dot1x authoritative
class-map type control subscriber match-all DOT1X_NO_RESP
 match method dot1x
 match result-type method dot1x agent-not-found
class-map type control subscriber match-all MAB_FAILED
 match method mab
 match result-type method mab authoritative
class-map type control subscriber match-any IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_AUTH_VLAN
 match activated-service-template DEFAULT_CRITICAL_VOICE_TEMPLATE
class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_AUTH_VLAN
 match activated-service-template DEFAULT_CRITICAL_VOICE_TEMPLATE
!
service-template CRITICAL_AUTH_VLAN
 vlan <critical-vlan>
!
policy-map type control subscriber NACO-DOT1X-MAB
 event session-started match-all
  10 class always do-until-failure
   10 authenticate using dot1x priority 10
 event authentication-failure match-first
  5 class DOT1X_FAILED do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  10 class AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure
   10 activate service-template CRITICAL_AUTH_VLAN
   20 activate service-template DEFAULT_CRITICAL_VOICE_TEMPLATE
   30 authorize
   40 pause reauthentication
  20 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure
   10 pause reauthentication
   20 authorize
  30 class DOT1X_NO_RESP do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  40 class MAB_FAILED do-until-failure
   10 terminate mab
   20 authentication-restart 60
  60 class always do-until-failure
   10 terminate dot1x
   20 terminate mab
   30 authentication-restart 60
 event agent-found match-all
  10 class always do-until-failure
   10 terminate mab
   20 authenticate using dot1x priority 10
 event aaa-available match-all
  10 class IN_CRITICAL_AUTH do-until-failure
   10 clear-session
  20 class NOT_IN_CRITICAL_AUTH do-until-failure
   10 resume reauthentication
 event inactivity-timeout match-all
  10 class always do-until-failure
   10 clear-session
!
interface range GigabitEthernet1/0/1 - 48
 switchport mode access
 switchport access vlan <onboarding-vlan>
 switchport voice vlan <voice-vlan>
 device-tracking attach-policy NACO-TRACK
 access-session host-mode multi-auth
 access-session closed
 access-session port-control auto
 authentication periodic
 authentication timer reauthenticate server
 mab
 dot1x pae authenticator
 dot1x timeout tx-period 7
 dot1x max-reauth-req 3
 spanning-tree portfast
 service-policy type control subscriber NACO-DOT1X-MAB
```

- **IBNS 2.0 ports are open by default.** Leave out `access-session closed`
  for monitor mode, as in the [pilot](../pilot.md). Add it to enforce.
  Without it, a port only logs decisions and lets every device in.
- `tx-period 7` and `max-reauth-req 3` make a device without 802.1X fall
  back to MAB after about 30 seconds.
- `device-tracking attach-policy` must be on every access port. It cannot
  sit in an interface template.

### When NACo cannot be reached

NACo never lets a device in without a decision. When NACo is stopped,
restarting or failing, the switch gets no answer at all. For up to one
minute after NACo stops, FreeRADIUS still answers the first steps of an
EAP exchange; after that, nothing is answered. The switch marks the server
dead when both conditions are met: 10 seconds since the last valid packet
from the server, and 3 consecutive timeouts. Authentication and accounting
timeouts both count.

While the server is dead:

- a **new host** lands in the critical VLAN (`AAA_SVR_DOWN_UNAUTHD_HOST`);
- an **authorized host** keeps its session, and re-authentication pauses
  (`AAA_SVR_DOWN_AUTHD_HOST`);
- when NACo answers again (`aaa-available`), the switch clears the critical
  sessions so they authenticate again, and resumes re-authentication for
  the others.

The critical VLAN must exist and be active on the switch. Otherwise the
sessions keep retrying and failing. `dot1x critical eapol` sends EAPoL
Success when the port fails open, so the supplicant does not hang. Test it
as in the [pilot](../pilot.md#5-when-naco-cannot-be-reached), and wait more
than a minute after `docker compose stop naco` before you connect the test
device.

### Notes

**MAB.** The switch sends the MAC as User-Name and as password
(`aabbccddeeff`), Service-Type Call-Check, Calling-Station-Id
`AA-BB-CC-DD-EE-FF` and a Message-Authenticator. NACo recognises this as
MAB. Leave `mab request format` at its default. Do not configure
`mab eap`: it makes MAB use EAP-MD5, which NACo does not support.

**VLAN.** NACo sends the policy's VLAN as a numeric ID (RFC 3580). The VLAN
must exist on the switch. NACo does not send VLAN names.

**Change of Authorization.** IOS-XE NAKs a Disconnect unless every session
attribute in it matches the session. NACo uses the values the switch
reported, so they match. A Disconnect ends the session without disabling
the port, and the host authenticates again. A wired MAB device (a printer,
a camera) cannot see that its VLAN changed. It keeps its old IP address
until its DHCP lease renews or someone unplugs it.

**Reply attributes.** Add them to a policy (see [policies](../policies.md#reply-attributes)):

| Purpose | Attribute | Value |
|---|---|---|
| ACL defined on the switch | `Filter-Id` | the ACL number followed by `.in` or `.out` |
| Per-user ACL entries | `Cisco-AVPair` | `ip:inacl#1=permit ip any any` (one entry per value) |
| Re-authentication timer | `Session-Timeout`, with `Termination-Action` = `RADIUS-Request` | seconds; the port needs `authentication timer reauthenticate server` |
| Guest portal redirect | `Cisco-AVPair` | `url-redirect-acl=…`, `url-redirect=…` — see [guest portal](../guest-portal.md) |

NACo does not serve downloadable ACLs. Use `Filter-Id` or
`Cisco-AVPair` `ip:inacl#…` instead.

### IBNS 1.0

A switch that already uses `authentication …` commands on its ports
(IBNS 1.0, as in [network devices](../network-devices.md) and the
[pilot](../pilot.md)) can stay that way. The differences:

- accounting is `aaa accounting dot1x default start-stop group NACO-GROUP`;
- ports are closed unless you add `authentication open` (monitor mode);
- the server-dead actions are `authentication event server dead action
  authorize vlan <critical-vlan>` and `… authorize voice` on the port;
- `show authentication sessions` instead of `show access-session`.

`authentication convert-to new-style` converts a switch to IBNS 2.0. It
cannot be undone.

## Catalyst 9800 wireless controller

```text
aaa new-model
radius server NACO
 address ipv4 <naco-ip> auth-port 1812 acct-port 1813
 key <shared-secret>
 automate-tester username naco-probe probe-on
!
aaa group server radius NACO-GROUP
 server name NACO
!
aaa authentication dot1x NACO-DOT1X group NACO-GROUP
aaa authorization network default group NACO-GROUP
aaa authorization network NACO-MAB group NACO-GROUP
aaa accounting identity NACO-ACCT start-stop group NACO-GROUP
!
radius-server dead-criteria time 5 tries 3
radius-server deadtime 5
radius-server attribute wireless authentication call-station-id ap-macaddress-ssid
radius-server attribute wireless accounting call-station-id ap-macaddress-ssid
!
aaa server radius dynamic-author
 client <naco-ip> server-key <shared-secret>
 port 3799
 auth-type any
!
wlan CORP 1 CORP
 security dot1x authentication-list NACO-DOT1X
 no shutdown
!
wlan DEVICES 2 DEVICES
 mac-filtering NACO-MAB
 no security wpa
 no security wpa wpa2
 no security wpa wpa2 ciphers aes
 no security wpa akm dot1x
 no shutdown
!
wireless profile policy NACO-POLICY
 aaa-override
 accounting-list NACO-ACCT
 vlan <users-vlan>
 no shutdown
!
wireless tag policy NACO-TAG
 wlan CORP policy NACO-POLICY
 wlan DEVICES policy NACO-POLICY
```

Apply the policy tag to the access points (*Configuration > Tags*). In the
GUI, the RADIUS server is under *Configuration > Security > AAA > Servers*,
with *Support for CoA* checked.

- `aaa authorization network default` is required. An 802.1X WLAN has no
  authorization list of its own. Without it, and without `aaa-override` on
  the policy profile, the controller ignores NACo's VLAN.
- `DEVICES` is an open WLAN with MAC filtering (MAB). MAC filtering can
  also be combined with 802.1X or a PSK on one WLAN.
- Add `nac` to the policy profile only for the guest portal redirect.

### When NACo cannot be reached

Cisco documents no critical VLAN for centrally authenticated WLANs. While
NACo cannot decide, new clients cannot connect: the controller blocks their
traffic until authentication succeeds. Clients already connected keep
their session until they re-authenticate or the session times out.

The AAA cache (17.18.1 and later) re-admits clients from a cached
Access-Accept while the server is unreachable. Cisco lists EAP-TLS,
PEAP-MSCHAPv2 and MAB for it. Of NACo's methods, that covers EAP-TLS and
MAB, not EAP-TTLS or PEAP/GTC.

### Notes

**MAB.** The controller sends User-Name `e87f95532012`, Calling-Station-Id
`e8-7f-95-53-20-12`, Service-Type Call-Check and a Message-Authenticator.
Keep the defaults. NACo accepts any MAC notation the controller can be set
to.

**SSID.** With `ap-macaddress-ssid`, Called-Station-Id is the AP's MAC and
the SSID (`d4-ad-bd-a2-8f-20:CORP`), which NACo reads. The controller also
sends `Cisco-AVPair` `cisco-wlan-ssid=…`, which NACo uses when
Called-Station-Id holds no SSID. Do not pick a type that adds text after
the SSID: NACo would read the extra text as part of the SSID.

**VLAN.** NACo sends a numeric VLAN ID. The VLAN must exist on the
controller.

**Change of Authorization.** On a Disconnect, the client associates again.
The controller creates the `audit-session-id` itself; NACo includes it
when the controller reported it in accounting.

**Accounting.** Interim updates are on by default and event-driven: DHCP,
IP address or roaming changes trigger them.

**Reply attributes:**

| Purpose | Attribute | Value |
|---|---|---|
| ACL defined on the controller | `Airespace-ACL-Name` | the ACL name; create the ACL on the controller first |
| Guest portal redirect | `Cisco-AVPair` | `url-redirect-acl=…`, `url-redirect=…`; needs `nac` on the policy profile |

**Message-Authenticator.** Cisco's best-practice guide recommends `send-ma`
and `validate-ma` under `radius server`. See *Check in the pilot* before you
add `validate-ma`.

## AireOS

AireOS 8.10 is the last release train. NACo works with it on a best-effort
basis. Configure the same things as on the 9800: NACo as RADIUS server for
authentication and accounting, with dynamic authorization (RFC 3576)
allowed. Cisco's AireOS-to-9800 mapping guide gives the AireOS form of the
WLAN settings:

```text
config wlan aaa-override enable <wlan-id>
config wlan mac-filtering enable <wlan-id>
```

Set the Call Station ID type (`config radius auth callStationIdType`) so
that Called-Station-Id carries the AP's MAC and the SSID. Add
`config wlan nac radius enable <wlan-id>` only for the guest portal
redirect. Most other AireOS details are unverified; they are listed under
*Check in the pilot*.

## Switch logins (TACACS+)

In NACo, add each device under *TACACS+ clients* with its source address
and its own key (see [TACACS+](../tacacs.md)). NACo answers a shell start
with `priv-lvl=<the group's level>`, plus any `shell:` lines on the group.
It checks every command against the group's command set.

The local fallback account below is used **only when NACo does not
answer**. A reject from NACo (unknown user, wrong password, no
device-admin group) ends the login; it does not fall back. So the console
uses a local-only method list, and a wrong NACo setting cannot lock you out
of it. Test from a second session before you close the first.

### IOS-XE

```text
username <breakglass-user> privilege 15 secret <strong-password>
enable secret <enable-secret>
!
aaa new-model
!
tacacs server NACO
 address ipv4 <naco-ip>
 key <tacacs-key>
!
aaa group server tacacs+ NACO-TAC
 server name NACO
 ip tacacs source-interface <mgmt-if>
!
aaa authentication login default group NACO-TAC local
aaa authentication login CONSOLE local
aaa authentication enable default group NACO-TAC enable
aaa authorization exec default group NACO-TAC local if-authenticated
aaa authorization commands 1 default group NACO-TAC local if-authenticated
aaa authorization commands 15 default group NACO-TAC local if-authenticated
aaa authorization config-commands
aaa accounting exec default start-stop group NACO-TAC
aaa accounting commands 1 default start-stop group NACO-TAC
aaa accounting commands 15 default start-stop group NACO-TAC
!
line con 0
 login authentication CONSOLE
line vty 0 15
 login authentication default
 transport input ssh
```

- Add `ip vrf forwarding <vrf>` to the server group when the source
  interface is in a VRF.
- Keep `aaa authorization config-commands`. Cisco's documents disagree on
  its default.
- AAA authorization is off on the console by default. Leave it off at
  first. Keep an `enable secret`.
- Level-0 commands (`disable`, `enable`, `exit`, `help`, `logout`) are not
  authorized unless you also configure command authorization for level 0.
- Give administrators' NACo group privilege 15. Their session then starts
  in privileged EXEC, and they do not need `enable`.

### NX-OS

```text
feature tacacs+
!
username <breakglass-user> password <strong-password> role network-admin
!
tacacs-server host <naco-ip> key 0 <tacacs-key>
ip tacacs source-interface mgmt0
aaa group server tacacs+ NACO-TAC
  server <naco-ip>
  use-vrf management
!
aaa authentication login default group NACO-TAC
aaa authentication login console local
aaa authentication login error-enable
aaa accounting default group NACO-TAC
```

- NX-OS falls back to local accounts by itself when no server answers, so
  the default list has no `local`. `error-enable` shows a message when it
  does.
- The key can be at most 63 characters (NACo needs at least 16).
- Give the break-glass account a name no NACo user has. A local account
  with the same name gives the remote user its local roles.
- NX-OS uses PAP by default. `aaa authentication login ascii-authentication`
  switches to ASCII. NACo supports both. Do not turn on TACACS+ over TLS:
  NACo does not offer it.
- From 10.6(2)F, user names made only of digits are not supported.
- **Leave command authorization off.** On NX-OS it disables role-based
  access (RBAC) for every user, and Cisco does not document what each
  command request contains. If you turn it on anyway, attach a command set
  to every device-admin group first.

NX-OS grants rights by **role**, not by privilege level. After a login it
asks NACo for the shell's attributes. On the NACo group, set *Device-admin
privilege* 15, and under *TACACS+ attributes for other vendors* add:

```text
shell: shell:roles*"network-admin"
```

The `*` makes the attribute optional, so IOS-XE devices that the same group
logs in to ignore it. With `=` it would be mandatory. For read-only access,
use `network-operator`.

## Verify

```text
! Catalyst switch
show aaa servers
show access-session interface GigabitEthernet1/0/1 details
show running-config | section aaa|radius
show logging process smd reverse
! Catalyst 9800
show wireless profile policy detailed NACO-POLICY | s Interim
! TACACS+ on IOS-XE
test aaa group tacacs+ <user> <password> legacy
show tacacs
debug aaa authorization
debug tacacs
! TACACS+ on NX-OS
show tacacs-server groups
show aaa authorization all
test aaa server tacacs+ <naco-ip> vrf management <user> <password>
test aaa group NACO-TAC <user> <password>
debug tacacs+ all
```

- From 16.3.2, `debug radius` output no longer appears in the log buffer;
  use `show logging process smd`. On a 9800, use *Monitoring > Wireless >
  Clients* and *Troubleshooting > Radioactive Trace*.
- `test aaa group NACO-GROUP <user> <password> new-code` (RADIUS) sends no
  Message-Authenticator, and Cisco calls it deprecated. NACo drops it
  unless the client is marked **Legacy NAS** (*Require
  Message-Authenticator* off). Test with a real 802.1X or MAB device, or
  switch the requirement off for the test only.
- In NACo: *Logs* for every decision, *Sessions* for the result of each
  Disconnect, *Logs → TACACS+* for logins and commands, and
  `docker compose logs freeradius` for requests that get no answer.

## Check in the pilot

Catalyst switches:

- **Disconnect.** Approve or block a test device; *Sessions* must show the
  Disconnect acknowledged. How IOS checks Event-Timestamp is not
  documented, so keep NTP on the switch and the NACo host.
- **Probes.** `naco-probe` must appear in *Logs* while the server is dead.
  If the probes carry no Message-Authenticator (not documented), NACo drops
  them, and the server comes back only after `deadtime`.
- **Critical VLAN template.** Cisco shows only ACLs and SGTs inside a
  `service-template`; check that `vlan <critical-vlan>` is accepted (`?`).
  `DEFAULT_CRITICAL_VOICE_TEMPLATE` is reported as built in, but not in
  official documents. If your switch lacks it, remove the lines that name
  it.
- **Framed-IP-Address** reaches *Sessions* within seconds of the device
  getting an address (guest portal only).
- **`Filter-Id` with an ACL name.** Cisco documents ACL numbers.

Catalyst 9800:

- **CoA port.** Which port *Support for CoA* in the GUI sets (1700 or
  3799); look at `aaa server radius dynamic-author`.
- **Periodic interim accounting** is not documented. A client connected
  for over 24 hours without roaming or an IP change may drop out of
  *Sessions*, and can then not be disconnected. A community report says
  `aaa accounting update … periodic` is accepted.
- **Framed-IP-Address** in the interim updates (guest portal only).
- **WLAN security.** `security dot1x authentication-list` and the defaults
  of a new WLAN (WPA2, 802.1X) are not confirmed; check them in the GUI.
- **Re-authentication while NACo is down**: what happens to a connected
  client.
- **`send-ma` and `validate-ma`**: whether your release has them. Test
  `validate-ma` before you rely on it.
- **TACACS+** should work as on IOS-XE; not verified.

AireOS:

- **CoA.** Where to enable it for NACo's entry (reportedly *Support for
  CoA* under *Security > AAA > RADIUS > Authentication*), and its port
  (1700 or 3799). Whether it acknowledges NACo's Disconnect.
- **Call Station ID type** for `aa-bb-cc-dd-ee-ff:SSID` (reportedly "AP MAC
  Address:SSID"), and the defaults for MAC delimiter and interim updates.
- **Message-Authenticator** in MAC-filtering requests. Cisco's BlastRADIUS
  advisory gives no fix for AireOS. If NACo drops the requests, mark the
  controller Legacy NAS.

TACACS+:

- **IOS-XE `enable`.** Community reports say IOS sends the logged-in user,
  or `$enab15$`. NACo refuses `$enab15$`, and IOS does not then fall back
  to the local enable secret. Privilege 15 on the group avoids `enable`.
- **IOS-XE command expansion** (`sh run` arriving as `show
  running-config`) comes from community posts. Check with `debug aaa
  authorization`.
- **NX-OS role request.** It is assumed to use `service=shell`. If *Logs →
  TACACS+* shows another service refused, add a line for that service.
- **NX-OS role.** Check the role a session gets (usually with `show
  user-account <user>`). Cisco's guide writes `shell:roles=network-admin`
  without quotes; its TAC example uses quotes. Also check whether
  `priv-lvl` changes the role on 10.x, and the role a session gets without
  `shell:roles` (probably the read-only `network-operator`).
- **NX-OS privilege.** Test with a group below privilege 15. NACo refuses a
  request above the group's privilege, and Cisco does not document what
  NX-OS sends there.

## References

- [Catalyst 9300, IOS-XE 17.12: Configuring RADIUS](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/configuring_radius.html)
- [IOS-XE 17: RADIUS Change of Authorization](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-17/sec-usr-aaa-xe-17-book/sec-rad-coa.html)
- [Catalyst 9300, IOS-XE 17.12: Configuring IEEE 802.1x Port-Based Authentication](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/configuring_ieee_802_1x_port_based_authentication.html)
- [ISE Secure Wired Access Prescriptive Deployment Guide](https://community.cisco.com/t5/security-knowledge-base/ise-secure-wired-access-prescriptive-deployment-guide/ta-p/3641515)
- [Configure IBNS 2.0 for Single-Host and Multi-Domain](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-3750-x-series-switches/207193-Configure-IBNS-2-0-for-Single-Host-and-M.html)
- [Understand AAA Dead Detection and Deadtime on IOS XE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/225882-understand-aaa-dead-detection-and.html)
- [Troubleshoot Dot1x on Catalyst 9000 Series Switches](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021x/220919-troubleshoot-dot1x-on-catalyst-9000-seri.html)
- [Catalyst 9800 Configuration Best Practices](https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/guide-c07-743627.html)
- [9800 17.15: RADIUS Call Station Identifier](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_radius-call-station-identifier.html)
- [9800: Understand and Configure AAA Cache](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/225368-understand-and-configure-aaa-cache-for.html)
- [AireOS to Catalyst 9800 Command Reference Mapping Guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/cli-mapping/cli_mapping/cisco-aireos-controller-to-cisco-catalyst-9800-series-wireless-controller-command-reference-mapping-guide.html)
- [Catalyst 9300, IOS-XE 17.18: Configuring TACACS+](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_tacacs_.html)
- [Nexus 9000 NX-OS 10.6: Configuring TACACS+](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/m-configuring-tacacs.html)
- [Nexus 9000 NX-OS 10.6: Configuring AAA](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/m-configuring-aaa.html)
