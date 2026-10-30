# MikroTik

This page covers MikroTik RouterOS 7.15 and later (checked against the 7.26
manual) in three roles:

- **wired**: `/interface dot1x server`, 802.1X and MAC authentication on
  switch and router ports;
- **wifi**: the `wifi` package (`/interface wifi`; the wifi-qcom,
  wifi-qcom-be, wifi-mediatek and wifi-qcom-ac packages, called `wifiwave2`
  before 7.13);
- **wireless**: the legacy `wireless` package (`/interface wireless`), the
  only option on MIPS and 802.11a/b/g/n devices.

Choose the device type **Standard (RFC 5176)**. RouterOS has no TACACS+,
and NACo cannot authenticate router logins (see the end of this page).

## In NACo — what to enter

*RADIUS clients → Add client*:

- **IP address or network** — the router's `src-address` (below). With
  CAPsMAN, the CAPsMAN controller is the RADIUS client, so it is one
  address. Stand-alone APs each send RADIUS themselves: cover them with a
  network.
- **Shared secret** — 16 characters or more.
- **Device type** — Standard (RFC 5176).
- **CoA port** — 3799, once you set the router to listen there (below).
  RouterOS listens on 1700 by default; if you keep that, enter 1700 here.
- **Require Message-Authenticator** — leave on. From 7.15 (and 6.49.18)
  RouterOS puts it in every request except accounting. On older firmware,
  upgrade, or switch it off for that client (*Legacy NAS*).
- **Accounting** — turn on interim updates, every 360 minutes or less. NACo
  closes a session that has had no accounting for 24 hours.

The Standard type's Disconnect-Request carries Acct-Session-Id, User-Name,
Calling-Station-Id, NAS-IP-Address and NAS-Identifier as the router
reported them, plus Event-Timestamp and Message-Authenticator. NACo sends
only Disconnect-Requests, never a CoA-Request. Users authenticate with
EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC; PEAP-MSCHAPv2 is not
supported ([802.1X and certificates](../eap.md)).

## RADIUS client and Disconnect

For all three roles:

```text
/radius
add address=<naco-ip> secret="<shared-secret>" service=dot1x,wireless \
    src-address=<nas-mgmt-ip> comment=NACo
/radius incoming
set accept=yes port=3799
```

- `service=wireless` covers both the `wifi` and the legacy `wireless`
  package; `dot1x` covers the wired server.
- Set `src-address`. Without it a router with several addresses sends from
  the outgoing interface.
- From 7.15, `require-message-auth=yes-for-request-resp` is the default: the
  router drops replies without Message-Authenticator. NACo's replies always
  carry it. The argument does not exist before 7.15.
- Do not use `protocol=radsec`; NACo does not offer RadSec.
- `/radius incoming` is off by default and listens on port 1700. If the
  router filters its input chain, allow UDP 3799 from `<naco-ip>`.
- With CAPsMAN, the controller receives the Disconnect-Requests.

## Wired: `/interface dot1x server`

> **Lock-out warning.** A dot1x server on the port you manage the router
> through cuts you off. Turning on `vlan-filtering` on a bridge without
> management access in the bridge VLAN table does too. Work from the serial
> console, or in Safe Mode (Ctrl+X in the CLI, *Safe Mode* in WinBox), which
> undoes the changes if your session drops.

Bridge VLAN filtering must already be on, with `<users-vlan>`,
`<onboarding-vlan>` and `<critical-vlan>` on the uplink. Then:

```text
/interface bridge port set [find interface=<access-port>] edge=yes
/interface dot1x server
add interface=<access-port> auth-types=dot1x,mac-auth \
    accounting=yes interim-update=5m reauth-period=1h \
    server-fail-vlan-id=<critical-vlan> comment=NACo
```

- **The port is port-based.** After one client authenticates, traffic from
  every host on the port is accepted. To limit the port to the authenticated
  MAC, add the reply attribute `Mikrotik-Switching-Filter = "action allow,
  src-mac-address none action drop"`. It works only on switch chips with
  rule support (Marvell Prestera, QCA8337, Atheros8327/8316), not on
  CRS1xx/2xx.
- 802.1X comes first. MAC authentication starts only after three
  `retrans-timeout` periods: about 90 seconds by default.
- The bridge must run (R/M)STP, or EAP frames are not accepted. Use
  `edge=yes` on access ports.
- **MAC address**: `radius-mac-format` sets User-Name and password. The
  default is `XX:XX:XX:XX:XX:XX`; every value works with NACo.
- **VLAN**: NACo's VLAN sets the port's untagged VLAN. This needs bridge
  `vlan-filtering=yes`; only devices with hardware-offloaded VLAN filtering
  do it in the switch chip. Send numeric VLAN IDs.
- **Accounting**: on by default, but `interim-update` defaults to 0 (none).
  Set it as above.
- **Disconnect**: MikroTik does not document it for the dot1x server.
  Assume it does not work. `reauth-period` makes NACo's changes take effect
  at the next re-authentication; for MAC authentication it re-checks the
  last seen MAC.
- **When NACo cannot be reached**: FreeRADIUS does not answer at all.
  `server-fail-vlan-id` (7.2 and later, needs `vlan-filtering`) puts the
  port in the critical VLAN once the request times out. Without it, the
  client simply gets no access. `reject-vlan-id` applies to an
  Access-Reject only.

## Wireless: `wifi` package

```text
/interface wifi aaa
add name=naco called-format=II-II-II-II-II-II:S interim-update=5m
/interface wifi security
add name=naco-eap authentication-types=wpa2-eap,wpa3-eap eap-accounting=yes
/interface wifi
set [find default-name=wifi1] configuration.ssid=<ssid> security=naco-eap aaa=naco
```

For an SSID that admits devices without 802.1X by MAC:

```text
/interface wifi access-list
add interface=<mab-ssid-interface> action=query-radius radius-accounting=yes
```

- **802.1X**: the AP relays EAP to NACo.
- **MAC authentication**: the `query-radius` rule sends the MAC as user
  name with an empty password (the `password-format` default). NACo takes
  that as MAB, so leave it as it is. If NACo permits, the AP goes on with
  the interface's normal security (PSK or EAP).
- **Do not add `query-radius` to an 802.1X SSID** unless NACo permits MAB
  for every device there. The MAC check runs before EAP.
- **Formats**: `username-format` and `calling-format` default to
  `AA:AA:AA:AA:AA:AA`. Keep them a plain MAC; any separator and case works.
  `called-format` defaults to `II-II-II-II-II-II:S`, which gives
  `AA-BB-CC-DD-EE-FF:<SSID>`. Do not change it to `S`, `N` or a format
  without the MAC.
- **Accounting**: `eap-accounting` is off by default. For MAC
  authentication, set `radius-accounting=yes` on the access-list rule.
  Interim updates default to 5 minutes.
- **Disconnect**: supported since 7.2.
- **VLAN**: MikroTik does not document which attribute sets the client VLAN
  on `wifi`. Users report that `Mikrotik-Wireless-VLANID` with
  `Mikrotik-Wireless-VLANIDtype = 0` works on a cAP ax and RFC 3580 does
  not. Add both as reply attributes to the policy, next to its VLAN.
  Devices without VLAN offloading (HaLow, wifi-qcom-ac) refuse clients that
  get a VLAN; wifi-qcom-ac needs a `pvid` first. Since 7.11, wifi
  interfaces join the bridge VLAN on their own.
- **When NACo cannot be reached**: there is no fallback. New clients cannot
  connect.

## Wireless: legacy `wireless` package

```text
/interface wireless security-profiles
add name=naco mode=dynamic-keys authentication-types=wpa2-eap eap-methods=passthrough \
    radius-eap-accounting=yes interim-update=5m radius-called-format=mac:ssid
add name=naco-mab mode=none radius-mac-authentication=yes radius-mac-accounting=yes \
    interim-update=5m
/interface wireless set <wlan-iface> security-profile=naco
```

- No WPA3: it exists only in the `wifi` package.
- **MAC authentication**: User-Name follows `radius-mac-format` (default
  `XX:XX:XX:XX:XX:XX`); every value works with NACo. The password is empty
  by default, which NACo takes as MAB, so leave it as it is. With
  `radius-mac-authentication=yes` on an EAP profile, MAC authentication
  runs first and EAP follows.
- **Accounting**: `radius-eap-accounting` and `radius-mac-accounting` are
  off by default, and `interim-update` is 0. Set them as above.
  `Acct-Interim-Interval` in NACo's reply overrides the interval.
- **SSID**: `radius-called-format=mac:ssid` (the default) sends
  `XX-XX-XX-XX-XX-XX:SSID`. The values `mac` and `ssid` break NACo's SSID
  conditions.
- **VLAN**: per-client VLANs come from `Mikrotik-Wireless-VLANID` and
  `Mikrotik-Wireless-VLANIDtype = 0`. Add both to the policy. RFC 3580 is
  not documented for wireless.
- **Disconnect**: through CAPsMAN from 7.19. Stand-alone APs: not
  documented.
- **When NACo cannot be reached**: there is no fallback.

## Reply attributes

| FreeRADIUS name | Use |
|---|---|
| `Mikrotik-Wireless-VLANID` | client VLAN on wireless |
| `Mikrotik-Wireless-VLANIDtype` | VLAN tag type: 0 = 802.1q, 1 = 802.1ad |
| `Mikrotik-Switching-Filter` | switch rules on a dot1x port |
| `Mikrotik-Wireless-Forward` | 0 = do not forward the client's frames to other wireless clients |
| `Mikrotik-Wireless-PSK` | per-client PSK in a MAC-authentication accept (legacy wireless) |
| `Mikrotik-Wireless-Comment` | comment in the registration table |
| `Session-Timeout` | wireless: disconnect after this many seconds |
| `Acct-Interim-Interval` | accounting interval (legacy wireless) |

`Filter-Id` applies only to PPP and HotSpot, not to dot1x or wireless.

## Router logins

RouterOS has no TACACS+. Its logins over RADIUS (`service=login` and `/user
aaa set use-radius=yes`) use MS-CHAPv2, which NACo does not support. NACo
therefore cannot authenticate RouterOS logins. Keep local accounts.

## Verify

```text
/system logging add topics=radius,debug
/system logging add topics=dot1x,debug
/radius monitor 0
/radius incoming monitor
/interface dot1x server state print
/interface dot1x server active print
/interface bridge vlan print detail
/interface wifi registration-table print detail
/interface wireless registration-table print detail
/log print where topics~"radius"
```

`/radius monitor` counts requests, accepts, rejects, timeouts and bad
replies. `/radius incoming monitor` counts Disconnect results (acks and
naks). `/interface dot1x server active print` shows the user name, MAC,
VLAN and `auth-info` of each wired session.

Then check in NACo:

1. *Logs* shows one MAB and one 802.1X decision. On wireless, the SSID is
   filled in.
2. The client is in the right VLAN (`vlan-id` in the active sessions or the
   registration table).
3. *Sessions* shows the session with Start and interim updates.
4. *Sessions → Disconnect* returns ACK on `wifi`.
5. Stop NACo (`docker compose stop naco`) and wait a minute: FreeRADIUS
   keeps answering the first steps of an EAP exchange for up to a minute.
   Then connect a wired client: `auth-info` reads `dot1x (server fail
   vlan)` or `mac-auth (server fail vlan)`. Start NACo again.

## Check in the pilot

- **Disconnect on dot1x ports**: not documented. Try *Sessions →
  Disconnect* and watch `/radius incoming monitor`. If it NAKs, rely on
  `reauth-period`.
- **Disconnect on `wifi` and CAPsMAN**: MikroTik does not say which
  attributes it uses to find the session. Check that NACo's request is
  ACKed. Stand-alone legacy APs are not documented at all.
- **Wired MAC password**: what the dot1x server sends as password with the
  default `mac-auth-mode=mac-as-username` is not documented (probably
  nothing). NACo accepts no password, an empty one, or the MAC. If *Logs*
  shows wired MAB as a rejected password login, set
  `mac-auth-mode=mac-as-username-and-password`.
- **VLAN on `wifi`**: only users report that `Mikrotik-Wireless-VLANID`
  works, and others report failures (wifi-qcom 7.23.1 with PEAP,
  wifi-qcom-ac). Test it on your hardware.
- **Client IP for the guest portal**: Framed-IP-Address is not documented.
  The dot1x server most likely sends none. Legacy wireless reports the
  "last seen IP" since 6.44; its attribute is not named. Check *Sessions*
  before you use the [guest portal](../guest-portal.md).
- **Outages on wired ports**: what happens at `reauth-period` while NACo
  cannot decide, and when a port leaves the server-fail VLAN afterwards.
- **Outages on wireless**: whether a cached MAC-authentication reply
  (`aaa.mac-caching`, `radius-mac-caching`) is used while NACo is silent.
- **Timers**: RouterOS resends after `timeout` (1100 ms by default). It
  documents no dead-server marking, no retry count and no failover order
  between `/radius` entries.
- **VLAN names**: not documented. Send numeric IDs.

## References

- [RADIUS client and `/radius incoming`](https://manual.mikrotik.com/docs/authentication-authorization-accounting/radius/)
- [Dot1X server](https://manual.mikrotik.com/docs/authentication-authorization-accounting/dot1x/)
- [WiFi (`wifi` package)](https://manual.mikrotik.com/docs/wireless/wifi/)
- [Wireless interface (legacy `wireless`)](https://manual.mikrotik.com/docs/wireless/abgn/wireless-interface)
- [Enterprise wireless security](https://manual.mikrotik.com/docs/wireless/user-guides/enterprise-wireless-security-user)
- [User AAA (logins over RADIUS)](https://manual.mikrotik.com/docs/authentication-authorization-accounting/user/)
- [Bridge VLAN table](https://manual.mikrotik.com/docs/bridging-and-switching/user-guides/bridge-vlan-table)
- RouterOS changelogs: `https://upgrade.mikrotik.com/routeros/<version>/CHANGELOG`
  (for example [7.15](https://upgrade.mikrotik.com/routeros/7.15/CHANGELOG))
