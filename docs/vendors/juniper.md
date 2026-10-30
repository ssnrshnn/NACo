# Juniper

This page covers EX switches running Junos with the ELS command line
(EX2300, EX3400, EX4100, EX4400 on current Junos), EX switches and access
points managed by Juniper Mist, and administrator logins to Junos over
TACACS+. Choose the device type **Juniper** for EX switches, whether you
configure them on the command line or through Mist. For Mist access points
choose **Standard (RFC 5176)**: they discard a disconnect request without an
Event-Timestamp, and the Juniper type leaves it out.

Read [network devices](../network-devices.md) for what NACo expects from
every device, and run [a pilot](../pilot.md) before you enforce anything.

## In NACo — what to enter

*RADIUS clients → Add client*:

| Field | EX switch (CLI or Mist) | Mist access points |
|---|---|---|
| Name | e.g. `ex-access-01` | e.g. `mist-aps-site1` |
| IP address or network | the switch's `source-address` | the access points' network, e.g. `10.0.20.0/24` |
| Shared secret | 16+ characters, the same as on the switch | the same as on the WLAN |
| Device type | Juniper | Standard (RFC 5176) |
| CoA port | 3799 | the port of the WLAN's CoA/DM server (NACo default 3799) |
| Require Message-Authenticator | on | on |

Every Mist access point sends RADIUS from its own address, so one network
entry covers them all (at most a /16). An entry for an exact address wins
over a network that contains it. Disconnects go to the access point that
holds the session, with the network entry's secret.

What the disconnect request carries, each value exactly as the device
reported it in accounting and only when it did:

- **Juniper** — Acct-Session-Id, User-Name, Calling-Station-Id,
  NAS-IP-Address and Message-Authenticator. No Event-Timestamp: Junos
  answers NAK to a Disconnect-Request that carries anything besides NAS and
  session identification.
- **Standard** — the same plus NAS-Identifier and Event-Timestamp. Mist
  access points drop a request whose timestamp is too far from their clock,
  so the NACo host needs correct time (NTP).

NACo sends only Disconnect-Requests, never a CoA-Request, so it cannot
bounce a port. A wired MAC-authenticated device (a printer) that NACo moves
to another VLAN keeps its old IP address until its DHCP lease renews. Short
leases on the onboarding VLAN shorten that wait.

Users authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## EX switches (Junos)

```text
set access radius-server <naco-ip> port 1812
set access radius-server <naco-ip> secret "<shared-secret>"
set access radius-server <naco-ip> source-address <switch-ip>
set access radius-server <naco-ip> dynamic-request-port 3799
set access radius-server <naco-ip> message-authenticator
set access profile NACO authentication-order radius
set access profile NACO radius authentication-server <naco-ip>
set access profile NACO radius accounting-server <naco-ip>
set access profile NACO accounting order radius
set access profile NACO accounting update-interval 15
set protocols dot1x authenticator authentication-profile-name NACO
set vlans USERS vlan-id <users-vlan>
set vlans ONBOARDING vlan-id <onboarding-vlan>
set vlans CRITICAL vlan-id <critical-vlan>
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members ONBOARDING
set protocols dot1x authenticator interface ge-0/0/1 supplicant multiple
set protocols dot1x authenticator interface ge-0/0/1 mac-radius authentication-protocol pap
set protocols dot1x authenticator interface ge-0/0/1 server-fail vlan-name CRITICAL
```

- `source-address` — Juniper recommends it; it is the address for NACo.
- `message-authenticator` — the switch requires it in NACo's answers,
  which always carry it. Juniper advises setting this explicitly.
- `mac-radius authentication-protocol pap` — **required.** Junos uses
  EAP-MD5 for MAC RADIUS by default, which NACo does not support.
- `supplicant multiple` — every device on the port gets its own session.
- The switch sends three EAPOL requests, then falls back to MAC RADIUS.
  On ports for devices that never do 802.1X, `mac-radius restrict` skips
  802.1X.

### Accounting

The switch sends Start, Interim and Stop records; `update-interval` is in
minutes. NACo needs an update at least every 360 minutes, because it closes
sessions that have had no accounting for 24 hours.

The switch sends Framed-IP-Address only when its DHCP snooping table has a
binding for the client. The [guest portal](../guest-portal.md) needs it, so
enable DHCP snooping (`dhcp-security`) on the access VLANs if you use the
portal. That configuration is not covered here.

### Disconnect (CoA)

The switch listens on UDP 3799 and accepts disconnect requests only from a
configured `access radius-server`, with that server's secret. NACo sends
them from `<naco-ip>`, so nothing else is needed. Do not use
`radius-disconnect-port` or `radius-disconnect`: those statements configure
L2TP, not 802.1X.

### When NACo cannot be reached

When NACo cannot decide (host down, NACo stopped, restarting or failing),
FreeRADIUS does not answer at all, not even Status-Server probes, and the
switch applies its `server-fail` action:

| `server-fail` | Effect |
|---|---|
| `deny` (default) | no access for devices that authenticate now |
| `vlan-name CRITICAL` | they are put in the critical VLAN, which must exist |
| `use-cache` | devices already authenticated keep access when they re-authenticate; new ones are denied |
| `permit` | everyone gets in — no NAC during the outage |

Server-fail mostly takes effect at re-authentication. With `vlan-name`, a
device that re-authenticates while NACo is down moves to the critical VLAN,
even if it was in the users VLAN. With `use-cache` it stays. Choose per
site. Server-fail is not supported for EAP-TLS clients on trunk ports; for
phones there is a separate `server-fail-voip`.

To test, stop NACo (`docker compose stop naco`) and wait a minute before
you connect a device: FreeRADIUS keeps answering the first steps of an EAP
exchange for up to a minute, then goes silent.

### Notes

- **MAC format.** MAC RADIUS sends the MAC as User-Name and User-Password,
  lowercase without separators (`00040ffdacfe`). Calling-Station-Id looks
  like `00-03-47-e1-ba-b9`. NACo accepts both. Do not set a global
  `mac-radius password`: with a password other than the MAC, NACo treats
  the request as a password login, not MAB.
- **Message-Authenticator.** Junos includes it in every 802.1X and MAC
  RADIUS request, so leave *Require Message-Authenticator* on.
- **VLAN.** NACo sends the policy's VLAN as a number. The switch must have
  a VLAN with that `vlan-id`. Dynamic VLANs do not work on trunk ports,
  layer 3 interfaces or Junos Evolved layer 2.
- **Reply attributes** (policy editor names):

  | Attribute | Use |
  |---|---|
  | `Filter-Id` | name of a firewall filter configured on the switch |
  | `Juniper-Switching-Filter` | filter terms, e.g. `match destination-ip 192.168.1.0/31 action allow` |
  | `Juniper-VoIP-Vlan` | voice VLAN (spelled `Vlan`) |
  | `Juniper-CWA-Redirect` | central web authentication redirect; Juniper calls it `Juniper-CWA-Redirect-URL` |
  | `Juniper-AV-Pair` | e.g. `Ip-Mac-Session-Binding`, `Supplicant-Mode-Single`, `Retain-Mac-Aged-Session` |

## Juniper Mist

### Mist-managed EX switches

Mist pushes Junos configuration, so everything above applies. In the switch
template:

- **Authentication Servers → RADIUS** — NACo as authentication server
  (1812) and accounting server (1813), **Interim Interval** (seconds, e.g.
  `900`), **Dynamic Request Port** 3799.
- Mist offers *Source Address* only for Mist Auth. For NACo, add
  `set access radius-server <naco-ip> source-address <switch-ip>` under
  *Additional CLI Commands*, or enter the address the switch really sends
  from in NACo.
- **Port profile → Use dot1x authentication** — *MAC authentication* on,
  **Authentication Protocol: PAP**. List the NACo VLANs under *Dynamic
  VLAN*. Set the critical VLAN as *Server Fail Network*. Leave *Bypass
  authentication when server is down* off: it means no NAC during an
  outage. The reauthentication interval defaults to 65000 seconds.
- Mist advises against steering VLANs with Filter-Id, and against dynamic
  port profiles together with RADIUS or MAB.

### Mist access points

Configure RADIUS on the WLAN:

- **Security** — WPA2/WPA3-Enterprise for 802.1X, or *MAC address
  authentication by RADIUS lookup* (any security type other than
  Enterprise).
- **Authentication and accounting servers** — `<naco-ip>`, ports 1812 and
  1813, the shared secret. Leave NAS-IP unset: each access point then sends
  its own address.
- **Accounting interim interval** — set it, e.g. `600` seconds. The default
  `0` means "use the value from the Access-Accept", and NACo sends none
  unless a policy adds `Acct-Interim-Interval`.
- **CoA/DM Server** — `<naco-ip>`, the shared secret, the default port.
- **VLAN** — *Dynamic*, so the access point applies the policy's VLAN.

The access points include Message-Authenticator in every request and send
Framed-IP-Address in accounting: the Start record may lack it, and an
Interim-Update brings it, so the guest portal works. MAC authentication
uses Service-Type Call-Check, which NACo treats as MAB. Called-Station-Id
is `XX-XX-XX-XX-XX-XX:SSID`, so policies can match the SSID.

Reply attributes Mist applies: `Filter-Id`, `Airespace-ACL-Name`,
`Aruba-User-Role` (a role for WxLAN policies), `Airespace-Interface-Name`
(a VLAN by name) and `Cisco-AVPair` (`url-redirect=…`, or
`psk-mode=ascii` with `psk=…`).

## Switch logins (TACACS+)

```text
set system tacplus-server <naco-ip> secret "<tacacs-key>"
set system tacplus-server <naco-ip> source-address <switch-ip>
set system authentication-order [ tacplus password ]
set system login user remote class read-only
set system login user naco-super class super-user
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus
```

In NACo:

1. *TACACS+ clients* — the switch's `source-address` and `<tacacs-key>`.
2. *Groups* — give each admin group a **Device-admin privilege**. Junos
   ignores the level, but without one NACo refuses the login.
3. In the same group, **TACACS+ attributes for other vendors**, for
   example:

   ```text
   junos-exec: local-user-name=naco-super
   ```

After login Junos asks for the service `junos-exec`. NACo answers with the
group's `junos-exec` lines, and the user gets the class of the local
template user named in `local-user-name` (`naco-super` above). Junos also
reads `allow-commands`, `deny-commands`, `allow-configuration`,
`deny-configuration`, their `-regexps` forms, and `user-permissions`.
Junos asks once, after login, and enforces these itself, so NACo command
sets do not apply to Junos. Use `allow-commands` / `deny-commands` lines
instead.

A group with no `junos-exec` line is refused. By default Junos ignores the
refusal and logs the user in with the class of the `remote` template
(read-only above), or of a local account with the same name. Without
either, the login fails. With `set system tacplus-options
strict-authorization` (Junos 13.3 and later), Junos denies the login
instead. Turn that on only once every admin group has a `junos-exec` line.

With `password` after `tacplus`, Junos uses local accounts when NACo does
not answer. Keep a local super-user account with a password. Test every
change from a second session before you close the first.
*Logs → TACACS+* shows logins and, with the accounting lines above, the
commands.

On Mist-managed switches TACACS+ is a switch template option. Users not
defined locally map to `remote` there too.

## Verify

```text
show dot1x interface brief
show dot1x interface ge-0/0/1.0 detail
show network-access aaa statistics radius
show network-access aaa statistics accounting
show network-access aaa statistics dynamic-requests
```

`detail` shows the supplicant, the authentication method, the VLAN and
any dynamic filter the switch applied. `dynamic-requests` counts the
disconnect requests it accepted and refused. In NACo, *Logs* shows each
decision and *Sessions* the result of each disconnect.

## Check in the pilot

- **Disconnect on EX.** Whether the switch accepts the Juniper type's
  request, or counts Message-Authenticator as an attribute it does not
  allow. Check *Sessions* and `dynamic-requests`. Junos error causes:
  503 session not found, 403 NAS identification mismatch, 401 unsupported
  attribute.
- **Old releases.** Community reports say `authentication-protocol pap`
  is missing on very old releases (e.g. 12.3R9). The release that added
  `message-authenticator` is not known.
- **MAC formats.** Juniper's accounting example is old; check the formats
  in *Logs*. The Service-Type of MAC RADIUS requests is not documented.
- **Mist source address.** Whether Mist keeps the `source-address` line
  added under *Additional CLI Commands*.
- **Mist access points.** Confirm in *Sessions* that Standard-type
  disconnects are accepted; if not, check the NACo host's clock. According
  to third-party docs generated from the Mist API, the WLAN's timestamp
  check can be turned off (`coa_servers.disable_event_timestamp_check`).
  Not documented: the CoA/DM port, what the access points do when NACo
  does not answer, and the notation of MAC user names. Mist Edge as a
  RADIUS proxy was not looked at.
- **TACACS+.** Whether Junos logs in with ASCII or PAP (NACo supports
  both). Whether a password NACo rejects falls through to the local
  password: Juniper's documentation contradicts itself. Test from a second
  session.
- **Mist TACACS+.** Whether Mist templates let you define the local
  template users that `local-user-name` refers to.

## References

- [RADIUS server configuration (EX)](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/radius-server-configuration-ex-series-cli.html)
- [802.1X authentication on switches — CoA, VLANs, attributes](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/802-1x-authentication-switching-devices.html)
- [MAC RADIUS authentication](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/mac-radius-authentication-switching-devices.html)
- [MAC RADIUS authentication protocol](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/task/authentication-protocol-mac-radius.html)
- [802.1X and MAC RADIUS accounting](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/802-1x-and-mac-radius-accounting.html)
- [`interface` (802.1X) statement](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/ref/statement/interface-802-1x.html)
- [`show network-access aaa statistics`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-network-access-aaa-statistics.html)
- [TACACS+ authentication](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/user-access-tacacs-authentication.html)
  and [`tacplus-options`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/tacplus-options-edit-system.html)
- L2TP statements, not for 802.1X: [`radius-disconnect`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/radius-disconnect-edit-access.html),
  [`radius-disconnect-port`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/radius-disconnect-port-edit-access.html)
- [Mist switch configuration options](https://www.juniper.net/documentation/us/en/software/mist/mist-wired/topics/topic-map/switch-config-options.html)
- [Mist RADIUS attributes](https://www.juniper.net/documentation/us/en/software/mist/mist-wireless/topics/topic-map/radius-attributes.html),
  [CoA](https://www.juniper.net/documentation/us/en/software/mist/mist-wireless/topics/concept/coa.html),
  [MAC authentication](https://www.juniper.net/documentation/us/en/software/mist/mist-wireless/topics/concept/mac-authentication.html)
- [Mist and Junos: BlastRADIUS](https://www.mist.com/documentation/radius-protocol-vulnerability-blast-radius/)
