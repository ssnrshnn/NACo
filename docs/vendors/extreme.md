# Extreme Networks

This page covers Extreme Switch Engine (EXOS) switches, with Network Login
(NetLogin) for 802.1X and MAC authentication, and administrator logins over
TACACS+. It follows the Switch Engine 32.7.1 documentation and was tested
with Switch Engine 33.6.1 (the EXOS VM): 802.1X, MAC authentication, VLANs,
accounting, Disconnect, the service-unavailable VLAN and TACACS+ logins with
command authorization. Choose the device type **Extreme Networks**. ExtremeCloud IQ wireless was not verified; see the
[last section](#extremecloud-iq-wireless--not-verified).

Read [network devices](../network-devices.md) for what NACo expects from
every device, and run [a pilot](../pilot.md) before you enforce anything.

## In NACo — what to enter

*RADIUS clients → Add client*:

| Field | Value |
|---|---|
| Name | e.g. `x465-floor2` |
| IP address or network | the switch's `client-ip` from the RADIUS commands below |
| Shared secret | 16+ characters, the same as `shared-secret` on the switch |
| Device type | Extreme Networks |
| CoA port | 3799 |
| Require Message-Authenticator | on (see below) |

Switch Engine 33.6.1 puts Message-Authenticator in MAC-authentication
requests too, so leave *Require Message-Authenticator* on. The 32.7.1
documentation suggests older releases add it to 802.1X (EAP) requests only:
if MAC authentications go unanswered and `docker compose logs freeradius`
says the packet has no Message-Authenticator, switch the setting off for
that client (the panel then shows it as **Legacy NAS**) or upgrade.

With the Extreme type, a disconnect request carries Calling-Station-Id and
NAS-IP-Address, exactly as the switch reported them in accounting and only
when it did, plus Message-Authenticator. Nothing else is included. Switch
Engine identifies a session by MAC address; it answers *Missing-Attribute*
without NAS-IP-Address and *Invalid-Attribute-Value* for a MAC without
separators. Disconnects need ONEPolicy — see [below](#disconnect-coa).

NACo sends only Disconnect-Requests, never a CoA-Request, so it cannot
bounce a port. A wired MAC-authenticated device (a printer) that NACo moves
to another VLAN keeps its old IP address until its DHCP lease renews.

Users authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## Switch Engine (EXOS)

Create the users, onboarding and critical VLANs on the switch first, with
the VLAN IDs your NACo policies use (`<users-vlan>`, `<onboarding-vlan>`,
`<critical-vlan>`). Commands on the switch refer to VLANs by name.

```text
create vlan "nl-temp"
configure netlogin vlan "nl-temp"
configure radius netlogin primary server <naco-ip> 1812 client-ip <switch-ip> vr VR-Default shared-secret <shared-secret>
configure radius-accounting netlogin primary server <naco-ip> 1813 client-ip <switch-ip> vr VR-Default shared-secret <shared-secret>
enable radius netlogin
enable radius-accounting netlogin
enable netlogin dot1x mac
enable netlogin ports <ports> dot1x mac
configure netlogin ports <ports> mode mac-based-vlans
configure netlogin authentication service-unavailable vlan <critical-vlan-name> ports <ports> untagged
enable netlogin authentication service-unavailable vlan ports <ports>
configure netlogin mac authentication database-order radius
configure radius dynamic-authorization 1 server <naco-ip> client-ip <switch-ip> vr VR-Default shared-secret <shared-secret>
enable radius dynamic-authorization
```

- `configure netlogin vlan` — Network Login can be enabled only once it
  has a VLAN of its own.
- `netlogin` in `enable radius netlogin` and `enable radius-accounting
  netlogin` keeps administrator logins off RADIUS. Without the keyword,
  management logins go to RADIUS too, and RADIUS and TACACS+ cannot both
  be used for them.
- `vr VR-Default` — use `VR-Mgmt` if the switch reaches NACo through its
  management port. For `dynamic-authorization`, the default virtual router
  is `VR-Mgmt`.
- `enable netlogin … mac` adds the default MAC list itself from 31.3 on.
- `mode mac-based-vlans` lets several devices on one port sit in different
  untagged VLANs.
- `<critical-vlan-name>` is the name of the VLAN with ID `<critical-vlan>`.
- `database-order radius` — without it, MAC authentication also asks the
  switch's local database and fails instead of using the critical VLAN
  while NACo cannot be reached.
- Disconnects need ONEPolicy, which rules out the `service-unavailable`
  lines; read [Disconnect](#disconnect-coa) before you choose.

### Accounting

Switch Engine sends only Start and Stop records: no interim updates (33.6.1
ignores `Acct-Interim-Interval` in the Access-Accept), and no
Framed-IP-Address. A re-authentication sends no new Start either. That has
two consequences:

- The [guest portal](../guest-portal.md) cannot learn the client's IP
  address from these switches, so it is not available on them.
- NACo closes sessions that have had no accounting for 24 hours. A device
  connected for longer drops out of *Sessions*, and later policy changes
  no longer disconnect it. Where devices stay connected for days, raise
  `radius.stale_session_hours` in `config/config.yaml` (up to 720, see
  [configuration](../configuration.md)).

### Disconnect (CoA)

The switch listens on UDP 3799. It accepts requests only from a configured
`dynamic-authorization` server, and drops a request whose
Message-Authenticator is invalid. By default (`nas-ip require`) the
NAS-IP-Address must match the primary IP address of the switch's default
interface. If disconnects fail because of that, Switch Engine 31.3 and
later can skip the check:

```text
configure radius dynamic-authorization 1 nas-ip ignore
```

As Extreme states, disconnects need ONEPolicy. Without it, the switch
answers every Disconnect-Request with a NAK, *Session-Context-Not-Found*,
whatever it carries. With ONEPolicy, and the policy map told to take the
VLAN from NACo's RFC 3580 attributes, the switch ACKs and NACo's changes
apply at once — blocking a device ends its session, and it is rejected
when it tries again:

```text
enable policy
configure policy maptable response tunnel
configure policy vlanauthorization enable
enable netlogin dot1x mac
```

Two costs come with it:

- **No service-unavailable VLAN.** With ONEPolicy the
  `service-unavailable` commands no longer exist: while NACo cannot
  decide, new clients get no access at all.
- `enable policy` and `disable policy` clear NetLogin settings (the
  NetLogin VLAN, port modes, the global methods). Enter the NetLogin
  commands from [Switch Engine](#switch-engine-exos) again afterwards,
  without the `service-unavailable` lines under ONEPolicy.

Choose one: **ONEPolicy** — NACo's changes take effect at once, nobody new
gets in during an outage; or **no ONEPolicy** — a critical VLAN during
outages, and NACo's changes take effect only when a client authenticates
again (802.1X clients every hour by default; MAC clients are not
re-authenticated by default).

### When NACo cannot be reached

When NACo cannot decide (host down, NACo stopped, restarting or failing),
FreeRADIUS does not answer at all, not even Status-Server probes. Switch
Engine then puts devices that authenticate in the *service-unavailable*
VLAN. Up to 10 of these VLANs per port are possible since 30.2. Rules:

- It applies only when RADIUS is the only authentication method; a reject
  from NACo is honoured. For MAC clients that needs `database-order
  radius` (above).

- It does not apply to 802.1X or MAC clients on ports that also do web
  authentication, nor with ONEPolicy (above).
- MAC re-authentication is off by default (`reauth-period` 0), so MAC
  clients already connected keep their access.

To test, stop NACo (`docker compose stop naco`) and wait a minute before
you connect a device: FreeRADIUS keeps answering the first steps of an EAP
exchange for up to a minute, then goes silent.

### Notes

- **MAC format.** MAC authentication sends the MAC as user name and
  password, by default uppercase without separators (`00E018A8C540`), with
  Service-Type Call-Check, which NACo treats as MAB. `configure netlogin
  mac username format [hyphenated | colon-separated | none]` and (30.3 and
  later) `configure netlogin mac username case (lower|upper)` change the
  format; NACo accepts all of them. Because of Call-Check, a MAC-list
  password does not stop NACo from treating the request as MAB.
  Calling-Station-Id is hyphenated. A port with both methods runs MAC
  authentication for an 802.1X client too; the 802.1X result wins, but
  *Devices* lists the client's MAC as pending.
- **User name.** For EAP-TTLS and PEAP the switch shows and accounts the
  outer identity (`anonymous`); it ignores the User-Name in NACo's
  Access-Accept. *Sessions* in NACo shows the real user.
- **VLAN.** NACo sends the policy's VLAN as a number. That works for VLANs
  configured on the switch. `configure netlogin dynamic-vlan enable` (with
  uplink ports) creates missing ones, by ID only. Extreme's own attributes
  take precedence over the policy's VLAN.
- **Reply attributes** (policy editor names):

  | Attribute | Use |
  |---|---|
  | `Extreme-Netlogin-Vlan` | a VLAN by name (text) |
  | `Extreme-Netlogin-Vlan-Tag` | a VLAN by ID (number) |
  | `Extreme-Netlogin-Extended-Vlan` | several VLANs, e.g. `Uv1;Tcorp` (untagged `v1`, tagged `corp`) |
  | `Extreme-Security-Profile`, `Extreme-Netlogin-Only` | see Extreme's list of supported attributes |
  | `Filter-Id` | a ONEPolicy profile name |
  | `Session-Timeout` with `Termination-Action` | re-authenticate MAC clients periodically |

  `Extreme-Policy-ACL` is not in FreeRADIUS' dictionary, so the policy
  editor refuses it and you cannot use it.

## Switch logins (TACACS+)

```text
configure tacacs primary server <naco-ip> client-ip <switch-ip> vr VR-Default
configure tacacs primary shared-secret <tacacs-key>
enable tacacs
configure tacacs-accounting primary server <naco-ip> client-ip <switch-ip> vr VR-Default
configure tacacs-accounting primary shared-secret <tacacs-key>
enable tacacs-accounting
enable tacacs-authorization
```

- In NACo, add the switch under *TACACS+ clients* with `<switch-ip>` and
  `<tacacs-key>`. Give the admin group a **Device-admin privilege**, and
  optionally a command set ([TACACS+](../tacacs.md)).
- Switch Engine has two levels, read-only and read-write, and reads
  `priv-lvl` from the authorization answer: level 15 is read-write (`#`
  prompt), anything lower read-only (`>`). It asks for level 15 in every
  request; NACo answers with the group's level regardless. With
  `configure tacacs priv-lvl optional` (the default, 22.5 and later), a
  login without `priv-lvl` is read-only.
- `enable tacacs-authorization` sends every command to NACo before it
  runs, as typed (`show switch | include Name`) with the `shell` service,
  so the group's command set applies. Command sets match the whole line,
  so `show *` also permits `show … | include …`. The *save configuration?*
  question at logout is a command too. Enable it last, after a test login
  works.
- With `enable tacacs-accounting`, NACo logs every command as well as the
  session start and stop.
- The local database is used only when TACACS+ is unavailable. A user NACo
  rejects cannot log in with a local password. Keep a local `admin`
  account, and test from a second session before you close the first.

## Verify

```text
show netlogin
show netlogin mac-list
show radius
show radius-accounting
show radius dynamic-authorization 1
show netlogin authentication service-unavailable vlan
show tacacs
```

In NACo, *Logs* shows each decision and *Logs → TACACS+* each login and
command. *Sessions* shows the result of each disconnect.

## ExtremeCloud IQ wireless — not verified

ExtremeCloud IQ documentation could not be read, and nothing about it has
been checked. If each access point sends RADIUS from its own address, add
the access points' network as one RADIUS client. Check in the pilot:

- whether each access point sends RADIUS itself, or one access point
  proxies for the others;
- the Called-Station-Id format, so policies can match the SSID;
- whether MAC-authentication requests carry Message-Authenticator;
- the port and attributes its disconnect support needs. Choose a device
  type, then check the result in *Sessions*;
- the user-name format for MAC authentication.

## Check in the pilot

- **Disconnects** on hardware with ONEPolicy, and whether your switch
  needs `nas-ip ignore`.
- **Message-Authenticator** in MAC-authentication requests on releases
  before 33.6.1.
- **During an outage.** What happens when an 802.1X client re-authenticates
  while NACo is down.
- **Before 31.3.** Add the default MAC list by hand (command reference:
  *add mac-list*).
- **Source address.** Check that requests arrive from the `client-ip`; if
  not, FreeRADIUS logs an unknown client.
- **Calling-Station-Id case.** It does not matter to NACo, but check it in
  *Logs*.
- **TACACS+**: whether a login NACo does not authorize still gets in,
  read-only, with `priv-lvl optional`.

## References

User Guide 32.7.1 (`https://documentation.extremenetworks.com/switchengine_32.7.1/`):

- [RADIUS client](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-9F14ACEE-4369-4550-8286-E6C948BBF7A7.shtml),
  [RADIUS accounting](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-25992425-BDC2-4A21-9CF1-54640693D4E7.shtml)
- [Supported RADIUS attributes](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-50BA5560-F4F0-4D23-9A13-A68A510C4175.shtml),
  [standard attributes used by Extreme switches](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-739FD162-2AE4-4E0E-878B-7DED2D5D0268.shtml)
- [Disconnect-Request](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-83474DFA-DD3D-4631-B6BE-44BA545A96DC.shtml),
  [session identification](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-4FF3D3BB-14E5-446E-AE5D-04D636F3B1A7.shtml),
  [limitations](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-F87465D8-2FC4-4A37-9CCD-A29D104AA2E0.shtml)
- [MAC-based authentication](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-0BECA962-5CC2-46E8-9E69-62A428DB1C63.shtml),
  [service-unavailable VLAN](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-D970029E-7F41-4472-9BB2-15913B74A84C.shtml),
  [dynamic VLANs](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-EAF27009-AD15-4A00-8B4A-1FB02214DECE.shtml)
- [TACACS+ for management access](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-D64C0760-8CCC-4F25-91D5-DBF8FC9311E0.shtml),
  [TACACS+ example](https://documentation.extremenetworks.com/switchengine_32.7.1/GUID-89FC5EB6-F5B7-4EDD-A719-9F8EA4ECA6F2.shtml)

Command Reference 32.7.1 (`https://documentation.extremenetworks.com/switchengine_commands_32.7.1/`):

- [`configure radius dynamic-authorization`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-E878A038-B4B1-4B5D-8F50-BDBD2BA81FB8.shtml)
- [`configure netlogin mac username format`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-C11C9285-A0CC-4714-88BD-C101FA3929C9.shtml),
  [`… case`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-67BB7A09-A4E4-438D-84C6-943D28FD18E4.shtml)
- [`configure netlogin authentication service-unavailable vlan`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-2B91D03E-1A49-4923-B014-F737A89B813C.shtml)
- [`configure tacacs priv-lvl`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-4D352A49-5D0F-4BF3-93B0-DEADF4245BB2.shtml),
  [`enable tacacs-authorization`](https://documentation.extremenetworks.com/switchengine_commands_32.7.1/GUID-68E0B2A8-C851-4F3D-BF2D-E13FDAC32A22.shtml)
