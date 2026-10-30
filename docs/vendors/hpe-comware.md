# HPE Comware and H3C

This page covers HPE switches on Comware 7 (FlexNetwork 5130, 5140, 5510,
5710; FlexFabric 5940, 5945) and H3C switches on Comware 7. It is written
from H3C's S5130S-EI Comware 7 Release 63xx guides (March 2026). HPE's own
Comware guides were not read, so release numbers such as F6377 are H3C's.
Choose the device type **Standard (RFC 5176)**. What every device needs is
in [network devices](../network-devices.md); what to test is at the end of
this page.

## In NACo — what to enter

*RADIUS clients → Add client*:

| Field | Value |
|---|---|
| Name | for example `access-sw01` |
| IP address | the switch's `nas-ip` from the RADIUS scheme below. Without it, the switch uses the primary address of the outgoing interface. |
| Shared secret | 16 to 64 characters (Comware's limit for a plain-text key is 64). *Generate* makes 24. |
| Device type | Standard (RFC 5176) — Huawei, H3C/Comware, MikroTik, UniFi, Omada, others |
| CoA port | leave empty for 3799, Comware's default |
| Require Message-Authenticator | on from release F6377 with the setting below; off on older releases |

**Message-Authenticator.** By default Comware puts it only in EAP requests.
MAB and PAP requests carry none, so NACo does not answer them, while 802.1X
keeps working. From F6377, `auth-attribute message-authenticator force-mode
request` in the RADIUS scheme adds it. On older releases, switch *Require
Message-Authenticator* off for the switch; it then shows as **Legacy NAS**.

**Disconnects.** For this device type NACo sends a Disconnect-Request with
Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address and
NAS-Identifier, each only if the switch reported it in accounting, plus
Event-Timestamp and Message-Authenticator. NACo sends no CoA-Request and
never bounces a port: a wired MAB device whose VLAN changes keeps its old IP
address until its DHCP lease renews.

**Policies.** The policy's VLAN goes out as the RFC 3580 tunnel attributes,
by VLAN ID. Comware attributes go in the policy's *Extra RADIUS attributes*
([reply attributes](../policies.md#reply-attributes)). 802.1X clients use
EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC; PEAP-MSCHAPv2 is not supported
([802.1X](../eap.md)).

**When NACo cannot decide**, nothing answers, and the switch puts new
clients in the critical VLAN (below). For a minute after NACo stops,
FreeRADIUS may still answer the first steps of an EAP exchange, so wait more
than a minute before you test the fallback. See
[network devices](../network-devices.md#when-naco-cannot-decide).

## Comware 7 — RADIUS, 802.1X and MAC authentication

The RADIUS scheme, the probe, dynamic authorization and the ISP domain:

```text
radius-server test-profile naco-probe username naco-probe password simple <probe-password> interval 5
radius scheme naco
 primary authentication <naco-ip> key simple <shared-secret> test-profile naco-probe
 primary accounting <naco-ip> key simple <shared-secret>
 user-name-format without-domain
 nas-ip <switch-ip>
 timer realtime-accounting 15
 auth-attribute message-authenticator force-mode request
 quit
radius dynamic-author server
 client ip <naco-ip> key simple <shared-secret>
 quit
domain naco
 authentication lan-access radius-scheme naco
 authorization lan-access radius-scheme naco
 accounting lan-access radius-scheme naco
 quit
domain default enable naco
```

802.1X, MAC authentication and the critical VLAN on an access port:

```text
dot1x
dot1x authentication-method eap
mac-authentication
mac-authentication domain naco
interface GigabitEthernet1/0/1
 port access vlan <onboarding-vlan>
 dot1x
 dot1x port-method macbased
 mac-authentication
 dot1x critical vlan <critical-vlan>
 mac-authentication critical vlan <critical-vlan>
 dot1x re-authenticate server-unreachable keep-online
 mac-authentication re-authenticate server-unreachable keep-online
```

`<switch-ip>` is the address you added in NACo. On releases before F6377,
leave out the `auth-attribute` line.

- **`user-name-format without-domain`** is required. By default the scheme
  adds the ISP domain to the user name (`alice@naco`), which matches no
  NACo user.
- **`dot1x authentication-method eap`** is required. By default Comware
  terminates EAP itself and asks the server with CHAP. NACo's EAP-TLS,
  EAP-TTLS and PEAP need EAP passed through.
- **No `local` in the domain.** The critical VLAN works only when
  authentication is by RADIUS alone. A user who fails local authentication
  after RADIUS is not put in the critical VLAN.
- **Server dead.** The critical VLAN takes users whose authentication failed
  because every RADIUS server of their domain is unreachable. A MAC-auth
  client in the critical VLAN stays there while the servers stay
  unreachable. By default the switch logs clients off when no server is
  reachable for re-authentication; `re-authenticate server-unreachable
  keep-online` keeps them.
- **Probe.** The test profile asks NACo every 5 minutes (default 60) with
  the user `naco-probe`. Give it a password; otherwise the switch makes up
  a random one. NACo rejects it, and the probe appears in *Logs*. It does
  not need to exist in NACo.
- **MAC authentication.** By default the user name and the password are both
  the MAC, lower case without hyphens (`aabbccddeeff`). `with-hyphen`,
  `separator colon` and upper case work with NACo too. Do not use `fixed`:
  NACo needs the MAC as the user name. The default method is PAP; CHAP also
  counts as MAB.
- **Calling-Station-Id** defaults to `HH-HH-HH-HH-HH-HH`. Every
  `attribute 31 mac-format` setting works with NACo.
- **Accounting.** The default interim interval is 12 minutes. NACo needs 6
  hours or less. With `accounting-on enable`, the switch sends Accounting-On
  after a reboot, and NACo closes all of that switch's sessions at once.
- **Disconnects.** The switch discards disconnects from addresses not listed
  under `radius dynamic-author server`. From F6377 the `client` line also
  takes `message-authenticator force-mode`. NACo's disconnects carry
  Message-Authenticator.
- **VLAN.** Comware takes a VLAN ID or a VLAN name. A name is compared with
  the VLAN's *description*, not its name. NACo sends the ID, so you need not
  set descriptions.
- **Guest portal.** It needs Framed-IP-Address in accounting. The attribute
  is in Comware's list, but when it is sent is not documented. NACo does not
  read `H3C-Ip-Host-Addr`.

Useful reply attributes (FreeRADIUS names, vendor H3C):

| Purpose | Attribute |
|---|---|
| ACL number or user profile | `Filter-Id`: a value that starts with a digit is an ACL number, otherwise a user profile name |
| Session timeout | `Session-Timeout`, `Termination-Action` |
| User group | `H3C-User-Group` |
| Rate limiting | `H3C-Input-Peak-Rate` and the other rate attributes (H3C 1–6) |
| Dynamic ACL, AV pairs | `H3C-Av-Pair` |

## Switch logins (TACACS+)

Comware calls TACACS+ *HWTACACS*. In NACo, add the switch under *TACACS+
clients* with its `nas-ip` and a key of at least 16 characters, and give the
admins' group a *device-admin privilege* ([TACACS+](../tacacs.md)).

Comware takes a login user's roles from the authorization reply, in the
form `roles="role-1 role-2"`. NACo answers the shell service with
`priv-lvl=<group's level>` and adds every `shell:` line from the group's
*TACACS+ attributes for other vendors* (*Groups → Edit*). For full admins,
enter:

```text
shell: roles="network-admin"
```

For a group with fewer rights, name roles that exist on the switch, for
example `shell: roles="level-0 level-1 level-2"`. `level-15` has the same
rights as `network-admin`. A login user without authorization gets
`level-0`.

```text
hwtacacs scheme naco-tac
 primary authentication <naco-ip>
 primary authorization <naco-ip>
 primary accounting <naco-ip>
 key authentication simple <tacacs-key>
 key authorization simple <tacacs-key>
 key accounting simple <tacacs-key>
 user-name-format without-domain
 nas-ip <switch-ip>
 quit
domain system
 authentication login hwtacacs-scheme naco-tac local
 authorization login hwtacacs-scheme naco-tac local
 authorization command hwtacacs-scheme naco-tac local
 accounting login hwtacacs-scheme naco-tac local
 quit
line vty 0 63
 authentication-mode scheme
 command authorization
 command accounting
```

- NACo checks every command against the group's command set. The switch
  allows only commands that both NACo and the user's role permit.
- Keep a local account. The switch uses `local` only when NACo does not
  answer, never after NACo refuses. Test from a second session before you
  close the first.
- Do not use `role default-role enable network-admin`, as some integration
  examples do: it gives every authenticated user `network-admin`.

## Verify — show commands

```text
display radius scheme
display radius statistics
display dot1x
display dot1x connection
display mac-authentication connection
display dot1x mac-address critical-vlan
display mac-authentication mac-address critical-vlan
```

`display mac-authentication connection` shows the user name, the IPv4
address and the authorization VLAN of each client. Every request also
appears in NACo's *Logs*, and every session in *Sessions*.

## Check in the pilot

Nobody has confirmed these points from the vendor documentation. Test them
before you rely on them:

- **HPE-branded switches.** The commands and the F6377 release come from
  H3C's guides. Check them on your HPE release. Check also that HPE's
  firmware uses H3C's vendor ID (25506) for the `H3C-` attributes.
- **The `primary authentication` line.** The key and the test profile on one
  line are assembled from the command syntax. Check with `display radius
  scheme` that both are set.
- **The probe.** Whether the test profile's packets carry
  Message-Authenticator with `force-mode request`. If they do not, NACo
  drops them and the switch marks NACo unreachable while it works. Check
  also that a reject counts as reachable: `naco-probe` must appear in
  *Logs*.
- **Domain in MAC user names.** Whether the switch would add the domain to
  MAC-auth user names too. `user-name-format without-domain` avoids it;
  check that *Logs* shows MAC requests as MAB.
- **Disconnects.** Which attributes the switch uses to find the session is
  not documented. Check that *Sessions → Disconnect* is acknowledged.
- **Guest portal.** Whether accounting carries Framed-IP-Address.
- **TACACS+ roles.** No source says that Comware maps `priv-lvl` to a role,
  hence the `roles` line. Check that an admin gets `network-admin`. The
  shell service is assumed from H3C's ClearPass example. If *Logs →
  TACACS+* refuses a login with "no attributes for service …", add the same
  `roles` line for that service.
- **`command accounting`** under `line vty` was not checked for every model.

## References

- H3C S5130S-EI Comware 7 R63xx:
  [AAA configuration](https://www.h3c.com/en/d_202603/2777037_294551_0.htm),
  [AAA commands](https://www.h3c.com/en/d_202603/2776894_294551_0.htm),
  [802.1X configuration](https://www.h3c.com/en/d_202603/2777038_294551_0.htm),
  [802.1X commands](https://www.h3c.com/en/d_202603/2776895_294551_0.htm),
  [MAC authentication configuration](https://www.h3c.com/en/d_202603/2777039_294551_0.htm),
  [MAC authentication commands](https://www.h3c.com/en/d_202603/2776896_294551_0.htm),
  [RBAC](https://www.h3c.com/en/d_202603/2776960_294551_0.htm),
  [login management](https://www.h3c.com/en/d_202603/2776961_294551_0.htm)
- [H3C, Aruba ClearPass integration examples](https://www.h3c.com/en/d_202304/1837835_294551_0.htm)
  (HWTACACS and dynamic authorization)
- [FreeRADIUS 3.2 dictionaries](https://github.com/FreeRADIUS/freeradius-server/tree/v3.2.x/share)
  (`dictionary.h3c`)
