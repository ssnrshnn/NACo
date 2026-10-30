# Dell

This page covers Dell PowerSwitch on SmartFabric OS10, releases 10.5.x to
10.6.0.x. OS10's 802.1X is minimal. Dell documents no MAC authentication,
no RADIUS accounting for 802.1X, no Change of Authorization, no
RADIUS-assigned VLAN and no critical VLAN. On OS10, NACo can therefore only
accept or reject 802.1X clients. Choose the device type **Standard (RFC
5176)**; OS10 takes no Disconnect-Request, so the choice has no effect. Dell
Enterprise SONiC is a different operating system and is not covered here.

## In NACo — what to enter

*RADIUS clients → Add client*:

- **IP address or network** — the address of `ip radius source-interface`.
  With the management VRF, it is the management address. One entry per
  switch.
- **Shared secret** — 16 to 42 characters. OS10 takes at most 42 characters
  in plain text.
- **Device type** — Standard (RFC 5176).
- **CoA port** — leave 3799; OS10 does not listen for Disconnect-Requests.
- **Require Message-Authenticator** — leave on. 802.1X requests always carry
  it.

Users authenticate with EAP-TLS or EAP-TTLS with PAP. PEAP with GTC
probably works too (see *Check in the pilot*). PEAP-MSCHAPv2 is not
supported ([802.1X and certificates](../eap.md)).

## What works and what does not

| | OS10 |
|---|---|
| 802.1X | works, accept or reject. Dell lists EAP-TLS and EAP-TTLS (and EAP-MD5) |
| MAC authentication (MAB) | not supported. Printers and other devices without 802.1X cannot be admitted through NACo |
| Accounting | not supported for 802.1X. *Sessions* stays empty, NACo learns no client IP, and the [guest portal](../guest-portal.md) cannot work |
| Disconnect | not supported. A new decision reaches the port at the next re-authentication or link change |
| VLAN from NACo | not documented. The port stays in its `switchport access vlan` |
| When NACo cannot be reached | no critical VLAN. New clients stay unauthorized; a secondary RADIUS server is used if you configure one |

A permit gives the client the port's own VLAN. A VLAN in a NACo policy has
no documented effect on OS10 ports, so one policy can serve OS10 and other
switches.

## OS10 — RADIUS and 802.1X

```text
radius-server host <naco-ip> key <shared-secret> auth-port 1812
radius-server retransmit 3
radius-server timeout 5
ip radius source-interface loopback 0
!
dot1x system-auth-control
!
interface range ethernet 1/1/1-1/1/48
 switchport access vlan <users-vlan>
 dot1x port-control auto
 dot1x host-mode multi-auth
 dot1x re-authentication
 dot1x timeout re-authperiod 3600
```

- `radius-server host` has no accounting port: OS10 sends no accounting.
- Without `ip radius source-interface`, OS10 sends from the outgoing
  interface. If you use the management VRF (`radius-server vrf
  management`), you cannot also set a source interface; NACo then sees the
  management address.
- `dot1x port-control` is `force-authorized` by default, so the port lets
  everything through until you set `auto`.
- `dot1x host-mode` is `multi-host` by default: one authenticated client
  opens the port for all. `multi-auth` (from 10.5.2) authenticates each
  client.
- With no Disconnect, periodic re-authentication is how a changed NACo
  decision reaches a port. `shutdown` and `no shutdown` on the interface do
  it at once.
- 802.1X does not work on port-channels or their members.
- OS10 drops LLDP frames on an 802.1X port until a client authenticates.
  This matters for IP phones that use LLDP-MED.

## Switch logins (TACACS+)

```text
tacacs-server host <naco-ip> key <tacacs-key>
tacacs-server timeout 5
ip tacacs source-interface loopback 0
!
aaa authentication login default group tacacs+ local
aaa authentication login console local
aaa accounting commands all default start-stop group tacacs+
```

In NACo:

1. *TACACS+ clients* — the address of `ip tacacs source-interface` (with
   `tacacs-server vrf management`, the management address; the two cannot
   be combined), and a key of 16 to 42 characters.
2. *Groups* — give the administrators' group a device-admin privilege and,
   under *TACACS+ attributes for other vendors*, the OS10 role:

   ```text
   ppp: shell:roles=sysadmin
   ```

   At login, OS10 asks for authorization with `service=ppp protocol=ip` and
   needs a role in the reply: `sysadmin`, `secadmin`, `netadmin` or
   `netoperator`. The role decides the privilege on the switch (15 for the
   first three, 1 for `netoperator`). Without the line, NACo refuses the
   request.

Notes:

- `aaa authentication login console local` keeps the console on local
  accounts. Local accounts are also used when NACo cannot be reached. Test
  from a second session before you close the first.
- Command authorization exists from 10.5.1, for example `aaa authorization
  commands role sysadmin default group tacacs+ local`. Dell does not say
  what OS10 sends for each command, and `local` is used only when NACo is
  unreachable, not when it refuses. If NACo refuses the command requests,
  every command is refused. Try it on a lab switch first.
- OS10 logins over RADIUS need `DellEMC-Group-Name` in the reply. NACo does
  switch logins over TACACS+, so use TACACS+.

## Verify

```text
show dot1x
show dot1x interface ethernet 1/1/1
show running-configuration radius-server
show running-configuration tacacs-server
show running-configuration aaa
show users
```

- *Logs* shows each 802.1X decision. *Sessions* shows nothing for OS10.
- *Logs → TACACS+* shows the login and the `ppp` authorization with the
  role. If the switch logs that the privilege level is not configured and
  starts the session as `netoperator`, the role did not arrive.
- Stop NACo (`docker compose stop naco`) and wait a minute: FreeRADIUS
  keeps answering the first steps of an EAP exchange for up to a minute.
  Then connect a new client: it must stay unauthorized. Start NACo again.

## Check in the pilot

- **VLAN**: whether OS10 really ignores the VLAN from NACo. Dell documents
  no RADIUS-assigned VLAN, but does not say that it ignores one. Check the
  port's VLAN after a permit that carries one.
- **PEAP with GTC**: Dell does not list it. The switch only relays EAP, so
  it probably works.
- **Re-authentication while NACo cannot be reached**: what happens to
  authorized ports is not documented. Test it before you turn on `dot1x
  re-authentication` widely, or use a long `re-authperiod`.
- **TACACS+ role**: Dell's user guide says a login without a role fails;
  Dell's KB says it lands in `netoperator`. The KB's server also sends
  privilege level 15 with the role. If the role does not take, add a second
  line `ppp: priv-lvl=15`.
- **TACACS+ commands**: which service and arguments OS10 sends for each
  command. *Logs → TACACS+* shows it.

## References

- [Dell EMC SmartFabric OS10 User Guide 10.5.2 (PDF)](https://dl.dell.com/topicspdf/dell-emc-smartfabric-os10_users-guide13_en-us.pdf):
  802.1X on pp. 514–528, security and AAA on pp. 1307–1318
- [Dell EMC SmartFabric OS10 User Guide 10.5.0 (PDF)](https://dl.dell.com/topicspdf/dell-emc-smartfabric-os10_users-guide10_en-us.pdf)
- [SmartFabric OS10 User Guide 10.6.0.x: 802.1X](https://www.dell.com/support/manuals/en-us/smartfabric-os10-emp-partner/smartfabric-os-user-guide-10-6-0-x/8021x?guid=guid-6e80b4a8-e709-4e5d-929e-05cb68f19eb2&lang=en-us)
- [Dell KB 000181974: OS10 TACACS+ configuration on ClearPass](https://www.dell.com/support/kbdoc/en-us/000181974/os10-tacacs-configuration-on-clearpass)
