# TACACS+ — switch logins

NACo is a TACACS+ server (RFC 8907) for administrators logging in to
switches, routers and firewalls: authentication, authorization of the shell
and of every command, and accounting of what was done. It listens on TCP 49
of the host.

Network access (RADIUS policies) and device administration are separate:
a user may log in to a switch only if their **group has a device-admin
profile**, whatever the RADIUS policies say.

## Set up

1. **TACACS+ clients** — add each device with its source address and its own
   key (16+ characters). Requests from other addresses are not answered.
2. **Groups** — give a group a *device-admin privilege* (1–15) and,
   optionally, a *command set*. Members of a group without a privilege
   cannot log in to devices.
3. **Command sets** — an ordered list of *permit* / *deny* rules with
   wildcard patterns, and a default for commands no rule matches:

   ```text
   permit  show *
   permit  ping *
   permit  traceroute *
   deny    *                      (default: deny)
   ```

   Patterns match the whole command line, case-insensitively, with
   abbreviations already expanded by the device (`sh run` arrives as
   `show running-config`). Without a command set, every command up to the
   group's privilege level is allowed.
4. Users log in with their NACo or LDAP / AD password. *Logs → TACACS+*
   shows every login, `enable`, authorized or refused command and the
   accounting records.

Authentication supports ASCII (interactive) and PAP logins and `enable`,
which is granted up to the group's privilege level.

## Cisco IOS-XE

```text
tacacs server NACO
 address ipv4 10.0.0.10
 key <tacacs-key>
aaa group server tacacs+ NACO-TAC
 server name NACO
 ip tacacs source-interface Vlan10
!
aaa new-model
aaa authentication login default group NACO-TAC local
aaa authentication enable default group NACO-TAC enable
aaa authorization exec default group NACO-TAC local if-authenticated
aaa authorization commands 1 default group NACO-TAC local if-authenticated
aaa authorization commands 15 default group NACO-TAC local if-authenticated
aaa authorization config-commands
aaa accounting exec default start-stop group NACO-TAC
aaa accounting commands 1 default start-stop group NACO-TAC
aaa accounting commands 15 default start-stop group NACO-TAC
!
line vty 0 15
 login authentication default
```

Keep a local fallback account and test from a second session before you
close the first one. On IOS-XE the fallback is used only when NACo does not
answer; a login NACo refuses is refused. Other vendors differ — the vendor
pages say. With `privilege 15` in the user's group, IOS starts the session
in privileged EXEC (`priv-lvl=15`).

## Other vendors

Devices ask NACo for authorization of a *service*. Cisco-style devices ask
for `shell`, and NACo answers with the group's privilege level
(`priv-lvl=N`) and checks each command against the group's command set.

Others ask for their own service and expect their own attributes. Give the
group one line per attribute under *Groups → TACACS+ attributes for other
vendors*, as `service: attribute=value` (or `attribute*value` for an
optional one). Members receive exactly those lines for that service; a
service with no line is refused. Lines for `shell` are sent along with
`priv-lvl` when a session starts.

| Device | Service it asks for | Lines on the NACo group |
|---|---|---|
| Cisco IOS, IOS-XE, Arista EOS, Aruba AOS-CX and AOS-S | `shell` | none — the privilege level is enough |
| Cisco NX-OS | `shell` | a role, e.g. `shell: shell:roles*"network-admin"` (`*`: optional, so IOS-XE logins of the same group ignore it) |
| HPE Comware, H3C | `shell` | a role, e.g. `shell: roles="network-admin"` |
| Juniper Junos | `junos-exec` | the login class template, e.g. `junos-exec: local-user-name=remote-admin` |
| Fortinet FortiOS (with authorization enabled) | `fortigate` | the admin profile, e.g. `fortigate: admin_prof=super_admin` |
| Dell OS10 | `ppp` (`protocol=ip`) | the role, e.g. `ppp: shell:roles=sysadmin` |
| Ruckus ICX | `shell` | none — level 15 is super-user, 1–14 port-configuration; for read-only try `shell: foundry-privlvl=5` (check in the pilot) |

The exact attribute names and values each device expects, and its
configuration with a local fallback, are on the [vendor pages](network-devices.md#vendors).
MikroTik has no TACACS+.
