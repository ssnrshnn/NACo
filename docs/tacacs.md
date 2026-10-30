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
close the first one. With `privilege 15` in the user's group, IOS starts the
session in privileged EXEC (`priv-lvl=15`).

## Other vendors

Juniper (`system tacplus-server`), Aruba AOS-CX (`tacacs-server host`),
Arista (`tacacs-server host`), Fortinet, Palo Alto and others work the same
way: point them at the NACo host, port 49, with the client's key; enable
command authorization and accounting where the device offers it.
