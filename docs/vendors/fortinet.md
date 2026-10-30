# Fortinet

This page covers a FortiGate with FortiSwitch units managed over FortiLink,
FortiAP access points managed by the FortiGate, and administrator logins to
the FortiGate over TACACS+. It follows the FortiOS 7.4 and 7.6 and
FortiSwitchOS 7.2 to 7.6 documentation. Choose the device type
**Fortinet** for the switches and for the FortiGate. Read
[network devices](../network-devices.md) and run [a pilot](../pilot.md)
before you enforce anything.

## In NACo — what to enter

Each FortiSwitch sends RADIUS for its own ports, through the FortiGate.
The FortiGate sends RADIUS for Wi-Fi. *RADIUS clients → Add client*:

| Field | FortiSwitch units (FortiLink) | FortiGate (Wi-Fi) |
|---|---|---|
| IP address or network | the FortiLink network, e.g. `10.255.1.0/24` | the FortiGate's `source-ip` |
| Shared secret | 16+ characters, as in `config user radius` | the same |
| Device type | Fortinet | Fortinet |
| CoA port | 3799 | 3799 |
| Require Message-Authenticator | on | on; see the pilot list |

One network entry covers every FortiSwitch on the FortiLink (at most a
/16). An entry for an exact address wins over a network that contains it.
Disconnects go to the switch that holds the session.

With the Fortinet type, a disconnect request carries User-Name,
Calling-Station-Id and NAS-IP-Address, each exactly as the device reported
it in accounting and only when it did, plus Event-Timestamp and
Message-Authenticator. It carries no Acct-Session-Id: FortiSwitch does not
list it as supported, and answers NAK (401) to unsupported attributes.

NACo sends only Disconnect-Requests, never a CoA-Request, so it cannot
bounce a port. A wired MAC-authenticated device (a printer) that NACo moves
to another VLAN keeps its old IP address until its DHCP lease renews.

Users authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## FortiSwitch over FortiLink

RADIUS from the switches crosses the FortiGate, so you need a firewall
policy from the FortiLink interface to NACo. Disconnects reach the switches
only if that policy has **NAT disabled** and the FortiLink interfaces have
routable addresses other than 169.254.1.x. Fortinet's own example uses
`set nat enable`; do not copy it, because with NAT all switches share the
FortiGate's address. NACo also needs a route to the FortiLink network, and
the FortiGate must let UDP 3799 through from NACo to the switches.

```text
config user radius
    edit "NACO"
        set server "<naco-ip>"
        set secret <shared-secret>
        set radius-coa enable
        set acct-interim-interval 900
        config accounting-server
            edit 1
                set status enable
                set server "<naco-ip>"
                set secret <shared-secret>
                set port 1813
            next
        end
    next
end
config user group
    edit "NACO-USERS"
        set member "NACO"
    next
end
config firewall policy
    edit 0
        set name "fortilink-to-naco"
        set srcintf "fortilink"
        set dstintf "<interface-towards-naco>"
        set srcaddr "all"
        set dstaddr "<naco-address-object>"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat disable
    next
end
config switch-controller security-policy local-access
    edit "default"
        set internal-allowaccess ping https ssh radius-acct
    next
end
config switch-controller security-policy 802-1X
    edit "NACO-8021X"
        set security-mode 802.1X-mac-based
        set user-group "NACO-USERS"
        set mac-auth-bypass enable
        set eap-passthru enable
        set authserver-timeout-vlan enable
        set authserver-timeout-vlanid "<critical-vlan-interface>"
    next
end
config switch-controller managed-switch
    edit "<switch-serial>"
        config ports
            edit "port1"
                set port-security-policy "NACO-8021X"
            next
        end
    next
end
```

- `radius-coa enable` and `radius-acct` in the switch's local access let
  the switches accept disconnect requests on UDP 3799.
- The accounting server is off by default; `set status enable` turns it
  on. `acct-interim-interval` is in seconds (60–86400).
- `802.1X-mac-based` gives every device on the port its own session (up
  to 20 per port). In this mode a disconnect ends only that device's
  session; the port stays up.
- `eap-passthru enable` relays EAP to NACo. Accounting, disconnects and
  VLANs by name need it; it is the default since 6.2.0. FortiSwitch does
  not support EAP-MD5.
- For the monitor-mode step of the pilot, add `set open-auth enable` to
  the security policy. Remove it to enforce.

### Accounting

The switches send Start, Interim, Stop, On and Off records. NACo needs an
update at least every 360 minutes, because it closes sessions that have
had no accounting for 24 hours; 900 seconds is well inside that. The
switches add Framed-IP-Address when they know the client's address, which
needs DHCP snooping on the 802.1X ports. Only the
[guest portal](../guest-portal.md) needs it.

### When NACo cannot be reached

When NACo cannot decide (host down, NACo stopped, restarting or failing),
FreeRADIUS does not answer at all, not even Status-Server probes.
`authserver-timeout-vlan` then puts devices in the critical VLAN:

- `authserver-timeout-vlanid` takes the name of the critical VLAN's
  interface (VLAN `<critical-vlan>`), not its number. This untagged
  variant needs FortiSwitchOS 6.4.3 or later.
- `authserver-timeout-tagged` (`lldp-voice` or `static`) is the tagged
  variant, from FortiOS 7.4.4, for MAC-based mode, EAP and MAB.
- `authserver-timeout-period` is 3–15 seconds, default 3.

To test, stop NACo (`docker compose stop naco`) and wait a minute before
you connect a device: FreeRADIUS keeps answering the first steps of an EAP
exchange for up to a minute, then goes silent.

### Notes

- **MAC format.** MAB sends the MAC as user name and password with
  Service-Type Call-Check, which NACo treats as MAB. The default is
  lowercase with hyphens (`00-11-22-33-44-55`). From FortiOS 7.4.2 with
  FortiSwitchOS 7.4.1, the `mac-*-delimiter` settings accept `colon`,
  `hyphen`, `none` or `single-hyphen`, and `mac-case` sets the case. NACo
  accepts all of them.
- **Message-Authenticator.** FortiSwitch includes it in MAB and 802.1X
  requests. Use a release with the BlastRADIUS fix (FG-IR-24-255):
  FortiSwitchOS 7.4.1, 7.2.6, 7.0.8 or later; 7.6 is not affected.
- **VLAN.** NACo sends the policy's VLAN as a number. FortiSwitch can also
  match a name against the VLAN's description, but NACo's VLAN field is
  numeric.
- **Reply attributes** (policy editor names): `Filter-Id`,
  `NAS-Filter-Rule` (dynamic ACLs, FortiOS 7.4.4 and later with
  `set dacl enable`), `Session-Timeout` (needs
  `radius-timeout-overwrite enable`), `Class`, `Fortinet-Group-Name`,
  `Egress-VLANID`, `Egress-VLAN-Name`. `Fortinet-Host-Port-AVPair` (port
  bounce) works only in a CoA-Request, which NACo does not send.

## FortiAP (Wi-Fi through the FortiGate)

For 802.1X and MAC-authentication SSIDs in tunnel or local-bridge mode,
the FortiGate asks NACo. Its RADIUS client entry uses the `source-ip`.

```text
config user radius
    edit "NACO"
        set source-ip <fortigate-ip>
    next
end
config wireless-controller vap
    edit "corp"
        set ssid "<ssid>"
        set security wpa2-only-enterprise
        set auth radius
        set radius-server "NACO"
        set dynamic-vlan enable
        set called-station-id-type mac
    next
end
```

- `dynamic-vlan` is off by default; without it the SSID ignores the VLAN.
- `called-station-id-type mac` (FortiOS 7.6.1 and later, the default)
  sends `<AP MAC>:<SSID>`, so policies can match the SSID. With `ip` or
  `apname`, NACo uses `Fortinet-SSID` instead, if the FortiGate sends it.
- MAC authentication on an SSID: `set radius-mac-auth enable` and
  `set radius-mac-auth-server "NACO"` in the VAP (CLI only). The VAP's
  `mac-case` defaults to uppercase; NACo accepts any case and delimiter.
- Accounting uses the server's `acct-interim-interval`; the VAP also has
  `roaming-acct-interim-update`.
- VLANs: the tunnel attributes with an ID from 1 to 4094. FortiAP also
  accepts a VLAN name tag or a VLAN pool.
- The FortiGate requires Message-Authenticator in NACo's answers
  (`require-message-authenticator`, on by default), and NACo always
  includes it. The BlastRADIUS fix is in FortiOS 7.6.1, 7.4.6 and 7.2.11;
  FortiAP is not affected.
- Reply attributes: `Filter-Id` (a Wi-Fi user group), `Fortinet-Group-Name`.
  `Fortinet-Captive-Portal-URL` is not in FreeRADIUS' dictionary, so the
  policy editor refuses it.

## Switch logins (TACACS+)

Administrator logins to the FortiGate:

```text
config user tacacs+
    edit "NACO"
        set server "<naco-ip>"
        set key <tacacs-key>
        set authen-type ascii
        set source-ip <fortigate-ip>
    next
end
config user group
    edit "NACO-ADMINS"
        set member "NACO"
    next
end
config system admin
    edit "naco-admins"
        set remote-auth enable
        set accprofile "<profile>"
        set vdom "root"
        set wildcard enable
        set remote-group "NACO-ADMINS"
    next
end
config log tacacs+accounting setting
    set status enable
    set server "<naco-ip>"
    set server-key <tacacs-key>
end
config log tacacs+accounting filter
    set login-audit enable
    set config-change-audit enable
    set cli-cmd-audit enable
end
```

- `authen-type ascii` or `pap`. Not `chap`, `mschap` or `auto`: NACo
  refuses CHAP and MS-CHAP, and `auto` tries PAP, MS-CHAP, then CHAP.
- In NACo, add the FortiGate under *TACACS+ clients* with `<fortigate-ip>`
  and `<tacacs-key>`. Give the admin group a **Device-admin privilege**.
  FortiOS ignores the level, but without one NACo refuses the login.
- Leave `authorization` at its default, disabled. Every administrator NACo
  lets in then gets the wildcard admin's `accprofile`.
- FortiOS has no per-command authorization, so NACo command sets do not
  apply. `cli-cmd-audit` sends every command to *Logs → TACACS+*.

With `set authorization enable`, FortiOS asks for the service `fortigate`
and reads only `admin_prof` and `memberof`. Add the line to the group under
**TACACS+ attributes for other vendors**:

```text
fortigate: admin_prof=<profile>
```

How `memberof` (`fortigate: memberof=<group>`) maps to FortiGate groups
was not confirmed. If the answer carries neither attribute, the FortiGate
uses the values under `config system admin`. A group without a `fortigate`
line is refused; whether FortiOS then blocks the login is not confirmed.

Keep a local `super_admin`: local admins are separate entries and do not
depend on NACo. The FortiGate remembers an unreachable server for
`status-ttl` (default 300 seconds). Test from a second session before you
close the first.

## Verify

```text
diagnose test authserver radius NACO pap <user> <password>
diagnose switch-controller switch-info 802.1X-dacl <switch-serial> <port>
execute switch-controller switch-action 802-1X clear-auth-mac <switch-serial> <mac>
execute switch-controller switch-action 802-1X clear-auth-port <switch-serial> <port>
```

`diagnose test authserver` comes from the FortiGate itself, so it uses the
FortiGate's RADIUS client entry. The `clear-auth` commands make a device
or a port authenticate again. In NACo, *Logs* shows each decision and
*Sessions* the result of each disconnect.

## Check in the pilot

- **FortiSwitch disconnects.** Confirm in *Sessions* that they are
  acknowledged, and which FortiGate policy lets UDP 3799 from NACo reach
  the FortiLink network (not confirmed).
- **Firewall policy.** The name of a predefined RADIUS service to use
  instead of `ALL` was not confirmed.
- **During an outage.** Whether connected devices keep access when they
  re-authenticate while NACo is down (`reauth-period`, `link-down-auth` in
  `config switch-controller 802-1X-settings`).
- **Session view.** A general `diagnose switch-controller switch-info
  802.1X <switch-serial>` probably exists but was not confirmed.
- **`Fortinet-Group-Name`.** Fortinet says authentication fails if it does
  not match. That matters only if the FortiGate user group has
  `config match` entries.
- **Wi-Fi.** Which device sends RADIUS in local-standalone mode. Whether
  the FortiGate includes Message-Authenticator in its own MAC and PAP
  requests, `diagnose test authserver` included; if FreeRADIUS logs it as
  missing, switch *Require Message-Authenticator* off for the FortiGate
  (**Legacy NAS**). Whether Wi-Fi accounting carries Framed-IP-Address
  (guest portal). Which attributes a wireless disconnect needs, and on
  which interface the FortiGate listens. What happens to Wi-Fi clients
  when NACo cannot be reached. The Called-Station-Id format before 7.6.1,
  and whether `Fortinet-SSID` is sent.
- **TACACS+ with authorization enabled.** Whether a refusal from NACo
  blocks the login, how `memberof` maps, and whether the wildcard admin
  applies `admin_prof`. Log in and check the profile you get.
- **FortiSwitch standalone** (without FortiLink) supports disconnects, but
  its RADIUS and 802.1X commands were not looked at.

## References

- [FortiSwitch security policies (FortiLink guide 7.6.0)](https://docs.fortinet.com/document/fortiswitch/7.6.0/fortilink-guide/756049/fortiswitch-security-policies)
- [Supported attributes for RADIUS CoA (FortiSwitchOS 7.2.10)](https://docs.fortinet.com/document/fortiswitch/7.2.10/administration-guide/137894/appendix-b-supported-attributes-for-radius-coa-and-rsso)
- [`config user radius`](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/164332072/config-user-radius),
  [configuring a RADIUS server](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/759080/configuring-a-radius-server),
  [RADIUS AVPs and VSAs](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/952303/radius-avps-and-vsas)
- [`config wireless-controller vap`](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/304313044/config-wireless-controller-vap),
  [Called-Station-Id](https://docs.fortinet.com/document/fortiap/7.6.5/fortiwifi-and-fortiap-configuration-guide/446373/configuring-the-radius-called-station-id-setting),
  [MAC-based authentication](https://docs.fortinet.com/document/fortiap/7.6.5/fortiwifi-and-fortiap-configuration-guide/86726/mac-based-authentication),
  [VLAN assignment by RADIUS](https://docs.fortinet.com/document/fortiap/7.6.5/fortiwifi-and-fortiap-configuration-guide/685372/vlan-assignment-by-radius)
- [TACACS+ servers](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/864014/tacacs-servers),
  [TACACS+ VSAs](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/756731/remote-administrators-with-tacacs-vsa-attributes),
  [`config user tacacs+`](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/555694309/config-user-tacacs),
  [accounting setting](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/306881233/config-log-tacacs-accounting-setting),
  [accounting filter](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/336222423/config-log-tacacs-accounting-filter)
- [FG-IR-24-255 (BlastRADIUS)](https://www.fortiguard.com/psirt/FG-IR-24-255)
