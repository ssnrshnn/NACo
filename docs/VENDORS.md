# Vendor compatibility guide

NACo speaks standard RADIUS (RFC 2865/2866/3580/5176) and TACACS+ (RFC 8907),
so any compliant NAS works out of the box. Dynamic VLAN assignment uses the
vendor-neutral `Tunnel-Type` / `Tunnel-Medium-Type` / `Tunnel-Private-Group-Id`
triplet, which every major switch and AP vendor honours.

Beyond VLANs, policies can attach **vendor-specific attributes (VSAs)** to the
Access-Accept — user roles, bandwidth limits, admin privilege levels. Add them
in *Policies → Add Policy → RADIUS reply attributes* (or the
`reply_attributes` field on `POST /api/v1/policies`). Attribute names must
exist in [`naco/radius/dictionary`](https://github.com/ssnrshnn/NACo/tree/main/naco/radius/dictionary); adding a new
VSA is a two-line dictionary edit plus a restart.

Example policy body:

```json
{
  "name": "employees-aruba",
  "conditions": [{"type": "group", "op": "in", "value": ["employees"]}],
  "action": "PERMIT",
  "vlan": 20,
  "reply_attributes": {
    "Aruba-User-Role": "employee",
    "Session-Timeout": 28800
  }
}
```

Values may be strings, integers, or lists (a list sends the attribute
multiple times — the usual pattern for `Cisco-AVPair`).

---

## Quick matrix

| Vendor | 802.1X / MAB | Dynamic VLAN | CoA / Disconnect (RFC 5176) | Role / extras via VSA |
|---|---|---|---|---|
| Cisco IOS / IOS-XE | ✅ | ✅ Tunnel-* | ✅ port 3799* | `Cisco-AVPair` |
| Cisco WLC / 9800 | ✅ | ✅ | ✅ | `Cisco-AVPair` (`url-redirect`, ACL) |
| Aruba AOS-CX / controllers / Instant | ✅ | ✅ | ✅ | `Aruba-User-Role`, `Aruba-User-Vlan` |
| HPE ProCurve / ArubaOS-Switch | ✅ | ✅ | ✅ | `HP-Privilege-Level` |
| Juniper EX / SRX (Junos) | ✅ | ✅ | ✅ | `Juniper-Local-User-Name`, allow/deny-commands |
| Fortinet FortiGate / FortiSwitch / FortiAP | ✅ | ✅ | ✅ | `Fortinet-Group-Name` |
| MikroTik RouterOS | ✅ | ✅ | ✅ | `Mikrotik-Group`, `Mikrotik-Rate-Limit` |
| Ubiquiti UniFi | ✅ | ✅ Tunnel-* only | ⚠️ AP-dependent | WISPr bandwidth attrs |
| Extreme EXOS | ✅ | ✅ | ✅ | `Extreme-Netlogin-Vlan` |
| Ruckus SmartZone / Unleashed | ✅ | ✅ | ✅ | `Ruckus-User-Groups` |
| Huawei VRP | ✅ | ✅ | ✅ | `Huawei-Exec-Privilege` |
| Palo Alto (admin auth) | n/a | n/a | n/a | `PaloAlto-Admin-Role` |
| Arista EOS | ✅ | ✅ | ✅ | `Arista-AVPair` |

\* NACo sends CoA/Disconnect from port 3799; point the NAS `aaa server radius
dynamic-author` (or equivalent) at the NACo host.

All examples below assume:

- NACo at `10.0.0.10`, auth `1812`, acct `1813`, CoA `3799`
- 802.1X/EAP goes to the bundled FreeRADIUS on `2812`/`2813` (default-on
  sidecar) — use those ports instead of 1812/1813 wherever a config below
  enables dot1x; keep MAB/PAP on 1812
- Shared secret `S3cret!` (must match the NAS entry in *RADIUS Clients*)
- **Message-Authenticator enabled** — NACo drops Access-Requests without it
  by default (BlastRADIUS mitigation). Every config below turns it on where
  the vendor makes it optional.

---

## Cisco IOS / IOS-XE (Catalyst)

```
radius server NACO
 address ipv4 10.0.0.10 auth-port 1812 acct-port 1813
 key S3cret!
!
radius-server attribute 8 include-in-access-req
! Message-Authenticator on every request (IOS-XE 17.x+)
radius-server attribute 80 include-in-access-req
!
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius
!
aaa server radius dynamic-author
 client 10.0.0.10 server-key S3cret!
 port 3799
!
dot1x system-auth-control
!
interface range Gi1/0/1 - 48
 switchport mode access
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 mab
 dot1x pae authenticator
```

Device-admin (TACACS+):

```
tacacs server NACO
 address ipv4 10.0.0.10
 key S3cret!
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting commands 15 default start-stop group tacacs+
```

Useful reply attributes: `Cisco-AVPair = "shell:priv-lvl=15"` (RADIUS admin
login), `Cisco-AVPair = "url-redirect=https://…"` (web redirect on WLC).

## Aruba (AOS-CX switches)

```
radius-server host 10.0.0.10 key plaintext S3cret!
radius-server host 10.0.0.10 tls disable
radius dyn-authorization enable
radius dyn-authorization client 10.0.0.10 secret-key plaintext S3cret!
aaa authentication port-access dot1x authenticator enable
aaa authentication port-access mac-auth enable

interface 1/1/1-1/1/48
    aaa authentication port-access dot1x authenticator
    aaa authentication port-access mac-auth
```

Use `Aruba-User-Role` to land clients in a locally defined role, or plain
`Tunnel-Private-Group-Id` for the VLAN.

## Juniper EX (Junos)

```
set access radius-server 10.0.0.10 secret S3cret!
set access radius-server 10.0.0.10 port 1812
set access profile NACO authentication-order radius
set access profile NACO radius authentication-server 10.0.0.10
set protocols dot1x authenticator authentication-profile-name NACO
set protocols dot1x authenticator interface ge-0/0/0.0 supplicant multiple
set protocols dot1x authenticator interface ge-0/0/0.0 mac-radius
```

## Fortinet FortiGate

```
config user radius
    edit "naco"
        set server "10.0.0.10"
        set secret S3cret!
        set radius-coa enable
        set message-authenticator enable
    next
end
config user group
    edit "employees"
        set member "naco"
        config match
            edit 1
                set server-name "naco"
                set group-name "employees"
            next
        end
    next
end
```

Return `Fortinet-Group-Name = employees` from the policy so the FortiGate
maps the session into the right firewall group.

## MikroTik RouterOS

```
/radius add service=login,wireless,dhcp address=10.0.0.10 secret=S3cret!
/radius incoming set accept=yes port=3799
```

`Mikrotik-Rate-Limit = "10M/10M"` gives per-user bandwidth caps;
`Mikrotik-Group = full` maps RADIUS admin logins to a RouterOS group.

## Ubiquiti UniFi

Network application → *Settings → Profiles → RADIUS*: create a profile with
auth/acct servers `10.0.0.10:1812/1813`, enable *RADIUS MAC authentication*
on the SSID/switch profile as needed. UniFi honours the standard Tunnel-*
VLAN attributes; per-user bandwidth uses the WISPr attributes
(`WISPr-Bandwidth-Max-Down` / `-Up`, bits per second).

## Extreme EXOS

```
configure radius netlogin primary server 10.0.0.10 1812 client-ip 10.0.0.1 vr VR-Default
configure radius netlogin primary shared-secret S3cret!
enable radius netlogin
enable netlogin dot1x mac
enable netlogin ports 1-48 dot1x mac
```

VLAN by name via `Extreme-Netlogin-Vlan`, or numerically via Tunnel-*.

## Ruckus (SmartZone / Unleashed)

Configure the AAA server under *Services → AAA*; enable 802.1X or MAC auth
per WLAN. `Ruckus-User-Groups` selects a local user-group/role.

## HPE ProCurve / ArubaOS-Switch

```
radius-server host 10.0.0.10 key S3cret!
radius-server host 10.0.0.10 dyn-authorization
aaa authentication port-access eap-radius
aaa port-access authenticator 1-48
aaa port-access mac-based 1-48
```

`HP-Privilege-Level = 15` grants manager access for RADIUS-authenticated
admin logins.

## Palo Alto (admin authentication)

*Device → Server Profiles → RADIUS* → point at NACo, then map
`PaloAlto-Admin-Role` to a local admin role profile. (PAN-OS also supports
TACACS+ against NACo for command accounting.)

---

## TACACS+ device administration

Every vendor above that supports TACACS+ (Cisco, Juniper, Aruba, Arista,
Huawei, Palo Alto, Fortinet) can point at NACo port 49. Per-command
authorization is driven by **Command Sets** in the admin UI; privilege
levels map through the TACACS+ `priv-lvl` pair. Per-device keys go in
`tacacs.clients`.

## Troubleshooting

- **Access-Request silently dropped** → the NAS is not sending
  Message-Authenticator. Fix the NAS (preferred) or set
  `radius.require_message_authenticator: false` (understand the BlastRADIUS
  risk first).
- **VLAN ignored by the NAS** → check the port/SSID actually allows dynamic
  VLANs and the VLAN exists on the switch; the NAS falls back to its default
  VLAN when the triplet is present but unusable.
- **`Failed to attach reply attribute … check the name exists`** in the NACo
  log → the attribute isn't in `naco/radius/dictionary`; add its `VENDOR` /
  `ATTRIBUTE` lines and restart.
- **CoA/Disconnect NAK or timeout** → confirm the NAS has dynamic
  authorization enabled and lists NACo's IP with the same shared secret.
