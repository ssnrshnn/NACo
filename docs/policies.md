# Policies

## How a decision is made

For every Access-Request NACo works through three steps; *Logs* records
the outcome and the reason for each one.

1. **Identity.** The user is checked first: password (local bcrypt or an
   LDAP bind), certificate (EAP-TLS: the certificate's CN must be an enabled
   NACo user) or, for MAB, the MAC address — which must equal the
   Calling-Station-Id. Unknown or disabled users and wrong passwords are
   rejected here.
2. **Hard rules.** A blocked device is always rejected; so is a request from
   a disabled RADIUS client.
3. **Policies**, in order from the top: the first policy whose conditions
   all match decides — *permit* (with an optional VLAN and reply attributes)
   or *deny*. **Nothing matches → deny.**

The *Simulator* runs steps 2 and 3 for an imagined request and shows every
policy it tried and which condition failed.

## Conditions

All conditions of a policy must hold. Text comparisons ignore case;
`matches` takes shell-style wildcards (`*`, `?`, `[…]`).

| Condition | Operators | Example |
|---|---|---|
| always | | a final catch-all |
| username | equals, not equals, in, matches | `matches svc-*` |
| group | in, not in | `in staff, contractors` |
| method | in | `EAP-TLS`, `EAP-TTLS`, `PEAP`, `PAP`, `MAB` |
| device status | in | `approved`, `pending`, `guest` |
| device type | in, not in | `printer`, `phone` (set on the device) |
| vendor | in, matches | `matches *Cisco*` (from the MAC's OUI) |
| MAC | equals, in, matches | `matches 00:1b:63:*` |
| RADIUS client | in, not in | switch names |
| SSID | in, not in, matches | from Called-Station-Id |
| time | between, on chosen days | `08:00–18:00 mon–fri`; overnight `22:00–06:00` works (server time zone) |

**Device status** is `approved` or `pending` for devices NACo knows (every
MAC it sees is recorded as pending first), and `guest` for a device that
registered on the guest portal and whose registration has not expired.

## Typical policy sets

```text
10  deny    group in contractors, time 20:00–07:00
20  permit  method in EAP-TLS                        VLAN 20   (managed laptops)
30  permit  group in staff                           VLAN 20
40  permit  MAB, device status approved, type printer VLAN 40
50  permit  MAB, device status guest                 VLAN 60   (guest internet)
60  permit  MAB, device status pending               VLAN 99   (onboarding / portal)
```

Pending devices land in an onboarding VLAN until someone approves them on
*Devices* — or until they register on the guest portal, which moves them to
the guest policy.

## Reply attributes

A permit can add RADIUS attributes to the Access-Accept — a role, an ACL,
a session timeout. Names are those of FreeRADIUS' dictionaries (the editor
refuses unknown names and suggests the closest one); values are text or
numbers, and a list sends the attribute several times. The VLAN attributes
come from the VLAN field; attributes that belong to the protocol itself
(Message-Authenticator, EAP, MS-MPPE keys, …) cannot be set.

## Changes take effect on live sessions

Saving a policy, reordering, approving or blocking a device, disabling a
user or a guest registration expiring makes NACo re-evaluate the active
sessions. Only sessions whose decision changed (other result, VLAN or
attributes) are disconnected; the device re-authenticates and receives the
new decision. If the policy set cannot be loaded, NACo denies new requests
and disconnects nothing.
