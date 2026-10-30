# Guest portal

The portal is **central web authentication** (CWA): a visitor's device joins
an open SSID or a wired port, is placed in an onboarding network, opens a
web page, accepts the terms — optionally with an access code — and is moved
to the guest network for a number of hours.

## How it works

1. The device connects; the switch or controller sends a **MAB** request.
   NACo records the MAC as a *pending* device and the policy for pending
   devices permits it into the onboarding VLAN, usually with a redirect to
   `http://<NACO_HOST>/portal`.
2. The switch's **accounting** tells NACo the device's IP address
   (Framed-IP-Address).
3. The browser opens the portal. NACo finds the device **by the browser's IP
   address** through that RADIUS session — never from anything the browser
   sends — so a guest can only ever register their own device.
4. On *Accept*, NACo registers the MAC as a guest for
   `portal.session_hours`, re-evaluates the session and disconnects it; the
   device authenticates again, now with device status **guest**, and the guest
   policy applies.
5. When the registration expires (or an administrator ends it on *Guests*),
   the session is re-evaluated again and the device falls back to the pending
   policy.

## What the network must provide

- **MAB** on the guest ports or SSID, and **accounting with interim updates
  that include Framed-IP-Address** (Cisco switches: `device-tracking`;
  wireless controllers report it by default).
- **No NAT** between the onboarding network and the NACo host: the portal
  must see the device's own address.
- From the onboarding network, only DHCP, DNS and the NACo host on TCP 80 are
  reachable; everything else is blocked or redirected to the portal.
- **Dynamic authorization** (CoA) from the NACo host, so the device can be
  moved after registration.

The portal is plain HTTP on purpose: captive-portal detection on phones and
laptops does not follow HTTPS, and nothing secret is entered. The form is
protected against cross-site requests and rate-limited per address.

## Policies

```text
50  permit  MAB, device status guest     VLAN 60   (internet only)
60  permit  MAB, device status pending   VLAN 99   + redirect attributes
```

Approved devices (printers, phones) should match an earlier policy, so they
never see the portal.

### Redirect on Cisco switches and WLCs

Add to the pending policy:

```text
Cisco-AVPair = ["url-redirect-acl=GUEST-REDIRECT", "url-redirect=http://nac.example.com/portal"]
```

and on the switch an ACL that says what is **not** redirected:

```text
ip access-list extended GUEST-REDIRECT
 deny   udp any any eq bootps
 deny   udp any any eq domain
 deny   tcp any host 10.0.0.10 eq www
 permit tcp any any eq www
ip http server
```

(`ip http server` lets the switch intercept HTTP for the redirect.) On a
9800 WLC use the same attributes with a redirect ACL defined on the
controller, and enable *RADIUS NAC* on the policy profile.

### Without redirect support

Give the onboarding VLAN a DNS server that answers every name with the NACo
host's address. NACo's web server sends any request for an unknown host name
to the portal, so the operating system's captive-portal check opens it by
itself.

## Settings

In `config/config.yaml` (`docker compose restart naco` after a change):

```yaml
portal:
  enabled: true
  organization: Example Ltd        # shown on the page
  session_hours: 8                 # how long a registration lasts
  access_code: ""                  # e.g. today's code at reception; empty = click-through
  terms: |
    By using this network you agree to …
  match_window_minutes: 15         # how fresh the RADIUS session must be
```

## When a guest is not recognized

The page says so when NACo cannot match the browser's address to a recent
RADIUS session. Check, in this order: the device is in the onboarding VLAN
(*Sessions*), the session shows an IP address (accounting with
Framed-IP-Address), and there is no NAT between the guest and NACo.
