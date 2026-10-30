# TP-Link Omada

This page covers TP-Link Omada switches and EAP access points managed by an
Omada controller (6.1 and 6.2). Choose the device type **Standard (RFC
5176)**. Every switch and EAP sends RADIUS from its own address, so one NACo
client with a network covers them all. Some features need a recent
controller and matching device firmware:

- Disconnect on switches: controller 6.1 or later;
- Guest VLAN, NAS ID, *Require Message-Authenticator* and VLAN assignment
  on MAC-based switch ports: controller 6.2 or later.

Agile switches do not support 802.1X.

## In NACo — what to enter

*RADIUS clients → Add client*:

- **IP address or network** — a network that covers every Omada switch and
  EAP, for example `10.0.20.0/24` (at most a /16). NACo sends each
  Disconnect-Request to the device that reported the session.
- **Shared secret** — 16 characters or more, without `?`, `"`, `%` or `\`.
  TP-Link warns that these characters may break RADIUS. The *Generate*
  button uses only letters and digits.
- **Device type** — Standard (RFC 5176). Its Disconnect-Request carries
  Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address and
  NAS-Identifier as the device reported them, plus Event-Timestamp and
  Message-Authenticator.
- **CoA port** — 3799.
- **Require Message-Authenticator** — start with it on. TP-Link itself
  notes that non-EAP requests "typically do not include" the attribute, so
  switch MAB may arrive without it. If MAB requests get no answer and
  `docker compose logs freeradius` reports a missing Message-Authenticator,
  switch it off (*Legacy NAS*). To do that for one switch only, give the
  switch its own address entry; an address overrides the network.
- **Accounting** — interim updates every 360 minutes or less. NACo closes a
  session that has had no accounting for 24 hours.

NACo sends only Disconnect-Requests, never a CoA-Request. Users
authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## RADIUS profile

*Network Settings → Profile → RADIUS Profile → Create New RADIUS Profile*
(some 6.x guides show *Network Config → RADIUS Profile*):

```text
Name:                          NACo
Authentication Server IP/URL:  <naco-ip>   Port 1812   Password <shared-secret>
RADIUS Accounting:             on — <naco-ip>  1813  <shared-secret>, Interim Update on
VLAN Assignment (wireless):    on
RADIUS CoA:                    on — CoA password <shared-secret>
```

- **RADIUS CoA** has its own password. Set it to the same shared secret:
  NACo signs its Disconnect-Requests with the client's shared secret.
- Set the interim interval to about 300 seconds.
- A profile takes up to four authentication servers.
- The profile's own *Require Message-Authenticator* makes the device drop
  replies without the attribute. NACo's replies always carry it.
- Do not turn on RadSec; NACo does not offer it.

## Switches

*Network Settings → Authentication → 802.1X*:

```text
802.1X:                   on
RADIUS Profile:           NACo
Authentication Protocol:  EAP
Authentication Type:      MAC-Based
VLAN Assignment:          on
MAB Format:               aabbccddeeff
+ Add → switch → ports → Authentication Mode: Both
```

- **Authentication Protocol: EAP.** PAP mode turns EAP into PAP, which
  breaks EAP-TLS, EAP-TTLS and PEAP.
- **MAC-Based** authenticates each client. *Port-Based* opens the port for
  all clients after the first one.
- **Both**: 802.1X first. If a client does not start 802.1X, or fails it,
  the port tries MAB every 30 seconds.
- The port profile's 802.1X Control stays at **Auto** (the default in
  controller mode).
- **MAC address**: the switch sends the MAC as user name and password. All
  six MAB formats work with NACo.
- **VLAN**: VLAN Assignment on MAC-Based ports needs controller 6.2;
  before that it works on Port-Based ports only. Send numeric IDs. Do not
  assign the Default Network's VLAN dynamically; TP-Link warns of network
  problems.
- **Disconnect**: needs switch firmware recommended for controller 6.1 or
  later. After NACo moves a MAC-authenticated device to another VLAN, the
  device keeps its old IP address until its DHCP lease renews.
- **When NACo cannot be reached**: TP-Link documents no critical VLAN. The
  *Guest VLAN* (6.2) is "for guest clients whose authentication fails or
  times out"; whether that covers a silent NACo is not documented.

## EAPs (wireless)

1. 802.1X: create the WLAN with Security **WPA-Enterprise** and select the
   NACo profile.
2. MAC authentication: *Network Config → MAC-Based Authentication*. Tick
   it, select the SSIDs, the NACo RADIUS profile and a **MAC Address
   Format**. All six formats work with NACo. NACo accepts the MAC or an
   empty password, so **Empty Password** can stay as it is.

- MAC authentication comes before WPA, and WPA before the portal. A MAC
  Filter overrides MAC authentication.
- Disconnect works for WPA-Enterprise, MAC-based authentication and PPSK on
  EAPs.
- **VLAN**: *VLAN Assignment* in the RADIUS profile. Not for portal or
  RADIUS hotspot clients.
- **SSID**: TP-Link does not document the Called-Station-Id format. NACo
  reads the SSID from Called-Station-Id (`<MAC>:<SSID>`) or from
  `TP-CAPWAP-SSID`. Check that *Logs* shows it before you write SSID
  conditions.
- The default NAS-Identifier is `TP-Link_<AP model>_<AP MAC>_NAS`. It does
  not matter to NACo, which identifies the device by its address.
- **When NACo cannot be reached**: there is no critical VLAN. New clients fail
  to connect.

## Reply attributes

TP-Link documents only the VLAN (`Tunnel-Type`, `Tunnel-Medium-Type`,
`Tunnel-Private-Group-Id`, which NACo sends from the policy's VLAN field).
FreeRADIUS has TP-Link attributes (`TPLink-Recv-limit`,
`TPLink-Xmit-limit`, `TPLink-Redirect-Url` and others), but TP-Link does
not say which of them its switches and EAPs apply to 802.1X or MAC
authentication; they look meant for the portal. Whether `Filter-Id` or
`Session-Timeout` apply is not documented.

## Switch logins (TACACS+)

TP-Link has a guide, *How to Configure TACACS+ Authentication on Switches
via Omada Controller*. It is not covered here; for NACo's side see
[TACACS+](../tacacs.md).

## Verify

- In the controller: the *Clients* page shows each client and its network.
- On a switch: *Tools → Terminal*, device type *Switch*, then
  `show dot1x auth-state`. TP-Link's older stand-alone guide also uses:

  ```text
  show dot1x global
  show dot1x interface
  show aaa group radius
  show vlan
  ```

Then check in NACo:

1. *Logs* shows one MAB and one 802.1X decision for a switch port and for
   an SSID.
2. *Sessions* shows each session with Start and interim updates.
3. *Sessions → Disconnect* returns ACK, and the client authenticates again.
4. Stop NACo (`docker compose stop naco`) and wait a minute: FreeRADIUS
   keeps answering the first steps of an EAP exchange for up to a minute,
   then does not answer at all. Connect a new client and note what the
   switch and the EAP do. Start NACo again.

## Check in the pilot

- **Disconnect**: TP-Link does not say which attributes it uses to find the
  session. The CoA port 3799 comes from a third-party page.
- **Message-Authenticator**: whether switch MAB and EAP MAC authentication
  carry it.
- **Guest VLAN**: whether it applies when NACo does not answer. A 2017
  TP-Link guide for stand-alone switches says MAB works only with the Guest
  VLAN disabled; test MAB with the Guest VLAN on.
- **Dynamic VLANs on switch ports**: TP-Link's older guide also adds the
  VLANs NACo assigns to the port profile's untagged networks. Try that if
  the VLAN does not apply.
- **SSID and Calling-Station-Id**: neither format is documented. NACo
  requires the MAB user name to be the same MAC as Calling-Station-Id, so
  check that MAB succeeds and *Logs* shows the SSID.
- **Client IP for the guest portal**: whether accounting carries
  Framed-IP-Address is not documented. Check *Sessions* before you use the
  [guest portal](../guest-portal.md).
- **Interim interval**: its range and default are not documented.
- **Outages**: what connected clients do when they re-authenticate while
  NACo is silent.

## References

- [How to build an 802.1X access authentication system using switches in Omada Controller](https://support.omadanetworks.com/us/document/12898/)
- [How to configure MAC-based authentication on Omada Controller](https://support.omadanetworks.com/us/document/13321/)
- [How to configure 802.1X VLAN assignment on Omada Controller](https://support.omadanetworks.com/us/document/13239/)
- [How to troubleshoot 802.1X authentication failures on Omada switches](https://support.omadanetworks.com/us/document/13180/)
- [How to troubleshoot RADIUS authentication failures on Omada networks](https://support.omadanetworks.com/us/document/13177/)
- [Omada Open API 6.2.14: RADIUS profiles](https://omada-northbound-docs.tplinkcloud.com/openapi/oc/6.2.14/04.4%20Site%20Network%20Setting-Profiles.html)
