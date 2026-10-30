# Ubiquiti UniFi

This page covers UniFi switches and access points managed by the UniFi
Network application 9.x and 10.x. Choose the device type **Standard (RFC
5176)**. Every UniFi AP and switch sends RADIUS from its own address, so one
NACo client with a network covers them all. You administer UniFi devices
through UniFi accounts, so TACACS+ does not apply.

## In NACo — what to enter

*RADIUS clients → Add client*:

- **IP address or network** — a network that covers every UniFi AP and
  switch, for example the management network `10.0.20.0/24` (at most a /16).
  NACo sends each Disconnect-Request to the device that reported the
  session.
- **Shared secret** — 16 characters or more.
- **Device type** — Standard (RFC 5176). Its Disconnect-Request carries
  Acct-Session-Id, User-Name, Calling-Station-Id, NAS-IP-Address and
  NAS-Identifier as the AP reported them, plus Event-Timestamp and
  Message-Authenticator.
- **CoA port** — 3799.
- **Require Message-Authenticator** — leave on. Ubiquiti says nothing about
  it. If a device's MAC authentication gets no answer and `docker compose
  logs freeradius` reports a missing Message-Authenticator, update its
  firmware or switch the option off (*Legacy NAS*). A device with its own
  address entry overrides the network, so you can do this for one device.
- **Accounting** — interim updates every 360 minutes or less (300 in the
  profile below). NACo closes a session that has had no accounting for 24
  hours.

NACo sends only Disconnect-Requests, never a CoA-Request. Users
authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## RADIUS profile

*Settings → Networks → RADIUS Servers → Create New* (older releases:
*Settings → Profiles → RADIUS*):

```text
Name:                          NACo
Authentication server:         <naco-ip>  port 1812  secret <shared-secret>
Accounting server:             <naco-ip>  port 1813  secret <shared-secret>
Accounting Interim Interval:   300
RADIUS Assigned VLAN Support:  Wired Networks and Wireless Networks
```

- Ubiquiti recommends a short interim interval, about 300, when you use
  CoA. Its article gives the unit as ms, but the controller accepts
  60–86400, so it is most likely seconds.
- **RADIUS Assigned VLAN Support** must be on, or the VLAN from NACo is not
  applied. For wireless, keep the VLAN mode optional, not required: with
  required, a permit without a VLAN fails.
- Do not turn on RADIUS over TLS (RadSec); NACo does not offer it.

## Switches

1. *Settings → Networks → Global Switch Settings*: turn on **802.1X
   Control** and select the NACo profile. To change one switch only:
   *Devices → <switch> → Settings → Override Global Switch Settings*.
2. *Settings → Profiles → Ethernet Ports*: create a port profile with
   Primary Network = `<onboarding-vlan>` and **802.1X Control: MAC-based**.
3. *UniFi Devices → <switch> → Port Manager*: select the port, set its
   Ethernet Port Profile to the new profile, and apply.

- **MAC-based** is the only mode documented to do both 802.1X and MAC
  authentication for each client. With *Credentials*, one authenticated
  client opens the port for all.
- **MAC address**: the switch sends the MAC as user name and password, as
  12 hex digits without separators. NACo accepts it in either case.
- **VLAN**: send numeric IDs; the VLAN must exist as a UniFi network.
  Without a VLAN from NACo, the client gets the port's Primary Network.
- **Disconnect**: Ubiquiti documents no CoA for switches. A new NACo
  decision reaches a wired session only when the client connects or
  authenticates again.
- **When NACo cannot be reached**: new clients get no access. 802.1X Control
  also has a *Fallback VLAN*, but Ubiquiti does not say when it applies
  (see *Check in the pilot*).

## Access points

1. *Settings → WiFi → <SSID>*: Security Protocol **WPA2 Enterprise** or
   **WPA3 Enterprise**, and select the NACo profile.
2. For devices without 802.1X: on the SSID, turn on **RADIUS MAC
   Authentication** and choose a **MAC Address Format**. All six formats
   work with NACo. NACo accepts the MAC or an empty password, so UniFi's
   empty-password option can stay as it is.
3. On each Enterprise SSID, turn on **DAS/DAC (CoA)** so the APs accept
   Disconnect-Requests. This needs the accounting server, a short interim
   interval, and UDP 3799 open between NACo and the APs.

- **SSID**: a third-party trace shows the APs sending Called-Station-Id as
  `B4-FB-E4-48-F2-B0:<SSID>`. NACo reads the SSID from it.
- **NAS-Identifier** can be chosen per SSID. It does not matter to NACo,
  which identifies the device by its address.
- **VLAN**: without a VLAN from NACo, the client stays in the SSID's
  network.
- **Firmware**: use current AP firmware. 8.5.18 (U7/E7) fixed CoA
  re-authentication timeouts. 8.7.11 sends Accounting-Stop on reboot and
  upgrade. 8.0.77 (U7-LR) fixed MLO clients losing connectivity with
  dynamic VLANs.
- **When NACo cannot be reached**: there is no critical VLAN. New clients fail
  to connect. A second authentication server in the profile gives failover.

## Reply attributes

Ubiquiti documents only the VLAN (`Tunnel-Type`, `Tunnel-Medium-Type`,
`Tunnel-Private-Group-Id`, which NACo sends from the policy's VLAN field).
FreeRADIUS has no Ubiquiti dictionary, so NACo cannot send Ubiquiti vendor
attributes. Whether UniFi applies `Filter-Id` or `Session-Timeout` is not
documented.

## Verify

1. *Logs* shows one MAB and one 802.1X decision for a switch port and for an
   SSID. On wireless, the SSID is filled in.
2. The UniFi *Clients* list shows each client in the network NACo chose.
3. *Sessions* shows the wireless session with Start and interim updates.
4. *Sessions → Disconnect* on a wireless session returns ACK, and the
   client reconnects.
5. Stop NACo (`docker compose stop naco`) and wait a minute: FreeRADIUS
   keeps answering the first steps of an EAP exchange for up to a minute,
   then does not answer at all. Connect a new client: it gets no access
   (or, on a switch, the Fallback VLAN if that applies). Start NACo again.

## Check in the pilot

- **Disconnect on APs**: Ubiquiti lists as required "User-Name,
  Framed-IP-Address, Calling-Station-ID, etc", Acct-Session-Id,
  NAS-IP-Address and NAS-Identifier. It does not say whether that list is
  for the Disconnect-Request or for the server's session data. NACo sends
  all of them except Framed-IP-Address. Check that the AP ACKs.
- **Switches**: whether they send accounting at all, and confirm that they
  take no Disconnect.
- **Fallback VLAN**: whether it applies to rejected clients, to clients
  without 802.1X, or when NACo does not answer.
- **Message-Authenticator**: whether switch MAB and AP MAC authentication
  carry it. Check `docker compose logs freeradius`.
- **SSID**: the Called-Station-Id format comes from a third-party trace.
  Check that *Logs* shows the SSID.
- **Client IP for the guest portal**: whether AP accounting carries
  Framed-IP-Address is not documented. Check *Sessions* before you use the
  [guest portal](../guest-portal.md).
- **Labels and units**: the exact wording of the wireless VLAN mode
  (optional or required) and of the empty-password option, and whether the
  interim interval is in seconds.
- **Known issues** (third-party): a MAC-based port profile sometimes takes
  effect only after 802.1X Control is set to Force Authorized and back. The
  built-in ports of UDM and UDR gateways may not support 802.1X.
- **Outages**: what connected clients do when they re-authenticate while
  NACo is silent.

## References

- [Configuring a RADIUS server in UniFi](https://help.ui.com/hc/en-us/articles/360015268353)
  (RADIUS profile, CoA, VLAN support)
- [MAC-based VLAN assignment using 802.1X in UniFi Network](https://help.ui.com/hc/en-us/articles/115004589707)
- [UniFi switch settings](https://help.ui.com/hc/en-us/articles/33402927617047)
- [UniFi WiFi SSID and AP settings overview](https://help.ui.com/hc/en-us/articles/32065480092951)
- [UniFi AP and switch firmware release notes](https://community.ui.com/rss/releases/UAP-USW-Firmware/9fc3b2fa-9e73-449a-924f-470e79884470)
