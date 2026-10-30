# Cisco Meraki

This page covers Meraki MS switches and MR access points, configured in the
Meraki dashboard. Meraki's documents used here describe MS 17 and 18
(classic MS, with MS390 and C9300-M where noted) and MR 31 to 33. In NACo,
choose the device type **Cisco Meraki**. Catalyst switches and the 9800
controller are on the [Cisco](cisco.md) page.

## In NACo — what to enter

Under *RADIUS clients → Add client*:

| Field | What to enter |
|---|---|
| IP address or network | Every MS switch and every *gateway* MR sends RADIUS from its own LAN IP, or from its alternate management interface (AMI) if you set one up. Enter the network that holds them, for example `10.0.20.0/24` (at most /16). Repeaters (LAN IP "N/A") do not need to be covered |
| Shared secret | at least 16 characters; the same secret goes into the dashboard |
| Device type | Cisco Meraki |
| CoA port | leave empty (1700) |
| Require Message-Authenticator | on |

An exact address always wins over a network. Add a single device with its
own address when it needs other settings, for example *Require
Message-Authenticator* off. The panel then shows that device as
**Legacy NAS**.

With this device type, NACo's Disconnect-Request (RFC 5176) carries
Calling-Station-Id, NAS-IP-Address, `Cisco-AVPair` `audit-session-id` (when
the device reported one) and Message-Authenticator. Every value is exactly
as the device reported it in accounting. NACo sends only
Disconnect-Requests, never a CoA-Request: no reauthenticate, no port
bounce.

An MR accepts CoA only from the address that is configured as its RADIUS
server, and an MS probably does the same. So NACo's Disconnects must leave
the NACo host from `<naco-ip>`. Watch out for a host with several
addresses, or NAT in between.

Two dashboard features do not work with NACo:

- **The RADIUS *Test* button always fails.** It uses PEAP-MSCHAPv2, which
  NACo does not support. Test with a real client instead.
- **Leave *RADIUS proxy* off** (MR). Through the proxy, CoA does not work,
  and the requests come from Meraki's cloud instead of the access point.

## Meraki MS switches

### Access policy

*Switching > Configure > Access policies > Add an access policy*:

```text
Authentication method        my RADIUS server
RADIUS servers               Host <naco-ip>   Port 1812   Secret <shared-secret>
RADIUS testing               Enabled
RADIUS CoA support           Enabled
RADIUS accounting            Enabled
RADIUS accounting servers    Host <naco-ip>   Port 1813   Secret <shared-secret>
Host mode                    Single-Host, or Multi-Domain with IP phones
Access policy type           Hybrid authentication
Concurrent authentication    off
Guest VLAN                   (empty)
Critical Authentication VLAN <critical-vlan>
Suspend re-authentication when RADIUS servers are unreachable   on (default)
```

Then apply it to ports: *Switching > Monitor > Switch ports > Edit*, type
*access*, the access policy above, and as VLAN the one a device gets when
its policy names none, for example `<onboarding-vlan>`.

- **Hybrid authentication** tries 802.1X first. A device that fails
  802.1X, or sends no EAP within 8 seconds, falls back to MAB.
- **Concurrent authentication** runs 802.1X and MAB in parallel. Meraki
  warns that it adds load and gives odd results with ISE. Leave it off.
- **Multi-Domain** allows one data and one voice device and needs a voice
  VLAN on the port. In **Multi-Auth**, every device authenticates. On
  classic MS, all of them must get the same VLAN; MS390 and C9300-M allow
  a VLAN per session.
- **Authentication mode** is *Closed* by default. *Open* (monitor mode, as
  in the [pilot](../pilot.md)) exists only on MS130 and MS150 with MS 18.
- RADIUS timers are fixed: 3 attempts, 5 seconds timeout.

Dashboard API: `POST /networks/{networkId}/switch/accessPolicies` with
`radiusServers`, `radiusTestingEnabled`, `radiusCoaSupportEnabled`,
`radiusAccountingEnabled`, `radiusAccountingServers`, `hostMode`,
`accessPolicyType` and `radius.criticalAuth`. There is no field for the CoA
port or the accounting interval.

### When NACo cannot be reached

NACo never lets a device in without a decision. When NACo is stopped,
restarting or failing, the switch gets no answer at all. For up to one
minute after NACo stops, FreeRADIUS still answers the first steps of an
EAP exchange; after that, nothing is answered.

With *RADIUS testing* on, the switch sends an Access-Request as
`meraki_8021x_test` every 24 hours. It marks the server unavailable when
that test fails or when a client authentication to it fails. After a
failure, it tests every 60 seconds until a test passes. Any answer passes:
Accept, Reject or Challenge.

While NACo is unavailable:

- a **new client** goes to the critical VLAN;
- a **connected client** stays: *Suspend re-authentication* is on by
  default (MS390 and C9300-M always suspend);
- when NACo answers again, the switch bounces the port so the client
  authenticates again, unless *Disable port bounce* is set. Without
  *RADIUS testing*, clients stay in the critical VLAN.

The critical VLAN needs MS 14 or later. On classic MS, it works in
Single-Host, Multi-Host and Multi-Domain mode, not in Multi-Auth. A voice
critical VLAN, if you set one, must differ from the data one. MS390 and
C9300-M also offer *RADIUS caching*, which re-authorizes clients from a
cache while the server is unreachable.

### Notes

**MAB.** The switch sends the MAC as User-Name and as password, lower case
without separators (`aabbccddeeff`), with PAP. Calling-Station-Id is
`AA-BB-CC-DD-EE-FF`. Neither format can be changed. NACo recognises it as
MAB.

**VLAN.** NACo sends the policy's VLAN as a numeric ID (RFC 3580). Meraki's
*VLAN profiles* also accept VLAN names, but NACo sends only IDs.

**Accounting.** The switch sends start, stop, and an interim update every
20 minutes. The interval cannot be changed, and it is fine for NACo.

**Change of Authorization.** The switch listens on UDP **1700**; no setting
changes it. Meraki's documentation says a Disconnect is matched on
`audit-session-id` and Calling-Station-Id. The switch learns the
`audit-session-id` from the RADIUS server's Access-Accept, and NACo sends
none there. NACo's Disconnect therefore carries Calling-Station-Id and
NAS-IP-Address, as another open-source NAC (PacketFence) does for Meraki.
Meraki's port bounce is a CoA-Request, which NACo does not send. A wired
MAB device whose VLAN changes keeps its old IP address until its DHCP
lease renews or someone unplugs it.

**Reply attributes.** Add them to a policy (see [policies](../policies.md#reply-attributes)):

| Purpose | Attribute | Value |
|---|---|---|
| Group policy ACL | `Filter-Id` | the exact group policy name (case-sensitive). Set *RADIUS attribute specifying group policy name* to Filter-Id in the access policy. MS 14.5+, MS390 15.8+ |
| IP phones | `Cisco-AVPair` | `device-traffic-class=voice` — needed in Multi-Domain and Multi-Auth |
| URL redirect | `Cisco-AVPair` | `url-redirect=<url>` — MS210, 225, 250, 350, 355, 390, 410, 420, 425 and C9300-M |

A group policy name the switch does not know leaves the client
authenticated, with **all its traffic dropped**. A dynamic voice VLAN needs
MS 15 or later and a static voice VLAN on the port.

## Meraki MR access points

### SSID

*Wireless > Configure > Access control*, then select the SSID:

```text
Security                        Enterprise with my RADIUS server
RADIUS servers                  Host <naco-ip>   Port 1812   Secret <shared-secret>
RADIUS testing                  on
RADIUS CoA support              on
RADIUS proxy                    off
RADIUS accounting servers       Host <naco-ip>   Port 1813   Secret <shared-secret>
Accounting interim interval     600 seconds
RADIUS Accounting Start Delay   10 to 15 seconds (only for the guest portal)
Called Station ID               AP MAC address:SSID name (the default)
Client IP and VLAN              External DHCP server assigned, VLAN tagging on
RADIUS override                 on
```

For devices without 802.1X, use a second SSID with *Security* set to
*MAC-based access control (no encryption)* and *Splash page* set to *None
(direct access)*. The rest is the same. That SSID is open: the MR cannot
fall back from 802.1X to MAB on one SSID. Leave the *Cisco Identity
Services Engine (ISE) Authentication* splash option off.

**Adding a RADIUS server to an SSID disconnects the clients on it.** Do it
at a quiet time.

- *RADIUS override* must be on, or the AP ignores NACo's VLAN. It does not
  work in NAT mode.
- *Accounting interim interval* appears once an accounting server is saved.
  It needs MR 28 or later on every AP. Any value up to 6 hours works with
  NACo, which closes a session that has had no accounting for 24 hours.
- *RADIUS Accounting Start Delay* (0 to 60 seconds, MR 28 and later)
  delays the accounting start, so that it carries the client's DHCP
  address. Without it, the start carries no Framed-IP-Address. Only the
  [guest portal](../guest-portal.md) needs that address.
- Keep the default *Called Station ID*. A custom template (for example the
  SSID number) gives NACo a wrong SSID, or none.

Dashboard API: `PUT /networks/{networkId}/wireless/ssids/{number}` with
`authMode` (`8021x-radius`, or `open-with-radius` for MAC-based),
`radiusServers`, `radiusTestingEnabled`, `radiusCoaEnabled`,
`radiusProxyEnabled`, `radiusAccountingEnabled`,
`radiusAccountingServers`, `radiusAccountingInterimInterval`,
`radiusAccountingStartDelay`, `radiusOverride` and
`radiusCalledStationId`.

### When NACo cannot be reached

- **802.1X SSIDs have no critical VLAN.** New clients cannot connect while
  NACo cannot decide.
- **MAC-based SSIDs** have *RADIUS Guest VLAN* (MR 27.2 and later). A
  client goes there when it is rejected *or* when the server is
  unreachable. It works as a critical VLAN, but devices NACo rejects (a
  blocked device, for example) land there too. Choose a VLAN that is safe
  for them.
- With several RADIUS servers, *RADIUS fallback* (going back to a
  higher-priority server) relies on Status-Server. NACo answers
  Status-Server only while it can decide.
- *RADIUS testing* works as on MS: any answer counts as alive.

### Notes

**MAB.** User-Name and password are the MAC, lower case without separators
(`aabbccddeeff`). Calling-Station-Id is `AA-BB-CC-DD-EE-FF`. The AP sends no
Service-Type unless the ISE splash option is on. NACo recognises MAB from
the MAC in User-Name and the same MAC as password.

**SSID.** Called-Station-Id is the AP's MAC and the SSID name
(`AA-BB-CC-DD-EE-FF:Corp`), which NACo reads.

**VLAN.** NACo sends a numeric VLAN ID (RFC 3580); *RADIUS override* must
be on.

**Change of Authorization.** It needs MR 24 or later. It does not work in
repeater mode or through the RADIUS proxy. NACo sends the Disconnect to
the AP that serves the client. Meraki matches a Disconnect on
`audit-session-id` and Calling-Station-Id, but the AP generates an
`audit-session-id` only with the ISE splash option. NACo's Disconnect
therefore carries Calling-Station-Id and NAS-IP-Address. Before MR 32.1,
turning on CoA disables fast roaming (PMKSA, OKC, 802.11r), so every roam
is a full 802.1X authentication.

**Reply attributes.** For a group policy, set *RADIUS attribute specifying
group policy name* to Filter-Id on the SSID. Then send `Filter-Id` with
the exact name of a group policy from *Network-wide > Group policies*.

## Switch logins (TACACS+)

Not applicable. MS switches and MR access points have no device command
line; you manage them only in the dashboard.

## Verify

In the dashboard:

- *Wireless > Monitor > Access points*: add the *LAN IP* column. These are
  the addresses NACo must cover.
- *Network-wide > Monitor > Event log*: 802.1X and MAC authentication
  events. On MS, "802.1X Canned EAP Success" means the switch put the
  client in the critical, guest or failed-authentication VLAN.
- *Network-wide > Monitor > Packet capture* on the switch uplink or the
  AP's wired interface, with the filter:

  ```text
  ip.addr==<naco-ip> && radius
  ```

- *Switching > Switches >* (the switch) *> Tools > Ping* to `<naco-ip>`.

In NACo: *Logs* for every decision (the SSID column shows the SSID name),
*Sessions* for the result of each Disconnect, and
`docker compose logs freeradius`. An *unknown client* there means a device's
address is not covered by any RADIUS client.

## Check in the pilot

- **MS and MR acknowledge NACo's Disconnect.** It carries
  Calling-Station-Id and NAS-IP-Address, and no `audit-session-id`. Approve
  or block a test device, check the result in *Sessions*, and check that
  the client authenticates again.
- **MR CoA port.** Meraki says 1700 for ISE and 3799 for other servers.
  NACo uses 1700 for Meraki. If Disconnects get no answer, try 3799 in the
  RADIUS client.
- **MS accepts CoA only from the configured RADIUS server address.** Meraki
  documents this for MR only.
- **MS MAB requests carry a Message-Authenticator.** It is not documented.
  If NACo drops them (`docker compose logs freeradius`), add that switch
  with its own address and *Require Message-Authenticator* off.
- **MR firmware before 32.1.3** (Wi-Fi 6, 6E and 7 models): MAC
  authentication failed when the Access-Accept carried no
  Message-Authenticator. Check that MAB works on older firmware.
- **Framed-IP-Address in MS accounting** (guest portal on MS ports only).
  Meraki does not document it. Check *Sessions* or a packet capture.
- **Framed-IP-Address in MR interim updates**, and the default interim
  interval (set it explicitly as above).
- **Critical VLAN with Multi-Auth on MS 18.** The access-policy page says
  no, the MS 18 features list says yes.
- **Server-dead behaviour on MS.** Stop NACo, wait more than a minute,
  connect a new client: it must land in the critical VLAN. Start NACo: the
  port must bounce and the client authenticate again.
- **Connected MR clients while NACo is down**: what happens when they
  re-authenticate or roam is not documented.
- **CoA with 802.11r on MR 32.1.** Meraki lists ISE 3.3 Patch 5 or later as
  a requirement. Behaviour with other servers is unknown.
- **URL redirect on MS390 and C9300-M** also needs a walled-garden ACL
  (`Walled-Garden-00`, `-01`, …). The attribute that carries its name is
  not documented.

## References

- [MS switch access policies (802.1X)](https://documentation.meraki.com/Switching/MS_-_Switches/Design_and_Configure/Configuration_Guides/Access_Control/MS_Switch_Access_Policies_(802.1X))
- [Change of Authorization with RADIUS (CoA) on MS switches](https://documentation.meraki.com/Switching/MS_-_Switches/Design_and_Configure/Configuration_Guides/Access_Control/Change_of_Authorization_with_RADIUS_(CoA)_on_MS_Switches)
- [Meraki MS group policy access control lists](https://documentation.meraki.com/Switching/MS_-_Switches/Design_and_Configure/Configuration_Guides/Access_Control/Meraki_MS_Group_Policy_Access_Control_Lists)
- [Alternate management interface on MS devices](https://documentation.meraki.com/Switching/MS_-_Switches/Operate_and_Maintain/How-Tos/Alternate_Management_Interface_on_MS_Devices)
- [MS firmware features directory](https://documentation.meraki.com/Platform_Management/Product_Information/Compatibility_and_Firmware/MS_Firmware_Features_Directory)
- [MR Meraki RADIUS 2.0](https://documentation.meraki.com/Wireless/Design_and_Configure/Configuration_Guides/Access_Control/MR_Meraki_RADIUS_2.0)
- [Change of Authorization with RADIUS (CoA) on MR access points](https://documentation.meraki.com/Wireless/Design_and_Configure/Configuration_Guides/Encryption_and_Authentication/Change_of_Authorization_with_RADIUS_(CoA)_on_MR_Access_Points)
- [Configuring RADIUS authentication with WPA2-Enterprise](https://documentation.meraki.com/MR/Encryption_and_Authentication/Configuring_RADIUS_Authentication_with_WPA2-Enterprise)
- [Enabling MAC-based access control on an SSID](https://documentation.meraki.com/MR/Encryption_and_Authentication/Enabling_MAC-based_access_control_on_an_SSID)
- [MR RADIUS troubleshooting](https://documentation.meraki.com/MR/Wireless_Troubleshooting/MR_RADIUS_Troubleshooting)
- [MR firmware release notes](https://documentation.meraki.com/Wireless/Product_Information/Compatibility_and_Firmware/MR_Firmware_Release_Notes)
- [Meraki Dashboard API: create a switch access policy](https://developer.cisco.com/meraki/api-v1/create-network-switch-access-policy/), [update a wireless SSID](https://developer.cisco.com/meraki/api-v1/update-network-wireless-ssid/)
