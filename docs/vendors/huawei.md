# Huawei

This page covers Huawei S-series campus switches (S5700, S5720, S12700 and
similar) and CloudEngine S switches on VRP, with NAC in unified mode. The
commands come from V200R0xx material. Nothing here has been confirmed for
V600R0xx (CloudEngine S "YunShan"). Choose the device type
**Standard (RFC 5176)**.

Huawei's own documentation could not be read for this page. It rests on
Huawei troubleshooting pages, a 2016 interoperability report, and
OpenNAC's Huawei page; the last two are third-party sources. Test every
step in [a pilot](../pilot.md) before you rely on it, and see
[Check in the pilot](#check-in-the-pilot).

## In NACo — what to enter

*RADIUS clients → Add client*:

| Field | Value |
|---|---|
| Name | e.g. `s5720-floor1` |
| IP address or network | the address the switch sends RADIUS from (`display radius-server configuration template NACO` shows it as *Source IP*) |
| Shared secret | 16+ characters, the same as `shared-key` on the switch |
| Device type | Standard (RFC 5176) — Huawei, … |
| CoA port | 3799 |
| Require Message-Authenticator | on; see the note below |

With the Standard type, a disconnect request carries Acct-Session-Id,
User-Name, Calling-Station-Id, NAS-IP-Address and NAS-Identifier, each
exactly as the switch reported it in accounting and only when it did, plus
Event-Timestamp and Message-Authenticator.

NACo sends only Disconnect-Requests, never a CoA-Request, so it cannot
bounce a port. A wired MAC-authenticated device (a printer) that NACo moves
to another VLAN keeps its old IP address until its DHCP lease renews.

Users authenticate with EAP-TLS, EAP-TTLS with PAP, or PEAP with GTC;
PEAP-MSCHAPv2 is not supported ([802.1X and certificates](../eap.md)).

## S-series and CloudEngine S (VRP)

Check the NAC mode first: `display authentication mode`. The configuration
below is for **unified mode**, which Huawei's examples describe as the
default. Changing the mode needs a save and a reboot.

```text
radius-server template NACO
 radius-server shared-key cipher <shared-secret>
 radius-server authentication <naco-ip> 1812 weight 80
 radius-server accounting <naco-ip> 1813 weight 80
 undo radius-server user-name domain-included
#
radius-server authorization <naco-ip> shared-key cipher <shared-secret>
#
aaa
 authentication-scheme NACO-AUTH
  authentication-mode radius
 accounting-scheme NACO-ACCT
  accounting-mode radius
 domain NACO
  authentication-scheme NACO-AUTH
  accounting-scheme NACO-ACCT
  radius-server NACO
#
dot1x-access-profile name NACO-D1X
 dot1x authentication-method eap
#
mac-access-profile name NACO-MAC
#
authentication-profile name NACO
 dot1x-access-profile NACO-D1X
 mac-access-profile NACO-MAC
 access-domain NACO force
 authentication event authen-server-down action authorize vlan <critical-vlan>
 authentication event authen-server-up action re-authen
#
interface GigabitEthernet0/0/1
 port link-type hybrid
 port hybrid pvid vlan <onboarding-vlan>
 port hybrid untagged vlan <onboarding-vlan>
 authentication-profile NACO
```

- `undo radius-server user-name domain-included` — by default the switch
  adds the domain to the user name. Without this line the user name would
  carry `@NACO` and match neither NACo users nor MAC addresses.
- `dot1x authentication-method eap` — **required.** The switch must relay
  EAP to NACo. In common mode the default is CHAP (the switch ends EAP
  itself), which NACo cannot use.
- `radius-server authorization` — lets NACo send disconnect requests.
  Huawei S switches listen on UDP 3799, NACo's default CoA port.
- The `authentication event` lines come from OpenNAC's tested
  configuration (V200R011C10 and V200R022C00), not from Huawei.

### Accounting

`accounting-mode radius` in the accounting scheme turns RADIUS accounting
on. NACo needs interim updates at least every 360 minutes, because it
closes sessions that have had no accounting for 24 hours. Once a session is closed, a later policy
change no longer reaches it. The interim-update command was not confirmed;
see the pilot list.

Framed-IP-Address is needed only for the [guest portal](../guest-portal.md).
OpenNAC adds `authentication update-ip-accounting enable` to the
authentication profile, so the switch sends an accounting update once it
learns the client's IP address. That presumably needs DHCP snooping or IP
learning on the access VLANs.

### When NACo cannot be reached

When NACo cannot decide (host down, NACo stopped, restarting or failing),
FreeRADIUS does not answer at all, not even Status-Server probes.
`display radius-server configuration` shows the switch's defaults: timeout
5 seconds, 2 retransmissions, dead time 5 minutes, detect interval 60
seconds. Once the switch marks NACo dead, `authen-server-down action
authorize vlan` puts devices that authenticate in the critical VLAN.
`authen-server-up action re-authen` makes them authenticate again when
NACo is back.

To test, stop NACo (`docker compose stop naco`) and wait a minute before
you connect a device: FreeRADIUS keeps answering the first steps of an EAP
exchange for up to a minute, then goes silent.

### Notes

- **MAC format.** By default MAC authentication sends the MAC as
  User-Name and password, lowercase without separators (`0005e01c02e3`).
  The other `mac-authen username macaddress format` choices work too:
  `with-hyphen` (`0005-e01c-02e3`) and `with-hyphen normal`
  (`00-05-e0-1c-02-e3`, V200R009 and later). Calling-Station-Id defaults to
  `xxxx-xxxx-xxxx`, which NACo accepts, so no format change is needed. The
  interoperability report used `calling-station-id mac-format hyphen-split
  mode2` in the template (`xx-xx-xx-xx-xx-xx`); NACo accepts that as well.
- **PAP or CHAP for MAC authentication.** Either works. NACo treats a
  request as MAB when the user name is a MAC and the password is the same
  MAC, empty, or absent. The interoperability report sets
  `radius-attribute set Service-Type 10` (Call-Check) in the template for
  another RADIUS server; NACo does not need it.
- **Message-Authenticator.** Whether the switch includes it in MAC and
  password requests is not known. If those requests go unanswered and
  `docker compose logs freeradius` reports a missing Message-Authenticator,
  switch *Require Message-Authenticator* off for this client. The panel then
  shows it as **Legacy NAS**.
- **VLAN.** NACo sends the policy's VLAN as a number. That worked in the
  interoperability report. The VLAN must exist on the switch.
- **Reply attributes.** `Filter-Id` with an ACL number (the report used
  ACL 3000). FreeRADIUS also knows `Huawei-Data-Filter`,
  `Huawei-Ext-Specific`, `Huawei-PortalURL`, `Huawei-HTTP-Redirect-URL`,
  `Huawei-Web-URL` and `Huawei-Domain-Name`; check what each does on your
  release. Huawei's UCL and user-group attributes are not in FreeRADIUS'
  dictionary, so the policy editor refuses them and you cannot use them.

## Switch logins (TACACS+)

Huawei switches log administrators in over HWTACACS, Huawei's TACACS+
implementation. Its configuration guide could not be read for this page, so
no configuration is given here: follow the HWTACACS chapter of your
release's configuration guide.

In NACo, add the switch under *TACACS+ clients* with its source address and
key, and give the administrators' group a *device-admin privilege* and,
optionally, a command set ([TACACS+](../tacacs.md)). Expect the switch to
ask for the `shell` service; NACo answers with `priv-lvl=<group's level>`
and checks each command it is asked about against the group's command set.
*Logs → TACACS+* shows what the switch asks for — if it is another service,
add that service's lines to the group.

Keep a local administrator account, and test from a second session before
you close the first.

## Verify

```text
display authentication mode
display radius-server configuration template NACO
test-aaa <user> <password> radius-template NACO
display radius-server authorization configuration
display authentication-profile configuration name NACO
display dot1x-access-profile configuration name NACO-D1X
display mac-access-profile configuration name NACO-MAC
display authentication interface GigabitEthernet0/0/1
```

`test-aaa` reports *Account test succeed!* for a valid NACo user, and the
attempt appears in *Logs*. If it gets no answer, check
`docker compose logs freeradius` (see Message-Authenticator above). In
NACo, *Sessions* shows the result of each disconnect.

## Check in the pilot

- **Sources.** Huawei's documentation blocks automated reading. This page
  rests on readable Huawei troubleshooting pages, on search-engine extracts
  of Huawei pages, and on two third-party sources: a 2016 Tolly
  interoperability report (Huawei-sponsored; Huawei S with Cisco ISE,
  V200R010) and OpenNAC's Huawei integration page (V200R011C10,
  V200R022C00). Treat every command as needing a test on your release.
- **V600R0xx (CloudEngine S).** Not checked at all.
- **Unified mode.** Confirm it is the default on your release, and that a
  mode change needs a save and a reboot.
- **RADIUS source address.** The command that sets it was not confirmed.
  Use the *Source IP* from `display radius-server configuration template
  NACO`.
- **Message-Authenticator** in MAC-authentication and `test-aaa` requests.
- **Interim accounting.** Reportedly `accounting realtime <minutes>` in
  the accounting scheme; the syntax is not confirmed.
- **Framed-IP-Address.** `authentication update-ip-accounting enable`
  (OpenNAC) and the DHCP snooping or IP learning it needs.
- **Disconnect.** Whether the switch accepts the Standard type's
  attributes. Whether it requires NAS-IP-Address. Whether the
  `match-type` of `radius-server authorization` defaults to *any*.
  Whether newer releases also need `radius-server authorization
  server-source …`. The switch reportedly parses Calling-Station-Id in a
  disconnect as `xxxxxxxxxxxx` by default, while NACo sends the format the
  switch used in accounting. `radius-server authorization
  calling-station-id decode-mac-format` reportedly makes it follow the
  template's format.
- **Critical VLAN.** The `authen-server-down` / `authen-server-up` lines
  come from OpenNAC. It is not known whether devices already connected keep
  their VLAN when they re-authenticate while NACo is down.
- **Optional OpenNAC lines.** OpenNAC also uses `authentication
  dot1x-mac-bypass`, `radius-server testuser` (a probe, which would appear
  in *Logs* as a rejected user) and `radius-server detect-server interval`.
  Check whether your release needs them.
- **Attributes.** The value format of `Filter-Id`, and whether a VLAN by
  name works.
- **TACACS+.** Which service HWTACACS asks for, and whether commands
  arrive expanded or as typed — NACo matches whole command lines.

## References

- Huawei troubleshooting, MAC authentication:
  [user name formats](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_s/en/content/s/42_edesk_mac_authentication_unsuccessful/edesk_mac_authentication_unsuccessful_edesk005.html),
  [RADIUS template display](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_s/en/content/s/42_edesk_mac_authentication_unsuccessful/edesk_mac_authentication_unsuccessful_edesk004.html),
  [authentication mode](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_s/en/content/s/42_edesk_mac_authentication_unsuccessful/edesk_mac_authentication_unsuccessful_edesk001.html)
- [Tolly report 216161: Huawei S with Cisco ISE](https://community.cisco.com/kxiwq67737/attachments/kxiwq67737/discussions-network-access-control/552711/1/Tolly216161TechnicalReport-Huawei-CiscoISE-InteroperabilityCertification.pdf)
  (third party, 2016)
- [OpenNAC: Huawei wired devices](https://doc-opennac.opencloudfactory.com/1.2.5/reference-guide/opennac-network-device-compatibility/wired-supported-devices/Huawei.html)
  (third party)
- Huawei product documentation (not readable automatically):
  [calling-station-id mac-format](https://support.huawei.com/enterprise/en/doc/EDOC1100008296/5985a20c/calling-station-id-mac-format),
  [RADIUS commands](https://support.huawei.com/enterprise/en/doc/EDOC1100271769/36562c7b/radius-configuration-commands),
  [CoA and DM](https://support.huawei.com/enterprise/en/doc/EDOC1100213104/e93f1c34/configuring-the-radius-coa-or-dm-function),
  [decode-mac-format](https://support.huawei.com/enterprise/en/doc/EDOC1100156634/9724167d/radius-server-authorization-calling-station-id-decode-mac-format),
  [802.1X access profile](https://support.huawei.com/enterprise/en/doc/EDOC1100277032/31e20da8/configuring-an-8021x-access-profile),
  [802.1X troubleshooting](https://support.huawei.com/enterprise/en/doc/EDOC1000091883/555fddbe/troubleshooting-8021x-authentication-failures)
