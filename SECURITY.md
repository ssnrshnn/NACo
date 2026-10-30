# Security policy

NACo decides who may join a network; vulnerability reports are welcome and
handled with priority.

## Supported versions

| Version | |
|---|---|
| 3.x | supported — fixes are released as 3.x.y |
| 2.x and earlier (incl. RaspISE) | not supported; there is no upgrade path, install 3.x |

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/ssnrshnn/NACo/security/advisories/new).

Include what you found, the affected version or commit, and a way to
reproduce it (requests, packet captures or a test case help most).

You will get an answer within 3 working days. Confirmed issues are fixed as
fast as their severity requires — high and critical ones within 30 days —
and published as a GitHub security advisory with a CVE once a release is
available. Reporters are credited unless they prefer otherwise.

## Scope

In scope: the NACo application, its FreeRADIUS and Caddy configuration, the
container images, `quickstart.sh` and the other scripts in this repository.

Out of scope: weaknesses inherent to the protocols NACo implements and
documents (MAC spoofing against MAB, the obfuscation strength of TACACS+,
plain-HTTP guest portals), denial of service by flooding, and findings that
require control of the Docker host.

How NACo is protected is described in [docs/security.md](docs/security.md).
