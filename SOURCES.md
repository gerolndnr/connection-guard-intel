# Sources (Phase 0 review, 6 October 2026)

Each source is fetched without a key. `redistribute` (in `intel/sources.py`) says whether its data may go into the published lists. Sources that are not cleared are used for evaluation only (`--all`).

| Source | Category | Terms as published | Redistribute |
| --- | --- | --- | --- |
| Tor bulk exit list (check.torproject.org) | TOR | Published by the Tor Project so that services can identify Tor exits | yes |
| Apple iCloud Private Relay egress ranges | RELAY | Published by Apple so that services can recognise Private Relay (RFC 8805 geofeed); no licence text | yes |
| AWS ip-ranges.json, Google Cloud cloud.json, Oracle public_ip_ranges.json | HOSTING | Published by the providers for firewall and routing use | yes |
| DigitalOcean, Linode/Akamai geofeeds | HOSTING | RFC 8805 self-published geofeeds, meant for public consumption | yes |
| RIPEstat announced prefixes (RIS) for the hosting ASNs in `HOSTING_ASNS` | HOSTING | RIPE NCC, free with attribution | yes |
| RIPEstat announced prefixes for `VPN_OPERATOR_ASNS` | VPN (`operator-asn`) | RIPE NCC routing data; ownership by the VPN operator from public records | yes |
| Mullvad relays API | VPN | Public API used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| NordVPN servers API | VPN | Undocumented public API used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| IVPN servers.json | VPN | Public list used by its open-source apps; no licence text | yes (owner decision, 6 Oct 2026) |
| PIA server list | VPN | Public list used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| Surfshark clusters (host names, resolved by DNS) | VPN | Public list used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| Proton logicals | VPN | Rejected without app headers (HTTP 422); not used | no |
| Vultr geofeed | HOSTING | To be added (TLS chain issue on the test machine only) | – |

## Operator server lists

Addresses are facts, but in the EU a server list can be protected as a database (sui generis database right). The owner decided on 6 October 2026 to include the lists, with these safeguards:

- Only addresses are published; names, locations and keys are not.
- Attribution per operator, in each list's header.
- Takedown: an operator who objects writes to legal@connectionguard.net, and its source is switched off with the next build.

Without these lists, VPN detection drops from 97 % to 10 % on the benchmark dataset (see README).

## Hosting and operator ASNs

`HOSTING_ASNS` and `VPN_OPERATOR_ASNS` are reviewed by hand. Rules:

- No consumer ISP belongs on either list.
- An operator ASN needs public evidence that the VPN operator runs the network:
  - AS209854 Cyberzone S.A. is Surfshark's operating company.
  - AS39351 31173 Services AB is Mullvad's.
  - AS136787 PacketHub S.A. belongs to Nord Security.
