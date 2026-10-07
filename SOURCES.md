# Sources (Phase 0 review, 6 October 2026)

Each source is fetched without a key. `redistribute` (in `intel/sources.py`) says whether its data may go into the published lists. Sources that are not cleared are used for evaluation only (`--all`).

| Source | Category | Terms as published | Redistribute |
| --- | --- | --- | --- |
| Tor bulk exit list (check.torproject.org) | TOR | Published by the Tor Project so that services can identify Tor exits | yes |
| Tor Project CollecTor exit lists, one snapshot per day of the last 3 days (collector.torproject.org/recent/exit-lists) | TOR | Published by the Tor Project for research and for identifying Tor exits | yes (added 7 Oct 2026) |
| Apple iCloud Private Relay egress ranges | RELAY | Published by Apple so that services can recognise Private Relay (RFC 8805 geofeed); no licence text | yes |
| Cloudflare WARP and Gateway egress: RIPEstat announced prefixes of AS13335 inside 104.28.0.0/14 and 2a09:bac0::/29 | RELAY | RIPE NCC routing data, free with attribution. Cloudflare publishes no WARP list; it repurposed 104.28.0.0/14 for Gateway and WARP when it took the block out of its CDN ranges (2021). Cloudflare's CDN ranges (cloudflare.com/ips) are never included. Added 7 Oct 2026 | yes |
| AWS ip-ranges.json, Google Cloud cloud.json, Oracle public_ip_ranges.json | HOSTING | Published by the providers for firewall and routing use | yes |
| DigitalOcean, Linode/Akamai geofeeds | HOSTING | RFC 8805 self-published geofeeds, meant for public consumption | yes |
| RIPEstat announced prefixes (RIS) for the hosting ASNs in `HOSTING_ASNS` | HOSTING | RIPE NCC, free with attribution | yes |
| RIPEstat announced prefixes for `VPN_OPERATOR_ASNS` | VPN (`operator-asn`) | RIPE NCC routing data; ownership by the VPN operator from public records | yes |
| Mullvad relays API | VPN | Public API used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| NordVPN servers API | VPN | Undocumented public API used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| IVPN servers.json | VPN | Public list used by its open-source apps; no licence text | yes (owner decision, 6 Oct 2026) |
| PIA server list | VPN | Public list used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| Surfshark clusters (host names, resolved by DNS) | VPN | Public list used by its apps; no licence text | yes (owner decision, 6 Oct 2026) |
| AirVPN status API | VPN | Public status API, no licence text | yes (owner decision, 6 Oct 2026; added 7 Oct) |
| Windscribe server list | VPN | Public list used by its apps, no licence text | yes (added 7 Oct 2026) |
| IPVanish OpenVPN configuration archive (host names, resolved by DNS) | VPN | Public download, no licence text | yes (added 7 Oct 2026) |
| PrivadoVPN OpenVPN configuration archive (host names, resolved by DNS) | VPN | Public download, no licence text | yes (added 7 Oct 2026) |
| OVPN server API | VPN | Public API used by its apps, no licence text | yes (added 7 Oct 2026) |
| AzireVPN locations (pool host names, resolved by DNS) | VPN | Public API, no licence text | yes (added 7 Oct 2026) |
| PrivateVPN, vpn.ac, FastestVPN server pages (host names, resolved by DNS) | VPN | Public web pages, no licence text | yes (added 7 Oct 2026) |
| Proton logicals | VPN | Needs a Proton login since 2026 ("Invalid access token"); we use no accounts and imitate no app. ProtonVPN is covered by Proton AG's VPN networks (below) and the hosting rules | no |
| VPN Gate | VPN | Volunteers' home connections that rotate hourly; not used | no |
| Vultr geofeed | HOSTING | To be added (TLS chain issue on the test machine only) | – |

## Operator server lists

Addresses are facts, but in the EU a server list can be protected as a database (sui generis database right). The owner decided on 6 October 2026 to include the lists, with these safeguards:

- Only addresses are published; names, locations and keys are not.
- Attribution per operator, in each list's header.
- Takedown: an operator who objects writes to legal@connectionguard.net, and its source is switched off with the next build.

Without these lists, VPN detection drops from 97 % to 10 % on the benchmark dataset (see README).

## Inference

A published list covers only the servers an operator names, and other services rent the same data centres. Three rules extend the lists, and none of them ever reaches outside a published hosting range:

- **/24:** a hosting /24 with at least one published VPN server.
- **/22:** a hosting /22 with at least two such /24s.
- **VPN-dominated hosting network:** a hosting ASN in which at least **four** different VPN operators publish servers counts as VPN as a whole. This is the owner's decision of 7 October 2026. The networks marked this way are listed in each `manifest.json` under `inference.dense_asns`, with the operators found in them. Networks that may also serve business or consumer customers are excluded (`DENSE_ASN_EXCLUDE`).

The rules were chosen by leaving each of the 14 operators out of the build in turn and measuring how many of its servers the others still find (README).

## Hosting and operator ASNs

`HOSTING_ASNS` and `VPN_OPERATOR_ASNS` are reviewed by hand. Rules:

- No consumer ISP belongs on either list.
- An operator ASN needs public evidence that the VPN operator runs the network:
  - AS209854 Cyberzone S.A. is Surfshark's operating company.
  - AS39351 31173 Services AB is Mullvad's.
  - AS136787, AS147049, AS207137 and AS141039 PacketHub S.A. belong to Nord Security.
  - AS62651, AS140952 and AS22781 Strong Technology LLC run StrongVPN and IPVanish (Ziff Davis), whose published servers sit there.
  - AS209103, AS199218 and AS208172 are registered to Proton AG as "ProtonVPN", "ProtonVPN-2" and "PV-HOSTED" (RIPE). AS62371, Proton's mail and company network, is not listed.

    A one-off spot check on 7 October 2026 resolved 176 ProtonVPN entry servers from the host names in its configuration files (30 countries). Nothing was published from it. Before Proton's networks were added, 82 % of those servers were already on the list, through the hosting rules (M247, Datacamp); with them, 89 %.
- The hosting ASNs added on 7 October 2026 come from where the 14 published server lists actually sit (bgp.tools prefix table), reviewed by name. Transit carriers (Cogent, GTT) and a consumer ISP (Afrihost) were left out.

## Open proxies (added 7 October 2026)

`proxy.txt` takes an address when public proxy lists of at least two different maintainers name it on the same day, and keeps it for 7 days. Addresses inside a RELAY range are never listed. Only the address is published, never the port.

| List | Licence | Published |
| --- | --- | --- |
| jetkai/proxy-list | MIT | yes |
| clarketm/proxy-list | MIT | yes |
| sunny9577/proxy-scraper | MIT | yes |
| ErcinDedeoglu/proxies | MIT | yes |
| TheSpeedX/PROXY-List, ShiftyTR/Proxy-List, hookzof/socks5_list, roosterkid/openproxylist, mmpx12/proxy-list, zloi-user/hideip.me, prxchk/proxy-list | no licence published | yes (owner decision, 7 Oct 2026) |
| MuRongPIG/Proxy-Master | GPL-3.0 | yes (owner decision, 7 Oct 2026) |
| proxyscrape free API | commercial service, terms not reviewed | yes (owner decision, 7 Oct 2026) |

With the MIT lists alone, 4,590 addresses met the two-maintainer rule on 7 October 2026, because most addresses come from one maintainer (ErcinDedeoglu). With all twelve maintainers, 31,905 did, and the benchmark's proxy cohort went from 17 to 68 of 100 listed, with no home or mobile address listed.

monosans, proxifly and vakhov are not used: mc-antivpn-bench builds its proxy cohort from them, so using them would only measure coverage.

