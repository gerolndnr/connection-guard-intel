# Connection Guard Intel

Lists for recognising VPN, Tor, privacy-relay and hosting addresses, built daily from public sources. Connection Guard loads them as local lists: player addresses never leave the server, and there is no quota and no per-lookup cost.

| List | Meaning in Connection Guard |
| --- | --- |
| `vpn.txt` | Commercial VPN servers and exits from 24 operators, the ranges around them, and VPN-dominated data-centre networks: positive |
| `tor.txt` | Tor exits, kept 3 days after they were last listed: positive |
| `relay.txt` | iCloud Private Relay and Cloudflare WARP: its own setting, allowed by default |
| `proxy.txt` | Open proxies named by public proxy lists of at least two different maintainers, kept 7 days: positive. Read by Connection Guard 0.6.1 and later; listed in `manifest.json` under `additional_lists`, which 0.6.0 ignores. Never inside a relay range. |
| `hosting.txt` | Data centres and clouds: review only, never a VPN verdict on its own. Data-centre networks dominated by VPN services are in `vpn.txt` instead (see SOURCES.md, Inference). |
| `booster.txt` | Gaming booster nodes (Mudfish): a label. Connection Guard 0.6.2 lets them in by default (`booster: ALLOW`) or counts them as VPN (`booster: VPN`). Booster nodes are taken out of inferred VPN ranges, so older versions no longer refuse them either; a server a VPN operator publishes stays VPN. |
| `mobile.txt` | Mobile carriers behind carrier-grade NAT: a label. Many players share one address, so `/cg explain` warns that an IP ban or an IP-based alt check hits innocent players there. |
| `shared.txt` | Exits that many accounts use across several Connection Guard servers (network signals): a review label for alt accounts and residential proxies. Evaluation only until it is measured; not published yet. |

`proxy.txt` and the three labels are listed in `manifest.json` under `additional_lists`, which Connection Guard 0.6.0 ignores; 0.6.1 reads only the proxy list.

An address that is on no list is **unknown**, not clean. Connection Guard then asks its next detection service.

**Monthly report:** on the first of each month, [reports/](reports/) gets a summary of what changed in the lists, taken from the signed manifests alone (`python -m intel.report`).

**In your own plugin or bot:** [clients/](clients/) has one-file clients for Java, Node.js and Python that verify the signature and check addresses locally.

Lists: `https://intel.connectionguard.net/{vpn,tor,relay,hosting,proxy,booster,mobile}.txt`, `manifest.json` and `manifest.json.sig`, rebuilt daily. Sources, terms and the takedown route are in [SOURCES.md](SOURCES.md); corrections and objections go to legal@connectionguard.net.

## How it is built

```sh
python -m intel.build --out dist          # published lists: only sources cleared in SOURCES.md
python -m intel.build --out eval --all    # every source, for evaluation only
python -m unittest discover -s tests
```

The pipeline:

1. Fetches each source, resuming downloads that end early and failing on short answers. An optional source may fail; the manifest reports it and its last addresses stay through the history.
2. Collapses the networks.
3. Infers VPN ranges only inside published hosting ranges:
   - a /24 holding a published VPN server;
   - a /22 holding two such /24s;
   - a whole hosting network in which at least four VPN operators publish servers (SOURCES.md, Inference).
4. Keeps addresses after their source stopped listing them:
   - VPN addresses: 14 days;
   - proxies: 7 days;
   - Tor exits: 3 days, from the Tor Project's CollecTor snapshots from the first build on.
5. Takes a proxy only when lists of two different maintainers name it, and never lists an address inside a relay range.
6. Refuses to publish:
   - when one of the four main lists shrinks by more than 20 %;
   - when `lists` holds anything but VPN, TOR, RELAY and HOSTING;
   - when `manifest.json` exceeds 60,000 bytes.

   The last two protect Connection Guard 0.6.0, which rejects such a manifest; new lists go into `additional_lists`.
7. Signs `manifest.json` with ECDSA P-256 (`INTEL_SIGNING_KEY`).

## Evaluation (7 October 2026)

Scored on the [mc-antivpn-bench](https://github.com/gerolndnr/mc-antivpn-bench) dataset `detection-v1`, 692 labelled addresses, locally with `python -m intel.evaluate`:

| Cohort | n | 6 Oct (5 lists) | 7 Oct morning (14 lists, inference) | 7 Oct evening (published lists) |
| --- | --- | --- | --- | --- |
| Commercial VPN | 125 | 111 | 125 | **125** (100 %) |
| Fresh VPN | 37 | 35 | 37 | **37** (100 %) |
| VPN IPv6 | 40 | 40 | 40 | **40** (100 %) |
| Tor | 80 | 66 | 70 | **80** (100 %), with 3 days of exits |
| Public proxies (`proxy.txt`, 0.6.1) | 100 | – | – | **19** |
| Residential, mobile, residential IPv6 (false positives) | 310 | 0 | 0 | **0** |
| Of those recognised as relay (WARP), let in by default | 310 | – | – | 2 |

The Tor row is built from exits seen on 4 October, three days before. With only the exits running at the moment of a build it would be 64/80; the three days of CollecTor snapshots bring it to 80/80, and no home or mobile address is among them.

**Read this with care.** The benchmark's VPN ground truth comes from five of the same operator lists, so these rows show coverage, not generalisation. Two numbers show generalisation.

**Operators held out of the build:**

| Held out | 6 Oct | 7 Oct |
| --- | --- | --- |
| PIA | 0 % | 56 % |
| Surfshark | 24 % | 44 % |

**Leave one operator out.** For each of the 14 operators, build without it and count how many of its published servers the rest still finds. The average across operators:

| Lists and rules | Average found |
| --- | --- |
| Exact lists and operator networks only | 10 % |
| /24 rule of 6 October (two servers of one operator) | 23 % |
| /24 and /22 rules | 30 % |
| **+ VPN-dominated hosting networks (≥ 4 operators, published)** | **57 %** |

**Time split (25 October 2026).** The build of 6 October saw 10,291 servers of five operators (IVPN, Mullvad, NordVPN, PIA, Surfshark). By 25 October the same operators published 1,071 servers it had not seen. Rebuilt with today's rules from the servers of 6 October (`python -m intel.timesplit --history`):

| | New servers | Already VPN by the rules | + operator networks | Hosting (review) | Missed |
| --- | --- | --- | --- | --- | --- |
| Mullvad | 4 | 75 % | 75 % | 25 % | 0 % |
| NordVPN | 137 | 67 % | 100 % | 0 % | 0 % |
| PIA | 739 | 70 % | 70 % | 16 % | 14 % |
| Surfshark | 191 | 57 % | 93 % | 3 % | 4 % |
| **All** | **1,071** | **68 %** | **78 %** | **11 %** | **10 %** |

So a server an operator adds is usually on the list before the operator publishes it. Caveats: today's hosting ranges are used (they barely change and say nothing about VPN servers), and the rules are today's, with five operators instead of 24 to infer from, which makes the number conservative.

**Labels (25 October 2026)** on `detection-v1`: `mobile.txt` names 7 of the 100 mobile players (its 18 carriers are mostly American and Indian; the probes are mostly European) and none of the 310 home and VPN-free players is refused because of a label. 74 of the 640 Mudfish booster addresses were inside inferred VPN ranges; they are taken out.

**Proxies.** `proxy.txt` uses none of the three lists the benchmark's proxy cohort was built from (monosans, proxifly, vakhov), so the 19 is not circular. Since 7 October 2026 it is built from all twelve maintainers' lists, whatever their licence (owner decision, SOURCES.md). Inside Connection Guard's chain the list matters most where Blackbox needs confirmation (0.6.1): replayed on the benchmark's answers, it brings the chain to 90 of 100 proxies with one home or mobile player refused.

The comparison with other detection services runs in mc-antivpn-bench under the same conditions as for every product: the `providers` family measures Intel as a service of its own (`cg-intel`), marked as the author's project.
