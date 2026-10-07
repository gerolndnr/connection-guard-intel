# Connection Guard Intel

Lists for recognising VPN, Tor, privacy-relay and hosting addresses, built daily from public sources. Connection Guard loads them as local lists: player addresses never leave the server, and there is no quota and no per-lookup cost.

| List | Meaning in Connection Guard |
| --- | --- |
| `vpn.txt` | Commercial VPN servers and exits from 14 operators, the ranges around them, and VPN-dominated data-centre networks: positive |
| `tor.txt` | Tor exits: positive |
| `relay.txt` | iCloud Private Relay and Cloudflare WARP: its own setting, allowed by default |
| `proxy.txt` | Open proxies named by public proxy lists of at least two different maintainers, kept 7 days: positive. Read by Connection Guard 0.6.1 and later; listed in `manifest.json` under `additional_lists`, which 0.6.0 ignores. Never inside a relay range. |
| `hosting.txt` | Data centres and clouds: review only, never a VPN verdict on its own. Data-centre networks dominated by VPN services are in `vpn.txt` instead (see SOURCES.md, Inference). |

An address that is on no list is **unknown**, not clean. Connection Guard then asks its next detection service.

Lists: `https://intel.connectionguard.net/{vpn,tor,relay,hosting,proxy}.txt`, `manifest.json` and `manifest.json.sig`, rebuilt daily. Sources, terms and the takedown route are in [SOURCES.md](SOURCES.md); corrections and objections go to legal@connectionguard.net.

## How it is built

```sh
python -m intel.build --out dist          # published lists: only sources cleared in SOURCES.md
python -m intel.build --out eval --all    # every source, for evaluation only
python -m unittest discover -s tests
```

The pipeline:

1. Fetches each source, resuming downloads that end early and failing on short answers.
2. Collapses the networks.
3. Infers a VPN /24 only from two or more addresses of the same operator inside a published hosting range.
4. Keeps rotated VPN addresses for 14 days.
5. Refuses to publish if a list shrinks by more than 20 %.
6. Signs `manifest.json` with ECDSA P-256 (`INTEL_SIGNING_KEY`).

## Evaluation (7 October 2026)

Scored on the [mc-antivpn-bench](https://github.com/gerolndnr/mc-antivpn-bench) dataset `detection-v1`, 692 labelled addresses, locally with `python -m intel.evaluate`:

| Cohort | n | 6 Oct (5 lists) | 7 Oct (14 lists, inference) |
| --- | --- | --- | --- |
| Commercial VPN | 125 | 111 | **125** (100 %) |
| Fresh VPN | 37 | 35 | **37** (100 %) |
| VPN IPv6 | 40 | 40 | 40 (100 %) |
| Tor | 80 | 66 | **70** (88 %) |
| Residential, mobile, residential IPv6 (false positives) | 310 | 0 | **0** |

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

A time split, re-scored a week after a build, follows.

The comparison with other detection services runs in mc-antivpn-bench under the same conditions as for every product.
