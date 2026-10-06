# Connection Guard Intel

Lists for recognising VPN, Tor, privacy-relay and hosting addresses, built daily from public sources. Connection Guard loads them as local lists: player addresses never leave the server, and there is no quota and no per-lookup cost.

| List | Meaning in Connection Guard |
| --- | --- |
| `vpn.txt` | Commercial VPN servers and exits: positive |
| `tor.txt` | Tor exits: positive |
| `relay.txt` | iCloud Private Relay: its own setting, allowed by default |
| `hosting.txt` | Data centres and clouds: review only, never a VPN verdict on its own |

An address that is on no list is **unknown**, not clean. Connection Guard then asks its next detection service.

Lists: `https://intel.connectionguard.net/{vpn,tor,relay,hosting}.txt`, `manifest.json` and `manifest.json.sig`, rebuilt daily. Sources, terms and the takedown route are in [SOURCES.md](SOURCES.md); corrections and objections go to legal@connectionguard.net.

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

## Evaluation (6 October 2026)

Scored on the [mc-antivpn-bench](https://github.com/gerolndnr/mc-antivpn-bench) dataset `detection-v1`, 692 labelled addresses, locally with `python -m intel.evaluate`:

| Cohort | n | With operator lists | Without | Held out (not in the build) |
| --- | --- | --- | --- | --- |
| Commercial VPN | 125 | 97 % | 10 % | PIA 0 %, Surfshark 52 % |
| Fresh VPN | 37 | 95 % | 8 % | |
| VPN IPv6 | 40 | 100 % | 2 % | |
| Tor | 80 | 95 % | 95 % | |
| Residential, mobile, residential IPv6 (false positives) | 310 | 0 % | 0 % | |

**Read this with care.** The benchmark's VPN ground truth comes from the same operator lists, so the first column shows coverage, not generalisation. The honest numbers are:

- the held-out column,
- the false positives,
- and a time split, re-scored a week after a build.

The comparison with other detection services runs in mc-antivpn-bench under the same conditions as for every product.
