# Clients

One file each, for using Connection Guard Intel in your own plugin, proxy or Discord bot. Each one downloads the signed
lists, verifies the ECDSA signature against the pinned key and every list's SHA-256, refuses lists older than 72 hours,
and answers lookups in memory. The addresses you check never leave your machine, and there is no quota.

| Language | File | Needs |
| --- | --- | --- |
| Java 11+ (Paper, Velocity, BungeeCord, standalone) | [java/ConnectionGuardIntel.java](java/ConnectionGuardIntel.java) | nothing; copy it and change the package |
| Node.js 18+ (discord.js bots) | [js/cg-intel.mjs](js/cg-intel.mjs) | nothing |
| Python 3.9+ (discord.py bots, scripts) | [python/cg_intel.py](python/cg_intel.py) | `cryptography` |

Each returns the categories (VPN, TOR, PROXY, RELAY, HOSTING), the labels (BOOSTER, MOBILE, SHARED) and `block`, which
is true for VPN, Tor and proxy. An address on no list is unknown, not clean; HOSTING is worth a look, not a verdict.

```bash
python3 python/cg_intel.py 203.0.113.7
node js/cg-intel.mjs 203.0.113.7
java java/ConnectionGuardIntel.java 203.0.113.7
```

Download once a day, off your main thread; the lists are rebuilt at 03:17 UTC. Please keep the default user agent, so
we can see which clients are in use. Code under the MIT licence; the lists' sources and terms are in
[SOURCES.md](../SOURCES.md). Connection Guard itself uses the lists through its own loader, not these files.
