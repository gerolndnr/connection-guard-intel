"""Every data source: where it comes from, under which terms, and how its answer becomes entries.

Parsers take the raw answer bytes, so tests run them on recorded fixtures without network access.
`redistribute` records the review in SOURCES.md: a source that is not cleared is fetched for evaluation only.
"""
import csv
import io
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .model import HOSTING, RELAY, TOR, VPN, Entry, net


@dataclass
class Source:
    id: str
    category: str
    url: str
    parse: Callable[[bytes], list]
    terms: str
    redistribute: bool
    headers: dict = field(default_factory=dict)


def _lines(body):
    return [l.strip() for l in body.decode('utf-8', 'replace').splitlines() if l.strip() and not l.startswith('#')]


def entries(texts, category, source, method='exact'):
    out = []
    for t in texts:
        n = net(t, method)
        if n is not None:
            out.append(Entry(n, category, source, method))
    return out


# ------------------------------------------------------------------- Tor and relays
def parse_tor(body):
    return entries(_lines(body), TOR, 'tor-bulk-exit-list')


def parse_icloud(body):
    # RFC 8805 geofeed: prefix,country,region,city,
    return entries([row[0] for row in csv.reader(io.StringIO(body.decode('utf-8', 'replace'))) if row and not row[0].startswith('#')],
                   RELAY, 'icloud-private-relay', 'prefix')


# ------------------------------------------------------------------- cloud ranges
def parse_aws(body):
    j = json.loads(body)
    return entries([p['ip_prefix'] for p in j['prefixes']] + [p['ipv6_prefix'] for p in j['ipv6_prefixes']], HOSTING, 'aws', 'prefix')


def parse_gcp(body):
    j = json.loads(body)
    return entries([p.get('ipv4Prefix') or p.get('ipv6Prefix') for p in j['prefixes']], HOSTING, 'gcp', 'prefix')


def parse_oracle(body):
    j = json.loads(body)
    return entries([c['cidr'] for r in j['regions'] for c in r['cidrs']], HOSTING, 'oracle', 'prefix')


def parse_geofeed(source):
    def parse(body):
        return entries([l.split(',')[0] for l in _lines(body)], HOSTING, source, 'prefix')
    return parse


def parse_ripestat(source):
    def parse(body):
        return entries([p['prefix'] for p in json.loads(body)['data']['prefixes']], HOSTING, source, 'prefix')
    return parse


# ------------------------------------------------------------------- VPN operators
def parse_mullvad(body):
    texts = []
    for r in json.loads(body):
        if not r.get('active', True):
            continue
        texts += [r.get('ipv4_addr_in')] if r.get('ipv4_addr_in') else []
        texts += [r.get('ipv6_addr_in')] if r.get('ipv6_addr_in') else []
    return vpn(texts, 'mullvad')


def parse_nordvpn(body):
    texts = []
    for s in json.loads(body):
        texts += [t for t in (s.get('station'), s.get('ipv6_station')) if t]
    return vpn(texts, 'nordvpn')


def parse_ivpn(body):
    j = json.loads(body)
    texts = []
    for group in ('wireguard', 'openvpn'):
        for server in j.get(group, []):
            for h in server.get('hosts', []):
                texts += [t for t in (h.get('host'), (h.get('ipv6') or {}).get('host') if isinstance(h.get('ipv6'), dict) else None) if t]
    return vpn(texts, 'ivpn')


def parse_pia(body):
    j = json.loads(body.decode('utf-8', 'replace').splitlines()[0])
    texts = [s['ip'] for r in j['regions'] for group in r['servers'].values() for s in group if s.get('ip')]
    return vpn(texts, 'pia')


def parse_surfshark(body, resolve=None):
    hosts = sorted({c['connectionName'] for c in json.loads(body) if c.get('connectionName')})
    resolve = resolve or resolve_all
    return vpn(resolve(hosts), 'surfshark')


def vpn(texts, source):
    out = []
    for t in texts:
        method = 'v6-subnet' if ':' in t else 'exact'
        n = net(t, method)
        if n is not None:
            out.append(Entry(n, VPN, source, method))
    return out


def resolve_all(hosts):
    def one(h):
        try:
            return [a[4][0] for a in socket.getaddrinfo(h, None)]
        except OSError:
            return []
    with ThreadPoolExecutor(16) as pool:
        return sorted({ip for ips in pool.map(one, hosts) for ip in ips})


# Hosting ASNs that VPN services and proxies rent most often, beyond the clouds that publish their ranges.
# Announced prefixes come from RIPEstat (RIS data). Each one is reviewable here; no consumer ISP belongs on it.
HOSTING_ASNS = {
    24940: 'Hetzner', 16276: 'OVH', 51167: 'Contabo', 9009: 'M247', 60068: 'Datacamp (CDN77)', 60781: 'Leaseweb NL',
    28753: 'Leaseweb DE', 20473: 'Vultr (Choopa)', 63949: 'Akamai Linode', 14061: 'DigitalOcean',
    12876: 'Scaleway', 8560: 'IONOS', 199524: 'G-Core Labs', 21859: 'Zenlayer', 62240: 'Clouvider', 40676: 'Psychz',
    8100: 'QuadraNet', 11878: 'tzulo', 203020: 'HostRoyale', 206804: 'EstNOC', 137409: 'GSL Networks',
    42708: 'GleSYS',
    212238: 'Datacamp', 49981: 'WorldStream', 51396: 'Pfcloud',
    206092: 'IPXO', 30633: 'Leaseweb USA', 46562: 'Performive', 47583: 'Hostinger',
}

# Networks that VPN operators run themselves: everything announced there is VPN infrastructure, whatever the
# operator's own server list shows. Each entry needs public evidence of the ownership (SOURCES.md).
VPN_OPERATOR_ASNS = {
    209854: 'Cyberzone S.A. (Surfshark)',
    39351: '31173 Services AB (Mullvad)',
    136787: 'PacketHub S.A. (Nord Security)',
}


def parse_operator_asn(source):
    def parse(body):
        return [Entry(n, VPN, source, 'operator-asn') for n in
                (net(p['prefix'], 'prefix') for p in json.loads(body)['data']['prefixes']) if n is not None]
    return parse


SOURCES = [
    Source('tor-bulk-exit-list', TOR, 'https://check.torproject.org/torbulkexitlist', parse_tor,
           'Tor Project, published for exactly this use (blocking or allowing Tor exits).', True),
    Source('icloud-private-relay', RELAY, 'https://mask-api.icloud.com/egress-ip-ranges.csv', parse_icloud,
           'Apple publishes the egress ranges so that services can recognise Private Relay; no licence text.', True),
    Source('aws', HOSTING, 'https://ip-ranges.amazonaws.com/ip-ranges.json', parse_aws,
           'AWS publishes its ranges for firewall and routing use.', True),
    Source('gcp', HOSTING, 'https://www.gstatic.com/ipranges/cloud.json', parse_gcp,
           'Google Cloud publishes its customer ranges.', True),
    Source('oracle', HOSTING, 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', parse_oracle,
           'Oracle Cloud publishes its ranges.', True),
    Source('digitalocean', HOSTING, 'https://digitalocean.com/geo/google.csv', parse_geofeed('digitalocean'),
           'RFC 8805 geofeed, published for public consumption.', True),
    Source('linode', HOSTING, 'https://geoip.linode.com/', parse_geofeed('linode'),
           'RFC 8805 geofeed, published for public consumption.', True),
] + [
    Source(f'asn-{asn}', HOSTING, f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}',
           parse_ripestat(f'asn-{asn}'), f'RIPEstat (RIS) announced prefixes of AS{asn} {name}; RIPE NCC terms, attribution.', True)
    for asn, name in HOSTING_ASNS.items()
] + [
    Source(f'operator-asn-{asn}', VPN, f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}',
           parse_operator_asn(f'operator-asn-{asn}'), f'RIPEstat (RIS) announced prefixes of AS{asn} {name}; RIPE NCC terms, attribution.', True)
    for asn, name in VPN_OPERATOR_ASNS.items()
] + [
    # VPN operators: the server lists their own apps load. Only the addresses are published, with attribution and a
    # takedown route (SOURCES.md); the owner decided on 6 October 2026 to include them.
    Source('mullvad', VPN, 'https://api.mullvad.net/www/relays/all/', parse_mullvad, 'Public relay API, no licence text.', True),
    Source('nordvpn', VPN, 'https://api.nordvpn.com/v1/servers?limit=20000&fields[station]=1&fields[ipv6_station]=1&fields[hostname]=1',
           parse_nordvpn, 'Undocumented public API used by its apps, no licence text.', True),
    Source('ivpn', VPN, 'https://api.ivpn.net/v4/servers.json', parse_ivpn, 'Public server list used by its open-source apps, no licence text.', True),
    Source('pia', VPN, 'https://serverlist.piaservers.net/vpninfo/servers/v6', parse_pia, 'Public server list used by its apps, no licence text.', True),
    Source('surfshark', VPN, 'https://api.surfshark.com/v4/server/clusters/generic', parse_surfshark,
           'Public cluster list (host names, resolved by DNS), no licence text.', True),
]
