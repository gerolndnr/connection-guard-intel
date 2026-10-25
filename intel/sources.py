"""Every data source: where it comes from, under which terms, and how its answer becomes entries.

Parsers take the raw answer bytes, so tests run them on recorded fixtures without network access.
`redistribute` records the review in SOURCES.md: a source that is not cleared is fetched for evaluation only.
"""
import csv
import io
import json
import re
import socket
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .model import BOOSTER, HOSTING, MOBILE, PROXY, RELAY, SHARED, TOR, VPN, Entry, net


@dataclass
class Source:
    id: str
    category: str
    url: str
    parse: Callable[[bytes], list]
    terms: str
    redistribute: bool
    headers: dict = field(default_factory=dict)
    # Optional sources may fail without stopping the build (reported in the manifest; the 14-day history keeps their
    # last addresses). Used for operators that block data-centre clients such as CI runners.
    optional: bool = False
    # Proxy lists: the maintainer. An address counts only when lists of at least two different maintainers name it.
    group: str = ''


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


COLLECTOR = 'https://collector.torproject.org/recent/exit-lists/'


def parse_collector_exits(get=None, days=3):
    """Exit addresses from CollecTor's exit lists (TorDNSEL) of the last `days` days, one snapshot per day: the newest
    and the newest at least 24 h, 48 h ... older. The bulk list names only the exits running at the moment of the
    fetch; exits come and go, so this keeps those seen in the last 3 days from the first build on."""
    import datetime
    def parse(index):
        from .model import fetch
        names = sorted(set(re.findall(r'href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})"', index.decode('utf-8', 'replace'))))
        if not names:
            return []
        when = lambda n: datetime.datetime.strptime(n, '%Y-%m-%d-%H-%M-%S')
        newest = when(names[-1])
        picked = []
        for day in range(days):
            older = [n for n in names if newest - when(n) >= datetime.timedelta(days=day)]
            if older and older[-1] not in picked:
                picked.append(older[-1])
        found = []
        for name in picked:
            body = (get or fetch)(COLLECTOR + name)
            found += re.findall(r'^ExitAddress (\S+) ', body.decode('utf-8', 'replace'), re.M)
        return entries(sorted(set(found)), TOR, 'tor-collector')
    return parse


def parse_icloud(body):
    # RFC 8805 geofeed: prefix,country,region,city,
    return entries([row[0] for row in csv.reader(io.StringIO(body.decode('utf-8', 'replace'))) if row and not row[0].startswith('#')],
                   RELAY, 'icloud-private-relay', 'prefix')


# Cloudflare's client egress blocks: WARP, Zero Trust Gateway and Cloudflare's share of iCloud Private Relay. Cloudflare
# publishes no WARP list; when it removed 104.28.0.0/14 from its CDN ranges (cloudflare.com/ips, 2021) it said the block
# was repurposed for Gateway and WARP, and 2a09:bac0::/29 is its IPv6 counterpart. Only what AS13335 actually announces
# inside these blocks is listed, and nothing from the CDN ranges, so a website behind Cloudflare never becomes a relay.
CLOUDFLARE_EGRESS_BLOCKS = ('104.28.0.0/14', '2a09:bac0::/29')


def parse_cloudflare_egress(body):
    import ipaddress
    blocks = [ipaddress.ip_network(b) for b in CLOUDFLARE_EGRESS_BLOCKS]
    prefixes = []
    for p in json.loads(body)['data']['prefixes']:
        n = ipaddress.ip_network(p['prefix'], strict=False)
        if any(n.version == b.version and n.subnet_of(b) for b in blocks):
            prefixes.append(p['prefix'])
    return entries(prefixes, RELAY, 'cloudflare-warp', 'prefix')


# ------------------------------------------------------------------- open proxies
_PROXY_LINE = re.compile(r'(?:^|[/@\s])((?:\d{1,3}\.){3}\d{1,3})(?=[:\s]|$)')


def parse_proxy_list(source):
    """`ip:port`, `scheme://ip:port` or `ip` per line. The port is dropped: a listed address is a proxy exit."""
    def parse(body):
        found = []
        for line in body.decode('utf-8', 'replace').splitlines():
            m = _PROXY_LINE.search(line.strip())
            if m:
                found.append(m.group(1))
        return entries(found, PROXY, source)
    return parse


def proxy_source(sid, group, url, terms, redistribute):
    return Source(sid, PROXY, url, parse_proxy_list(sid), terms, redistribute, optional=True, group=group)


GH = 'https://raw.githubusercontent.com/'
# Public open-proxy lists, reviewed 7 October 2026. Every list is published, whatever its licence (owner decision,
# 7 October 2026, as for the VPN operator lists); the terms column keeps each list's licence on record.
# The benchmark's proxy cohort comes from monosans, proxifly and vakhov, so those three are deliberately not used.
PROXY_SOURCES = [
    proxy_source('proxy-jetkai', 'jetkai', GH + 'jetkai/proxy-list/main/online-proxies/txt/proxies.txt', 'MIT licence (jetkai/proxy-list).', True),
    proxy_source('proxy-clarketm', 'clarketm', GH + 'clarketm/proxy-list/master/proxy-list-raw.txt', 'MIT licence (clarketm/proxy-list).', True),
    proxy_source('proxy-sunny9577', 'sunny9577', GH + 'sunny9577/proxy-scraper/master/proxies.txt', 'MIT licence (sunny9577/proxy-scraper).', True),
] + [
    proxy_source(f'proxy-ercin-{kind}', 'ercin', GH + f'ErcinDedeoglu/proxies/main/proxies/{kind}.txt', 'MIT licence (ErcinDedeoglu/proxies).', True)
    for kind in ('http', 'https', 'socks4', 'socks5')
] + [
    proxy_source(f'proxy-speedx-{kind}', 'speedx', GH + f'TheSpeedX/PROXY-List/master/{kind}.txt', 'No licence published.', True)
    for kind in ('http', 'socks4', 'socks5')
] + [
    proxy_source('proxy-shiftytr', 'shiftytr', GH + 'ShiftyTR/Proxy-List/master/proxy.txt', 'No licence published.', True),
    proxy_source('proxy-hookzof', 'hookzof', GH + 'hookzof/socks5_list/master/proxy.txt', 'No licence published.', True),
    proxy_source('proxy-roosterkid', 'roosterkid', GH + 'roosterkid/openproxylist/main/HTTPS_RAW.txt', 'No licence published.', True),
    proxy_source('proxy-mmpx12', 'mmpx12', GH + 'mmpx12/proxy-list/master/proxies.txt', 'No licence published.', True),
    proxy_source('proxy-zloi', 'zloi', GH + 'zloi-user/hideip.me/main/http.txt', 'No licence published.', True),
    proxy_source('proxy-prxchk', 'prxchk', GH + 'prxchk/proxy-list/main/all.txt', 'No licence published.', True),
    proxy_source('proxy-murongpig', 'murongpig', GH + 'MuRongPIG/Proxy-Master/main/http.txt', 'GPL-3.0.', True),
    proxy_source('proxy-proxyscrape', 'proxyscrape', 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=all&timeout=10000&country=all&ssl=all&anonymity=all',
                 'Commercial service; free-API terms not reviewed.', True),
]


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


def parse_airvpn(body):
    """AirVPN status API: up to four IPv4 and four IPv6 entry addresses per server (exits are the same addresses)."""
    keys = [f'ip_v{v}_in{i}' for v in (4, 6) for i in range(1, 5)]
    return vpn([s[k] for s in json.loads(body).get('servers', []) for k in keys if s.get(k)], 'airvpn')


def parse_windscribe(body):
    """Windscribe's public server list (the one its apps load): every node with its addresses ip, ip2 and ip3."""
    texts = [node[k] for loc in json.loads(body).get('data', []) for group in loc.get('groups') or [] for node in group.get('nodes') or []
             for k in ('ip', 'ip2', 'ip3') if node.get(k)]
    return vpn(texts, 'windscribe')


def parse_ovpn(body):
    return vpn([s['ip'] for dc in json.loads(body).get('datacenters', []) for s in dc.get('servers', []) if s.get('ip')], 'ovpn')


def parse_azirevpn(body, resolve=None):
    hosts = sorted({loc['pool'] for loc in json.loads(body).get('locations', []) if loc.get('pool')})
    return vpn((resolve or resolve_all)(hosts), 'azirevpn')


def openvpn_zip(source, resolve=None):
    """An operator's published OpenVPN configuration archive: every `remote` host, resolved by DNS."""
    def parse(body):
        hosts, literal = set(), []
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            names = z.namelist()
            if len(names) > 20_000:
                raise ValueError(f'{source}: {len(names)} files in the archive')
            for name in names:
                if z.getinfo(name).file_size > 1_000_000:
                    continue
                for m in re.finditer(rb'^\s*remote\s+(\S+)', z.read(name), re.M):
                    h = m.group(1).decode('ascii', 'replace')
                    if net(h) is not None:
                        literal.append(h)
                    else:
                        hosts.add(h)
        return vpn(literal + (resolve or resolve_all)(sorted(hosts)), source)
    return parse


def page_hosts(source, pattern, resolve=None):
    """An operator's public server page: host names matching the operator's own domain, resolved by DNS."""
    rx = re.compile(pattern)
    def parse(body):
        hosts = sorted(set(rx.findall(body.decode('utf-8', 'replace'))))
        return vpn((resolve or resolve_all)(hosts), source)
    return parse


def page_table(source, pattern, resolve=None):
    """An operator's public server table: the addresses printed in rows that name one of its hosts, plus those hosts
    resolved by DNS (a server keeps its printed address when DNS fails, and a moved server its new one)."""
    rx, ip = re.compile(pattern), re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
    def parse(body):
        rows = [r for r in re.findall(r'<tr\b.*?</tr>', body.decode('utf-8', 'replace'), re.S) if rx.search(r)]
        hosts = sorted({h for r in rows for h in rx.findall(r)})
        return vpn(sorted({a for r in rows for a in ip.findall(r)}) + (resolve or resolve_all)(hosts), source)
    return parse


GLUETUN_MAX_AGE_DAYS = 120


def parse_gluetun(source, resolve=None, now=None, max_age_days=GLUETUN_MAX_AGE_DAYS):
    """One provider file of gluetun-servers (MIT): every server's host name, resolved by DNS now, plus the addresses
    the file records when its last update is at most `max_age_days` old. A stale file still contributes host names,
    and a host name that no longer resolves contributes nothing."""
    import time
    def parse(body):
        j = json.loads(body)
        servers = j.get('servers') or []
        fresh = (now or time.time()) - (j.get('timestamp') or 0) <= max_age_days * 86400
        recorded = [ip for s in servers for ip in s.get('ips') or []] if fresh else []
        hosts = sorted({s['hostname'] for s in servers if s.get('hostname')})
        return vpn(recorded + (resolve or resolve_all)(hosts), source)
    return parse


GLUETUN = 'https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/'
# Providers without a public server list of their own, from the server data the gluetun VPN client maintains
# (github.com/qdm12/gluetun-servers, MIT). Added 25 October 2026. Operators Intel reads directly stay on their own lists.
GLUETUN_PROVIDERS = ('cyberghost', 'expressvpn', 'giganews', 'protonvpn', 'purevpn', 'slickvpn', 'torguard',
                     'vpn unlimited', 'vpnsecure', 'vyprvpn')


def gluetun_source(provider):
    sid = provider.replace(' ', '')
    return Source(sid, VPN, GLUETUN + provider.replace(' ', '%20') + '.json', parse_gluetun(sid),
                  'gluetun-servers (MIT licence, github.com/qdm12/gluetun-servers); host names resolved by DNS.', True, optional=True)


# ------------------------------------------------------------------- labels (additional lists)
def parse_mudfish(body, resolve=None):
    """Mudfish's public node status page: each row names a node by country and id; its host is
    node-<country>-<id, five digits>.mudfish.net, resolved by DNS."""
    rows = re.findall(r'data-name="([A-Z]{2})\b[^"]*">\s*<td[^>]*>\s*<a href="/admin/serverstatus/(\d+)"', body.decode('utf-8', 'replace'))
    hosts = sorted({f'node-{cc.lower()}-{int(sid):05d}.mudfish.net' for cc, sid in rows})
    return [Entry(n, BOOSTER, 'mudfish', 'exact') for n in (net(ip) for ip in (resolve or resolve_all)(hosts)) if n is not None]


# Networks that carry only (or almost only) mobile subscribers, behind carrier-grade NAT. Holder names checked on
# RIPEstat on 25 October 2026; carriers whose ASN also carries fixed lines or business customers are left out.
MOBILE_ASNS = {
    21928: 'T-Mobile USA', 22394: 'Verizon Wireless (Cellco)', 6167: 'Verizon Wireless (Cellco)', 20057: 'AT&T Mobility',
    20365: 'Freedom Mobile', 28403: 'Telcel (RadioMovil Dipsa)', 26615: 'TIM Brasil', 206067: 'Three UK', 51207: 'Free Mobile',
    39603: 'Play (P4)', 16135: 'Turkcell', 55836: 'Reliance Jio', 45609: 'Bharti Airtel mobile', 38266: 'Vodafone Idea',
    9644: 'SK Telecom', 132199: 'Globe mobile', 23693: 'Telkomsel', 24203: 'XL Axiata',
}


def parse_mobile_asn(source):
    def parse(body):
        return entries([p['prefix'] for p in json.loads(body)['data']['prefixes']], MOBILE, source, 'prefix')
    return parse


SIGNALS_URL = 'https://api.connectionguard.net/v1/intel/signals.json'
# A prefix that the servers' own rules let in this often is a known community network (school, LAN party, family),
# not an anonymous exit.
SHARED_MAX_ALLOWED_SHARE = 0.10


def parse_signals(body):
    """Prefixes that several networks of Connection Guard servers report many accounts from (the cloud publishes
    only prefixes with at least 3 sources and 10 accounts; apps/api/src/signals.ts in connection-guard-cloud)."""
    out = []
    for p in json.loads(body).get('prefixes') or []:
        if p['allowed_by_rule'] > SHARED_MAX_ALLOWED_SHARE * max(1, p['logins']):
            continue
        n = net(p['p'], 'prefix')
        if n is not None:
            out.append(Entry(n, SHARED, 'network-signals', 'signals'))
    return out


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
    # Added 7 October 2026 from where the 14 published VPN server lists actually sit (bgp.tools prefix table),
    # reviewed by name: data centres and VPS hosts only. Transit carriers and consumer ISPs were left out.
    25369: 'Hydra Communications', 136557: 'Host Universal', 49453: 'Global Layer', 396356: 'Latitude.sh',
    262287: 'Latitude.sh LTDA', 36352: 'HostPapa', 42201: 'PVDataNet', 42675: 'Obehosting', 34343: 'Eweka Internet Services',
    205467: 'Base IP', 34305: 'Base IP', 43357: 'Owl Limited', 32489: 'Amanah Tech', 6206: 'Netrouting',
    51852: 'Private Layer', 13737: 'Interconnecx', 51430: 'AltusHost', 52048: 'RixHost', 43350: 'NForce Entertainment',
    63473: 'HostHatch', 197706: 'Keminet', 50304: 'Blix Solutions', 55720: 'Gigabit Hosting', 43289: 'Trabia',
    53356: 'Free Range Cloud Hosting', 42831: 'UK Dedicated Servers', 397423: 'Tier.Net', 46664: 'VolumeDrive',
    400587: 'Ryamer', 41564: 'Orion Network', 394256: 'Tech Futures Interactive', 133480: '5G Network Operations',
    4785: 'xTom', 3258: 'xTom Japan',
}

# Networks that VPN operators run themselves: everything announced there is VPN infrastructure, whatever the
# operator's own server list shows. Each entry needs public evidence of the ownership (SOURCES.md).
VPN_OPERATOR_ASNS = {
    209854: 'Cyberzone S.A. (Surfshark)',
    39351: '31173 Services AB (Mullvad)',
    136787: 'PacketHub S.A. (Nord Security)',
    147049: 'PacketHub S.A. (Nord Security)', 207137: 'PacketHub S.A. (Nord Security)', 141039: 'PacketHub S.A. (Nord Security)',
    62651: 'Strong Technology (StrongVPN, IPVanish)', 140952: 'Strong Technology (StrongVPN, IPVanish)',
    22781: 'Strong Technology (StrongVPN, IPVanish)',
    # ProtonVPN: its server API needs a login since 2026, so Proton is covered by the networks Proton AG runs for its
    # VPN (RIPE holders "ProtonVPN", "ProtonVPN-2", "PV-HOSTED") and by the hosting rules. AS62371 is Proton's mail
    # and company network and is not listed.
    209103: 'ProtonVPN (Proton AG)', 199218: 'ProtonVPN-2 (Proton AG)', 208172: 'PV-HOSTED (Proton AG)',
}


def parse_operator_asn(source):
    def parse(body):
        return [Entry(n, VPN, source, 'operator-asn') for n in
                (net(p['prefix'], 'prefix') for p in json.loads(body)['data']['prefixes']) if n is not None]
    return parse


SOURCES = [
    Source('tor-bulk-exit-list', TOR, 'https://check.torproject.org/torbulkexitlist', parse_tor,
           'Tor Project, published for exactly this use (blocking or allowing Tor exits).', True),
    Source('tor-collector', TOR, COLLECTOR, parse_collector_exits(),
           'Tor Project CollecTor exit lists, published for research and for identifying Tor exits.', True, optional=True),
    Source('icloud-private-relay', RELAY, 'https://mask-api.icloud.com/egress-ip-ranges.csv', parse_icloud,
           'Apple publishes the egress ranges so that services can recognise Private Relay; no licence text.', True),
    Source('cloudflare-warp', RELAY, 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335', parse_cloudflare_egress,
           'RIPEstat (RIS) announced prefixes of AS13335 Cloudflare inside its WARP/Gateway egress blocks; RIPE NCC terms, attribution.', True),
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
    # Added 7 October 2026 under the same decision and safeguards (addresses only, attribution, takedown).
    Source('airvpn', VPN, 'https://airvpn.org/api/status/', parse_airvpn, 'Public status API, no licence text.', True),
    Source('windscribe', VPN, 'https://assets.windscribe.com/serverlist/mob-v2/1/0', parse_windscribe,
           'Public server list used by its apps, no licence text.', True),
    Source('ipvanish', VPN, 'https://configs.ipvanish.com/configs/configs.zip', openvpn_zip('ipvanish'),
           'Public OpenVPN configuration archive (host names, resolved by DNS), no licence text.', True, optional=True),
    Source('privadovpn', VPN, 'https://privadovpn.com/apps/ovpn_configs.zip', openvpn_zip('privadovpn'),
           'Public OpenVPN configuration archive (host names, resolved by DNS), no licence text.', True),
    Source('ovpn', VPN, 'https://www.ovpn.com/v2/api/client/entry', parse_ovpn, 'Public server API used by its apps, no licence text.', True),
    Source('azirevpn', VPN, 'https://api.azirevpn.com/v2/locations', parse_azirevpn,
           'Public locations API (pool host names, resolved by DNS), no licence text.', True),
    Source('privatevpn', VPN, 'https://privatevpn.com/serverlist/', page_hosts('privatevpn', r'[a-z0-9-]+\.pvdata\.host'),
           'Public server page (host names, resolved by DNS), no licence text.', True),
    Source('vpnac', VPN, 'https://vpn.ac/status', page_hosts('vpnac', r'\b[a-z]{2}[0-9]{1,2}\.vpn\.ac\b'),
           'Public status page (host names, resolved by DNS), no licence text.', True),
    Source('fastestvpn', VPN, 'https://support.fastestvpn.com/vpn-servers/', page_hosts('fastestvpn', r'[a-z0-9-]+\.jumptoserver\.com'),
           'Public server page (host names, resolved by DNS), no licence text.', True),
    # Added 13 October 2026 under the same decision and safeguards; suggested by zowi. The page footer says
    # "All Rights Reserved" and gives no reuse terms, so only the addresses are taken.
    Source('worldvpn', VPN, 'https://www.worldvpn.net/servers', page_table('worldvpn', r'\b[a-z0-9-]+\.ocservvpn\.com\b'),
           'Public server page (addresses and host names, resolved by DNS); footer "All Rights Reserved", no reuse terms.', True),
] + [gluetun_source(p) for p in GLUETUN_PROVIDERS] + PROXY_SOURCES + [
    Source('mudfish', BOOSTER, 'https://mudfish.net/server/status', parse_mudfish,
           'Public node status page (host names, resolved by DNS), no licence text.', True, optional=True),
] + [
    Source(f'mobile-asn-{asn}', MOBILE, f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}',
           parse_mobile_asn(f'mobile-asn-{asn}'), f'RIPEstat (RIS), AS{asn} {name}.', True, optional=True)
    for asn, name in MOBILE_ASNS.items()
] + [
    # Evaluation only until the benchmark shows its false-positive rate (plan, phase 5).
    Source('network-signals', SHARED, SIGNALS_URL, parse_signals,
           'Connection Guard network signals: prefixes and counts only, from at least 3 sources.', False, optional=True),
]
