"""VPN operators' own address blocks in the RIPE Database, and the RFC 8805 geofeeds those blocks name.

Operators that rent addresses inside hosting networks often register the block in their own company's name
(an `inetnum` whose `org:` is, say, Packethub S.A. for NordVPN). Those blocks are VPN infrastructure whether or not
the operator's server list shows them, and they sit in networks the ASN rules cannot split.

    python -m intel.registry discover     # full-text search for the operators' organisations -> registry-orgs.json
    python -m intel.registry survey       # what the blocks and geofeeds add to a build (--lists dist)

The build reads only `registry-orgs.json`: a reviewed list of organisation handles and names, so a new organisation
never enters the lists without review. Each handle is looked up with the RIPE Database REST API (inverse query on
`org`, no personal data), which is the documented way to query the database.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.parse

from .model import VPN, Entry, fetch, net

ORGS_FILE = os.path.join(os.path.dirname(__file__), 'registry-orgs.json')
REST = 'https://rest.db.ripe.net/search.json'
FULLTEXT = 'https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select'

# operator: (full-text keyword, organisation names that count, brand). Names are matched case-insensitively and in
# full. Only companies whose business is the VPN service: a group's other companies (Nord's Saily eSIM, Proton's mail)
# are left out, and Proton is covered by its VPN networks (sources.VPN_OPERATOR_ASNS).
OPERATORS = {
    'nordvpn': ('packethub', r'packet ?hub( s\.?a\.?)?', 'NordVPN (Nord Security)'),
    'surfshark': ('cyberzone', r'cyberzone s\.a\.', 'Surfshark'),
    'mullvad': ('mullvad', r'mullvad vpn ab', 'Mullvad'),
    'mullvad-31173': ('"31173 services"', r'31173 services( ab| \w+( \w+)?)', 'Mullvad (31173 Services)'),
    'cyberghost': ('cyberghost', r'cyberghost s\.?r\.?l\.?( ip network)?', 'CyberGhost'),
    'expressvpn': ('"express technologies"', r'express technologies ltd\.?', 'ExpressVPN'),
    'purevpn': ('"gz systems"', r'gz systems (ltd|limited)( d/b/a purevpn\.com)?', 'PureVPN'),
    'ivpn': ('ivpn', r'ivpn limited', 'IVPN'),
    'torguard': ('vpnetworks', r'vpnetworks llc( vpnetworks llc)?', 'TorGuard'),
    'ovpn': ('"ovpn integritet"', r'ovpn integritet ab', 'OVPN'),
    'azirevpn': ('netbouncer', r'netbouncer ab', 'AzireVPN'),
    'strongvpn': ('"strong technology"', r'strong technology,? llc', 'StrongVPN, IPVanish'),
    'hotspotshield': ('pango', r'pango inc\.?', 'Hotspot Shield'),
    'astrill': ('astrill', r'astrill', 'Astrill'),
}


def _json(body):
    return json.loads(body.decode('utf-8', 'replace'))


def get_json(url, attempts=4):
    """Both RIPE APIs answer XML unless asked for JSON. The full-text search sometimes answers empty and the REST API
    sometimes times out, so both are retried; a 404 ("no objects") is an answer and raised at once."""
    import time
    for attempt in range(attempts):
        try:
            body = fetch(url, timeout=30, headers={'Accept': 'application/json'})
            if body.strip():
                return body
        except Exception as e:  # noqa: BLE001 - retried below, raised after the last attempt
            if '404' in str(e) or attempt == attempts - 1:
                raise
        time.sleep(2 * (attempt + 1))
    raise ValueError(f'empty answer from {url}')


def fulltext_url(keyword, start=0):
    q = f'({keyword}) AND (object-type:organisation)'
    return FULLTEXT + '?' + urllib.parse.urlencode(dict(q=q, start=start, rows=100, wt='json', hl='false', facet='false'))


def organisations(body, name_rx):
    """(handle, name) of every organisation in a full-text answer whose whole name matches `name_rx`."""
    rx, out = re.compile(name_rx, re.I), []
    for doc in _json(body)['result'].get('docs') or []:
        f = {s['str']['name']: s['str'].get('value') for s in doc['doc']['strs']}
        name = (f.get('org-name') or '').strip()
        if f.get('object-type') == 'organisation' and rx.fullmatch(name):
            out.append((f['lookup-key'], name))
    return sorted(set(out))


def org_url(handle):
    return f'https://rest.db.ripe.net/ripe/organisation/{urllib.parse.quote(handle)}.json'


def parse_registry(source, handles, get=None):
    """A build source: its URL is the first organisation (which always exists, unlike its blocks); every handle's
    blocks are then looked up."""
    def parse(_org):
        return entries_of(lookup(handles, get), source)
    return parse


def inverse_url(handle, kind):
    return REST + '?' + urllib.parse.urlencode(
        [('query-string', handle), ('inverse-attribute', 'org'), ('type-filter', kind), ('flags', 'no-referenced'), ('flags', 'no-irt')])


GEOFEED_REMARK = re.compile(r'^\s*geofeed\s+(https://\S+)', re.I)


def blocks(body):
    """[(network, country, geofeed url or None)] of an inverse answer. An inetnum range becomes its CIDR blocks."""
    out = []
    for obj in (_json(body).get('objects') or {}).get('object') or []:
        attrs = [(a['name'], a['value']) for a in obj['attributes']['attribute']]
        first = attrs[0][1]
        country = next((v for k, v in attrs if k == 'country'), '')
        feed = next((v for k, v in attrs if k == 'geofeed'), None) or next(
            (m.group(1) for k, v in attrs if k == 'remarks' for m in [GEOFEED_REMARK.match(v)] if m), None)
        try:
            if ' - ' in first:
                lo, hi = (ipaddress.ip_address(x.strip()) for x in first.split(' - '))
                nets = list(ipaddress.summarize_address_range(lo, hi))
            else:
                nets = [ipaddress.ip_network(first.strip(), strict=False)]
        except ValueError:
            continue
        out += [(n, country, feed) for n in nets]
    return out


def lookup(handles, get=None):
    """Every block registered to the handles, IPv4 and IPv6."""
    get = get or get_json
    found = []
    for handle in handles:
        for kind in ('inetnum', 'inet6num'):
            try:
                body = get(inverse_url(handle, kind))
            except Exception as e:  # noqa: BLE001 - "no entries" is an HTTP 404 in the RIPE REST API
                if '404' in str(e):
                    continue
                raise
            found += blocks(body)
    return found


def load_orgs(path=ORGS_FILE):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)['operators']


def entries_of(found, source):
    out = []
    for n, _, _ in found:
        n = net(str(n), 'prefix')
        if n is not None:
            out.append(Entry(n, VPN, source, 'registry'))
    return out


# ------------------------------------------------------------------- geofeeds
def feed_rows(body):
    """(network, country) per RFC 8805 row."""
    out = []
    for line in body.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        cols = [c.strip() for c in line.split(',')]
        n = net(cols[0], 'prefix')
        if n is not None:
            out.append((n, cols[1].upper() if len(cols) > 1 else ''))
    return out


def feed_host(url):
    host = urllib.parse.urlsplit(url).hostname or ''
    return '.'.join(host.split('.')[-2:])


def geofeed_entries(found, source, get=None, owned=()):
    """Rows of the geofeeds the operator's blocks name. A geofeed on a host the operator owns (`owned`: registrable
    domains) is the operator's own address plan, and every row counts. A geofeed on someone else's host (an address
    broker or the hosting network) lists that company's other customers too, so only rows inside the operator's own
    blocks count, which adds no address but shows the virtual locations."""
    get = get or fetch
    own = [n for n, _, _ in found]
    by_version = {4: [n for n in own if n.version == 4], 6: [n for n in own if n.version == 6]}
    out, report = [], {}
    for url in sorted({f for _, _, f in found if f}):
        try:
            rows = feed_rows(get(url, limit=8_000_000))
        except Exception as e:  # noqa: BLE001 - one broken geofeed must not stop the others
            report[url] = f'failed: {type(e).__name__}'
            continue
        mine = feed_host(url) in owned
        kept = [n for n, _ in rows if mine or any(n.subnet_of(o) for o in by_version[n.version])]
        report[url] = dict(rows=len(rows), kept=len(kept), owned=mine)
        out += [Entry(n, VPN, source, 'geofeed') for n in kept]
    return out, report


def mismatches(found, rows):
    """Blocks whose geofeed country differs from the registered country: the virtual locations VPNs advertise."""
    registered = {n: c for n, c, _ in found}
    out = []
    for n, country in rows:
        for block, reg in registered.items():
            if block.version == n.version and n.subnet_of(block) and reg and country and reg != country:
                out.append((str(n), reg, country))
                break
    return out


# ------------------------------------------------------------------- command line
def discover(get=None, out=ORGS_FILE):
    get = get or get_json
    result = {}
    for op, (keyword, rx, brand) in OPERATORS.items():
        found = organisations(get(fulltext_url(keyword)), rx)
        result[op] = dict(brand=brand, organisations=[dict(handle=h, name=n) for h, n in found])
        print(f'{op}: {len(found)} organisations', file=sys.stderr)
    with open(out, 'w') as f:
        json.dump(dict(note='RIPE Database organisations registered by VPN operators; reviewed by name. '
                            'Regenerate with python -m intel.registry discover and review the diff.',
                       operators=result), f, indent=1, sort_keys=True)
        f.write('\n')
    return result


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=('discover', 'survey'))
    p.add_argument('--lists', help='a build directory (vpn.txt, hosting.txt) to measure what the blocks add')
    p.add_argument('--dataset', help='mc-antivpn-bench detection jsonl: count negatives inside the blocks')
    p.add_argument('--out', default=None, help='survey: write the report as JSON')
    p.add_argument('--cache', default=None, help='survey: blocks per operator, fetched once and reused')
    a = p.parse_args(argv)
    if a.command == 'discover':
        discover()
        return
    from .survey import survey
    survey(load_orgs(), a.lists, a.dataset, a.out, a.cache)


if __name__ == '__main__':
    main()
