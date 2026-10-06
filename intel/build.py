"""Builds the lists: fetch every source, collapse per category, check against the previous build, write and sign.

    python -m intel.build --out dist            # published lists (only sources cleared for redistribution)
    python -m intel.build --out eval --all      # every source, for evaluation only; never published

Each list is the plugin's local list format (docs/LOCAL_DATA.md): one IP or CIDR per line, '#' comments.
"""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import sys
import time

from .model import CATEGORIES, HOSTING, VPN, Entry, fetch
from .sources import SOURCES

LIST_LIMIT = 4 * 1024 * 1024  # the plugin's bound for one decompressed list
SHRINK_ALARM = 0.20


def collect(sources, attempts=3):
    """Fetches and parses every source; a failing source is reported, never silently dropped."""
    entries, report = [], []
    for s in sources:
        status, error, got = 'ok', None, []
        for attempt in range(attempts):
            try:
                got = s.parse(fetch(s.url, headers=s.headers))
                break
            except Exception as e:  # noqa: BLE001 - reported per source
                error = f'{type(e).__name__}: {str(e)[:160]}'
                time.sleep(2 * (attempt + 1))
        else:
            status = 'failed'
        if status == 'ok' and not got:
            status, error = 'empty', 'parsed no usable networks'
        entries += got
        report.append(dict(id=s.id, category=s.category, url=s.url, terms=s.terms, status=status, error=error, entries=len(got)))
    return entries, report


def infer_vpn_prefixes(entries, min_hits=2):
    """IPv4 /24s that a VPN operator demonstrably uses inside a data centre.

    Operators publish only some of their exits (Surfshark resolves a few addresses per cluster by DNS, PIA rotates
    inside its ranges). A /24 becomes VPN when at least `min_hits` distinct published addresses of the same operator
    lie in it AND the /24 is inside a published hosting range, so a consumer network is never inferred."""
    hosting = [e.network for e in entries if e.category == HOSTING and e.network.version == 4]
    hosting_index = {}
    for n in hosting:
        hosting_index.setdefault(n.prefixlen, set()).add(int(n.network_address))

    def in_hosting(prefix24):
        value = int(prefix24.network_address)
        return any((value >> (32 - length) << (32 - length)) in starts for length, starts in hosting_index.items() if length <= 24)

    hits = {}
    for e in entries:
        if e.category == VPN and e.method == 'exact' and e.network.version == 4:
            p24 = e.network.supernet(new_prefix=24)
            hits.setdefault((e.source, p24), set()).add(e.network)
    return [Entry(p24, VPN, source, 'prefix-inferred') for (source, p24), addrs in sorted(hits.items(), key=lambda x: str(x[0]))
            if len(addrs) >= min_hits and in_hosting(p24)]


def lists(entries):
    """Collapsed networks per category, IPv4 before IPv6, sorted."""
    entries = list(entries) + infer_vpn_prefixes(entries)
    out = {}
    for category in CATEGORIES:
        nets = [e.network for e in entries if e.category == category]
        v4 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
        v6 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 6))
        out[category] = sorted(v4) + sorted(v6)
    return out


def render(category, networks, report, as_of):
    used = [r for r in report if r['category'] == category and r['status'] == 'ok']
    head = [f'# Connection Guard Intel: {category}', f'# as-of {as_of}', '# https://github.com/gerolndnr/connection-guard-intel',
            '# Sources:'] + [f'#   {r["id"]}: {r["url"]} ({r["terms"]})' for r in used]
    lines = [str(n) if n.prefixlen < n.max_prefixlen else str(n.network_address) for n in networks]
    return ('\n'.join(head + lines) + '\n').encode()


def addresses(networks):
    return sum(n.num_addresses for n in networks)


def check_shrink(previous, counts, force):
    """A category losing more than 20 % of its networks usually means a broken source, not a smaller internet."""
    problems = []
    for category, now in counts.items():
        before = (previous or {}).get('lists', {}).get(category, {}).get('networks')
        if before and now < before * (1 - SHRINK_ALARM):
            problems.append(f'{category}: {before} -> {now} networks')
    if problems and not force:
        raise SystemExit('refusing to publish, lists shrank: ' + '; '.join(problems) + ' (use --force after checking)')
    return problems


def sign(data, key_pem):
    """ECDSA P-256 over SHA-256 (verifiable by the Java 8 plugin without extra libraries)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = serialization.load_pem_private_key(key_pem.encode() if isinstance(key_pem, str) else key_pem, password=None)
    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode()


HISTORY_DAYS = 14


def with_history(entries, path, now):
    """Keeps published VPN addresses for 14 days after they were last seen.

    Operators rotate addresses and DNS answers vary (Surfshark resolves a few addresses per cluster), so one fetch
    sees only part of a fleet. An address leaves the list 14 days after its operator stopped publishing it."""
    history = {}
    if os.path.exists(path):
        with open(path) as f:
            history = json.load(f)
    stamp = now.timestamp()
    for e in entries:
        if e.category == VPN and e.method in ('exact', 'v6-subnet'):
            history[str(e.network)] = dict(source=e.source, method=e.method, last_seen=stamp)
    history = {k: v for k, v in history.items() if stamp - v['last_seen'] <= HISTORY_DAYS * 86400}
    current = {str(e.network) for e in entries}
    old = [Entry(ipaddress.ip_network(k), VPN, v['source'], v['method']) for k, v in history.items() if k not in current]
    with open(path, 'w') as f:
        json.dump(history, f, sort_keys=True)
    return list(entries) + old, len(old)


def build(out, include_all=False, force=False, sources=None, key_pem=None, now=None, state=None):
    sources = [s for s in (sources or SOURCES) if include_all or s.redistribute]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    as_of = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    entries, report = collect(sources)
    os.makedirs(out, exist_ok=True)
    os.makedirs(state or 'state', exist_ok=True)
    entries, kept = with_history(entries, os.path.join(state or 'state', 'vpn-history.json'), now)
    result = lists(entries)
    previous = None
    if os.path.exists(os.path.join(out, 'manifest.json')):
        with open(os.path.join(out, 'manifest.json')) as f:
            previous = json.load(f)
    counts = {c: len(n) for c, n in result.items()}
    warnings = check_shrink(previous, counts, force)
    manifest = dict(schema=1, as_of=as_of, evaluation_only=include_all, sources=report, warnings=warnings, lists={},
                    vpn_addresses_from_history=kept, history_days=HISTORY_DAYS)
    for category, networks in result.items():
        body = render(category, networks, report, as_of)
        if len(body) > LIST_LIMIT:
            raise SystemExit(f'{category}: {len(body)} bytes exceeds the plugin limit of {LIST_LIMIT}')
        name = f'{category.lower()}.txt'
        with open(os.path.join(out, name), 'wb') as f:
            f.write(body)
        manifest['lists'][category] = dict(file=name, sha256=hashlib.sha256(body).hexdigest(), bytes=len(body),
                                           networks=len(networks), addresses=addresses(networks))
    data = json.dumps(manifest, indent=1, sort_keys=True).encode()
    with open(os.path.join(out, 'manifest.json'), 'wb') as f:
        f.write(data)
    key_pem = key_pem or os.environ.get('INTEL_SIGNING_KEY')
    if key_pem:
        with open(os.path.join(out, 'manifest.json.sig'), 'w') as f:
            f.write(sign(data, key_pem) + '\n')
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--out', default='dist')
    p.add_argument('--all', action='store_true', help='include sources not cleared for redistribution (evaluation only)')
    p.add_argument('--state', help='directory for vpn-history.json, kept between builds and never published (default: state)')
    p.add_argument('--force', action='store_true', help='publish even if a list shrank by more than 20 %%')
    a = p.parse_args(argv)
    m = build(a.out, include_all=a.all, force=a.force, state=a.state)
    for r in m['sources']:
        print(f"{r['status']:6} {r['id']:22} {r['entries']:>7}" + (f"  {r['error']}" if r['error'] else ''))
    for c, l in m['lists'].items():
        print(f"{c:8} {l['networks']:>7} networks {l['addresses']:>14,} addresses {l['bytes']/1e6:5.2f} MB")
    if any(r['status'] != 'ok' for r in m['sources']):
        sys.exit(2)


if __name__ == '__main__':
    main()
