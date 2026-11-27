"""Evaluate a fresh proxy confirmation feed against a signed Intel generation, offline.

This module never reads or writes the production history. Its output is intentionally
unsigned and evaluation-only, and does not add a source to the published build.
"""

import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .build import LIST_LIMIT, MANIFEST_LIMIT, addresses, proxy_agreement, render
from .evaluate import Index
from .model import ADDITIONAL, BOOSTER, CATEGORIES, Entry, MOBILE, PROXY, RELAY, net
from .sources import GH, PROXY_SOURCES


TRIAL_ID = 'proxy-dahono-live'
TRIAL_GROUP = 'hproxy-dahono'  # two publications of the same observed pool are not two votes
TRIAL_REF = GH + 'Dahono-com/free-proxy-list/main/proxies/proxies.json'
MAX_CONFIRMATION_AGE = datetime.timedelta(hours=6)  # twice the feed's stated three-hour cadence
SECONDARY_ID = 'proxy-proxio-checks'
SECONDARY_REF = GH + 'proxio-io/proxy-list/main/all.json'
SECONDARY_MAX_AGE = datetime.timedelta(days=1)
SNAPSHOT_LIMIT = 8 * 1024 * 1024
PROTOCOLS = frozenset(('http', 'https', 'socks4', 'socks5'))
# A CONNECT-only success corroborates an already verified endpoint; it is never a primary vote.
SECONDARY_PROTOCOLS = PROTOCOLS | {'connect25', 'connect80'}
ENDPOINT = re.compile(r'(\[[0-9a-fA-F:.]+\]|[0-9.]+):([0-9]{1,5})')
GUARDS = (RELAY, BOOSTER, MOBILE)


def bounded(path, limit):
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'{path.name}: exceeds {limit} bytes')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def timestamp(text, naive_is_utc=False):
    try:
        value = datetime.datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise ValueError('expected an ISO 8601 timestamp with a timezone') from exc
    if value.utcoffset() is None:
        if not naive_is_utc:
            raise ValueError('expected an ISO 8601 timestamp with a timezone')
        value = value.replace(tzinfo=datetime.timezone.utc)
    return value


def verify_baseline(folder, public_key):
    raw = bounded(folder / 'manifest.json', 65_536)
    signature = base64.b64decode(bounded(folder / 'manifest.json.sig', 256).strip(), validate=True)
    public_key.verify(signature, raw, ec.ECDSA(hashes.SHA256()))
    manifest = json.loads(raw)
    if manifest.get('schema') != 1 or manifest.get('evaluation_only') is not False:
        raise ValueError('expected a signed production baseline')
    primary, extra = manifest['lists'], manifest.get('additional_lists', {})
    if set(primary) != set(CATEGORIES) or not set(extra) <= set(ADDITIONAL) or PROXY not in extra:
        raise ValueError('unexpected baseline categories or missing proxy list')
    bodies = {}
    for kind, meta in (primary | extra).items():
        name = f'{kind.lower()}.txt'
        if meta['file'] != name:
            raise ValueError(f'unexpected filename for {kind}')
        data = bounded(folder / name, LIST_LIMIT)
        if len(data) != meta['bytes'] or sha(data) != meta['sha256']:
            raise ValueError(f'signed baseline mismatch: {name}')
        bodies[kind] = data
    return manifest, sha(raw), bodies


def load_networks(body):
    lines = (line.strip() for line in body.decode().splitlines())
    return [ipaddress.ip_network(line, strict=False) for line in lines if line and not line.startswith('#')]


def pinned(ref, observed):
    owner, repo, _, path = ref.removeprefix(GH).split('/', 3)
    expected = rf'{re.escape(GH + owner + "/" + repo + "/")}[0-9a-f]{{40}}/{re.escape(path)}'
    return isinstance(observed, str) and re.fullmatch(expected, observed) is not None


def snapshot(path, receipt, source, as_of, max_age=None):
    if not pinned(source, receipt['url']):
        raise ValueError(f'{path.name}: expected its original URL at an immutable commit')
    age = as_of - timestamp(receipt['committed_at'])
    if age < datetime.timedelta(0) or (max_age is not None and age > max_age):
        raise ValueError(f'{path.name}: snapshot is future-dated or too old')
    body = bounded(path, SNAPSHOT_LIMIT)
    if sha(body) != receipt['sha256']:
        raise ValueError(f'{path.name}: snapshot SHA-256 mismatch')
    return body


def endpoint_network(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return net(str(ip))


def measured_proxies(body):
    """Accept literal IPs from the verified JSON feed, not a loose match on arbitrary fields."""
    rows = json.loads(body)
    if not isinstance(rows, list):
        raise ValueError('expected a measured proxy array')
    endpoints = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        protocols, rtt, uptime = row.get('protocols'), row.get('latency_ms'), row.get('uptime_24h')
        if not isinstance(protocols, list) or not protocols or any(
                not isinstance(p, str) or p not in PROTOCOLS for p in protocols):
            continue
        if (type(rtt) not in (int, float) or not (0 < rtt < float('inf'))
                or type(uptime) not in (int, float) or not (0 < uptime <= 100)):
            continue
        endpoint = row.get('proxy')
        match = ENDPOINT.fullmatch(endpoint) if isinstance(endpoint, str) else None
        if not match or not 0 < int(match[2]) <= 65535:
            continue
        network = endpoint_network(match[1].strip('[]'))
        if network is not None:
            endpoints.add((network, int(match[2])))
    if not endpoints:
        raise ValueError('no usable measured proxy addresses')
    return endpoints


def corroborating_measurements(body, as_of, committed_at):
    report = json.loads(body)
    if not isinstance(report, dict) or report.get('source') != 'https://proxio.io':
        raise ValueError('expected the Proxio export envelope')
    rows, count = report.get('proxies'), report.get('count')
    if not isinstance(rows, list) or type(count) is not int or count != len(rows):
        raise ValueError('missing or incomplete Proxio export')
    exported = timestamp(report['updated_at'])
    if not as_of - SECONDARY_MAX_AGE <= exported <= committed_at <= as_of:
        raise ValueError('Proxio export is stale or ahead of its snapshot')
    endpoints = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        port, host, protocols = row.get('port'), row.get('ip'), row.get('protocols')
        if (type(port) is not int or not 0 < port <= 65535 or not isinstance(host, str)
                or not isinstance(protocols, list) or not any(
                    isinstance(p, str) and p.lower() in SECONDARY_PROTOCOLS for p in protocols)):
            continue
        failures, results = row.get('fail_streak'), row.get('last_results')
        if type(failures) is not int or failures != 0 or not isinstance(results, str) or not results.endswith('1'):
            continue
        try:
            # The upstream API uses UTC even when its row timestamp omits an offset.
            checked = timestamp(row.get('last_checked'), naive_is_utc=True)
        except ValueError:
            continue
        if not as_of - SECONDARY_MAX_AGE <= checked <= exported:
            continue
        network = endpoint_network(host)
        if network is not None:
            endpoints.add((network, port))
    return endpoints


def additions(confirmed, entries, groups, baseline, protected, second_vote=()):
    trial = [Entry(network, PROXY, TRIAL_ID, 'exact') for network in confirmed]
    trial.extend(Entry(network, PROXY, SECONDARY_ID, 'exact') for network in second_vote)
    agreed = proxy_agreement(entries + trial, groups | {TRIAL_ID: TRIAL_GROUP, SECONDARY_ID: 'proxio'})
    previous, excluded = Index(baseline), Index(protected)
    return {network for network in agreed & confirmed
            if str(network.network_address) not in previous and str(network.network_address) not in excluded}


def build_trial(baseline, inputs, out, public_key):
    manifest, base_hash, bodies = verify_baseline(baseline, public_key)
    as_of = timestamp(manifest['as_of'])
    receipt_bytes = bounded(inputs / 'receipts.json', 65_536)
    receipts = json.loads(receipt_bytes)
    observed = measured_proxies(snapshot(inputs / 'confirmation.json', receipts['confirmation'], TRIAL_REF, as_of,
                                          MAX_CONFIRMATION_AGE))
    confirmed = {network for network, _ in observed}
    second_vote = set()
    secondary = receipts.get('secondary')
    if secondary is not None:
        body = snapshot(inputs / 'proxio.json', secondary, SECONDARY_REF, as_of, SECONDARY_MAX_AGE)
        rechecked = corroborating_measurements(body, as_of, timestamp(secondary['committed_at']))
        second_vote = {network for network, _ in observed & rechecked}
    sources = {s.id: s for s in PROXY_SOURCES if s.redistribute and s.url.startswith(GH)}
    entries, groups, seen = [], {}, set()
    for receipt in receipts['sources']:
        source_id = receipt['id']
        if source_id not in sources or source_id in seen:
            raise ValueError('unexpected or duplicate corroborating source')
        seen.add(source_id)
        source = sources[source_id]
        groups[source_id] = source.group
        body = snapshot(inputs / 'existing' / source_id, receipt, source.url, as_of)
        entries.extend(source.parse(body))
    if not entries and not second_vote:
        raise ValueError('no corroborating sources; the measurement feed alone cannot vote')
    previous = load_networks(bodies[PROXY])
    protected = [n for label in GUARDS if label in bodies for n in load_networks(bodies[label])]
    added = additions(confirmed, entries, groups, previous, protected, second_vote)
    merged = previous + list(added)
    proxies = [n for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in merged if n.version == version)]
    # Keep all published blocks. The mobile/booster protections apply to new hits only.
    info = receipts['confirmation']
    report = [r for r in manifest['sources'] if r['category'] == PROXY]
    report.append(dict(id=TRIAL_ID, category=PROXY, url=info['url'],
                       terms='Evaluation only; independent observations and data reuse not yet cleared', status='ok'))
    if secondary is not None:
        report.append(dict(id=SECONDARY_ID, category=PROXY, url=secondary['url'],
                           terms='Proxy check data by https://proxio.io/ (CC BY 4.0); trial uses exact IPs only',
                           status='ok'))
    bodies[PROXY] = render(PROXY, proxies, report, manifest['as_of'])
    if len(bodies[PROXY]) > LIST_LIMIT or len(proxies) > 100_000:
        raise ValueError('candidate proxy list exceeds plugin limits')
    manifest['evaluation_only'] = True
    manifest['additional_lists'][PROXY] = dict(file='proxy.txt', bytes=len(bodies[PROXY]), sha256=sha(bodies[PROXY]),
                                               networks=len(proxies), addresses=addresses(proxies))
    manifest['proxy_trial'] = dict(baseline_manifest_sha256=base_hash, receipts_sha256=sha(receipt_bytes),
                                   confirmed=len(confirmed), added=len(added),
                                   confirmation=info, corroborating_sources=sorted(seen))
    if secondary is not None:
        manifest['proxy_trial'].update(secondary=secondary, same_endpoint_confirmations=len(second_vote))
    data = json.dumps(manifest, indent=1, sort_keys=True).encode()
    if len(data) > MANIFEST_LIMIT:
        raise ValueError('candidate manifest exceeds plugin limits')
    out.mkdir(parents=True, exist_ok=False)
    for kind, body in bodies.items():
        (out / f'{kind.lower()}.txt').write_bytes(body)
    (out / 'manifest.json').write_bytes(data)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path, help='pinned, signed Intel bundle')
    parser.add_argument('--inputs', required=True, type=Path, help='pinned proxy snapshots and receipts.json')
    parser.add_argument('--out', required=True, type=Path, help='new directory for the unsigned evaluation bundle')
    opts = parser.parse_args()
    key_path = Path(__file__).resolve().parents[1] / 'signing-key.pub.pem'
    key = serialization.load_pem_public_key(key_path.read_bytes())
    manifest = build_trial(opts.baseline, opts.inputs, opts.out, key)
    print(json.dumps(manifest['proxy_trial'], sort_keys=True))


if __name__ == '__main__':
    main()
