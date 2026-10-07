"""Scores built lists against a labelled dataset (mc-antivpn-bench detection-v1), locally, without any request.

    python -m intel.evaluate --lists eval --dataset ../mc-antivpn-bench/cache/private/detection-v1.private.jsonl
                             [--holdout pia,surfshark]

Circularity: the benchmark's VPN ground truth comes from the same operator lists. Scores on those cohorts show
coverage, not generalisation. --holdout rebuilds VPN without the named operators and scores them separately; that,
the false-positive cohorts and the time-split (run again a week later) are the honest numbers.
"""
import argparse
import collections
import ipaddress
import json
import os

from .model import CATEGORIES, HOSTING, PROXY, RELAY, TOR, VPN

POSITIVE_COHORTS = ('commercial_vpn', 'fresh_vpn', 'vpn_v6', 'tor', 'proxy')
NEGATIVE_COHORTS = ('residential', 'mobile_cgnat', 'residential_v6')


class Index:
    def __init__(self, networks):
        self.by_len = collections.defaultdict(set)
        for n in networks:
            self.by_len[(n.version, n.prefixlen)].add(int(n.network_address))

    def __contains__(self, ip):
        a = ipaddress.ip_address(ip)
        bits = 32 if a.version == 4 else 128
        value = int(a)
        for (version, length), starts in self.by_len.items():
            if version == a.version and (value >> (bits - length) << (bits - length)) in starts:
                return True
        return False


def load(path):
    nets = []
    for line in open(path):
        line = line.strip()
        if line and not line.startswith('#'):
            nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def score(indexes, items, holdout=()):
    rows = collections.defaultdict(collections.Counter)
    for item in items:
        key = item['cohort'] + (f" [held out: {item.get('provider')}]" if item.get('provider') in holdout else '')
        rows[key]['n'] += 1
        verdict = next((c for c in (TOR, VPN, PROXY, RELAY) if c in indexes and item['ip'] in indexes[c]), None)
        if verdict:
            rows[key][verdict] += 1
            rows[key]['blocked' if verdict in (TOR, VPN, PROXY) else 'relay'] += 1
        if item['ip'] in indexes[HOSTING]:
            rows[key]['hosting'] += 1
    return rows


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--lists', default='eval')
    p.add_argument('--dataset', required=True)
    p.add_argument('--holdout', default='', help='operators to leave out of the VPN list, e.g. pia,surfshark')
    p.add_argument('--dense-asn', type=int, default=None, help='with --holdout: the dense-ASN threshold to rebuild with')
    a = p.parse_args(argv)
    holdout = tuple(h for h in a.holdout.split(',') if h)
    items = [json.loads(l) for l in open(a.dataset)]
    indexes = {c: Index(load(os.path.join(a.lists, f'{c.lower()}.txt'))) for c in CATEGORIES}
    if os.path.exists(os.path.join(a.lists, 'proxy.txt')):  # read by Connection Guard 0.6.1 and later
        indexes[PROXY] = Index(load(os.path.join(a.lists, 'proxy.txt')))
    if holdout:
        # Re-parse the sources without the held-out operators. Hosting ranges and operator networks stay in, because
        # the inference rules need them; an operator ASN of a held-out operator is left out as well.
        from .build import collect, lists
        from .sources import SOURCES, VPN_OPERATOR_ASNS
        held_asns = {f'operator-asn-{asn}' for asn, name in VPN_OPERATOR_ASNS.items() if any(h.removesuffix('vpn') in name.lower() for h in holdout)}
        entries, _ = collect([s for s in SOURCES if s.category in (VPN, HOSTING) and s.id not in holdout and s.id not in held_asns])
        indexes[VPN] = Index(lists(entries, a.dense_asn)[VPN])
    rows = score(indexes, items, holdout)
    order = sorted(rows, key=lambda k: (k.split(' ')[0] not in POSITIVE_COHORTS, k))
    print(f"{'cohort':44}{'n':>5}{'blocked':>9}{'%':>6}{'relay':>7}{'hosting':>9}")
    for k in order:
        r = rows[k]
        print(f"{k:44}{r['n']:>5}{r['blocked']:>9}{100 * r['blocked'] / r['n']:>5.0f}%{r['relay']:>7}{r['hosting']:>9}")


if __name__ == '__main__':
    main()
