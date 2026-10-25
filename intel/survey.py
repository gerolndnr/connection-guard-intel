"""What a candidate source adds to a build: new addresses, where they sit, and what they do on the benchmark.

Used for the registry blocks, the geofeeds and the host-name enumeration before they become sources. All numbers
are local: the candidate's networks against a build directory and a mc-antivpn-bench dataset.
"""
import bisect
import collections
import ipaddress
import json
import os

from .evaluate import Index, load


class Coverage:
    """Collapsed networks of one family as sorted integer intervals, for counting overlapping addresses."""
    def __init__(self, networks):
        merged = list(ipaddress.collapse_addresses(networks))
        self.starts = [int(n.network_address) for n in merged]
        self.ends = [int(n.broadcast_address) for n in merged]

    def overlap(self, network):
        lo, hi = int(network.network_address), int(network.broadcast_address)
        i, total = max(bisect.bisect_right(self.starts, lo) - 1, 0), 0
        while i < len(self.starts) and self.starts[i] <= hi:
            total += max(0, min(hi, self.ends[i]) - max(lo, self.starts[i]) + 1)
            i += 1
        return total


def additions(networks, lists_dir):
    """IPv4 addresses of `networks`: total, already VPN, new inside HOSTING (were review only), new outside both."""
    v4 = list(ipaddress.collapse_addresses(n for n in networks if n.version == 4))
    vpn_nets = [n for n in load(os.path.join(lists_dir, 'vpn.txt')) if n.version == 4]
    hosting_nets = [n for n in load(os.path.join(lists_dir, 'hosting.txt')) if n.version == 4]
    vpn, either = Coverage(vpn_nets), Coverage(vpn_nets + hosting_nets)
    out = collections.Counter()
    for n in v4:
        total, known, listed = n.num_addresses, vpn.overlap(n), either.overlap(n)
        out.update(total=total, already_vpn=known, new_in_hosting=listed - known, new_elsewhere=total - listed)
    out['v6_networks'] = sum(1 for n in networks if n.version == 6)
    return dict(out)


def benchmark(networks, dataset, lists_dir=None):
    """Per cohort: items inside `networks`, and of those how many the build's VPN list misses."""
    index = Index(networks)
    vpn = Index(load(os.path.join(lists_dir, 'vpn.txt'))) if lists_dir else None
    rows = collections.defaultdict(collections.Counter)
    for line in open(dataset):
        item = json.loads(line)
        rows[item['cohort']]['n'] += 1
        if item['ip'] in index:
            rows[item['cohort']]['hit'] += 1
            if vpn is not None and item['ip'] not in vpn:
                rows[item['cohort']]['hit_not_in_vpn'] += 1
    return {k: dict(v) for k, v in sorted(rows.items())}


def survey(orgs, lists_dir, dataset, out=None, cache=None):
    """`cache`: a JSON file of the blocks per operator, written on the first run and read on later ones."""
    from . import registry
    cached = json.load(open(cache)) if cache and os.path.exists(cache) else {}
    report, blocks = {}, {}
    for op, v in orgs.items():
        handles = [o['handle'] for o in v['organisations']]
        if not handles:
            continue
        if op in cached:
            found = [(ipaddress.ip_network(n), c, f) for n, c, f in cached[op]]
        else:
            found = registry.lookup(handles)
        blocks[op] = [(str(n), c, f) for n, c, f in found]
        nets = [n for n, _, _ in found]
        row = dict(brand=v['brand'], blocks=len(found))
        if lists_dir:
            row['additions'] = additions(nets, lists_dir)
        if dataset:
            row['benchmark'] = benchmark(nets, dataset, lists_dir)
        report[op] = row
        print(op, json.dumps(row))
    if cache and not cached:
        with open(cache, 'w') as f:
            json.dump(blocks, f)
    if out:
        with open(out, 'w') as f:
            json.dump(report, f, indent=1)
    return report
