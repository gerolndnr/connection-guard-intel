"""Time split: how many VPN servers that appeared after an earlier build did that build already catch?

    python -m intel.timesplit --history <vpn-history.json of build T>     # the honest number, fetches today's sources
    python -m intel.timesplit --old <lists of build T> --new <lists of build T+n>

--history takes the exact servers an earlier build saw (its state file names each server and its operator), applies
today's rules to them with today's hosting ranges, and scores the servers the same operators publish today that the
earlier build did not see. Hosting ranges barely move, so using today's does not leak the answer.

--old/--new needs only two published builds, but published lists collapse a server into any inferred block around
it, so only servers outside every block stay visible as exact entries. That biases the score towards misses; use it
for a quick look, not for a published number.

Both directories hold published lists (the `lists` artifact of a build run). A server counts as published exactly when
it is a short entry of vpn.txt (IPv4 longer than /24, IPv6 longer than /64); everything shorter is inference or an
operator network. Servers that are exact in the new build and not exact in the old one are new since T; the score is
how many of them the old build's vpn.txt already contained, and how many fell into its hosting.txt for review.
Both builds should use the same sources (compare the `sources` in their manifests), otherwise a new source counts as
new servers.
"""
import argparse
import ipaddress
import json
import os

from .evaluate import Index, load
from .model import HOSTING, VPN, Entry

EXACT_MIN_PREFIX = {4: 25, 6: 65}
MAX_EXPAND = 256  # a collapsed run of exact servers is at most a few addresses; never expand a block


def exact(networks):
    out = set()
    for n in networks:
        if n.prefixlen >= EXACT_MIN_PREFIX[n.version] and n.num_addresses <= MAX_EXPAND:
            out.update(n) if n.num_addresses > 1 else out.add(n.network_address)
    return out


def split(old_dir, new_dir):
    old_vpn = load(os.path.join(old_dir, 'vpn.txt'))
    old_exact = exact(old_vpn)
    new = sorted((a for a in exact(load(os.path.join(new_dir, 'vpn.txt'))) if a not in old_exact),
                 key=lambda a: (a.version, int(a)))
    vpn, hosting = Index(old_vpn), Index(load(os.path.join(old_dir, 'hosting.txt')))
    caught = [a for a in new if str(a) in vpn]
    review = [a for a in new if str(a) not in vpn and str(a) in hosting]
    by_family = {v: sum(1 for a in new if a.version == v) for v in (4, 6)}
    as_of = lambda d: json.load(open(os.path.join(d, 'manifest.json')))['as_of']
    return {'old': as_of(old_dir), 'new': as_of(new_dir), 'new_servers': len(new), 'by_family': by_family,
            'caught': len(caught), 'hosting_only': len(review), 'missed': len(new) - len(caught) - len(review)}


def simulate(history_path, today=None):
    """Scores today's servers of the operators in an earlier build's history against that build, rebuilt with today's rules.

    `today` is the result of build.collect for those operators, the hosting sources and the operator networks (tests
    pass their own)."""
    from .build import collect, lists
    from .sources import SOURCES
    with open(history_path) as f:
        history = json.load(f)
    old = [Entry(ipaddress.ip_network(k), VPN, v['source'], 'exact') for k, v in history.items() if v['method'] == 'exact']
    operators = {e.source for e in old}
    if today is None:
        today, _ = collect([s for s in SOURCES if s.category == HOSTING or s.id in operators or s.id.startswith('operator-asn-')])
    seen = {e.network for e in old}
    new = {}
    for e in today:
        if e.category == VPN and e.method == 'exact' and e.source in operators and e.network not in seen:
            new.setdefault(e.network, e.source)
    hosting = [e for e in today if e.category == HOSTING]
    networks = [e for e in today if e.category == VPN and e.source.startswith('operator-asn-')]
    rules_only = Index(lists(old + hosting)[VPN])
    with_networks = Index(lists(old + hosting + networks)[VPN])
    hosting_index = Index(lists(hosting)[HOSTING])
    rows = {}
    for n, source in new.items():
        ip = str(n.network_address)
        r = rows.setdefault(source, dict(new=0, rules=0, networks=0, hosting_only=0))
        r['new'] += 1
        if ip in rules_only:
            r['rules'] += 1
        elif ip in with_networks:
            r['networks'] += 1
        elif ip in hosting_index:
            r['hosting_only'] += 1
    return dict(old_servers=len(old), operators=sorted(operators), rows=rows)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--history')
    p.add_argument('--old')
    p.add_argument('--new')
    a = p.parse_args(argv)
    if a.history:
        r = simulate(a.history)
        print(f"{r['old_servers']} servers of {', '.join(r['operators'])} in the earlier build")
        print(f"{'operator':12}{'new':>7}{'by rules':>10}{'+networks':>11}{'review':>8}{'missed':>8}")
        total = dict(new=0, rules=0, networks=0, hosting_only=0)
        for source, row in sorted(r['rows'].items()) + [('all', total)]:
            if source != 'all':
                for k in total:
                    total[k] += row[k]
            missed = row['new'] - row['rules'] - row['networks'] - row['hosting_only']
            pct = lambda x: f"{100 * x / (row['new'] or 1):.0f}%"
            print(f"{source:12}{row['new']:>7}{pct(row['rules']):>10}{pct(row['rules'] + row['networks']):>11}"
                  f"{pct(row['hosting_only']):>8}{pct(missed):>8}")
        return
    r = split(a.old, a.new)
    n = r['new_servers'] or 1
    print(f"{r['old']} -> {r['new']}: {r['new_servers']} new servers (IPv4 {r['by_family'][4]}, IPv6 {r['by_family'][6]})")
    print(f"  already in vpn.txt     {r['caught']:>6}  {100 * r['caught'] / n:5.1f} %")
    print(f"  only in hosting.txt    {r['hosting_only']:>6}  {100 * r['hosting_only'] / n:5.1f} %")
    print(f"  missed                 {r['missed']:>6}  {100 * r['missed'] / n:5.1f} %")


if __name__ == '__main__':
    main()
