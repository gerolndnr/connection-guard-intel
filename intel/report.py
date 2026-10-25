"""Monthly report: what changed in the published lists between two builds, from their signed manifests alone.

    python -m intel.report --old <manifest.json of a month ago> --new <manifest.json now> [--out reports]

Written to reports/<year>-<month>.md by the monthly workflow (.github/workflows/report.yml), which takes both
manifests from the build artifacts (kept 90 days). Numbers come only from the manifests, so anyone can check them.
"""
import argparse
import datetime
import json
import os

ORDER = ('VPN', 'TOR', 'PROXY', 'RELAY', 'HOSTING', 'BOOSTER', 'MOBILE', 'SHARED')
MEANING = {'VPN': 'VPN servers and ranges', 'TOR': 'Tor exits', 'PROXY': 'Open proxies', 'RELAY': 'Privacy relays',
           'HOSTING': 'Data centres (review)', 'BOOSTER': 'Gaming boosters (label)', 'MOBILE': 'Mobile carriers (label)',
           'SHARED': 'Shared exits (label)'}
# Sources that come in families (one per network) are counted, not named.
FAMILIES = (('operator-asn-', 'VPN operator network'), ('mobile-asn-', 'mobile carrier network'), ('asn-', 'hosting network'))


def _names(ids):
    named, counted = [], {}
    for i in sorted(ids):
        family = next((label for prefix, label in FAMILIES if i.startswith(prefix)), None)
        if family:
            counted[family] = counted.get(family, 0) + 1
        else:
            named.append(i)
    return named + [f"{n} {label}{'s' if n > 1 else ''}" for label, n in counted.items()]


def _lists(m):
    return {**m.get('lists', {}), **m.get('additional_lists', {})}


def _operators(m):
    """VPN sources that publish servers (not operator networks), with how many entries each gave."""
    return {s['id']: s['entries'] for s in m['sources'] if s['category'] == 'VPN' and not s['id'].startswith('operator-asn-')
            and s['status'] == 'ok'}


def _change(new, old):
    if old is None:
        return 'new'
    if old == 0:
        return '–' if new == 0 else 'new'
    pct = 100 * (new - old) / old
    return f'{new - old:+,} ({pct:+.0f} %)'


def report(old, new):
    month = datetime.datetime.fromisoformat(old['as_of'].replace('Z', '+00:00'))
    lines = [f"# Connection Guard Intel, {month.strftime('%B %Y')}", '',
             f"Builds compared: {old['as_of']} and {new['as_of']}. Every number comes from the two signed manifests.", '',
             '| List | Networks | Change |', '| --- | ---: | ---: |']
    old_lists, new_lists = _lists(old), _lists(new)
    for name in ORDER:
        if name in new_lists:
            n = new_lists[name]['networks']
            o = old_lists.get(name, {}).get('networks')
            lines.append(f'| {MEANING[name]} (`{name.lower()}.txt`) | {n:,} | {_change(n, o)} |')
    tor_new, tor_old = new_lists['TOR']['addresses'], old_lists.get('TOR', {}).get('addresses')
    proxy_new, proxy_old = new_lists.get('PROXY', {}).get('addresses'), old_lists.get('PROXY', {}).get('addresses')
    ops_new, ops_old = _operators(new), _operators(old)
    servers_new, servers_old = sum(ops_new.values()), sum(ops_old.values())
    dense_new = set(new.get('inference', {}).get('dense_asns', {}))
    dense_old = set(old.get('inference', {}).get('dense_asns', {}))
    lines += ['', '## VPN', '',
              f"- {len(ops_new)} operator{'s publish' if len(ops_new) != 1 else ' publishes'} their servers ({len(ops_old)} a month before); together "
              f'{servers_new:,} server addresses ({_change(servers_new, servers_old)}).',
              f"- {len(dense_new)} data-centre networks count as VPN as a whole, because at least "
              f"{new.get('inference', {}).get('dense_asn_min_operators', '?')} operators run servers there"
              + (f" (new: {', '.join('AS' + a for a in sorted(dense_new - dense_old))})" if dense_new - dense_old else '')
              + (f" (no longer: {', '.join('AS' + a for a in sorted(dense_old - dense_new))})" if dense_old - dense_new else '') + '.',
              f"- {new.get('vpn_addresses_from_history', 0):,} addresses come from the {new.get('history_days', 14)}-day history "
              '(servers an operator stopped listing recently).',
              '', '## Tor and proxies', '',
              f'- {tor_new:,} Tor exit addresses ({_change(tor_new, tor_old)}), kept {new.get("tor_history_days", 3)} days.']
    if proxy_new is not None:
        lines.append(f'- {proxy_new:,} open proxy addresses ({_change(proxy_new, proxy_old)}), each named by at least '
                     f"{new.get('proxy', {}).get('min_lists', 2)} independent lists.")
    added = sorted({s['id'] for s in new['sources']} - {s['id'] for s in old['sources']})
    removed = sorted({s['id'] for s in old['sources']} - {s['id'] for s in new['sources']})
    failing = sorted(s['id'] for s in new['sources'] if s['status'] != 'ok')
    lines += ['', '## Sources', '', f"- {len(new['sources'])} sources in the latest build."]
    if added:
        lines.append(f"- Added: {', '.join(_names(added))}.")
    if removed:
        lines.append(f"- Removed: {', '.join(_names(removed))}.")
    lines.append(f"- Not answering in the latest build: {', '.join(_names(failing))}." if failing else '- Every source answered in the latest build.')
    lines += ['', 'Sources and terms: [SOURCES.md](../SOURCES.md). Accuracy is measured in '
              '[mc-antivpn-bench](https://github.com/gerolndnr/mc-antivpn-bench), where Intel is the author\'s own project.', '']
    return '\n'.join(lines), month.strftime('%Y-%m')


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--old', required=True)
    p.add_argument('--new', required=True)
    p.add_argument('--out', default='reports')
    a = p.parse_args(argv)
    with open(a.old) as f:
        old = json.load(f)
    with open(a.new) as f:
        new = json.load(f)
    text, month = report(old, new)
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f'{month}.md')
    with open(path, 'w') as f:
        f.write(text)
    print(path)


if __name__ == '__main__':
    main()
