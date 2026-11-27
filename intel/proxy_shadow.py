"""Daily shadow measurement of the offline proxy trial (`intel.proxy_trial`): counts only, nothing is published.

Each run pins the trial's inputs to the newest commits before the signed published baseline, builds the
evaluation-only candidate and compares it with the baseline:

- how many addresses the trial would add, and how many of them lie outside every hosting range;
- for each earlier day, how many of that day's additions the published `proxy.txt` lists by now, i.e. how often
  the regular maintainers confirm the trial later (the trial was early) and how often never.

The added addresses are kept only in the workflow's cache (`--state`), because the trial's feeds are not cleared
for redistribution. Reports hold counts.
"""

import argparse
import datetime
import ipaddress
import json
import os
import shutil
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .evaluate import Index
from .proxy_trial import (MAX_CONFIRMATION_AGE, SECONDARY_MAX_AGE, SECONDARY_REF, SNAPSHOT_LIMIT, TRIAL_REF,
                          build_trial, load_networks, sha, timestamp)
from .sources import GH, PROXY_SOURCES

API = 'https://api.github.com/repos/'
KEEP_DAYS = 14   # additions older than this are no longer followed
LATER = (1, 3, 7)  # days after which confirmation by the published list is reported
EXPAND_LIMIT = 256


def get(url, token=None, limit=SNAPSHOT_LIMIT):
    headers = {'User-Agent': 'connection-guard-intel-shadow', 'Accept': 'application/vnd.github+json'}
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('larger than the trial accepts')
    return data


def pin(ref, until, token=None):
    """The file at `ref` in the newest commit before `until`, with the receipt `intel.proxy_trial` checks."""
    owner, repo, _branch, path = ref.removeprefix(GH).split('/', 3)
    query = urllib.parse.urlencode(dict(path=path, until=until, per_page=1))
    commits = json.loads(get(f'{API}{owner}/{repo}/commits?{query}', token, 1_000_000))
    if not commits:
        raise LookupError('no commit before the baseline')
    commit = commits[0]
    url = f'{GH}{owner}/{repo}/{commit["sha"]}/{path}'
    body = get(url)
    committed = commit['commit']['committer']['date'].replace('Z', '+00:00')
    return body, dict(url=url, committed_at=committed, sha256=sha(body))


def collect(as_of, inputs, token=None):
    """Pinned snapshots and receipts.json for one trial; returns the sources left out and why."""
    until = as_of.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    (inputs / 'existing').mkdir(parents=True)
    receipts, skipped = dict(sources=[]), {}
    body, receipts['confirmation'] = pin(TRIAL_REF, until, token)
    if as_of - timestamp(receipts['confirmation']['committed_at']) > MAX_CONFIRMATION_AGE:
        raise LookupError('the trial feed has no snapshot from the six hours before the baseline')
    (inputs / 'confirmation.json').write_bytes(body)
    try:
        body, receipt = pin(SECONDARY_REF, until, token)
        if as_of - timestamp(receipt['committed_at']) > SECONDARY_MAX_AGE:
            raise LookupError('older than a day')
        (inputs / 'proxio.json').write_bytes(body)
        receipts['secondary'] = receipt
    except Exception as error:
        skipped['proxio'] = f'{type(error).__name__}: {error}'[:120]
    for source in PROXY_SOURCES:
        if not (source.redistribute and source.url.startswith(GH)):
            continue
        try:
            body, receipt = pin(source.url, until, token)
        except Exception as error:
            skipped[source.id] = f'{type(error).__name__}: {error}'[:120]
            continue
        (inputs / 'existing' / source.id).write_bytes(body)
        receipts['sources'].append(dict(receipt, id=source.id))
    (inputs / 'receipts.json').write_text(json.dumps(receipts, indent=1, sort_keys=True))
    return skipped


def members(networks):
    out = set()
    for network in networks:
        if network.num_addresses > EXPAND_LIMIT:
            continue  # the trial adds exact addresses; wide blocks come from the baseline
        out.update(str(a) for a in (network if network.num_addresses > 1 else [network.network_address]))
    return out


def measure(baseline, candidate, state, day, extra=None):
    """Counts for `day` and the follow-up of earlier days. `state` holds {day: [added addresses]}."""
    published = load_networks((baseline / 'proxy.txt').read_bytes())
    listed = Index(published)
    hosting = Index(load_networks((baseline / 'hosting.txt').read_bytes()))
    added = sorted(a for a in members(load_networks((candidate / 'proxy.txt').read_bytes())) if a not in listed)
    report = dict(day=day, added=len(added), added_outside_hosting=sum(a not in hosting for a in added),
                  published_proxies=sum(n.num_addresses for n in published), **(extra or {}))
    followed = {}
    today = datetime.date.fromisoformat(day)
    for earlier, addresses in sorted(state.items()):
        age = (today - datetime.date.fromisoformat(earlier)).days
        if age <= 0 or age > KEEP_DAYS:
            continue
        followed[earlier] = dict(age_days=age, added=len(addresses), published_now=sum(a in listed for a in addresses))
    report['earlier_days'] = followed
    kept = {d: v for d, v in state.items() if 0 < (today - datetime.date.fromisoformat(d)).days < KEEP_DAYS}
    kept[day] = added
    return report, kept


def summary(reports):
    """A Markdown table over all daily reports, newest first."""
    by_day = {r['day']: r for r in reports}
    lines = ['# Proxy shadow measurement (evaluation only)', '',
             'Daily counts from `python -m intel.proxy_shadow`. The trial (Dahono, confirmed by an existing maintainer or '
             'by Proxio at the same address and port) is never published; only these counts are. "Published later" counts '
             'the day\'s additions that the regular `proxy.txt` lists by day 1, 3 and 7.', '',
             '| Day | Status | Trial adds | Outside hosting | Published later (d1 / d3 / d7) |',
             '| --- | --- | ---: | ---: | --- |']
    for day in sorted(by_day, reverse=True):
        r = by_day[day]
        later = []
        for k in LATER:
            match = next((other['earlier_days'][day] for other in by_day.values()
                          if day in other.get('earlier_days', {}) and other['earlier_days'][day]['age_days'] == k), None)
            later.append(f'{match["published_now"]}/{match["added"]}' if match else '–')
        lines.append(f'| {day} | {r.get("status", "ok")} | {r.get("added", "–")} | {r.get("added_outside_hosting", "–")} | '
                     f'{" / ".join(later)} |')
    return '\n'.join(lines) + '\n'


def run(baseline, work, state_dir, reports_dir, token=None):
    key = serialization.load_pem_public_key((Path(__file__).resolve().parents[1] / 'signing-key.pub.pem').read_bytes())
    manifest = json.loads((baseline / 'manifest.json').read_bytes())
    as_of = timestamp(manifest['as_of'])
    day = as_of.date().isoformat()
    state_path = state_dir / 'proxy-shadow.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    if work.exists():
        shutil.rmtree(work)
    extra = dict(baseline_as_of=manifest['as_of'])
    try:
        extra['skipped_sources'] = collect(as_of, work / 'inputs', token)
        try:
            trial = build_trial(baseline, work / 'inputs', work / 'candidate', key)['proxy_trial']
        except ValueError as error:
            if 'Proxio' not in str(error):
                raise
            # A stale Proxio export must not cost the day: run on the primary feed and the maintainers alone.
            receipts = json.loads((work / 'inputs' / 'receipts.json').read_text())
            receipts.pop('secondary', None)
            (work / 'inputs' / 'receipts.json').write_text(json.dumps(receipts, indent=1, sort_keys=True))
            extra['skipped_sources']['proxio'] = f'ValueError: {error}'[:120]
            trial = build_trial(baseline, work / 'inputs', work / 'candidate', key)['proxy_trial']
        extra.update(status='ok', trial_confirmed=trial['confirmed'],
                     same_endpoint_confirmations=trial.get('same_endpoint_confirmations'))
        report, state = measure(baseline, work / 'candidate', state, day, extra)
    except Exception as error:
        report = dict(day=day, status=f'failed: {type(error).__name__}: {error}'[:200], **extra)
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True))
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f'{day}.json').write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    reports = [json.loads(p.read_text()) for p in sorted(reports_dir.glob('*.json'))]
    (reports_dir / 'README.md').write_text(summary(reports))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path, help='the signed published bundle (lists branch)')
    parser.add_argument('--work', required=True, type=Path, help='scratch directory, replaced on every run')
    parser.add_argument('--state', required=True, type=Path, help='cache directory with earlier additions (never published)')
    parser.add_argument('--reports', required=True, type=Path, help='directory of the daily count reports')
    opts = parser.parse_args(argv)
    report = run(opts.baseline, opts.work, opts.state, opts.reports, os.environ.get('GITHUB_TOKEN'))
    print(json.dumps(report, sort_keys=True))
    if report.get('status') != 'ok':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
