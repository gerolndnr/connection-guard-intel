import tempfile
import unittest
from pathlib import Path

from intel.proxy_shadow import measure, summary


def write(folder, name, lines):
    (folder / name).write_text('# test\n' + '\n'.join(lines) + '\n')


class ProxyShadowTest(unittest.TestCase):
    def test_counts_additions_and_follows_them_until_the_published_list_has_them(self):
        with tempfile.TemporaryDirectory() as root:
            base, cand = Path(root, 'base'), Path(root, 'cand')
            base.mkdir(), cand.mkdir()
            write(base, 'proxy.txt', ['198.51.100.1/32', '198.51.100.7/32'])
            write(base, 'hosting.txt', ['203.0.113.0/24'])
            write(cand, 'proxy.txt', ['198.51.100.1/32', '198.51.100.7/32', '203.0.113.5/32', '192.0.2.9/32'])
            # Two days ago the trial added .7 (published by now) and .8 (never published).
            state = {'2026-11-25': ['198.51.100.7', '198.51.100.8'], '2026-11-01': ['192.0.2.1']}
            report, kept = measure(base, cand, state, '2026-11-27')
            self.assertEqual(report['added'], 2)
            self.assertEqual(report['added_outside_hosting'], 1)
            self.assertEqual(report['earlier_days'], {'2026-11-25': dict(age_days=2, added=2, published_now=1)})
            self.assertEqual(sorted(kept), ['2026-11-25', '2026-11-27'])  # older than 14 days is dropped
            self.assertEqual(kept['2026-11-27'], ['192.0.2.9', '203.0.113.5'])

    def test_the_summary_reports_later_confirmation_by_age(self):
        reports = [dict(day='2026-11-26', status='ok', added=4, added_outside_hosting=1, earlier_days={}),
                   dict(day='2026-11-27', status='ok', added=2, added_outside_hosting=0,
                        earlier_days={'2026-11-26': dict(age_days=1, added=4, published_now=3)})]
        table = summary(reports)
        self.assertIn('| 2026-11-26 | ok | 4 | 1 | 3/4 / – / – |', table)
        self.assertIn('| 2026-11-27 | ok | 2 | 0 | – / – / – |', table)


if __name__ == '__main__':
    unittest.main()
