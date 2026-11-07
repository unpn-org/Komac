"""Regression checks for audit coverage ordering and isolated DNS failures."""
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from audit_nsis import pending_artifacts, resolver_available


def artifact(sha, family):
    return {'sha256': sha, 'references': [{'id': family}]}


class RunnerTests(unittest.TestCase):
    def test_new_artifacts_precede_old_artifact_rechecks(self):
        items = [artifact('a', 'Old'), artifact('z', 'New'), artifact('b', 'Old')]
        pending = pending_artifacts(items, set(), {'a', 'b'})
        self.assertEqual([item['sha256'] for item in pending], ['z', 'a', 'b'])
        self.assertFalse(pending[0]['previously_analyzed'])

    def test_completed_artifacts_are_skipped_and_packages_are_diversified(self):
        items = [artifact('0', 'Done'), artifact('a', 'One'), artifact('b', 'One'), artifact('z', 'Two')]
        pending = pending_artifacts(items, {'0'}, set())
        self.assertEqual([item['sha256'] for item in pending], ['a', 'z', 'b'])

    def test_only_requested_regressions_are_prioritized_before_new_work(self):
        items = [artifact('a', 'Old'), artifact('b', 'Fix'), artifact('z', 'New')]
        pending = pending_artifacts(items, set(), {'a', 'b'}, regressions={'b'})
        self.assertEqual([item['sha256'] for item in pending], ['b', 'z', 'a'])

    @patch('audit_nsis.socket.getaddrinfo')
    def test_one_failed_healthcheck_does_not_imply_global_dns_outage(self, lookup):
        lookup.side_effect = [socket.gaierror(-2, 'Name not known'), [(socket.AF_INET,)]]
        self.assertTrue(resolver_available())

    @patch('audit_nsis.socket.getaddrinfo', side_effect=socket.gaierror(-2, 'Name not known'))
    def test_both_failed_healthchecks_stop_submissions(self, lookup):
        self.assertFalse(resolver_available())


if __name__ == '__main__':
    unittest.main()
