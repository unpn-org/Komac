"""Coverage must stay accurate while a live journal is appended or replaced."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('nsis_progress', Path(__file__).parents[1] / 'scripts/nsis_progress.py')
progress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(progress)


def record(sha='a', status='ok', **extra):
    return {'sha256': sha, 'status': status,
            'references': [{'id': 'Example.App', 'version': '1.0'}], **extra}


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'results.jsonl'
        self.journal = progress.Journal(self.path)

    def append(self, row):
        with self.path.open('a') as stream:
            stream.write(json.dumps(row) + '\n')

    def test_partial_write_is_counted_only_when_complete(self):
        encoded = json.dumps(record(returncode=0)).encode()
        self.path.write_bytes(encoded[:25])
        self.journal.update()
        self.assertEqual(self.journal.runs, 0)
        with self.path.open('ab') as stream:
            stream.write(encoded[25:] + b'\n')
        self.journal.update()
        self.journal.update()
        self.assertEqual(self.journal.runs, 1)
        self.assertEqual(self.journal.attempted, {'a'})
        self.assertEqual(self.journal.invalid, 0)

    def test_rechecks_preserve_unique_coverage_and_latest_outcome(self):
        self.append(record(returncode=0, independent_arp_check={'corroborated_fields': ['DisplayName']}))
        self.append(record(status='interrupted'))
        self.append(record('b', 'download_failed'))
        self.append(record('c', 'analysis_timeout'))
        self.journal.update()
        self.assertEqual(self.journal.runs, 4)
        self.assertEqual(self.journal.attempted, {'a', 'c'})
        self.assertEqual(self.journal.output, {'a'})
        self.assertEqual(self.journal.literals, {'a'})
        self.assertEqual(self.journal.latest['a']['status'], 'interrupted')
        self.assertEqual(self.journal.verified, set())

    def test_replaced_or_truncated_journal_resets_counts(self):
        self.append(record(returncode=0))
        self.journal.update()
        replacement = self.path.with_suffix('.new')
        replacement.write_text(json.dumps(record('b', 'download_failed')) + '\n')
        replacement.replace(self.path)
        self.journal.update()
        self.assertEqual(self.journal.runs, 1)
        self.assertEqual(set(self.journal.latest), {'b'})
        self.assertEqual(self.journal.attempted, set())
        self.path.write_text('')
        self.journal.update()
        self.assertEqual(self.journal.runs, 0)

    def test_bad_complete_row_does_not_hide_following_results(self):
        self.path.write_text('{broken}\n')
        self.append(record(returncode=0))
        self.journal.update()
        self.assertEqual(self.journal.invalid, 1)
        self.assertEqual(self.journal.runs, 1)

    def test_result_history_reads_each_record_without_retaining_raw_payloads(self):
        self.append(record(returncode=0, analysis={'ProductCode': 'actual-key'}))
        self.append(record(status='interrupted'))
        self.journal.update()
        self.assertEqual(self.journal.read_record('a')['status'], 'interrupted')
        self.assertEqual(self.journal.read_record('a', 1)['analysis']['ProductCode'], 'actual-key')
        with self.assertRaises(KeyError):
            self.journal.read_record('a', 3)
        self.assertNotIn('analysis', self.journal.latest['a'])

    def test_search_filters_all_references_and_paginates_latest_records(self):
        row = record('a', references=[{'id': 'First.App', 'version': '1'},
                                     {'id': 'Other.App', 'version': '2', 'architecture': 'arm64'}],
                     scope_differences=[{'scope': 'user'}], flags=['simulation_warning'])
        self.append(row)
        self.append(record('b', 'download_failed'))
        self.journal.update()
        self.assertEqual(self.journal.search('ARM64')['items'][0]['sha256'], 'a')
        self.assertEqual(self.journal.search(flag='differences')['total'], 1)
        self.assertEqual(self.journal.search(flag='simulation_warning')['total'], 1)
        self.assertEqual(self.journal.search(status='download_failed')['items'][0]['sha256'], 'b')
        self.assertEqual(self.journal.search(offset=1, limit=1)['items'][0]['sha256'], 'a')
        self.assertNotIn('search', self.journal.search()['items'][0])

    def test_numeric_paths_are_flagged_without_rewriting_historical_records(self):
        self.append(record(analysis={'InstallationMetadata': {'DefaultInstallLocation': r'0\app'}}))
        self.journal.update()
        self.assertEqual(self.journal.search(flag='suspicious_install_location')['total'], 1)
        self.assertNotIn('flags', self.journal.read_record('a'))
        self.append(record(analysis={'InstallationMetadata': {'DefaultInstallLocation': r'%LocalAppData%\Programs\app'}}))
        self.journal.update()
        self.assertEqual(self.journal.search(flag='suspicious_install_location')['total'], 0)


if __name__ == '__main__':
    unittest.main()
