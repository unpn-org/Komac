#!/usr/bin/env python3
"""Live, read-only NSIS audit monitor. Uses only the Python standard library."""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
from urllib.parse import parse_qs, urlsplit


class Journal:
    """Tail complete records, keeping distinct-artifact coverage across rechecks."""
    def __init__(self, path):
        self.path = path
        self.identity = None
        self.offset = 0
        self.reset()

    def reset(self):
        self.offset = 0
        self.runs = self.invalid = 0
        self.latest = {}
        self.records = {}
        self.history = defaultdict(list)
        self.attempted, self.output, self.literals, self.verified = set(), set(), set(), set()
        self.recent = deque(maxlen=25)

    def update(self):
        try:
            with self.path.open('rb') as stream:
                stat = os.fstat(stream.fileno())
                identity = (stat.st_dev, stat.st_ino)
                if identity != self.identity or stat.st_size < self.offset:
                    self.reset()
                    self.identity = identity
                stream.seek(self.offset)
                while line := stream.readline():
                    record_offset = self.offset
                    # A writer may be between writes. Retry the unfinished row.
                    if not line.endswith(b'\n'):
                        break
                    self.offset = stream.tell()
                    try:
                        result = json.loads(line)
                        sha, status = result['sha256'], result['status']
                        ref = result['references'][0]
                    except (ValueError, KeyError, IndexError, TypeError):
                        self.invalid += 1
                        continue
                    self.runs += 1
                    self.records[self.runs] = (record_offset, len(line))
                    self.history[sha].append(self.runs)
                    if 'returncode' in result or status == 'analysis_timeout':
                        self.attempted.add(sha)
                    if status == 'ok':
                        self.output.add(sha)
                    evidence = result.get('independent_arp_check', {})
                    analysis = result.get('analysis', {})
                    installers = analysis.get('Installers', [analysis.get('Installer', analysis)]) if isinstance(analysis, dict) else analysis
                    flags = list(result.get('flags', []))
                    if any(re.match(r'^[+-]?\d+(?:[\\/]|$)', installer.get('InstallationMetadata', {}).get('DefaultInstallLocation', ''))
                           for installer in (installers or [])) and 'suspicious_install_location' not in flags:
                        flags.append('suspicious_install_location')
                    if evidence.get('corroborated_fields'):
                        self.literals.add(sha)
                    if result.get('arp_verified'):
                        self.verified.add(sha)
                    item = {'sha256': sha, 'package': ref['id'], 'version': ref.get('version', ''),
                            'status': status, 'flags': flags,
                            'errors': len(result.get('simulation_errors', [])),
                            'warnings': len(result.get('simulation_warnings', [])),
                            'literal_check': evidence.get('status', 'not_checked'),
                            'bytes': result.get('bytes'), 'seconds': result.get('seconds'),
                            'timings': result.get('timings', {}), 'job_kind': result.get('job_kind'),
                            'differences': sum(len(result.get(key, [])) for key in
                                ('arp_differences', 'scope_differences', 'product_code_differences')),
                            'search': ' '.join(str(ref.get(key, '')) for ref in result['references']
                                               for key in ('id', 'version', 'architecture')).casefold(),
                            'sequence': self.runs}
                    self.latest[sha] = item
                    self.recent.appendleft(item)
        except FileNotFoundError:
            pass

    def read_record(self, sha, sequence=None):
        if sha not in self.latest:
            raise KeyError('No completed result recorded for this artifact yet')
        sequence = sequence or self.latest[sha]['sequence']
        if sequence not in self.history[sha]:
            raise KeyError('Unknown result for this artifact')
        offset, length = self.records[sequence]
        with self.path.open('rb') as stream:
            stat = os.fstat(stream.fileno())
            if (stat.st_dev, stat.st_ino) != self.identity:
                raise KeyError('Journal changed; refresh the results list')
            stream.seek(offset)
            result = json.loads(stream.read(length))
        if result.get('sha256') != sha:
            raise KeyError('Journal changed; refresh the results list')
        return result

    def search(self, query='', status='', flag='', offset=0, limit=50):
        query = query.casefold()
        items = [item for item in self.latest.values()
                 if (not query or query in item['search'] or query in item['sha256'])
                 and (not status or item['status'] == status)
                 and (not flag or (flag == 'differences' and item['differences']) or flag in item['flags'])]
        items.sort(key=lambda item: item['sequence'], reverse=True)
        return {'total': len(items), 'offset': offset, 'limit': limit,
                'items': [{key: value for key, value in item.items() if key != 'search'}
                          for item in items[offset:offset + limit]]}


class Monitor:
    def __init__(self, root):
        self.root = root
        self.journal = Journal(root / 'results.jsonl')
        self.total = 0
        self.index_identity = None
        self.cached = None
        self.refreshed = 0
        self.observations = {}

    def snapshot(self):
        if self.cached is not None and time.monotonic() - self.refreshed < 5:
            return self.cached
        self.journal.update()
        index = self.root / 'index.jsonl'
        try:
            stat = index.stat()
            identity = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
            if identity != self.index_identity:
                with index.open('rb') as stream:
                    self.total = sum(bool(line.strip()) for line in stream)
                self.index_identity = identity
        except FileNotFoundError:
            self.total = 0
        worker, locked = {}, False
        try:
            with self.journal.path.with_suffix('.lock').open() as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    fcntl.flock(stream, fcntl.LOCK_UN)
                except BlockingIOError:
                    locked = True
                worker = json.load(stream)
        except (OSError, ValueError):
            pass
        now = time.time()
        active = []
        if locked:
            for path in (self.root / 'downloads').glob('nsis-*/activity.json'):
                try:
                    item = json.loads(path.read_text())
                    if item.get('pid') != worker.get('pid'):
                        continue
                    item['age_seconds'] = max(0, int(now - item['phase_started']))
                    item['bytes'] = sum(p.stat().st_size for p in path.parent.glob('installer.*'))
                    prior = self.observations.get(item['sha256'])
                    item['download_bytes_per_second'] = (max(0, item['bytes'] - prior[1]) / (now - prior[0])
                        if prior and now > prior[0] and item['phase'] == 'download' else None)
                    self.observations[item['sha256']] = (now, item['bytes'])
                    active.append(item)
                except (OSError, ValueError, KeyError):
                    continue
        active_hashes = {item['sha256'] for item in active}
        self.observations = {sha: observation for sha, observation in self.observations.items() if sha in active_hashes}
        session, session_resources = {}, {}
        try:
            with (self.root / 'progress.log').open('rb') as stream:
                first = stream.readline()
                end = stream.seek(0, 2)
                stream.seek(max(0, end - 65536))
                lines = stream.read().splitlines()
            header = json.loads(first)
            session_resources = header.get('resources', {})
            for line in reversed(lines):
                try:
                    row = json.loads(line)
                    if 'finished' in row:
                        session = row
                        break
                except ValueError:
                    continue
            session['queued_at_start'] = header.get('pending')
        except (OSError, ValueError):
            pass
        memory, worker_rss = None, None
        try:
            memory = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                          if line.startswith('MemAvailable:'))
            if locked and isinstance(worker.get('pid'), int):
                worker_rss = next(int(line.split()[1]) * 1024
                                  for line in Path(f"/proc/{worker['pid']}/status").read_text().splitlines()
                                  if line.startswith('VmRSS:'))
        except (OSError, StopIteration):
            pass
        latest = self.journal.latest.values()
        statuses = dict(Counter(item['status'] for item in latest))
        latest_checks = dict(Counter(item['literal_check'] for item in latest))
        try:
            updated = self.journal.path.stat().st_mtime
        except OSError:
            updated = None
        resources = {**session_resources, 'memory_available_bytes': memory,
                     'worker_rss_bytes': worker_rss, 'disk_free_bytes': shutil.disk_usage(self.root).free}
        try:
            resources['limits'] = json.loads((self.root / 'resource-policy.json').read_text())
        except (OSError, ValueError):
            resources['limits'] = {}
        self.cached = {
            'updated_at': datetime.now(timezone.utc).isoformat(), 'worker_running': locked,
            'journal_updated_at': updated, 'total_artifacts': self.total,
            'analyzed_artifacts': len(self.journal.attempted),
            'artifacts_returning_metadata': len(self.journal.output),
            'literal_arp_corroborated': len(self.journal.literals),
            'runtime_arp_verified': len(self.journal.verified),
            'journaled_artifacts': len(self.journal.latest), 'runs': self.journal.runs,
            'invalid_records': self.journal.invalid, 'latest_statuses': statuses,
            'latest_literal_checks': latest_checks,
            'artifacts_with_simulation_errors': sum(item['errors'] > 0 for item in latest),
            'artifacts_with_warnings': sum(item['warnings'] > 0 for item in latest),
            'literal_conflicts': sum('literal_arp_conflict' in item['flags'] for item in latest),
            'recent_timings': {key: round(sum(item['timings'].get(key, 0) for item in self.journal.recent) /
                max(1, sum(key in item['timings'] for item in self.journal.recent)), 3)
                for key in ('download', 'analysis_wait', 'analysis', 'independent_check')
                if any(key in item['timings'] for item in self.journal.recent)},
            'active': sorted(active, key=lambda item: (item['phase'], item['package'])),
            'recent': list(self.journal.recent), 'session': session, 'resources': resources,
        }
        self.refreshed = time.monotonic()
        return self.cached


def human_bytes(value):
    return 'unavailable' if value is None else f'{value / (1024 ** 3):.1f} GiB'


def terminal(data):
    total, analyzed = data['total_artifacts'], data['analyzed_artifacts']
    percent = 100 * analyzed / total if total else 0
    lines = [f"NSIS audit | {'RUNNING' if data['worker_running'] else 'STOPPED'} | {data['updated_at']}",
             f'Analyzed: {analyzed:,} / {total:,} ({percent:.2f}%)',
             f"Returned metadata: {data['artifacts_returning_metadata']:,} | Literal ARP corroborated: {data['literal_arp_corroborated']:,} | Runtime verified: {data['runtime_arp_verified']:,}",
             f"Journal: {data['runs']:,} runs, {data['journaled_artifacts']:,} distinct artifacts (includes download failures)",
             'Latest statuses: ' + ', '.join(f'{key}={value:,}' for key, value in sorted(data['latest_statuses'].items())),
             f"Available RAM: {human_bytes(data['resources']['memory_available_bytes'])} | Free disk: {human_bytes(data['resources']['disk_free_bytes'])}",
             '', 'Current work:']
    for job in data['active']:
        phase = 'downloading / queued' if job['phase'] == 'download' else job['phase']
        lines.append(f"  {job['package'][:65]:65} {phase:23} {job['age_seconds']:>5}s {job['bytes'] / 1048576:>8.1f} MiB")
    if not data['active']:
        lines.append('  No active jobs observed.')
    lines += ['', 'Recent results:']
    for row in data['recent'][:10]:
        lines.append(f"  {row['package']} {row['version']}: {row['status']}" +
                     (f" ({', '.join(row['flags'])})" if row['flags'] else ''))
    lines += ['', 'Coverage counts distinct installers. Rechecks do not increase it.',
              'Literal ARP matches are not runtime verification.']
    return '\n'.join(lines) + '\n'


def atomic_write(path, text):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(text)
    temp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('target/nsis-audit'))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--serve', type=int, metavar='PORT', help='serve a local live dashboard')
    mode.add_argument('--watch', action='store_true', help='refresh the terminal every five seconds')
    parser.add_argument('--host', default='127.0.0.1')
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    monitor = Monitor(args.root.resolve())

    def publish():
        data = monitor.snapshot()
        atomic_write(args.root / 'progress.json', json.dumps(data, indent=2) + '\n')
        atomic_write(args.root / 'progress.txt', terminal(data))
        return data

    if args.serve is None:
        try:
            while True:
                data = monitor.snapshot()
                if args.watch and sys.stdout.isatty():
                    print('\033[2J\033[H', end='')
                print(terminal(data), end='', flush=True)
                if not args.watch:
                    break
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        return

    html = Path(__file__).with_suffix('.html').read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            path, query = url.path, parse_qs(url.query)
            try:
                if path in ('/', '/index.html'):
                    body, content_type = html, 'text/html; charset=utf-8'
                elif path == '/api/progress':
                    body, content_type = json.dumps(monitor.snapshot()).encode(), 'application/json'
                elif path == '/api/artifacts':
                    monitor.snapshot()
                    offset = max(0, int(query.get('offset', ['0'])[0]))
                    limit = max(1, min(100, int(query.get('limit', ['50'])[0])))
                    result = monitor.journal.search(query.get('q', [''])[0], query.get('status', [''])[0],
                                                    query.get('flag', [''])[0], offset, limit)
                    body, content_type = json.dumps(result).encode(), 'application/json'
                elif match := re.fullmatch(r'/api/artifacts/([0-9a-f]{64})(/trace)?', path):
                    monitor.snapshot()
                    sha, trace = match.groups()
                    sequence = int(query['run'][0]) if 'run' in query else None
                    result = monitor.journal.read_record(sha, sequence)
                    if trace:
                        trace_path = Path(result.get('log_file', '')).resolve()
                        if not trace_path.is_relative_to((monitor.root / 'logs').resolve()) or not trace_path.is_file():
                            raise KeyError('No saved trace is available for this result')
                        with trace_path.open('rb') as stream:
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/gzip')
                            self.send_header('Content-Disposition', f'attachment; filename="{sha}.log.gz"')
                            self.send_header('Content-Length', str(os.fstat(stream.fileno()).st_size))
                            self.end_headers()
                            try:
                                shutil.copyfileobj(stream, self.wfile, 65536)
                            except (OSError, TimeoutError):
                                pass
                        return
                    history = []
                    for seq in reversed(monitor.journal.history[sha]):
                        row = monitor.journal.read_record(sha, seq)
                        history.append({'run': seq, 'status': row['status'],
                                        'analyzer_sha256': row.get('analyzer_sha256'),
                                        'seconds': row.get('seconds')})
                    body = json.dumps({'result': result, 'history': history,
                                       'run': sequence or monitor.journal.latest[sha]['sequence']}).encode()
                    content_type = 'application/json'
                else:
                    self.send_error(404)
                    return
            except (ValueError, KeyError, OSError) as error:
                body, content_type = json.dumps({'error': str(error)}).encode(), 'application/json'
                self.send_response(404 if isinstance(error, (KeyError, OSError)) else 400)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    class LocalServer(HTTPServer):
        def get_request(self):
            client, address = super().get_request()
            client.settimeout(3)
            return client, address

    server = LocalServer((args.host, args.serve), Handler)
    server.timeout = 1
    publish()
    print(f'NSIS progress: http://{args.host}:{server.server_port}', flush=True)
    try:
        last_publish = time.monotonic()
        while True:
            server.handle_request()
            if time.monotonic() - last_publish >= 5:
                publish()
                last_publish = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
