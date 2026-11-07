#!/usr/bin/env python3
"""Resumable winget NSIS corpus audit. Requires Python 3 and PyYAML.

Index a winget-pkgs checkout or GitHub tar.gz snapshot, then download each unique
artifact, verify its SHA256, and run Komac in an isolated subprocess. Manifest ARP
differences are triage candidates, not proof that Komac is wrong. Installers are
never executed. JSONL results retain errors, timeouts and unavailable downloads.
"""
import argparse
import concurrent.futures
import hashlib
import gzip
import fcntl
import shutil
import signal
import socket
import threading
import http.client
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import yaml

if __package__:
    from .independent_nsis import inspect_literals, compare_literals
else:
    from independent_nsis import inspect_literals, compare_literals

DISK_RESERVE = 3 * 1024 * 1024 * 1024


def manifests(source):
    if source.is_dir():
        for path in sorted(source.rglob('*.installer.yaml')):
            yield str(path.relative_to(source)), path.read_bytes()
    else:
        with tarfile.open(source, 'r|gz') as archive:
            for member in archive:
                if member.isfile() and member.name.endswith('.installer.yaml'):
                    yield member.name.split('/', 1)[-1], archive.extractfile(member).read()


def index(source, output):
    artifacts = {}
    count = 0
    for path, raw in manifests(source):
        if b'nullsoft' not in raw.lower():
            continue
        # The fields compared here have string scalar types. Avoid YAML 1.1
        # coercion of numeric-looking versions and names.
        manifest = yaml.load(raw, Loader=yaml.CBaseLoader)
        for child in manifest.get('Installers', []):
            effective = {**manifest, **child}
            if effective.get('InstallerType') != 'nullsoft' and effective.get('NestedInstallerType') != 'nullsoft':
                continue
            count += 1
            sha = effective['InstallerSha256'].lower()
            artifact = artifacts.setdefault(sha, {'sha256': sha, 'urls': [], 'references': []})
            url = effective['InstallerUrl']
            if url not in artifact['urls']:
                artifact['urls'].append(url)
            artifact['references'].append({
                'manifest': path, 'id': manifest['PackageIdentifier'],
                'version': str(manifest['PackageVersion']),
                'architecture': effective['Architecture'],
                'scope': effective.get('Scope'),
                'nested_files': effective.get('NestedInstallerFiles', []),
                'type': effective.get('InstallerType'),
                'arp': effective.get('AppsAndFeaturesEntries', []),
                'product_code': effective.get('ProductCode'),
            })
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w') as stream:
        for artifact in artifacts.values():
            stream.write(json.dumps(artifact) + '\n')
    print(json.dumps({'references': count, 'unique_artifacts': len(artifacts), 'index': str(output)}), flush=True)


class DownloadBudget:
    def __init__(self, mibps):
        self.rate = mibps * 1024 * 1024
        self.next = 0.0
        self.lock = threading.Lock()

    def consume(self, count, args):
        if not self.rate: return
        with self.lock:
            now = time.monotonic()
            until = max(now, self.next)
            self.next = until + count / self.rate
        while not args.stopping and (delay := until - time.monotonic()) > 0:
            time.sleep(min(delay, 0.25))


def wait_for_memory(args):
    while not args.stopping:
        try:
            available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))
        except (OSError, StopIteration):
            return True
        if available >= args.headroom_mib * 1024:
            return True
        time.sleep(5)
    return False


def resolver_available():
    """A dead vendor hostname must not stop a healthy machine's whole audit."""
    for host in ('github.com', 'www.microsoft.com'):
        try:
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            return True
        except socket.gaierror:
            continue
    return False


def pending_artifacts(artifacts, completed, ever_analyzed, priorities=(), regressions=()):
    # Advance coverage before rechecks, and visit varied packages before versions.
    seen = set()
    def priority(artifact):
        family = artifact['references'][0]['id']
        repeated = family in seen
        seen.add(family)
        artifact['previously_analyzed'] = artifact['sha256'] in ever_analyzed
        return artifact['sha256'] not in regressions, family not in priorities, artifact['previously_analyzed'], repeated, artifact['sha256']
    return sorted((artifact for artifact in artifacts if artifact['sha256'] not in completed), key=priority)


def resume_summary(result):
    """Retain only the fields needed to decide whether an artifact needs work."""
    summary = {key: result[key] for key in
               ('sha256', 'status', 'analyzer_sha256', 'independent_reader_sha256', 'nested_path')
               if key in result}
    summary['references'] = [{key: reference[key] for key in ('id', 'type')}
                             for reference in result['references']]
    summary['simulation_errors'] = bool(result.get('simulation_errors'))
    summary['independent_arp_check'] = {'status': result.get('independent_arp_check', {}).get('status')}
    return summary


def save_trace(path, result, args):
    errors = []
    warnings = []
    with path.open(errors='replace') as stream:
        for line in stream:
            prefix = re.sub(r'\x1b\[[0-9;]*m', '', line).lstrip() if '\x1b' in line else line.lstrip()
            if prefix.startswith('ERROR ') and len(errors) < 100:
                errors.append(line.rstrip())
            if prefix.startswith('WARN ') and len(warnings) < 100:
                warnings.append(line.rstrip())
    result['simulation_errors'] = errors
    result['simulation_warnings'] = warnings
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 65536))
        tail = stream.read().decode(errors='replace')
    if args.logs:
        log = args.logs / args.analyzer_sha256 / args.runner_sha256 / (result['sha256'] + '.log.gz')
        log.parent.mkdir(parents=True, exist_ok=True)
        with path.open('rb') as source, gzip.open(log, 'wb') as destination:
            shutil.copyfileobj(source, destination, 65536)
        result['log_file'] = str(log)
    else:
        result['stderr_tail'] = tail
    return tail


def installers_from_output(actual):
    if isinstance(actual, dict):
        actual = actual.get('Installers', [actual.get('Installer', actual)])
    if not isinstance(actual, list) or not actual or not all(isinstance(item, dict) for item in actual):
        raise ValueError('expected one or more installer mappings in analyzer output')
    return actual


def request_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('installer URL must use HTTP or HTTPS')
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc.encode('idna').decode('ascii'),
        urllib.parse.quote(parts.path, safe="/%:@!$&'()*+,;=-._~"),
        urllib.parse.quote(parts.query, safe="%/:?@!$&'()*+,;=-._~"), parts.fragment))


def select_nested(archive_path, artifact, work, stopping=lambda: False):
    paths = {item['RelativeFilePath'].replace('\\', '/') for ref in artifact['references']
             for item in ref.get('nested_files', [])}
    if len(paths) != 1:
        raise ValueError('a unique manifest-selected nested installer is required')
    selected = next(iter(paths))
    with zipfile.ZipFile(archive_path) as archive:
        members = [item for item in archive.infolist()
                   if item.filename.replace('\\', '/').casefold() == selected.casefold() and not item.is_dir()]
        if len(members) != 1:
            raise ValueError(f'nested installer is missing or ambiguous: {selected}')
        member = members[0]
        if member.file_size > shutil.disk_usage(work).free - DISK_RESERVE:
            raise ValueError('nested installer exceeds available disk reserve')
        # Never extract an archive-controlled path onto the filesystem.
        output = work / ('selected' + Path(selected).suffix)
        digest = hashlib.sha256()
        with archive.open(member) as source, output.open('wb') as destination:
            while data := source.read(1024 * 1024):
                if stopping():
                    raise InterruptedError('nested extraction interrupted')
                if shutil.disk_usage(work).free < DISK_RESERVE:
                    raise OSError('disk space reserve reached during nested extraction')
                digest.update(data)
                destination.write(data)
    return output, selected, digest.hexdigest()


def audit(artifact, args):
    started = time.monotonic()
    result = audit_artifact(artifact, args)
    result['seconds'] = round(time.monotonic() - started, 3)
    result['finished_at'] = time.time()
    return result


def audit_artifact(artifact, args):
    result = {'sha256': artifact['sha256'], 'references': artifact['references'],
              'analyzer_sha256': args.analyzer_sha256, 'runner_sha256': args.runner_sha256,
              'independent_reader_sha256': args.independent_reader_sha256,
              'arp_verified': False,
              'job_kind': 'recheck' if artifact.get('previously_analyzed') else 'new',
              'started_at': time.time(), 'timings': {}}
    started = time.monotonic()
    errors = []
    if not re.fullmatch('[0-9a-f]{64}', artifact['sha256']):
        return {**result, 'status': 'audit_error', 'error': 'invalid artifact SHA256'}
    with tempfile.TemporaryDirectory(prefix='nsis-', dir=args.work) as temp:
        previous_phase, phase_clock, phase_wall = None, started, time.time()
        def activity(phase, **progress):
            nonlocal previous_phase, phase_clock, phase_wall
            if phase != previous_phase:
                clock = time.monotonic()
                if previous_phase is not None:
                    result['timings'][previous_phase] = round(
                        result['timings'].get(previous_phase, 0) + clock - phase_clock, 3)
                previous_phase, phase_clock, phase_wall = phase, clock, time.time()
            temporary = Path(temp) / 'activity.tmp'
            temporary.write_text(json.dumps({
                'pid': os.getpid(), 'sha256': artifact['sha256'],
                'package': artifact['references'][0]['id'],
                'version': artifact['references'][0]['version'],
                'job_kind': result['job_kind'], 'phase': phase,
                'analyzer_sha256': args.analyzer_sha256, 'runner_sha256': args.runner_sha256,
                'phase_started': phase_wall, 'started_at': result['started_at'], **progress,
            }))
            temporary.replace(Path(temp) / 'activity.json')
        activity('download')
        path = Path(temp) / ('installer.zip' if artifact['references'][0]['type'] == 'zip' else 'installer.exe')
        if args.failure_cache:
            cached = args.failure_cache / (artifact['sha256'] + path.suffix)
            if cached.is_file():
                activity('cache')
                try:
                    digest = hashlib.sha256()
                    with cached.open('rb') as source, path.open('wb') as destination:
                        while data := source.read(1024 * 1024):
                            if args.stopping: return {**result, 'status': 'interrupted'}
                            digest.update(data)
                            destination.write(data)
                    if digest.hexdigest() == artifact['sha256']:
                        result.update(bytes=path.stat().st_size, url=artifact['urls'][0], cache_hit=True)
                    else:
                        result['cache_error'] = 'cached artifact hash mismatch; retrying download'
                except OSError as error:
                    result['cache_error'] = str(error)
        for url in artifact['urls']:
            if result.get('cache_hit'): break
            activity('download')
            if not wait_for_memory(args): return {**result, 'status': 'interrupted'}
            try:
                request = urllib.request.Request(request_url(url), headers={'User-Agent': 'Komac-NSIS-audit/1.0'})
                digest = hashlib.sha256()
                size = 0
                with urllib.request.urlopen(request, timeout=30) as response, path.open('wb') as stream:
                    total = response.headers.get('Content-Length', '')
                    total = int(total) if total.isdigit() else None
                    last_update = 0
                    # read() can wait indefinitely to fill the entire request
                    # on a trickling server. read1() returns available data so
                    # cancellation, deadlines, and progress remain responsive.
                    read_chunk = getattr(response, 'read1', response.read)
                    while data := read_chunk(1024 * 1024):
                        if args.stopping:
                            return {**result, 'status': 'interrupted'}
                        size += len(data)
                        if shutil.disk_usage(args.work).free < DISK_RESERVE:
                            raise OSError('disk space reserve reached')
                        if args.max_bytes and size > args.max_bytes:
                            raise ValueError('download exceeds --max-bytes')
                        if time.monotonic() - started > args.download_timeout:
                            raise TimeoutError('download deadline exceeded')
                        args.download_budget.consume(len(data), args)
                        digest.update(data)
                        stream.write(data)
                        if time.monotonic() - last_update >= 1:
                            activity('download', downloaded_bytes=size, total_bytes=total)
                            last_update = time.monotonic()
                if digest.hexdigest() != artifact['sha256']:
                    raise ValueError(f'SHA256 mismatch: {digest.hexdigest()}')
                result.update(url=url, bytes=size)
                activity('download_complete', downloaded_bytes=size, total_bytes=size)
                break
            except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException) as error:
                errors.append({'url': url, 'error': str(error)})
                if 'disk space reserve reached' in str(error) or getattr(error, 'errno', None) == 28:
                    args.stopping = True
                    return {**result, 'status': 'resource_limited', 'reason': 'disk_reserve', 'errors': errors}
                # A broken executor resolver says nothing about the artifact.
                # Stop promptly rather than recording thousands of false URL failures.
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                if isinstance(reason, socket.gaierror) and not resolver_available():
                    args.stopping = True
                    return {**result, 'status': 'infrastructure_error', 'errors': errors}
        else:
            return {**result, 'status': 'download_failed', 'errors': errors}
        if artifact['references'][0]['type'] == 'zip':
            activity('archive')
            try:
                path, selected, digest = select_nested(path, artifact, Path(temp), lambda: args.stopping)
                result.update(nested_path=selected, nested_sha256=digest)
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
                if args.stopping:
                    return {**result, 'status': 'interrupted'}
                return {**result, 'status': 'archive_error', 'error': str(error)}
        trace_path = Path(temp) / 'analysis.log'
        try:
            command = [str(args.komac), 'analyze', str(path)]
            if args.prlimit:
                limits = ['--core=0']
                if args.memory_mib: limits.append(f'--as={args.memory_mib * 1024 * 1024}')
                if args.trace_mib: limits.append(f'--fsize={args.trace_mib * 1024 * 1024}')
                command = [args.prlimit, *limits, '--', *command]
            activity('analysis_wait')
            with args.analysis_slots, trace_path.open('w') as trace:
                if not wait_for_memory(args): return {**result, 'status': 'interrupted'}
                activity('analysis')
                proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=trace,
                                      text=True, timeout=args.analysis_timeout,
                                      env={**os.environ, 'NO_COLOR': '1', 'RUST_BACKTRACE': '1', 'RUST_LOG': 'warn'})
                activity('independent_check')
                result['independent_arp_check'] = (inspect_literals(path) if not args.stopping
                                                   else {'status': 'interrupted', 'runtime_verified': False})
                activity('postprocess')
            result.update(returncode=proc.returncode, stdout=proc.stdout)
            stderr = save_trace(trace_path, result, args)
            result['status'] = 'ok' if proc.returncode == 0 else 'analysis_failed'
            if proc.returncode in (-signal.SIGINT, -signal.SIGTERM):
                result.update(status='interrupted', reason='analysis interrupted by a signal')
            if proc.returncode != 0 and any(message in stderr.lower() for message in
                    ('memory allocation of', 'cannot allocate memory', 'out of memory')):
                result['status'] = 'resource_limited'
                result['memory_mib'] = args.memory_mib
            if proc.returncode == -signal.SIGXFSZ:
                result.update(status='resource_limited', reason='trace_size_limit')
            if proc.returncode == 0:
                actual = yaml.load(proc.stdout, Loader=yaml.CBaseLoader)
                result['analysis'] = actual
                installers = installers_from_output(actual)
                result['independent_arp_check'] = compare_literals(result['independent_arp_check'], installers)
                result['installer_count'] = len(installers)
                result['flags'] = []
                if not any(installer.get('InstallerType') == 'nullsoft' or
                           installer.get('NestedInstallerType') == 'nullsoft' for installer in installers):
                    result['flags'].append('nsis_not_detected')
                if '$ERROR' in proc.stdout:
                    result['flags'].append('string_resolution_error')
                if any(re.match(r'^[+-]?\d+(?:[\\/]|$)', installer.get('InstallationMetadata', {}).get('DefaultInstallLocation', ''))
                       for installer in installers):
                    result['flags'].append('suspicious_install_location')
                if result['simulation_errors']:
                    result['flags'].append('simulation_error')
                if result.get('simulation_warnings'):
                    result['flags'].append('simulation_warning')
                if result['independent_arp_check'].get('candidate_conflicts'):
                    result['flags'].append('literal_arp_conflict')
                if not any(installer.get('AppsAndFeaturesEntries') for installer in installers):
                    result['flags'].append('no_arp_detected')
                result['arp_differences'] = []
                result['scope_differences'] = []
                result['product_code_differences'] = []
                for ref in artifact['references']:
                    architecture_candidates = [installer for installer in installers
                        if installer.get('Architecture') == ref['architecture']]
                    scopes = sorted({installer['Scope'] for installer in architecture_candidates if installer.get('Scope')})
                    if ref.get('scope') and scopes and ref['scope'] not in scopes:
                        result['scope_differences'].append({'reference': ref, 'analyzed_scopes': scopes})
                    codes = {entry.get('ProductCode', '').casefold() for installer in architecture_candidates
                        for entry in installer.get('AppsAndFeaturesEntries', [])}
                    codes.update(installer['ProductCode'].casefold() for installer in architecture_candidates if installer.get('ProductCode'))
                    if ref.get('product_code') and codes and ref['product_code'].casefold() not in codes:
                        result['product_code_differences'].append(ref)
                    candidates = [installer for installer in architecture_candidates
                        if
                        (not ref.get('scope') or installer.get('Scope') == ref['scope'])]
                    if ref['arp'] and not any(ref['arp'] == installer.get('AppsAndFeaturesEntries', [])
                                              for installer in candidates):
                        result['arp_differences'].append(ref)
        except subprocess.TimeoutExpired:
            result['status'] = 'analysis_timeout'
            if trace_path.exists(): save_trace(trace_path, result, args)
        except (yaml.YAMLError, ValueError, AttributeError) as error:
            result.update(status='output_error', error=str(error))
        if args.failure_cache and result.get('status') in ('analysis_failed', 'analysis_timeout', 'resource_limited'):
            try:
                with args.cache_lock:
                    size = path.stat().st_size
                    used = sum(item.stat().st_size for item in args.failure_cache.iterdir() if item.is_file())
                    if size <= 128 * 1024 * 1024 and used + size <= 2 * 1024 * 1024 * 1024:
                        cache_sha = result.get('nested_sha256', artifact['sha256'])
                        destination = args.failure_cache / (cache_sha + path.suffix)
                        if not destination.exists():
                            partial = destination.with_suffix('.partial')
                            shutil.copyfile(path, partial)
                            partial.replace(destination)
                        result['artifact_file'] = str(destination)
            except OSError as error:
                result['cache_error'] = str(error)

        activity('finished')

    result['seconds'] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='checkout or tar.gz; creates/replaces index')
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--results', type=Path)
    parser.add_argument('--komac', type=Path, default=Path('target/debug/komac'))
    parser.add_argument('--work', type=Path, default=Path('target/nsis-audit/downloads'))
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--analysis-jobs', type=int, default=2)
    parser.add_argument('--cpu-count', type=int, help='CPU affinity budget; default leaves two CPUs free')
    parser.add_argument('--memory-mib', type=int, default=6144, help='per-analysis virtual-memory cap; 0 disables')
    parser.add_argument('--trace-mib', type=int, default=512, help='per-analysis output file size cap')
    parser.add_argument('--download-mibps', type=float, default=32, help='aggregate download throughput cap; 0 disables')
    parser.add_argument('--headroom-mib', type=int, default=4096, help='wait before starting work if available memory is below this')
    parser.add_argument('--failure-cache', type=Path, help='retain failing artifacts up to 128 MiB, within a 2 GiB cache')
    parser.add_argument('--logs', type=Path, help='gzip full analysis traces separately')
    parser.add_argument('--priority-id', action='append', default=[], help='visit this package before the rest of the full corpus')
    parser.add_argument('--reuse-previous', action='store_true', help='also resume across older analyzer versions; provenance is retained')
    parser.add_argument('--recheck-id', action='append', default=[], help='with reuse-previous, recheck this package after analyzer changes')
    parser.add_argument('--recheck-errors', action='store_true', help='recheck previous interpreter errors and failed analyses after analyzer changes')
    parser.add_argument('--recheck-static', action='store_true', help='recheck missing or older independent bytecode checks')
    parser.add_argument('--regression-shas', type=Path, help='recheck and prioritize only these exact SHA256 artifacts after a relevant fix')
    parser.add_argument('--limit', type=int, default=0, help='0 audits every indexed artifact')
    parser.add_argument('--max-bytes', type=int, default=0, help='0 means unlimited; skips are recorded')
    parser.add_argument('--download-timeout', type=int, default=180)
    parser.add_argument('--analysis-timeout', type=int, default=120)
    args = parser.parse_args()
    regression_shas = set(args.regression_shas.read_text().split()) if args.regression_shas else set()
    if any(not re.fullmatch('[0-9a-f]{64}', sha) for sha in regression_shas):
        parser.error('regression-shas must contain lowercase SHA256 hashes')
    if min(args.jobs, args.analysis_jobs) < 1 or min(args.memory_mib, args.trace_mib, args.headroom_mib, args.download_mibps) < 0:
        parser.error('concurrency must be positive and memory-mib nonnegative')
    if hasattr(os, 'sched_getaffinity'):
        available = sorted(os.sched_getaffinity(0))
        cpu_count = args.cpu_count or max(1, len(available) - 2)
        if not 1 <= cpu_count <= len(available):
            parser.error('cpu-count exceeds available CPUs')
        os.sched_setaffinity(0, available[:cpu_count])
    if hasattr(os, 'nice'):
        os.nice(10)
    args.prlimit = shutil.which('prlimit')
    if args.results and (args.memory_mib or args.trace_mib) and not args.prlimit:
        parser.error('prlimit is required to enforce memory limits')
    args.stopping = False
    def stop(signum, frame):
        args.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if args.source:
        index(args.source, args.index)
    if not args.results:
        return
    args.komac = args.komac.resolve()
    args.binary_profile = 'release' if 'release' in args.komac.parts else 'debug'
    if not args.komac.is_file():
        parser.error(f'Komac binary missing: {args.komac}')
    args.analyzer_sha256 = hashlib.sha256(args.komac.read_bytes()).hexdigest()
    independent_source = Path(inspect_literals.__code__.co_filename).read_bytes()
    args.independent_reader_sha256 = hashlib.sha256(independent_source).hexdigest()
    runner_source = Path(__file__).read_bytes()
    args.runner_sha256 = hashlib.sha256(runner_source + b'\0' + independent_source).hexdigest()
    # A running audit must not silently switch binaries when Cargo rebuilds.
    binary = args.work / 'analyzers' / args.analyzer_sha256 / args.komac.name
    binary.parent.mkdir(parents=True, exist_ok=True)
    if not binary.exists():
        shutil.copy2(args.komac, binary)
    with binary.open('rb') as stream:
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024): digest.update(chunk)
    if digest.hexdigest() != args.analyzer_sha256:
        parser.error('analyzer changed during snapshot; restart after the build finishes')
    runner_snapshot = binary.parent / args.runner_sha256
    runner_snapshot.mkdir(exist_ok=True)
    (runner_snapshot / 'audit_nsis.py').write_bytes(runner_source)
    (runner_snapshot / 'independent_nsis.py').write_bytes(independent_source)
    args.komac = binary.resolve()
    args.analysis_slots = threading.Semaphore(args.analysis_jobs)
    args.download_budget = DownloadBudget(args.download_mibps)
    args.cache_lock = threading.Lock()
    if args.failure_cache:
        args.failure_cache.mkdir(parents=True, exist_ok=True)
    if args.logs:
        args.logs.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.writer_lock = args.results.with_suffix('.lock').open('a+')
    try:
        fcntl.flock(args.writer_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error('another audit is already writing this results file')
    args.writer_lock.seek(0)
    args.writer_lock.truncate()
    json.dump({'pid': os.getpid(), 'results': str(args.results.resolve()),
               'index': str(args.index.resolve()), 'analyzer_sha256': args.analyzer_sha256}, args.writer_lock)
    args.writer_lock.flush()
    completed, ever_analyzed = set(), set()
    if args.results.exists():
        latest = {}
        with args.results.open() as stream:
            for line in stream:
                previous = json.loads(line)
                if 'returncode' in previous or previous['status'] == 'analysis_timeout':
                    ever_analyzed.add(previous['sha256'])
                latest[previous['sha256']] = resume_summary(previous)
        for previous in latest.values():
            same_binary = previous.get('analyzer_sha256') == args.analyzer_sha256
            needs_recheck = previous['sha256'] in regression_shas or any(ref['id'] in args.recheck_id for ref in previous['references'])
            if args.recheck_errors and (previous.get('simulation_errors') or
                    previous['status'] in ('analysis_failed', 'analysis_timeout', 'resource_limited', 'output_error')):
                needs_recheck = True
            missing_static = args.recheck_static and previous['status'] in ('ok', 'analysis_failed', 'analysis_timeout', 'resource_limited', 'output_error') and (previous.get('independent_arp_check', {}).get('status') not in ('inspected', 'unsupported') or previous.get('independent_reader_sha256') != args.independent_reader_sha256)
            if missing_static:
                needs_recheck = True
            missing_nested_selection = any(ref['type'] == 'zip' for ref in previous['references']) and not previous.get('nested_path')
            if not missing_nested_selection and ((same_binary and not missing_static) or (args.reuse_previous and not needs_recheck)) and previous.get('status') not in ('interrupted', 'infrastructure_error', 'audit_error'):
                completed.add(previous['sha256'])
        del latest
    with args.index.open() as stream:
        artifacts = [json.loads(line) for line in stream]
    pending = pending_artifacts(artifacts, completed, ever_analyzed, args.priority_id, regression_shas)
    if args.limit:
        pending = pending[:args.limit]
    print(json.dumps({'indexed': len(artifacts), 'completed': len(completed), 'pending': len(pending),
                      'started_at': time.time(),
                      'resources': {'cpus': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
                                    'downloads': args.jobs, 'analyses': args.analysis_jobs,
                                    'download_mibps': args.download_mibps,
                                    'binary_profile': args.binary_profile,
                                    'memory_mib_per_analysis': args.memory_mib}}), flush=True)
    counts, work_counts, analysis_counts = {}, {'new': 0, 'recheck': 0}, {'new': 0, 'recheck': 0}
    with args.results.open('a', buffering=1) as stream, concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        iterator = iter(pending)
        futures = set()
        for artifact in iterator:
            futures.add(pool.submit(audit, artifact, args))
            if len(futures) >= args.jobs:
                break
        while futures:
            done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                result = future.result()
                stream.write(json.dumps(result, default=str) + '\n')
                status = result['status']
                counts[status] = counts.get(status, 0) + 1
                kind = result.get('job_kind', 'new')
                work_counts[kind] += 1
                if 'returncode' in result or status == 'analysis_timeout':
                    analysis_counts[kind] += 1
                print(json.dumps({'finished': sum(counts.values()), 'counts': counts,
                                  'work_counts': work_counts, 'analysis_counts': analysis_counts}), flush=True)
                artifact = None if args.stopping else next(iterator, None)
                if artifact is not None:
                    futures.add(pool.submit(audit, artifact, args))


if __name__ == '__main__':
    main()
