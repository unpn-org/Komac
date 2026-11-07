#!/usr/bin/env python3
"""Count distinct artifacts, separating analysis attempts from correctness checks."""
import argparse
from collections import Counter
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', type=Path)
args = parser.parse_args()
latest, attempted, output, verified, binaries, literals = {}, set(), set(), set(), set(), set()
runs = 0
with args.results.open() as stream:
    for line in stream:
        result = json.loads(line)
        sha = result['sha256']
        runs += 1
        latest[sha] = result
        binaries.add(result.get('analyzer_sha256'))
        if 'returncode' in result or result['status'] == 'analysis_timeout':
            attempted.add(sha)
        if result['status'] == 'ok':
            output.add(sha)
        if result.get('arp_verified'):
            verified.add(sha)
        if result.get('independent_arp_check', {}).get('corroborated_fields'):
            literals.add(sha)
print(json.dumps({
    'runs': runs,
    'unique_artifacts_with_results': len(latest),
    'unique_analysis_attempts': len(attempted),
    'unique_artifacts_returning_output': len(output),
    'independently_verified_arp_artifacts': len(verified),
    'unique_artifacts_with_literal_arp_corroboration': len(literals),
    'latest_literal_check_status': dict(Counter(r.get('independent_arp_check', {}).get('status', 'not_checked') for r in latest.values())),
    'analyzer_versions': len(binaries),
    'latest_status_by_artifact': dict(Counter(r['status'] for r in latest.values())),
}, indent=2))
