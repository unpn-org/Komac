#!/usr/bin/env python3
"""Compile known NSIS source and assert ARP against its writes, without manifests.

Usage: NSISDIR=... python3 scripts/check_nsis_fixture.py --makensis ... --komac ...
Requires PyYAML. Generated installers are analyzed, never executed.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import zlib
import yaml
from independent_nsis import inspect_literals, compare_literals

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--makensis', default='makensis')
parser.add_argument('--komac', type=Path, default=Path('target/debug/komac'))
args = parser.parse_args()
source = Path(__file__).resolve().parents[1] / 'tests/fixtures/nsis/arp.nsi'
expected = {
    'LogicalNot': {'DisplayName': 'Logical not', 'Publisher': '1:0', 'ProductCode': 'LogicalNot'},
    'Formatted': {'DisplayName': 'Formatted integers', 'Publisher': 'v07:0x000000FF', 'ProductCode': 'Formatted'},
    'SharedAppData': {'DisplayName': 'Shared app data', 'Publisher': '%ProgramData%', 'ProductCode': 'SharedAppData'},
    'UnicodeSlice': {'DisplayName': 'Unicode slicing', 'Publisher': '2:🚀:ab', 'ProductCode': 'UnicodeSlice'},
    'EmptyInternal': {'DisplayName': 'Empty internal app', 'Publisher': ':end', 'ProductCode': 'EmptyInternal'},
    'Numbers': {'DisplayName': 'Numeric app', 'Publisher': '65535:10', 'ProductCode': 'Numbers'},
    'Find': {'DisplayName': 'Find app', 'Publisher': 'arp.ini', 'ProductCode': 'Find'},
    'FullPath': {'DisplayName': 'Full path app', 'Publisher': r'%LocalAppData%\Programs\ARP regression\Payload', 'ProductCode': 'FullPath'},
    'Ini': {'DisplayName': 'INI app', 'DisplayVersion': '3.2.1', 'Publisher': 'From INI', 'ProductCode': 'Ini'},
    'OutputDirectory': {'DisplayName': r'%LocalAppData%\Programs\ARP regression\Payload', 'Publisher': '1033', 'ProductCode': 'OutputDirectory'},
    'Typed': {'DisplayName': 'Typed app', 'Publisher': '42', 'ProductCode': 'Typed'},
    'View': {'DisplayName': '32-bit entry', 'Publisher': '64-bit entry', 'ProductCode': 'View'},
    'Enumeration': {'DisplayName': 'Enumeration app', 'Publisher': 'First:Value', 'ProductCode': 'Enumeration'},
    'Main': {'DisplayName': 'Main app', 'DisplayVersion': '1.2.3',
             'Publisher': 'Publisher € 🚀 1.2.3', 'ProductCode': 'Main'},
    'Keep': {'DisplayName': 'Keep app', 'ProductCode': 'Keep'},
    'MachineContext': {'DisplayName': 'Machine context', 'Publisher': 'Machine context', 'ProductCode': 'MachineContext'},
    'UserContext': {'DisplayName': 'User context', 'Publisher': 'User context', 'ProductCode': 'UserContext'},
    'Callback': {'DisplayName': 'Callback app', 'ProductCode': 'Callback'},
}
with tempfile.TemporaryDirectory(prefix='nsis-oracle-') as temp:
    for compressor in ['zlib', 'bzip2', 'lzma', '/SOLID zlib', '/SOLID bzip2', '/SOLID lzma']:
        path = Path(temp) / 'arp.exe'
        subprocess.run([args.makensis, '-V2', f'-DOUTPUT={path}', f'-DCOMPRESSION={compressor}', str(source)], check=True)
        result = subprocess.run([str(args.komac.resolve()), 'analyze', str(path)], capture_output=True, text=True, check=True)
        # Preserve string scalars such as 65535:10; YAML 1.1 calls that an integer.
        actual = yaml.load(result.stdout, Loader=yaml.CBaseLoader)
        actual = actual.get('Installer', actual)
        entries = {entry['ProductCode']: entry for entry in actual.get('AppsAndFeaturesEntries', [])}
        assert entries == expected, (compressor, entries)
        assert actual['InstallationMetadata']['DefaultInstallLocation'] == r'%LocalAppData%\Programs\ARP regression', actual
        evidence = compare_literals(inspect_literals(path), [actual])
        if 'bzip2' not in compressor:
            assert evidence['status'] == 'inspected', (compressor, evidence)
            assert evidence.get('corroborated_fields') and not evidence.get('candidate_conflicts'), (compressor, evidence)
            # A bad value copied into a manifest must not become the oracle.
            wrong = {**actual, 'AppsAndFeaturesEntries': [{'ProductCode': 'Main', 'DisplayName': 'A bad value copied from a manifest'}]}
            conflicts = compare_literals(evidence, [wrong])['candidate_conflicts']
            assert any(item['field'] == 'DisplayName' for item in conflicts), (compressor, conflicts)
        print(f'{compressor}: ARP matches source writes')
    # A section editor can leave an extra sector before the NSIS header.
    # NSIS searches file-aligned sectors, so this remains a valid installer;
    # update its trailing CRC after inserting the sector.
    data = path.read_bytes()
    first = data.find(b'\xef\xbe\xad\xdeNullsoftInst') - 4
    assert first >= 0 and first % 512 == 0
    data = data[:first] + bytes(512) + data[first:]
    data = data[:-4] + zlib.crc32(data[512:-4]).to_bytes(4, 'little')
    path.write_bytes(data)
    result = subprocess.run([str(args.komac.resolve()), 'analyze', str(path)],
                            capture_output=True, text=True, check=True)
    actual = yaml.load(result.stdout, Loader=yaml.CBaseLoader)
    actual = actual.get('Installer', actual)
    assert {entry['ProductCode']: entry for entry in actual.get('AppsAndFeaturesEntries', [])} == expected
    evidence = compare_literals(inspect_literals(path), [actual])
    assert evidence['status'] == 'inspected' and evidence.get('corroborated_fields') and not evidence.get('candidate_conflicts'), evidence
    print('Padded NSIS header: ARP matches source writes')
    for mode in ['ABORT_INIT', 'QUIT_INIT', 'ABORT_SECTION', 'QUIT_SECTION']:
        path = Path(temp) / 'termination.exe'
        subprocess.run([args.makensis, '-V2', f'-DOUTPUT={path}', f'-D{mode}',
                        str(source.with_name('termination.nsi'))], check=True, capture_output=True)
        result = subprocess.run([str(args.komac.resolve()), 'analyze', str(path)],
                                capture_output=True, text=True, check=True)
        actual = yaml.load(result.stdout, Loader=yaml.CBaseLoader)
        actual = actual.get('Installer', actual)
        expected_termination = [{'DisplayName': 'Failure callback', 'ProductCode': 'Failure'}] if mode == 'ABORT_SECTION' else []
        assert actual.get('AppsAndFeaturesEntries', []) == expected_termination, (mode, actual)
        print(f'{mode}: no unreachable ARP writes')
