#!/usr/bin/env python3
"""Compile real System plugin calls and check their ARP writes without execution."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--makensis', default='makensis')
parser.add_argument('--komac', type=Path, default=Path('target/release/komac'))
args = parser.parse_args()
source = Path(__file__).resolve().parents[1] / 'tests/fixtures/nsis/system.nsi'
with tempfile.TemporaryDirectory(prefix='nsis-system-') as temp:
    for target in ['x86-unicode', 'x86-ansi', 'amd64-unicode']:
        path = Path(temp) / f'{target}.exe'
        switches = [f'-DTARGET={target}']
        if target.startswith('x86'):
            switches = [f'-DUNICODE={"true" if target.endswith("unicode") else "false"}']
        subprocess.run([args.makensis, '-V2', f'-DOUTPUT={path}', *switches,
                        str(source)], capture_output=True, text=True, check=True)
        environment = {**os.environ, 'RUST_LOG': 'warn',
                       'KOMAC_NSIS_WINDOWS_VERSION': '10.0.26300.9818',
                       'KOMAC_NSIS_NATIVE_ARCH': 'x64'}
        result = subprocess.run([str(args.komac.resolve()), 'analyze', str(path)],
                                capture_output=True, text=True, env=environment, check=True)
        actual = yaml.load(result.stdout, Loader=yaml.CBaseLoader)
        actual = actual.get('Installer', actual)
        assert actual.get('AppsAndFeaturesEntries') == [{
            'DisplayName': 'System fixture', 'DisplayVersion': '1.2.3',
            'Publisher': 'From System', 'ProductCode': 'SystemRegression',
        }], (target, actual, result.stderr)
        assert actual['InstallationMetadata']['DefaultInstallLocation'] == r'%LocalAppData%\Programs\System regression', (target, actual)
        assert 'Unmodeled System' not in result.stderr, (target, result.stderr)
        print(f'{target}: System calls reach the expected ARP writes')
