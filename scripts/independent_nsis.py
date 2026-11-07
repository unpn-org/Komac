"""Independent, bounded corroboration of literal NSIS ARP writes.

Uses Python's LZMA/zlib decoders and reads instruction/string tables directly.
It does not import Komac code or use manifest values as expected output. Literal
agreement is evidence about encoded values, not proof of execution, ordering,
plugin effects, registry deletions, or an observed Windows registry capture.
"""
import lzma
from pathlib import Path
import struct
import zlib

MAX_HEADER = 64 * 1024 * 1024
MAX_DICTIONARY = 64 * 1024 * 1024
ARP_PARENT = r'Software\Microsoft\Windows\CurrentVersion\Uninstall'.casefold()
FIELDS = {'displayname': 'DisplayName', 'publisher': 'Publisher', 'displayversion': 'DisplayVersion'}


def _overlay(stream):
    stream.seek(0)
    dos = stream.read(64)
    if dos[:2] != b'MZ' or len(dos) < 64:
        raise ValueError('not a PE executable')
    stream.seek(struct.unpack_from('<I', dos, 60)[0])
    pe = stream.read(24)
    if pe[:4] != b'PE\0\0' or len(pe) != 24:
        raise ValueError('invalid PE signature')
    machine, count = struct.unpack_from('<HH', pe, 4)
    if not 1 <= count <= 96:
        raise ValueError('unsupported PE section count')
    stream.seek(struct.unpack_from('<H', pe, 20)[0], 1)
    sections = stream.read(count * 40)
    if len(sections) != count * 40:
        raise ValueError('truncated PE section table')
    end = max(sum(struct.unpack_from('<II', sections, i + 16)) for i in range(0, len(sections), 40))
    return end, machine in (0x8664, 0xaa64)


def _decode(stream, start, stored, target, signature):
    candidates = []
    for skip in (0, 1):
        data = signature[skip:]
        if len(data) >= 6 and data[0] == 0x5d and data[5] == 0 and (not skip or signature[0] <= 1):
            dictionary = int.from_bytes(data[1:5], 'little')
            if dictionary <= MAX_DICTIONARY:
                filters = ([{'id': lzma.FILTER_X86}] if skip and signature[0] else [])
                filters.append({'id': lzma.FILTER_LZMA1, 'dict_size': max(4096, dictionary), 'lc': 3, 'lp': 0, 'pb': 2})
                candidates.append(('lzma1', skip + 5, filters))
    if len(signature) > 1 and signature[0] < 40 and (signature[1] == 1 or signature[1] >= 0xe0):
        dictionary = (2 | (signature[0] & 1)) << (signature[0] // 2 + 11)
        if dictionary <= MAX_DICTIONARY:
            candidates.append(('lzma2', 1, [{'id': lzma.FILTER_LZMA2, 'dict_size': dictionary}]))
    candidates.append(('deflate', 0, None))
    for codec, skip, filters in candidates:
        try:
            stream.seek(start + skip)
            decoder = (lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters) if filters
                       else zlib.decompressobj(-15))
            fragments, produced, consumed = [], 0, skip
            while produced < target:
                available = min(65536, MAX_HEADER - consumed)
                if stored is not None:
                    available = min(available, stored - consumed)
                if available <= 0:
                    raise ValueError('independent decoder input limit reached')
                data = stream.read(available)
                if not data:
                    raise ValueError('truncated compressed header')
                consumed += len(data)
                decoded = decoder.decompress(data, max_length=target - produced)
                fragments.append(decoded)
                produced += len(decoded)
                if decoder.eof and produced < target:
                    raise ValueError('compressed header ended early')
            return b''.join(fragments), codec
        except (lzma.LZMAError, zlib.error, ValueError, EOFError):
            continue
    raise ValueError('header codec unsupported by independent reader or input is malformed')


def inspect_literals(path):
    try:
        with Path(path).open('rb') as stream:
            overlay, wide = _overlay(stream)
            stream.seek(overlay)
            probe = stream.read(1024 * 1024 + 28)
            positions = [0, *range((-overlay % 512) or 512, 1024 * 1024 + 1, 512)]
            offset = next((pos for pos in positions
                           if len(probe[pos:pos+28]) == 28 and
                           probe[pos+4:pos+20] == b'\xef\xbe\xad\xdeNullsoftInst'), None)
            if offset is None:
                raise ValueError('NSIS header unavailable; wrapper or unsupported executable')
            overlay += offset
            first = probe[offset:offset+28]
            stream.seek(overlay + 28)
            flags, expected = struct.unpack_from('<I', first)[0], struct.unpack_from('<I', first, 20)[0]
            if not 4 <= expected <= MAX_HEADER:
                raise ValueError('header exceeds independent reader limits')
            bi = bool(flags & (16 | 32 | 64))
            extra = stream.read(24)
            indexed = bi and (int.from_bytes(extra[4:12], 'little') == expected or
                             int.from_bytes(extra[8:12], 'little') == 0x80000000 and
                             int.from_bytes(extra[4:8], 'little') != 0)
            start = overlay + 28 + (4 if indexed else 8 if bi else 0)
            stream.seek(start)
            signature = stream.read(16)
            if len(signature) < 8:
                raise ValueError('truncated NSIS header record')
            width = 8 if bi else 4
            if bi and (signature[3] == 0x80 or int.from_bytes(signature[:4], 'little') == expected):
                width = 4
            size = int.from_bytes(signature[:width], 'little')
            if size == expected:
                stream.seek(start + width)
                header, codec = stream.read(expected), 'none'
            else:
                nonsolid = signature[width - 1] == 0x80
                # A solid LZMA dictionary byte can also be 0x80. Validate the
                # decompressed size prefix instead of relying on that byte.
                for frame in ([True, False] if nonsolid else [False]):
                    try:
                        stored = size & ((1 << (width * 8 - 1)) - 1) if frame else None
                        payload = start + width if frame else start
                        stream.seek(payload)
                        header, codec = _decode(stream, payload, stored, expected if frame else expected + width,
                                                stream.read(16))
                        if not frame:
                            if int.from_bytes(header[:width], 'little') != expected:
                                raise ValueError('solid header size mismatch')
                            header = header[width:]
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError('independent header framing or codec unsupported')
            if len(header) != expected:
                raise ValueError('decoded header size mismatch')
            block_width = 12 if wide and not indexed else 8
            blocks = [(int.from_bytes(header[4+i*block_width:4+i*block_width+block_width-4], 'little'),
                       int.from_bytes(header[4+i*block_width+block_width-4:4+(i+1)*block_width], 'little'))
                      for i in range(5)]
            entry_start, count = blocks[2]
            string_start, string_end = blocks[3][0], blocks[4][0]
            if not 0 < count <= MAX_HEADER // 28 or not entry_start <= string_start <= string_end <= len(header):
                raise ValueError('invalid entry or string table range')
            stride, remainder = divmod(string_start - entry_start, count)
            if remainder or stride not in (28, 32):
                raise ValueError(f'independent reader does not support instruction width {stride}')
            strings = header[string_start:string_end]
            unicode = strings.startswith(b'\0\0')
            cache = {}
            def literal(offset):
                if offset in cache:
                    return cache[offset]
                if offset < 0:
                    return None
                pos, step = offset * (2 if unicode else 1), 2 if unicode else 1
                end = pos
                while end < min(len(strings), pos + 16384) and strings[end:end+step] != b'\0' * step:
                    end += step
                if end >= len(strings) or end >= pos + 16384:
                    return None
                raw = strings[pos:end]
                units = struct.unpack('<' + 'H' * (len(raw)//2), raw) if unicode else raw
                dynamic = any(unit in (1,2,3,4,0xe000,0xe001,0xe002,0xe003) for unit in units)
                if not unicode:
                    dynamic |= any(unit >= 252 for unit in units)
                value = None if dynamic else raw.decode('utf-16le' if unicode else 'cp1252', errors='replace')
                if len(cache) < 4096:
                    cache[offset] = value
                return value
            entries, dynamic_keys = {}, False
            for index in range(count):
                words = struct.unpack_from('<7I', header, entry_start + index * stride)
                if words[0] != 51 or words[5] not in (1, 2):
                    continue
                root = words[1]
                if root not in (0, 0x80000001, 0x80000002):
                    continue
                key, name = literal(words[2]), literal(words[3])
                if key is None:
                    dynamic_keys = True
                    continue
                parent, separator, code = key.rstrip('\\').rpartition('\\')
                if not separator or parent.casefold() != ARP_PARENT or not code:
                    continue
                if name is None:
                    dynamic_keys = True
                    continue
                if name.casefold() not in FIELDS:
                    continue
                if len(entries) >= 512 and code.casefold() not in entries:
                    raise ValueError('independent literal-entry limit reached')
                entry = entries.setdefault(code.casefold(), {'ProductCode': code, 'values': {}, 'dynamic_fields': [], 'scopes': [], 'dynamic_scope': False})
                entry['dynamic_scope'] |= root == 0
                scope = {0x80000001: 'user', 0x80000002: 'machine'}.get(root)
                if scope and scope not in entry['scopes']:
                    entry['scopes'].append(scope)
                field, value = FIELDS[name.casefold()], literal(words[4])
                if value is None:
                    if field not in entry['dynamic_fields']:
                        entry['dynamic_fields'].append(field)
                else:
                    values = entry['values'].setdefault(field, [])
                    if value not in values:
                        if len(values) >= 32:
                            raise ValueError('independent literal-value limit reached')
                        values.append(value)
            return {'status': 'inspected', 'codec': codec, 'instruction_width': stride,
                    'entries': list(entries.values()), 'dynamic_keys': dynamic_keys,
                    'runtime_verified': False}
    except (OSError, ValueError, struct.error, lzma.LZMAError, zlib.error, OverflowError, MemoryError) as error:
        return {'status': 'unsupported', 'reason': str(error), 'runtime_verified': False}


def compare_literals(evidence, installers):
    if evidence['status'] != 'inspected':
        return evidence
    candidates = {entry['ProductCode'].casefold(): entry for entry in evidence['entries']}
    matches, conflicts = [], []
    for installer in installers:
        for actual in installer.get('AppsAndFeaturesEntries', []):
            code = actual.get('ProductCode', installer.get('ProductCode', ''))
            candidate = candidates.get(code.casefold())
            if not candidate:
                continue
            matches.append({'ProductCode': code, 'field': 'ProductCode', 'actual': code,
                            'encoded_values': [candidate['ProductCode']]})
            if installer.get('Scope') and candidate['scopes'] and len(installer.get('AppsAndFeaturesEntries', [])) == 1:
                item = {'ProductCode': code, 'field': 'Scope', 'actual': installer['Scope'],
                        'encoded_values': candidate['scopes']}
                if installer['Scope'] in candidate['scopes']:
                    matches.append(item)
                elif not candidate['dynamic_scope'] and not evidence['dynamic_keys']:
                    conflicts.append(item)
            for field, values in candidate['values'].items():
                if field not in actual:
                    continue
                item = {'ProductCode': code, 'field': field, 'actual': actual[field], 'encoded_values': values}
                if actual[field] in values:
                    matches.append(item)
                elif field not in candidate['dynamic_fields'] and not evidence['dynamic_keys']:
                    conflicts.append(item)
    return {**evidence, 'corroborated_fields': matches, 'candidate_conflicts': conflicts}


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installer', type=Path)
    parser.add_argument('--metadata', type=Path, help='Komac analyze YAML to compare against encoded literals')
    args = parser.parse_args()
    evidence = inspect_literals(args.installer)
    if args.metadata:
        import yaml
        actual = yaml.load(args.metadata.read_text(), Loader=yaml.CBaseLoader)
        installers = actual.get('Installers', [actual.get('Installer', actual)]) if isinstance(actual, dict) else actual
        evidence = compare_literals(evidence, installers)
    print(json.dumps(evidence, indent=2))
