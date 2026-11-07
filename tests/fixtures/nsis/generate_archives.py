"""Generate tiny copy-method 7z fixtures with the standard signature/header CRCs."""
from pathlib import Path
import struct
import zlib


def integer(value):
    for count in range(8):
        if value < 1 << (7 * (count + 1)):
            prefix = ((1 << count) - 1) << (8 - count)
            return bytes([prefix | (value >> (8 * count))]) + value.to_bytes(8, 'little')[:count]
    return b'\xff' + struct.pack('<Q', value)


def crc(value):
    return struct.pack('<I', zlib.crc32(value))


def archive(files):
    data = b''.join(body for _, body in files)
    names = b'\0' + ''.join(name + '\0' for name, _ in files).encode('utf-16le')
    pack = b'\x06\x00\x01\x09' + integer(len(data)) + b'\x0a\x01' + crc(data) + b'\x00'
    unpack = b'\x07\x0b\x01\x00\x01\x01\x00\x0c' + integer(len(data)) + b'\x0a\x01' + crc(data) + b'\x00'
    streams = b'\x08'
    if len(files) > 1:
        streams += b'\x0d' + integer(len(files)) + b'\x09'
        streams += b''.join(integer(len(body)) for _, body in files[:-1])
        streams += b'\x0a\x01' + b''.join(crc(body) for _, body in files)
    header = b'\x01\x04' + pack + unpack + streams + b'\x00\x00'
    header += b'\x05' + integer(len(files)) + b'\x11' + integer(len(names)) + names + b'\x00\x00'
    start = struct.pack('<QQ', len(data), len(header)) + crc(header)
    return b'7z\xbc\xaf\x27\x1c\x00\x04' + crc(start) + start + data + header


if __name__ == '__main__':
    root = Path(__file__).parent
    setup = ('Setup.ExE', b'compiled setup fixture')
    root.joinpath('setup.7z').write_bytes(archive([setup]))
    pe = bytearray(134)
    pe[:2] = b'MZ'
    pe[60:64] = struct.pack('<I', 128)
    pe[128:132] = b'PE\0\0'
    pe[132:134] = struct.pack('<H', 0xaa64)
    root.joinpath('setup-arm64.7z').write_bytes(archive([setup, ('CORE/FireFox.ExE', pe)]))
