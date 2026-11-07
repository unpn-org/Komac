//! NSIS LZMA2 records.
//!
//! Each record contains a dictionary property byte followed by a raw LZMA2 stream.

use std::io::{self, Read, Seek, SeekFrom};

pub fn dictionary_size(property: u8) -> io::Result<u32> {
    match property {
        0..=39 => Ok((2 | u32::from(property & 1)) << (u32::from(property) / 2 + 11)),
        40 => Ok(u32::MAX),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

/// Returns `true` if the record has valid LZMA2 framing and the expected decompressed size.
///
/// The dictionary property byte alone does not distinguish LZMA2 from DEFLATE.
pub fn probe<R: Read + Seek>(reader: &mut R, stored: u64, expected: u64) -> io::Result<bool> {
    let start = reader.stream_position()?;
    let result = (|| -> io::Result<bool> {
        let Some(end) = start.checked_add(stored) else {
            return Ok(false);
        };
        let byte = |reader: &mut R| -> io::Result<u8> {
            let mut value = [0];
            reader.read_exact(&mut value)?;
            Ok(value[0])
        };
        dictionary_size(byte(reader)?)?;
        let mut produced = 0u64;
        for chunk in 0..65536 {
            if reader.stream_position()? >= end {
                return Ok(false);
            }
            let control = byte(reader)?;
            if control == 0 {
                return Ok(produced == expected && reader.stream_position()? == end);
            }
            if chunk == 0 && control != 1 && control < 0xe0 {
                return Ok(false);
            }
            if control != 1 && control != 2 && control < 0x80 {
                return Ok(false);
            }
            let mut lengths = [0; 2];
            reader.read_exact(&mut lengths)?;
            let low = u64::from(u16::from_be_bytes(lengths));
            let (unpacked, packed) = if control >= 0x80 {
                reader.read_exact(&mut lengths)?;
                if control >= 0xc0 {
                    let property = byte(reader)?;
                    if property >= 225 || property % 45 / 9 + property % 9 > 4 {
                        return Ok(false);
                    }
                }
                (
                    (u64::from(control & 31) << 16) + low + 1,
                    u64::from(u16::from_be_bytes(lengths)) + 1,
                )
            } else {
                (low + 1, low + 1)
            };
            produced += unpacked;
            if produced > expected {
                return Ok(false);
            }
            let Some(next) = reader.stream_position()?.checked_add(packed) else {
                return Ok(false);
            };
            if next >= end {
                return Ok(false);
            }
            reader.seek(SeekFrom::Start(next))?;
        }
        Ok(false)
    })();
    reader.seek(SeekFrom::Start(start))?;
    Ok(result.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;
    use crate::analysis::installers::nsis::{
        first_header::FirstHeader,
        header::{Compression, Decoder, Header},
    };

    #[test]
    fn validates_complete_framing_and_restores_position() {
        let data = b"\x10\x01\0\x04first\0";
        let mut reader = Cursor::new(data);
        assert!(probe(&mut reader, data.len() as u64, 5).unwrap());
        assert_eq!(reader.position(), 0);
        assert!(!probe(&mut reader, data.len() as u64, 6).unwrap());
        assert!(!probe(&mut reader, data.len() as u64 - 1, 5).unwrap());
        assert!(!probe(&mut reader, data.len() as u64 + 1, 5).unwrap());
        assert!(dictionary_size(41).is_err());
    }

    #[test]
    fn detects_and_decodes_non_solid_lzma2_header() {
        // Python's independent raw LZMA2 encoder, dictionary 1 MiB, input
        // b"header" repeated 1000 times. Includes the NSIS dictionary byte.
        let packed = [
            16, 224, 23, 111, 0, 39, 93, 0, 52, 25, 72, 72, 106, 117, 68, 127, 190, 175, 188, 47,
            47, 144, 178, 48, 233, 243, 72, 101, 70, 28, 254, 174, 86, 19, 234, 75, 85, 48, 26,
            112, 184, 166, 143, 102, 246, 29, 215, 0,
        ];
        let words = [
            4u32,
            0xdeadbeef,
            0x6c6c754e,
            0x74666f73,
            0x74736e49,
            6000,
            28 + 4 + packed.len() as u32,
        ];
        let first: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let first = FirstHeader::try_read_from_io(first.as_slice()).unwrap();
        let mut stream = (packed.len() as u32 | 0x8000_0000).to_le_bytes().to_vec();
        stream.extend(packed);
        let decoded = Header::decompress(Cursor::new(stream), &first).unwrap();
        assert_eq!(decoded.compression, Compression::Lzma2);
        assert!(!decoded.is_solid);
        assert_eq!(decoded.data, b"header".repeat(1000));
        let mut decoder = Decoder::new_lzma2(Cursor::new(packed)).unwrap();
        let mut data = Vec::new();
        decoder.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"header".repeat(1000));
        // A hostile 4-GiB dictionary must be rejected before allocation.
        assert!(Decoder::new_lzma2(Cursor::new([40])).is_err());
    }
}
