use std::io::{self, Cursor, Read, Seek, SeekFrom};

use zerocopy::LE;

use super::header::{Compression, Decoder, nsis_bzip2, nsis_deflate};
use crate::{analysis::installers::utils::LzmaStreamHeader, read::ReadBytesExt};

/// Reads embedded files using the offsets recorded by ExtractFile.
pub struct FileData<R> {
    reader: R,
    data_offset: u64,
    header_size: u32,
    is_solid: bool,
    non_solid_start_offset: u32,
    compression: Compression,
}

impl<R: Read + Seek> FileData<R> {
    pub fn new(
        reader: R,
        data_offset: u64,
        header_size: u32,
        is_solid: bool,
        non_solid_start_offset: u32,
        compression: Compression,
    ) -> Self {
        Self {
            reader,
            data_offset,
            header_size,
            is_solid,
            non_solid_start_offset,
            compression,
        }
    }

    pub fn read(&mut self, position: u64) -> io::Result<Cursor<Vec<u8>>> {
        let mut compression = self.compression;
        let compressed_size = if self.is_solid {
            self.reader.seek(SeekFrom::Start(self.data_offset))?;
            None
        } else {
            // position includes the four-byte size prefix; seek back to read it.
            self.reader.seek(SeekFrom::Start(
                self.data_offset + u64::from(self.non_solid_start_offset) + position,
            ))?;
            let size = self.reader.read_u32::<LE>()?;
            if size & 0x8000_0000 == 0 {
                compression = Compression::None;
            }
            Some((size & !0x8000_0000) as usize)
        };
        let mut decoder = match compression {
            Compression::None => Decoder::None(&mut self.reader),
            Compression::Lzma(filter_flag) => {
                if filter_flag {
                    self.reader.seek_relative(1)?;
                }
                let header = self.reader.read_t::<LzmaStreamHeader>()?;
                Decoder::new_lzma1(&mut self.reader, header)?
            }
            Compression::Zlib => Decoder::Zlib(nsis_deflate::Decoder::new(&mut self.reader)),
            Compression::BZip2 => Decoder::NsisBZip2(nsis_bzip2::Decoder::new(
                &mut self.reader,
                compressed_size,
                usize::MAX,
            )?),
        };
        let size = if self.is_solid {
            // Skip the header and preceding file records to reach this file's size prefix.
            let skip = u64::from(self.header_size) + position;
            if io::copy(&mut decoder.by_ref().take(skip), &mut io::sink())? != skip {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Some(u64::from(decoder.read_u32::<LE>()?))
        } else if compression == Compression::None {
            compressed_size.map(|size| size as u64)
        } else {
            None
        };
        let mut bytes = Vec::new();
        decoder
            .take(size.unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        if size.is_some_and(|size| size != bytes.len() as u64) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Cursor::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use flate2::{Compression as Level, write::DeflateEncoder};
    use rstest::rstest;

    use super::*;

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Level::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    // Raw LZMA streams with the five-byte NSIS properties/dictionary header.
    fn lzma(bytes: &[u8]) -> Vec<u8> {
        if bytes == b"first" {
            vec![
                93, 0, 0, 16, 0, 0, 51, 26, 74, 172, 12, 121, 176, 51, 254, 255, 252, 102, 64, 0,
            ]
        } else {
            vec![
                93, 0, 0, 16, 0, 0, 3, 0, 54, 206, 22, 253, 41, 152, 243, 58, 67, 119, 50, 116,
                249, 171, 248, 206, 77, 81, 38, 55, 11, 188, 179, 132, 120, 214, 215, 222, 255,
                210, 109, 0, 0,
            ]
        }
    }

    #[rstest]
    #[case(Compression::None)]
    #[case(Compression::Zlib)]
    #[case(Compression::Lzma(false))]
    fn reads_solid_files_after_header_and_other_files(#[case] compression: Compression) {
        let mut stream = 6_u32.to_le_bytes().to_vec();
        stream.extend(b"header");
        stream.extend(5_u32.to_le_bytes());
        stream.extend(b"first");
        stream.extend(6_u32.to_le_bytes());
        stream.extend(b"second");
        let mut bytes = b"stub".to_vec();
        bytes.extend(match compression {
            Compression::Zlib => deflate(&stream),
            Compression::Lzma(_) => lzma(&stream),
            _ => stream,
        });
        let mut reader = FileData::new(Cursor::new(bytes), 4, 6, true, 0, compression);
        assert_eq!(reader.read(13).unwrap().into_inner(), b"second");
        assert_eq!(reader.read(4).unwrap().into_inner(), b"first");
    }

    #[rstest]
    #[case(Compression::Zlib)]
    #[case(Compression::Lzma(true))]
    fn reads_non_solid_compressed_and_uncompressed_records(#[case] compression: Compression) {
        let mut bytes = b"stub".to_vec();
        bytes.extend(6_u32.to_le_bytes());
        bytes.extend(b"header");
        let compressed = match compression {
            Compression::Lzma(_) => {
                let mut bytes = vec![0]; // NSIS filter flag
                bytes.extend(lzma(b"first"));
                bytes
            }
            _ => deflate(b"first"),
        };
        bytes.extend((compressed.len() as u32 | 0x8000_0000).to_le_bytes());
        bytes.extend(&compressed);
        bytes.extend(6_u32.to_le_bytes());
        bytes.extend(b"second");
        let mut reader = FileData::new(Cursor::new(bytes), 4, 6, false, 6, compression);
        assert_eq!(
            reader
                .read(8 + compressed.len() as u64)
                .unwrap()
                .into_inner(),
            b"second"
        );
        assert_eq!(reader.read(4).unwrap().into_inner(), b"first");
    }

    #[test]
    fn rejects_truncated_file_records() {
        let mut bytes = 0_u32.to_le_bytes().to_vec();
        bytes.extend(10_u32.to_le_bytes());
        bytes.extend(b"short");
        let mut reader = FileData::new(Cursor::new(bytes), 0, 0, true, 0, Compression::None);
        assert_eq!(
            reader.read(4).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
