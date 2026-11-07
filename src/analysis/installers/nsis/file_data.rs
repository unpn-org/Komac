use std::io::{self, Cursor, Read, Seek, SeekFrom};

use tracing::warn;
use zerocopy::LE;

use super::header::{Compression, Decoder, nsis_bzip2, nsis_deflate, threaded_lzma};
use crate::{analysis::installers::utils::LzmaStreamHeader, read::ReadBytesExt};

/// A reader for embedded NSIS files.
///
/// File offsets are taken from `ExtractFile` instructions.
pub struct FileData<R> {
    reader: R,
    data_offset: u64,
    header_size: u32,
    is_solid: bool,
    non_solid_start_offset: u64,
    compression: Compression,
    record_width: usize,
    indexed_files: Option<Vec<super::header::indexed::FileRecord>>,
}

impl<R: Read + Seek> FileData<R> {
    pub fn new(
        reader: R,
        data_offset: u64,
        header_size: u32,
        is_solid: bool,
        non_solid_start_offset: u64,
        compression: Compression,
    ) -> Self {
        Self {
            reader,
            data_offset,
            header_size,
            is_solid,
            non_solid_start_offset,
            compression,
            record_width: 4,
            indexed_files: None,
        }
    }

    pub fn with_record_width(mut self, width: usize) -> Self {
        self.record_width = width;
        self
    }

    pub fn with_indexed_files(
        mut self,
        files: Option<Vec<super::header::indexed::FileRecord>>,
    ) -> Self {
        self.indexed_files = files;
        self
    }

    pub fn read(&mut self, position: u64) -> io::Result<Cursor<Vec<u8>>> {
        if let Some(files) = &self.indexed_files {
            let id = position
                .checked_sub(4)
                .and_then(|id| usize::try_from(id).ok())
                .ok_or(io::ErrorKind::InvalidData)?;
            let file = *files.get(id).ok_or(io::ErrorKind::InvalidData)?;
            return self.read_indexed(file);
        }
        self.read_regular(position)
    }

    fn read_indexed(
        &mut self,
        file: super::header::indexed::FileRecord,
    ) -> io::Result<Cursor<Vec<u8>>> {
        if self.is_solid || self.record_width != 8 || !(1..=65536).contains(&file.parts) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let metadata_size = u64::from(file.parts - 1) * 16;
        let start = self
            .data_offset
            .checked_add(self.non_solid_start_offset)
            .and_then(|start| start.checked_add(8))
            .and_then(|start| start.checked_add(file.offset))
            .ok_or(io::ErrorKind::InvalidData)?;
        self.reader.seek(SeekFrom::Start(start))?;
        let mut parts = vec![(0u64, 0u64)];
        for _ in 1..file.parts {
            let packed = self.reader.read_t::<zerocopy::U64<LE>>()?.get();
            let output = self.reader.read_t::<zerocopy::U64<LE>>()?.get();
            let &(previous, previous_output) = parts.last().unwrap();
            if packed <= previous || output < previous_output || output > 512 * 1024 * 1024 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            parts.push((packed, output));
        }
        let mut output = Vec::new();
        for (offset, output_offset) in parts {
            if output_offset != output.len() as u64 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let position = file
                .offset
                .checked_add(metadata_size)
                .and_then(|position| position.checked_add(offset))
                .and_then(|position| position.checked_add(4))
                .ok_or(io::ErrorKind::InvalidData)?;
            let part = self.read_regular(position)?.into_inner();
            if output.len() as u64 + part.len() as u64 > 512 * 1024 * 1024 {
                return Err(io::Error::other("Indexed NSIS file exceeds analysis limit"));
            }
            output.extend(part);
        }
        Ok(Cursor::new(output))
    }

    fn read_regular(&mut self, position: u64) -> io::Result<Cursor<Vec<u8>>> {
        // FsEntry::position includes the standard four-byte prefix. BI records
        // have eight-byte prefixes, including the one preceding the header.
        let position = position
            .checked_sub(4)
            .and_then(|position| position.checked_add(self.record_width as u64))
            .ok_or(io::ErrorKind::InvalidData)?;
        let mut compression = self.compression;
        let compressed_size = if self.is_solid {
            self.reader.seek(SeekFrom::Start(self.data_offset))?;
            None
        } else {
            // position includes the four-byte size prefix; seek back to read it.
            let start = self
                .data_offset
                .checked_add(self.non_solid_start_offset)
                .and_then(|start| start.checked_add(position))
                .ok_or(io::ErrorKind::InvalidData)?;
            self.reader.seek(SeekFrom::Start(start))?;
            let size = if self.record_width == 8 {
                self.reader.read_t::<zerocopy::U64<LE>>()?.get()
            } else {
                u64::from(self.reader.read_u32::<LE>()?)
            };
            let mask = 1u64 << (self.record_width * 8 - 1);
            if size & mask == 0 {
                compression = Compression::None;
            }
            Some(usize::try_from(size & !mask).map_err(|_| io::ErrorKind::InvalidData)?)
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
            Compression::ThreadedLzma => {
                Decoder::ThreadedLzma(threaded_lzma::Decoder::new(&mut self.reader))
            }
            Compression::Lzma2 => Decoder::new_lzma2(&mut self.reader)?,
            Compression::Zlib => Decoder::Zlib(nsis_deflate::Decoder::new(&mut self.reader)),
            Compression::BZip2 => Decoder::NsisBZip2(nsis_bzip2::Decoder::new(
                &mut self.reader,
                compressed_size,
                usize::MAX,
            )?),
        };
        let size = if self.is_solid {
            // Skip the header and preceding file records to reach this file's size prefix.
            let skip = u64::from(self.header_size)
                .checked_add(position)
                .ok_or(io::ErrorKind::InvalidData)?;
            if io::copy(&mut decoder.by_ref().take(skip), &mut io::sink())? != skip {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Some(if self.record_width == 8 {
                decoder.read_t::<zerocopy::U64<LE>>()?.get()
            } else {
                u64::from(decoder.read_u32::<LE>()?)
            })
        } else if compression == Compression::None {
            compressed_size.map(|size| size as u64)
        } else {
            None
        };
        let mut bytes = Vec::new();
        const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
        if size.is_some_and(|size| size > MAX_FILE_SIZE) {
            warn!("Embedded NSIS file exceeds the static analysis size limit");
            return Err(io::ErrorKind::InvalidData.into());
        }
        decoder
            .take(size.unwrap_or(MAX_FILE_SIZE + 1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_SIZE {
            warn!("Embedded NSIS file exceeds the static analysis size limit");
            return Err(io::ErrorKind::InvalidData.into());
        }
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
    use crate::analysis::installers::nsis::{file_system::FsEntry, header::indexed::FileRecord};

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
    #[case(Compression::Lzma2)]
    fn reads_non_solid_compressed_and_uncompressed_records(#[case] compression: Compression) {
        let mut bytes = b"stub".to_vec();
        bytes.extend(6_u32.to_le_bytes());
        bytes.extend(b"header");
        let compressed = match compression {
            Compression::Lzma2 => b"\x10\x01\0\x04first\0".to_vec(),
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

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn reads_bi_eight_byte_record_lengths(#[case] solid: bool) {
        let mut data = 6u64.to_le_bytes().to_vec();
        data.extend(b"header");
        data.extend(5u64.to_le_bytes());
        data.extend(b"first");
        data.extend(6u64.to_le_bytes());
        data.extend(b"second");
        let mut reader = FileData::new(Cursor::new(data), 0, 6, solid, 6, Compression::None)
            .with_record_width(8);
        let first = FsEntry::new_file("first.exe", None, 0u64);
        let second = FsEntry::new_file("second.exe", None, 13u64);
        assert_eq!(
            reader.read(first.position().unwrap()).unwrap().into_inner(),
            b"first"
        );
        assert_eq!(
            reader
                .read(second.position().unwrap())
                .unwrap()
                .into_inner(),
            b"second"
        );
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

    #[test]
    fn reads_indexed_multipart_files_in_output_order() {
        let mut data = 6u64.to_le_bytes().to_vec();
        data.extend(b"header");
        // One descriptor: second packed record is 13 bytes after the first;
        // its uncompressed output starts after the five bytes of "first".
        data.extend(13u64.to_le_bytes());
        data.extend(5u64.to_le_bytes());
        data.extend(5u64.to_le_bytes());
        data.extend(b"first");
        data.extend(6u64.to_le_bytes());
        data.extend(b"second");
        let mut reader = FileData::new(Cursor::new(data), 0, 6, false, 6, Compression::None)
            .with_record_width(8)
            .with_indexed_files(Some(vec![FileRecord {
                offset: 0,
                parts: 2,
            }]));
        assert_eq!(reader.read(4).unwrap().into_inner(), b"firstsecond");
        assert!(reader.read(5).is_err());
    }
}
