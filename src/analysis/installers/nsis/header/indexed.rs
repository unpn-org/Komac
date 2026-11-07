//! Indexed payloads used by Garena's NSIS 2.46 Unicode fork.
//!
//! Entries are 32 bytes and file records are 12 bytes. Multipart records start with pairs of
//! packed offsets and output offsets, stored as `u64` values.

use std::io::{self, Read, Seek, SeekFrom};

#[derive(Clone, Copy, Debug)]
pub struct FileRecord {
    pub offset: u64,
    pub parts: u32,
}

pub fn probe<R: Read + Seek>(reader: &mut R, header_size: u32) -> io::Result<bool> {
    let start = reader.stream_position()?;
    let mut bytes = [0; 12];
    let result = reader.read_exact(&mut bytes);
    reader.seek(SeekFrom::Start(start))?;
    result?;
    let size = u64::from_le_bytes(bytes[4..].try_into().unwrap());
    Ok(size == u64::from(header_size) || (size >> 32 == 0x8000_0000 && size as u32 != 0))
}

pub fn file_records(data: &[u8], offset: u32, count: u32) -> io::Result<Vec<FileRecord>> {
    let bytes = data
        .get(offset as usize..)
        .ok_or(io::ErrorKind::InvalidData)?;
    if !bytes.len().is_multiple_of(12) || (count != 0 && count as usize != bytes.len() / 12) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    bytes
        .chunks_exact(12)
        .map(|record| {
            let offset = u64::from_le_bytes(record[..8].try_into().unwrap());
            let parts = u32::from_le_bytes(record[8..].try_into().unwrap());
            if !(1..=65536).contains(&parts) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(FileRecord { offset, parts })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::analysis::installers::nsis::header::Header;

    #[test]
    fn recognizes_the_32_byte_first_header_and_bounds_the_index() {
        let mut data = vec![0; 4];
        data.extend((0x8000_0000_0000_1234u64).to_le_bytes());
        let mut reader = Cursor::new(data);
        assert!(probe(&mut reader, 94404).unwrap());
        assert_eq!(reader.position(), 0);
        assert!(file_records(&[0; 11], 0, 0).is_err());
        assert!(file_records(&[0; 12], 0, 0).is_err());
    }

    #[test]
    fn reads_the_ninth_block_without_shifting_callbacks() {
        let mut data = vec![0u8; 368];
        for (index, (offset, count)) in [
            (308u32, 0u32),
            (308, 0),
            (308, 1),
            (340, 0),
            (342, 1),
            (356, 0),
            (0, 0),
            (0, 0),
            (356, 0),
        ]
        .into_iter()
        .enumerate()
        {
            data[4 + index * 8..8 + index * 8].copy_from_slice(&offset.to_le_bytes());
            data[8 + index * 8..12 + index * 8].copy_from_slice(&count.to_le_bytes());
        }
        data[116..120].copy_from_slice(&(-1i32).to_le_bytes());
        data[308..312].copy_from_slice(&1u32.to_le_bytes()); // Return
        data[364..368].copy_from_slice(&1u32.to_le_bytes()); // one file part
        let header = Header::read_indexed(&data).unwrap();
        assert_eq!(header.code_on_init(), -1);
        assert_eq!(header.install_registry_root_key(), 0);
        assert_eq!(header.indexed_files().unwrap().len(), 1);
        assert_eq!(header.indexed_files().unwrap()[0].parts, 1);
        data[24..28].copy_from_slice(&2u32.to_le_bytes());
        assert!(Header::read_indexed(&data).is_err());
    }
}
