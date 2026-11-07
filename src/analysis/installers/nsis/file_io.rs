use std::{
    collections::HashMap,
    io::{self, Cursor},
};

use encoding_rs::UTF_16LE;
use indextree::NodeId;
use tracing::warn;

use super::variables::MAX_STRING_LENGTH;

const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

enum Content {
    Packed(u64),
    Bytes(Vec<u8>),
    Unknown,
}

struct Handle {
    file: NodeId,
    position: usize,
    readable: bool,
    writable: bool,
}

/// Bounded file contents and handles used by NSIS file instructions.
#[derive(Default)]
pub struct Files {
    contents: HashMap<NodeId, Content>,
    handles: HashMap<i32, Handle>,
    next_handle: i32,
}

impl Files {
    pub fn register(&mut self, file: NodeId, position: u64) {
        self.contents.insert(file, Content::Packed(position));
    }

    pub fn open(
        &mut self,
        file: NodeId,
        readable: bool,
        writable: bool,
        empty: bool,
    ) -> Option<i32> {
        if self.handles.len() >= 256 {
            return None;
        }
        self.next_handle = self.next_handle.checked_add(1)?;
        if empty {
            self.contents.insert(file, Content::Bytes(Vec::new()));
        }
        self.handles.insert(
            self.next_handle,
            Handle {
                file,
                position: 0,
                readable,
                writable,
            },
        );
        Some(self.next_handle)
    }

    pub fn close(&mut self, handle: i32) {
        self.handles.remove(&handle);
    }

    pub fn bytes(
        &mut self,
        file: NodeId,
        read: &mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> Option<Vec<u8>> {
        self.load(file, read)?;
        let Content::Bytes(bytes) = self.contents.get(&file)? else {
            return None;
        };
        Some(bytes.clone())
    }

    fn used_bytes(&self) -> usize {
        self.contents
            .values()
            .map(|value| match value {
                Content::Bytes(bytes) => bytes.len(),
                _ => 0,
            })
            .sum()
    }

    fn load(
        &mut self,
        file: NodeId,
        read: &mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> Option<()> {
        if let Some(Content::Packed(position)) = self.contents.get(&file) {
            let bytes = read(*position).ok().map(Cursor::into_inner);
            let bytes = bytes.filter(|bytes| {
                bytes.len() <= MAX_FILE_BYTES && self.used_bytes() + bytes.len() <= MAX_TOTAL_BYTES
            });
            self.contents
                .insert(file, bytes.map_or(Content::Unknown, Content::Bytes));
        }
        if matches!(self.contents.get(&file), Some(Content::Bytes(_))) {
            Some(())
        } else {
            warn!(
                "File contents are unavailable during static analysis; dependent metadata requires independent validation"
            );
            None
        }
    }

    pub fn read(
        &mut self,
        handle: i32,
        wide: bool,
        character: bool,
        maximum: usize,
        read: &mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> Option<String> {
        let entry = self.handles.get(&handle)?;
        if !entry.readable {
            return None;
        }
        let (file, mut position) = (entry.file, entry.position);
        self.load(file, read)?;
        let Content::Bytes(bytes) = self.contents.get(&file)? else {
            return None;
        };
        if wide && !character && position == 0 && bytes.starts_with(b"\xff\xfe") {
            position = 2;
        }
        let width = if wide { 2 } else { 1 };
        let unit = |position: usize| -> Option<u16> {
            let value = bytes.get(position..position.checked_add(width)?)?;
            Some(if wide {
                u16::from_le_bytes(value.try_into().ok()?)
            } else {
                u16::from(value[0])
            })
        };
        let start = position;
        let mut end = start;
        for _ in 0..maximum.min(MAX_STRING_LENGTH - 1) {
            let Some(value) = unit(position) else {
                break;
            };
            position += width;
            if character {
                break;
            }
            if value == 0 {
                break;
            }
            end = position;
            if matches!(value, 10 | 13) {
                if end - start < maximum.saturating_mul(width)
                    && unit(position).is_some_and(|next| matches!(next, 10 | 13) && next != value)
                {
                    position += width;
                    end = position;
                }
                break;
            }
        }
        if position == start {
            return None;
        }
        let output = if character {
            unit(start)?.to_string()
        } else {
            if wide {
                UTF_16LE
                    .decode_without_bom_handling(&bytes[start..end])
                    .0
                    .into_owned()
            } else {
                super::codepage::decode(&bytes[start..end]).into_owned()
            }
        };
        self.handles.get_mut(&handle)?.position = position;
        Some(output)
    }

    pub fn write(
        &mut self,
        handle: i32,
        value: &[u8],
        bom: bool,
        read: &mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> Option<NodeId> {
        let entry = self.handles.get(&handle)?;
        if !entry.writable {
            return None;
        }
        let (file, mut position) = (entry.file, entry.position);
        self.load(file, read)?;
        let used = self.used_bytes();
        let Content::Bytes(bytes) = self.contents.get_mut(&file)? else {
            return None;
        };
        let prefix = bom && position == 0 && bytes.is_empty();
        if prefix {
            position = 2;
        }
        let end = position.checked_add(value.len())?;
        let length = end.max(bytes.len());
        if length > MAX_FILE_BYTES || used - bytes.len() + length > MAX_TOTAL_BYTES {
            return None;
        }
        bytes.resize(length, 0);
        if prefix {
            bytes[..2].copy_from_slice(b"\xff\xfe");
        }
        bytes[position..end].copy_from_slice(value);
        self.handles.get_mut(&handle)?.position = end;
        Some(file)
    }

    pub fn seek(
        &mut self,
        handle: i32,
        offset: i32,
        origin: u32,
        read: &mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> Option<usize> {
        let entry = self.handles.get(&handle)?;
        let (file, position) = (entry.file, entry.position);
        let base = match origin {
            0 => 0,
            1 => position,
            2 => {
                self.load(file, read)?;
                let Content::Bytes(bytes) = self.contents.get(&file)? else {
                    return None;
                };
                bytes.len()
            }
            _ => return None,
        };
        let position = usize::try_from((base as i64).checked_add(i64::from(offset))?).ok()?;
        if position > MAX_FILE_BYTES {
            return None;
        }
        self.handles.get_mut(&handle)?.position = position;
        Some(position)
    }
}

#[cfg(test)]
mod tests {
    use indextree::Arena;

    use super::*;

    #[test]
    fn embedded_lines_reach_eof_and_closed_handles_are_invalid() {
        let mut arena = Arena::new();
        let file = arena.new_node(());
        let mut files = Files::default();
        files.register(file, 4);
        let mut read = |position| {
            assert_eq!(position, 4);
            Ok(Cursor::new(b"Publisher=Example\r\nVersion=1.2\n".to_vec()))
        };
        let handle = files.open(file, true, false, false).unwrap();
        assert_eq!(
            files.read(handle, false, false, 8191, &mut read).as_deref(),
            Some("Publisher=Example\r\n")
        );
        assert_eq!(
            files.read(handle, false, false, 8191, &mut read).as_deref(),
            Some("Version=1.2\n")
        );
        assert_eq!(files.read(handle, false, false, 8191, &mut read), None);
        assert_eq!(files.seek(handle, 0, 0, &mut read), Some(0));
        assert_eq!(
            files.read(handle, false, true, 1, &mut read).as_deref(),
            Some("80")
        );
        files.close(handle);
        assert_eq!(files.read(handle, false, false, 8191, &mut read), None);
    }

    #[test]
    fn unicode_writes_bom_word_reads_and_seeks_share_contents() {
        let mut arena = Arena::new();
        let file = arena.new_node(());
        let mut files = Files::default();
        let mut read = |_| Err(io::ErrorKind::NotFound.into());
        let handle = files.open(file, true, true, true).unwrap();
        let bytes: Vec<_> = "Linköping\r\n第二行"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(files.write(handle, &bytes, true, &mut read), Some(file));
        files.seek(handle, 0, 0, &mut read).unwrap();
        assert_eq!(
            files.read(handle, true, false, 8191, &mut read).as_deref(),
            Some("Linköping\r\n")
        );
        assert_eq!(
            files.read(handle, true, false, 8191, &mut read).as_deref(),
            Some("第二行")
        );
        assert_eq!(files.seek(handle, -2, 2, &mut read), Some(bytes.len()));
        assert_eq!(
            files.read(handle, true, true, 1, &mut read).as_deref(),
            Some("34892")
        );
        let other = files.open(file, true, false, false).unwrap();
        assert_eq!(
            files.read(other, true, false, 4, &mut read).as_deref(),
            Some("Link")
        );
    }

    #[test]
    fn unknown_files_and_oversized_writes_are_not_fabricated() {
        let mut arena = Arena::new();
        let file = arena.new_node(());
        let mut files = Files::default();
        let mut read = |_| Err(io::ErrorKind::NotFound.into());
        let unknown = files.open(file, true, false, false).unwrap();
        assert_eq!(files.read(unknown, false, false, 10, &mut read), None);
        let handle = files.open(file, true, true, true).unwrap();
        files.write(handle, b"safe", false, &mut read).unwrap();
        assert_eq!(files.seek(handle, -1, 0, &mut read), None);
        assert_eq!(
            files.write(handle, &vec![0; MAX_FILE_BYTES], false, &mut read),
            None
        );
        assert_eq!(
            files.bytes(file, &mut read).as_deref(),
            Some(b"safe".as_slice())
        );
    }
}
