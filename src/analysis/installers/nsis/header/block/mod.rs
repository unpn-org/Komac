mod r#type;

use std::{borrow::Cow, fmt, io::Cursor, ops::Index, slice};

use strum::{EnumCount, IntoEnumIterator};
pub use r#type::BlockType;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, TryFromBytes, U32, U64};

use crate::{
    analysis::installers::nsis::{
        Entry, NsisError, language::table::LanguageTable, section::Section,
    },
    read::ReadBytesExt,
};

#[derive(Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct BlockHeader {
    pub offset: U64<LE>,
    num: U32<LE>,
}

impl BlockHeader {
    #[inline]
    pub const fn offset(&self) -> u64 {
        self.offset.get()
    }

    #[inline]
    pub const fn num(&self) -> u32 {
        self.num.get()
    }
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("offset", &self.offset())
            .field("num", &self.num())
            .finish()
    }
}

#[derive(Copy, Clone, Default, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct BlockHeaders([BlockHeader; BlockType::COUNT]);

impl BlockHeaders {
    /// If the NSIS installer is 64-bit, the offset value in the `BlockHeader` is a u64 rather than
    /// a u32.
    pub fn read_dynamic_from_prefix(
        data: &[u8],
        is_64_bit: bool,
    ) -> Result<(Self, &[u8]), NsisError> {
        if is_64_bit {
            Self::read_from_prefix(data).map_err(NsisError::from)
        } else {
            let mut reader = Cursor::new(data);
            let mut block_headers = Self::default();
            for header in &mut block_headers {
                *header = BlockHeader {
                    offset: reader.read_t::<U32<LE>>()?.into(),
                    num: reader.read_t::<U32<LE>>()?,
                }
            }
            let mut reader_position = reader.position();
            if block_headers[BlockType::Pages].offset() == 276 {
                reader_position -= size_of::<u32>() as u64;
            }
            Ok((
                block_headers,
                &data[usize::try_from(reader_position).unwrap_or_default()..],
            ))
        }
    }

    /// Returns the data of a block.
    fn get<'data>(&self, data: &'data [u8], block_type: BlockType) -> &'data [u8] {
        let Ok(start) = usize::try_from(self[block_type].offset()) else {
            return &[];
        };
        let end = self
            .iter()
            .skip(block_type as usize + 1)
            .find(|block_header| block_header.offset > U64::ZERO)
            .and_then(|block| usize::try_from(block.offset()).ok())
            .unwrap_or(start);
        data.get(start..end).unwrap_or_default()
    }

    /// Returns the pages block.
    pub fn pages_block<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        self.get(data, BlockType::Pages)
    }

    /// Returns the sections block.
    fn sections_block<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        self.get(data, BlockType::Sections)
    }

    pub fn sections<'data>(&self, data: &'data [u8]) -> impl Iterator<Item = &'data Section> {
        let sections = self.sections_block(data);
        let section_size = sections
            .len()
            .checked_div(self[BlockType::Sections].num() as usize)
            .filter(|&size| size != 0)
            .unwrap_or(1);
        sections
            .chunks_exact(section_size)
            .flat_map(Section::ref_from_bytes)
    }

    /// Returns the entries block.
    fn entries_block<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        self.get(data, BlockType::Entries)
    }

    /// Returns a slice of [`Entry`] from the entries block.
    pub fn entries<'data>(&self, data: &'data [u8]) -> Result<&'data [Entry], NsisError> {
        let entries = self.entries_block(data);
        if entries.is_empty() {
            return Ok(&[]);
        }
        <[Entry]>::try_ref_from_bytes(entries)
            .map_err(|error| NsisError::ZeroCopy(error.to_string()))
    }

    /// The indexed fork appends a seventh operand to standard instructions.
    pub fn indexed_entries(&self, data: &[u8]) -> Result<Vec<Entry>, NsisError> {
        let raw = self.entries_block(data);
        if (self[BlockType::Entries].num() as usize).checked_mul(32) != Some(raw.len()) {
            return Err(NsisError::ZeroCopy(
                "Invalid indexed NSIS instruction block length".to_owned(),
            ));
        }
        raw.chunks_exact(32)
            .map(|entry| {
                Entry::try_read_from_bytes(&entry[..28])
                    .map_err(|error| NsisError::ZeroCopy(error.to_string()))
            })
            .collect()
    }

    /// BI adds two operands, including the high half of embedded file offsets.
    pub fn bi_entries(&self, data: &[u8]) -> Result<(Vec<Entry>, Vec<Option<u64>>), NsisError> {
        self.bi_entries_layout(data, true, false)
            .or_else(|_| self.bi_entries_layout(data, true, true))
            .or_else(|_| self.bi_entries_layout(data, false, false))
    }

    fn bi_entries_layout(
        &self,
        data: &[u8],
        external: bool,
        log: bool,
    ) -> Result<(Vec<Entry>, Vec<Option<u64>>), NsisError> {
        let raw = self.entries_block(data);
        if raw.len() % 36 != 0
            || (self[BlockType::Entries].num() != 0
                && raw.len() / 36 != self[BlockType::Entries].num() as usize)
        {
            return Err(NsisError::ZeroCopy(
                "Invalid NSISBI instruction block length".to_owned(),
            ));
        }
        let mut entries = Vec::new();
        let mut positions = Vec::new();
        for raw in raw.chunks_exact(36) {
            let words: Vec<u32> = raw
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .collect();
            let mut opcode = words[0];
            if external {
                opcode = match opcode {
                    21 => 20, // ExtractStubFile has ExtractFile's operands.
                    22 => 74, // VerifyExternalFile needs independent payload validation.
                    23.. => opcode - 2,
                    _ => opcode,
                };
            }
            if log && opcode != 74 {
                if opcode == 63 {
                    opcode = 70;
                } else if opcode > 63 {
                    opcode -= 1;
                }
            }
            let mut normal = [0u32; 7];
            normal.copy_from_slice(&words[..7]);
            normal[0] = opcode;
            let position = match opcode {
                20 => {
                    normal = [
                        opcode, words[1], words[2], words[3], words[5], words[6], words[7],
                    ];
                    Some(u64::from(words[3]) | (u64::from(words[4]) << 32))
                }
                51 => {
                    normal = [
                        opcode, words[1], words[2], words[3], words[4], words[6], words[7],
                    ];
                    None
                }
                62 => {
                    normal = [opcode, words[1], words[2], words[4], words[5], 0, 0];
                    Some(u64::from(words[2]) | (u64::from(words[3]) << 32))
                }
                _ => None,
            };
            let mut bytes = [0u8; 28];
            for (out, word) in bytes.chunks_exact_mut(4).zip(normal) {
                out.copy_from_slice(&word.to_le_bytes());
            }
            entries.push(Entry::try_read_from_bytes(&bytes).map_err(|error| {
                NsisError::ZeroCopy(format!(
                    "Invalid NSISBI entry {} {:?}: {error}",
                    entries.len(),
                    words
                ))
            })?);
            positions.push(position);
        }
        Ok((entries, positions))
    }

    /// Park moved Unicode and font opcodes into the middle of the instruction table.
    /// Try the documented layouts and validate every resulting instruction.
    pub fn park_entries<'data>(
        &self,
        data: &'data [u8],
        unicode: bool,
    ) -> Result<Cow<'data, [Entry]>, NsisError> {
        let raw = self.entries_block(data);
        for fonts in 0..=2 {
            for log in [false, true] {
                let mut entries = Vec::new();
                for bytes in raw.chunks_exact(size_of::<Entry>()) {
                    let mut bytes: [u8; size_of::<Entry>()] = bytes.try_into().unwrap();
                    let mut opcode = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    if opcode >= 44 {
                        if fonts >= 1 {
                            if opcode == 44 {
                                opcode = 72;
                            } else {
                                opcode -= 1;
                            }
                        }
                        if fonts >= 2 && opcode != 72 {
                            if opcode == 44 {
                                opcode = 73;
                            } else {
                                opcode -= 1;
                            }
                        }
                        if opcode < 72 && opcode >= 58 {
                            if unicode {
                                if opcode == 58 {
                                    opcode = 68;
                                } else if opcode == 59 {
                                    opcode = 69;
                                } else {
                                    opcode -= 2;
                                }
                            }
                            if opcode < 68 && opcode >= 63 && log {
                                if opcode == 63 {
                                    opcode = 70;
                                } else {
                                    opcode -= 1;
                                }
                            }
                            if opcode == 68 && !unicode {
                                opcode = 71;
                            }
                        }
                    }
                    bytes[..4].copy_from_slice(&opcode.to_le_bytes());
                    match Entry::try_read_from_bytes(&bytes) {
                        Ok(entry) => entries.push(entry),
                        Err(_) => break,
                    }
                }
                if entries.len() * size_of::<Entry>() == raw.len() {
                    return Ok(Cow::Owned(entries));
                }
            }
        }
        Err(NsisError::ZeroCopy(
            "Unsupported NSIS Park instruction layout".to_owned(),
        ))
    }

    /// Returns the strings block.
    pub fn strings_block<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        self.get(data, BlockType::Strings)
    }

    /// Returns the language table block.
    pub fn language_table_block<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        self.get(data, BlockType::LangTables)
    }

    /// Returns an iterator of [`LanguageTable`] in the language table block.
    pub fn language_tables<'data>(
        &self,
        data: &'data [u8],
    ) -> impl Iterator<Item = &'data LanguageTable> {
        let language_table_block = self.language_table_block(data);

        // This should match the language table size defined in the NSIS header, but calculating it
        // manually covers the case when the defined language table size is 0 or -1.
        let language_table_size = language_table_block
            .len()
            .checked_div(self[BlockType::LangTables].num() as usize)
            .filter(|&size| size != 0)
            .unwrap_or(1);

        language_table_block
            .chunks_exact(language_table_size)
            .flat_map(LanguageTable::ref_from_bytes)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &BlockHeader> {
        self.into_iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut BlockHeader> {
        self.into_iter()
    }
}

impl fmt::Debug for BlockHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct NamedBlockHeader {
            r#type: BlockType,
            block_header: BlockHeader,
        }

        impl fmt::Debug for NamedBlockHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(self.r#type.as_str())
                    .field("offset", &self.block_header.offset())
                    .field("num", &self.block_header.num())
                    .finish()
            }
        }

        f.debug_list()
            .entries(
                BlockType::iter()
                    .zip(self.iter())
                    .map(|(r#type, &block_header)| NamedBlockHeader {
                        r#type,
                        block_header,
                    }),
            )
            .finish()
    }
}

impl Index<BlockType> for BlockHeaders {
    type Output = BlockHeader;

    fn index(&self, index: BlockType) -> &Self::Output {
        self.0.index(index as usize)
    }
}

impl<'a> IntoIterator for &'a BlockHeaders {
    type Item = &'a BlockHeader;

    type IntoIter = slice::Iter<'a, BlockHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut BlockHeaders {
    type Item = &'a mut BlockHeader;

    type IntoIter = slice::IterMut<'a, BlockHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bi_instruction_width_and_full_file_offsets() {
        let words = [20u32, 0, 1, 0x89abcdef, 2, 0x11223344, 0x55667788, 0, 0];
        let data: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut blocks = BlockHeaders::default();
        blocks.0[BlockType::Strings as usize].offset = U64::new(data.len() as u64);
        blocks.0[BlockType::Entries as usize].num = U32::new(1);
        let (entries, offsets) = blocks.bi_entries(&data).unwrap();
        assert_eq!(offsets, vec![Some(0x2_89abcdef)]);
        let Entry::ExtractFile {
            datetime, position, ..
        } = entries[0]
        else {
            panic!("incorrect opcode");
        };
        assert_eq!(position.get() as u32, 0x89abcdef);
        assert_eq!(datetime.get(), 0x5566778811223344);
        assert!(blocks.bi_entries(&data[..35]).is_err());
    }

    #[test]
    fn empty_blocks_do_not_panic() {
        let blocks = BlockHeaders::default();
        assert_eq!(blocks.sections(&[]).count(), 0);
        assert_eq!(blocks.language_tables(&[]).count(), 0);
        assert_eq!(blocks.entries(&[]).unwrap().len(), 0);
    }

    #[test]
    fn invalid_block_ranges_do_not_panic() {
        let mut blocks = BlockHeaders::default();
        blocks.0[BlockType::Strings as usize].offset = U64::new(u64::MAX);
        assert!(blocks.strings_block(&[0; 4]).is_empty());
    }
}
