use std::{borrow::Cow, io};

use encoding_rs::{Encoding, UTF_16LE};
use zerocopy::LE;

use super::VSType;
use crate::read::ReadBytesExt;

/// Represents a header for a `VS_VERSION` structure.
///
/// This is not an officially documented header, but rather is added to make parsing `VS_`
/// structures a little bit easier.
#[derive(Clone, Debug)]
pub struct VSHeader<'a> {
    length: u16,
    value_length: u16,
    r#type: VSType,
    key: Cow<'a, str>,
    pub end_offset: usize,
}

impl<'a> VSHeader<'a> {
    pub fn read_from(data: &'a [u8]) -> io::Result<Self> {
        Self::read_with_key_length_from(data, None)
    }

    pub fn read_with_key_length_from(
        data: &'a [u8],
        key_length: Option<usize>,
    ) -> io::Result<Self> {
        let mut reader = data;
        let length = reader.read_u16::<LE>()?;
        // Every offset, key and child must stay within its containing block.
        let mut data = data
            .get(size_of::<u16>()..usize::from(length))
            .ok_or_else(|| io::Error::other("Invalid version resource block length"))?;
        let value_length = data.read_u16::<LE>()?;
        let r#type = VSType::try_read_from(&mut data)?;

        // Use the provided key length or search for a 16-bit null word
        let key_length = if let Some(key_length) = key_length {
            key_length
        } else {
            let (chunks, _remainder) = data.as_chunks();
            chunks
                .iter()
                .position(|chunk| chunk == b"\0\0")
                .map(|index| index * size_of::<u16>())
                .ok_or_else(|| io::Error::other("Unterminated version resource key"))?
        };

        let key_bytes = data
            .get(..key_length)
            .ok_or_else(|| io::Error::other("Truncated version resource key"))?;
        if data.get(key_length..key_length + size_of::<u16>()) != Some(b"\0\0") {
            return Err(io::Error::other("Unterminated version resource key"));
        }
        let key = UTF_16LE.decode_with_bom_removal(key_bytes).0;

        let end_offset = size_of::<u16>() * 3 + key_length + size_of::<u16>(); // Null word

        Ok(Self {
            length,
            value_length,
            r#type,
            key,
            // An empty value may omit the final alignment padding.
            end_offset: end_offset
                .next_multiple_of(size_of::<u32>())
                .min(usize::from(length)),
        })
    }

    #[must_use]
    #[inline]
    pub const fn length(&self) -> u16 {
        self.length
    }

    #[must_use]
    #[inline]
    pub const fn value_length(&self) -> u16 {
        self.value_length
    }

    #[must_use]
    #[inline]
    pub const fn r#type(&self) -> VSType {
        self.r#type
    }

    #[must_use]
    #[inline]
    pub const fn is_binary(&self) -> bool {
        self.r#type.is_binary()
    }

    #[must_use]
    #[inline]
    pub const fn is_string(&self) -> bool {
        self.r#type.is_string()
    }

    #[must_use]
    #[inline]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// An 8-digit hexadecimal number stored as a Unicode string.
    ///
    /// The four most significant digits represent the language identifier.
    /// The four least significant digits represent the code page for which the data is formatted.
    /// Each Microsoft Standard Language identifier contains two parts: the low-order 10 bits
    /// specify the major language, and the high-order 6 bits specify the sublanguage.
    fn string_table_hex_key(&self) -> u32 {
        u32::from_str_radix(self.key(), 16).unwrap_or_default()
    }

    /// Returns the raw codepage value for a [`StringTable`].
    ///
    /// [`StringTable`]: super::VSStringTable
    #[expect(clippy::cast_possible_truncation)]
    #[must_use]
    #[inline]
    pub(super) fn string_table_raw_codepage(&self) -> u16 {
        self.string_table_hex_key() as u16
    }

    pub(super) fn string_table_codepage(&self) -> &'static Encoding {
        codepage::to_encoding(self.string_table_raw_codepage()).unwrap_or(UTF_16LE)
    }
}
