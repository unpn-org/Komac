use std::{borrow::Cow, fmt, io};

use encoding_rs::UTF_16LE;

use super::VSHeader;
use crate::analysis::installers::pe::vs_version_info::vs_type::VSType;

/// Represents a [`String`](https://docs.microsoft.com/windows/win32/menurc/string-str) structure.
#[derive(Clone)]
pub struct VSString<'a> {
    header: VSHeader<'a>,
    value: Cow<'a, str>,
}

impl<'a> VSString<'a> {
    pub fn read_from(data: &'a [u8]) -> io::Result<Self> {
        let header = VSHeader::read_from(data)?;
        let data = &data[..usize::from(header.length())];

        let data = &data[header.end_offset..];

        let (chunks, _remainder) = data.as_chunks();
        let value_len = chunks
            .iter()
            .position(|chunk| chunk == b"\0\0")
            .map_or(data.len(), |index| index * size_of::<u16>());

        let string_bytes = &data[..value_len];

        Ok(Self {
            header,
            value: UTF_16LE.decode_without_bom_handling(string_bytes).0,
        })
    }

    /// The length, in bytes, of this [`String`] structure.
    ///
    /// [`String`]: VSString
    pub const fn length(&self) -> u16 {
        self.header.length()
    }

    /// The size of the Value member.
    ///
    /// This field is not reliable in practice: some producers store a WORD
    /// count, others a byte count, and Windows does not enforce either
    /// interpretation. String values are always UTF-16 and NUL-terminated;
    /// Windows determines their length by scanning for the UTF-16 terminator
    /// and relies on [`wLength`] for traversal.
    ///
    /// [`wLength`]: Self::length
    pub const fn value_length(&self) -> u16 {
        self.header.value_length()
    }

    /// Returns the type of data in the version resource.
    ///
    /// The value is 1 if the version resource contains text data and 0 if the
    /// version resource contains binary data.
    #[must_use]
    #[inline]
    pub const fn r#type(&self) -> VSType {
        self.header.r#type()
    }

    #[must_use]
    #[inline]
    pub fn key(&self) -> &str {
        self.header.key()
    }

    #[must_use]
    #[inline]
    pub fn raw_value(&self) -> &str {
        &self.value
    }

    #[must_use]
    #[inline]
    pub fn value(&self) -> &str {
        self.value.trim()
    }
}

impl fmt::Display for VSString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key(), self.value())
    }
}

impl fmt::Debug for VSString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("String")
            .field("wLength", &self.length())
            .field("wValueLength", &self.value_length())
            .field("wType", &self.r#type())
            .field("szKey", &self.key())
            .field("Value", &self.value())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unicode_values_including_mojibake_encoded_by_the_producer() {
        for value in ["Linköping", "LinkÃ¶ping"] {
            let mut bytes = vec![0; 6];
            bytes[2..4].copy_from_slice(&((value.encode_utf16().count() + 1) as u16).to_le_bytes());
            bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
            bytes.extend("CompanyName\0".encode_utf16().flat_map(u16::to_le_bytes));
            bytes.resize(bytes.len().next_multiple_of(4), 0);
            bytes.extend(value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
            let length = bytes.len() as u16;
            bytes[..2].copy_from_slice(&length.to_le_bytes());
            let string = VSString::read_from(&bytes).unwrap();
            assert_eq!(string.key(), "CompanyName");
            assert_eq!(string.value(), value);
        }
    }
}
