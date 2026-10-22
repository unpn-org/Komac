mod var_dword;
mod vs_file_flags;
mod vs_fixed_file_info;
mod vs_header;
mod vs_string;
mod vs_string_file_info;
mod vs_string_table;
mod vs_type;
mod vs_var;
mod vs_var_file_info;

use std::io;

use indexmap::IndexMap;
use var_dword::VarDword;
use vs_file_flags::VSFileFlags;
use vs_fixed_file_info::VSFixedFileInfo;
use vs_header::VSHeader;
use vs_string::VSString;
pub use vs_string_file_info::VSStringFileInfo;
use vs_string_table::VSStringTable;
use vs_type::VSType;
use vs_var::VSVar;
use vs_var_file_info::VSVarFileInfo;
use zerocopy::{FromBytes, TryFromBytes, Unaligned};

/// Represents a [`VS_VERSIONINFO`](https://docs.microsoft.com/windows/win32/menurc/vs-versioninfo) structure.
#[derive(Debug)]
pub struct VSVersionInfo<'a> {
    pub fixed: &'a VSFixedFileInfo,
    string: Option<VSStringFileInfo<'a>>,
    var: Option<VSVarFileInfo<'a>>,
}

impl<'a> VSVersionInfo<'a> {
    const SIGNATURE_LEN: usize = "VS_VERSION_INFO".len() * size_of::<u16>();

    pub fn read_from(data: &'a [u8]) -> io::Result<Self> {
        let header = VSHeader::read_with_key_length_from(data, Some(Self::SIGNATURE_LEN))?;
        let data = &data[..usize::from(header.length())];

        if header.key() != "VS_VERSION_INFO" {
            return Err(io::Error::other("Invalid VS_VERSION_INFO signature"));
        }

        let mut offset = header.end_offset;

        let (fixed_file_info, _) = VSFixedFileInfo::try_ref_from_prefix(&data[offset..])
            .map_err(|err| io::Error::other(err.to_string()))?;

        offset += size_of::<VSFixedFileInfo>();
        offset = offset.next_multiple_of(size_of::<u32>());

        let mut string_file_info = None;
        let mut var_file_info = None;

        while offset < usize::from(header.length()) {
            let block_header = VSHeader::read_from(&data[offset..])?;

            let block = &data[offset..offset + usize::from(block_header.length())];

            match block_header.key() {
                "StringFileInfo" => string_file_info = Some(VSStringFileInfo::read_from(block)?),
                "VarFileInfo" => var_file_info = Some(VSVarFileInfo::read_from(block)?),
                _ => {}
            }

            offset += usize::from(block_header.length());
            offset = offset.next_multiple_of(size_of::<u32>());
        }

        Ok(VSVersionInfo {
            fixed: fixed_file_info,
            string: string_file_info,
            var: var_file_info,
        })
    }

    pub const fn string_file_info(&self) -> Option<&VSStringFileInfo<'a>> {
        self.string.as_ref()
    }

    pub const fn var_file_info(&self) -> Option<&VSVarFileInfo<'a>> {
        self.var.as_ref()
    }

    pub fn string_entries(&'a self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.string_file_info()
            .map(VSStringFileInfo::entries)
            .into_iter()
            .flatten()
    }

    pub fn string_table(&self) -> IndexMap<&str, &str> {
        self.string_file_info()
            .map(VSStringFileInfo::table)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn utf16(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn block(key: &str, value_length: u16, kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0; size_of::<u16>()];
        data.extend(value_length.to_le_bytes());
        data.extend(kind.to_le_bytes());
        data.extend(utf16(key));
        data.extend([0; size_of::<u16>()]);
        data.resize(data.len().next_multiple_of(size_of::<u32>()), 0);
        data.extend(payload);
        let length = u16::try_from(data.len()).unwrap();
        data[..size_of::<u16>()].copy_from_slice(&length.to_le_bytes());
        data
    }

    fn resource(children: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; size_of::<VSFixedFileInfo>()];
        payload[..4].copy_from_slice(&0xFEEF_04BD_u32.to_le_bytes());
        payload.extend(children);
        block(
            "VS_VERSION_INFO",
            size_of::<VSFixedFileInfo>() as u16,
            0,
            &payload,
        )
    }

    fn version_resource(value_length: u16) -> Vec<u8> {
        let string = block("ProductVersion", value_length, 1, &utf16("2.47.0\0"));
        let table = block("040904E4", 0, 1, &string);
        resource(&block("StringFileInfo", 0, 1, &table))
    }

    #[rstest]
    #[case(0)]
    #[case(7)]
    #[case(14)]
    #[case(u16::MAX)]
    fn reads_valid_version_strings_with_unreliable_value_lengths(#[case] value_length: u16) {
        let data = version_resource(value_length);
        let version_info = VSVersionInfo::read_from(&data).unwrap();

        assert_eq!(
            version_info.string_table().get("ProductVersion"),
            Some(&"2.47.0")
        );
    }

    #[rstest]
    #[case(0)] // VS_VERSION_INFO
    #[case(92)] // StringFileInfo
    #[case(128)] // StringTable
    #[case(152)] // String
    fn rejects_invalid_block_lengths(#[case] offset: usize) {
        for length in [0_u16, 1, u16::MAX] {
            let mut data = version_resource(7);
            data[offset..offset + size_of::<u16>()].copy_from_slice(&length.to_le_bytes());

            assert!(
                VSVersionInfo::read_from(&data).is_err(),
                "offset {offset}, length {length}"
            );
        }
    }

    #[test]
    fn rejects_child_extending_past_parent_even_with_trailing_resource_bytes() {
        let mut data = version_resource(7);
        let length = u16::try_from(data.len() - 2).unwrap();
        data[..size_of::<u16>()].copy_from_slice(&length.to_le_bytes());

        assert_eq!(
            VSVersionInfo::read_from(&data).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn rejects_every_truncated_prefix() {
        let data = version_resource(7);

        for end in 0..data.len() {
            assert!(
                VSVersionInfo::read_from(&data[..end]).is_err(),
                "length {end}"
            );
        }
    }

    #[test]
    fn rejects_unterminated_key() {
        let mut data = version_resource(7);
        let key_end = size_of::<u16>() * 3 + VSVersionInfo::SIGNATURE_LEN;
        data[key_end..key_end + size_of::<u16>()].fill(1);

        assert!(VSVersionInfo::read_from(&data).is_err());
    }

    #[test]
    fn unterminated_value_does_not_read_into_next_string() {
        let mut strings = block("ProductVersion", 7, 1, &utf16("2.47.0"));
        strings.resize(strings.len().next_multiple_of(size_of::<u32>()), 0);
        strings.extend(block("CompanyName", 7, 1, &utf16("Arelle\0")));
        let table = block("040904E4", 0, 1, &strings);
        let data = resource(&block("StringFileInfo", 0, 1, &table));
        let version_info = VSVersionInfo::read_from(&data).unwrap();

        assert_eq!(
            version_info.string_table().get("ProductVersion"),
            Some(&"2.47.0")
        );
        assert_eq!(
            version_info.string_table().get("CompanyName"),
            Some(&"Arelle")
        );
    }

    #[test]
    fn rejects_empty_string_file_info() {
        let data = resource(&block("StringFileInfo", 0, 1, &[]));

        assert!(VSVersionInfo::read_from(&data).is_err());
    }
}
