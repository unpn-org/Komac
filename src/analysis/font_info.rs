use std::{
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};

use encoding_rs::MACINTOSH;
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::analysis::installers::font::{FontAnalysis, FontError};

const TRUETYPE_SIGNATURE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
const OPENTYPE_SIGNATURE: [u8; 4] = *b"OTTO";
const SFNT_HEADER_SIZE: u64 = 12;
const TABLE_RECORD_SIZE: u64 = 16;
const NAME_HEADER_SIZE: usize = 6;
const NAME_RECORD_SIZE: usize = 12;
const FONT_VERSION_NAME_ID: u16 = 5;

#[derive(Debug)]
pub struct FontInfo {
    format: &'static str,
    faces: Vec<FontFaceInfo>,
}

impl Serialize for FontInfo {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let version = self
            .faces
            .iter()
            .flat_map(|face| &face.name_table)
            .filter(|name| name.name_id == FONT_VERSION_NAME_ID)
            .filter(|name| !normalize_font_version(&name.value).is_empty())
            .min_by_key(|name| name_record_priority(name.platform_id, name.language_id))
            .map(|name| normalize_font_version(&name.value));
        let mut info = serializer.serialize_struct(
            "FontInfo",
            1 + usize::from(version.is_some()) + usize::from(!self.faces.is_empty()),
        )?;
        info.serialize_field("Format", self.format)?;
        if let Some(version) = version {
            info.serialize_field("Version", version)?;
        }
        if !self.faces.is_empty() {
            info.serialize_field("Faces", &self.faces)?;
        }
        info.end()
    }
}

impl FontInfo {
    pub(crate) fn from_sfnt<R: Read + Seek>(
        reader: &mut R,
        file_length: u64,
        signature: [u8; 4],
        analysis: FontAnalysis,
        path: &str,
    ) -> Result<Self, FontError> {
        let face = read_face(reader, 0, file_length, Some(signature), analysis, path)?;
        Ok(Self {
            format: match signature {
                TRUETYPE_SIGNATURE => "TrueType",
                OPENTYPE_SIGNATURE => "OpenType",
                _ => unreachable!(),
            },
            faces: vec![face],
        })
    }

    pub(crate) fn from_collection<R: Read + Seek>(
        reader: &mut R,
        file_length: u64,
        analysis: FontAnalysis,
        path: &str,
    ) -> Result<Self, FontError> {
        if file_length < SFNT_HEADER_SIZE {
            return Err(FontError::CollectionHeaderOutOfBounds { path: path.into() });
        }

        let mut collection_header = [0u8; 8];
        reader.read_exact(&mut collection_header)?;
        let collection_version = be_u32(&collection_header[..4]);
        if !matches!(collection_version, 0x0001_0000 | 0x0002_0000) {
            return Err(FontError::UnsupportedCollectionVersion { path: path.into() });
        }
        let face_count = be_u32(&collection_header[4..]);
        let offsets_length = u64::from(face_count) * size_of::<u32>() as u64;
        if face_count == 0 || offsets_length + SFNT_HEADER_SIZE > file_length {
            return Err(FontError::InvalidCollectionFaceOffsets { path: path.into() });
        }

        let face_count = usize::try_from(face_count)
            .map_err(|_| FontError::TooManyCollectionFaces { path: path.into() })?;
        let offsets_length = usize::try_from(offsets_length)
            .map_err(|_| FontError::TooManyCollectionFaces { path: path.into() })?;
        let mut offsets = vec![0u8; offsets_length];
        reader.read_exact(&mut offsets)?;

        let mut faces = Vec::with_capacity(face_count);
        for offset in offsets.chunks_exact(size_of::<u32>()) {
            faces.push(read_face(
                reader,
                be_u32(offset),
                file_length,
                None,
                analysis,
                path,
            )?);
        }

        Ok(Self {
            format: "TrueTypeCollection",
            faces,
        })
    }

    pub(crate) fn into_font_version(self) -> Option<String> {
        let mut value = self
            .faces
            .into_iter()
            .flat_map(|face| face.name_table)
            .filter(|name| name.name_id == FONT_VERSION_NAME_ID)
            .filter(|name| !normalize_font_version(&name.value).is_empty())
            .min_by_key(|name| name_record_priority(name.platform_id, name.language_id))?
            .value;
        let normalized = normalize_font_version(&value);
        if normalized.is_empty() {
            return None;
        }
        let start = normalized.as_ptr() as usize - value.as_ptr() as usize;
        let end = start + normalized.len();
        value.truncate(end);
        value.drain(..start);
        Some(value)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FontFaceInfo {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    name_table: Vec<FontNameInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FontNameInfo {
    platform_id: u16,
    encoding_id: u16,
    language_id: u16,
    name_id: u16,
    value: String,
}

#[derive(Clone, Copy)]
struct TableRecord {
    offset: u32,
    length: u32,
}

fn read_face<R: Read + Seek>(
    reader: &mut R,
    directory_offset: u32,
    file_length: u64,
    signature: Option<[u8; 4]>,
    analysis: FontAnalysis,
    path: &str,
) -> Result<FontFaceInfo, FontError> {
    let name_table = find_name_table(reader, directory_offset, file_length, signature, path)?
        .map(|record| read_name_table(reader, record, analysis, path))
        .transpose()?
        .unwrap_or_default();

    Ok(FontFaceInfo { name_table })
}

fn find_name_table<R: Read + Seek>(
    reader: &mut R,
    directory_offset: u32,
    file_length: u64,
    signature: Option<[u8; 4]>,
    path: &str,
) -> Result<Option<TableRecord>, FontError> {
    let directory_offset = u64::from(directory_offset);
    let header_end = directory_offset + SFNT_HEADER_SIZE;
    if header_end > file_length {
        return Err(FontError::TableDirectoryHeaderOutOfBounds { path: path.into() });
    }

    let mut header = [0u8; SFNT_HEADER_SIZE as usize];
    if let Some(signature) = signature {
        debug_assert_eq!(directory_offset, 0);
        header[..signature.len()].copy_from_slice(&signature);
        reader.read_exact(&mut header[signature.len()..])?;
    } else {
        reader.seek(SeekFrom::Start(directory_offset))?;
        reader.read_exact(&mut header)?;
    }
    if header[..4] != TRUETYPE_SIGNATURE && header[..4] != OPENTYPE_SIGNATURE {
        return Err(FontError::UnsupportedSfntVersion { path: path.into() });
    }

    let table_count = be_u16(&header[4..6]);
    let directory_length = u64::from(table_count) * TABLE_RECORD_SIZE + SFNT_HEADER_SIZE;
    if directory_offset + directory_length > file_length {
        return Err(FontError::TableDirectoryOutOfBounds { path: path.into() });
    }

    for _ in 0..table_count {
        let mut record = [0u8; TABLE_RECORD_SIZE as usize];
        reader.read_exact(&mut record)?;
        if record[..4] == *b"name" {
            let record = TableRecord {
                offset: be_u32(&record[8..12]),
                length: be_u32(&record[12..16]),
            };
            if u64::from(record.offset) + u64::from(record.length) > file_length {
                return Err(FontError::TableRecordOutOfBounds { path: path.into() });
            }
            return Ok(Some(record));
        }
    }

    Ok(None)
}

fn read_name_table<R: Read + Seek>(
    reader: &mut R,
    record: TableRecord,
    analysis: FontAnalysis,
    path: &str,
) -> Result<Vec<FontNameInfo>, FontError> {
    let table_length = usize::try_from(record.length)
        .map_err(|_| FontError::NameTableTooLarge { path: path.into() })?;
    if table_length < NAME_HEADER_SIZE {
        return Err(FontError::NameTableHeaderOutOfBounds { path: path.into() });
    }

    let mut table = vec![0u8; table_length];
    reader.seek(SeekFrom::Start(u64::from(record.offset)))?;
    reader.read_exact(&mut table)?;

    let format = be_u16(&table[..2]);
    if format > 1 {
        return Err(FontError::UnsupportedNameTableFormat { path: path.into() });
    }
    let record_count = usize::from(be_u16(&table[2..4]));
    let string_offset = usize::from(be_u16(&table[4..6]));
    let records_end = record_count * NAME_RECORD_SIZE + NAME_HEADER_SIZE;
    if records_end > table.len() || string_offset < records_end || string_offset > table.len() {
        return Err(FontError::NameRecordArrayOutOfBounds { path: path.into() });
    }

    if analysis == FontAnalysis::Version {
        return read_preferred_version_name(&table, record_count, string_offset, path)
            .map(|name| name.into_iter().collect());
    }

    let mut names = Vec::with_capacity(record_count);
    for index in 0..record_count {
        let record = name_record(&table, index);
        if let Some(value) = decode_name(&table, record, string_offset, path)?
            && !value.trim().is_empty()
        {
            names.push(FontNameInfo {
                platform_id: record.platform_id,
                encoding_id: record.encoding_id,
                language_id: record.language_id,
                name_id: record.name_id,
                value,
            });
        }
    }
    Ok(names)
}

fn read_preferred_version_name(
    table: &[u8],
    record_count: usize,
    string_offset: usize,
    path: &str,
) -> Result<Option<FontNameInfo>, FontError> {
    for priority in 0..=5 {
        for index in 0..record_count {
            let record = name_record(table, index);
            if record.name_id != FONT_VERSION_NAME_ID
                || !supports_encoding(record)
                || name_record_priority(record.platform_id, record.language_id) != priority
            {
                continue;
            }
            let Some(value) = decode_name(table, record, string_offset, path)? else {
                continue;
            };
            if normalize_font_version(&value).is_empty() {
                continue;
            }
            return Ok(Some(FontNameInfo {
                platform_id: record.platform_id,
                encoding_id: record.encoding_id,
                language_id: record.language_id,
                name_id: record.name_id,
                value,
            }));
        }
    }
    Ok(None)
}

#[derive(Clone, Copy)]
struct NameRecord {
    platform_id: u16,
    encoding_id: u16,
    language_id: u16,
    name_id: u16,
    length: u16,
    offset: u16,
}

fn name_record(table: &[u8], index: usize) -> NameRecord {
    let start = NAME_HEADER_SIZE + index * NAME_RECORD_SIZE;
    let record = &table[start..start + NAME_RECORD_SIZE];
    NameRecord {
        platform_id: be_u16(&record[..2]),
        encoding_id: be_u16(&record[2..4]),
        language_id: be_u16(&record[4..6]),
        name_id: be_u16(&record[6..8]),
        length: be_u16(&record[8..10]),
        offset: be_u16(&record[10..12]),
    }
}

fn decode_name(
    table: &[u8],
    record: NameRecord,
    string_offset: usize,
    path: &str,
) -> Result<Option<String>, FontError> {
    if !supports_encoding(record) {
        return Ok(None);
    }
    let start = string_offset + usize::from(record.offset);
    let end = start + usize::from(record.length);
    let bytes = table
        .get(start..end)
        .ok_or_else(|| FontError::NameStringOutOfBounds { path: path.into() })?;

    if matches!(record.platform_id, 0 | 3) {
        if !bytes.len().is_multiple_of(2) {
            return Err(FontError::InvalidUtf16Name { path: path.into() });
        }
        let mut value = String::with_capacity(bytes.len());
        for character in char::decode_utf16(
            bytes
                .chunks_exact(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
        ) {
            value.push(character.map_err(|_| FontError::InvalidUtf16Name { path: path.into() })?);
        }
        Ok(Some(value))
    } else {
        let (value, _) = MACINTOSH.decode_without_bom_handling(bytes);
        Ok(Some(value.into_owned()))
    }
}

const fn supports_encoding(record: NameRecord) -> bool {
    match record.platform_id {
        0 => true,
        1 => record.encoding_id == 0,
        3 => matches!(record.encoding_id, 0 | 1 | 10),
        _ => false,
    }
}

const fn name_record_priority(platform_id: u16, language_id: u16) -> u8 {
    match (platform_id, language_id) {
        (3, 0x0409) => 0,
        (0, _) => 1,
        (3, _) => 2,
        (1, 0) => 3,
        (1, _) => 4,
        _ => 5,
    }
}

fn normalize_font_version(value: &str) -> &str {
    let value = value.trim().split(';').next().unwrap_or_default().trim();
    value
        .get(..8)
        .filter(|prefix| prefix.eq_ignore_ascii_case("version "))
        .map_or(value, |_| value[8..].trim())
}

fn be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::{FontFaceInfo, FontInfo, FontNameInfo, normalize_font_version};

    #[test]
    fn normalizes_font_version_prefix_and_suffix() {
        assert_eq!(normalize_font_version("Version 3.206"), "3.206");
        assert_eq!(normalize_font_version("version 1.2; build 4"), "1.2");
        assert_eq!(normalize_font_version("2.37"), "2.37");
    }

    #[test]
    fn normalizes_owned_font_version_without_reallocating() {
        let value = String::from("Version 3.206; build 4");
        let allocation = value.as_ptr();
        let value = FontInfo {
            format: "TrueType",
            faces: vec![FontFaceInfo {
                name_table: vec![FontNameInfo {
                    platform_id: 3,
                    encoding_id: 1,
                    language_id: 0x0409,
                    name_id: 5,
                    value,
                }],
            }],
        }
        .into_font_version()
        .unwrap();

        assert_eq!(value, "3.206");
        assert_eq!(value.as_ptr(), allocation);
    }
}
