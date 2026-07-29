use std::io::{self, Read, Seek, SeekFrom};

use camino::Utf8PathBuf;
use thiserror::Error;
use winget_types::installer::{Architecture, Installer, InstallerType};

use super::super::Installers;
use crate::analysis::FontInfo;

/// <https://learn.microsoft.com/en-us/typography/opentype/spec/otff#organization-of-an-opentype-font>
const TRUETYPE_SIGNATURE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
const OPENTYPE_SIGNATURE: [u8; 4] = *b"OTTO";
/// <https://learn.microsoft.com/en-us/typography/opentype/spec/otff#ttc-header>
const TRUETYPE_COLLECTION_SIGNATURE: [u8; 4] = *b"ttcf";
/// First 2 bytes are the little-endian FNT version (0x0200 or 0x0300).
const WINDOWS_FNT_SIGNATURES: [[u8; 2]; 2] = [[0x00, 0x02], [0x00, 0x03]];

#[derive(Error, Debug)]
pub enum FontError {
    #[error("{path} is not a valid font file")]
    NotFontFile { path: Utf8PathBuf },
    #[error("{path} contains a font table directory header that extends past the end of the file")]
    TableDirectoryHeaderOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains a font table directory with an unsupported sfnt version")]
    UnsupportedSfntVersion { path: Utf8PathBuf },
    #[error("{path} contains a font table directory that extends past the end of the file")]
    TableDirectoryOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains a font table record that points past the end of the file")]
    TableRecordOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains a font collection header that extends past the end of the file")]
    CollectionHeaderOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains a font collection with an unsupported version")]
    UnsupportedCollectionVersion { path: Utf8PathBuf },
    #[error("{path} contains an invalid font collection face-offset array")]
    InvalidCollectionFaceOffsets { path: Utf8PathBuf },
    #[error("{path} contains too many font collection faces")]
    TooManyCollectionFaces { path: Utf8PathBuf },
    #[error("{path} contains a name table that is too large to analyze")]
    NameTableTooLarge { path: Utf8PathBuf },
    #[error("{path} contains a truncated name table header")]
    NameTableHeaderOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains an unsupported name table format")]
    UnsupportedNameTableFormat { path: Utf8PathBuf },
    #[error("{path} contains an invalid name-record array")]
    NameRecordArrayOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains a name string that points past the end of the name table")]
    NameStringOutOfBounds { path: Utf8PathBuf },
    #[error("{path} contains an invalid UTF-16 name string")]
    InvalidUtf16Name { path: Utf8PathBuf },
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct Font {
    pub info: Option<FontInfo>,
}

impl Font {
    pub(crate) fn new<R: Read + Seek>(
        mut reader: R,
        path: &str,
        analysis: FontAnalysis,
    ) -> Result<Self, FontError> {
        let file_length = (analysis != FontAnalysis::None)
            .then(|| reader.seek(SeekFrom::End(0)))
            .transpose()?;
        reader.seek(SeekFrom::Start(0))?;

        let mut signature = [0u8; 4];
        reader.read_exact(&mut signature)?;

        let info = match (signature, file_length) {
            (TRUETYPE_SIGNATURE | OPENTYPE_SIGNATURE, Some(file_length)) => Some(
                FontInfo::from_sfnt(&mut reader, file_length, signature, analysis, path)?,
            ),
            (TRUETYPE_COLLECTION_SIGNATURE, Some(file_length)) => Some(FontInfo::from_collection(
                &mut reader,
                file_length,
                analysis,
                path,
            )?),
            (TRUETYPE_SIGNATURE | OPENTYPE_SIGNATURE | TRUETYPE_COLLECTION_SIGNATURE, None) => None,
            _ if WINDOWS_FNT_SIGNATURES.contains(&[signature[0], signature[1]]) => None,
            _ => return Err(FontError::NotFontFile { path: path.into() }),
        };

        Ok(Self { info })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FontAnalysis {
    #[default]
    None,
    Version,
    Full,
}

impl Installers for Font {
    fn installers(&self) -> Vec<Installer> {
        vec![Installer {
            r#type: Some(InstallerType::Font),
            architecture: Architecture::Neutral,
            ..Installer::default()
        }]
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn sfnt_with_version(version: &str) -> Vec<u8> {
        let value = version
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        let name_table_length = 18 + value.len();
        let mut bytes = vec![0; 28 + name_table_length];
        bytes[..4].copy_from_slice(&TRUETYPE_SIGNATURE);
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes[12..16].copy_from_slice(b"name");
        bytes[20..24].copy_from_slice(&28u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&(name_table_length as u32).to_be_bytes());
        bytes[30..32].copy_from_slice(&1u16.to_be_bytes());
        bytes[32..34].copy_from_slice(&18u16.to_be_bytes());
        bytes[34..36].copy_from_slice(&3u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&1u16.to_be_bytes());
        bytes[38..40].copy_from_slice(&0x0409u16.to_be_bytes());
        bytes[40..42].copy_from_slice(&5u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&(value.len() as u16).to_be_bytes());
        bytes[46..].copy_from_slice(&value);
        bytes
    }

    #[test]
    fn parses_sfnt_name_table() {
        let bytes = sfnt_with_version("Version 3.206");
        let font = Font::new(Cursor::new(bytes), "example.ttf", FontAnalysis::Full).unwrap();
        let info = font.info.unwrap();
        let value = serde_json::to_value(&info).unwrap();

        assert_eq!(value["Version"], "3.206");
        assert_eq!(value["Faces"].as_array().unwrap().len(), 1);
        assert_eq!(value["Faces"][0]["NameTable"][0]["NameId"], 5);
        assert_eq!(value["Faces"][0]["NameTable"][0]["Value"], "Version 3.206");
        assert_eq!(info.into_font_version().as_deref(), Some("3.206"));
    }

    #[test]
    fn parses_each_collection_face() {
        let mut bytes = vec![0; 72];
        bytes[..4].copy_from_slice(&TRUETYPE_COLLECTION_SIGNATURE);
        bytes[4..8].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&20u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&48u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&TRUETYPE_SIGNATURE);
        bytes[48..52].copy_from_slice(&OPENTYPE_SIGNATURE);

        let font = Font::new(Cursor::new(bytes), "collection.ttc", FontAnalysis::Full).unwrap();
        let info = font.info.unwrap();
        let value = serde_json::to_value(info).unwrap();

        assert_eq!(value["Faces"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_table_outside_file() {
        let bytes = sfnt_with_version("Version 1.0");
        let truncated = bytes[..28].to_vec();

        let error =
            Font::new(Cursor::new(truncated), "invalid.ttf", FontAnalysis::Full).unwrap_err();

        assert!(matches!(error, FontError::TableRecordOutOfBounds { .. }));
    }

    #[test]
    fn signature_only_analysis_does_not_read_the_table_directory() {
        let font = Font::new(
            Cursor::new(TRUETYPE_SIGNATURE),
            "update.ttf",
            FontAnalysis::None,
        )
        .unwrap();

        assert!(font.info.is_none());
    }

    #[test]
    fn version_analysis_keeps_only_the_version_name() {
        let font = Font::new(
            Cursor::new(sfnt_with_version("Version 3.206")),
            "update.ttf",
            FontAnalysis::Version,
        )
        .unwrap();
        let info = font.info.unwrap();
        let value = serde_json::to_value(&info).unwrap();

        assert_eq!(value["Faces"][0]["NameTable"].as_array().unwrap().len(), 1);
        assert_eq!(info.into_font_version().as_deref(), Some("3.206"));
    }
}
