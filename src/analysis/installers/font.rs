use std::io::{self, Read, Seek, SeekFrom};

use camino::Utf8PathBuf;
use thiserror::Error;
use winget_types::installer::{Architecture, Installer, InstallerType};

use super::super::Installers;

/// <https://learn.microsoft.com/en-us/typography/opentype/spec/otff#organization-of-an-opentype-font>
const TRUETYPE_SIGNATURE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
const OPENTYPE_SIGNATURE: [u8; 4] = *b"OTTO";
/// <https://learn.microsoft.com/en-us/typography/opentype/spec/otff#ttc-header>
const TRUETYPE_COLLECTION_SIGNATURE: [u8; 4] = *b"ttcf";
/// First 2 bytes are the little-endian FNT version (0x0200 or 0x0300).
const WINDOWS_FNT_SIGNATURES: [[u8; 2]; 2] = [[0x00, 0x02], [0x00, 0x03]];

const FONT_SIGNATURES: [[u8; 4]; 3] = [
    TRUETYPE_SIGNATURE,
    OPENTYPE_SIGNATURE,
    TRUETYPE_COLLECTION_SIGNATURE,
];

#[derive(Error, Debug)]
pub enum FontError {
    #[error("{path} is not a valid font file")]
    NotFontFile { path: Utf8PathBuf },
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct Font;

impl Font {
    pub fn new<R: Read + Seek>(mut reader: R, path: &str) -> Result<Self, FontError> {
        reader.seek(SeekFrom::Start(0))?;

        let mut signature = [0u8; 4];
        reader.read_exact(&mut signature)?;

        if FONT_SIGNATURES.contains(&signature) {
            return Ok(Self);
        }

        let fnt_version = [signature[0], signature[1]];
        if WINDOWS_FNT_SIGNATURES.contains(&fnt_version) {
            return Ok(Self);
        }

        Err(FontError::NotFontFile {
            path: Utf8PathBuf::from(path),
        })
    }
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
