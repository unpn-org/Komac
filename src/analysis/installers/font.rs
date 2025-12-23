use std::io::{Read, Seek};

use color_eyre::eyre::Result;
use winget_types::installer::{Architecture, Installer, InstallerType};

use super::super::Installers;

pub struct Font;

impl Font {
    pub fn new<R: Read + Seek>(_reader: R) -> Result<Self> {
        Ok(Self)
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
