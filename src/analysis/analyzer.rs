use std::{
    io::{Read, Seek},
    mem,
};

use camino::Utf8Path;
use color_eyre::eyre::{Result, bail};
use winget_types::{
    installer::Installer,
    locale::{Copyright, PackageName, Publisher},
    utils::ValidFileExtensions,
};

use super::PeInfo;
use crate::analysis::{
    Installers,
    installers::{
        Exe, Font, Msi, Zip,
        msix_family::{Msix, bundle::MsixBundle},
    },
};

pub struct Analyzer<'reader, R: Read + Seek> {
    pub file_name: String,
    pub copyright: Option<Copyright>,
    pub package_name: Option<PackageName>,
    pub publisher: Option<Publisher>,
    #[allow(dead_code)]
    pub file_version: Option<String>,
    #[allow(dead_code)]
    pub product_version: Option<String>,
    pub pe_info: Option<PeInfo>,
    pub installers: Vec<Installer>,
    pub zip: Option<Zip<&'reader mut R>>,
}

impl<'reader, R: Read + Seek> Analyzer<'reader, R> {
    pub(crate) fn new(
        reader: &'reader mut R,
        file_name: &str,
        font_analysis: FontAnalysis,
    ) -> Result<Self> {
        let path = Utf8Path::new(file_name);
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("appinstaller"))
        {
            // AppInstaller files should be converted to an MSIX or MSIXBundle before analysis.
            bail!(".appinstaller files are not supported for the analyze command");
        }

        let extension = ValidFileExtensions::from_path(path)?;

        let installers = match extension {
            ValidFileExtensions::Msi => Msi::new(reader)?.installers(),
            ValidFileExtensions::Msix | ValidFileExtensions::Appx => {
                Msix::new(reader)?.installers()
            }
            ValidFileExtensions::MsixBundle | ValidFileExtensions::AppxBundle => {
                MsixBundle::new(reader)?.installers()
            }
            ValidFileExtensions::Zip => {
                let mut scoped_zip = Zip::new(reader)?;
                let installers = mem::take(&mut scoped_zip.installers);
                return Ok(Self {
                    installers,
                    zip: Some(scoped_zip),
                    ..Self::default()
                });
            }
            ValidFileExtensions::Exe => {
                let mut exe = Exe::new(reader)?;
                return Ok(Self {
                    installers: exe.installers(),
                    copyright: exe
                        .legal_copyright
                        .take()
                        .and_then(|copyright| Copyright::new(copyright).ok()),
                    package_name: exe
                        .product_name
                        .take()
                        .and_then(|product_name| PackageName::new(product_name).ok()),
                    publisher: exe
                        .company_name
                        .take()
                        .and_then(|company_name| Publisher::new(company_name).ok()),
                    file_version: exe.file_version.take(),
                    product_version: exe.product_version.take(),
                    pe_info: exe.pe_info.take(),
                    ..Self::default()
                });
            }
            ValidFileExtensions::Fnt
            | ValidFileExtensions::Otc
            | ValidFileExtensions::Otf
            | ValidFileExtensions::Ttc
            | ValidFileExtensions::Ttf => Font::new(reader)?.installers(),
        };
        Ok(Self {
            installers,
            ..Self::default()
        })
    }

    /// Consumes the [`Analyzer`], returning the inner installers.
    pub fn into_installers(self) -> Vec<Installer> {
        self.installers
    }
}

impl<R: Read + Seek> Default for Analyzer<'_, R> {
    fn default() -> Self {
        Self {
            file_name: String::default(),
            copyright: None,
            package_name: None,
            publisher: None,
            file_version: None,
            product_version: None,
            pe_info: None,
            installers: Vec::default(),
            zip: None,
        }
    }
}
