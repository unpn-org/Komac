use std::str::FromStr;

use thiserror::Error;

pub const EXE: &str = "exe";
pub const MSI: &str = "msi";
pub const MSIX: &str = "msix";
pub const APPX: &str = "appx";
pub const MSIX_BUNDLE: &str = "msixbundle";
pub const APPX_BUNDLE: &str = "appxbundle";
pub const ZIP: &str = "zip";
pub const APP_INSTALLER: &str = "appinstaller";

/// An enumeration of valid file extensions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileExtension {
    Exe,
    Msi,
    Msix,
    Appx,
    MsixBundle,
    AppxBundle,
    Zip,
    AppInstaller,
    Otf,
    Ttf,
    Fnt,
    Ttc,
    Otc,
}

impl FileExtension {
    /// Returns `true` if the extension is `.appinstaller`.
    #[must_use]
    #[inline]
    pub const fn is_app_installer(self) -> bool {
        matches!(self, Self::AppInstaller)
    }

    /// Returns the file extension as a static string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exe => EXE,
            Self::Msi => MSI,
            Self::Msix => MSIX,
            Self::Appx => APPX,
            Self::MsixBundle => MSIX_BUNDLE,
            Self::AppxBundle => APPX_BUNDLE,
            Self::Zip => ZIP,
            Self::AppInstaller => APP_INSTALLER,
            Self::Otf => "otf",
            Self::Ttf => "ttf",
            Self::Fnt => "fnt",
            Self::Ttc => "ttc",
            Self::Otc => "otc",
        }
    }

    /// Returns whether the file type can be used as a nested installer in an archive.
    #[must_use]
    pub const fn is_valid_nested_installer(self) -> bool {
        !matches!(self, Self::Zip) && !self.is_app_installer()
    }

    /// Extracts a valid installer extension from a path.
    pub fn from_path(path: &camino::Utf8Path) -> Result<Self, UnsupportedFileExtensionError> {
        path.extension().unwrap_or_default().parse()
    }

    /// Finds the last path segment in a URL with a valid installer extension.
    ///
    /// Looking through all path segments supports download-wrapper URLs such as
    /// `https://example.com/file.msi/download`.
    #[must_use]
    pub fn from_url(url: &url::Url) -> Option<Self> {
        url.path_segments()?.rev().find_map(|segment| {
            segment.rsplit_once('.').and_then(|(file_stem, extension)| {
                if file_stem.is_empty() {
                    None
                } else {
                    extension.parse().ok()
                }
            })
        })
    }
}

#[derive(Debug, Error)]
#[error("{0} is not a supported file extension")]
pub struct UnsupportedFileExtensionError(String);

impl FromStr for FileExtension {
    type Err = UnsupportedFileExtensionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.rsplit_once('.').map_or(s, |(_, extension)| extension);
        match s {
            s if s.eq_ignore_ascii_case(EXE) => Ok(Self::Exe),
            s if s.eq_ignore_ascii_case(MSI) => Ok(Self::Msi),
            s if s.eq_ignore_ascii_case(MSIX) => Ok(Self::Msix),
            s if s.eq_ignore_ascii_case(APPX) => Ok(Self::Appx),
            s if s.eq_ignore_ascii_case(MSIX_BUNDLE) => Ok(Self::MsixBundle),
            s if s.eq_ignore_ascii_case(APPX_BUNDLE) => Ok(Self::AppxBundle),
            s if s.eq_ignore_ascii_case(ZIP) => Ok(Self::Zip),
            s if s.eq_ignore_ascii_case(APP_INSTALLER) => Ok(Self::AppInstaller),
            s if s.eq_ignore_ascii_case("otf") => Ok(Self::Otf),
            s if s.eq_ignore_ascii_case("ttf") => Ok(Self::Ttf),
            s if s.eq_ignore_ascii_case("fnt") => Ok(Self::Fnt),
            s if s.eq_ignore_ascii_case("ttc") => Ok(Self::Ttc),
            s if s.eq_ignore_ascii_case("otc") => Ok(Self::Otc),
            _ => Err(UnsupportedFileExtensionError(s.to_ascii_lowercase())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileExtension;

    #[test]
    fn parses_extensions_case_insensitively() {
        assert_eq!(
            "MSIXBUNDLE".parse::<FileExtension>().unwrap(),
            FileExtension::MsixBundle
        );
        assert_eq!(".Exe".parse::<FileExtension>().unwrap(), FileExtension::Exe);
        assert_eq!(
            "installer.x64.MSI".parse::<FileExtension>().unwrap(),
            FileExtension::Msi
        );
    }

    #[test]
    fn extracts_extension_from_download_wrapper_url() {
        let url = url::Url::parse("https://example.com/releases/installer.MSI/download").unwrap();

        assert_eq!(FileExtension::from_url(&url), Some(FileExtension::Msi));
    }

    #[test]
    fn extracts_extension_from_path() {
        assert_eq!(
            FileExtension::from_path(camino::Utf8Path::new("dir/installer.EXE")).unwrap(),
            FileExtension::Exe
        );
    }
}
