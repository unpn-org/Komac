use std::fs::File;

use chrono::NaiveDate;
use winget_types::{Sha256String, installer::Architecture, utils::ValidFileExtensions};

use crate::manifests::Url;

pub struct DownloadedFile {
    pub file: File,
    pub url: Url,
    pub sha_256: Sha256String,
    pub file_name: String,
    pub last_modified: Option<NaiveDate>,
}

impl DownloadedFile {
    pub fn architecture(&self) -> Option<Architecture> {
        self.url.override_architecture().or_else(|| {
            if matches!(
                self.file_name.parse(),
                Ok(ValidFileExtensions::MsixBundle | ValidFileExtensions::AppxBundle)
            ) {
                None
            } else {
                Architecture::from_url(self.url.as_str())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempfile;
    use winget_types::{Sha256String, installer::Architecture};

    use super::DownloadedFile;
    use crate::manifests::Url;

    fn downloaded_file(url: &str, file_name: &str) -> DownloadedFile {
        DownloadedFile {
            file: tempfile().unwrap(),
            url: url.parse::<Url>().unwrap(),
            sha_256: Sha256String::default(),
            file_name: file_name.to_owned(),
            last_modified: None,
        }
    }

    #[test]
    fn does_not_infer_architecture_for_bundle_with_extensionless_url() {
        let file = downloaded_file(
            "https://example.com/download/WinDirStat_x86_x64_arm64",
            "WinDirStat_x86_x64_arm64.msixbundle",
        );

        assert_eq!(
            Architecture::from_url(file.url.as_str()),
            Some(Architecture::Arm64)
        );
        assert_eq!(file.architecture(), None);
    }

    #[test]
    fn allows_explicit_architecture_override_for_bundle() {
        let file = downloaded_file(
            "https://example.com/download/application|arm64",
            "application.msixbundle",
        );

        assert_eq!(file.architecture(), Some(Architecture::Arm64));
    }

    #[test]
    fn infers_architecture_for_non_bundle() {
        let file = downloaded_file(
            "https://example.com/download/application-arm64",
            "application.exe",
        );

        assert_eq!(file.architecture(), Some(Architecture::Arm64));
    }
}
