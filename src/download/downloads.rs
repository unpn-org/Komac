use std::{
    collections::HashMap,
    io::{Read, Seek},
    mem,
};

use color_eyre::Result;
use futures_util::{StreamExt, TryStreamExt, stream};
use tracing::debug;
use winget_types::{installer::{Architecture, InstallerManifest}, url::DecodedUrl};

use super::DownloadedFile;
use crate::{
    analysis::Analyzer,
    traits::InstallerManifestExt,
};

#[derive(Default)]
pub struct Downloads(Vec<DownloadedFile>);

impl Downloads {
    /// Creates a new [`Downloads`] from an iterator of [`DownloadedFile`].
    #[cfg_attr(not(test), expect(unused))]
    pub fn new<I>(downloads: I) -> Self
    where
        I: IntoIterator<Item = DownloadedFile>,
    {
        Self(downloads.into_iter().collect())
    }

    /// Removes and returns the last downloaded file, if any.
    #[allow(dead_code)]
    pub fn pop(&mut self) -> Option<DownloadedFile> {
        self.0.pop()
    }

    pub async fn analyze(
        &mut self,
        manifest: Option<&InstallerManifest>,
    ) -> Result<HashMap<DecodedUrl, Analyzer<'_, impl Read + Seek + use<>>>> {
        stream::iter(self.0.iter_mut().map(
            |DownloadedFile {
                 file,
                 download,
                 sha_256,
                 last_modified,
                 ..
             }| async move {
                let architecture = download.url().override_architecture()
                    .or_else(|| Architecture::from_url(download.url().as_str()));
                let installer_type = manifest.and_then(|manifest| {
                    manifest.installer_type_for_url(download.url().inner(), architecture)
                });
                let mut file_analyzer = Analyzer::with_installer_type(
                    file,
                    &download.file_name,
                    installer_type,
                )?;
                for installer in &mut file_analyzer.installers {
                    if let Some(architecture) = architecture {
                        installer.architecture = architecture;
                    }
                    debug!("{download}: {architecture:?}");
                    installer.url = download.url().inner().clone();
                    installer.sha_256 = sha_256.clone();
                    installer.release_date = *last_modified;
                }
                file_analyzer.file_name = mem::take(&mut download.file_name);
                Ok((mem::take(download.url_mut().inner_mut()), file_analyzer))
            },
        ))
        .buffer_unordered(num_cpus::get())
        .try_collect::<HashMap<_, _>>()
        .await
    }
}

impl Extend<DownloadedFile> for Downloads {
    fn extend<T: IntoIterator<Item = DownloadedFile>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use winget_types::installer::{Installer, InstallerType, NestedInstallerType};
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::download::Download;

    #[tokio::test]
    async fn manifest_zip_type_extracts_msix_during_download_analysis() -> Result<()> {
        for (root_type, entry_type, expected) in [
            (Some(InstallerType::Zip), None, InstallerType::Zip),
            (None, Some(InstallerType::Zip), InstallerType::Zip),
            (
                Some(InstallerType::Zip),
                Some(InstallerType::Msix),
                InstallerType::Msix,
            ),
        ] {
            let mut file = tempfile::tempfile()?;
            {
                let mut writer = ZipWriter::new(&mut file);
                for (path, contents) in [
                    ("AppxManifest.xml", br#"<Package>
                        <Identity Name="Test.App" Version="1.0.0.0" Publisher="CN=Test" ProcessorArchitecture="x64" />
                        <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" /></Dependencies>
                    </Package>"#.as_slice()),
                    ("AppxSignature.p7x", b"test signature".as_slice()),
                    ("Assets/font.ttf", &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                ] {
                    writer.start_file(path, SimpleFileOptions::default())?;
                    writer.write_all(contents)?;
                }
                writer.finish()?;
            }
            file.rewind()?;
            let mut files = Downloads::new([DownloadedFile {
                file,
                download: Download {
                    url: "https://example.com/app-2.msix".parse()?,
                    file_name: "app-2.msix".to_owned(),
                    response: None,
                },
                sha_256: Default::default(),
                last_modified: None,
            }]);
            let mut manifest = InstallerManifest {
                r#type: root_type,
                installers: vec![Installer {
                    r#type: entry_type,
                    url: "https://example.com/app-1.msix".parse()?,
                    ..Installer::default()
                }],
                ..InstallerManifest::default()
            };
            let results = files.analyze(Some(&manifest)).await?;
            let analyzer = results.values().next().unwrap();
            assert_eq!(analyzer.installers[0].r#type, Some(expected));
            if expected == InstallerType::Zip {
                assert_eq!(
                    analyzer.installers[0].nested_installer_type,
                    Some(NestedInstallerType::Font)
                );
                assert_eq!(
                    analyzer.zip.as_ref().unwrap().possible_installer_files,
                    ["Assets/font.ttf"]
                );
                manifest.update_installers(&analyzer.installers, &HashMap::new());
                assert_eq!(manifest.installers[0].r#type, Some(InstallerType::Zip));
            } else {
                assert!(analyzer.zip.is_none());
            }
        }
        Ok(())
    }
}
