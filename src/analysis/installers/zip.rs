#[cfg(feature = "cli")]
use std::mem;
use std::{
    collections::BTreeSet,
    io,
    io::{Read, Seek, SeekFrom},
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::Result;
#[cfg(feature = "cli")]
use inquire::{CustomType, MultiSelect, min_length};
use regex::Regex;
use thiserror::Error;
use tracing::debug;
#[cfg(feature = "cli")]
use winget_types::installer::PortableCommandAlias;
use winget_types::{
    installer::{Installer, InstallerType, NestedInstallerFiles},
    utils::ValidFileExtensions,
};
use zip::ZipArchive;

use super::super::Analyzer;
#[cfg(feature = "cli")]
use crate::prompts::handle_inquire_error;
use crate::traits::path::LowercaseExtension;

const IGNORABLE_FOLDERS: [&str; 2] = ["__MACOSX", "resources"];

#[derive(Debug, Error)]
#[error("{path} is not a valid nested installer file")]
struct InvalidNestedInstallerError {
    path: Utf8PathBuf,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

enum NestedFileMatch {
    Contains(String),
    Glob(Regex),
}

impl NestedFileMatch {
    fn new(pattern: &str) -> Result<Self> {
        if pattern.contains(['*', '?', '[']) {
            Ok(Self::Glob(Regex::new(&glob_to_regex(pattern))?))
        } else {
            Ok(Self::Contains(pattern.to_ascii_lowercase()))
        }
    }

    fn matches(&self, path: &Utf8Path) -> bool {
        match self {
            Self::Contains(pattern) => path.as_str().to_ascii_lowercase().contains(pattern),
            Self::Glob(pattern) => {
                let path = path.as_str().to_ascii_lowercase();
                let file_name = Utf8Path::new(&path).file_name().unwrap_or(path.as_str());

                pattern.is_match(&path) || pattern.is_match(file_name)
            }
        }
    }
}

fn glob_to_regex(pattern: &str) -> String {
    let pattern = pattern.replace('\\', "/").to_ascii_lowercase();
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '*' => {
                if chars.next_if_eq(&'*').is_some() {
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push_str("[^/]"),
            '[' => {
                regex.push('[');
                if chars.next_if_eq(&'!').is_some() {
                    regex.push('^');
                } else if chars.next_if_eq(&'^').is_some() {
                    regex.push('\\');
                    regex.push('^');
                }

                for character in chars.by_ref() {
                    if character == ']' {
                        regex.push(']');
                        break;
                    }
                    if character == '\\' {
                        regex.push('/');
                    } else {
                        regex.push(character);
                    }
                }
            }
            _ => regex.push_str(&regex::escape(&character.to_string())),
        }
    }

    regex.push('$');
    regex
}

pub struct Zip<R: Read + Seek> {
    archive: ZipArchive<R>,
    pub possible_installer_files: Vec<Utf8PathBuf>,
    pub installers: Vec<Installer>,
}

#[derive(Clone)]
pub struct MatchedInstaller {
    pub installer: Installer,
    #[allow(dead_code)]
    pub file_version: Option<String>,
    #[allow(dead_code)]
    pub product_version: Option<String>,
}

impl<R: Read + Seek> Zip<R> {
    pub fn new(reader: R) -> Result<Self> {
        let mut zip = ZipArchive::new(reader)?;

        let possible_installer_files = zip
            .file_names()
            .map(Utf8Path::new)
            .filter(|file_name| {
                ValidFileExtensions::from_path(file_name)
                    .is_ok_and(ValidFileExtensions::is_valid_nested_installer)
            })
            .filter(|file_name| {
                // Ignore folders that the main executable is unlikely to be in
                file_name.components().all(|component| {
                    IGNORABLE_FOLDERS
                        .iter()
                        .all(|folder| !component.as_str().eq_ignore_ascii_case(folder))
                })
            })
            .map(Utf8Path::to_path_buf)
            .collect::<Vec<_>>();

        debug!(?possible_installer_files);

        // If there's only one valid file in the zip, extract and analyze it
        let installers = if let [chosen_file_name] = possible_installer_files.as_slice() {
            let nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                relative_file_path: chosen_file_name.lowercase_extension(),
                portable_command_alias: None,
            }]);
            let file_installers = Self::analyze_nested_file_in_archive(&mut zip, chosen_file_name)?;

            file_installers
                .into_iter()
                .map(|installer| Installer {
                    r#type: Some(InstallerType::Zip),
                    nested_installer_type: installer
                        .r#type
                        .and_then(|installer_type| installer_type.try_into().ok()),
                    nested_installer_files: nested_installer_files.clone(),
                    ..installer
                })
                .collect()
        } else {
            vec![Installer {
                r#type: Some(InstallerType::Zip),
                ..Installer::default()
            }]
        };

        Ok(Self {
            archive: zip,
            possible_installer_files,
            installers,
        })
    }

    #[cfg(feature = "cli")]
    pub fn prompt(&mut self) -> Result<()> {
        if !self.possible_installer_files.is_empty() {
            let chosen = MultiSelect::new(
                "Select the nested files",
                mem::take(&mut self.possible_installer_files),
            )
            .with_validator(min_length!(1))
            .prompt()
            .map_err(handle_inquire_error)?;
            let mut chosen_paths = chosen.iter();
            let first_file_installers = Self::analyze_nested_file_in_archive(
                &mut self.archive,
                chosen_paths.next().unwrap(),
            )?;
            for path in chosen_paths {
                Self::analyze_nested_file_in_archive(&mut self.archive, path)?;
            }
            let first_file_is_portable = first_file_installers
                .first()
                .is_some_and(|installer| installer.r#type == Some(InstallerType::Portable));
            let nested_installer_files = chosen
                .into_iter()
                .map(|path| {
                    Ok(NestedInstallerFiles {
                        portable_command_alias: if first_file_is_portable {
                            CustomType::<PortableCommandAlias>::new(&format!(
                                "Portable command alias for {path}:",
                            ))
                            .prompt_skippable()
                            .map_err(handle_inquire_error)?
                        } else {
                            None
                        },
                        relative_file_path: path.lowercase_extension(),
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            self.installers = first_file_installers
                .into_iter()
                .map(|installer| Installer {
                    r#type: Some(InstallerType::Zip),
                    nested_installer_type: installer
                        .r#type
                        .and_then(|installer_type| installer_type.try_into().ok()),
                    nested_installer_files: nested_installer_files.clone(),
                    ..installer
                })
                .collect();
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn analyze_matches(&mut self, matches: &[String]) -> Result<Vec<Installer>> {
        Ok(self
            .analyze_matches_with_metadata(matches)?
            .into_iter()
            .map(|analysis| analysis.installer)
            .collect())
    }

    pub fn analyze_matches_with_metadata(
        &mut self,
        matches: &[String],
    ) -> Result<Vec<MatchedInstaller>> {
        let matches = matches
            .iter()
            .map(|pattern| NestedFileMatch::new(pattern))
            .collect::<Result<Vec<_>>>()?;

        let installers = self
            .possible_installer_files
            .iter()
            .filter(|path| matches.iter().any(|file_match| file_match.matches(path)))
            .map(|path| {
                let mut nested_file = self.archive.by_name(path.as_str())?;
                let mut temp_file = tempfile::tempfile()?;
                io::copy(&mut nested_file, &mut temp_file)?;
                temp_file.seek(SeekFrom::Start(0))?;

                let nested_analyzer =
                    Analyzer::new(&mut temp_file, path.as_str()).map_err(|source| {
                        InvalidNestedInstallerError {
                            path: path.clone(),
                            source: source.into(),
                        }
                    })?;
                let nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                    relative_file_path: path.lowercase_extension(),
                    portable_command_alias: None,
                }]);
                let file_version = nested_analyzer.file_version;
                let product_version = nested_analyzer.product_version;

                Ok(nested_analyzer
                    .installers
                    .into_iter()
                    .map(move |installer| Installer {
                        r#type: Some(InstallerType::Zip),
                        nested_installer_type: installer
                            .r#type
                            .and_then(|installer_type| installer_type.try_into().ok()),
                        nested_installer_files: nested_installer_files.clone(),
                        ..installer
                    })
                    .map({
                        let file_version = file_version.clone();
                        let product_version = product_version.clone();
                        move |installer| MatchedInstaller {
                            installer,
                            file_version: file_version.clone(),
                            product_version: product_version.clone(),
                        }
                    }))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(installers)
    }

    fn analyze_nested_file_in_archive(
        archive: &mut ZipArchive<R>,
        path: &Utf8Path,
    ) -> Result<Vec<Installer>> {
        let mut chosen_file = archive.by_name(path.as_str())?;
        let mut temp_file = tempfile::tempfile()?;
        io::copy(&mut chosen_file, &mut temp_file)?;
        temp_file.seek(SeekFrom::Start(0))?;
        let analyzer = Analyzer::new(&mut temp_file, path.as_str()).map_err(|source| {
            InvalidNestedInstallerError {
                path: path.to_owned(),
                source: source.into(),
            }
        })?;
        Ok(analyzer.installers)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use color_eyre::eyre::Result;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;

    const TTF_SIGNATURE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

    fn zip_with_files(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut buffer);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

            for (path, contents) in files {
                writer.start_file(path, options)?;
                writer.write_all(contents)?;
            }

            writer.finish()?;
        }

        Ok(buffer.into_inner())
    }

    #[rstest::rstest]
    #[case("package.nupkg")]
    #[case("package.NUPKG")]
    #[case("package.dat")]
    #[case("package")]
    #[case("package.zip")]
    fn analyzes_zip_contents_regardless_of_archive_extension(
        #[case] file_name: &str,
    ) -> Result<()> {
        let mut reader = Cursor::new(zip_with_files(&[("nested/font.ttf", &TTF_SIGNATURE)])?);
        let analyzer = Analyzer::new(&mut reader, file_name)?;

        assert!(analyzer.zip.is_some());
        let installer = &analyzer.installers[0];
        assert_eq!(installer.r#type, Some(InstallerType::Zip));
        assert_eq!(
            installer.nested_installer_type,
            Some(winget_types::installer::NestedInstallerType::Font)
        );
        assert_eq!(
            installer
                .nested_installer_files
                .first()
                .unwrap()
                .relative_file_path,
            "nested/font.ttf"
        );
        Ok(())
    }

    #[test]
    fn unknown_extension_rejects_non_zip_contents() {
        for contents in [b"not a zip".as_slice(), b"PK\x03\x04", b""] {
            let mut reader = Cursor::new(contents);
            assert!(Analyzer::new(&mut reader, "package.nupkg").is_err());
        }
    }

    #[test]
    fn nupkg_extracts_nested_msi() -> Result<()> {
        use msi::{Column, Insert, Package, PackageType, Value};
        use winget_types::installer::{Architecture, NestedInstallerType};

        let mut msi = Package::create(PackageType::Installer, Cursor::new(Vec::new()))?;
        msi.summary_info_mut().set_arch("x64");
        msi.create_table(
            "Property",
            vec![
                Column::build("Property").primary_key().string(72),
                Column::build("Value").string(0),
            ],
        )?;
        let product_code = "{45B61AD4-7D73-48B9-B9B4-724C9F0828E6}";
        msi.insert_rows(
            Insert::into("Property")
                .row(vec![Value::from("ProductCode"), Value::from(product_code)]),
        )?;
        msi.create_table(
            "Directory",
            vec![
                Column::build("Directory").primary_key().string(72),
                Column::build("Directory_Parent").nullable().string(72),
                Column::build("DefaultDir").string(255),
            ],
        )?;
        let msi_bytes = msi.into_inner()?.into_inner();
        let mut reader = Cursor::new(zip_with_files(&[(
            "redist/GameInputRedist.msi",
            &msi_bytes,
        )])?);

        let analyzer = Analyzer::new(&mut reader, "gameinput.nupkg")?;
        let installer = &analyzer.installers[0];
        assert_eq!(installer.r#type, Some(InstallerType::Zip));
        assert_eq!(
            installer.nested_installer_type,
            Some(NestedInstallerType::Msi)
        );
        assert_eq!(installer.architecture, Architecture::X64);
        assert_eq!(installer.product_code.as_deref(), Some(product_code));
        assert_eq!(
            installer
                .nested_installer_files
                .first()
                .unwrap()
                .relative_file_path,
            "redist/GameInputRedist.msi"
        );
        Ok(())
    }

    #[test]
    fn nupkg_extracts_nested_appx_and_preserves_standalone_appx_analysis() -> Result<()> {
        use winget_types::{Sha256String, installer::NestedInstallerType};

        let appx = zip_with_files(&[
            ("AppxManifest.xml", br#"<Package>
                <Identity Name="Microsoft.NET.Native.Framework.2.2" Version="2.2.29512.0"
                    Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                    ProcessorArchitecture="x64" />
                <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.10049.0" /></Dependencies>
            </Package>"#),
            ("AppxSignature.p7x", b"test signature"),
        ])?;
        for file_name in ["framework.appx", "framework.msix"] {
            let mut reader = Cursor::new(&appx);
            let analyzer = Analyzer::new(&mut reader, file_name)?;
            assert!(analyzer.zip.is_none());
            assert_eq!(analyzer.installers[0].r#type, Some(InstallerType::Appx));
        }

        let nested_path = "tools/SharedLibrary/ret/Native/framework.appx";
        let mut reader = Cursor::new(zip_with_files(&[(nested_path, &appx)])?);
        let mut analyzer = Analyzer::new(&mut reader, "framework.nupkg")?;
        let installer = &analyzer.installers[0];
        assert_eq!(installer.r#type, Some(InstallerType::Zip));
        assert_eq!(
            installer.nested_installer_type,
            Some(NestedInstallerType::Appx)
        );
        assert_eq!(
            installer.package_family_name.as_ref().unwrap().to_string(),
            "Microsoft.NET.Native.Framework.2.2_8wekyb3d8bbwe"
        );
        assert_eq!(
            installer.signature_sha_256,
            Some(Sha256String::hash_from_reader(
                b"test signature".as_slice()
            )?)
        );
        assert_eq!(
            installer
                .nested_installer_files
                .first()
                .unwrap()
                .relative_file_path,
            nested_path
        );
        let matched = analyzer
            .zip
            .as_mut()
            .unwrap()
            .analyze_matches(&["*.appx".to_owned()])?;
        assert_eq!(matched.len(), 1);
        assert_eq!(
            matched[0].nested_installer_type,
            Some(NestedInstallerType::Appx)
        );
        Ok(())
    }

    #[test]
    fn selected_nested_files_reject_invalid_file_with_valid_extension() -> Result<()> {
        let zip_bytes = zip_with_files(&[("valid.ttf", &TTF_SIGNATURE), ("invalid.ttf", b"nope")])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes))?;
        let selected_files = [
            Utf8PathBuf::from("valid.ttf"),
            Utf8PathBuf::from("invalid.ttf"),
        ];

        let error = selected_files
            .iter()
            .map(|path| Zip::analyze_nested_file_in_archive(&mut zip.archive, path))
            .collect::<Result<Vec<_>>>()
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid.ttf is not a valid nested installer file"
        );
        Ok(())
    }

    #[test]
    fn selected_nested_file_accepts_valid_file() -> Result<()> {
        let zip_bytes = zip_with_files(&[
            ("valid.ttf", &TTF_SIGNATURE),
            ("ignored.txt", b"not an installer"),
        ])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes))?;
        let selected_file = Utf8PathBuf::from("valid.ttf");

        let installers = Zip::analyze_nested_file_in_archive(&mut zip.archive, &selected_file)?;

        assert_eq!(installers[0].r#type, Some(InstallerType::Font));
        Ok(())
    }

    #[test]
    fn multiple_nested_candidates_do_not_infer_nested_installer() -> Result<()> {
        let zip_bytes = zip_with_files(&[
            ("first.exe", b"not an exe"),
            ("second.exe", b"not an exe"),
            ("valid.ttf", &TTF_SIGNATURE),
        ])?;

        let zip = Zip::new(Cursor::new(zip_bytes))?;

        assert_eq!(zip.installers[0].r#type, Some(InstallerType::Zip));
        assert_eq!(zip.installers[0].nested_installer_type, None);
        assert!(zip.installers[0].nested_installer_files.is_empty());
        Ok(())
    }
}
