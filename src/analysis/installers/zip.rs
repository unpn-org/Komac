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
