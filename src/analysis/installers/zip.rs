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

use super::{super::Analyzer, font::FontAnalysis};
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
    font_analysis: FontAnalysis,
    pub possible_installer_files: Vec<Utf8PathBuf>,
    pub installers: Vec<Installer>,
}

pub struct MatchedInstaller {
    pub installer: Installer,
    #[allow(dead_code)]
    pub file_version: Option<String>,
    #[allow(dead_code)]
    pub product_version: Option<String>,
    #[allow(dead_code)]
    pub font_version: Option<String>,
}

impl<R: Read + Seek> Zip<R> {
    pub(crate) fn new(reader: R, font_analysis: FontAnalysis) -> Result<Self> {
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
            let file_installers =
                Self::analyze_nested_file_in_archive(&mut zip, chosen_file_name, font_analysis)?;

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
            font_analysis,
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
                self.font_analysis,
            )?;
            for path in chosen_paths {
                Self::analyze_nested_file_in_archive(&mut self.archive, path, self.font_analysis)?;
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

    /// Select every nested installer candidate without prompting.
    pub fn select_all(&mut self) -> Result<()> {
        let chosen = self.possible_installer_files.clone();
        let Some((first_path, remaining_paths)) = chosen.split_first() else {
            return Ok(());
        };
        let first_file_installers = Self::analyze_nested_file_in_archive(
            &mut self.archive,
            first_path,
            self.font_analysis,
        )?;
        for path in remaining_paths {
            Self::analyze_nested_file_in_archive(&mut self.archive, path, self.font_analysis)?;
        }
        let nested_installer_files = chosen
            .into_iter()
            .map(|path| NestedInstallerFiles {
                portable_command_alias: None,
                relative_file_path: path.lowercase_extension(),
            })
            .collect::<BTreeSet<_>>();
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
                    Analyzer::new(&mut temp_file, path.as_str(), self.font_analysis).map_err(
                        |source| InvalidNestedInstallerError {
                            path: path.clone(),
                            source: source.into(),
                        },
                    )?;
                let nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                    relative_file_path: path.lowercase_extension(),
                    portable_command_alias: None,
                }]);
                let file_version = nested_analyzer.file_version;
                let product_version = nested_analyzer.product_version;
                let font_version = nested_analyzer.font_version;

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
                    .map(move |installer| MatchedInstaller {
                        installer,
                        file_version: file_version.clone(),
                        product_version: product_version.clone(),
                        font_version: font_version.clone(),
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
        font_analysis: FontAnalysis,
    ) -> Result<Vec<Installer>> {
        let mut chosen_file = archive.by_name(path.as_str())?;
        let mut temp_file = tempfile::tempfile()?;
        io::copy(&mut chosen_file, &mut temp_file)?;
        temp_file.seek(SeekFrom::Start(0))?;
        let analyzer =
            Analyzer::new(&mut temp_file, path.as_str(), font_analysis).map_err(|source| {
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

    const EMPTY_TTF: [u8; 12] = [0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];

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
        let zip_bytes = zip_with_files(&[("valid.ttf", &EMPTY_TTF), ("invalid.ttf", b"nope")])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Full)?;
        let selected_files = [
            Utf8PathBuf::from("valid.ttf"),
            Utf8PathBuf::from("invalid.ttf"),
        ];

        let error = selected_files
            .iter()
            .map(|path| {
                Zip::analyze_nested_file_in_archive(&mut zip.archive, path, FontAnalysis::Full)
            })
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
            ("valid.ttf", &EMPTY_TTF),
            ("ignored.txt", b"not an installer"),
        ])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Full)?;
        let selected_file = Utf8PathBuf::from("valid.ttf");

        let installers = Zip::analyze_nested_file_in_archive(
            &mut zip.archive,
            &selected_file,
            FontAnalysis::Full,
        )?;

        assert_eq!(installers[0].r#type, Some(InstallerType::Font));
        Ok(())
    }

    #[test]
    fn select_all_uses_every_nested_installer_file() -> Result<()> {
        let zip_bytes = zip_with_files(&[
            ("first.ttf", &EMPTY_TTF),
            ("nested/second.TTF", &EMPTY_TTF),
            ("ignored.txt", b"not an installer"),
        ])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Full)?;

        zip.select_all()?;

        let paths = zip.installers[0]
            .nested_installer_files
            .iter()
            .map(|file| file.relative_file_path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["first.ttf", "nested/second.ttf"]);
        assert_eq!(
            zip.installers[0].nested_installer_type,
            Some(winget_types::installer::NestedInstallerType::Font)
        );
        Ok(())
    }

    #[test]
    fn select_all_rejects_invalid_nested_installer_file() -> Result<()> {
        let zip_bytes = zip_with_files(&[("valid.ttf", &EMPTY_TTF), ("invalid.ttf", b"nope")])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Full)?;

        let error = zip.select_all().unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid.ttf is not a valid nested installer file"
        );
        Ok(())
    }

    #[test]
    fn multiple_nested_candidates_do_not_infer_nested_installer() -> Result<()> {
        let zip_bytes = zip_with_files(&[
            ("first.exe", b"not an exe"),
            ("second.exe", b"not an exe"),
            ("valid.ttf", &EMPTY_TTF),
        ])?;

        let zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Full)?;

        assert_eq!(zip.installers[0].r#type, Some(InstallerType::Zip));
        assert_eq!(zip.installers[0].nested_installer_type, None);
        assert!(zip.installers[0].nested_installer_files.is_empty());
        Ok(())
    }

    #[test]
    fn version_analysis_reads_only_selected_nested_font() -> Result<()> {
        let value = "Version 4.2"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        let name_table_length = 18 + value.len();
        let mut valid = vec![0; 28 + name_table_length];
        valid[..4].copy_from_slice(&EMPTY_TTF[..4]);
        valid[4..6].copy_from_slice(&1u16.to_be_bytes());
        valid[12..16].copy_from_slice(b"name");
        valid[20..24].copy_from_slice(&28u32.to_be_bytes());
        valid[24..28].copy_from_slice(&(name_table_length as u32).to_be_bytes());
        valid[30..32].copy_from_slice(&1u16.to_be_bytes());
        valid[32..34].copy_from_slice(&18u16.to_be_bytes());
        valid[34..36].copy_from_slice(&3u16.to_be_bytes());
        valid[36..38].copy_from_slice(&1u16.to_be_bytes());
        valid[38..40].copy_from_slice(&0x0409u16.to_be_bytes());
        valid[40..42].copy_from_slice(&5u16.to_be_bytes());
        valid[42..44].copy_from_slice(&(value.len() as u16).to_be_bytes());
        valid[46..].copy_from_slice(&value);
        let mut invalid = EMPTY_TTF;
        invalid[4..6].copy_from_slice(&1u16.to_be_bytes());
        let zip_bytes = zip_with_files(&[("selected.ttf", &valid), ("ignored.ttf", &invalid)])?;
        let mut zip = Zip::new(Cursor::new(zip_bytes), FontAnalysis::Version)?;

        let analyses = zip.analyze_matches_with_metadata(&["selected.ttf".to_owned()])?;

        assert_eq!(analyses.len(), 1);
        assert_eq!(analyses[0].font_version.as_deref(), Some("4.2"));
        Ok(())
    }
}
