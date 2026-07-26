#[cfg(feature = "cli")]
use std::mem;
use std::{
    collections::{BTreeSet, HashMap},
    io,
    io::{Read, Seek, SeekFrom},
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::Result;
#[cfg(feature = "cli")]
use inquire::{CustomType, MultiSelect, min_length};
use regex::Regex;
use tracing::debug;
#[cfg(feature = "cli")]
use winget_types::installer::PortableCommandAlias;
use winget_types::installer::{Installer, InstallerType, NestedInstallerFiles};
use zip::ZipArchive;

use super::super::Analyzer;
#[cfg(feature = "cli")]
use crate::prompts::handle_inquire_error;

const VALID_NESTED_FILE_EXTENSIONS: [&str; 6] =
    ["msix", "msi", "appx", "exe", "msixbundle", "appxbundle"];

const IGNORABLE_FOLDERS: [&str; 2] = ["__MACOSX", "resources"];

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
                VALID_NESTED_FILE_EXTENSIONS.iter().any(|file_extension| {
                    file_name
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case(file_extension))
                })
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

        let installer_type_counts = VALID_NESTED_FILE_EXTENSIONS
            .iter()
            .map(|file_extension| {
                (
                    file_extension,
                    possible_installer_files
                        .iter()
                        .filter(|file_name| {
                            file_name.extension().is_some_and(|extension| {
                                extension.eq_ignore_ascii_case(file_extension)
                            })
                        })
                        .count(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut nested_installer_files = BTreeSet::new();
        let mut installers = None;

        // If there's only one valid file in the zip, extract and analyze it
        if installer_type_counts
            .values()
            .filter(|&&count| count == 1)
            .count()
            == 1
        {
            let chosen_file_name = &possible_installer_files[0];
            nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                relative_file_path: chosen_file_name.clone(),
                portable_command_alias: None,
            }]);
            if let Ok(mut chosen_file) = zip.by_name(chosen_file_name.as_str()) {
                let mut temp_file = tempfile::tempfile()?;
                io::copy(&mut chosen_file, &mut temp_file)?;
                temp_file.seek(SeekFrom::Start(0))?;
                let file_analyzer = Analyzer::new(&mut temp_file, chosen_file_name.as_str())?;
                installers = Some(
                    file_analyzer
                        .installers
                        .into_iter()
                        .map(|installer| Installer {
                            r#type: Some(InstallerType::Zip),
                            nested_installer_type: installer
                                .r#type
                                .and_then(|installer_type| installer_type.try_into().ok()),
                            nested_installer_files: nested_installer_files.clone(),
                            ..installer
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }

        Ok(Self {
            archive: zip,
            possible_installer_files,
            installers: installers.unwrap_or_else(|| {
                vec![Installer {
                    r#type: Some(InstallerType::Zip),
                    nested_installer_files,
                    ..Installer::default()
                }]
            }),
        })
    }

    #[cfg(feature = "cli")]
    pub fn prompt(&mut self) -> Result<()> {
        if !&self.possible_installer_files.is_empty() {
            let chosen = MultiSelect::new(
                "Select the nested files",
                mem::take(&mut self.possible_installer_files),
            )
            .with_validator(min_length!(1))
            .prompt()
            .map_err(handle_inquire_error)?;
            let first_choice = chosen.first().unwrap();
            let mut temp_file = tempfile::tempfile()?;
            io::copy(
                &mut self.archive.by_name(first_choice.as_str())?,
                &mut temp_file,
            )?;
            temp_file.seek(SeekFrom::Start(0))?;
            let file_analyzer = Analyzer::new(&mut temp_file, first_choice.file_name().unwrap())?;
            let nested_installer_files = chosen
                .into_iter()
                .map(|path| {
                    Ok(NestedInstallerFiles {
                        portable_command_alias: if file_analyzer.installers[0].r#type
                            == Some(InstallerType::Portable)
                        {
                            CustomType::<PortableCommandAlias>::new(&format!(
                                "Portable command alias for {path}:",
                            ))
                            .prompt_skippable()
                            .map_err(handle_inquire_error)?
                        } else {
                            None
                        },
                        relative_file_path: path,
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            self.installers = file_analyzer
                .installers
                .into_iter()
                .map(|installer| Installer {
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

                let nested_analyzer = Analyzer::new(&mut temp_file, path.as_str())?;
                let nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                    relative_file_path: path.clone(),
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
}
