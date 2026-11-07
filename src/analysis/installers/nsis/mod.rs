mod codepage;
mod entry;
mod error;
mod file_data;
mod file_io;
mod file_system;
mod first_header;
mod header;
mod ini;
mod int_fmt;
mod language;
mod registry;
mod section;
mod state;
mod strings;
mod variables;
mod version;

use std::io::{Read, Seek, SeekFrom};

use camino::Utf8Path;
pub use error::NsisError;
use msi::LanguageId;
use registry::Registry;
use state::NsisState;
use strsim::levenshtein;
use tracing::{debug, error, warn};
use typed_path::{Utf8Component, Utf8WindowsPath, Utf8WindowsPathBuf};
use variables::Variables;
use winget_types::{
    LanguageTag,
    installer::{
        AppsAndFeaturesEntries, AppsAndFeaturesEntry, Architecture, InstallationMetadata,
        Installer, InstallerType, Scope,
    },
};

use super::{
    nsis::{
        entry::{Entry, EntryError},
        file_system::FsEntry,
        first_header::FirstHeader,
        header::{Decompressed, Header},
    },
    pe::{PE, utils::machine_from_exe_reader},
    utils::{RELATIVE_PROGRAM_FILES_64, RELATIVE_TEMP_FOLDER},
};
use crate::{
    analysis::{
        Installers, extensions::FileExtension,
        installers::nsis::first_header::finder::FirstHeaderFinder,
    },
    traits::{FromMachine, IntoWingetArchitecture},
};

const APP_32: &str = "app-32";
const APP_64: &str = "app-64";

pub struct Nsis {
    pub architecture: Architecture,
    pub is_portable: bool,
    pub registry: Registry,
    pub primary_language_id: u16,
    pub install_directory: Option<Utf8WindowsPathBuf>,
}

impl Nsis {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, NsisError> {
        let manifest = pe.manifest(&mut reader).ok();
        let finder = FirstHeaderFinder::find(&mut reader, pe)?;
        let first_header = finder.first_header();
        let indexed = first_header.is_nsisbi()
            && header::indexed::probe(&mut reader, first_header.length_of_header())?;
        let data_offset = finder.data_offset()
            + if indexed {
                4
            } else if first_header.is_nsisbi() {
                8
            } else {
                0
            };
        reader.seek(SeekFrom::Start(data_offset))?;
        debug!(?finder, data_offset);

        let Decompressed {
            data: decompressed_data,
            is_solid,
            non_solid_start_offset,
            record_width,
            compression,
            decoder,
        } = Header::decompress(&mut reader, finder.first_header())?;

        let architecture = pe.winget_architecture();

        let header = if indexed {
            Header::read_indexed(&decompressed_data)?
        } else {
            Header::read_from(&decompressed_data, architecture.is_64_bit())?
        };

        debug!(?header);

        let mut file_data = file_data::FileData::new(
            decoder.into_inner(),
            data_offset,
            first_header.length_of_header(),
            is_solid,
            non_solid_start_offset,
            compression,
        )
        .with_record_width(record_width)
        .with_indexed_files(header.indexed_files().map(<[_]>::to_vec));
        let mut read_file = |position| file_data.read(position);
        let mut state = NsisState::new(
            &decompressed_data,
            &header,
            manifest.as_deref(),
            &mut read_file,
            first_header.is_nsisbi(),
        )?;
        state.mock_caller.configure(
            architecture,
            state.str_block.starts_with(b"\0\0"),
            manifest.as_deref(),
        );
        state.exec_flags[entry::ExecFlag::Silent] =
            zerocopy::I32::new(i32::from(first_header.is_silent()));

        state.exec_flags[entry::ExecFlag::RegView] =
            zerocopy::I32::new(if architecture.is_64_bit() {
                0x100
            } else {
                0x200
            });

        enum Outcome {
            Ready,
            Success,
            Failed,
            Quit,
            Incomplete,
        }
        let mut outcome = Outcome::Ready;

        // Abort/Quit in .onInit prevents installation. Interpreter failures also
        // cannot justify registry writes from sections that were never reached.
        if header.code_on_init() != -1 {
            debug!("Simulating code execution for .onInit callback");
            match state.execute_code_segment(header.code_on_init()) {
                Ok(Entry::Quit) => {
                    warn!(
                        "Installer quit during initialization; installation sections were not reached"
                    );
                    outcome = Outcome::Quit;
                }
                Err(invalid_entry) => {
                    error!(%invalid_entry);
                    outcome = Outcome::Incomplete;
                }
                _ => {}
            }
        }

        for (index, section) in header.blocks().sections(&decompressed_data).enumerate() {
            if !matches!(outcome, Outcome::Ready) {
                break;
            }
            if state
                .section_flags
                .get(index)
                .is_none_or(|flags| flags & 1 == 0)
            {
                continue;
            }
            debug!(
                r#"Simulating code execution for section {index} "{}""#,
                state.get_string(section.name_offset())
            );
            match state.execute_code_segment(section.code_offset()) {
                Ok(Entry::Quit) => {
                    warn!(
                        index,
                        "Installer quit during section execution; later sections were not reached"
                    );
                    outcome = Outcome::Quit;
                }
                Err(invalid_entry) => {
                    outcome = if matches!(
                        invalid_entry,
                        EntryError::Abort { .. } | EntryError::Execute
                    ) {
                        Outcome::Failed
                    } else {
                        Outcome::Incomplete
                    };
                    error!(%invalid_entry);
                }
                _ => {}
            }
        }

        if matches!(outcome, Outcome::Ready) {
            outcome = Outcome::Success;
        }
        let callback = match outcome {
            Outcome::Success => header.code_on_inst_success(),
            Outcome::Failed => header.code_on_inst_failed(),
            _ => -1,
        };
        if callback != -1 {
            debug!(callback, "Simulating installation outcome callback");
            match state.execute_code_segment(callback) {
                Err(EntryError::Abort { .. }) | Ok(..) => {}
                Err(invalid_entry) => error!(%invalid_entry),
            }
        }

        let mut architecture =
            Option::from(architecture).filter(|&architecture| architecture != Architecture::X86);

        for entry in state.file_system.entries().map(FsEntry::name) {
            // If there is an app-64 entry, the app is x64.
            // If there is an app-32 entry or both entries are present, the app is x86.
            // (x86 apps can still install on x64 systems)
            if entry.contains(APP_64) && architecture.is_none() {
                architecture = Some(Architecture::X64);
            } else if entry.contains(APP_32) {
                architecture = Some(Architecture::X86);
            }
        }

        debug!(%state.registry, %state.file_system);

        architecture = architecture
            .or_else(|| {
                let mut has_32_bit_section = false;
                let mut has_64_bit_section = false;

                for section in header.blocks().sections(&decompressed_data) {
                    let name = state.get_string(section.name_offset());
                    has_32_bit_section |= name.contains("32Bit") || name.contains("32-bit");
                    has_64_bit_section |= name.contains("64Bit") || name.contains("64-bit");
                }

                match (has_32_bit_section, has_64_bit_section) {
                    (true, true) => Some(Architecture::X86),
                    (false, true) => Some(Architecture::X64),
                    _ => None,
                }
            })
            .or_else(|| {
                state
                    .variables
                    .install_dir()
                    .is_some_and(|dir| dir.as_str().contains(RELATIVE_PROGRAM_FILES_64))
                    .then_some(Architecture::X64)
            })
            .or_else(|| {
                let app_name = state.get_string(state.language_table.name_offset()?);
                state
                    .file_system
                    .files()
                    .filter(|file| {
                        FileExtension::from_path(Utf8Path::new(file.name()))
                            .is_ok_and(|extension| extension == FileExtension::Exe)
                    })
                    .min_by_key(|file| levenshtein(file.name(), &app_name))
                    .and_then(|file| {
                        let mut reader = (state.read_file)(file.position()?).ok()?;
                        let machine = machine_from_exe_reader(&mut reader).ok()?;
                        Architecture::try_from_machine(machine)
                    })
            });

        Ok(Self {
            architecture: architecture.unwrap_or(Architecture::X86),
            is_portable: state.is_portable(),
            registry: state.registry,
            install_directory: state
                .variables
                .install_dir()
                .map(Utf8WindowsPath::to_path_buf),
            primary_language_id: state.language_table.id(),
        })
    }

    #[cfg(test)]
    pub fn display_name(&self) -> Option<&registry::Value> {
        const DISPLAY_NAME: &str = "DisplayName";

        self.registry
            .uninstall_entries()
            .find_map(|(_, _, values)| Registry::uninstall_value(values, DISPLAY_NAME))
    }
}

impl Installers for Nsis {
    fn installers(&self) -> Vec<Installer> {
        let product_code = self.registry.product_code();
        let detected_scope = self.registry.product_code_scope();
        let install_directory_scope = self
            .install_directory
            .as_deref()
            .and_then(Scope::from_install_directory);
        let scope = match (detected_scope, install_directory_scope) {
            (Some(detected_scope), Some(install_directory_scope))
                if detected_scope != install_directory_scope =>
            {
                None
            }
            (detected_scope, install_directory_scope) => detected_scope.or(install_directory_scope),
        };
        let apps_and_features_entries = self
            .registry
            .uninstall_entries()
            .filter_map(|(_, code, values)| {
                let name = Registry::uninstall_value(values, "DisplayName");
                let publisher = Registry::uninstall_value(values, "Publisher");
                let version = Registry::uninstall_value(values, "DisplayVersion");
                (name.is_some() || publisher.is_some() || version.is_some()).then(|| {
                    AppsAndFeaturesEntry::builder()
                        .maybe_display_name(name.cloned())
                        .maybe_publisher(publisher.cloned())
                        .maybe_display_version(version.cloned())
                        .product_code(code)
                        .build()
                })
            })
            .collect::<AppsAndFeaturesEntries>();

        let installer = Installer {
            locale: LanguageId::from_id(self.primary_language_id)
                .tag()
                .parse::<LanguageTag>()
                .ok(),
            architecture: self.architecture,
            r#type: if self.is_portable {
                Some(InstallerType::Portable)
            } else {
                Some(InstallerType::Nullsoft)
            },
            scope,
            product_code: product_code.map(str::to_owned),
            apps_and_features_entries,
            installation_metadata: InstallationMetadata::new_install_location(
                self.install_directory
                    .as_deref()
                    .filter(|path| {
                        !path.components().next().is_none_or(|component| {
                            component
                                .as_str()
                                .eq_ignore_ascii_case(RELATIVE_TEMP_FOLDER)
                        })
                    })
                    .map(|path| path.to_path_buf()),
            ),
            ..Installer::default()
        };

        vec![installer]
    }
}

#[cfg(test)]
mod tests {
    use registry::RegRoot;

    use super::*;

    const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Test.App";

    fn nsis_with_scope_signals(root: RegRoot, install_directory: &str) -> Nsis {
        let mut registry = Registry::new();
        registry.insert_value(root, UNINSTALL_KEY, "DisplayName", "Test App");

        Nsis {
            architecture: Architecture::X64,
            is_portable: false,
            registry,
            primary_language_id: 1033,
            install_directory: Some(Utf8WindowsPathBuf::from(install_directory)),
        }
    }

    #[test]
    fn keeps_nsis_scope_when_detected_scope_matches_install_location_scope() {
        let installer =
            nsis_with_scope_signals(RegRoot::HKEY_LOCAL_MACHINE, r"%ProgramFiles%\Test App")
                .installers()
                .remove(0);

        assert_eq!(installer.scope, Some(Scope::Machine));
    }

    #[test]
    fn does_not_set_nsis_scope_when_detected_scope_conflicts_with_install_location_scope() {
        let installer =
            nsis_with_scope_signals(RegRoot::HKEY_CURRENT_USER, r"%ProgramFiles%\Test App")
                .installers()
                .remove(0);

        assert_eq!(installer.scope, None);
    }
    #[test]
    fn arp_values_are_kept_with_their_own_uninstall_key() {
        let mut nsis =
            nsis_with_scope_signals(RegRoot::HKEY_LOCAL_MACHINE, r"%ProgramFiles%\Test App");
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            r"Software\A",
            "DisplayName",
            "Wrong App",
        );
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            r"Software\A",
            "Publisher",
            "Wrong Publisher",
        );
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            UNINSTALL_KEY,
            "DisplayVersion",
            "1.2.3",
        );
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            r"software\microsoft\windows\currentversion\uninstall\Other.App",
            "displayname",
            "Other App",
        );
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            r"software\microsoft\windows\currentversion\uninstall\Other.App",
            "publisher",
            "Other Publisher",
        );
        let installer = nsis.installers().remove(0);
        let entries = installer
            .apps_and_features_entries
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        let app = entries
            .iter()
            .find(|entry| entry.display_name() == Some("Test App"))
            .unwrap();
        assert_eq!(app.publisher(), None);
        assert_eq!(
            app.display_version().map(ToString::to_string),
            Some("1.2.3".to_owned())
        );
        assert_eq!(app.product_code(), Some("Test.App"));
        let other = entries
            .iter()
            .find(|entry| entry.display_name() == Some("Other App"))
            .unwrap();
        assert_eq!(other.publisher(), Some("Other Publisher"));
        assert_eq!(other.display_version(), None);
    }

    #[test]
    fn does_not_report_arp_for_non_uninstall_keys() {
        let mut nsis =
            nsis_with_scope_signals(RegRoot::HKEY_LOCAL_MACHINE, r"%ProgramFiles%\Test App");
        nsis.registry
            .remove_key(RegRoot::HKEY_LOCAL_MACHINE, UNINSTALL_KEY);
        nsis.registry.insert_value(
            RegRoot::HKEY_LOCAL_MACHINE,
            r"Software\Test",
            "DisplayName",
            "Not ARP",
        );
        assert!(nsis.installers()[0].apps_and_features_entries.is_empty());
        assert_eq!(nsis.display_name(), None);
    }
}
