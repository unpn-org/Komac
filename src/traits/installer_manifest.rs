use std::{
    collections::{BTreeSet, HashMap},
    mem,
};

use camino::Utf8PathBuf;
use itertools::Itertools;
use winget_types::{
    installer::{
        Installer, InstallerManifest, InstallerType, NestedInstallerFiles, NestedInstallerType,
    },
    url::DecodedUrl,
};

use crate::{
    match_installers::{match_installers, unmatched_installers},
    traits::path::LowercaseExtension,
};

pub trait InstallerManifestExt {
    fn inherit_manifest_properties(&self) -> impl Iterator<Item = Installer> + '_;

    fn update_installers(
        &mut self,
        new_installers: &[Installer],
        possible_installer_files: &HashMap<DecodedUrl, Vec<Utf8PathBuf>>,
    );
}

impl InstallerManifestExt for InstallerManifest {
    fn inherit_manifest_properties(&self) -> impl Iterator<Item = Installer> + '_ {
        self.installers
            .iter()
            .cloned()
            .map(|installer| inherit_installer_properties(installer, self))
    }

    fn update_installers(
        &mut self,
        new_installers: &[Installer],
        possible_installer_files: &HashMap<DecodedUrl, Vec<Utf8PathBuf>>,
    ) {
        let previous_installers = self.inherit_manifest_properties().collect::<Vec<_>>();

        let url_counts = previous_installers
            .iter()
            .map(|installer| &installer.url)
            .counts();

        let matched_installers = match_installers(&previous_installers, new_installers);
        let unmatched_installers = unmatched_installers(&matched_installers, new_installers);
        self.installers = matched_installers
            .into_iter()
            .map(|(mut previous_installer, new_installer)| {
                let possible_installer_files = possible_installer_files
                    .get(&new_installer.url)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let previous_nested_files =
                    mem::take(&mut previous_installer.nested_installer_files);
                let duplicate_url = url_counts
                    .get(&previous_installer.url)
                    .is_some_and(|count| *count > 1);
                let mut installer =
                    merge_installer(previous_installer, new_installer, duplicate_url);

                let nested_files = if !previous_nested_files.is_empty() {
                    previous_nested_files
                } else if !self.nested_installer_files.is_empty() {
                    self.nested_installer_files.clone()
                } else {
                    mem::take(&mut installer.nested_installer_files)
                };
                installer.nested_installer_files =
                    fix_relative_paths(nested_files, possible_installer_files);

                installer
            })
            .chain(
                unmatched_installers
                    .into_iter()
                    .map(|installer| inherit_installer_properties(installer, self)),
            )
            .collect();
    }
}

fn inherit_installer_properties(installer: Installer, manifest: &InstallerManifest) -> Installer {
    Installer {
        // The new downloads supply release dates, rather than the previous manifest root.
        release_date: installer.release_date,
        ..installer.inherit_from(manifest)
    }
}

fn merge_installer(
    previous_installer: Installer,
    new_installer: Installer,
    duplicate_url: bool,
) -> Installer {
    let installer_type = match (previous_installer.r#type, new_installer.r#type) {
        (Some(InstallerType::Portable), _) | (_, Some(InstallerType::Portable)) => {
            previous_installer.r#type
        }
        _ => new_installer.r#type,
    };
    let nested_installer_type = match (
        previous_installer.nested_installer_type,
        new_installer.nested_installer_type,
    ) {
        (Some(NestedInstallerType::Portable), _) | (_, Some(NestedInstallerType::Portable)) => {
            previous_installer
                .nested_installer_type
                .or(new_installer.nested_installer_type)
        }
        _ => new_installer
            .nested_installer_type
            .or(previous_installer.nested_installer_type),
    };
    let previous_architecture = previous_installer.architecture;
    let previous_scope = previous_installer.scope;
    let mut installer = new_installer.merge_with(previous_installer);
    installer.r#type = installer_type;
    installer.nested_installer_type = nested_installer_type;

    if duplicate_url {
        // One executable can serve multiple manifest entries. Analysis sees its default
        // configuration, so retain each entry's declared architecture and scope.
        installer.architecture = previous_architecture;
        installer.scope = previous_scope.or(installer.scope);
    }
    installer
}

fn fix_relative_paths(
    nested_installer_files: BTreeSet<NestedInstallerFiles>,
    possible_installer_files: &[Utf8PathBuf],
) -> BTreeSet<NestedInstallerFiles> {
    if possible_installer_files.is_empty() {
        return nested_installer_files;
    }

    nested_installer_files
        .into_iter()
        .filter_map(|nested_installer_file| {
            let relative_path = &nested_installer_file.relative_file_path;
            if possible_installer_files.iter().any(|path| {
                path.as_str() == relative_path.as_str()
                    || winget_types::Path::new(path.as_str()).normalize()
                        == relative_path.normalize()
            }) {
                Some(nested_installer_file)
            } else {
                possible_installer_files
                    .iter()
                    .min_by_key(|file_path| {
                        strsim::levenshtein(
                            file_path.as_str(),
                            nested_installer_file.relative_file_path.as_str(),
                        )
                    })
                    .map(|path| NestedInstallerFiles {
                        relative_file_path: path.lowercase_extension(),
                        ..nested_installer_file
                    })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use rstest::rstest;
    use winget_types::installer::{
        Architecture, Installer, InstallerManifest, InstallerType, NestedInstallerFiles,
        NestedInstallerType, Scope, Switches, UpgradeBehavior,
    };

    use super::{InstallerManifestExt, fix_relative_paths, merge_installer};
    use crate::manifests::to_yaml_string;

    #[test]
    fn update_preserves_all_root_installer_properties() {
        let properties: serde_json::Value = serde_saphyr::from_str(indoc::indoc! {r#"
            InstallerLocale: en-US
            Platform: [Windows.Desktop]
            MinimumOSVersion: 10.0.19041.0
            InstallerType: zip
            NestedInstallerType: portable
            NestedInstallerFiles:
            - RelativeFilePath: app.exe
            Scope: machine
            InstallModes: [interactive, silent, silentWithProgress]
            InstallerSwitches:
              Silent: /silent
              SilentWithProgress: /passive
              Interactive: /interactive
              InstallLocation: /dir=<INSTALLPATH>
              Log: /log=<LOGPATH>
              Upgrade: /upgrade
              Custom: /custom
              Repair: /repair
            InstallerSuccessCodes: [10]
            ExpectedReturnCodes:
            - InstallerReturnCode: 20
              ReturnResponse: cancelledByUser
            UpgradeBehavior: install
            Commands: [app]
            Protocols: [app]
            FileExtensions: [app]
            Dependencies:
              WindowsFeatures: [NetFx3]
              WindowsLibraries: [library]
              PackageDependencies:
              - PackageIdentifier: Test.Dependency
                MinimumVersion: '1.0'
              ExternalDependencies: [external]
            PackageFamilyName: Microsoft.WindowsTerminal_8wekyb3d8bbwe
            ProductCode: '{11111111-1111-1111-1111-111111111111}'
            Capabilities: [internetClient]
            RestrictedCapabilities: [runFullTrust]
            Markets:
              AllowedMarkets: [US]
            InstallerAbortsTerminal: true
            InstallLocationRequired: true
            RequireExplicitUpgrade: true
            DisplayInstallWarnings: true
            UnsupportedOSArchitectures: [x86]
            UnsupportedArguments: [log]
            AppsAndFeaturesEntries:
            - DisplayName: Test Application
            ElevationRequirement: elevatesSelf
            InstallationMetadata:
              DefaultInstallLocation: '%ProgramFiles%/Test'
            DownloadCommandProhibited: true
            RepairBehavior: installer
            ArchiveBinariesDependOnPath: true
            Authentication:
              AuthenticationType: microsoftEntraId
              MicrosoftEntraIdAuthenticationInfo:
                Resource: https://example.com
        "#})
        .unwrap();
        let mut value = serde_json::to_value(InstallerManifest {
            package_identifier: "Test.Package".parse().unwrap(),
            package_version: "1.0".parse().unwrap(),
            ..InstallerManifest::default()
        })
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .extend(properties.as_object().unwrap().clone());
        let mut manifest: InstallerManifest = serde::Deserialize::deserialize(&value).unwrap();
        manifest.installers.push(Installer {
            architecture: Architecture::X64,
            r#type: Some(InstallerType::Zip),
            url: "https://example.com/app-1-x64.zip".parse().unwrap(),
            ..Installer::default()
        });
        // Cover both a matched installer and a newly added architecture.
        let new_installers =
            [Architecture::X64, Architecture::Arm64].map(|architecture| Installer {
                architecture,
                r#type: Some(InstallerType::Zip),
                url: format!("https://example.com/app-2-{architecture}.zip")
                    .parse()
                    .unwrap(),
                ..Installer::default()
            });

        manifest.update_installers(&new_installers, &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.installers.len(), 2);
        for installer in manifest.inherit_manifest_properties() {
            let value = serde_json::to_value(installer).unwrap();
            for (key, expected) in properties.as_object().unwrap() {
                assert_eq!(value.get(key), Some(expected), "{key}");
            }
        }
    }

    #[test]
    fn installer_switches_override_root_switches_individually() {
        let manifest = InstallerManifest {
            switches: Switches::builder()
                .silent("/root-silent".parse().unwrap())
                .custom("/root-custom".parse().unwrap())
                .install_location("/root=<INSTALLPATH>".parse().unwrap())
                .log("/log=<LOGPATH>".parse().unwrap())
                .build(),
            installers: vec![Installer {
                switches: Switches::builder()
                    .silent("/installer-silent".parse().unwrap())
                    .install_location("/installer=<INSTALLPATH>".parse().unwrap())
                    .build(),
                ..Installer::default()
            }],
            ..InstallerManifest::default()
        };
        let inherited = manifest.inherit_manifest_properties().next().unwrap();
        assert_eq!(
            inherited.switches,
            Switches::builder()
                .silent("/installer-silent".parse().unwrap())
                .custom("/root-custom".parse().unwrap())
                .install_location("/installer=<INSTALLPATH>".parse().unwrap())
                .log("/log=<LOGPATH>".parse().unwrap())
                .build()
        );
    }

    #[test]
    fn mixed_installer_types_preserve_root_properties() {
        let mut manifest = InstallerManifest {
            upgrade_behavior: Some(UpgradeBehavior::Install),
            file_extensions: BTreeSet::from(["slu".parse().unwrap()]),
            release_date: Some("2026-09-15".parse().unwrap()),
            ..InstallerManifest::default()
        };
        let mut new_installers = Vec::new();
        for architecture in [Architecture::X64, Architecture::Arm64] {
            for (installer_type, extension, release_date) in [
                (InstallerType::Nullsoft, "exe", "2026-09-18"),
                (InstallerType::Msix, "Msix", "2026-09-19"),
            ] {
                manifest.installers.push(Installer {
                    architecture,
                    r#type: Some(installer_type),
                    url: format!("https://example.com/Seelen.UI_2.8.5_{architecture}.{extension}")
                        .parse()
                        .unwrap(),
                    ..Installer::default()
                });
                let mut new_installer = Installer {
                    architecture,
                    r#type: Some(installer_type),
                    url: format!("https://example.com/Seelen.UI_2.8.6_{architecture}.{extension}")
                        .parse()
                        .unwrap(),
                    release_date: Some(release_date.parse().unwrap()),
                    ..Installer::default()
                };
                if installer_type == InstallerType::Msix {
                    new_installer.upgrade_behavior = manifest.upgrade_behavior;
                    new_installer
                        .file_extensions
                        .clone_from(&manifest.file_extensions);
                }
                new_installers.push(new_installer);
            }
        }

        manifest.update_installers(&new_installers, &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.installers.len(), 4);
        assert_eq!(manifest.upgrade_behavior, Some(UpgradeBehavior::Install));
        assert_eq!(
            manifest.file_extensions,
            BTreeSet::from(["slu".parse().unwrap()])
        );
        assert_eq!(manifest.release_date, None);
        for installer in &manifest.installers {
            assert_eq!(installer.upgrade_behavior, None);
            assert!(installer.file_extensions.is_empty());
            let analyzed_installer = new_installers
                .iter()
                .find(|new_installer| new_installer.url == installer.url)
                .unwrap();
            assert_eq!(installer.release_date, analyzed_installer.release_date);
        }
    }

    #[test]
    fn nested_paths_match_windows_separators_on_all_platforms() {
        let nested_file = NestedInstallerFiles {
            relative_file_path: r"app\bin\app.exe".into(),
            portable_command_alias: None,
        };
        let candidates = [camino::Utf8PathBuf::from("app/bin/app.exe")];

        assert_eq!(
            fix_relative_paths(BTreeSet::from([nested_file.clone()]), &candidates),
            BTreeSet::from([nested_file])
        );
    }

    #[rstest]
    #[case::shared_minimum(None, "10.0.19041.0")]
    #[case::installer_override(Some("10.0.22000.0"), "10.0.19041.0")]
    #[case::detected_minimum(None, "10.0.26100.0")]
    fn mixed_archives_and_msix_preserve_minimum_os_version(
        #[case] archive_minimum: Option<&str>,
        #[case] detected_minimum: &str,
    ) {
        let root_minimum = "10.0.19041.0".parse().unwrap();
        let archive_minimum = archive_minimum.map(|minimum| minimum.parse().unwrap());
        let detected_minimum = detected_minimum.parse().unwrap();
        let mut manifest = InstallerManifest {
            minimum_os_version: Some(root_minimum),
            ..InstallerManifest::default()
        };
        let mut new_installers = Vec::new();
        for architecture in [Architecture::X64, Architecture::Arm64] {
            for (installer_type, extension) in [
                (InstallerType::Zip, "zip"),
                (InstallerType::Msix, "msixbundle"),
            ] {
                manifest.installers.push(Installer {
                    architecture,
                    r#type: Some(installer_type),
                    minimum_os_version: if installer_type == InstallerType::Zip {
                        archive_minimum
                    } else {
                        Some(root_minimum)
                    },
                    url: format!("https://example.com/NanaBox_1.6.1498.0.{extension}")
                        .parse()
                        .unwrap(),
                    ..Installer::default()
                });
                new_installers.push(Installer {
                    architecture,
                    r#type: Some(installer_type),
                    minimum_os_version: (installer_type == InstallerType::Msix)
                        .then_some(detected_minimum),
                    url: format!("https://example.com/NanaBox_1.7.1633.0.{extension}")
                        .parse()
                        .unwrap(),
                    ..Installer::default()
                });
            }
        }

        manifest.update_installers(&new_installers, &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.installers.len(), 4);
        let archive_minimum = archive_minimum.unwrap_or(root_minimum);
        assert_eq!(
            manifest.minimum_os_version,
            (archive_minimum == detected_minimum).then_some(archive_minimum)
        );
        for installer in &manifest.installers {
            let expected = if installer.r#type == Some(InstallerType::Zip) {
                archive_minimum
            } else {
                detected_minimum
            };
            assert_eq!(
                installer.minimum_os_version.or(manifest.minimum_os_version),
                Some(expected)
            );
        }
    }

    #[rstest]
    #[case::root_defaults(false)]
    #[case::installer_overrides(true)]
    fn inherits_root_properties_without_replacing_installer_values(#[case] overrides: bool) {
        let installer = if overrides {
            Installer {
                r#type: Some(InstallerType::Inno),
                nested_installer_type: Some(NestedInstallerType::Inno),
                scope: Some(Scope::User),
                upgrade_behavior: Some(UpgradeBehavior::UninstallPrevious),
                file_extensions: BTreeSet::from(["custom".parse().unwrap()]),
                ..Installer::default()
            }
        } else {
            Installer::default()
        };
        let manifest = InstallerManifest {
            r#type: Some(InstallerType::Nullsoft),
            nested_installer_type: Some(NestedInstallerType::Portable),
            scope: Some(Scope::Machine),
            upgrade_behavior: Some(UpgradeBehavior::Install),
            file_extensions: BTreeSet::from(["slu".parse().unwrap()]),
            installers: vec![installer.clone()],
            ..InstallerManifest::default()
        };
        let expected = if overrides {
            installer
        } else {
            Installer {
                r#type: manifest.r#type,
                nested_installer_type: manifest.nested_installer_type,
                scope: manifest.scope,
                upgrade_behavior: manifest.upgrade_behavior,
                file_extensions: manifest.file_extensions.clone(),
                ..Installer::default()
            }
        };

        assert_eq!(
            manifest.inherit_manifest_properties().collect::<Vec<_>>(),
            vec![expected]
        );
    }

    #[test]
    fn shared_url_preserves_manifest_architectures() {
        let mut manifest = InstallerManifest {
            installers: [Architecture::X86, Architecture::X64]
                .map(|architecture| Installer {
                    architecture,
                    url: "https://example.com/app-1.exe".parse().unwrap(),
                    ..Installer::default()
                })
                .into(),
            ..InstallerManifest::default()
        };
        let new_installer = Installer {
            architecture: Architecture::X86,
            url: "https://example.com/app-2.exe".parse().unwrap(),
            ..Installer::default()
        };

        manifest.update_installers(std::slice::from_ref(&new_installer), &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.installers.len(), 2);
        assert_eq!(manifest.installers[0].architecture, Architecture::X86);
        assert_eq!(manifest.installers[1].architecture, Architecture::X64);
        assert!(
            manifest
                .installers
                .iter()
                .all(|installer| installer.url == new_installer.url)
        );
    }

    #[test]
    fn update_keeps_installers_without_previous_matches() {
        let previous_installer = Installer {
            architecture: Architecture::X64,
            url: "https://example.com/app-1-x64.exe".parse().unwrap(),
            ..Installer::default()
        };
        let mut manifest = InstallerManifest {
            installers: vec![previous_installer],
            ..InstallerManifest::default()
        };
        let new_installers =
            [Architecture::X64, Architecture::Arm64].map(|architecture| Installer {
                architecture,
                url: format!("https://example.com/app-2-{architecture}.exe")
                    .parse()
                    .unwrap(),
                ..Installer::default()
            });
        manifest.update_installers(&new_installers, &HashMap::new());
        let installers = manifest.installers;

        assert_eq!(installers.len(), 2);
        assert!(
            new_installers
                .iter()
                .all(|installer| installers.contains(installer))
        );
    }

    #[test]
    fn update_repairs_inherited_nested_paths_and_preserves_aliases() {
        let mut manifest = InstallerManifest {
            r#type: Some(InstallerType::Zip),
            nested_installer_type: Some(NestedInstallerType::Portable),
            nested_installer_files: BTreeSet::from([NestedInstallerFiles {
                relative_file_path: "app-1/bin/app.exe".into(),
                portable_command_alias: Some("app".parse().unwrap()),
            }]),
            installers: vec![Installer {
                architecture: Architecture::X64,
                url: "https://example.com/app-1.zip".parse().unwrap(),
                ..Installer::default()
            }],
            ..InstallerManifest::default()
        };
        let new_installer = Installer {
            architecture: Architecture::X64,
            r#type: Some(InstallerType::Zip),
            url: "https://example.com/app-2.zip".parse().unwrap(),
            ..Installer::default()
        };
        let candidates =
            HashMap::from([(new_installer.url.clone(), vec!["app-2/bin/app.exe".into()])]);

        manifest.update_installers(&[new_installer], &candidates);
        let installers = manifest.installers;

        assert_eq!(installers.len(), 1);
        assert_eq!(
            installers[0].nested_installer_type,
            Some(NestedInstallerType::Portable)
        );
        assert_eq!(
            installers[0].nested_installer_files,
            BTreeSet::from([NestedInstallerFiles {
                relative_file_path: "app-2/bin/app.exe".into(),
                portable_command_alias: Some("app".parse().unwrap()),
            }])
        );
    }

    #[rstest]
    #[case::exe_detected_as_portable(
        Some(NestedInstallerType::Exe),
        Some(NestedInstallerType::Portable),
        Some(NestedInstallerType::Exe)
    )]
    #[case::declared_portable(
        Some(NestedInstallerType::Portable),
        Some(NestedInstallerType::Inno),
        Some(NestedInstallerType::Portable)
    )]
    #[case::detected_installer_type(
        Some(NestedInstallerType::Exe),
        Some(NestedInstallerType::Inno),
        Some(NestedInstallerType::Inno)
    )]
    #[case::unknown_previous(
        None,
        Some(NestedInstallerType::Portable),
        Some(NestedInstallerType::Portable)
    )]
    #[case::unknown_new(Some(NestedInstallerType::Exe), None, Some(NestedInstallerType::Exe))]
    fn update_preserves_nested_installer_type_when_portable(
        #[case] previous_type: Option<NestedInstallerType>,
        #[case] detected_type: Option<NestedInstallerType>,
        #[case] expected_type: Option<NestedInstallerType>,
    ) {
        let mut manifest = InstallerManifest {
            r#type: Some(InstallerType::Zip),
            nested_installer_type: previous_type,
            installers: [Architecture::X64, Architecture::Arm64]
                .map(|architecture| Installer {
                    architecture,
                    url: format!("https://example.com/app-1-{architecture}.zip")
                        .parse()
                        .unwrap(),
                    ..Installer::default()
                })
                .into(),
            ..InstallerManifest::default()
        };
        let new_installers =
            [Architecture::X64, Architecture::Arm64].map(|architecture| Installer {
                architecture,
                r#type: Some(InstallerType::Zip),
                nested_installer_type: detected_type,
                url: format!("https://example.com/app-2-{architecture}.zip")
                    .parse()
                    .unwrap(),
                ..Installer::default()
            });

        manifest.update_installers(&new_installers, &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.r#type, Some(InstallerType::Zip));
        assert_eq!(manifest.nested_installer_type, expected_type);
        assert_eq!(manifest.installers.len(), 2);
        for installer in &manifest.installers {
            assert_eq!(installer.nested_installer_type, None);
            assert!(new_installers.iter().any(|new_installer| {
                new_installer.architecture == installer.architecture
                    && new_installer.url == installer.url
            }));
        }
    }

    #[test]
    fn shared_installer_preserves_scopes_through_manifest_generation() {
        const INSTALLER_URL: &str = "https://github.com/streamlink/windows-builds/releases/download/8.6.1-1/streamlink-8.6.1-1-py314-x86_64.exe";
        const INSTALLER_SHA_256: &str =
            "C3265138A124D2481AC4B7A82D6E129A8FF52B5487575CF6EADE3EB217BEBDCE";

        let previous_installers = [(Scope::User, "/CURRENTUSER"), (Scope::Machine, "/ALLUSERS")]
            .map(|(scope, custom)| Installer {
                architecture: Architecture::X64,
                r#type: Some(InstallerType::Nullsoft),
                scope: Some(scope),
                url: "https://example.com/streamlink-8.6.0.exe".parse().unwrap(),
                switches: Switches::builder().custom(custom.parse().unwrap()).build(),
                ..Installer::default()
            });
        // Analysis observes the executable's default scope without the manifest's switches.
        let new_installer = Installer {
            architecture: Architecture::X64,
            r#type: Some(InstallerType::Nullsoft),
            scope: Some(Scope::Machine),
            url: INSTALLER_URL.parse().unwrap(),
            sha_256: serde_saphyr::from_str(INSTALLER_SHA_256).unwrap(),
            ..Installer::default()
        };
        let mut manifest = InstallerManifest {
            installers: previous_installers.into(),
            ..InstallerManifest::default()
        };
        manifest.update_installers(&[new_installer], &HashMap::new());
        manifest.optimize();

        assert_eq!(manifest.scope, None);
        assert_eq!(
            to_yaml_string(&manifest.installers).unwrap(),
            indoc::indoc! {"
                - Architecture: x64
                  Scope: user
                  InstallerUrl: https://github.com/streamlink/windows-builds/releases/download/8.6.1-1/streamlink-8.6.1-1-py314-x86_64.exe
                  InstallerSha256: C3265138A124D2481AC4B7A82D6E129A8FF52B5487575CF6EADE3EB217BEBDCE
                  InstallerSwitches:
                    Custom: /CURRENTUSER
                - Architecture: x64
                  Scope: machine
                  InstallerUrl: https://github.com/streamlink/windows-builds/releases/download/8.6.1-1/streamlink-8.6.1-1-py314-x86_64.exe
                  InstallerSha256: C3265138A124D2481AC4B7A82D6E129A8FF52B5487575CF6EADE3EB217BEBDCE
                  InstallerSwitches:
                    Custom: /ALLUSERS
            "}
        );
    }

    #[rstest]
    #[case::shared_user(true, Some(Scope::User), Some(Scope::Machine), Some(Scope::User))]
    #[case::shared_machine(true, Some(Scope::Machine), Some(Scope::User), Some(Scope::Machine))]
    #[case::unknown_previous(true, None, Some(Scope::Machine), Some(Scope::Machine))]
    #[case::unknown_new(true, Some(Scope::User), None, Some(Scope::User))]
    #[case::separate_url(false, Some(Scope::User), Some(Scope::Machine), Some(Scope::Machine))]
    fn merges_scope_for_shared_and_separate_installers(
        #[case] duplicate_url: bool,
        #[case] previous_scope: Option<Scope>,
        #[case] detected_scope: Option<Scope>,
        #[case] expected_scope: Option<Scope>,
    ) {
        let previous_installer = Installer {
            scope: previous_scope,
            ..Installer::default()
        };
        let new_installer = Installer {
            scope: detected_scope,
            ..Installer::default()
        };
        assert_eq!(
            merge_installer(previous_installer, new_installer, duplicate_url).scope,
            expected_scope
        );
    }
}
