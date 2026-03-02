use std::{
    collections::{BTreeSet, HashMap},
    mem,
    num::NonZeroUsize,
    sync::Arc,
};

use camino::Utf8PathBuf;
use color_eyre::eyre::{Report, eyre};
use futures_util::TryFutureExt;
use itertools::Itertools;
use tokio::try_join;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{InstallerType, NestedInstallerFiles},
    locale::ReleaseNotes,
    url::ReleaseNotesUrl,
};

use super::{
    analyze_installer::{analyze_sources, parse_installer_inputs},
    error::{AnthelionError, AnthelionResult},
    types::{
        CreatedPullRequest, GeneratedManifest, ReplacementSelection, UpdatePackageRequest,
        UpdatePackageResult, UpdatedPackage,
    },
};
use crate::{
    download::Downloader,
    github::{GITHUB_HOST, client::GitHub},
    match_installers::{match_installers, unmatched_installers},
    traits::path::{LowercaseExtension, NormalizePath},
};

enum VersionSelector {
    Explicit(Box<PackageVersion>),
    ProductVersion,
    FileVersion,
    DisplayVersion,
}

fn parse_version_selector(selection: &str) -> AnthelionResult<VersionSelector> {
    let selection = selection.trim();
    if selection.is_empty() {
        return Err(AnthelionError::invalid("version must not be empty"));
    }

    Ok(match selection {
        "display" => VersionSelector::DisplayVersion,
        "product" => VersionSelector::ProductVersion,
        "file" => VersionSelector::FileVersion,
        value => VersionSelector::Explicit(Box::new(value.parse().map_err(|error| {
            AnthelionError::invalid(format!("Invalid package version: {error}"))
        })?)),
    })
}

fn parse_replacement(
    replacement: Option<ReplacementSelection>,
) -> AnthelionResult<Option<PackageVersion>> {
    replacement
        .map(|replacement| match replacement.target.as_str() {
            "latest" => {
                if replacement.value.is_some() {
                    return Err(AnthelionError::invalid(
                        "replace.value may only be set when replace.target is version",
                    ));
                }
                "latest".parse().map_err(|error| {
                    AnthelionError::failure(
                        Report::from(error).wrap_err("Failed to create latest-version selector"),
                    )
                })
            }
            "version" => {
                let value = replacement
                    .value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        AnthelionError::invalid(
                            "replace.value is required when replace.target is version",
                        )
                    })?;
                value.parse().map_err(|error| {
                    AnthelionError::invalid(format!("Invalid replacement version: {error}"))
                })
            }
            target => Err(AnthelionError::invalid(format!(
                "Invalid replacement target {target:?}"
            ))),
        })
        .transpose()
}

/// Update an existing package version in winget-pkgs.
///
/// # Errors
///
/// Returns `InvalidArg` when provided arguments are invalid (identifier, URLs, versions, or selectors).
/// Returns `GenericFailure` when downloading installers, analyzing content, loading manifests,
/// or creating the pull request fails.
pub async fn update_package(
    github: &GitHub,
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
    options: UpdatePackageRequest,
) -> AnthelionResult<UpdatePackageResult> {
    let submit = match options.mode.as_str() {
        "generate" => false,
        "submit" => true,
        mode => {
            return Err(AnthelionError::invalid(format!(
                "Invalid update mode {mode:?}"
            )));
        }
    };
    let package_identifier: PackageIdentifier = options
        .package_identifier
        .parse()
        .map_err(|e| AnthelionError::invalid(format!("Invalid package identifier: {e}")))?;

    let version_selector = parse_version_selector(&options.version)?;
    let installers = parse_installer_inputs(options.installers)?;
    let github_url = installers
        .iter()
        .find(|source| source.url.host_str() == Some(GITHUB_HOST))
        .map(|source| source.url.clone().into_inner());

    let release_notes_url: Option<ReleaseNotesUrl> = options
        .release_notes
        .as_ref()
        .and_then(|notes| notes.url.as_ref())
        .map(|url| url.parse())
        .transpose()
        .map_err(|e| AnthelionError::invalid(format!("Invalid release notes URL: {e}")))?;

    let release_notes: Option<ReleaseNotes> = options
        .release_notes
        .and_then(|notes| notes.text)
        .map(ReleaseNotes::new)
        .transpose()
        .map_err(|e| AnthelionError::invalid(format!("Invalid release notes: {e}")))?;

    let replace = parse_replacement(options.replace)?;

    match options.package_kind.as_deref() {
        None | Some("auto" | "standard") => {}
        Some("font") => {
            return Err(AnthelionError::invalid(
                "Font packages are not supported by this build",
            ));
        }
        Some(kind) => {
            return Err(AnthelionError::invalid(format!(
                "Invalid package kind {kind:?}"
            )));
        }
    }

    let versions = github
        .get_versions(&package_identifier)
        .await
        .map_err(|e| AnthelionError::failure(Report::from(e).wrap_err("Failed to get versions")))?;

    let latest_version = versions
        .last()
        .ok_or_else(|| AnthelionError::failure(eyre!("No versions found for package")))?;

    let (mut manifests, mut github_values, mut download_results) = try_join!(
        github
            .get_manifests(&package_identifier, latest_version)
            .map_err(|e| AnthelionError::failure(
                Report::from(e).wrap_err("Failed to get manifests")
            )),
        async {
            if let Some(url) = github_url {
                github
                    .get_all_values_from_url(url)
                    .await
                    .transpose()
                    .map_err(|e| {
                        AnthelionError::failure(
                            Report::from(e).wrap_err("Failed to get GitHub values"),
                        )
                    })
            } else {
                Ok(None)
            }
        },
        analyze_sources(downloader, concurrency, installers),
    )?;

    let installer_results = download_results
        .iter_mut()
        .flat_map(|analysis| mem::take(&mut analysis.installers))
        .map(|analysis| analysis.installer)
        .collect::<Vec<_>>();

    let product_version = download_results
        .iter()
        .filter_map(|analysis| analysis.product_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let file_version = download_results
        .iter()
        .filter_map(|analysis| analysis.file_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let display_version = installer_results
        .iter()
        .flat_map(|installer| installer.apps_and_features_entries.iter())
        .filter_map(|entry| entry.display_version())
        .find(|value| !value.as_str().trim().is_empty());

    let package_version: PackageVersion = match version_selector {
        VersionSelector::Explicit(package_version) => *package_version,
        VersionSelector::ProductVersion => product_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is product, but installer analysis found no ProductVersion",
                )
            })?
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid ProductVersion: {e}")))?,
        VersionSelector::FileVersion => file_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is file, but installer analysis found no FileVersion",
                )
            })?
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid FileVersion: {e}")))?,
        VersionSelector::DisplayVersion => display_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is display, but installer analysis found no DisplayVersion",
                )
            })?
            .as_str()
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid DisplayVersion: {e}")))?,
    };

    let replace_version = resolve_replace_version(
        replace.as_ref(),
        &versions,
        latest_version,
        &package_version,
    )
    .map_err(AnthelionError::invalid)?;

    let possible_installer_files = download_results
        .into_iter()
        .map(|analysis| (analysis.url, analysis.possible_installer_files))
        .collect::<HashMap<_, _>>();

    let previous_installers = mem::take(&mut manifests.installer.installers)
        .into_iter()
        .map(|mut installer| {
            if manifests.installer.r#type.is_some() {
                installer.r#type = manifests.installer.r#type;
            }
            if manifests.installer.nested_installer_type.is_some() {
                installer.nested_installer_type = manifests.installer.nested_installer_type;
            }
            if manifests.installer.scope.is_some() {
                installer.scope = manifests.installer.scope;
            }
            installer
        })
        .collect::<Vec<_>>();

    let url_counts = previous_installers
        .iter()
        .map(|installer| installer.url.clone())
        .counts();

    let matched_installers = match_installers(previous_installers, &installer_results);
    let unmatched_installers = unmatched_installers(&matched_installers, &installer_results);
    let mut installers = matched_installers
        .into_iter()
        .map(|(mut previous_installer, new_installer)| {
            let possible_installer_files = possible_installer_files
                .get(&new_installer.url)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let installer_type = match previous_installer.r#type {
                Some(InstallerType::Portable) => previous_installer.r#type,
                _ => match new_installer.r#type {
                    Some(InstallerType::Portable) => previous_installer.r#type,
                    _ => new_installer.r#type,
                },
            };

            let previous_nested_files = mem::take(&mut previous_installer.nested_installer_files);
            let duplicate_url = url_counts
                .get(&previous_installer.url)
                .is_some_and(|count| *count > 1);
            let previous_architecture = previous_installer.architecture;

            let mut installer = new_installer.merge_with(previous_installer);
            installer.r#type = installer_type;

            let nested_files_to_fix = if !previous_nested_files.is_empty() {
                Some(previous_nested_files)
            } else if !manifests.installer.nested_installer_files.is_empty() {
                Some(manifests.installer.nested_installer_files.clone())
            } else if !installer.nested_installer_files.is_empty() {
                Some(mem::take(&mut installer.nested_installer_files))
            } else {
                None
            };

            if let Some(nested_files) = nested_files_to_fix {
                installer.nested_installer_files =
                    fix_relative_paths(nested_files, possible_installer_files);
            }

            if duplicate_url {
                installer.architecture = previous_architecture;
            }
            installer
        })
        .collect::<Vec<_>>();

    installers.extend(unmatched_installers);

    manifests.installer.package_version = package_version.clone();
    manifests.installer.installers = installers;
    manifests.installer.optimize();

    manifests.installer.locale = None;
    manifests
        .installer
        .installers
        .iter()
        .flat_map(|installer| &installer.locale)
        .all_equal()
        .then(|| &mut manifests.installer.installers)
        .into_iter()
        .flatten()
        .for_each(|installer| installer.locale = None);

    manifests.update(&package_version, &mut github_values, None);

    manifests
        .installer
        .apps_and_features_entries
        .iter_mut()
        .for_each(|entry| entry.deduplicate(&manifests.default_locale));

    manifests
        .installer
        .installers
        .iter_mut()
        .flat_map(|installer| &mut installer.apps_and_features_entries)
        .for_each(|entry| entry.deduplicate(&manifests.default_locale));

    if let Some(release_notes_url) = release_notes_url {
        manifests.default_locale.release_notes_url = Some(release_notes_url);
    }

    if let Some(release_notes) = release_notes {
        manifests.default_locale.release_notes = Some(release_notes);
    }

    let changes = manifests.create(&package_identifier, &package_version, None);

    if !submit {
        return Ok(UpdatePackageResult {
            package: UpdatedPackage {
                identifier: package_identifier.to_string(),
                version: package_version.to_string(),
            },
            manifests: changes
                .iter()
                .map(|change| GeneratedManifest {
                    path: change.path().to_owned(),
                    yaml: change.manifest().to_owned(),
                })
                .collect(),
            pull_request: None,
        });
    }

    let pull_request_url = github
        .add_version()
        .identifier(&package_identifier)
        .version(&package_version)
        .versions(&versions)
        .changes(changes.clone())
        .maybe_replace_version(replace_version)
        .issue_resolves(&[])
        .automated(true)
        .send()
        .await
        .map_err(|e| {
            AnthelionError::failure(Report::from(e).wrap_err("Failed to create pull request"))
        })?;

    Ok(UpdatePackageResult {
        package: UpdatedPackage {
            identifier: package_identifier.to_string(),
            version: package_version.to_string(),
        },
        manifests: changes
            .iter()
            .map(|change| GeneratedManifest {
                path: change.path().to_owned(),
                yaml: change.manifest().to_owned(),
            })
            .collect(),
        pull_request: Some(CreatedPullRequest {
            url: pull_request_url.url().to_string(),
            diff_url: pull_request_url.diff_view_url().to_string(),
        }),
    })
}

fn resolve_replace_version<'a>(
    replace: Option<&'a PackageVersion>,
    versions: &'a BTreeSet<PackageVersion>,
    latest_version: &'a PackageVersion,
    package_version: &PackageVersion,
) -> Result<Option<&'a PackageVersion>, String> {
    let replace_version = replace
        .map(|version| {
            if version.is_latest() {
                latest_version
            } else {
                version
            }
        })
        .filter(|&version| version.as_str() != package_version.as_str());

    if let Some(version) = replace_version
        && !versions.contains(version)
    {
        if let Some(closest) = version.closest(versions) {
            return Err(format!(
                "Replacement version {version} does not exist. The closest version is {closest}"
            ));
        }
        return Err(format!("Replacement version {version} does not exist"));
    }

    Ok(replace_version)
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
            if possible_installer_files.contains(&nested_installer_file.relative_file_path)
                || possible_installer_files
                    .contains(&nested_installer_file.relative_file_path.normalize())
            {
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
    use super::{VersionSelector, parse_replacement, parse_version_selector};
    use crate::anthelion::types::ReplacementSelection;

    #[test]
    fn version_selection_requires_only_the_relevant_value() {
        assert!(matches!(
            parse_version_selector("1.2.3").unwrap(),
            VersionSelector::Explicit(_)
        ));
    }

    #[test]
    fn latest_replacement_has_no_magic_string_in_the_public_api() {
        let replacement = parse_replacement(Some(ReplacementSelection {
            target: "latest".to_owned(),
            value: None,
        }))
        .unwrap()
        .unwrap();

        assert!(replacement.is_latest());
    }
}
