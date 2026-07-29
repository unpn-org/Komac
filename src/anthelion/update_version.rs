use std::{
    collections::{BTreeSet, HashMap},
    mem,
    num::NonZeroUsize,
    sync::Arc,
};

use color_eyre::eyre::{Result, WrapErr, eyre};
use itertools::Itertools;
use tokio::try_join;
use winget_types::{PackageIdentifier, PackageVersion, locale::ReleaseNotes, url::ReleaseNotesUrl};

use super::{
    analyze_installer::{analyze_sources, first_non_empty, parse_installer_inputs},
    error::InvalidArgument,
    types::{
        CreatedPullRequest, GeneratedManifest, ReplacementSelection, UpdatePackageRequest,
        UpdatePackageResult, UpdatedPackage,
    },
};
use crate::{
    download::Downloader,
    github::{GITHUB_HOST, client::GitHub},
    traits::InstallerManifestExt,
};

enum VersionSelector {
    Explicit(Box<PackageVersion>),
    ProductVersion,
    FileVersion,
    DisplayVersion,
    FontVersion,
}

fn parse_version_selector(selection: &str) -> Result<VersionSelector> {
    let selection = selection.trim();
    if selection.is_empty() {
        return Err(InvalidArgument("version must not be empty".into()).into());
    }

    Ok(match selection {
        "display" => VersionSelector::DisplayVersion,
        "product" => VersionSelector::ProductVersion,
        "file" => VersionSelector::FileVersion,
        "fontVersion" => VersionSelector::FontVersion,
        value => VersionSelector::Explicit(Box::new(
            value
                .parse()
                .map_err(|error| InvalidArgument(format!("Invalid package version: {error}")))?,
        )),
    })
}

fn parse_replacement(replacement: Option<ReplacementSelection>) -> Result<Option<PackageVersion>> {
    replacement
        .map(|replacement| match replacement.target.as_str() {
            "latest" => {
                if replacement.value.is_some() {
                    return Err(InvalidArgument(
                        "replace.value may only be set when replace.target is version".into(),
                    )
                    .into());
                }
                "latest"
                    .parse()
                    .wrap_err("Failed to create latest-version selector")
            }
            "version" => {
                let value = replacement
                    .value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        InvalidArgument(
                            "replace.value is required when replace.target is version".into(),
                        )
                    })?;
                Ok(value.parse().map_err(|error| {
                    InvalidArgument(format!("Invalid replacement version: {error}"))
                })?)
            }
            target => Err(InvalidArgument(format!("Invalid replacement target {target:?}")).into()),
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
) -> Result<UpdatePackageResult> {
    let submit = match options.mode.as_str() {
        "generate" => false,
        "submit" => true,
        mode => {
            return Err(InvalidArgument(format!("Invalid update mode {mode:?}")).into());
        }
    };
    let package_identifier: PackageIdentifier = options
        .package_identifier
        .parse()
        .map_err(|e| InvalidArgument(format!("Invalid package identifier: {e}")))?;

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
        .map_err(|e| InvalidArgument(format!("Invalid release notes URL: {e}")))?;

    let release_notes: Option<ReleaseNotes> = options
        .release_notes
        .and_then(|notes| notes.text)
        .map(ReleaseNotes::new)
        .transpose()
        .map_err(|e| InvalidArgument(format!("Invalid release notes: {e}")))?;

    let replace = parse_replacement(options.replace)?;

    let package_kind = match options.package_kind.as_deref() {
        None | Some("auto") => None,
        Some("standard") => Some(false),
        Some("font") => Some(true),
        Some(kind) => {
            return Err(InvalidArgument(format!("Invalid package kind {kind:?}")).into());
        }
    };

    let (versions, font) = github
        .get_versions(&package_identifier, package_kind)
        .await
        .wrap_err("Failed to get versions")?;

    let latest_version = versions
        .last()
        .ok_or_else(|| eyre!("No versions found for package"))?;

    let mut manifests = github
        .get_manifests(&package_identifier, latest_version, font)
        .await
        .wrap_err("Failed to get manifests")?;

    let (mut github_values, mut download_results) = try_join!(
        async {
            if let Some(url) = github_url {
                github
                    .get_all_values_from_url(url)
                    .await
                    .transpose()
                    .wrap_err("Failed to get GitHub values")
            } else {
                Ok(None)
            }
        },
        analyze_sources(
            downloader,
            concurrency,
            installers,
            font && matches!(version_selector, VersionSelector::FontVersion),
            Some(&manifests.installer),
        ),
    )?;

    let installer_results = download_results
        .iter_mut()
        .flat_map(|analysis| mem::take(&mut analysis.installers))
        .map(|analysis| analysis.installer)
        .collect::<Vec<_>>();

    let product_version = first_non_empty(
        download_results
            .iter()
            .filter_map(|analysis| analysis.product_version.as_deref()),
    );
    let file_version = first_non_empty(
        download_results
            .iter()
            .filter_map(|analysis| analysis.file_version.as_deref()),
    );
    let font_version = first_non_empty(
        download_results
            .iter()
            .filter_map(|analysis| analysis.font_version.as_deref()),
    );
    let display_version = installer_results
        .iter()
        .flat_map(|installer| installer.apps_and_features_entries.iter())
        .filter_map(|entry| entry.display_version())
        .find(|value| !value.as_str().trim().is_empty());

    let package_version: PackageVersion = match version_selector {
        VersionSelector::Explicit(package_version) => *package_version,
        VersionSelector::ProductVersion => {
            parse_detected_version(product_version, "product", "ProductVersion")?
        }
        VersionSelector::FileVersion => {
            parse_detected_version(file_version, "file", "FileVersion")?
        }
        VersionSelector::DisplayVersion => parse_detected_version(
            display_version.map(|version| version.as_str()),
            "display",
            "DisplayVersion",
        )?,
        VersionSelector::FontVersion => {
            parse_detected_version(font_version, "fontVersion", "font version")?
        }
    };

    let replace_version = resolve_replace_version(
        replace.as_ref(),
        &versions,
        latest_version,
        &package_version,
    )
    .map_err(InvalidArgument)?;

    let possible_installer_files = download_results
        .into_iter()
        .map(|analysis| (analysis.url, analysis.possible_installer_files))
        .collect::<HashMap<_, _>>();

    manifests.installer.package_version = package_version.clone();
    manifests
        .installer
        .update_installers(&installer_results, &possible_installer_files);

    manifests.installer.locale = None;
    if manifests
        .installer
        .installers
        .iter()
        .flat_map(|installer| &installer.locale)
        .all_equal()
    {
        for installer in &mut manifests.installer.installers {
            installer.locale = None;
        }
    }

    manifests.update(&package_version, &mut github_values, None);

    manifests
        .installer
        .apps_and_features_entries
        .iter_mut()
        .chain(
            manifests
                .installer
                .installers
                .iter_mut()
                .flat_map(|installer| &mut installer.apps_and_features_entries),
        )
        .for_each(|entry| entry.deduplicate(&manifests.default_locale));

    if let Some(release_notes_url) = release_notes_url {
        manifests.default_locale.release_notes_url = Some(release_notes_url);
    }

    if let Some(release_notes) = release_notes {
        manifests.default_locale.release_notes = Some(release_notes);
    }

    // `optimize` sorts installers, so it must run after all installer mutations.
    manifests.installer.optimize();

    let changes = manifests.create(&package_identifier, &package_version, None, font);

    let generated_manifests = changes
        .iter()
        .map(|change| GeneratedManifest {
            path: change.path().to_owned(),
            yaml: change.manifest().to_owned(),
        })
        .collect();
    let pull_request = if submit {
        let pull_request = github
            .add_version()
            .identifier(&package_identifier)
            .version(&package_version)
            .versions(&versions)
            .changes(changes)
            .maybe_replace_version(replace_version)
            .issue_resolves(&[])
            .automated(true)
            .send()
            .await
            .wrap_err("Failed to create pull request")?;
        Some(CreatedPullRequest {
            url: pull_request.url().to_string(),
            diff_url: pull_request.diff_view_url().to_string(),
        })
    } else {
        None
    };

    Ok(UpdatePackageResult {
        package: UpdatedPackage {
            identifier: package_identifier.to_string(),
            version: package_version.to_string(),
        },
        manifests: generated_manifests,
        pull_request,
    })
}

fn parse_detected_version(
    value: Option<&str>,
    source: &str,
    field: &str,
) -> Result<PackageVersion> {
    let analysis = if source == "fontVersion" {
        "selected font"
    } else {
        "installer"
    };
    Ok(value
        .ok_or_else(|| {
            InvalidArgument(format!(
                "version.source is {source}, but {analysis} analysis found no {field}"
            ))
        })?
        .parse()
        .map_err(|error| InvalidArgument(format!("Invalid {field}: {error}")))?)
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
        assert!(matches!(
            parse_version_selector("fontVersion").unwrap(),
            VersionSelector::FontVersion
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
