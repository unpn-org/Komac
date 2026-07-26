use std::{num::NonZeroUsize, sync::Arc};

use camino::Utf8PathBuf;
use color_eyre::eyre::{Report, eyre};
use futures_util::{StreamExt, TryStreamExt, stream};
use indexmap::IndexMap;
use napi::Either;
use winget_types::{
    Sha256String,
    installer::{Architecture, Installer},
    url::DecodedUrl,
};

use super::error::{AnthelionError, AnthelionResult};
use super::types::{
    AnalyzedArtifact, AnalyzedInstaller, AppsAndFeaturesEntry, DetectedVersions, InstallerSource,
};
use crate::{
    analysis::Analyzer,
    download::{DownloadedFile, Downloader},
    manifests::Url,
};

#[derive(Clone)]
pub struct ArtifactAnalysis {
    pub url: DecodedUrl,
    pub sha256: Sha256String,
    pub release_date: Option<chrono::NaiveDate>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub installers: Vec<InstallerAnalysis>,
    pub possible_installer_files: Vec<Utf8PathBuf>,
}

#[derive(Clone)]
pub struct InstallerAnalysis {
    pub installer: Installer,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
}

pub(super) struct ParsedInstallerSource {
    pub(super) url: Url,
    architecture: Option<Architecture>,
    nested_installer_matches: Vec<String>,
}

pub(super) fn parse_installer_inputs(
    inputs: Vec<Either<String, InstallerSource>>,
) -> AnthelionResult<Vec<ParsedInstallerSource>> {
    if inputs.is_empty() {
        return Err(AnthelionError::invalid(
            "At least one installer is required",
        ));
    }

    inputs
        .into_iter()
        .map(|input| {
            let (url, architecture, nested_installer_matches) = match input {
                Either::A(url) => (url, None, None),
                Either::B(source) => (
                    source.url,
                    source.architecture,
                    source.nested_installer_matches,
                ),
            };
            Ok(ParsedInstallerSource {
                url: parse_installer_url(&url)?,
                architecture: architecture
                    .map(|architecture| {
                        architecture.parse().map_err(|_| {
                            AnthelionError::invalid(format!(
                                "Invalid installer architecture {architecture:?}"
                            ))
                        })
                    })
                    .transpose()?,
                nested_installer_matches: nested_installer_matches.unwrap_or_default(),
            })
        })
        .collect()
}

fn parse_installer_url(input: &str) -> AnthelionResult<Url> {
    let url = input.trim();
    if url.is_empty() {
        return Err(AnthelionError::invalid("Installer URLs must not be empty"));
    }

    url.parse()
        .map_err(|error| AnthelionError::invalid(format!("Invalid installer URL {url:?}: {error}")))
}

pub(super) async fn analyze_sources(
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
    sources: Vec<ParsedInstallerSource>,
) -> AnthelionResult<Vec<ArtifactAnalysis>> {
    let parsed_sources = sources
        .into_iter()
        .map(|source| {
            (
                AnalysisKey {
                    url: source.url.original_url().to_string(),
                    nested_installer_matches: source.nested_installer_matches,
                },
                source.url,
                source.architecture,
            )
        })
        .collect::<Vec<_>>();
    let mut unique_urls = IndexMap::<AnalysisKey, (_, usize)>::new();
    for (key, url, _) in &parsed_sources {
        match unique_urls.entry(key.clone()) {
            indexmap::map::Entry::Occupied(mut entry) => entry.get_mut().1 += 1,
            indexmap::map::Entry::Vacant(entry) => {
                entry.insert((url.clone(), 1));
            }
        }
    }

    // Keep the original URL beside each future: downloads may resolve GitHub `latest` links or
    // fall back from decoded URLs, either of which changes the URL stored in the result.
    let mut analyzed_by_url = stream::iter(unique_urls)
        .map(|(source_key, (url, source_count))| {
            let downloader = Arc::clone(&downloader);
            async move {
                let mut files = downloader.download([url]).await.map_err(|error| {
                    AnthelionError::failure(error.wrap_err("Failed to download installer"))
                })?;
                let file = files.pop().ok_or_else(|| {
                    AnthelionError::failure(eyre!(
                        "Downloader returned no file for {}",
                        source_key.url
                    ))
                })?;
                let (source_key, analysis) = tokio::task::spawn_blocking(move || {
                    let analysis = analyze_download(file, &source_key.nested_installer_matches)?;
                    Ok::<_, AnthelionError>((source_key, analysis))
                })
                .await
                .map_err(|error| {
                    AnthelionError::failure(
                        Report::from(error).wrap_err("Installer analysis task failed"),
                    )
                })??;
                Ok::<_, AnthelionError>((source_key, (analysis, source_count)))
            }
        })
        .buffer_unordered(concurrency.get())
        .try_collect::<std::collections::HashMap<_, _>>()
        .await?;

    parsed_sources
        .into_iter()
        .map(|(source_key, _source, architecture)| {
            let mut analysis = match analyzed_by_url.entry(source_key) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if entry.get().1 == 1 {
                        entry.remove().0
                    } else {
                        entry.get_mut().1 -= 1;
                        entry.get().0.clone()
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    return Err(AnthelionError::failure(eyre!(
                        "No analysis was returned for {}",
                        entry.key().url
                    )));
                }
            };
            if let Some(architecture) = architecture {
                for installer in &mut analysis.installers {
                    installer.installer.architecture = architecture;
                }
            }
            Ok(analysis)
        })
        .collect()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AnalysisKey {
    url: String,
    nested_installer_matches: Vec<String>,
}

fn analyze_download(
    mut file: DownloadedFile,
    nested_installer_matches: &[String],
) -> AnthelionResult<ArtifactAnalysis> {
    let mut analyzer = Analyzer::new(&mut file.file, &file.file_name).map_err(|error| {
        AnthelionError::failure(error.wrap_err(format!("Failed to analyze {}", file.file_name)))
    })?;

    let matched = if let Some(zip) = &mut analyzer.zip
        && !nested_installer_matches.is_empty()
    {
        let matched = zip
            .analyze_matches_with_metadata(nested_installer_matches)
            .map_err(|error| {
                AnthelionError::failure(error.wrap_err(format!(
                    "Failed to analyze matching installers in {}",
                    file.file_name
                )))
            })?;

        analyzer.file_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.file_version.clone()),
        )
        .or(analyzer.file_version);
        analyzer.product_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.product_version.clone()),
        )
        .or(analyzer.product_version);
        Some(matched)
    } else {
        None
    };

    let mut installers: Vec<InstallerAnalysis> = if let Some(matched) = matched {
        matched
            .into_iter()
            .map(|analysis| InstallerAnalysis {
                installer: analysis.installer,
                file_version: analysis.file_version,
                product_version: analysis.product_version,
            })
            .collect()
    } else {
        analyzer
            .installers
            .drain(..)
            .map(|installer| InstallerAnalysis {
                installer,
                file_version: analyzer.file_version.clone(),
                product_version: analyzer.product_version.clone(),
            })
            .collect()
    };

    let architecture = file
        .url
        .override_architecture()
        .or_else(|| winget_types::installer::Architecture::from_url(file.url.as_str()));
    for analysis in &mut installers {
        let installer = &mut analysis.installer;
        if let Some(architecture) = architecture {
            installer.architecture = architecture;
        }
        installer.url = file.url.inner().clone();
        installer.sha_256 = file.sha_256.clone();
        installer.release_date = file.last_modified;
    }

    let possible_installer_files = analyzer
        .zip
        .take()
        .map(|zip| zip.possible_installer_files)
        .unwrap_or_default();

    Ok(ArtifactAnalysis {
        url: file.url.into_inner(),
        sha256: file.sha_256,
        release_date: file.last_modified,
        file_version: analyzer.file_version,
        product_version: analyzer.product_version,
        installers,
        possible_installer_files,
    })
}

fn first_non_empty(values: impl Iterator<Item = String>) -> Option<String> {
    for mut value in values {
        let start = value.len() - value.trim_start().len();
        let end = value.trim_end().len();
        if start < end {
            value.truncate(end);
            value.drain(..start);
            return Some(value);
        }
    }
    None
}

impl From<ArtifactAnalysis> for AnalyzedArtifact {
    fn from(analysis: ArtifactAnalysis) -> Self {
        Self {
            url: analysis.url.to_string(),
            sha256: analysis.sha256.to_string(),
            release_date: analysis.release_date.map(|date| date.to_string()),
            versions: DetectedVersions {
                file: analysis.file_version,
                product: analysis.product_version,
            },
            installers: analysis
                .installers
                .into_iter()
                .map(AnalyzedInstaller::from)
                .collect(),
        }
    }
}

impl From<InstallerAnalysis> for AnalyzedInstaller {
    fn from(analysis: InstallerAnalysis) -> Self {
        let installer = analysis.installer;
        Self {
            versions: DetectedVersions {
                file: analysis.file_version,
                product: analysis.product_version,
            },
            locale: installer.locale.map(|locale| locale.to_string()),
            architecture: installer.architecture.to_string(),
            installer_type: installer
                .r#type
                .map(|installer_type| installer_type.to_string()),
            nested_installer_type: installer
                .nested_installer_type
                .map(|installer_type| installer_type.to_string()),
            nested_installer_files: installer
                .nested_installer_files
                .into_iter()
                .map(|file| file.relative_file_path.to_string())
                .collect(),
            apps_and_features_entries: installer
                .apps_and_features_entries
                .into_iter()
                .map(|entry| AppsAndFeaturesEntry {
                    display_name: entry.display_name().map(str::to_owned),
                    publisher: entry.publisher().map(str::to_owned),
                    display_version: entry.display_version().map(ToString::to_string),
                    product_code: entry.product_code().map(str::to_owned),
                    upgrade_code: entry.upgrade_code().map(str::to_owned),
                    installer_type: entry
                        .installer_type()
                        .map(|installer_type| installer_type.to_string()),
                })
                .collect(),
            scope: installer.scope.map(|scope| scope.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use winget_types::installer::Installer;

    use super::{AnalysisKey, InstallerAnalysis, parse_installer_url};
    use crate::anthelion::types::AnalyzedInstaller;

    #[test]
    fn keeps_architecture_out_of_the_url() {
        let url = parse_installer_url("https://example.com/app.exe").unwrap();

        assert_eq!(url.as_str(), "https://example.com/app.exe");
        assert_eq!(url.override_architecture(), None);
    }

    #[test]
    fn nested_match_rules_are_part_of_the_analysis_cache_key() {
        let url = "https://example.com/archive.zip".to_owned();
        let first = AnalysisKey {
            url: url.clone(),
            nested_installer_matches: vec!["first.exe".to_owned()],
        };
        let second = AnalysisKey {
            url,
            nested_installer_matches: vec!["second.exe".to_owned()],
        };

        assert_ne!(first, second);
    }

    #[test]
    fn installer_analysis_preserves_its_detected_versions() {
        let installer = AnalyzedInstaller::from(InstallerAnalysis {
            installer: Installer::default(),
            file_version: Some("1.2.3.4".to_owned()),
            product_version: Some("1.2.3".to_owned()),
        });

        assert_eq!(installer.versions.file.as_deref(), Some("1.2.3.4"));
        assert_eq!(installer.versions.product.as_deref(), Some("1.2.3"));
    }
}
