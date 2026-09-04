use std::{num::NonZeroUsize, sync::Arc};

use camino::Utf8PathBuf;
use color_eyre::eyre::{Result, WrapErr, eyre};
use futures_util::{StreamExt, TryStreamExt, stream};
use indexmap::IndexMap;
use jiff::civil::Date;
use napi::Either;
use winget_types::{
    Sha256String,
    installer::{Architecture, InstallerManifest, InstallerType},
    url::DecodedUrl,
};

use super::{
    error::InvalidArgument,
    types::{
        AnalyzedArtifact, AnalyzedInstaller, AppsAndFeaturesEntry, DetectedVersions,
        InstallerSource,
    },
};
use crate::{
    analysis::{
        Analyzer,
        installers::{font::FontAnalysis, zip::MatchedInstaller},
    },
    download::{DownloadedFile, Downloader},
    manifests::Url,
    traits::InstallerManifestExt,
};

#[derive(Clone)]
pub struct ArtifactAnalysis {
    pub url: DecodedUrl,
    pub sha256: Sha256String,
    pub release_date: Option<Date>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub font_version: Option<String>,
    pub installers: Vec<MatchedInstaller>,
    pub possible_installer_files: Vec<Utf8PathBuf>,
}

pub(super) struct ParsedInstallerSource {
    pub(super) url: Url,
    architecture: Option<Architecture>,
    nested_installer_matches: Vec<String>,
}

pub(super) fn parse_installer_inputs(
    inputs: Vec<Either<String, InstallerSource>>,
) -> Result<Vec<ParsedInstallerSource>> {
    if inputs.is_empty() {
        return Err(InvalidArgument("At least one installer is required".into()).into());
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
                            InvalidArgument(format!(
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

fn parse_installer_url(input: &str) -> Result<Url> {
    let url = input.trim();
    if url.is_empty() {
        return Err(InvalidArgument("Installer URLs must not be empty".into()).into());
    }

    Ok(url
        .parse()
        .map_err(|error| InvalidArgument(format!("Invalid installer URL {url:?}: {error}")))?)
}

pub(super) async fn analyze_sources(
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
    sources: Vec<ParsedInstallerSource>,
    font_version: bool,
    manifest: Option<&InstallerManifest>,
) -> Result<Vec<ArtifactAnalysis>> {
    let mut unique_urls = IndexMap::new();
    let parsed_sources = sources
        .into_iter()
        .map(|source| {
            let key = AnalysisKey {
                url: source.url.original_url().to_string(),
                nested_installer_matches: source.nested_installer_matches,
                installer_type: manifest.and_then(|manifest| {
                    manifest.installer_type_for_url(
                        source.url.inner(),
                        source.architecture.or(source.url.override_architecture()),
                    )
                }),
            };
            unique_urls
                .entry(key.clone())
                .or_insert((source.url, 0_usize))
                .1 += 1;
            (key, source.architecture)
        })
        .collect::<Vec<_>>();

    // Keep the original URL beside each future: downloads may resolve GitHub `latest` links or
    // fall back from decoded URLs, either of which changes the URL stored in the result.
    let mut analyzed_by_url = stream::iter(unique_urls)
        .map(|(source_key, (url, source_count))| {
            let downloader = Arc::clone(&downloader);
            async move {
                let mut files = downloader
                    .download([url])
                    .await
                    .wrap_err("Failed to download installer")?;
                let file = files
                    .pop()
                    .ok_or_else(|| eyre!("Downloader returned no file for {}", source_key.url))?;
                let (source_key, analysis) = tokio::task::spawn_blocking(move || {
                    let analysis = analyze_download(
                        file,
                        &source_key.nested_installer_matches,
                        font_version,
                        source_key.installer_type,
                    )?;
                    Ok::<_, color_eyre::Report>((source_key, analysis))
                })
                .await
                .wrap_err("Installer analysis task failed")??;
                Ok::<_, color_eyre::Report>((source_key, (analysis, source_count)))
            }
        })
        .buffer_unordered(concurrency.get())
        .try_collect::<std::collections::HashMap<_, _>>()
        .await?;

    parsed_sources
        .into_iter()
        .map(|(source_key, architecture)| {
            let mut analysis = match analyzed_by_url.entry(source_key) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if entry.get().1 == 1 {
                        entry.remove().0
                    } else {
                        let (analysis, remaining) = entry.get_mut();
                        *remaining -= 1;
                        analysis.clone()
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    return Err(eyre!("No analysis was returned for {}", entry.key().url));
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
    installer_type: Option<InstallerType>,
}

fn analyze_download(
    mut file: DownloadedFile,
    nested_installer_matches: &[String],
    font_version: bool,
    installer_type: Option<InstallerType>,
) -> Result<ArtifactAnalysis> {
    let architecture = file.architecture();
    let file_name = file.download.file_name().to_owned();
    let mut analyzer = Analyzer::with_installer_type(
        &mut file.file,
        &file_name,
        if font_version {
            FontAnalysis::Version
        } else {
            FontAnalysis::None
        },
        installer_type,
    )
    .wrap_err_with(|| format!("Failed to analyze {file_name}"))?;

    let mut installers = if let Some(zip) = &mut analyzer.zip
        && !nested_installer_matches.is_empty()
    {
        let matched = zip
            .analyze_matches_with_metadata(nested_installer_matches)
            .wrap_err_with(|| format!("Failed to analyze matching installers in {file_name}"))?;

        analyzer.file_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.file_version.as_deref()),
        )
        .map(str::to_owned)
        .or(analyzer.file_version);
        analyzer.product_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.product_version.as_deref()),
        )
        .map(str::to_owned)
        .or(analyzer.product_version);
        analyzer.font_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.font_version.as_deref()),
        )
        .map(str::to_owned)
        .or(analyzer.font_version);
        matched
    } else {
        analyzer
            .installers
            .drain(..)
            .map(|installer| MatchedInstaller {
                installer,
                file_version: analyzer.file_version.clone(),
                product_version: analyzer.product_version.clone(),
                font_version: analyzer.font_version.clone(),
            })
            .collect()
    };

    for analysis in &mut installers {
        let installer = &mut analysis.installer;
        if let Some(architecture) = architecture {
            installer.architecture = architecture;
        }
        installer.url = file.download.url().inner().clone();
        installer.sha_256 = file.sha_256.clone();
        installer.release_date = file.last_modified;
    }

    let possible_installer_files = analyzer
        .zip
        .take()
        .map(|zip| zip.possible_installer_files)
        .unwrap_or_default();

    Ok(ArtifactAnalysis {
        url: file.download.into_url().into_inner(),
        sha256: file.sha_256,
        release_date: file.last_modified,
        file_version: analyzer.file_version,
        product_version: analyzer.product_version,
        font_version: analyzer.font_version,
        installers,
        possible_installer_files,
    })
}

pub(super) fn first_non_empty<'a>(values: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    values.map(str::trim).find(|value| !value.is_empty())
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
                font: analysis.font_version,
            },
            installers: analysis
                .installers
                .into_iter()
                .map(AnalyzedInstaller::from)
                .collect(),
        }
    }
}

impl From<MatchedInstaller> for AnalyzedInstaller {
    fn from(analysis: MatchedInstaller) -> Self {
        let installer = analysis.installer;
        Self {
            versions: DetectedVersions {
                file: analysis.file_version,
                product: analysis.product_version,
                font: analysis.font_version,
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

    use super::{AnalysisKey, MatchedInstaller, parse_installer_url};
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
            installer_type: None,
        };
        let second = AnalysisKey {
            url,
            nested_installer_matches: vec!["second.exe".to_owned()],
            installer_type: None,
        };

        assert_ne!(first, second);
    }

    #[test]
    fn manifest_installer_type_is_part_of_the_analysis_cache_key() {
        let msix = AnalysisKey {
            url: "https://example.com/app.msix".to_owned(),
            nested_installer_matches: Vec::new(),
            installer_type: Some(winget_types::installer::InstallerType::Msix),
        };
        let zip = AnalysisKey {
            installer_type: Some(winget_types::installer::InstallerType::Zip),
            ..msix.clone()
        };
        assert_ne!(msix, zip);
    }

    #[test]
    fn installer_analysis_preserves_its_detected_versions() {
        let installer = AnalyzedInstaller::from(MatchedInstaller {
            installer: Installer::default(),
            file_version: Some("1.2.3.4".to_owned()),
            product_version: Some("1.2.3".to_owned()),
            font_version: Some("Version 1.234".to_owned()),
        });

        assert_eq!(installer.versions.file.as_deref(), Some("1.2.3.4"));
        assert_eq!(installer.versions.product.as_deref(), Some("1.2.3"));
        assert_eq!(installer.versions.font.as_deref(), Some("Version 1.234"));
    }
}
