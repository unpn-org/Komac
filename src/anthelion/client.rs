use std::{num::NonZeroUsize, sync::Arc};

use color_eyre::eyre::WrapErr;
use napi::Either;
use napi_derive::napi;
use secrecy::SecretString;
use winget_types::{PackageIdentifier, PackageVersion};

use super::{
    analyze_installer::{analyze_sources, parse_installer_inputs},
    error::{InvalidArgument, to_napi_error},
    github_configuration,
    types::{
        AnalyzedArtifact, GitHubRelease, InstallerSource, KomacOptions, PullRequest,
        PullRequestQuery, UpdatePackageRequest, UpdatePackageResult,
    },
    update_version::update_package,
};
use crate::{
    download::Downloader,
    github::{client::GitHub, graphql::types::PullRequestState as GitHubPullRequestState},
};

struct GitHubToken(SecretString);

impl AsRef<SecretString> for GitHubToken {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

/// Reusable Komac client.
///
/// A client owns the HTTP connection pools used for GitHub requests and installer downloads.
/// Create one client per process and share it across operations.
#[napi]
pub struct Komac {
    github: Option<GitHub>,
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
}

#[napi]
impl Komac {
    /// Create a reusable client. If omitted, `githubToken` falls back to `GITHUB_TOKEN`.
    #[napi(constructor)]
    pub fn new(options: Option<KomacOptions>) -> napi::Result<Self> {
        let options = options.unwrap_or_default();
        let default_concurrency = NonZeroUsize::new(num_cpus::get()).unwrap_or(NonZeroUsize::MIN);
        let concurrency = options
            .download_concurrency
            .map(|value| {
                usize::try_from(value)
                    .ok()
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| {
                        InvalidArgument("downloadConcurrency must be greater than zero".into())
                    })
            })
            .transpose()?
            .unwrap_or(default_concurrency);

        let downloader = Downloader::new_with_concurrent_and_progress(concurrency, false)
            .map(Arc::new)
            .wrap_err("Failed to create installer downloader")
            .map_err(to_napi_error)?;
        let github_token = options
            .github_token
            .or_else(|| github_configuration::github_token().map(str::to_owned));
        let github = github_token
            .map(|token| {
                if token.trim().is_empty() {
                    return Err(InvalidArgument("githubToken must not be empty".into()).into());
                }
                let token = GitHubToken(SecretString::new(token.into_boxed_str()));
                GitHub::new(&token)
                    .wrap_err("Failed to create GitHub client")
                    .map_err(to_napi_error)
            })
            .transpose()?;

        Ok(Self {
            github,
            downloader,
            concurrency,
        })
    }

    /// Download and analyze one installer artifact.
    #[napi]
    pub async fn analyze_installer(
        &self,
        installer: Either<String, InstallerSource>,
    ) -> napi::Result<AnalyzedArtifact> {
        self.analyze_installers(vec![installer])
            .await?
            .pop()
            .ok_or_else(|| napi::Error::from_reason("Installer analysis returned no result"))
    }

    /// Download and analyze several installer artifacts concurrently.
    #[napi]
    pub async fn analyze_installers(
        &self,
        installers: Vec<Either<String, InstallerSource>>,
    ) -> napi::Result<Vec<AnalyzedArtifact>> {
        analyze_sources(
            Arc::clone(&self.downloader),
            self.concurrency,
            parse_installer_inputs(installers).map_err(to_napi_error)?,
            true,
            None,
        )
        .await
        .map(|analyses| analyses.into_iter().map(AnalyzedArtifact::from).collect())
        .map_err(to_napi_error)
    }

    /// Find an existing pull request for a package version.
    #[napi]
    pub async fn find_pull_request(
        &self,
        query: PullRequestQuery,
    ) -> napi::Result<Option<PullRequest>> {
        let package_identifier: PackageIdentifier = query
            .package_identifier
            .parse()
            .map_err(|error| InvalidArgument(format!("Invalid package identifier: {error}")))?;
        let package_version: PackageVersion = query
            .version
            .parse()
            .map_err(|error| InvalidArgument(format!("Invalid package version: {error}")))?;

        self.require_github()?
            .get_existing_pull_request(
                &package_identifier,
                &package_version,
                query.authored_by_current_user_only.unwrap_or_default(),
            )
            .await
            .wrap_err("Failed to find an existing pull request")
            .map_err(to_napi_error)
            .map(|pull_request| {
                pull_request.map(|pull_request| PullRequest {
                    url: pull_request.url.to_string(),
                    author: pull_request.author_login().cloned().unwrap_or_default(),
                    authored_by_current_user: pull_request.viewer_did_author,
                    state: (match pull_request.state {
                        GitHubPullRequestState::Open => "open",
                        GitHubPullRequestState::Closed => "closed",
                        GitHubPullRequestState::Merged => "merged",
                    })
                    .to_owned(),
                    created_at: pull_request.created_at.to_string(),
                })
            })
    }

    /// Fetch normalized notes from a GitHub release.
    #[napi]
    pub async fn get_github_release_notes(
        &self,
        release: GitHubRelease,
    ) -> napi::Result<Option<String>> {
        self.require_github()?
            .get_all_values()
            .owner(release.owner)
            .repo(release.repository)
            .tag_name(release.tag)
            .send()
            .await
            .wrap_err("Failed to fetch GitHub release notes")
            .map_err(to_napi_error)
            .map(|values| values.release_notes.map(|notes| notes.to_string()))
    }

    /// Generate manifests for an updated package and optionally submit them as a pull request.
    #[napi]
    pub async fn update_package(
        &self,
        request: UpdatePackageRequest,
    ) -> napi::Result<UpdatePackageResult> {
        update_package(
            self.require_github()?,
            Arc::clone(&self.downloader),
            self.concurrency,
            request,
        )
        .await
        .map_err(to_napi_error)
    }
}

impl Komac {
    fn require_github(&self) -> napi::Result<&GitHub> {
        self.github.as_ref().ok_or_else(|| {
            napi::Error::from_reason("This operation requires githubToken in the Komac constructor")
        })
    }
}
