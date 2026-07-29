use napi::Either;
use napi_derive::napi;

/// Configuration shared by every operation performed by a `Komac` client.
#[napi(object)]
pub struct KomacOptions {
    /// GitHub token used by repository operations. Defaults to `GITHUB_TOKEN`.
    /// Installer analysis does not require a token.
    pub github_token: Option<String>,
    /// Maximum number of installers downloaded or analyzed concurrently.
    /// Defaults to the number of available logical CPUs.
    pub download_concurrency: Option<u32>,
}

/// A downloadable installer artifact.
#[napi(object)]
#[derive(Clone)]
pub struct InstallerSource {
    /// Installer URL without an encoded architecture suffix.
    pub url: String,
    /// Override architecture detection for this artifact.
    #[napi(ts_type = "'x86' | 'x64' | 'arm' | 'arm64' | 'neutral'")]
    pub architecture: Option<String>,
    /// ZIP entry patterns to analyze instead of automatic nested-installer selection.
    pub nested_installer_matches: Option<Vec<String>>,
}

/// Analysis of one downloaded artifact.
#[napi(object)]
pub struct AnalyzedArtifact {
    /// Final installer URL used by the downloader.
    pub url: String,
    /// SHA-256 digest of the downloaded bytes.
    pub sha256: String,
    /// HTTP last-modified date, when supplied by the server.
    pub release_date: Option<String>,
    /// Version metadata detected in the artifact.
    pub versions: DetectedVersions,
    /// Installers represented by this artifact, including selected nested installers.
    pub installers: Vec<AnalyzedInstaller>,
}

/// Version metadata detected while inspecting an installer.
#[napi(object)]
pub struct DetectedVersions {
    /// PE `FileVersion`, if present.
    pub file: Option<String>,
    /// PE `ProductVersion`, if present.
    pub product: Option<String>,
    /// OpenType name ID 5, normalized for package-version use, if present.
    pub font: Option<String>,
}

/// Installer information detected during analysis.
#[napi(object)]
pub struct AnalyzedInstaller {
    /// Version metadata detected from this installer.
    pub versions: DetectedVersions,
    /// Installer locale, if present.
    pub locale: Option<String>,
    /// Installer architecture.
    #[napi(ts_type = "'x86' | 'x64' | 'arm' | 'arm64' | 'neutral'")]
    pub architecture: String,
    /// Installer type, if detected.
    pub installer_type: Option<String>,
    /// Nested installer type, if present.
    pub nested_installer_type: Option<String>,
    /// Relative paths of nested installer files within an archive.
    pub nested_installer_files: Vec<String>,
    /// Apps and Features / ARP entries detected for this installer.
    pub apps_and_features_entries: Vec<AppsAndFeaturesEntry>,
    /// Install scope, if present.
    pub scope: Option<String>,
}

/// Apps and Features / ARP metadata detected during analysis.
#[napi(object)]
pub struct AppsAndFeaturesEntry {
    pub display_name: Option<String>,
    pub publisher: Option<String>,
    pub display_version: Option<String>,
    pub product_code: Option<String>,
    pub upgrade_code: Option<String>,
    pub installer_type: Option<String>,
}

/// Query for an existing WinGet pull request.
#[napi(object)]
pub struct PullRequestQuery {
    pub package_identifier: String,
    pub version: String,
    /// Restrict results to pull requests authored by the authenticated user.
    pub authored_by_current_user_only: Option<bool>,
}

/// Existing pull request metadata.
#[napi(object)]
pub struct PullRequest {
    pub url: String,
    pub author: String,
    pub authored_by_current_user: bool,
    #[napi(ts_type = "'open' | 'closed' | 'merged'")]
    pub state: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

/// Identifies a GitHub release.
#[napi(object)]
pub struct GitHubRelease {
    pub owner: String,
    pub repository: String,
    pub tag: String,
}

/// Update an existing package using newly published installers.
#[napi(object)]
pub struct UpdatePackageRequest {
    /// Package identifier, for example `Microsoft.VisualStudioCode`.
    pub package_identifier: String,
    /// Explicit package version, or `display`, `product`, `file`, or `fontVersion` to use detected metadata.
    pub version: String,
    /// New installer artifacts.
    pub installers: Vec<Either<String, InstallerSource>>,
    /// Release notes fields for the default locale manifest.
    pub release_notes: Option<ReleaseNotesInput>,
    /// Existing version to remove in the same pull request.
    #[napi(ts_type = "{ target: 'latest' } | { target: 'version'; value: string }")]
    pub replace: Option<ReplacementSelection>,
    /// Package layout. Defaults to `auto`, which probes standard manifests before fonts.
    #[napi(ts_type = "'auto' | 'standard' | 'font'")]
    pub package_kind: Option<String>,
    /// Generate manifests locally or submit them as a pull request.
    #[napi(ts_type = "'generate' | 'submit'")]
    pub mode: String,
}

/// Existing package version to replace.
#[napi(object)]
pub struct ReplacementSelection {
    #[napi(ts_type = "'latest' | 'version'")]
    pub target: String,
    /// Required only when `target` is `version`.
    pub value: Option<String>,
}

/// Release notes fields to apply to the default locale manifest.
#[napi(object)]
pub struct ReleaseNotesInput {
    pub text: Option<String>,
    pub url: Option<String>,
}

/// Result of generating or submitting a package update.
#[napi(object)]
pub struct UpdatePackageResult {
    pub package: UpdatedPackage,
    pub manifests: Vec<GeneratedManifest>,
    /// Present only when `mode` was `submit` and pull-request creation succeeded.
    pub pull_request: Option<CreatedPullRequest>,
}

/// Package version created by an update.
#[napi(object)]
pub struct UpdatedPackage {
    pub identifier: String,
    pub version: String,
}

/// Generated manifest file.
#[napi(object)]
pub struct GeneratedManifest {
    /// File path within the package repository.
    pub path: String,
    /// YAML manifest content.
    pub yaml: String,
}

/// Newly created pull request links.
#[napi(object)]
pub struct CreatedPullRequest {
    pub url: String,
    pub diff_url: String,
}
