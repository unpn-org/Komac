mod commit_title;
mod package_path;
pub mod pull_request;

use std::{env, fmt::Write, num::NonZeroU32};

use bon::builder;
pub use commit_title::CommitTitle;
use itertools::Itertools;
pub use package_path::PackagePath;
use rand::RngExt;
use uuid::Uuid;
use winget_types::{
    LanguageTag, Manifest, ManifestType, PackageIdentifier, PackageVersion, url::DecodedUrl,
};

use crate::update_state::UpdateState;

const YAML_EXTENSION: &str = ".yaml";
const LOCALE_PART: &str = ".locale.";
const INSTALLER_PART: &str = ".installer";

pub fn is_manifest_file<M: Manifest>(
    file_name: &str,
    package_identifier: &PackageIdentifier,
    default_locale: Option<&LanguageTag>,
) -> bool {
    let package_identifier = package_identifier.as_str();
    let identifier_len = package_identifier.len();
    let file_name_len = file_name.len();

    // All manifest file names start with the package identifier
    if !file_name.starts_with(package_identifier) {
        return false;
    }

    // All manifest files end with the YAML extension
    if !file_name.ends_with(YAML_EXTENSION) {
        return false;
    }

    match M::TYPE {
        ManifestType::Version => file_name_len == identifier_len + YAML_EXTENSION.len(),
        ManifestType::Installer => {
            file_name.get(identifier_len..file_name_len - YAML_EXTENSION.len())
                == Some(INSTALLER_PART)
        }
        ManifestType::DefaultLocale | ManifestType::Locale => {
            // Check if the file name after the identifier starts with `.locale.`
            if file_name.get(identifier_len..identifier_len + LOCALE_PART.len())
                != Some(LOCALE_PART)
            {
                return false;
            }

            let locale = file_name
                .get(identifier_len + LOCALE_PART.len()..file_name_len - YAML_EXTENSION.len());

            locale.is_some_and(|locale| {
                default_locale.is_some_and(|default_locale| match M::TYPE {
                    ManifestType::DefaultLocale => default_locale.to_string() == locale,
                    ManifestType::Locale => default_locale.to_string() != locale,
                    _ => false,
                })
            })
        }
    }
}

#[builder(finish_fn = build)]
pub fn pull_request_body(
    #[builder(default)] issue_resolves: &[NonZeroU32],
    alternative_text: Option<&str>,
    #[builder(default)] automated: bool,
    _created_with: Option<&str>,
    _created_with_url: Option<&DecodedUrl>,
) -> String {
    const EMOJIS: [&str; 10] = ["🌌", "🌠", "⭐", "✨", "🌟", "☄️", "🚀", "🛰️", "🌠", "🔭"];

    let mut body = String::new();
    if let Some(alternative_text) = alternative_text {
        let _ = writeln!(body, "### {alternative_text}");
    } else {
        let mut rng = rand::rng();
        let emoji = EMOJIS[rng.random_range(0..EMOJIS.len())];

        if automated {
            let _ = write!(body, "Automatically updated by {emoji} Anthelion.");
        } else {
            let _ = write!(body, "Created by {emoji} Anthelion.");
        }
    }

    if !issue_resolves.is_empty() {
        let _ = writeln!(body);
        for issue in issue_resolves.iter().sorted_unstable() {
            let _ = writeln!(body, "- Resolves #{issue}");
        }
    }

    if env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true") {
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push('\n');
        let _ = writeln!(body, "<details>");
        let _ = writeln!(body, "<summary>Debug</summary>");
        let _ = writeln!(body);

        if let (Ok(repository), Ok(run_id)) =
            (env::var("GITHUB_REPOSITORY"), env::var("GITHUB_RUN_ID"))
        {
            let server_url =
                env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".to_owned());
            let _ = writeln!(
                body,
                "Run URL: {server_url}/{repository}/actions/runs/{run_id}"
            );
        }
        let _ = writeln!(
            body,
            "Anthelion komac SHA: {}",
            option_env!("GITHUB_SHA").unwrap_or("N/A")
        );

        let _ = writeln!(body, "</details>");
    }

    body
}

pub fn branch_name(
    package_identifier: &PackageIdentifier,
    package_version: &PackageVersion,
) -> String {
    /// GitHub rejects branch names longer than 255 bytes. Considering `refs/heads/`, 244 bytes are
    /// left for the name.
    const MAX_BRANCH_NAME_LEN: usize = u8::MAX as usize - "refs/heads/".len();

    let mut uuid_buffer = Uuid::encode_buffer();
    let uuid = Uuid::new_v4().simple().encode_upper(&mut uuid_buffer);
    let mut branch_name = format!("{package_identifier}-{package_version}-{uuid}");
    if branch_name.len() > MAX_BRANCH_NAME_LEN {
        branch_name.truncate(MAX_BRANCH_NAME_LEN - uuid.len());
        branch_name.push_str(uuid);
    }
    branch_name
}

pub fn commit_title(
    package_identifier: &PackageIdentifier,
    package_version: &PackageVersion,
    update_state: UpdateState,
) -> String {
    format!("{update_state}: {package_identifier} version {package_version}")
}

#[cfg(test)]
mod tests {
    use winget_types::{
        DefaultLocaleManifest, InstallerManifest, LanguageTag, LocaleManifest, PackageIdentifier,
        VersionManifest, icu_locale::langid,
    };

    use super::{is_manifest_file, pull_request_body};

    #[test]
    fn pull_request_body_uses_explicit_attribution() {
        assert!(pull_request_body().build().starts_with("Created by "));
        assert!(
            pull_request_body()
                .automated(true)
                .build()
                .starts_with("Automatically updated by ")
        );
    }

    #[test]
    fn valid_installer_manifest_file() {
        assert!(is_manifest_file::<InstallerManifest>(
            "Package.Identifier.installer.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            None,
        ))
    }

    #[test]
    fn invalid_installer_manifest_file() {
        assert!(!is_manifest_file::<InstallerManifest>(
            "Package.Identifier.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            None,
        ))
    }

    #[test]
    fn valid_default_locale_manifest_file() {
        assert!(is_manifest_file::<DefaultLocaleManifest>(
            "Package.Identifier.locale.en-US.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            Some(&LanguageTag::new(langid!("en-US"))),
        ))
    }

    #[test]
    fn invalid_default_locale_manifest_file() {
        assert!(!is_manifest_file::<DefaultLocaleManifest>(
            "Package.Identifier.locale.en-US.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            Some(&LanguageTag::new(langid!("zh-CN"))),
        ))
    }

    #[test]
    fn valid_locale_manifest_file() {
        assert!(is_manifest_file::<LocaleManifest>(
            "Package.Identifier.locale.zh-CN.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            Some(&LanguageTag::new(langid!("en-US"))),
        ))
    }

    #[test]
    fn invalid_locale_manifest_file() {
        assert!(!is_manifest_file::<LocaleManifest>(
            "Package.Identifier.locale.en-US.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            Some(&LanguageTag::new(langid!("en-US"))),
        ))
    }

    #[test]
    fn valid_version_manifest_file() {
        assert!(is_manifest_file::<VersionManifest>(
            "Package.Identifier.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            None,
        ))
    }

    #[test]
    fn invalid_version_manifest_file() {
        assert!(!is_manifest_file::<VersionManifest>(
            "Package.Identifier.installer.yaml",
            &"Package.Identifier".parse::<PackageIdentifier>().unwrap(),
            None,
        ))
    }
}
