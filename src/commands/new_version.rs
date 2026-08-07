use std::{
    collections::BTreeSet,
    mem,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
};

use anstream::println;
use clap::Parser;
use color_eyre::eyre::{Result, bail, eyre};
use indicatif::ProgressBar;
use inquire::CustomType;
use itertools::Itertools;
use ordinal::Ordinal;
use owo_colors::OwoColorize;
use secrecy::SecretString;
use serde::Deserialize;
use winget_types::{
    LanguageTag, PackageIdentifier, PackageVersion, VersionManifest,
    installer::{
        Command, FileExtension, InstallModes, InstallerManifest, InstallerSuccessCode,
        InstallerType, Protocol, Switches, UpgradeBehavior,
        switches::{CustomSwitch, SilentSwitch, SilentWithProgressSwitch},
    },
    locale::{
        Agreement, Author, Copyright, DefaultLocaleManifest, Description, Documentation, Icon,
        InstallationNotes, License, Moniker, PackageName, Publisher, ReleaseNotes,
        ShortDescription, Tag,
    },
    url::{
        CopyrightUrl, DecodedUrl, LicenseUrl, PackageUrl, PublisherSupportUrl, PublisherUrl,
        ReleaseNotesUrl,
    },
};

use crate::{
    commands::utils::{SPINNER_TICK_RATE, SubmitOption, check_package_type},
    download::Downloader,
    github::{
        GITHUB_HOST,
        client::GitHub,
        utils::{PackagePath, pull_request::Change},
    },
    manifests::{Manifests, Url, print_changes},
    prompts::{
        check_prompt, handle_inquire_error,
        list::list_prompt,
        radio_prompt,
        text::{TextPrompt, confirm_prompt, optional_prompt, required_prompt},
    },
    token::TokenManager,
};

/// Create a new package from scratch
#[expect(clippy::struct_excessive_bools, reason = "CLI flags")]
#[derive(Parser)]
pub struct NewVersion {
    /// The package's unique identifier
    #[arg(value_name = "PACKAGE_IDENTIFIER")]
    identifier: Option<PackageIdentifier>,

    /// The package's version
    #[arg(short = 'v', long = "version")]
    version: Option<PackageVersion>,

    /// The list of package installers
    #[arg(short, long, num_args = 1.., value_hint = clap::ValueHint::Url)]
    urls: Vec<Url>,

    /// Run without prompting, using package data from a JSON object
    #[arg(long, value_name = "JSON")]
    non_interactive: Option<String>,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// List of issues that adding this package or version would resolve
    #[arg(long)]
    resolves: Vec<NonZeroU32>,

    /// Automatically submit a pull request
    #[arg(short, long)]
    submit: bool,

    /// Name of external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH")]
    created_with: Option<String>,

    /// URL to external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH_URL", value_hint = clap::ValueHint::Url)]
    created_with_url: Option<DecodedUrl>,

    /// Directory to output the manifests to
    #[arg(short, long, env = "OUTPUT_DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    output: Option<PathBuf>,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Run without submitting
    #[arg(long, env = "DRY_RUN")]
    dry_run: bool,

    /// Skip checking for existing pull requests
    #[arg(long, env)]
    skip_pr_check: bool,

    /// Look for the package under fonts instead of probing manifests first
    #[arg(long)]
    font: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN", hide_env_values = true)]
    token: Option<SecretString>,
}

impl NewVersion {
    pub async fn run(mut self) -> Result<()> {
        let mut input = self
            .non_interactive
            .take()
            .map(|json| serde_json::from_str::<NonInteractiveInput>(&json))
            .transpose()?;
        let non_interactive = input.is_some();
        let dry_run = self.dry_run || (non_interactive && !self.submit);

        if non_interactive && self.token.is_none() {
            bail!("Non-interactive mode requires --token or GITHUB_TOKEN");
        }

        let token_manager = TokenManager::handle(self.token).await?;
        let github = GitHub::new(token_manager)?;

        let identifier =
            resolve_required(self.identifier, None::<&str>, non_interactive, "identifier")?;

        let package = github
            .get_package(&identifier, self.font.then_some(true))
            .await?;

        if let Some(latest_version) = package.latest_version() {
            println!("Latest version of {identifier}: {latest_version}");
        }

        let version = resolve_required(self.version, None::<&str>, non_interactive, "version")?;

        let mut package = package.into_versioned(&version, &github).await?;
        if !self.skip_pr_check && !dry_run && !package.prompt_existing_pr()? {
            return Ok(());
        }

        let mut urls = mem::take(&mut self.urls);
        if urls.is_empty() {
            if non_interactive {
                bail!("Non-interactive mode requires at least one --urls value");
            }
            while urls.len() < 1024 {
                let message = format!("{} Installer URL", Ordinal(urls.len() + 1));
                let url_prompt =
                    CustomType::new(&message).with_error_message("Please enter a valid URL");
                let installer_url = if urls.len() + 1 == 1 {
                    Some(url_prompt.prompt().map_err(handle_inquire_error)?)
                } else {
                    url_prompt
                        .with_help_message("Press ESC if you do not have any more URLs")
                        .prompt_skippable()
                        .map_err(handle_inquire_error)?
                };
                if let Some(url) = installer_url {
                    urls.push(url);
                } else {
                    break;
                }
            }
        }

        let github_values = tokio::spawn({
            let github = github.clone();
            let github_url = urls
                .iter()
                .find(|url| url.host_str() == Some(GITHUB_HOST))
                .cloned();
            async move {
                github_url
                    .map(|url| github.get_all_values_from_url(url.into_inner()))
                    .unwrap_or_default()
                    .await
            }
        });

        let downloader = Downloader::new_with_concurrent(self.concurrent_downloads)?;
        let mut files = downloader.download(urls.iter().cloned()).await?;
        let mut download_results = files.analyze().await?;

        let mut installers = Vec::new();
        for analyzer in &mut download_results.values_mut() {
            let mut silent = None;
            let mut silent_with_progress = None;
            let mut custom = None;
            if !non_interactive
                && analyzer
                    .installers
                    .iter()
                    .any(|installer| installer.r#type == Some(InstallerType::Exe))
            {
                if confirm_prompt(&format!("Is {} a portable exe?", analyzer.file_name))? {
                    for installer in &mut analyzer.installers {
                        installer.r#type = Some(InstallerType::Portable);
                    }
                }
                silent = Some(required_prompt::<SilentSwitch, &str>(None, None)?);
                silent_with_progress = Some(required_prompt::<SilentWithProgressSwitch, &str>(
                    None, None,
                )?);
            }
            if !non_interactive
                && analyzer
                    .installers
                    .iter()
                    .any(|installer| installer.r#type == Some(InstallerType::Portable))
            {
                custom = optional_prompt::<CustomSwitch, &str>(None, None)?;
            }
            if let Some(zip) = &mut analyzer.zip {
                if non_interactive {
                    zip.select_all()?;
                } else {
                    zip.prompt()?;
                }
                for (installer, zip_installer) in
                    analyzer.installers.iter_mut().zip(zip.installers.iter())
                {
                    installer.nested_installer_type = zip_installer.nested_installer_type;
                    installer
                        .nested_installer_files
                        .clone_from(&zip_installer.nested_installer_files);
                }
            }
            let switches = Switches::builder()
                .maybe_silent(silent)
                .maybe_silent_with_progress(silent_with_progress)
                .maybe_custom(custom)
                .build();
            let mut analyzer_installers = mem::take(&mut analyzer.installers);
            if !switches.is_empty() {
                for installer in &mut analyzer_installers {
                    installer.switches = switches.clone();
                }
            }
            installers.extend(analyzer_installers);
        }
        let default_locale = resolve_required(
            input.as_mut().and_then(|input| input.package_locale.take()),
            Some("en-US"),
            non_interactive,
            "package_locale",
        )?;
        let mut installer_manifest = InstallerManifest {
            package_identifier: identifier.clone(),
            package_version: version.clone(),
            installers,
            ..InstallerManifest::default()
        };

        let is_font = check_package_type(&installer_manifest)?;

        if !is_font {
            installer_manifest.install_modes = if installer_manifest
                .installers
                .iter()
                .any(|installer| installer.r#type == Some(InstallerType::Inno))
            {
                InstallModes::all()
            } else if non_interactive {
                InstallModes::empty()
            } else {
                check_prompt::<InstallModes>()?
            };
            if !non_interactive {
                installer_manifest.success_codes = list_prompt::<InstallerSuccessCode>()?;
                installer_manifest.upgrade_behavior = Some(radio_prompt::<UpgradeBehavior>()?);
                installer_manifest.commands = list_prompt::<Command>()?;
                installer_manifest.protocols = list_prompt::<Protocol>()?;
            }
            installer_manifest.file_extensions = if installer_manifest
                .installers
                .iter()
                .all(|installer| installer.file_extensions.is_empty())
                && !non_interactive
            {
                list_prompt::<FileExtension>()?
            } else {
                BTreeSet::new()
            };
        }

        let mut github_values = match github_values.await? {
            Some(future) => Some(future?),
            None => None,
        };

        let default_locale_manifest = DefaultLocaleManifest {
            package_identifier: identifier.clone(),
            package_version: version.clone(),
            package_locale: default_locale.clone(),
            publisher: resolve_required(
                input.as_mut().and_then(|input| input.publisher.take()),
                download_results
                    .values()
                    .find(|analyzer| analyzer.publisher.is_some())
                    .and_then(|analyzer| analyzer.publisher.as_ref())
                    .or_else(|| {
                        github_values
                            .as_ref()
                            .and_then(|values| values.publisher.as_ref())
                    }),
                non_interactive,
                "publisher",
            )?,
            publisher_url: resolve_optional(
                input.as_mut().and_then(|input| input.publisher_url.take()),
                github_values.as_ref().map(|values| &values.publisher_url),
                non_interactive,
            )?,
            publisher_support_url: resolve_optional(
                input
                    .as_mut()
                    .and_then(|input| input.publisher_support_url.take()),
                github_values
                    .as_ref()
                    .and_then(|values| values.issues_url.as_ref()),
                non_interactive,
            )?,
            privacy_url: input.as_mut().and_then(|input| input.privacy_url.take()),
            author: resolve_optional(
                input.as_mut().and_then(|input| input.author.take()),
                None::<&str>,
                non_interactive,
            )?,
            package_name: resolve_required(
                input.as_mut().and_then(|input| input.package_name.take()),
                download_results
                    .values()
                    .find(|analyzer| analyzer.package_name.is_some())
                    .and_then(|analyzer| analyzer.package_name.as_ref()),
                non_interactive,
                "package_name",
            )?,
            package_url: resolve_optional(
                input.as_mut().and_then(|input| input.package_url.take()),
                github_values.as_ref().map(|values| &values.package_url),
                non_interactive,
            )?,
            license: resolve_required(
                input.as_mut().and_then(|input| input.license.take()),
                github_values
                    .as_ref()
                    .and_then(|values| values.license.as_ref()),
                non_interactive,
                "license",
            )?,
            license_url: resolve_optional(
                input.as_mut().and_then(|input| input.license_url.take()),
                github_values
                    .as_ref()
                    .and_then(|values| values.license_url.as_ref()),
                non_interactive,
            )?,
            copyright: resolve_optional(
                input.as_mut().and_then(|input| input.copyright.take()),
                download_results
                    .values()
                    .find(|analyzer| analyzer.copyright.is_some())
                    .and_then(|analyzer| analyzer.copyright.as_ref()),
                non_interactive,
            )?,
            copyright_url: resolve_optional(
                input.as_mut().and_then(|input| input.copyright_url.take()),
                None::<&str>,
                non_interactive,
            )?,
            short_description: resolve_required(
                input
                    .as_mut()
                    .and_then(|input| input.short_description.take()),
                github_values
                    .as_ref()
                    .and_then(|values| values.description.as_ref()),
                non_interactive,
                "short_description",
            )?,
            description: resolve_optional(
                input.as_mut().and_then(|input| input.description.take()),
                None::<&str>,
                non_interactive,
            )?,
            moniker: resolve_optional(
                input.as_mut().and_then(|input| input.moniker.take()),
                None::<&str>,
                non_interactive,
            )?,
            tags: match input.as_mut().and_then(|input| input.tags.take()) {
                Some(tags) => tags,
                None => match github_values
                    .as_mut()
                    .map(|values| mem::take(&mut values.topics))
                {
                    Some(topics) => topics,
                    None if non_interactive => BTreeSet::new(),
                    None => list_prompt::<Tag>()?,
                },
            },
            agreements: input
                .as_mut()
                .and_then(|input| input.agreements.take())
                .unwrap_or_default(),
            release_notes: input
                .as_mut()
                .and_then(|input| input.release_notes.take())
                .or_else(|| {
                    github_values
                        .as_mut()
                        .and_then(|values| values.release_notes.take())
                }),
            release_notes_url: resolve_optional(
                input
                    .as_mut()
                    .and_then(|input| input.release_notes_url.take()),
                github_values
                    .as_ref()
                    .and_then(|values| values.release_notes_url.as_ref()),
                non_interactive,
            )?,
            purchase_url: input.as_mut().and_then(|input| input.purchase_url.take()),
            installation_notes: input
                .as_mut()
                .and_then(|input| input.installation_notes.take()),
            documentations: input
                .as_mut()
                .and_then(|input| input.documentations.take())
                .unwrap_or_default(),
            icons: input
                .as_mut()
                .and_then(|input| input.icons.take())
                .unwrap_or_default(),
            ..DefaultLocaleManifest::default()
        };

        installer_manifest
            .apps_and_features_entries
            .iter_mut()
            .for_each(|entry| entry.deduplicate(&default_locale_manifest));

        installer_manifest
            .installers
            .iter_mut()
            .flat_map(|installer| &mut installer.apps_and_features_entries)
            .for_each(|entry| entry.deduplicate(&default_locale_manifest));

        installer_manifest.locale = None;
        installer_manifest
            .installers
            .iter()
            .flat_map(|installer| &installer.locale)
            .all_equal()
            .then(|| &mut installer_manifest.installers)
            .into_iter()
            .flatten()
            .for_each(|installer| installer.locale = None);

        // `optimize` sorts installers, so it must run after all installer mutations.
        installer_manifest.optimize();

        let manifests = Manifests {
            installer: installer_manifest,
            default_locale: default_locale_manifest,
            locales: package
                .manifests
                .take()
                .map(|manifests| manifests.locales)
                .unwrap_or_default(),
            version: VersionManifest::new(identifier.clone(), version.clone(), default_locale),
        };

        let mut changes =
            manifests.create(&identifier, &version, self.created_with.as_deref(), is_font);

        if dry_run {
            print_changes(changes.iter().map(Change::manifest));
            return Ok(());
        }

        let submit_option = SubmitOption::prompt(&mut changes, &identifier, &version, self.submit)?;

        let package_path = PackagePath::new(&identifier, Some(&version), None, is_font);
        if let Some(output) = self.output.map(|out| out.join(package_path.as_str())) {
            changes.write_to(output.as_path()).await?;
            println!(
                "{} written all manifest files to {}",
                "Successfully".green(),
                output.display()
            );
        }

        if submit_option.is_exit() {
            return Ok(());
        }

        // Create an indeterminate progress bar to show as a pull request is being created
        let pr_progress = ProgressBar::new_spinner().with_message(format!(
            "Creating a pull request for {identifier} {version}"
        ));
        pr_progress.enable_steady_tick(SPINNER_TICK_RATE);

        let pull_request = github
            .add_version()
            .identifier(&identifier)
            .version(&version)
            .versions(package.versions())
            .changes(changes)
            .issue_resolves(&self.resolves)
            .maybe_created_with(self.created_with.as_deref())
            .maybe_created_with_url(self.created_with_url.as_ref())
            .send()
            .await?;

        pr_progress.finish_and_clear();

        pull_request.print_success();

        if self.open_pr {
            open::that(pull_request.url().as_str())?;
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct NonInteractiveInput {
    package_locale: Option<LanguageTag>,

    publisher: Option<Publisher>,

    publisher_url: Option<PublisherUrl>,

    publisher_support_url: Option<PublisherSupportUrl>,

    privacy_url: Option<url::Url>,

    package_name: Option<PackageName>,

    package_url: Option<PackageUrl>,

    moniker: Option<Moniker>,

    author: Option<Author>,

    license: Option<License>,

    license_url: Option<LicenseUrl>,

    copyright: Option<Copyright>,

    copyright_url: Option<CopyrightUrl>,

    short_description: Option<ShortDescription>,

    description: Option<Description>,

    tags: Option<BTreeSet<Tag>>,

    agreements: Option<BTreeSet<Agreement>>,

    release_notes: Option<ReleaseNotes>,

    release_notes_url: Option<ReleaseNotesUrl>,

    purchase_url: Option<url::Url>,

    installation_notes: Option<InstallationNotes>,

    documentations: Option<BTreeSet<Documentation>>,

    icons: Option<BTreeSet<Icon>>,
}

fn resolve_required<T, U>(
    input: Option<T>,
    default: Option<U>,
    non_interactive: bool,
    field_name: &str,
) -> Result<T>
where
    T: FromStr + TextPrompt,
    <T as FromStr>::Err: std::fmt::Display + std::fmt::Debug + Sync + Send + 'static,
    U: AsRef<str>,
{
    match input {
        Some(value) => Ok(value),
        None if non_interactive => default
            .map(|value| {
                value
                    .as_ref()
                    .parse::<T>()
                    .map_err(|error| eyre!(error.to_string()))
            })
            .transpose()?
            .ok_or_else(|| {
                eyre!("Missing required field `{field_name}` in non-interactive JSON input")
            }),
        None => Ok(required_prompt(None, default)?),
    }
}

fn resolve_optional<T, U>(
    input: Option<T>,
    default: Option<U>,
    non_interactive: bool,
) -> Result<Option<T>>
where
    T: FromStr + TextPrompt,
    <T as FromStr>::Err: std::fmt::Display + std::fmt::Debug + Sync + Send + 'static,
    U: AsRef<str>,
{
    match input {
        Some(value) => Ok(Some(value)),
        None if non_interactive => default
            .map(|value| {
                value
                    .as_ref()
                    .parse::<T>()
                    .map_err(|error| eyre!(error.to_string()))
            })
            .transpose(),
        None => Ok(optional_prompt(None, default)?),
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{NewVersion, NonInteractiveInput};

    const INPUT: &str = r#"{
        "PackageLocale": "en-US",
        "Publisher": "Example Publisher",
        "PublisherUrl": "https://example.com",
        "PublisherSupportUrl": "https://example.com/support",
        "PrivacyUrl": "https://example.com/privacy",
        "Author": "Example Author",
        "PackageName": "Example Package",
        "PackageUrl": "https://example.com/package",
        "License": "MIT",
        "LicenseUrl": "https://example.com/license",
        "Copyright": "Copyright Example Publisher",
        "CopyrightUrl": "https://example.com/copyright",
        "ShortDescription": "An example package",
        "Description": "A longer example package description",
        "Moniker": "example",
        "Tags": ["example", "utility"],
        "Agreements": [{
            "AgreementLabel": "Terms",
            "Agreement": "Example terms",
            "AgreementUrl": "https://example.com/terms"
        }],
        "ReleaseNotes": "Example release notes",
        "ReleaseNotesUrl": "https://example.com/releases/1.2.3",
        "PurchaseUrl": "https://example.com/purchase",
        "InstallationNotes": "Example installation notes",
        "Documentations": [{
            "DocumentLabel": "Guide",
            "DocumentUrl": "https://example.com/guide"
        }],
        "Icons": [{
            "IconUrl": "https://example.com/icon.png",
            "IconFileType": "png",
            "IconResolution": "64x64",
            "IconTheme": "default",
            "IconSha256": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        }]
    }"#;

    const CLI_INPUT: &str = "{}";

    #[test]
    fn parses_non_interactive_json() {
        let command = NewVersion::try_parse_from(["komac-new", "--non-interactive", INPUT])
            .expect("valid JSON should parse");
        let input = serde_json::from_str::<NonInteractiveInput>(
            &command.non_interactive.expect("input should be present"),
        )
        .expect("valid input should deserialize");

        assert_eq!(
            input.package_locale.map(|locale| locale.to_string()),
            Some("en-US".to_owned())
        );
        assert_eq!(input.tags.map(|tags| tags.len()), Some(2));
        assert_eq!(input.agreements.map(|agreements| agreements.len()), Some(1));
        assert!(input.release_notes.is_some());
        assert_eq!(
            input
                .documentations
                .map(|documentations| documentations.len()),
            Some(1)
        );
        assert_eq!(input.icons.map(|icons| icons.len()), Some(1));
    }

    #[test]
    fn rejects_non_pascal_case_json_fields() {
        let input = INPUT.replace("PackageName", "package_name");

        assert!(serde_json::from_str::<NonInteractiveInput>(&input).is_err());
    }

    #[test]
    fn rejects_cli_only_json_fields() {
        for input in [
            r#"{"PackageIdentifier":"Json.Package"}"#,
            r#"{"PackageVersion":"2.0.0"}"#,
            r#"{"Urls":["https://example.com/installer.exe"]}"#,
        ] {
            assert!(serde_json::from_str::<NonInteractiveInput>(input).is_err());
        }
    }

    #[test]
    fn only_cli_package_parameters_are_registered() {
        const REMOVED_OPTIONS: [&str; 15] = [
            "package-locale",
            "publisher",
            "publisher-url",
            "publisher-support-url",
            "package-name",
            "package-url",
            "moniker",
            "author",
            "license",
            "license-url",
            "copyright",
            "copyright-url",
            "short-description",
            "description",
            "release-notes-url",
        ];

        let command = NewVersion::command();

        assert_eq!(command.get_positionals().count(), 1);
        for option in ["version", "urls"] {
            assert!(
                command
                    .get_arguments()
                    .any(|argument| argument.get_long() == Some(option))
            );
        }
        for option in REMOVED_OPTIONS {
            assert!(
                command
                    .get_arguments()
                    .all(|argument| argument.get_long() != Some(option)),
                "removed option --{option} is still registered"
            );
        }
    }

    #[test]
    fn parses_identifier_version_and_urls_from_cli() {
        let command = NewVersion::try_parse_from([
            "komac-new",
            "Cli.Package",
            "--version",
            "2.0.0",
            "--urls",
            "https://example.com/installer.exe|x64",
            "--non-interactive",
            CLI_INPUT,
        ])
        .expect("identifier, version, and URLs should parse from the CLI");

        assert_eq!(
            command.identifier.map(|identifier| identifier.to_string()),
            Some("Cli.Package".to_owned())
        );
        assert_eq!(
            command.version.map(|version| version.to_string()),
            Some("2.0.0".to_owned())
        );
        assert_eq!(command.urls.len(), 1);
    }
}
