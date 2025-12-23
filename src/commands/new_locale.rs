use std::{collections::BTreeSet, mem, num::NonZeroU32};

use anstream::println;
use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::eyre::{Result, bail};
use indicatif::ProgressBar;
use owo_colors::OwoColorize;
use secrecy::SecretString;
use winget_types::{
    LanguageTag, ManifestType, ManifestVersion, PackageIdentifier, PackageVersion,
    locale::{
        Author, Copyright, Description, License, LocaleManifest, PackageName, Publisher,
        ShortDescription, Tag,
    },
    url::{
        CopyrightUrl, DecodedUrl, LicenseUrl, PackageUrl, PublisherSupportUrl, PublisherUrl,
        ReleaseNotesUrl,
    },
};

use crate::{
    commands::utils::{SPINNER_TICK_RATE, SubmitOption},
    github::{
        WINGET_PKGS_FULL_NAME,
        client::GitHub,
        utils::{
            PackagePath,
            pull_request::{Change, Changes},
        },
    },
    manifests::{Manifests, print_changes},
    prompts::{
        list::list_prompt_with_help,
        text::{optional_prompt_with_help, required_prompt},
    },
    token::TokenManager,
};

/// Create a new locale manifest for an existing package version
#[expect(clippy::struct_excessive_bools, reason = "CLI flags")]
#[derive(Parser)]
#[clap(visible_alias = "add-locale")]
pub struct NewLocale {
    /// The package's unique identifier
    #[arg()]
    package_identifier: Option<PackageIdentifier>,

    /// The package locale to create
    #[arg()]
    package_locale: Option<LanguageTag>,

    /// The package's version
    #[arg(short = 'v', long = "version")]
    package_version: Option<PackageVersion>,

    #[arg(long)]
    publisher: Option<Publisher>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    publisher_url: Option<PublisherUrl>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    publisher_support_url: Option<PublisherSupportUrl>,

    #[arg(long)]
    author: Option<Author>,

    #[arg(long)]
    package_name: Option<PackageName>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    package_url: Option<PackageUrl>,

    #[arg(long)]
    license: Option<License>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    license_url: Option<LicenseUrl>,

    #[arg(long)]
    copyright: Option<Copyright>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    copyright_url: Option<CopyrightUrl>,

    #[arg(long)]
    short_description: Option<ShortDescription>,

    #[arg(long)]
    description: Option<Description>,

    #[arg(long = "tag", value_name = "TAG")]
    tags: Vec<Tag>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    release_notes_url: Option<ReleaseNotesUrl>,

    /// List of issues that adding this locale would resolve
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

    /// Directory to output the manifest to
    #[arg(short, long, env = "OUTPUT_DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    output: Option<Utf8PathBuf>,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Run without submitting
    #[arg(long, env = "DRY_RUN")]
    dry_run: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN", hide_env_values = true)]
    token: Option<SecretString>,
}

impl NewLocale {
    pub async fn run(mut self) -> Result<()> {
        let token_manager = TokenManager::handle(self.token.take()).await?;
        let github = GitHub::new(&token_manager)?;

        let package_identifier = required_prompt(self.package_identifier.take(), None::<&str>)?;
        let (versions, font) = github.get_versions(&package_identifier, None).await?;
        let latest_version = versions.last().unwrap_or_else(|| unreachable!());

        println!("Latest version of {package_identifier}: {latest_version}");

        let package_version =
            required_prompt(self.package_version.take(), Some(latest_version.as_str()))?;
        if !versions.contains(&package_version) {
            if let Some(closest) = package_version.closest(&versions) {
                bail!(
                    "{} version {} does not exist in {WINGET_PKGS_FULL_NAME}. The closest version is {closest}",
                    package_identifier,
                    package_version,
                );
            }

            bail!(
                "{} version {} does not exist in {WINGET_PKGS_FULL_NAME}",
                package_identifier,
                package_version,
            );
        }

        let package_locale = required_prompt(self.package_locale.take(), None::<&str>)?;

        let mut manifests = github
            .get_manifests(&package_identifier, &package_version, font)
            .await?;

        validate_new_locale(&manifests, &package_locale)?;

        let locale_manifest = self.create_locale_manifest(
            &manifests,
            package_identifier.clone(),
            package_version.clone(),
            package_locale,
        )?;
        manifests.locales.push(locale_manifest);

        let package_path =
            PackagePath::new(&package_identifier, Some(&package_version), None, font);
        let mut changes = new_locale_changes(
            &package_identifier,
            &manifests,
            &package_path,
            self.created_with.as_deref(),
        )?;

        if let Some(output) = self
            .output
            .as_ref()
            .map(|out| out.join(package_path.as_str()))
        {
            changes.write_to(output.as_std_path()).await?;
            println!(
                "{} written locale manifest to {output}",
                "Successfully".green()
            );
        }

        if self.dry_run {
            print_changes(changes.iter().map(Change::manifest));
            return Ok(());
        }

        let submit_option = SubmitOption::prompt(
            &mut changes,
            &package_identifier,
            &package_version,
            self.submit,
        )?;

        if submit_option.is_exit() {
            return Ok(());
        }

        let pr_progress = ProgressBar::new_spinner().with_message(format!(
            "Creating a pull request for {package_identifier} {package_version}"
        ));
        pr_progress.enable_steady_tick(SPINNER_TICK_RATE);

        let pull_request = github
            .add_version()
            .identifier(&package_identifier)
            .version(&package_version)
            .versions(&versions)
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

    fn create_locale_manifest(
        &mut self,
        manifests: &Manifests,
        package_identifier: PackageIdentifier,
        package_version: PackageVersion,
        package_locale: LanguageTag,
    ) -> Result<LocaleManifest> {
        let default_locale = &manifests.default_locale;

        Ok(LocaleManifest {
            package_identifier,
            package_version,
            package_locale,
            publisher: optional_prompt_with_help(
                self.publisher.take(),
                default_locale_help(Some(&default_locale.publisher)),
            )?,
            publisher_url: optional_prompt_with_help(
                self.publisher_url.take(),
                default_locale_help(default_locale.publisher_url.as_ref()),
            )?,
            publisher_support_url: optional_prompt_with_help(
                self.publisher_support_url.take(),
                default_locale_help(default_locale.publisher_support_url.as_ref()),
            )?,
            privacy_url: None,
            author: optional_prompt_with_help(
                self.author.take(),
                default_locale_help(default_locale.author.as_ref()),
            )?,
            package_name: optional_prompt_with_help(
                self.package_name.take(),
                default_locale_help(Some(&default_locale.package_name)),
            )?,
            package_url: optional_prompt_with_help(
                self.package_url.take(),
                default_locale_help(default_locale.package_url.as_ref()),
            )?,
            license: optional_prompt_with_help(
                self.license.take(),
                default_locale_help(Some(&default_locale.license)),
            )?,
            license_url: optional_prompt_with_help(
                self.license_url.take(),
                default_locale_help(default_locale.license_url.as_ref()),
            )?,
            copyright: optional_prompt_with_help(
                self.copyright.take(),
                default_locale_help(default_locale.copyright.as_ref()),
            )?,
            copyright_url: optional_prompt_with_help(
                self.copyright_url.take(),
                default_locale_help(default_locale.copyright_url.as_ref()),
            )?,
            short_description: optional_prompt_with_help(
                self.short_description.take(),
                default_locale_help(Some(&default_locale.short_description)),
            )?,
            description: optional_prompt_with_help(
                self.description.take(),
                default_locale_help(default_locale.description.as_ref()),
            )?,
            tags: if self.tags.is_empty() {
                list_prompt_with_help::<Tag, _>(default_locale_tags_help(&default_locale.tags))?
            } else {
                mem::take(&mut self.tags)
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            },
            agreements: BTreeSet::new(),
            release_notes: None,
            release_notes_url: optional_prompt_with_help(
                self.release_notes_url.take(),
                default_locale_help(default_locale.release_notes_url.as_ref()),
            )?,
            purchase_url: None,
            installation_notes: None,
            documentations: BTreeSet::new(),
            icons: BTreeSet::new(),
            manifest_type: ManifestType::Locale,
            manifest_version: ManifestVersion::default(),
        })
    }
}

fn default_locale_help<T>(value: Option<T>) -> Option<String>
where
    T: AsRef<str>,
{
    value.map(|value| format!("Default locale: {}", value.as_ref()))
}

fn default_locale_tags_help(tags: &BTreeSet<Tag>) -> String {
    if tags.is_empty() {
        String::from("Default locale: (none)")
    } else {
        format!(
            "Default locale: {}",
            tags.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn validate_new_locale(manifests: &Manifests, package_locale: &LanguageTag) -> Result<()> {
    if package_locale == manifests.version.default_locale() {
        bail!("{package_locale} is already the default locale for {manifests}");
    }

    if manifests
        .locales
        .iter()
        .any(|locale| &locale.package_locale == package_locale)
    {
        bail!("{package_locale} already exists for {manifests}");
    }

    Ok(())
}

fn new_locale_changes(
    package_identifier: &PackageIdentifier,
    manifests: &Manifests,
    package_path: &PackagePath,
    created_with: Option<&str>,
) -> Result<Changes> {
    let locale_manifest = manifests
        .locales
        .last()
        .unwrap_or_else(|| unreachable!("new locale should have been pushed"));

    Ok(Changes::new([Change::new(
        format!(
            "{package_path}/{package_identifier}.locale.{}.yaml",
            locale_manifest.package_locale
        ),
        locale_manifest,
        created_with,
    )]))
}
