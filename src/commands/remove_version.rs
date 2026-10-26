use std::num::NonZeroU32;

use anstream::println;
use clap::Parser;
use color_eyre::eyre::{Result, bail};
use futures_util::TryFutureExt;
use inquire::{
    Text,
    validator::{MaxLengthValidator, MinLengthValidator},
};
use jiff::tz::TimeZone;
use owo_colors::OwoColorize;
use secrecy::SecretString;
use tokio::try_join;
use winget_types::{PackageIdentifier, PackageVersion};

use crate::{
    commands::utils::RateLimit,
    environment::CI,
    github::{WINGET_PKGS_FULL_NAME, client::GitHub},
    prompts::{handle_inquire_error, text::confirm_prompt},
    token::TokenManager,
};

/// Remove a version from winget-pkgs
///
/// To remove a package, all versions of that package must be removed
#[derive(Parser)]
pub struct RemoveVersion {
    /// The package's unique identifier
    #[arg(value_name = "PACKAGE_IDENTIFIER")]
    package_identifier: PackageIdentifier,

    /// The package's version
    #[arg(
        short = 'v',
        long = "version",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    package_version: Option<PackageVersion>,

    /// Remove all versions of the package
    #[arg(long, hide = true)]
    all: bool,

    /// Use the per-minute rate limit, potentially hitting the hourly rate limit in 7.5 minutes
    #[arg(long, hide = true)]
    fast: bool,

    #[arg(short = 'r', long = "reason")]
    deletion_reason: Option<String>,

    /// List of issues that removing this version would resolve
    #[arg(long)]
    resolves: Vec<NonZeroU32>,

    #[arg(short, long)]
    submit: bool,

    /// Don't show the package removal warning
    #[arg(long)]
    no_warning: bool,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Look for the package under fonts instead of probing manifests first
    #[arg(long)]
    font: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN", hide_env_values = true)]
    token: Option<SecretString>,
}

impl RemoveVersion {
    const MIN_REASON_LENGTH: usize = 4;
    const MAX_REASON_LENGTH: usize = 1000;

    pub async fn run(self) -> Result<()> {
        let token_manager = TokenManager::handle(self.token).await?;

        if !self.no_warning {
            println!(
                "{}",
                "Packages should only be removed when necessary".yellow()
            );
        }

        let github = GitHub::new(&token_manager)?;

        let (fork, winget_pkgs, (versions, font)) = try_join!(
            github
                .get_username()
                .and_then(|current_user| github.get_winget_pkgs().owner(current_user).send()),
            github.get_winget_pkgs().send(),
            github.get_versions(&self.package_identifier, self.font.then_some(true))
        )?;

        if let Some(version) = &self.package_version
            && !versions.contains(version)
        {
            bail!(
                "{} version {} does not exist in {WINGET_PKGS_FULL_NAME}",
                self.package_identifier,
                version,
            );
        }

        let latest_version = versions.last().unwrap_or_else(|| unreachable!());
        println!(
            "Latest version of {}: {latest_version}",
            &self.package_identifier
        );

        let versions_to_remove = self.package_version.as_ref().map_or_else(
            || versions.iter().collect::<Vec<_>>(),
            |version| vec![version],
        );
        for version in &versions_to_remove {
            let Some(pull_request) = github
                .get_existing_pull_request(&self.package_identifier, version, false)
                .await?
                .filter(|pull_request| pull_request.is_open())
            else {
                continue;
            };
            let created_at = pull_request.created_at.to_zoned(TimeZone::system());
            println!(
                "There is already {} pull request for {} {} that was created on {} at {}",
                pull_request.state,
                self.package_identifier,
                version,
                created_at.date(),
                created_at.time()
            );
            println!("{}", pull_request.url.blue());

            if *CI || !confirm_prompt("Would you like to proceed?")? {
                return Ok(());
            }
        }

        let removal_target = self.package_version.as_ref().map_or_else(
            || {
                format!(
                    "{} (all {} versions)",
                    self.package_identifier,
                    versions.len()
                )
            },
            |version| format!("{} version {version}", self.package_identifier),
        );
        let deletion_reason = match self.deletion_reason {
            Some(reason) => reason,
            None => Text::new(&format!("Give a reason for removing {removal_target}"))
                .with_validator(MinLengthValidator::new(Self::MIN_REASON_LENGTH))
                .with_validator(MaxLengthValidator::new(Self::MAX_REASON_LENGTH))
                .prompt()
                .map_err(handle_inquire_error)?,
        };
        let pull_requests = if self.all {
            "pull requests"
        } else {
            "a pull request"
        };
        let should_remove_manifest = self.submit
            || confirm_prompt(&format!(
                "Would you like to make {pull_requests} to remove {removal_target}?"
            ))?;

        if !should_remove_manifest {
            return Ok(());
        }

        let rate_limit = RateLimit::new(self.fast);
        for version in versions_to_remove {
            rate_limit.wait().await;

            let pull_request = github
                .remove_version()
                .identifier(&self.package_identifier)
                .version(version)
                .reason(&deletion_reason)
                .fork(&fork)
                .winget_pkgs(&winget_pkgs)
                .font(font)
                .issue_resolves(&self.resolves)
                .send()
                .await?;

            rate_limit.record().await;

            if self.open_pr {
                open::that(pull_request.url().as_str())?;
            }
        }

        Ok(())
    }
}
