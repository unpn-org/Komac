use anstream::println;
use clap::Parser;
use color_eyre::eyre::{Result, ensure};
use futures_util::TryFutureExt;
use secrecy::SecretString;
use tokio::try_join;
use winget_types::{PackageIdentifier, locale::Moniker};

use crate::{
    commands::utils::RateLimit,
    github::{client::GitHub, move_package::PackageMove},
    prompts::text::confirm_prompt,
    token::TokenManager,
};

/// Move all versions to a new package identifier
///
/// Creates two independent pull requests per version: one adding the new identifier,
/// and one removing the old identifier.
#[derive(Parser)]
pub struct MovePackage {
    /// The existing package identifier
    #[arg(value_name = "OLD_PACKAGE_IDENTIFIER")]
    old_identifier: PackageIdentifier,

    /// The destination package identifier
    #[arg(value_name = "NEW_PACKAGE_IDENTIFIER")]
    new_identifier: PackageIdentifier,

    /// Replace existing Moniker fields in the copied manifests
    #[arg(long)]
    moniker: Option<Moniker>,

    /// Submit all pull requests without prompting
    #[arg(short, long)]
    submit: bool,

    /// Use the per-minute rate limit, potentially hitting the hourly rate limit in 7.5 minutes
    #[arg(long)]
    fast: bool,

    /// Open pull request links automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Look for the package under fonts instead of probing manifests first
    #[arg(long)]
    font: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN", hide_env_values = true)]
    token: Option<SecretString>,
}

impl MovePackage {
    pub async fn run(self) -> Result<()> {
        ensure!(
            self.old_identifier != self.new_identifier,
            "The old and new package identifiers must be different"
        );
        let token_manager = TokenManager::handle(self.token).await?;
        let github = GitHub::new(&token_manager)?;
        let (fork, upstream, (versions, font)) = try_join!(
            github
                .get_username()
                .and_then(|user| github.get_winget_pkgs().owner(user).send()),
            github.get_winget_pkgs().send(),
            github.get_versions(&self.old_identifier, self.font.then_some(true)),
        )?;

        // Validate and prepare every version before creating any branches or pull requests.
        let mut moves = Vec::with_capacity(versions.len());
        for version in versions {
            moves.push(
                PackageMove::prepare(
                    &github,
                    &upstream,
                    &self.old_identifier,
                    &self.new_identifier,
                    version,
                    font,
                    self.moniker.as_ref(),
                )
                .await?,
            );
        }

        println!(
            "Move {} to {}: {} versions, {} pull requests.",
            self.old_identifier,
            self.new_identifier,
            moves.len(),
            moves.len() * 2,
        );
        if !self.submit && !confirm_prompt("Would you like to submit all move pull requests?")? {
            return Ok(());
        }

        let rate_limit = RateLimit::new(self.fast);
        for package_move in moves {
            package_move
                .submit(&github, &fork, &upstream, &rate_limit, self.open_pr)
                .await?;
        }
        Ok(())
    }
}
