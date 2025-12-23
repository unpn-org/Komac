use std::collections::BTreeSet;

use anstream::println;
use chrono::Local;
use inquire::error::InquireResult;
use owo_colors::OwoColorize;
use tokio::try_join;
use winget_types::{PackageIdentifier, PackageVersion};

use crate::{
    environment::CI,
    github::{GitHubError, client::GitHub, graphql::types::PullRequest},
    manifests::Manifests,
    prompts::text::confirm_prompt,
};

pub struct Versioned;

pub struct Unversioned;

pub trait VersionedState<'version> {
    type Version;
}

impl<'version> VersionedState<'version> for Versioned {
    type Version = &'version PackageVersion;
}

impl VersionedState<'_> for Unversioned {
    type Version = ();
}

pub struct Package<'identifier, 'version, V: VersionedState<'version>> {
    identifier: &'identifier PackageIdentifier,
    version: V::Version,
    versions: BTreeSet<PackageVersion>,
    font: bool,
    pub manifests: Option<Manifests>,
    existing_pr: Option<PullRequest>,
}

impl<'identifier, 'version, V: VersionedState<'version>> Package<'identifier, 'version, V> {
    /// Returns the package's identifier.
    #[expect(unused)]
    pub const fn identifier(&self) -> &'identifier PackageIdentifier {
        self.identifier
    }

    /// Returns whether the package is stored under the fonts root.
    pub const fn is_font(&self) -> bool {
        self.font
    }
}

impl Package<'_, '_, Versioned> {
    /// Returns the package's versions.
    pub const fn versions(&self) -> &BTreeSet<PackageVersion> {
        &self.versions
    }

    /// Returns the latest version of the package.
    pub fn latest_version(&self) -> &PackageVersion {
        self.versions.last().unwrap_or_else(|| unreachable!())
    }

    pub const fn manifests_mut(&mut self) -> Option<&mut Manifests> {
        self.manifests.as_mut()
    }

    pub fn prompt_existing_pr(&self) -> InquireResult<bool> {
        if *CI {
            return Ok(false);
        }

        let Some(ref pull_request) = self.existing_pr else {
            return Ok(true);
        };

        let created_at = pull_request.created_at.with_timezone(&Local);
        println!(
            "There is already {state} pull request for {identifier} {version} that was created on {date} at {time}",
            state = pull_request.state,
            identifier = self.identifier,
            version = self.version,
            date = created_at.date_naive(),
            time = created_at.time()
        );
        println!("{}", pull_request.url.blue());
        confirm_prompt("Would you like to proceed?")
    }
}

impl<'identifier> Package<'identifier, '_, Unversioned> {
    pub async fn into_versioned<'version, 'a>(
        self,
        version: &'version PackageVersion,
        github: &'a GitHub,
    ) -> Result<Package<'identifier, 'version, Versioned>, GitHubError> {
        let existing_pr = github
            .get_existing_pull_request(self.identifier, version, false)
            .await?;

        Ok(Package {
            identifier: self.identifier,
            version,
            manifests: self.manifests,
            versions: self.versions,
            font: self.font,
            existing_pr,
        })
    }

    /// Returns the latest version of the package, if the package exists.
    pub fn latest_version(&self) -> Option<&PackageVersion> {
        self.versions.last()
    }
}

impl GitHub {
    pub async fn get_versioned_package<'identifier, 'version>(
        &self,
        identifier: &'identifier PackageIdentifier,
        version: &'version PackageVersion,
        font: Option<bool>,
    ) -> Result<Package<'identifier, 'version, Versioned>, GitHubError> {
        let ((versions, font), existing_pr) = try_join!(
            self.get_versions(identifier, font),
            self.get_existing_pull_request(identifier, version, false),
        )?;

        Ok(Package {
            identifier,
            version,
            manifests: if let Some(version) = versions.last() {
                Some(self.get_manifests(identifier, version, font).await?)
            } else {
                None
            },
            versions,
            font,
            existing_pr,
        })
    }

    /// Fetches an unversioned [Package] which may not exist in `winget-pkgs`.
    pub async fn get_package<'identifier>(
        &self,
        identifier: &'identifier PackageIdentifier,
        font_hint: Option<bool>,
    ) -> Result<Package<'identifier, '_, Unversioned>, GitHubError> {
        let (versions, font) = match self.get_versions(identifier, font_hint).await {
            Ok(package) => package,
            Err(GitHubError::PackageNonExistent(_)) => {
                (BTreeSet::new(), font_hint.unwrap_or(false))
            }
            Err(err) => return Err(err),
        };

        Ok(Package {
            identifier,
            version: (),
            manifests: if let Some(version) = versions.last() {
                Some(self.get_manifests(identifier, version, font).await?)
            } else {
                None
            },
            versions,
            font,
            existing_pr: None,
        })
    }
}
