use anstream::println;
use color_eyre::eyre::{Context, Result, ensure, eyre};
use cynic::QueryBuilder;
use serde::{Serialize, de::DeserializeOwned};
use winget_types::{
    Manifest, ManifestType, PackageIdentifier, PackageVersion, VersionManifest,
    installer::InstallerManifest,
    locale::{DefaultLocaleManifest, LocaleManifest, Moniker},
    utils::GenericManifest,
};

use super::{
    GitHubError, MICROSOFT, WINGET_PKGS,
    client::{GitHub, RepositoryData},
    graphql::{
        create_commit::{FileAddition, FileDeletion},
        get_directory_content::GetDirectoryContentVariables,
        get_directory_content_with_text::{GetDirectoryContentWithText, TreeEntry},
    },
    utils::{PackagePath, branch_name},
};
use crate::{
    github::{rate_limit::RateLimit, utils::pull_request::convert_to_crlf},
    manifests::to_yaml_string,
};

pub struct PackageMove {
    old_identifier: PackageIdentifier,
    version: PackageVersion,
    title_suffix: String,
    files: Vec<(String, String, String)>,
}

impl PackageMove {
    pub async fn prepare(
        github: &GitHub,
        upstream: &RepositoryData,
        old_identifier: &PackageIdentifier,
        new_identifier: &PackageIdentifier,
        version: PackageVersion,
        font: bool,
        moniker: Option<&Moniker>,
    ) -> Result<Self> {
        let source = PackagePath::new(old_identifier, Some(&version), None, font);
        let destination = PackagePath::new(new_identifier, Some(&version), None, font);
        let (source_files, destination_files) = tokio::try_join!(
            directory(github, upstream, &source),
            directory(github, upstream, &destination),
        )?;
        ensure!(
            destination_files.is_none(),
            "Destination {destination} already exists"
        );
        let source_files = source_files.ok_or_else(|| eyre!("Source {source} does not exist"))?;
        let files = prepare_files(
            source_files,
            &source,
            &destination,
            old_identifier,
            new_identifier,
            moniker,
        )?;
        Ok(Self {
            old_identifier: old_identifier.clone(),
            title_suffix: format!("{old_identifier} {version} to {new_identifier} {version}"),
            version,
            files,
        })
    }

    pub async fn submit(
        &self,
        github: &GitHub,
        fork: &RepositoryData,
        upstream: &RepositoryData,
        rate_limit: &RateLimit,
        open_pr: bool,
    ) -> Result<()> {
        let mut addition_url = None;
        for removal in [false, true] {
            rate_limit.wait().await;
            let action = if removal { "Remove" } else { "Move" };
            let title = format!("{action} {}", self.title_suffix);
            let branch_name = branch_name(&self.old_identifier, &self.version);
            let branch = github
                .create_branch(&fork.id, &branch_name, upstream.default_branch_oid.clone())
                .await?;
            let additions = if removal {
                Vec::new()
            } else {
                self.files
                    .iter()
                    .map(|(_, path, text)| FileAddition::new(path, text))
                    .collect()
            };
            let deletions = if removal {
                self.files
                    .iter()
                    .map(|(path, _, _)| FileDeletion::new(path))
                    .collect()
            } else {
                Vec::new()
            };
            github
                .commit()
                .branch_id(&branch.id)
                .head_sha(upstream.default_branch_oid.clone())
                .message(&title)
                .additions(additions)
                .deletions(deletions)
                .create()
                .await?;
            let body = addition_url.as_ref().map_or_else(
                || "Copies this version to the new package identifier.".to_owned(),
                |url| {
                    format!("Removes the old package identifier. Corresponding addition PR: {url}")
                },
            );
            let pr = github
                .create_pull_request(
                    &upstream.id,
                    &fork.id,
                    &format!("{}:{branch_name}", fork.owner),
                    &upstream.default_branch_name,
                    &title,
                    &body,
                )
                .await?;
            rate_limit.record().await;
            println!(
                "\n{} PR for version {}:",
                if removal { "Removal" } else { "Addition" },
                self.version,
            );
            pr.print_success();
            if !removal {
                addition_url = Some(pr.url().clone());
            }
            if open_pr {
                open::that(pr.url().as_str())?;
            }
        }
        Ok(())
    }
}

// Read both sides at the commit used for every PR, and distinguish missing paths from API errors.
async fn directory(
    github: &GitHub,
    upstream: &RepositoryData,
    path: &PackagePath,
) -> Result<Option<Vec<TreeEntry>>, GitHubError> {
    let expression = format!("{}:{path}", upstream.default_branch_oid.as_str());
    let response = github
        .run_graphql_with_retry(&GetDirectoryContentWithText::build(
            GetDirectoryContentVariables::new(&MICROSOFT, &WINGET_PKGS, &expression),
        ))
        .await?;
    if response
        .errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(GitHubError::graphql_errors(
            eyre!("failed to get {path}"),
            response.errors,
        ));
    }
    let repository = response
        .data
        .and_then(|data| data.repository)
        .ok_or_else(|| {
            GitHubError::graphql_errors(eyre!("failed to get {path}"), response.errors)
        })?;
    repository
        .object
        .map(|object| {
            object
                .into_tree_entries()
                .ok_or_else(|| GitHubError::GraphQL(eyre!("{path} is not a directory")))
        })
        .transpose()
}

fn prepare_files(
    source_files: Vec<TreeEntry>,
    source: &PackagePath,
    destination: &PackagePath,
    old_identifier: &PackageIdentifier,
    new_identifier: &PackageIdentifier,
    moniker: Option<&Moniker>,
) -> Result<Vec<(String, String, String)>> {
    ensure!(!source_files.is_empty(), "Source {source} is empty");
    let mut files = Vec::with_capacity(source_files.len());
    for entry in source_files {
        let text = entry
            .object
            .and_then(|object| object.into_blob_text())
            .ok_or_else(|| eyre!("Cannot copy {source}/{}: not a text file", entry.name))?;
        let name = entry
            .name
            .replace(old_identifier.as_str(), new_identifier.as_str());
        let content = rewrite_manifest(&text, old_identifier, new_identifier, moniker)
            .wrap_err_with(|| format!("Failed to move {source}/{}", entry.name))?;
        files.push((
            format!("{source}/{}", entry.name),
            format!("{destination}/{name}"),
            content,
        ));
    }
    Ok(files)
}

fn rewrite_manifest(
    text: &str,
    old: &PackageIdentifier,
    new: &PackageIdentifier,
    moniker: Option<&Moniker>,
) -> Result<String> {
    let manifest_type = serde_saphyr::from_str::<GenericManifest>(text)?.r#type;
    match manifest_type {
        ManifestType::Version => reemit_manifest::<VersionManifest>(text, old, |manifest| {
            manifest.package_identifier = new.clone();
        }),
        ManifestType::Installer => reemit_manifest::<InstallerManifest>(text, old, |manifest| {
            manifest.package_identifier = new.clone();
        }),
        ManifestType::DefaultLocale => {
            reemit_manifest::<DefaultLocaleManifest>(text, old, |manifest| {
                manifest.package_identifier = new.clone();
                if manifest.moniker.is_some()
                    && let Some(moniker) = moniker
                {
                    manifest.moniker = Some(moniker.clone());
                }
            })
        }
        ManifestType::Locale => reemit_manifest::<LocaleManifest>(text, old, |manifest| {
            manifest.package_identifier = new.clone();
        }),
    }
}

fn reemit_manifest<M>(
    text: &str,
    old: &PackageIdentifier,
    update: impl FnOnce(&mut M),
) -> Result<String>
where
    M: Manifest + Serialize + DeserializeOwned,
{
    let mut manifest: M = serde_saphyr::from_str(text)?;
    ensure!(
        manifest.package_identifier() == old,
        "Expected package identifier {old}, found {}",
        manifest.package_identifier()
    );
    update(&mut manifest);

    // Preserve the original header, including its schema version, while re-emitting the YAML.
    let mut output = String::new();
    for line in text
        .lines()
        .take_while(|line| line.is_empty() || line.starts_with('#'))
    {
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&to_yaml_string(&manifest)?);
    Ok(convert_to_crlf(&output).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{PackagePath, TreeEntry, prepare_files, rewrite_manifest};
    use crate::github::graphql::get_directory_content_with_text::{Blob, BlobObject};

    #[test]
    fn copies_all_manifest_files_and_keeps_original_deletion_paths() {
        let old = "Old.Package".parse().unwrap();
        let new = "New.Package".parse().unwrap();
        let version = "1.0".parse().unwrap();
        for font in [false, true] {
            let source = PackagePath::new(&old, Some(&version), None, font);
            let destination = PackagePath::new(&new, Some(&version), None, font);
            let names = [
                "Old.Package.yaml",
                "Old.Package.installer.yaml",
                "Old.Package.locale.en-US.yaml",
                "Old.Package.locale.fr-FR.yaml",
            ];
            let entries = names
                .iter()
                .map(|name| TreeEntry {
                    name: (*name).to_owned(),
                    object: Some(BlobObject::Blob(Blob {
                        text: Some(fixture(name)),
                    })),
                })
                .collect();
            let files = prepare_files(entries, &source, &destination, &old, &new, None).unwrap();
            assert_eq!(files.len(), names.len());
            for ((deletion, addition, text), name) in files.iter().zip(names) {
                assert_eq!(deletion, &format!("{source}/{name}"));
                assert_eq!(
                    addition,
                    &format!(
                        "{destination}/{}",
                        name.replace("Old.Package", "New.Package")
                    )
                );
                let value: serde_json::Value = serde_saphyr::from_str(text).unwrap();
                assert_eq!(value["PackageIdentifier"], "New.Package");
                assert_eq!(value["PackageVersion"], "1.0");
            }
            assert!(prepare_files(vec![], &source, &destination, &old, &new, None).is_err());
            assert!(
                prepare_files(
                    vec![TreeEntry {
                        name: "unreadable.yaml".to_owned(),
                        object: None
                    }],
                    &source,
                    &destination,
                    &old,
                    &new,
                    None
                )
                .is_err()
            );
        }
    }

    fn fixture(name: &str) -> String {
        let (kind, fields) = if name.contains("installer") {
            (
                "installer",
                "Installers:\n- Architecture: x64\n  InstallerUrl: https://example.com/Old.Package.exe\n  InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            )
        } else if name.contains("en-US") {
            (
                "defaultLocale",
                "PackageLocale: en-US\nPublisher: Example\nPackageName: Old.Package\nLicense: MIT\nShortDescription: Old.Package description\nDescription: |\n  Old.Package\n  Moniker: example\nMoniker: old\n",
            )
        } else if name.contains("fr-FR") {
            ("locale", "PackageLocale: fr-FR\nDescription: Old.Package\n")
        } else {
            ("version", "DefaultLocale: en-US\n")
        };
        format!(
            "# Created by another tool\nPackageIdentifier: 'Old.Package'\nPackageVersion: '1.0'\n{fields}ManifestType: {kind}\nManifestVersion: 1.9.0\n"
        )
    }

    #[test]
    fn updates_only_identifier_and_existing_moniker_fields() {
        let old = "Old.Package".parse().unwrap();
        let new = "New.Package".parse().unwrap();
        let moniker = "new".parse().unwrap();
        for name in ["version", "installer", "en-US", "fr-FR"] {
            let text = fixture(name);
            for replacement in [None, Some(&moniker)] {
                let output = rewrite_manifest(&text, &old, &new, replacement).unwrap();
                let mut expected: serde_json::Value = serde_saphyr::from_str(&text).unwrap();
                expected["PackageIdentifier"] = "New.Package".into();
                if replacement.is_some() && name == "en-US" {
                    expected["Moniker"] = "new".into();
                }
                let actual: serde_json::Value = serde_saphyr::from_str(&output).unwrap();
                assert_eq!(actual, expected);
                assert!(output.starts_with("# Created by another tool\r\n"));
            }
        }
    }

    #[test]
    fn does_not_add_absent_moniker() {
        let text = fixture("en-US").replace("\nMoniker: old\n", "\n");
        let output = rewrite_manifest(
            &text,
            &"Old.Package".parse().unwrap(),
            &"New.Package".parse().unwrap(),
            Some(&"new".parse().unwrap()),
        )
        .unwrap();
        let actual: serde_json::Value = serde_saphyr::from_str(&output).unwrap();
        assert!(actual.get("Moniker").is_none());
        assert!(
            actual["Description"]
                .as_str()
                .unwrap()
                .contains("Moniker: example")
        );
    }

    #[test]
    fn rejects_invalid_or_mismatched_manifests() {
        let old = "Old.Package".parse().unwrap();
        let new = "New.Package".parse().unwrap();
        for text in [
            "invalid: [".to_owned(),
            "ManifestType: unsupported".to_owned(),
            "ManifestType: version\nPackageIdentifier: Old.Package\n".to_owned(),
            fixture("version").replace("Old.Package", "Wrong.Package"),
        ] {
            assert!(rewrite_manifest(&text, &old, &new, None).is_err());
        }
    }
}
